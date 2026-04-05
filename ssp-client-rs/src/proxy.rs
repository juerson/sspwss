#![allow(unused)]

use crate::routing::{get_route_action, RouteDecision};
use crate::{
    build_open_payload, get_args, routing::should_bypass_proxy, ws::get_mux_pool, DIAL_TIMEOUT,
};
use std::{
    error::Error,
    io::Error as IoError,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{timeout, Duration},
};

// ==============================================================================
// 对外函数入口
// ==============================================================================

pub async fn run_proxy_server(addr: &str) {
    let listener = TcpListener::bind(addr).await.expect("监听失败");
    log::info!(
        "[代理] 监听 {} -> {}",
        addr,
        mask_server_addr(&get_args().server)
    );

    loop {
        match listener.accept().await {
            Ok((conn, peer)) => {
                tokio::spawn(handle_connection(conn, peer));
            }
            Err(e) => {
                log::debug!("[代理] Accept 错误: {}", e);
            }
        }
    }
}

// ==============================================================================
// 地址脱敏
// ==============================================================================

fn mask_server_addr(addr: &str) -> String {
    if addr.is_empty() {
        return "*****".into();
    }
    match addr.split_once(':') {
        Some((h, p)) => format!("{}:{}", mask_host(h), p),
        None => mask_host(addr),
    }
}

fn mask_host(host: &str) -> String {
    const M: &str = "*****";
    if host.is_empty() {
        return M.into();
    }
    if host.starts_with('[') {
        return format!("{}{}", M, host);
    }
    if host.parse::<Ipv4Addr>().is_ok() {
        let p: Vec<&str> = host.split('.').collect();
        if p.len() == 4 {
            return format!("{}.{}.{}.{}", M, M, M, p[3]);
        }
    }
    if let Some(last) = host.rfind('.') {
        if last > 0 {
            if let Some(prev) = host[..last].rfind('.') {
                return format!("{}{}", M, &host[prev..]);
            }
            return format!("{}{}", M, &host[last..]);
        }
    }
    M.into()
}

// ==============================================================================
// 协议分发
// ==============================================================================

async fn handle_connection(mut conn: TcpStream, peer: SocketAddr) {
    let mut buf = [0u8; 1];
    if conn.read(&mut buf).await.unwrap_or(0) == 0 {
        return;
    }
    match buf[0] {
        0x05 => handle_socks5(conn, peer).await,
        b if b.is_ascii_alphabetic() => handle_http(conn, peer, b).await,
        b => log::debug!("[代理] 未知协议 0x{:02x} from {}", b, peer),
    }
}

// ==============================================================================
// SOCKS5 和 HTTP 代理
// ==============================================================================

async fn handle_socks5(mut conn: TcpStream, peer: SocketAddr) {
    let mut buf = vec![0u8; 256];

    if conn.read_exact(&mut buf[..1]).await.is_err() {
        return;
    }
    let n = buf[0] as usize;
    if n == 0 {
        let _ = conn.write_all(&[0x05, 0xFF]).await;
        return;
    }
    if conn.read_exact(&mut buf[..n]).await.is_err() {
        return;
    }
    if conn.write_all(&[0x05, 0x00]).await.is_err() {
        return;
    }

    if conn.read_exact(&mut buf[..4]).await.is_err() {
        return;
    }
    let (cmd, atyp) = (buf[1], buf[3]);

    let host = match atyp {
        0x01 => {
            if conn.read_exact(&mut buf[..4]).await.is_err() {
                return;
            }
            IpAddr::V4(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3])).to_string()
        }
        0x03 => {
            if conn.read_exact(&mut buf[..1]).await.is_err() {
                return;
            }
            let n = buf[0] as usize;
            if conn.read_exact(&mut buf[..n]).await.is_err() {
                return;
            }
            String::from_utf8_lossy(&buf[..n]).to_string()
        }
        0x04 => {
            if conn.read_exact(&mut buf[..16]).await.is_err() {
                return;
            }
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&buf[..16]).unwrap())).to_string()
        }
        _ => {
            let _ = conn
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return;
        }
    };

    if conn.read_exact(&mut buf[..2]).await.is_err() {
        return;
    }
    let port = u16::from_be_bytes([buf[0], buf[1]]);
    let target = format!("{}:{}", host, port);

    if cmd != 0x01 {
        let _ = conn
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return;
    }
    let r = match get_route_action(&host).await {
        RouteDecision::Reject => {
            log::info!("[SOCKS5] 🚫 REJECT {}", host);
            // SOCKS5 错误码 0x02 = Connection not allowed by ruleset
            let _ = conn
                .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return;
        }
        RouteDecision::Direct => {
            log::info!("[SOCKS5] ⚡ DIRECT {}", host);
            handle_direct(conn, &target, peer, 1, vec![]).await
        }
        RouteDecision::Tunnel => {
            log::info!("[SOCKS5] 🌐 PROXY  {}", host);
            handle_tunnel(conn, &target, peer, 1, vec![]).await
        }
    };
    if let Err(e) = r {
        let s = e.to_string();
        if !s.contains("broken pipe") && !s.contains("connection reset") && !s.contains("EOF") {
            log::debug!("[SOCKS5] {} 错误: {}", peer, s);
        }
    }
}

async fn handle_http(mut conn: TcpStream, peer: SocketAddr, first_byte: u8) {
    let mut head = vec![first_byte];
    let mut tmp = vec![0u8; 8192];
    match timeout(Duration::from_secs(5), conn.read(&mut tmp)).await {
        Ok(Ok(n)) if n > 0 => head.extend_from_slice(&tmp[..n]),
        _ => return,
    }

    let text = String::from_utf8_lossy(&head);
    let mut lines = text.lines();
    let parts: Vec<&str> = lines.next().unwrap_or("").split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let (method, url) = (parts[0], parts[1]);

    let mut host_hdr = String::new();
    for line in lines {
        if line.to_ascii_lowercase().starts_with("host:") {
            host_hdr = line[5..].trim().to_string();
            break;
        }
    }

    if method == "CONNECT" {
        //  HTTPS代理
        let thost = url.split(':').next().unwrap_or(url);
        let r = match get_route_action(thost).await {
            RouteDecision::Reject => {
                log::info!("[HTTPS] 🚫 REJECT  {}", thost);
                let _ = conn
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    .await;
                return;
            }
            RouteDecision::Direct => {
                log::info!("[HTTPS] ⚡ DIRECT {}", thost);
                handle_direct(conn, url, peer, 2, vec![]).await
            }
            RouteDecision::Tunnel => {
                log::info!("[HTTPS] 🌐 PROXY {}", thost);
                handle_tunnel(conn, url, peer, 2, vec![]).await
            }
        };
        if let Err(e) = r {
            log::debug!("[HTTPS CONNECT] {}", e);
        }
        return;
    }
    // http代理 => 普通HTTP
    if host_hdr.is_empty() {
        return;
    }
    let target = match host_hdr.contains(':') {
        true => host_hdr.clone(),
        false => format!("{}:80", host_hdr),
    };
    let thost = target.split(':').next().unwrap_or(&host_hdr).to_string();
    let r = match get_route_action(&thost).await {
        RouteDecision::Reject => {
            log::info!("[HTTP] 🚫 REJECT {}", thost);
            let _ = conn
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await;
            return;
        }
        RouteDecision::Direct => {
            log::info!("[HTTP] ⚡ DIRECT {}", thost);
            handle_direct(conn, &target, peer, 3, head).await
        }
        RouteDecision::Tunnel => {
            log::info!("[HTTP] 🌐 PROXY {}", thost);
            handle_tunnel(conn, &target, peer, 3, head).await
        }
    };
    if let Err(e) = r {
        log::debug!("[HTTP] {}", e);
    }
}

// ==============================================================================
// 直连 and 隧道代理
// ==============================================================================

/// 直连
async fn handle_direct(
    mut conn: TcpStream,
    target: &str,
    peer: SocketAddr,
    mode: i32,
    first_payload: Vec<u8>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let target = ensure_port(target, mode);
    let mut remote = match timeout(DIAL_TIMEOUT, TcpStream::connect(&target)).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            send_error(&mut conn, mode).await;
            return Err(format!("直连失败: {}", e).into());
        }
        Err(_) => {
            send_error(&mut conn, mode).await;
            return Err("直连超时".into());
        }
    };
    send_success(&mut conn, mode).await?;
    if !first_payload.is_empty() {
        remote.write_all(&first_payload).await?;
    }

    let (mut r1, mut w1) = conn.split();
    let (mut r2, mut w2) = remote.split();
    tokio::try_join!(
        async {
            tokio::io::copy(&mut r1, &mut w2).await?;
            w2.shutdown().await
        },
        async {
            tokio::io::copy(&mut r2, &mut w1).await?;
            w1.shutdown().await
        },
    )?;
    // log::debug!("[直连] 断开: {} -> {}", peer, target);
    Ok(())
}

/// 隧道代理(多路复用)
async fn handle_tunnel(
    mut conn: TcpStream,
    target: &str,
    peer: SocketAddr,
    resp_mode: i32,
    first_frame: Vec<u8>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    // 1. 从连接池获取一条逻辑流
    let (sink, mut source) = match get_mux_pool().open_stream(target).await {
        Ok(v) => v,
        Err(e) => {
            send_error(&mut conn, resp_mode).await;
            return Err(e);
        }
    };
    let sid = sink.sid;
    log::debug!("[隧道] sid={} -> {}", sid, target);

    // 2. 等待服务端 ACK
    //    服务端成功建立后端 TCP 时发空 TYPE_DATA；
    //    超出 MAX_CONNECTIONS 时发 TYPE_CLOSE → recv() 返回 None。
    match source.recv().await {
        None => {
            send_error(&mut conn, resp_mode).await;
            return Err(format!("服务端拒绝连接 sid={} target={}", sid, target).into());
        }
        Some(_) => {}
    }

    // 3. 通知客户端就绪
    send_success(&mut conn, resp_mode).await?;

    // 4. 发送缓冲的请求头
    if !first_frame.is_empty() {
        sink.send_data(&first_frame)
            .map_err(|e| format!("发送初始帧失败: {}", e))?;
    }

    // 5. 全双工中继
    let (mut conn_rx, mut conn_tx) = conn.into_split();

    // 任务 A：客户端 → Worker
    let h_to = tokio::spawn(async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = match conn_rx.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if sink.send_data(&buf[..n]).is_err() {
                break;
            }
        }
        sink.close().await;
    });

    // 任务 B：Worker → 客户端
    let h_from = tokio::spawn(async move {
        while let Some(payload) = source.recv().await {
            if payload.is_empty() {
                continue;
            }
            if conn_tx.write_all(&payload).await.is_err() {
                break;
            }
        }
    });

    // 任一方向结束时 abort 另一方，避免僵尸 task 堆积
    let mut h_to = Some(h_to);
    let mut h_from = Some(h_from);

    tokio::select! {
        _ = h_to.take().unwrap() => {
            if let Some(handle) = h_from {
                handle.abort();
            }
        }
        _ = h_from.take().unwrap() => {
            if let Some(handle) = h_to {
                handle.abort();
            }
        }
    }

    log::debug!("[隧道] 📴 sid={} {}", sid, target);
    Ok(())
}

// ==============================================================================
// 辅助函数
// ==============================================================================

fn ensure_port(target: &str, mode: i32) -> String {
    match target.contains(":") {
        true => target.to_string(),
        false => format!("{}:{}", target, if mode == 2 { "443" } else { "80" }),
    }
}

async fn send_error(conn: &mut TcpStream, mode: i32) {
    let _ = conn
        .write_all(if mode == 1 {
            &[0x05u8, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0] as &[u8]
        } else {
            b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
        })
        .await;
}

async fn send_success(conn: &mut TcpStream, mode: i32) -> Result<(), IoError> {
    match mode {
        1 => {
            conn.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
        }
        2 => {
            conn.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
        }
        _ => Ok(()),
    }
}
