//! 本地混合代理（SOCKS5 + HTTP）。
//!
//! 路由判定（防泄漏关键路径，参照 zks-client-cli proxy/mod.rs）：
//! 1. 域名规则命中 → 直接返回，不触发任何 DNS；
//! 2. 目标是字面 IP → 走 IP 规则（无需解析）；
//! 3. 只有存在"无 no-resolve 的 IP 谓词规则"时才解析域名；
//! 4. 解析走 `DnsResolver`（DIRECT → direct-nameserver，PROXY → tunnel://），
//!    失败则保留域名规则结果 —— 绝不回退系统 DNS（fail-closed）。
//!
//! 协议握手（纯字节读取阶段）限时：防止"连上不发包"的呆客户端/端口扫描
//! 挂着不动的连接泄漏任务。**数据转发绝不设总超时** —— 否则所有长连接
//! （keep-alive 的 HTTPS、下载、视频）都会被定时杀掉。

use crate::router::RuleAction;
use crate::{mux::get_mux_pool, DIAL_TIMEOUT};
use futures_util::stream::{FuturesUnordered, StreamExt};
use std::{
    error::Error,
    io::Error as IoError,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

/// 协议握手限时
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

// ==============================================================================
// 对外函数入口
// ==============================================================================

pub async fn run_proxy_server(addr: &str) {
    let listener = TcpListener::bind(addr).await.expect("监听失败");
    log::info!(
        "[代理] 监听 {} -> {}",
        addr,
        mask_server_addr(&crate::get_args().server)
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
// 路由判定与直连建连（防泄漏关键路径）
// ==============================================================================

/// 去掉 SOCKS5 读出的 IPv6 方括号（`[::1]` → `::1`）。
pub fn normalize_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// 路由判定：域名规则 → 字面 IP 规则 → （需要时）DnsResolver 解析后按 IP 判定。
/// none/global 模式直接短路；rule 模式下规则未加载时降级为全局代理。
pub async fn resolve_action(host: &str) -> RuleAction {
    use crate::router::RoutingMode;
    match crate::router::routing_mode() {
        RoutingMode::None => return RuleAction::Direct,
        RoutingMode::Global => return RuleAction::Proxy,
        RoutingMode::Rule => {}
    }

    let Some(r) = crate::router::get_router() else {
        return RuleAction::Proxy;
    };
    let host = normalize_host(host);

    // 1. 域名规则命中：不触发任何 DNS
    if let Some(action) = r.route_domain_opt(host) {
        return action;
    }

    // 2. 字面 IP：走 IP 规则（无需解析）
    if let Ok(ip) = host.parse::<IpAddr>() {
        return r.route_ip(&ip);
    }

    // 3. 路由不存在"需要解析"的 IP 谓词规则：保持域名阶段结论，绝不触发 DNS
    if !r.needs_ip_resolution() {
        return r.default_action.clone();
    }

    // 4. 解析（DIRECT → direct-nameserver；PROXY/未知 → tunnel://），fail-closed
    let Some(resolver) = crate::dns::get_resolver() else {
        log::debug!(
            "[路由] DNS 解析器未就绪，{} 保留域名规则结果",
            host
        );
        return r.default_action.clone();
    };

    match resolver.resolve(host).await {
        Ok(ips) => {
            for ip in &ips {
                if let Some(action) = r.route_ip_opt(ip) {
                    log::debug!("[路由] {} → {} → IP 规则", host, ip);
                    return action;
                }
            }
            r.default_action.clone()
        }
        Err(e) => {
            // fail-closed：隧道断开/上游失败时，绝不静默改用系统 DNS
            log::debug!(
                "[路由] {} 解析失败 ({}), 保留域名规则结果",
                host,
                e
            );
            r.default_action.clone()
        }
    }
}

/// Direct 分支连接：域名必须经 `DnsResolver` 解析，失败即拒绝（fail-closed）。
///
/// - 字面 IP / localhost → 不触发 DNS；
/// - 其它域名 → resolver（按路由选 direct-nameserver / tunnel://）；
///   没接线 resolver 时直接拒绝，绝不 `TcpStream::connect((host, port))`
///   走系统解析。
/// - 多个地址**并行竞速**（happy eyeballs 简化版）：geo 不符的第一个 IP
///   不再拖住整个连接，避免 10s 干等变白屏。
pub async fn connect_direct(
    host: &str,
    port: u16,
    connect_timeout: Duration,
) -> Result<TcpStream, String> {
    let host = normalize_host(host);

    let ips: Vec<IpAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![ip]
    } else if host.eq_ignore_ascii_case("localhost") {
        // 本地回环：绝不该把 localhost 送去远端 DoH
        vec![
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ]
    } else {
        let Some(resolver) = crate::dns::get_resolver() else {
            return Err(format!(
                "直连 {} 被拒绝: DNS 解析器未接线 (fail-closed)",
                host
            ));
        };
        resolver
            .resolve(host)
            .await
            .map_err(|e| format!("直连解析 {}: {}", host, e))?
    };

    if ips.is_empty() {
        return Err(format!("{} 没有可用地址", host));
    }

    let mut pending = ips
        .into_iter()
        .map(|ip| async move {
            match timeout(
                connect_timeout,
                TcpStream::connect(SocketAddr::new(ip, port)),
            )
            .await
            {
                Ok(Ok(stream)) => {
                    // 直连出口也关 Nagle：交互式流量（TLS 握手小包、SSH）最多可省 200ms
                    let _ = stream.set_nodelay(true);
                    Ok(stream)
                }
                Ok(Err(e)) => Err(format!("connect {}: {}", ip, e)),
                Err(_) => Err(format!("connect {}: 超时", ip)),
            }
        })
        .collect::<FuturesUnordered<_>>();

    let mut last_err = None;
    while let Some(result) = pending.next().await {
        match result {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| format!("{} 没有可用地址", host)))
}

/// 解析 "host:port"（支持 [IPv6]:port）；缺省端口用 default_port
pub fn parse_host_port(
    host_port: &str,
    default_port: u16,
) -> Result<(String, u16), Box<dyn Error + Send + Sync>> {
    if let Some(inner) = host_port.strip_prefix('[') {
        let end = inner.find(']').ok_or("无效 IPv6 地址: 缺少 ']'")?;
        let host = inner[..end].to_string();
        let port = inner
            .get(end + 2..)
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);
        return Ok((host, port));
    }
    let mut parts = host_port.rsplitn(2, ':');
    match (parts.next(), parts.next()) {
        (Some(port_str), Some(host)) => Ok((
            host.to_string(),
            port_str.parse().unwrap_or(default_port),
        )),
        _ => Ok((host_port.to_string(), default_port)),
    }
}

fn log_action(action: &RuleAction, host: &str, port: u16, tag: &str) {
    match action {
        RuleAction::Proxy => log::info!("[{}] 🌐 PROXY  {}:{}", tag, host, port),
        RuleAction::Direct => log::info!("[{}] ⚡ DIRECT {}:{}", tag, host, port),
        RuleAction::Reject => log::info!("[{}] 🚫 REJECT {}:{}", tag, host, port),
        RuleAction::Named(n) => log::info!("[{}] 🏷️  {} {}:{}", tag, n, host, port),
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
            IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(&buf[..16]).unwrap(),
            ))
            .to_string()
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

    if cmd != 0x01 {
        let _ = conn
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return;
    }

    let host = normalize_host(&host).to_string();
    let action = resolve_action(&host).await;
    log_action(&action, &host, port, "SOCKS5");
    let r = match action {
        RuleAction::Reject => {
            // SOCKS5 错误码 0x02 = Connection not allowed by ruleset
            let _ = conn
                .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            Ok(())
        }
        RuleAction::Direct => handle_direct(conn, &host, port, peer, 1, vec![]).await,
        RuleAction::Proxy | RuleAction::Named(_) => {
            handle_tunnel(conn, &format!("{}:{}", host, port), peer, 1, vec![]).await
        }
    };
    if let Err(e) = r {
        let s = e.to_string();
        if !s.contains("broken pipe") && !s.contains("connection reset") && !s.contains("EOF") {
            log::warn!("[SOCKS5] {} 错误: {}", peer, s);
        }
    }
}

async fn handle_http(mut conn: TcpStream, peer: SocketAddr, first_byte: u8) {
    let mut head = vec![first_byte];
    let mut tmp = vec![0u8; 8192];
    match timeout(HANDSHAKE_TIMEOUT, conn.read(&mut tmp)).await {
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
        // HTTPS代理
        let Ok((host, port)) = parse_host_port(url, 443) else {
            return;
        };
        let action = resolve_action(&host).await;
        log_action(&action, &host, port, "HTTPS");
        let r = match action {
            RuleAction::Reject => {
                let _ = conn
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    .await;
                Ok(())
            }
            RuleAction::Direct => handle_direct(conn, &host, port, peer, 2, vec![]).await,
            RuleAction::Proxy | RuleAction::Named(_) => {
                handle_tunnel(conn, &format!("{}:{}", host, port), peer, 2, vec![]).await
            }
        };
        if let Err(e) = r {
            log::warn!("[HTTPS CONNECT] {}", e);
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
    let Ok((host, port)) = parse_host_port(&target, 80) else {
        return;
    };
    let action = resolve_action(&host).await;
    log_action(&action, &host, port, "HTTP");
    let r = match action {
        RuleAction::Reject => {
            let _ = conn
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await;
            Ok(())
        }
        RuleAction::Direct => handle_direct(conn, &host, port, peer, 3, head).await,
        RuleAction::Proxy | RuleAction::Named(_) => {
            handle_tunnel(conn, &target, peer, 3, head).await
        }
    };
    if let Err(e) = r {
        log::warn!("[HTTP] {}", e);
    }
}

// ==============================================================================
// 直连 and 隧道代理
// ==============================================================================

/// 直连（域名经 DnsResolver 解析，fail-closed + happy eyeballs）
async fn handle_direct(
    mut conn: TcpStream,
    host: &str,
    port: u16,
    _peer: SocketAddr,
    mode: i32,
    first_payload: Vec<u8>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut remote = match connect_direct(host, port, DIAL_TIMEOUT).await {
        Ok(c) => c,
        Err(e) => {
            send_error(&mut conn, mode).await;
            return Err(format!("直连失败: {}", e).into());
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
    Ok(())
}

/// 隧道代理(多路复用)
async fn handle_tunnel(
    mut conn: TcpStream,
    target: &str,
    _peer: SocketAddr,
    resp_mode: i32,
    first_frame: Vec<u8>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    // 1. 从连接池获取一条逻辑流（mux 层已等服务端 ACK：
    //    某槽被拒/超时会自动换下一槽，全部失败才返回错误）
    let (sink, mut source) = match get_mux_pool().open_stream(target).await {
        Ok(v) => v,
        Err(e) => {
            send_error(&mut conn, resp_mode).await;
            return Err(e);
        }
    };
    let sid = sink.sid;
    log::debug!("[隧道] sid={} -> {}", sid, target);

    // 2. 通知客户端就绪
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
