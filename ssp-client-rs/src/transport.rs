//! 连接层：端点地址解析 + TLS 双栈（native-tls / rustls+ECH）+ WebSocket 升级。
//!
//! bootstrap 边界（防解析环）—— 建连地址按优先级：
//!   1. `--ip` 优选 IP（字面地址，无解析）
//!   2. `proxy-server-nameserver` 引导 DoH 解析的端点 IP（系统 DNS 看不到 worker 域名）
//!   3. 系统 getaddrinfo（残余一次性泄漏，保可用性）
//!
//! TLS 选择：`--ech off` / 回退走 native-tls，ECH 走 rustls（含平台证书校验）。
//! ECH 失败重试、降级计数在 `dial_with_ech` 内完成。
//!
//! 分层边界：本模块只负责"把一条已通过 ECDH 握手的 WebSocket 交出去"，
//! 不关心隧道协议帧（mux.rs），也不加密业务数据（crypto.rs）。

use crate::crypto::{Handshake, Session};
use crate::{get_args, DIAL_TIMEOUT};
use async_tungstenite::{
    tokio::TokioAdapter,
    tungstenite::http::{
        header::{
            CONNECTION, HOST, ORIGIN, SEC_WEBSOCKET_KEY,
            SEC_WEBSOCKET_VERSION, UPGRADE, USER_AGENT,
        },
        Request,
    },
    tungstenite::Message,
    WebSocketStream,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::StreamExt;
use native_tls::TlsConnector as NativeTlsConnector;
use once_cell::sync::OnceCell;

use std::{
    error::Error,
    io,
    net::{IpAddr, Ipv4Addr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    time::timeout,
};
use tokio_native_tls::{TlsConnector as TokioTlsConnector, TlsStream};
use tokio_rustls::TlsConnector as RustlsConnector;

/// TLS 握手超时
pub const WS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

// ==============================================================================
// --server / --ip 参数解析
// ==============================================================================

pub struct ServerAddrInfo {
    pub host: String,
    pub port: String,
    pub ws_url: String,
}
static SERVER_ADDR_INFO: OnceCell<ServerAddrInfo> = OnceCell::new();
pub fn get_server_addr_info() -> &'static ServerAddrInfo {
    SERVER_ADDR_INFO.get_or_init(|| {
        let raw = get_args()
            .server
            .split('/')
            .next()
            .unwrap_or(&get_args().server);
        let (host, port) = raw
            .split_once(':')
            .map(|(h, p)| (h.to_string(), p.to_string()))
            .unwrap_or_else(|| (raw.to_string(), "443".to_string()));
        ServerAddrInfo {
            ws_url: format!("wss://{}:{}/", host, port),
            host,
            port,
        }
    })
}

/// 解析 --ip 参数值（可能为 IPv4、IPv4 CIDR、逗号分隔多值；CIDR 随机取一个可用位）
pub fn resolve_cf_ip(input: &str) -> Option<String> {
    let parts: Vec<&str> = input
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if parts.is_empty() {
        return None;
    }
    let selected = parts[rand::random_range(0..parts.len())];
    if !selected.contains('/') {
        return Some(selected.to_string());
    }
    if let Some((ip_str, prefix_str)) = selected.split_once('/') {
        if let (Ok(base_ip), Ok(prefix)) = (ip_str.parse::<Ipv4Addr>(), prefix_str.parse::<u32>()) {
            if prefix >= 31 {
                return Some(ip_str.to_string());
            }
            let base_u32: u32 = base_ip.into();
            let host_bits = 32 - prefix;
            let total_ips = 1u32.checked_shl(host_bits).unwrap_or(0);
            if total_ips <= 2 {
                return Some(ip_str.to_string());
            }
            let mask = !((1u32.checked_shl(host_bits).unwrap_or(0)).wrapping_sub(1));
            let network = base_u32 & mask;
            let offset = rand::random_range(1..(total_ips - 1));
            return Some(Ipv4Addr::from(network + offset).to_string());
        }
    }

    Some(selected.to_string())
}

// ==============================================================================
// TLS 双栈（native-tls / rustls 统一为一个流类型）
// ==============================================================================

pub enum TlsStreamKind {
    Native(TlsStream<TcpStream>),
    Rustls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl AsyncRead for TlsStreamKind {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            TlsStreamKind::Native(s) => Pin::new(s).poll_read(cx, buf),
            TlsStreamKind::Rustls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TlsStreamKind {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        src: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            TlsStreamKind::Native(s) => Pin::new(s).poll_write(cx, src),
            TlsStreamKind::Rustls(s) => Pin::new(s).poll_write(cx, src),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            TlsStreamKind::Native(s) => Pin::new(s).poll_flush(cx),
            TlsStreamKind::Rustls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            TlsStreamKind::Native(s) => Pin::new(s).poll_shutdown(cx),
            TlsStreamKind::Rustls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

pub type WsStream = WebSocketStream<TokioAdapter<TlsStreamKind>>;

/// WS 消息类型（mux 层经由本模块收发，不直接接触 tungstenite）
pub type WsMessage = Message;

/// 构造 Binary WS 消息（隧道帧 → WS 消息的唯一入口）
pub fn ws_message_binary(data: Vec<u8>) -> WsMessage {
    Message::Binary(data.into())
}

// ==============================================================================
// ECH 提供者（由 main 初始化，连接层只读）
// ==============================================================================

static ECH_PROVIDER: OnceCell<Option<crate::ech::EchProvider>> = OnceCell::new();

pub fn set_ech_provider(p: Option<crate::ech::EchProvider>) {
    let _ = ECH_PROVIDER.set(p);
}

fn get_ech_provider() -> Option<&'static crate::ech::EchProvider> {
    ECH_PROVIDER.get().and_then(|o| o.as_ref())
}

// ==============================================================================
// 建连
// ==============================================================================

/// 建立一条完成 SSP ECDH 握手的 WebSocket 连接。
/// 连接地址候选逐个回退（优选 IP 失效不至于让重连永远失败）。
pub(crate) async fn dial_connection() -> Result<(WsStream, Arc<Session>), Box<dyn Error + Send + Sync>>
{
    let info = get_server_addr_info();
    let args = get_args();
    let host = info.host.clone();
    let port: u16 = info.port.parse().unwrap_or(443);

    let preferred = if args.ip.is_empty() {
        None
    } else {
        resolve_cf_ip(&args.ip)
    };

    // 端点 IP：字面 IP 直用；域名则先经 proxy-server-nameserver 引导 DoH 解析，
    // 失败回退 None → 用域名走系统解析（保可用性）
    let endpoint_ip = if preferred.is_some() || host.parse::<IpAddr>().is_ok() {
        None
    } else {
        match crate::dns::get_dns_config() {
            Some(cfg) => crate::dns::resolve_tunnel_endpoint(cfg, &host, port)
                .await
                .map(|addr| {
                    log::info!(
                        "[拨号] 端点 {} 经引导 DoH 解析为 {}（系统 DNS 未接触）",
                        host,
                        addr.ip()
                    );
                    addr.ip().to_string()
                }),
            None => None,
        }
    };

    let mut candidates: Vec<String> = Vec::new();
    if let Some(ip) = preferred {
        candidates.push(format!("{}:{}", ip, port));
    }
    match endpoint_ip {
        Some(ip) => candidates.push(format!("{}:{}", ip, port)),
        None => candidates.push(format!("{}:{}", host, port)),
    }

    let mut last_err = None;
    for addr in &candidates {
        match dial_with_ech(&host, addr).await {
            Ok(v) => return Ok(v),
            Err(e) => {
                log::warn!("[拨号] 连接 {} 失败: {}，尝试下一候选", addr, e);
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| "拨号失败".into()))
}

/// 先尝试 ECH，失败时按模式回退/报错。
///
/// - `auto`：配置取不到 / 握手失败 → 回退 native-tls；连续失败后进入降级冷却。
/// - `on`：只允许一次配置刷新重试，绝不降级（fail-closed）。
async fn dial_with_ech(
    host: &str,
    connect_addr: &str,
) -> Result<(WsStream, Arc<Session>), Box<dyn Error + Send + Sync>> {
    let Some(provider) = get_ech_provider() else {
        return dial_ws(host, connect_addr, DialTls::Native).await;
    };

    for attempt in 0..2 {
        let cfg = match provider.client_config(host).await {
            Ok((cfg, info)) => {
                log::debug!(
                    "[ECH] 配置就绪: host={} source={} {} bytes",
                    host,
                    info.source,
                    info.config_len
                );
                cfg
            }
            Err(e) if provider.is_auto() => {
                // 配置不可用（含降级冷却）在 auto 下是正常路径，不刷 WARN
                log::debug!("[ECH] 配置不可用: {}；回退 native-tls", e);
                break;
            }
            Err(e) => return Err(e.into()),
        };

        match dial_ws(host, connect_addr, DialTls::Rustls(&cfg)).await {
            Ok(v) => {
                provider.note_handshake_success().await;
                return Ok(v);
            }
            Err(e) if attempt == 0 => {
                log::warn!("[ECH] 握手失败 ({}): {}；刷新配置重试", connect_addr, e);
                provider.invalidate().await;
            }
            Err(e) => {
                log::warn!("[ECH] 握手仍失败 ({}): {}", connect_addr, e);
                if !provider.is_auto() {
                    return Err(e);
                }
                // 计一次「整次连接失败」，达到阈值后临时降级为普通 TLS
                provider.note_handshake_failure().await;
                break;
            }
        }
    }

    dial_ws(host, connect_addr, DialTls::Native).await
}

/// 连接器选择：`off`/回退走 native-tls，ECH 走 rustls
enum DialTls<'a> {
    Native,
    Rustls(&'a Arc<rustls::ClientConfig>),
}

/// 用指定地址建立 TCP + TLS + WebSocket 连接（SNI/Host 始终是 worker 域名）
async fn dial_ws(
    host: &str,
    connect_addr: &str,
    tls: DialTls<'_>,
) -> Result<(WsStream, Arc<Session>), Box<dyn Error + Send + Sync>> {
    let args = get_args();
    let info = get_server_addr_info();

    let tcp = timeout(DIAL_TIMEOUT, TcpStream::connect(connect_addr))
        .await
        .map_err(|_| format!("TCP 超时: {}", connect_addr))??;
    // 关 Nagle：握手/心跳/DNS 应答等小包不再被攒包延迟
    let _ = tcp.set_nodelay(true);

    let tls_stream = dial_tls(host, tcp, tls).await?;

    // rustls 能告诉我们 ECH 的真实结果（native-tls 没有这个概念）
    if let TlsStreamKind::Rustls(s) = &tls_stream {
        match s.get_ref().1.ech_status() {
            rustls::client::EchStatus::Accepted => {
                log::info!("[ECH] 服务端已接受 ECH，外层 SNI 已隐藏");
            }
            other => {
                log::debug!("[ECH] 服务端 ECH 状态: {:?}", other);
            }
        }
    }

    let mut kb = [0u8; 16];
    rand::fill(&mut kb);
    let ws_key = Engine::encode(&STANDARD, kb);

    let req = Request::builder()
        .uri(&info.ws_url)
        .header(HOST, host)
        .header(USER_AGENT, &args.ua)
        .header(ORIGIN, format!("https://{}", host))
        .header(SEC_WEBSOCKET_KEY, ws_key)
        .header(SEC_WEBSOCKET_VERSION, "13")
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, "websocket")
        .body(())?;

    let (ws, _): (WsStream, _) = timeout(
        WS_HANDSHAKE_TIMEOUT,
        async_tungstenite::tokio::client_async(req, tls_stream),
    )
    .await
    .map_err(|_| "WebSocket 升级超时")??;

    perform_handshake(ws).await
}

async fn dial_tls(
    host: &str,
    tcp: TcpStream,
    tls: DialTls<'_>,
) -> Result<TlsStreamKind, Box<dyn Error + Send + Sync>> {
    match tls {
        DialTls::Native => {
            let connector = TokioTlsConnector::from(NativeTlsConnector::builder().build()?);
            let s = timeout(WS_HANDSHAKE_TIMEOUT, connector.connect(host, tcp))
                .await
                .map_err(|_| "TLS 握手超时")??;
            Ok(TlsStreamKind::Native(s))
        }
        DialTls::Rustls(cfg) => {
            let connector = RustlsConnector::from(Arc::clone(cfg));
            let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
                .map_err(|e| format!("无效 SNI 域名 {:?}: {}", host, e))?;
            let s = timeout(WS_HANDSHAKE_TIMEOUT, connector.connect(server_name, tcp))
                .await
                .map_err(|_| "TLS 握手超时")??;
            Ok(TlsStreamKind::Rustls(s))
        }
    }
}

/// SSP ECDH 握手：交换公钥 → 派生会话密钥
async fn perform_handshake(
    mut ws: WsStream,
) -> Result<(WsStream, Arc<Session>), Box<dyn Error + Send + Sync>> {
    let hs = Handshake::new(get_args().token.as_bytes())?;
    ws.send(Message::Binary(hs.encrypt_own_pub_key()?.into()))
        .await?;

    let msg = timeout(WS_HANDSHAKE_TIMEOUT, ws.next())
        .await
        .map_err(|_| "ECDH 握手响应超时")?
        .ok_or("握手期间连接关闭")??;

    if let Message::Binary(b) = msg {
        let pub_key = hs.decrypt_peer_pub_key(&b)?;
        let shared = hs.derive_shared_secret(&pub_key)?;
        let session = hs.complete_with_secret(shared)?;
        log::debug!("[握手] ECDH 完成");
        return Ok((ws, session));
    }
    Err("握手协议错: 收到非 Binary 帧".into())
}
