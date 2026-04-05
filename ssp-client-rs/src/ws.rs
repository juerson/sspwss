#![allow(unused)]

use crate::{
    get_args, Handshake, Session, HEARTBEAT_INTERVAL, TYPE_CLOSE, TYPE_DATA, TYPE_HEART, TYPE_OPEN,
};
use async_tungstenite::{
    tokio::TokioAdapter,
    tungstenite::http::{
        header::{
            CONNECTION, HOST, ORIGIN, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL,
            SEC_WEBSOCKET_VERSION, UPGRADE, USER_AGENT,
        },
        Request,
    },
    tungstenite::Message,
    WebSocketStream,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use native_tls::TlsConnector as NativeTlsConnector;
use once_cell::sync::OnceCell;
use rand::Rng;
use std::{
    collections::HashMap,
    error::Error,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    net::TcpStream,
    sync::{mpsc, RwLock},
    time::{sleep, timeout},
};
use tokio_native_tls::{TlsConnector as TokioTlsConnector, TlsStream};

// ==============================================================================
// 辅助：处理命令行参数，--server 和 --ip
// ==============================================================================

// 解析 --server 参数值，提取 host 和 port，并构建 WebSocket URL
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

// 解析 --ip 参数值（可能为 IPv4、IPv4 CIDR、Domain）
pub fn resolve_cf_ip(input: &str) -> Option<String> {
    // 1. 分割字符串并清理空格
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
// 流处理组件
// ==============================================================================

pub struct StreamSink {
    pub sid: u8,
    conn: Arc<MuxConn>,
}

impl StreamSink {
    pub fn send_data(&self, data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        let frame = self.conn.crypto.encrypt(TYPE_DATA, self.sid, data)?;
        let msg = Message::Binary(Bytes::from(frame));
        self.conn.ws_tx.send(msg).map_err(|_| "WS 写入失败".into())
    }

    pub async fn close(self) {
        self.conn.streams.write().await.remove(&self.sid);
        if let Ok(frame) = self.conn.crypto.encrypt(TYPE_CLOSE, self.sid, &[]) {
            let _ = self.conn.ws_tx.send(Message::Binary(Bytes::from(frame)));
        }
        self.conn.stream_count.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct StreamSource {
    rx: mpsc::UnboundedReceiver<Bytes>,
}
impl StreamSource {
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.rx.recv().await
    }
}

// ==============================================================================
// 多路复用连接
// ==============================================================================

struct MuxConn {
    ws_tx: mpsc::UnboundedSender<Message>,
    crypto: Arc<Session>,
    streams: RwLock<HashMap<u8, mpsc::UnboundedSender<Bytes>>>,
    next_sid: AtomicU8,
    alive: AtomicBool,
    stream_count: AtomicUsize,
}

impl MuxConn {
    async fn open_stream(
        self: &Arc<Self>,
        target: &str,
    ) -> Result<(StreamSink, StreamSource), Box<dyn Error + Send + Sync>> {
        let (sid, rx) = {
            let mut streams = self.streams.write().await;
            let start = self.next_sid.load(Ordering::Relaxed);
            let mut s = start;
            loop {
                s = s.wrapping_add(1);
                if s == 0 {
                    s = 1;
                }
                if !streams.contains_key(&s) {
                    break;
                }
                if s == start {
                    return Err("SID 耗尽".into());
                }
            }
            self.next_sid.store(s, Ordering::Relaxed);
            let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
            streams.insert(s, tx);
            (s, rx)
        };
        self.stream_count.fetch_add(1, Ordering::Relaxed);
        let frame = self
            .crypto
            .encrypt(TYPE_OPEN, sid, &crate::build_open_payload(target))?;
        self.ws_tx
            .send(Message::Binary(Bytes::from(frame)))
            .map_err(|_| "WS 无法发送 OPEN")?;
        Ok((
            StreamSink {
                sid,
                conn: self.clone(),
            },
            StreamSource { rx },
        ))
    }
}

// ==============================================================================
// 连接池：提供流式接口供上层使用
// ==============================================================================

// 3个WebSocket连接槽，其它流都复用这3个连接，使用sid都注入这三个槽位
pub const POOL_SIZE: usize = 3;
pub struct MuxPool {
    slots: Vec<RwLock<Option<Arc<MuxConn>>>>,
    rr: AtomicUsize,
}
static GLOBAL_POOL: OnceCell<MuxPool> = OnceCell::new();
pub fn get_mux_pool() -> &'static MuxPool {
    GLOBAL_POOL.get_or_init(|| MuxPool {
        slots: (0..POOL_SIZE).map(|_| RwLock::new(None)).collect(),
        rr: AtomicUsize::new(0),
    })
}

impl MuxPool {
    async fn get_conn(&self, idx: usize) -> Result<Arc<MuxConn>, Box<dyn Error + Send + Sync>> {
        {
            let g = self.slots[idx].read().await;
            if let Some(c) = g.as_ref() {
                if c.alive.load(Ordering::Acquire) {
                    return Ok(c.clone());
                }
            }
        }
        let mut g = self.slots[idx].write().await;
        if let Some(c) = g.as_ref() {
            if c.alive.load(Ordering::Acquire) {
                return Ok(c.clone());
            }
        }

        let conn = dial_new().await?;
        *g = Some(conn.clone());
        log::info!("[连接池] slot={} 拨号成功", idx);
        Ok(conn)
    }

    pub async fn open_stream(
        &self,
        target: &str,
    ) -> Result<(StreamSink, StreamSource), Box<dyn Error + Send + Sync>> {
        let base = self.rr.fetch_add(1, Ordering::Relaxed);
        let mut last_e = None;
        for i in 0..POOL_SIZE {
            let idx = (base + i) % POOL_SIZE;
            match self.get_conn(idx).await {
                Ok(conn) => match conn.open_stream(target).await {
                    Ok(res) => return Ok(res),
                    Err(e) => last_e = Some(e),
                },
                Err(e) => last_e = Some(e),
            }
        }
        Err(last_e.unwrap_or_else(|| "所有连接不可用".into()))
    }
}

// ==============================================================================
// 拨号与内部任务逻辑
// ==============================================================================

async fn dial_new() -> Result<Arc<MuxConn>, Box<dyn Error + Send + Sync>> {
    let (ws, crypto) = dial_raw().await?;
    let (ws_sink, ws_stream) = ws.split();
    let (ws_tx, ws_rx) = mpsc::unbounded_channel();

    let conn = Arc::new(MuxConn {
        ws_tx,
        crypto,
        streams: RwLock::new(HashMap::new()),
        next_sid: AtomicU8::new(1),
        alive: AtomicBool::new(true),
        stream_count: AtomicUsize::new(0),
    });

    // 写任务 (Sender)
    let c1 = conn.clone();
    tokio::spawn(async move {
        let mut sink = ws_sink;
        let mut rx = ws_rx;
        while let Some(msg) = rx.recv().await {
            if sink.send(msg).await.is_err() {
                break;
            }
        }
        c1.alive.store(false, Ordering::Release);
    });

    // 读任务 (Receiver)
    let c2 = conn.clone();
    tokio::spawn(async move {
        let mut stream = ws_stream;
        while let Some(Ok(msg)) = stream.next().await {
            if let Message::Binary(data) = msg {
                if let Ok((typ, sid, payload)) = c2.crypto.decrypt_with_aead(&data) {
                    match typ {
                        TYPE_DATA => {
                            let ss = c2.streams.read().await;
                            if let Some(tx) = ss.get(&sid) {
                                // 将解密后的 Vec<u8> 转为 Bytes 并分发给逻辑流，转换过程是零拷贝的（只是所有权包装）
                                let _ = tx.send(Bytes::from(payload));
                            }
                        }
                        TYPE_CLOSE => {
                            c2.streams.write().await.remove(&sid);
                            c2.stream_count.fetch_sub(1, Ordering::Relaxed);
                        }
                        _ => {}
                    }
                }
            }
        }
        c2.alive.store(false, Ordering::Release);
        c2.streams.write().await.clear();
    });

    // 心跳任务
    let c3 = conn.clone();
    tokio::spawn(async move {
        while c3.alive.load(Ordering::Acquire) {
            sleep(HEARTBEAT_INTERVAL).await;
            if let Ok(f) = c3.crypto.encrypt(TYPE_HEART, 0, &[]) {
                if c3.ws_tx.send(Message::Binary(Bytes::from(f))).is_err() {
                    break;
                }
            }
        }
    });

    Ok(conn)
}

pub type WsStream = WebSocketStream<TokioAdapter<TlsStream<TcpStream>>>;

async fn dial_raw() -> Result<(WsStream, Arc<Session>), Box<dyn Error + Send + Sync>> {
    let info = get_server_addr_info();
    let args = get_args();
    let host = if args.ip.is_empty() {
        info.host.clone()
    } else {
        resolve_cf_ip(&args.ip).unwrap_or_else(|| args.ip.clone())
    };
    let tcp_addr = format!("{}:{}", host, info.port);
    let tcp = timeout(crate::DIAL_TIMEOUT, TcpStream::connect(&tcp_addr))
        .await
        .map_err(|_| format!("TCP 超时: {}", tcp_addr))??;

    let tls_connector = TokioTlsConnector::from(NativeTlsConnector::builder().build()?);
    let tls_stream = timeout(
        crate::WS_HANDSHAKE_TIMEOUT,
        tls_connector.connect(&info.host, tcp),
    )
    .await
    .map_err(|_| "TLS 握手超时")??;

    let mut kb = [0u8; 16];
    rand::fill(&mut kb);
    let ws_key = Engine::encode(&STANDARD, kb);

    let req = Request::builder()
        .uri(&info.ws_url)
        .header(HOST, &info.host)
        .header(USER_AGENT, &args.ua)
        .header(ORIGIN, format!("https://{}", &info.host))
        .header(SEC_WEBSOCKET_KEY, ws_key)
        .header(SEC_WEBSOCKET_VERSION, "13")
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, "websocket")
        .body(())?;

    let (ws, _): (WsStream, _) = timeout(
        crate::WS_HANDSHAKE_TIMEOUT,
        async_tungstenite::tokio::client_async(req, tls_stream),
    )
    .await
    .map_err(|_| "WebSocket 升级超时")??;

    perform_handshake(ws).await
}

async fn perform_handshake(
    mut ws: WsStream,
) -> Result<(WsStream, Arc<Session>), Box<dyn Error + Send + Sync>> {
    let hs = Handshake::new(get_args().token.as_bytes())?;
    ws.send(Message::Binary(Bytes::from(hs.encrypt_own_pub_key()?)))
        .await?;

    let msg = timeout(crate::WS_HANDSHAKE_TIMEOUT, ws.next())
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

pub async fn dial_websocket(
    retries: i32,
) -> Result<(WsStream, Arc<Session>), Box<dyn Error + Send + Sync>> {
    let mut last = None;
    for i in 1..=retries {
        if i > 1 {
            sleep(Duration::from_secs(1)).await;
        }
        match dial_raw().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                log::warn!("[拨号] 第 {} 次尝试失败: {}", i, e);
                last = Some(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| "拨号失败".into()))
}
