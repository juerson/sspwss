//! 多路复用层：单条 WebSocket 连接上的逻辑流复用、连接池、隧道 DNS 端点。
//!
//! 分层边界：本模块把 transport.rs 建好的加密 WS 连接切成 sid 逻辑流，
//! 并做存活维护（心跳 + 看门狗）。帧加密在 crypto.rs，建连在 transport.rs。
//!
//! 存活维护（v1.5 修复"长时间不活动后代理静默失效"）：
//! - 心跳：间隔 30s + 0~6s 抖动，连接间各自错开（消除固定节律特征）；
//!   服务端回显 TYPE_HEART，任何下行帧都会刷新 last_rx；
//! - 看门狗：超过 HEARTBEAT_TIMEOUT（90s）没有任何下行数据（含心跳回显）
//!   → 判定连接死亡（半开 TCP / NAT 重绑定 / CF 掐断），立即把 slot 标记
//!   失效、清空在途流并打 WARN 日志，下次请求自动重拨；
//! - 连接断开（读/写任务退出）打 WARN 日志——默认日志级别可见。

use crate::crypto::{PadPolicy, Session, TYPE_CLOSE, TYPE_DATA, TYPE_DNS, TYPE_HEART, TYPE_OPEN};
use crate::transport::{dial_connection, WsStream};
use crate::get_args;
use bytes::Bytes;
use futures_util::StreamExt;
use once_cell::sync::OnceCell;

use std::{
    collections::HashMap,
    error::Error,
    sync::{
        atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{mpsc, Semaphore},
    time::{sleep, timeout},
};

// ── 常量 ─────────────────────────────────────────────────────────────────────

/// 心跳间隔
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
/// 心跳抖动上限（毫秒）：避免多连接精确同频成为 DPI 特征
const HEARTBEAT_JITTER_MS: u64 = 6000;
/// 看门狗：超过该时长没有任何下行数据（含心跳回显）判定连接死亡
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(90);
/// 单次 DNS 帧交换超时
const DNS_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
/// DNS 帧并发上限
const MAX_INFLIGHT_DNS: usize = 64;
/// WebSocket 连接池槽数
pub const POOL_SIZE: usize = 3;
/// 等待服务端 OPEN ACK 的超时：半开连接/被拒时快速失败
const OPEN_ACK_TIMEOUT: Duration = Duration::from_secs(10);
/// 同一连接连续被拒 N 次后判定会话不可用（旧 worker 子请求预算耗尽时无显式信号）
const CONSECUTIVE_REJECT_LIMIT: u32 = 3;

/// OPEN 载荷合法性检查（禁止分隔符/空字符/空白）
pub fn is_valid_target(s: &str) -> bool {
    if s.contains('|') || s.contains('\x00') {
        return false;
    }
    if let Some((host, _)) = s.split_once(':') {
        return !host.is_empty();
    }
    if s.starts_with('[') && s.ends_with(']') {
        let bare = &s[1..s.len() - 1];
        return !bare.is_empty() && !bare.chars().any(|c| c.is_whitespace());
    }
    if s.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    !s.is_empty() && !s.chars().any(|c| c.is_whitespace())
}

const OPEN_PAYLOAD_MIN: usize = 256;

/// 构造 TYPE_OPEN 载荷：主目标 | fallback…\x00 + 随机填充（≥256B，抗探测）
pub fn build_open_payload(primary_target: &str) -> Vec<u8> {
    let args = get_args();
    let mut parts = vec![primary_target.to_string()];
    for fb in args.fallback.split(',') {
        let fb = fb.trim();
        if fb.is_empty() {
            continue;
        }
        if !is_valid_target(fb) {
            log::debug!("[配置] 跳过非法 fallback 地址: {:?}", fb);
            continue;
        }
        parts.push(fb.to_string());
    }
    let mut raw = parts.join("|").into_bytes();
    if raw.len() < OPEN_PAYLOAD_MIN {
        let pad_len = OPEN_PAYLOAD_MIN - raw.len() - 1;
        let mut pad = vec![0u8; pad_len];
        crate::crypto::get_rand_pool().read(&mut pad).ok();
        raw.push(0x00);
        raw.extend_from_slice(&pad);
    }
    raw
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ==============================================================================
// 流处理组件
// ==============================================================================

pub struct StreamSink {
    pub sid: u8,
    conn: Arc<MuxConn>,
    /// 是否为该流第一个 DATA 帧：做 bucket padding，
    /// 掩盖 TLS-in-TLS ClientHello 的长度指纹（worker 按 len 读 payload，无感知）。
    first_data: AtomicBool,
}

impl StreamSink {
    pub fn send_data(&self, data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        let pad = if self.first_data.swap(false, Ordering::Relaxed) {
            PadPolicy::Bucket
        } else {
            PadPolicy::Random
        };
        let frame = self
            .conn
            .crypto
            .encrypt_with_pad(TYPE_DATA, self.sid, data, pad)?;
        let msg = crate::transport::ws_message_binary(frame);
        self.conn.ws_tx.send(msg).map_err(|_| "WS 写入失败".into())
    }

    pub async fn close(self) {
        self.conn.streams.write().await.remove(&self.sid);
        if let Ok(frame) = self.conn.crypto.encrypt(TYPE_CLOSE, self.sid, &[]) {
            let _ = self.conn.ws_tx.send(crate::transport::ws_message_binary(frame));
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

type DnsPendingMap = StdMutex<HashMap<u16, tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>>>;

/// DNS 请求 ID 分配（进程内唯一即可；回包按 reqId 关联）
static NEXT_DNS_ID: AtomicU32 = AtomicU32::new(1);

struct MuxConn {
    ws_tx: mpsc::UnboundedSender<crate::transport::WsMessage>,
    crypto: Arc<Session>,
    streams: tokio::sync::RwLock<HashMap<u8, mpsc::UnboundedSender<Bytes>>>,
    next_sid: AtomicU8,
    alive: AtomicBool,
    stream_count: AtomicUsize,
    /// 在途 DNS 请求（reqId → 应答通道），响应由读任务按 reqId 分发
    dns_pending: DnsPendingMap,
    /// 最近一次收到下行数据的 unix 秒（含心跳回显）——看门狗依据
    last_rx: AtomicU64,
    /// 连续被拒计数（成功开流即清零）——连续多次被拒判定会话毒化，重拨
    consecutive_rejects: AtomicU32,
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
            .encrypt(TYPE_OPEN, sid, &build_open_payload(target))?;
        self.ws_tx
            .send(crate::transport::ws_message_binary(frame))
            .map_err(|_| "WS 无法发送 OPEN")?;
        Ok((
            StreamSink {
                sid,
                conn: self.clone(),
                first_data: AtomicBool::new(true),
            },
            StreamSource { rx },
        ))
    }

    /// 经隧道发一次 DNS 查询（TYPE_DNS 帧，sid=0），返回完整 wire 响应。
    pub async fn dns_exchange(
        self: &Arc<Self>,
        query: Vec<u8>,
    ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        // 分配未占用的 reqId（u16 空间回绕）
        let req_id = {
            let p = self.dns_pending.lock().unwrap();
            loop {
                let v = (NEXT_DNS_ID.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16;
                if v != 0 && !p.contains_key(&v) {
                    break v;
                }
            }
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.dns_pending.lock().unwrap().insert(req_id, tx);

        let mut payload = Vec::with_capacity(2 + query.len());
        payload.extend_from_slice(&req_id.to_be_bytes());
        payload.extend_from_slice(&query);

        let send_res = (|| -> Result<(), Box<dyn Error + Send + Sync>> {
            let frame = self.crypto.encrypt(TYPE_DNS, 0, &payload)?;
            self.ws_tx
                .send(crate::transport::ws_message_binary(frame))
                .map_err(|_| "WS 无法发送 DNS 帧".into())
        })();

        if let Err(e) = send_res {
            self.dns_pending.lock().unwrap().remove(&req_id);
            return Err(e);
        }

        match timeout(DNS_EXCHANGE_TIMEOUT, rx).await {
            Ok(Ok(Ok(bytes))) => Ok(bytes),
            Ok(Ok(Err(e))) => Err(e.into()),
            // 通道关闭：请求被取消（罕见，oneshot 发送端在 pending 表里被移除）
            Ok(Err(_)) => {
                self.dns_pending.lock().unwrap().remove(&req_id);
                Err("DNS 请求被取消".into())
            }
            // 超时：旧版 worker 不认识 TYPE_DNS 帧会静默忽略
            Err(_) => {
                self.dns_pending.lock().unwrap().remove(&req_id);
                Err("DNS 查询超时（若持续出现，说明 worker 未部署 DNS 帧，请更新 ssp-server/worker/worker.js 并重新部署）".into())
            }
        }
    }

    fn complete_dns(&self, req_id: u16, resp: Vec<u8>) {
        if let Some(tx) = self.dns_pending.lock().unwrap().remove(&req_id) {
            let _ = tx.send(Ok(resp));
        }
    }

    fn fail_all_dns(&self, err: &str) {
        let mut p = self.dns_pending.lock().unwrap();
        for (_, tx) in p.drain() {
            let _ = tx.send(Err(err.to_string()));
        }
    }

    /// 标记死亡（幂等），返回是否为首次标记
    fn set_dead(&self) -> bool {
        self.alive.swap(false, Ordering::AcqRel)
    }

    fn mark_dead(&self, why: &str) {
        if self.set_dead() {
            log::warn!("[连接池] 连接断开: {}（下次请求自动重拨）", why);
        }
        self.fail_all_dns("隧道已断开");
    }

    /// worker 主动回收会话（子请求预算轮换等设计行为）：INFO 级别
    fn mark_recycled(&self, why: &str) {
        if self.set_dead() {
            log::info!("[连接池] {}: 下次请求自动重拨", why);
        }
        self.fail_all_dns("隧道已断开");
    }

    /// 开流并等待服务端 ACK。被拒/超时计入连续拒绝计数：
    /// 连续 CONSECUTIVE_REJECT_LIMIT 次被拒 → 判定会话毒化（如旧 worker 的
    /// 子请求预算耗尽），标记重拨；存量流继续由读/写任务服务。
    async fn open_stream_with_ack(
        self: &Arc<Self>,
        target: &str,
    ) -> Result<(StreamSink, StreamSource), Box<dyn Error + Send + Sync>> {
        let (sink, mut source) = self.open_stream(target).await?;
        match timeout(OPEN_ACK_TIMEOUT, source.recv()).await {
            Err(_) => {
                let _ = sink.close().await;
                self.note_reject().await;
                Err(format!("服务端 ACK 超时（连接可能已死）target={}", target).into())
            }
            Ok(None) => {
                self.note_reject().await;
                Err(format!("服务端拒绝新流 target={}", target).into())
            }
            Ok(Some(_)) => {
                self.consecutive_rejects.store(0, Ordering::Relaxed);
                Ok((sink, source))
            }
        }
    }

    async fn note_reject(&self) {
        let n = self.consecutive_rejects.fetch_add(1, Ordering::Relaxed) + 1;
        if n == 1 {
            log::debug!("[隧道] slot 新流被拒/超时（尝试其它槽位）");
        }
        if n >= CONSECUTIVE_REJECT_LIMIT {
            self.mark_dead(&format!(
                "会话毒化（连续 {} 次新流被拒，疑似子请求预算耗尽）；该槽自动重拨，存量流继续",
                n
            ));
        }
    }
}

// ==============================================================================
// 隧道 DNS 端点（dns::TunnelUpstream 的对接面）
// ==============================================================================

/// 隧道 DNS 端点：DNS wire 查询经 TYPE_DNS 帧走隧道，由 Worker DoH 解析。
/// 连续超时 2 次判定 worker 未部署 DNS 帧，快速失败避免每个查询干等 10s。
#[derive(Clone)]
pub struct TunnelDns {
    slots: Arc<Semaphore>,
    unsupported: Arc<AtomicU32>,
}

static GLOBAL_TUNNEL_DNS: OnceCell<TunnelDns> = OnceCell::new();

pub fn get_tunnel_dns() -> &'static TunnelDns {
    GLOBAL_TUNNEL_DNS.get_or_init(|| TunnelDns {
        slots: Arc::new(Semaphore::new(MAX_INFLIGHT_DNS)),
        unsupported: Arc::new(AtomicU32::new(0)),
    })
}

impl TunnelDns {
    /// DNS wire 查询 → wire 响应（与 zks-client-cli TunnelClient::dns_exchange 语义一致）
    pub async fn dns_exchange(
        &self,
        query: Vec<u8>,
    ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        if self.unsupported.load(Ordering::Relaxed) >= 2 {
            return Err("worker 不支持 DNS 帧（DNS 查询已连续超时），请更新 ssp-server/worker/worker.js 并重新部署".into());
        }
        let _permit = self
            .slots
            .acquire()
            .await
            .map_err(|_| "DNS 并发槽已关闭".to_string())?;

        let conn = self.dns_conn().await?;
        match conn.dns_exchange(query).await {
            Ok(v) => {
                self.unsupported.store(0, Ordering::Relaxed);
                Ok(v)
            }
            Err(e) => {
                let s = e.to_string();
                if s.contains("超时") {
                    let n = self.unsupported.fetch_add(1, Ordering::Relaxed) + 1;
                    if n == 2 {
                        log::warn!("[DNS] 隧道 DNS 连续超时，判定 worker 未部署 DNS 帧；后续查询将快速失败");
                    }
                }
                Err(e)
            }
        }
    }

    /// 取一条可用隧道连接（轮询池槽位，必要时拨号）
    async fn dns_conn(&self) -> Result<Arc<MuxConn>, Box<dyn Error + Send + Sync>> {
        let pool = get_mux_pool();
        let base = pool.rr.fetch_add(1, Ordering::Relaxed);
        let mut last_e = None;
        for i in 0..POOL_SIZE {
            match pool.get_conn((base + i) % POOL_SIZE).await {
                Ok(c) => return Ok(c),
                Err(e) => last_e = Some(e),
            }
        }
        Err(last_e.unwrap_or_else(|| "所有连接不可用".into()))
    }
}

// ==============================================================================
// 连接池
// ==============================================================================

pub struct MuxPool {
    slots: Vec<tokio::sync::RwLock<Option<Arc<MuxConn>>>>,
    rr: AtomicUsize,
}
static GLOBAL_POOL: OnceCell<MuxPool> = OnceCell::new();
pub fn get_mux_pool() -> &'static MuxPool {
    GLOBAL_POOL.get_or_init(|| MuxPool {
        slots: (0..POOL_SIZE).map(|_| tokio::sync::RwLock::new(None)).collect(),
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

        let (ws, crypto) = dial_connection().await?;
        let conn = spawn_conn_tasks(ws, crypto);
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
        // 每个槽位都等到服务端 ACK 才算成功：某槽被拒/超时自动换下一槽，
        // 单槽毒化（如子请求预算耗尽）对用户请求无感
        for i in 0..POOL_SIZE {
            let idx = (base + i) % POOL_SIZE;
            match self.get_conn(idx).await {
                Ok(conn) => match conn.open_stream_with_ack(target).await {
                    Ok(res) => return Ok(res),
                    Err(e) => {
                        // 槽位被判死（毒化/worker 回收）：后台预拨号，下次请求零等待
                        if !conn.alive.load(Ordering::Acquire) {
                            tokio::spawn(async move {
                                let _ = get_mux_pool().get_conn(idx).await;
                            });
                        }
                        last_e = Some(e);
                    }
                },
                Err(e) => last_e = Some(e),
            }
        }
        Err(last_e.unwrap_or_else(|| "所有连接不可用".into()))
    }
}

// ==============================================================================
// 连接内部任务（读 / 写 / 心跳+看门狗）
// ==============================================================================

/// 拆分 WS 流并启动三个常驻任务，返回连接句柄
fn spawn_conn_tasks(ws: WsStream, crypto: Arc<Session>) -> Arc<MuxConn> {
    let (ws_sink, ws_stream) = ws.split();
    let (ws_tx, ws_rx) = mpsc::unbounded_channel();

    let conn = Arc::new(MuxConn {
        ws_tx,
        crypto,
        streams: tokio::sync::RwLock::new(HashMap::new()),
        next_sid: AtomicU8::new(1),
        alive: AtomicBool::new(true),
        stream_count: AtomicUsize::new(0),
        dns_pending: StdMutex::new(HashMap::new()),
        last_rx: AtomicU64::new(now_secs()),
        consecutive_rejects: AtomicU32::new(0),
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
        c1.mark_dead("WS 写入失败（发送通道关闭或对端不可写）");
    });

    // 读任务 (Receiver)：分发下行帧 + 刷新存活时间
    let c2 = conn.clone();
    tokio::spawn(async move {
        let mut stream = ws_stream;
        let mut close_reason = String::new();
        while let Some(Ok(msg)) = stream.next().await {
            c2.last_rx.store(now_secs(), Ordering::Relaxed);
            match msg {
                crate::transport::WsMessage::Binary(data) => {
                    if let Ok((typ, sid, payload)) = c2.crypto.decrypt_with_aead(&data) {
                        match typ {
                            TYPE_DATA => {
                                let ss = c2.streams.read().await;
                                if let Some(tx) = ss.get(&sid) {
                                    // 解密后的 Vec<u8> 转 Bytes 零拷贝分发给逻辑流
                                    let _ = tx.send(Bytes::from(payload));
                                }
                            }
                            TYPE_CLOSE => {
                                c2.streams.write().await.remove(&sid);
                                c2.stream_count.fetch_sub(1, Ordering::Relaxed);
                            }
                            TYPE_DNS => {
                                if payload.len() >= 2 {
                                    let req_id = u16::from_be_bytes([payload[0], payload[1]]);
                                    c2.complete_dns(req_id, payload[2..].to_vec());
                                }
                            }
                            // TYPE_HEART 回显等：仅刷新 last_rx，无需处理
                            _ => {}
                        }
                    }
                }
                // worker 主动关闭（如子请求预算回收）：记录原因用于日志分级
                crate::transport::WsMessage::Close(Some(frame)) => {
                    close_reason = frame.reason.to_string();
                    break;
                }
                _ => {}
            }
        }
        // 结束原因分级：worker 预算回收是设计行为（INFO），其余是真断开（WARN）
        if close_reason.contains("budget") {
            c2.mark_recycled(&format!("worker 会话预算回收: {}", close_reason));
        } else if close_reason.is_empty() {
            c2.mark_dead("WS 读通道结束（对端关闭/网络断开）");
        } else {
            c2.mark_dead(&format!("WS 关闭: {}", close_reason));
        }
        c2.streams.write().await.clear();
    });

    // 心跳任务（带抖动 + 看门狗）
    let c3 = conn.clone();
    tokio::spawn(async move {
        sleep(Duration::from_millis(rand::random_range(0..HEARTBEAT_JITTER_MS / 2))).await;
        loop {
            sleep(jittered_heartbeat_interval()).await;
            if !c3.alive.load(Ordering::Acquire) {
                break;
            }

            // 看门狗：HEARTBEAT_TIMEOUT 内没有任何下行数据（含心跳回显）
            // → 半开 TCP / NAT 重绑定 / 中间设备掐断，主动重置该连接
            let last = c3.last_rx.load(Ordering::Relaxed);
            let idle = now_secs().saturating_sub(last);
            if idle > HEARTBEAT_TIMEOUT.as_secs() {
                c3.mark_dead(&format!(
                    "{}s 无任何下行数据（含心跳回显），判定连接死亡",
                    idle
                ));
                c3.streams.write().await.clear();
                break;
            }

            if let Ok(f) = c3.crypto.encrypt(TYPE_HEART, 0, &[]) {
                if c3
                    .ws_tx
                    .send(crate::transport::ws_message_binary(f))
                    .is_err()
                {
                    break;
                }
            }
        }
    });

    conn
}

fn jittered_heartbeat_interval() -> Duration {
    HEARTBEAT_INTERVAL + Duration::from_millis(rand::random_range(0..HEARTBEAT_JITTER_MS))
}
