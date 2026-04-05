#![allow(unused)]
mod proxy;
mod routing;
mod ws;
mod rules;

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use clap::Parser;
use hkdf::Hkdf;
use once_cell::sync::OnceCell;
use parking_lot::RwLock;
use proxy::run_proxy_server;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    error::Error,
    io::{Error as IoError, Write},
    net::IpAddr,
    net::SocketAddr,
    process,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use ws::dial_websocket;
use x25519_dalek::{PublicKey, StaticSecret};

const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const TYPE_DATA: u8 = 0x01;
const TYPE_OPEN: u8 = 0x02;
const TYPE_CLOSE: u8 = 0x03;
const TYPE_HEART: u8 = 0x05;
const CONN_TIMEOUT: Duration = Duration::from_secs(10);
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const WS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const WS_READ_DEADLINE: Duration = Duration::from_secs(120);
const WS_MAX_RECONNECT: i32 = 5;
const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(8);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(90);
const DNS_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const TIME_WINDOW_SEC: i64 = 300;
const OPEN_PAYLOAD_MIN: usize = 256;

// ==============================================================================
// CLI args
// ==============================================================================

#[derive(Parser, Debug)]
#[command(name = "ssp-core", about = "A proxy client core")]
pub struct Args {
    #[arg(short, long, default_value = "127.0.0.1:30000")]
    listen: String,

    #[arg(short, long, required = true)]
    server: String,

    #[arg(long, default_value = "")]
    ip: String,

    #[arg(short, long, required = true)]
    token: String,

    #[arg(long, default_value = "global")]
    routing: String,

    #[arg(
        long,
        default_value = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
            AppleWebKit/537.36 (KHTML, like Gecko) \
            Chrome/146.0.0.0 Safari/537.36"
    )]
    ua: String,

    #[arg(long, default_value = "")]
    fallback: String,
}

static ARGS: OnceCell<Args> = OnceCell::new();

pub fn get_args() -> &'static Args {
    ARGS.get().expect("Args not initialized")
}

// ==============================================================================
// DNS cache
// ==============================================================================

pub struct DnsCache {
    store: RwLock<HashMap<String, DnsCacheEntry>>,
}

#[derive(Clone)]
pub struct DnsCacheEntry {
    pub addrs: Vec<SocketAddr>,
    pub expires: Instant,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            store: RwLock::new(HashMap::new()),
        }
    }

    pub fn get(&self, host: &str) -> Option<Vec<SocketAddr>> {
        let store = self.store.read();
        store.get(host).and_then(|e| {
            if Instant::now() < e.expires {
                Some(e.addrs.clone())
            } else {
                None
            }
        })
    }

    pub fn set(&self, host: String, addrs: Vec<SocketAddr>) {
        self.store.write().insert(
            host,
            DnsCacheEntry {
                addrs,
                expires: Instant::now() + DNS_CACHE_TTL,
            },
        );
    }
}

static GLOBAL_DNS_CACHE: OnceCell<DnsCache> = OnceCell::new();

pub fn get_dns_cache() -> &'static DnsCache {
    GLOBAL_DNS_CACHE.get_or_init(DnsCache::new)
}

// ==============================================================================
// replay-attack prevention
// ==============================================================================

pub struct ReplayWindow {
    max_seen: u64,
    bitmap: u64,
    initialized: bool,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            max_seen: 0,
            bitmap: 0,
            initialized: false,
        }
    }

    pub fn check(&mut self, n: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.max_seen = n;
            self.bitmap = 1;
            return true;
        }
        if n > self.max_seen {
            let shift = n - self.max_seen;
            self.bitmap = if shift >= 64 {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.max_seen = n;
            return true;
        }
        let diff = self.max_seen - n;
        if diff >= 64 {
            return false;
        }
        let bit = 1u64 << diff;
        if self.bitmap & bit != 0 {
            return false;
        }
        self.bitmap |= bit;
        true
    }
}

// ==============================================================================
// random pool
//
// Changed: pos is now AtomicUsize instead of RwLock<usize>.
// The original code held buf.write() while calling pos.read() then pos.write(),
// which works but is awkward.  Using an atomic removes the nested lock pattern
// and makes the intent clearer.  For the padding use-case here (non-key-material)
// minor races between threads are acceptable.
// ==============================================================================

pub struct RandPool {
    buf: RwLock<[u8; 4096]>,
    pos: AtomicUsize,
}

impl RandPool {
    pub fn new() -> Self {
        // Start at end so the first read always triggers a fresh fill.
        Self {
            buf: RwLock::new([0u8; 4096]),
            pos: AtomicUsize::new(4096),
        }
    }

    pub fn read(&self, dst: &mut [u8]) -> Result<(), IoError> {
        if dst.is_empty() {
            return Ok(());
        }
        // Large requests bypass the pool.
        if dst.len() > 4096 {
            rand::fill(dst);
            return Ok(());
        }

        let len = dst.len();
        let pos = self.pos.fetch_add(len, Ordering::Relaxed);

        if pos + len <= 4096 {
            // Common path: read from existing buffer.
            dst.copy_from_slice(&self.buf.read()[pos..pos + len]);
        } else {
            // Refill.  Multiple threads may race here; the last writer wins,
            // but for non-cryptographic padding that is fine.
            let mut buf = self.buf.write();
            rand::fill(&mut *buf);
            self.pos.store(len, Ordering::Relaxed);
            dst.copy_from_slice(&buf[..len]);
        }
        Ok(())
    }
}

static GLOBAL_RAND_POOL: OnceCell<RandPool> = OnceCell::new();

pub fn get_rand_pool() -> &'static RandPool {
    GLOBAL_RAND_POOL.get_or_init(RandPool::new)
}

// ==============================================================================
// ECDH handshake + session key derivation
// ==============================================================================

pub struct Handshake {
    psk: Vec<u8>,
    private_key: StaticSecret,
    public_key: PublicKey,
    handshake_aead: Aes256Gcm,
}

impl Handshake {
    pub fn new(psk: &[u8]) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);

        let hk = Hkdf::<Sha256>::new(Some(&[0u8; 16]), psk);
        let mut hkdf_key = [0u8; 32];
        hk.expand(b"sspv1.4-handshake", &mut hkdf_key)
            .map_err(|_| "HKDF expand failed")?;

        Ok(Self {
            psk: psk.to_vec(),
            private_key,
            public_key,
            handshake_aead: Aes256Gcm::new_from_slice(&hkdf_key)?,
        })
    }

    pub fn decrypt_peer_pub_key(
        &self,
        data: &[u8],
    ) -> Result<[u8; 32], Box<dyn Error + Send + Sync>> {
        if data.len() < NONCE_SIZE + TAG_SIZE {
            return Err("handshake packet too short".into());
        }
        let nonce = Nonce::from_slice(&data[..NONCE_SIZE]);
        let plain = self
            .handshake_aead
            .decrypt(nonce, &data[NONCE_SIZE..])
            .map_err(|_| "decrypt failed")?;
        if plain.len() < 32 {
            return Err("handshake plaintext too short".into());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&plain[..32]);
        Ok(key)
    }

    pub fn encrypt_own_pub_key(&self) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let pad_len = 16 + rand::random_range(0..32) as usize;
        let mut plain = vec![0u8; 32 + pad_len];
        plain[..32].copy_from_slice(self.public_key.as_bytes());
        rand::fill(&mut plain[32..]);

        let ciphertext = self
            .handshake_aead
            .encrypt(nonce, plain.as_ref())
            .map_err(|_| "encrypt failed")?;

        let mut out = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn derive_shared_secret(
        &self,
        peer_pub_key: &[u8],
    ) -> Result<[u8; 32], Box<dyn Error + Send + Sync>> {
        if peer_pub_key.len() != 32 {
            return Err("invalid peer pub key length".into());
        }
        let mut peer_arr = [0u8; 32];
        peer_arr.copy_from_slice(peer_pub_key);
        let shared = self.private_key.diffie_hellman(&PublicKey::from(peer_arr));
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.as_bytes());
        Ok(out)
    }

    pub fn complete_with_secret(
        &self,
        shared_secret: [u8; 32],
    ) -> Result<Arc<Session>, Box<dyn Error + Send + Sync>> {
        let salt = self.derive_session_salt(&shared_secret)?;
        let (tx_key, rx_key) = self.derive_session_keys(&shared_secret, &salt)?;
        Ok(Arc::new(Session {
            tx_aead: Aes256Gcm::new_from_slice(&tx_key)?,
            rx_aead: Aes256Gcm::new_from_slice(&rx_key)?,
            salt: salt[..4].to_vec(),
            nonce_counter: AtomicU64::new(0),
            replay: RwLock::new(ReplayWindow::new()),
            time_window_sec: TIME_WINDOW_SEC,
        }))
    }

    fn derive_session_salt(&self, shared: &[u8]) -> Result<[u8; 16], Box<dyn Error + Send + Sync>> {
        let hk = Hkdf::<Sha256>::new(Some(&self.psk), shared);
        let mut okm = [0u8; 16];
        hk.expand(b"sspv1.4-salt", &mut okm)
            .map_err(|_| "HKDF expand failed")?;
        Ok(okm)
    }

    fn derive_session_keys(
        &self,
        shared: &[u8],
        salt: &[u8],
    ) -> Result<([u8; 32], [u8; 32]), Box<dyn Error + Send + Sync>> {
        // Note: label inversion is intentional – mirrors the server-side derivation.
        let rx_key = self.derive_key(shared, salt, b"sspv1.4-tx")?;
        let tx_key = self.derive_key(shared, salt, b"sspv1.4-rx")?;
        Ok((tx_key, rx_key))
    }

    fn derive_key(
        &self,
        ikm: &[u8],
        salt: &[u8],
        purpose: &[u8],
    ) -> Result<[u8; 32], Box<dyn Error + Send + Sync>> {
        let mut info = Vec::with_capacity(purpose.len() + 1 + salt.len());
        info.extend_from_slice(purpose);
        info.push(0);
        info.extend_from_slice(salt);

        let hk = Hkdf::<Sha256>::new(Some(&self.psk), ikm);
        let mut okm = [0u8; 32];
        hk.expand(&info, &mut okm)
            .map_err(|_| "HKDF expand failed")?;
        Ok(okm)
    }
}

// ==============================================================================
// encrypted session
// ==============================================================================

pub struct Session {
    tx_aead: Aes256Gcm,
    rx_aead: Aes256Gcm,
    salt: Vec<u8>,
    nonce_counter: AtomicU64,
    replay: RwLock<ReplayWindow>,
    time_window_sec: i64,
}

impl Session {
    pub fn encrypt(
        &self,
        msg_type: u8,
        stream_id: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let plain = self.build_frame(msg_type, stream_id, payload)?;
        let nonce_val = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[..8].copy_from_slice(&nonce_val.to_be_bytes());
        nonce[8..].copy_from_slice(&self.salt);
        let nonce = Nonce::from_slice(&nonce);
        let ciphertext = self
            .tx_aead
            .encrypt(nonce, plain.as_ref())
            .map_err(|_| "encrypt failed")?;
        let mut out = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn build_frame(
        &self,
        msg_type: u8,
        stream_id: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let mut pad_byte = [0u8; 1];
        get_rand_pool().read(&mut pad_byte)?;
        let pad_len = (pad_byte[0] & 0x7F) as usize;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let mut frame = Vec::with_capacity(8 + payload.len() + pad_len);
        frame.push(msg_type);
        frame.push(stream_id);
        frame.extend_from_slice(&timestamp.to_be_bytes());
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);

        if pad_len > 0 {
            let mut pad = vec![0u8; pad_len];
            get_rand_pool().read(&mut pad)?;
            frame.extend_from_slice(&pad);
        }
        Ok(frame)
    }

    pub fn decrypt_with_aead(
        &self,
        data: &[u8],
    ) -> Result<(u8, u8, Vec<u8>), Box<dyn Error + Send + Sync>> {
        if data.len() < NONCE_SIZE + TAG_SIZE {
            return Err("frame too short".into());
        }
        let nonce = Nonce::from_slice(&data[..NONCE_SIZE]);
        let plaintext = self
            .rx_aead
            .decrypt(nonce, &data[NONCE_SIZE..])
            .map_err(|_| "decrypt failed")?;
        self.check_replay(&plaintext, &data[..NONCE_SIZE])?;
        self.parse_frame(&plaintext)
    }

    fn check_replay(
        &self,
        plaintext: &[u8],
        nonce: &[u8],
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if plaintext.len() < 8 {
            return Err("plaintext too short".into());
        }
        let timestamp =
            u32::from_be_bytes([plaintext[2], plaintext[3], plaintext[4], plaintext[5]]) as i64;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        if (now - timestamp).abs() > self.time_window_sec {
            return Err("timestamp out of window".into());
        }
        let n = u64::from_be_bytes([
            nonce[0], nonce[1], nonce[2], nonce[3], nonce[4], nonce[5], nonce[6], nonce[7],
        ]);
        if !self.replay.write().check(n) {
            return Err("replay detected".into());
        }
        Ok(())
    }

    fn parse_frame(&self, data: &[u8]) -> Result<(u8, u8, Vec<u8>), Box<dyn Error + Send + Sync>> {
        if data.len() < 8 {
            return Err("frame too short".into());
        }
        let payload_len = u16::from_be_bytes([data[6], data[7]]) as usize;
        let end = 8 + payload_len;
        if end > data.len() {
            return Err("invalid frame length".into());
        }
        Ok((data[0], data[1], data[8..end].to_vec()))
    }
}

// ==============================================================================
// target validation + OPEN payload
// ==============================================================================

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
    if s.parse::<IpAddr>().is_ok() {
        return true;
    }
    !s.is_empty() && !s.chars().any(|c| c.is_whitespace())
}

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
        get_rand_pool().read(&mut pad).ok();
        raw.push(0x00);
        raw.extend_from_slice(&pad);
    }
    raw
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            let timestamp = chrono::Local::now().format("%H:%M:%S%.3f");
            writeln!(buf, "{} {} {}", timestamp, record.level(), record.args())
        })
        .init();

    let args = Args::parse();
    ARGS.set(args).map_err(|_| "Failed to set args")?;

    let args = get_args();
    if args.server.is_empty() || args.token.is_empty() {
        log::error!(
            "必须指定 -s 服务端地址 和 -t 令牌\n示例:\n  \
             ./client -l 127.0.0.1:30000 -s your.worker.dev:443 -t YOUR-PSK"
        );
        process::exit(1);
    }

    // 无论何种路由模式都调用 init_routing：
    //   · global / none  → 只设置 ROUTING_MODE，无 I/O
    //   · 国家代码        → 加载/下载 mmdb，启动后台更新任务
    //   · 规则文件        → 内部判断
    routing::init_routing().await;

    // 提前触发连接池初始化，在第一个请求到来前预建 WS 连接。
    // get_mux_pool() 是懒初始化，首次调用时创建 MuxPool 结构
    let _ = ws::get_mux_pool();

    run_proxy_server(&args.listen).await;

    Ok(())
}
