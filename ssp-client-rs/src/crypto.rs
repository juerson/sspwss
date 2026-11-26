//! 协议层：SSP 帧常量、AES-256-GCM 会话加密、X25519 ECDH 握手、
//! 重放防护、随机池与帧填充策略。
//!
//! 分层边界：本模块只关心"字节如何加密/成帧"，不碰任何 I/O
//! （连接建立在 transport.rs，多路复用在 mux.rs）。

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use once_cell::sync::OnceCell;
use parking_lot::RwLock;
use sha2::Sha256;
use std::{
    error::Error,
    io::Error as IoError,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use x25519_dalek::{PublicKey, StaticSecret};

// ── 协议常量 ─────────────────────────────────────────────────────────────────

pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const TYPE_DATA: u8 = 0x01;
pub const TYPE_OPEN: u8 = 0x02;
pub const TYPE_CLOSE: u8 = 0x03;
pub const TYPE_DNS: u8 = 0x04;
pub const TYPE_HEART: u8 = 0x05;
/// 重放保护时间窗口
pub const TIME_WINDOW_SEC: i64 = 300;

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
// pos 用 AtomicUsize 而非 RwLock<usize>：去掉"持写锁再读写锁"的嵌套锁模式。
// padding 属非密钥用途，多线程间轻微竞态可接受。
// ==============================================================================

pub struct RandPool {
    buf: RwLock<[u8; 4096]>,
    pos: AtomicUsize,
}

impl RandPool {
    pub fn new() -> Self {
        // 从末尾起步，首次读取必定触发重新填充
        Self {
            buf: RwLock::new([0u8; 4096]),
            pos: AtomicUsize::new(4096),
        }
    }

    pub fn read(&self, dst: &mut [u8]) -> Result<(), IoError> {
        if dst.is_empty() {
            return Ok(());
        }
        // 大请求绕过池
        if dst.len() > 4096 {
            rand::fill(dst);
            return Ok(());
        }

        let len = dst.len();
        let pos = self.pos.fetch_add(len, Ordering::Relaxed);

        if pos + len <= 4096 {
            // 常规路径：从现有缓冲读取
            dst.copy_from_slice(&self.buf.read()[pos..pos + len]);
        } else {
            // 重新填充。多线程可能竞争；最后写者胜出，对非加密 padding 可接受
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
        // 注意：label 交换是有意的 —— 与服务端派生方式对应
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

/// 帧填充策略
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PadPolicy {
    /// 随机 0~127 字节（v1.4 原行为）
    Random,
    /// 桶内随机 padding：帧总长抬到 512/1024/2048 桶内，
    /// 用于每流第一个 DATA 帧（通常是 TLS ClientHello），破坏 TLS-in-TLS 长度指纹
    Bucket,
}

pub struct Session {
    tx_aead: Aes256Gcm,
    rx_aead: Aes256Gcm,
    salt: Vec<u8>,
    nonce_counter: AtomicU64,
    replay: RwLock<ReplayWindow>,
}

impl Session {
    pub fn encrypt(
        &self,
        msg_type: u8,
        stream_id: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        self.encrypt_with_pad(msg_type, stream_id, payload, PadPolicy::Random)
    }

    pub fn encrypt_with_pad(
        &self,
        msg_type: u8,
        stream_id: u8,
        payload: &[u8],
        policy: PadPolicy,
    ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let plain = self.build_frame(msg_type, stream_id, payload, policy)?;
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
        policy: PadPolicy,
    ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let pad_len = match policy {
            PadPolicy::Random => {
                let mut pad_byte = [0u8; 1];
                get_rand_pool().read(&mut pad_byte)?;
                (pad_byte[0] & 0x7F) as usize
            }
            PadPolicy::Bucket => {
                // 桶内随机：把帧总长抬到 512/1024/2048 桶内并加抖动，
                // 破坏 TLS-in-TLS ClientHello 的长度指纹（v1.5 隐蔽性加固）。
                // 服务端按 Payload Len 字段读取 payload，额外 padding 字节无感知。
                let base = 8 + payload.len();
                if base + 32 >= 2048 {
                    let mut pad_byte = [0u8; 1];
                    get_rand_pool().read(&mut pad_byte)?;
                    (pad_byte[0] & 0x7F) as usize
                } else {
                    let target = [512usize, 1024, 2048]
                        .into_iter()
                        .find(|&t| t > base + 32)
                        .unwrap_or(2048);
                    let mut pad_byte = [0u8; 1];
                    get_rand_pool().read(&mut pad_byte)?;
                    let jitter = (pad_byte[0] & 0x1F) as usize;
                    target - base - jitter
                }
            }
        };

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
        if (now - timestamp).abs() > TIME_WINDOW_SEC {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 从 Handshake 的中间产物构造「服务端视角」的会话：
    /// 服务端 tx = derive("tx")、rx = derive("rx")，与客户端的标签方向相反。
    /// （真实服务端是 worker.js；本 helper 仅为单测构建对端。）
    fn complete_as_server(h: &Handshake, shared: [u8; 32]) -> Arc<Session> {
        let salt = h.derive_session_salt(&shared).unwrap();
        // derive_session_keys 返回 (客户端 tx=derive("rx"), 客户端 rx=derive("tx"))
        let (client_tx_key, client_rx_key) = h.derive_session_keys(&shared, &salt).unwrap();
        Arc::new(Session {
            tx_aead: Aes256Gcm::new_from_slice(&client_rx_key).unwrap(),
            rx_aead: Aes256Gcm::new_from_slice(&client_tx_key).unwrap(),
            salt: salt[..4].to_vec(),
            nonce_counter: AtomicU64::new(0),
            replay: RwLock::new(ReplayWindow::new()),
        })
    }

    /// 完成一次 client↔server 握手，返回两侧会话
    fn paired_sessions(psk: &[u8]) -> (Arc<Session>, Arc<Session>) {
        let client_hs = Handshake::new(psk).unwrap();
        let server_hs = Handshake::new(psk).unwrap();

        // 客户端 → 服务端公钥
        let c_hello = client_hs.encrypt_own_pub_key().unwrap();
        let client_pub = server_hs.decrypt_peer_pub_key(&c_hello).unwrap();
        let shared_s = server_hs.derive_shared_secret(&client_pub).unwrap();
        let server = complete_as_server(&server_hs, shared_s);

        // 服务端 → 客户端公钥
        let s_hello = server_hs.encrypt_own_pub_key().unwrap();
        let server_pub = client_hs.decrypt_peer_pub_key(&s_hello).unwrap();
        let shared_c = client_hs.derive_shared_secret(&server_pub).unwrap();
        let client = client_hs.complete_with_secret(shared_c).unwrap();

        (client, server)
    }

    #[test]
    fn replay_window_accepts_and_rejects() {
        let mut w = ReplayWindow::new();
        assert!(w.check(1));
        assert!(w.check(2));
        assert!(w.check(5));
        assert!(!w.check(2), "重复 nonce 必须拒绝");
        assert!(!w.check(1), "重复 nonce 必须拒绝");
        assert!(w.check(6));
        assert!(w.check(70));
        assert!(!w.check(5), "窗口外旧 nonce 拒绝");
    }

    #[test]
    fn replay_window_shift_resets() {
        let mut w = ReplayWindow::new();
        assert!(w.check(0));
        assert!(w.check(200));
        // 大跳跃后位图重置
        assert!(w.check(1000));
        assert!(!w.check(1000));
    }

    #[test]
    fn handshake_roundtrip_between_client_and_server() {
        let (client, server) = paired_sessions(b"test-psk-for-crypto-roundtrip");

        // client → server
        let wire = client.encrypt(TYPE_DATA, 7, b"hello world").unwrap();
        let (typ, sid, payload) = server.decrypt_with_aead(&wire).unwrap();
        assert_eq!((typ, sid), (TYPE_DATA, 7));
        assert_eq!(payload, b"hello world");

        // server → client
        let wire = server.encrypt(TYPE_DATA, 9, b"pong").unwrap();
        let (typ, sid, payload) = client.decrypt_with_aead(&wire).unwrap();
        assert_eq!((typ, sid), (TYPE_DATA, 9));
        assert_eq!(payload, b"pong");
    }

    #[test]
    fn decrypt_rejects_tampered_and_replayed() {
        let (client, server) = paired_sessions(b"test-psk-for-crypto-roundtrip");

        let wire = client.encrypt(TYPE_DATA, 1, b"abc").unwrap();
        assert!(server.decrypt_with_aead(&wire).is_ok());

        let mut tampered = wire.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        assert!(server.decrypt_with_aead(&tampered).is_err(), "篡改必须失败");

        assert!(server.decrypt_with_aead(&wire).is_err(), "重放必须失败");
    }

    #[test]
    fn bucket_padding_lands_in_target_bucket() {
        let (client, _server) = paired_sessions(b"test-psk-for-crypto-roundtrip");

        // payload 100B → 帧基长 108 → 目标桶 512，抖动 0~31 → 明文总长 481~512
        let wire = client
            .encrypt_with_pad(TYPE_DATA, 1, &[0u8; 100], PadPolicy::Bucket)
            .unwrap();
        let plaintext_len = wire.len() - NONCE_SIZE - TAG_SIZE;
        assert!(
            (481..=512).contains(&plaintext_len),
            "帧明文总长应落在 512 桶内（抖动 0~31），实际 {}",
            plaintext_len
        );

        // 大 payload 不做桶填充，退回随机 padding（0~127）
        let wire = client
            .encrypt_with_pad(TYPE_DATA, 1, &[0u8; 4096], PadPolicy::Bucket)
            .unwrap();
        let plaintext_len = wire.len() - NONCE_SIZE - TAG_SIZE;
        assert!(
            (8 + 4096..=8 + 4096 + 127).contains(&plaintext_len),
            "大 payload 应回退随机 padding，实际 {}",
            plaintext_len
        );
    }

    #[test]
    fn rand_pool_reads_are_bounded() {
        let pool = RandPool::new();
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        pool.read(&mut a).unwrap();
        pool.read(&mut b).unwrap();
        // 两次读取内容不可能相同（128 位随机碰撞概率可忽略）
        assert_ne!(a, b);

        // 超大请求绕过池直接填充
        let mut big = vec![0u8; 8192];
        pool.read(&mut big).unwrap();
        assert!(big.iter().any(|&x| x != 0));
    }
}
