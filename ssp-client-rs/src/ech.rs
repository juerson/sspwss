//! 可选 ECH（Encrypted Client Hello）支持。
//!
//! 职责边界（只关心「取配置 → 造 rustls ClientConfig」，不碰连接和代理逻辑）：
//! 1. 从 DoH 查询 `HTTPS` RR 的 `ech` 参数，或使用 `--ech-config` 手工传入；
//! 2. 把 ECHConfigList 交给 rustls，生成带平台证书校验的 `ClientConfig`；
//! 3. 缓存配置（TTL 来自 DNS 记录的 TTL，带上下限），并做负缓存 / 单飞 / 降级冷却。
//!
//! 配置优先级：
//! 1. `--ech-config`（手工 base64，进程内永久有效）
//! 2. 目标 Worker 域名的 HTTPS RR
//! 3. `--ech-domain`（默认 cloudflare-ech.com）的 HTTPS RR
//!
//! 本模块不做任何网络连接，只发 DoH 查询（字面 IP，避免解析环）。

#![allow(dead_code)] // ECH 提供者接口保持完整（mode() 等诊断用）
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use hickory_proto::op::Message;
use hickory_proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
use hickory_proto::rr::{RData, RecordType};
use rustls::client::{EchConfig, EchMode};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::EchConfigListBytes;
use rustls_platform_verifier::BuilderVerifierExt;
use tokio::sync::Mutex;
use log::{debug, info, warn};

use crate::dns::config::{parse_upstream, DnsConfig, DohSpec, UpstreamSpec};
use crate::dns::message::build_query;
use crate::dns::upstream::{DohUpstream, Upstream};

pub const DEFAULT_ECH_DOMAIN: &str = "cloudflare-ech.com";
pub const DEFAULT_ECH_DOH: &str = "https://223.5.5.5/dns-query";

/// DNS 没给 TTL 时的默认缓存时长。
const DEFAULT_CONFIG_TTL: Duration = Duration::from_secs(3600);
/// 防止上游给 0 或过小的 TTL 导致每个连接都去查 DoH。
const MIN_CONFIG_TTL: Duration = Duration::from_secs(30);
/// 防止上游给超大 TTL 导致配置长期不更新。
const MAX_CONFIG_TTL: Duration = Duration::from_secs(6 * 3600);
/// 取配置失败后的负缓存：这段时间内直接回退，不反复打 DoH。
const NEGATIVE_TTL: Duration = Duration::from_secs(60);
/// `auto` 模式连续失败到阈值后，临时不再尝试 ECH，避免每次重连都先多花两次握手。
const DEGRADE_AFTER_FAILURES: u32 = 3;
const DEGRADED_COOLDOWN: Duration = Duration::from_secs(300);

pub type EchError = Box<dyn std::error::Error + Send + Sync>;
pub type EchResult<T> = std::result::Result<T, EchError>;

/// ECH 模式。`off` 不创建任何 ECH 对象；`auto` 失败回退；`on` fail-closed。
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum EchModeArg {
    Off,
    Auto,
    On,
}

#[derive(Clone, Debug)]
pub struct EchSettings {
    pub mode: EchModeArg,
    pub domain: String,
    pub doh: Option<String>,
    pub config_b64: Option<String>,
}

#[derive(Clone, Debug)]
pub struct EchInfo {
    /// `manual` / 目标域名 / `cloudflare-ech.com`
    pub source: String,
    /// ECHConfigList 字节数，仅用于日志诊断。
    pub config_len: usize,
    /// 这条配置还能用多久（来自 DNS TTL，已夹在上下限内）。
    pub ttl: Duration,
}

#[derive(Clone)]
pub struct EchProvider {
    inner: Arc<Inner>,
}

struct Inner {
    mode: EchModeArg,
    domain: String,
    doh: DohSpec,
    /// DoH 端点为域名时，引导阶段（系统 DNS）解析出的地址；
    /// 连接钉住该 IP，TLS SNI/证书校验仍用原域名。字面 IP DoH 时为 None。
    pinned: Option<std::net::SocketAddr>,
    manual: Option<Vec<u8>>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    entry: Option<Cached>,
    negative: Option<Negative>,
    /// `auto` 模式下的降级窗口：窗口内直接走 native-tls。
    degraded_until: Option<Instant>,
    /// 连续「整次连接都失败」的次数（一次连接内部重试只算一次）。
    consecutive_failures: u32,
}

struct Cached {
    target_host: String,
    config: Arc<rustls::ClientConfig>,
    info: EchInfo,
    expires_at: Instant,
}

struct Negative {
    target_host: String,
    until: Instant,
    message: String,
}

struct Fetched {
    bytes: Vec<u8>,
    ttl: Duration,
}

impl EchProvider {
    /// 解析 CLI + dns.yaml，选定 DoH；DoH 端点为域名时在此做引导解析（系统 DNS）。
    pub fn from_settings(settings: EchSettings, dns: &DnsConfig) -> EchResult<Self> {
        let (doh, pinned) = select_doh(settings.doh.as_deref(), dns)?;
        let manual = match settings.config_b64.as_deref() {
            Some(raw) => Some(decode_base64(raw)?),
            None => None,
        };

        Ok(Self {
            inner: Arc::new(Inner {
                mode: settings.mode,
                domain: settings.domain,
                doh,
                pinned,
                manual,
                state: Mutex::new(State::default()),
            }),
        })
    }

    /// 启动期预取配置；失败时由调用方按 mode 决定退出或警告。
    pub async fn warmup(&self, target_host: &str) -> EchResult<EchInfo> {
        self.client_config(target_host).await.map(|(_, info)| info)
    }

    /// 取当前可用的 rustls ClientConfig。
    ///
    /// 并发调用时只有第一个会真正查 DoH，其余在锁上等待后直接命中缓存（单飞）。
    pub async fn client_config(
        &self,
        target_host: &str,
    ) -> EchResult<(Arc<rustls::ClientConfig>, EchInfo)> {
        let mut state = self.inner.state.lock().await;
        let now = Instant::now();

        if self.inner.mode == EchModeArg::Auto {
            if let Some(until) = state.degraded_until {
                if now < until {
                    return Err(format!(
                        "ECH 降级冷却中（{}s 后重试），本次直接走普通 TLS",
                        until.saturating_duration_since(now).as_secs()
                    )
                    .into());
                }
                state.degraded_until = None;
            }
        }

        if let Some(entry) = &state.entry {
            if entry.target_host == target_host && now < entry.expires_at {
                return Ok((entry.config.clone(), entry.info.clone()));
            }
        }

        if let Some(negative) = &state.negative {
            if negative.target_host == target_host && now < negative.until {
                return Err(negative.message.clone().into());
            }
        }

        // 单飞：抓取期间一直持锁，其他调用排队后直接命中上面的缓存/负缓存。
        match self.inner.load(target_host).await {
            Ok((config, info)) => {
                state.entry = Some(Cached {
                    target_host: target_host.to_string(),
                    config: config.clone(),
                    info: info.clone(),
                    expires_at: now + info.ttl,
                });
                state.negative = None;
                Ok((config, info))
            }
            Err(e) => {
                let message = format!("{:#}", e);
                state.negative = Some(Negative {
                    target_host: target_host.to_string(),
                    until: now + NEGATIVE_TTL,
                    message: message.clone(),
                });
                Err(message.into())
            }
        }
    }

    pub fn mode(&self) -> EchModeArg {
        self.inner.mode
    }

    pub fn is_auto(&self) -> bool {
        self.inner.mode == EchModeArg::Auto
    }

    /// 服务端拒绝 ECH 时调用：丢弃当前配置，下一次重新拉取。
    ///
    /// 不清除负缓存与降级状态——「配置过期」和「网络不可用」是两回事。
    pub async fn invalidate(&self) {
        let mut state = self.inner.state.lock().await;
        state.entry = None;
    }

    /// 一整次 ECH 连接（含刷新重试）都失败后调用。
    ///
    /// `auto` 模式连续失败到阈值后进入冷却窗口，窗口内直接走 native-tls，
    /// 避免每次重连都先白跑两轮 ECH 握手。
    pub async fn note_handshake_failure(&self) {
        let mut state = self.inner.state.lock().await;
        state.entry = None;
        state.negative = None;
        state.consecutive_failures += 1;

        if self.inner.mode != EchModeArg::Auto
            || state.consecutive_failures < DEGRADE_AFTER_FAILURES
            || state.degraded_until.is_some()
        {
            return;
        }

        state.degraded_until = Some(Instant::now() + DEGRADED_COOLDOWN);
        warn!(
            "ECH 连续失败 {} 次，{}s 内改用普通 TLS（之后自动重试 ECH）",
            state.consecutive_failures,
            DEGRADED_COOLDOWN.as_secs()
        );
    }

    /// ECH 握手成功后调用，清零失败计数与降级窗口。
    pub async fn note_handshake_success(&self) {
        let mut state = self.inner.state.lock().await;
        state.consecutive_failures = 0;
        state.degraded_until = None;
    }
}

impl Inner {
    async fn load(
        &self,
        target_host: &str,
    ) -> EchResult<(Arc<rustls::ClientConfig>, EchInfo)> {
        if let Some(bytes) = &self.manual {
            let config = build_client_config(bytes.clone())?;
            return Ok((
                config,
                EchInfo {
                    source: "manual".to_string(),
                    config_len: bytes.len(),
                    ttl: DEFAULT_CONFIG_TTL,
                },
            ));
        }

        let mut sources = vec![target_host.to_string()];
        if !self.domain.eq_ignore_ascii_case(target_host) {
            sources.push(self.domain.clone());
        }

        let mut errors = Vec::new();
        for source in sources {
            match fetch_ech_config(&self.doh, self.pinned, &source).await {
                Ok(fetched) => {
                    let config = build_client_config(fetched.bytes.clone())?;
                    info!(
                        "ECH config loaded from {} ({} bytes, ttl={}s)",
                        source,
                        fetched.bytes.len(),
                        fetched.ttl.as_secs()
                    );
                    return Ok((
                        config,
                        EchInfo {
                            source,
                            config_len: fetched.bytes.len(),
                            ttl: fetched.ttl,
                        },
                    ));
                }
                Err(e) => {
                    debug!("no ECH config from {}: {:#}", source, e);
                    errors.push(format!("{}: {:#}", source, e));
                }
            }
        }

        Err(format!("无法获取 ECH 配置（已尝试 {}）", errors.join("; ")).into())
    }
}

/// DoH 端点为域名时，用系统 DNS 做引导解析并钉住结果
/// （连接走解析出的 IP，TLS SNI/证书校验仍用原域名，与 DoH 标准 bootstrap 语义一致）。
/// 这里是一次性引导查询，不会形成解析递归：解析 bootstrap 域名走系统 DNS，不走 DoH 自身。
fn resolve_bootstrap(spec: &DohSpec) -> EchResult<std::net::SocketAddr> {
    use std::net::ToSocketAddrs;

    let target = (spec.host.as_str(), spec.port);
    match target.to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                info!("ECH DoH bootstrap: {} -> {}", spec.host, addr);
                Ok(addr)
            } else {
                Err(format!("ECH DoH 端点域名 {} 解析失败: 无可用地址", spec.host).into())
            }
        }
        Err(e) => Err(format!("ECH DoH 端点域名 {} 解析失败: {}", spec.host, e).into()),
    }
}

fn select_doh(explicit: Option<&str>, dns: &DnsConfig) -> EchResult<(DohSpec, Option<std::net::SocketAddr>)> {
    if let Some(raw) = explicit {
        return match parse_upstream(raw) {
            // 字面 IP DoH：无需引导解析
            Ok(UpstreamSpec::Doh(spec)) if spec.ip.is_some() => Ok((spec, None)),
            // 域名 DoH：引导解析端点后钉住（TLS SNI/证书仍用原域名），与 Go 版行为对齐
            Ok(UpstreamSpec::Doh(spec)) => {
                let addr = resolve_bootstrap(&spec)?;
                Ok((spec, Some(addr)))
            }
            _ => Err("--ech-doh 必须是 DoH URL（例如 https://dns.alidns.com/dns-query 或 https://223.5.5.5/dns-query）".into()),
        };
    }

    if let Some(spec) = dns.default_nameserver.first() {
        return Ok((spec.clone(), None));
    }

    match parse_upstream(DEFAULT_ECH_DOH) {
        Ok(UpstreamSpec::Doh(spec)) if spec.ip.is_some() => Ok((spec, None)),
        _ => Err("没有可用的字面 IP DoH 来获取 ECH 配置；请检查 dns.yaml 或传 --ech-doh".into()),
    }
}

async fn fetch_ech_config(doh: &DohSpec, pinned: Option<std::net::SocketAddr>, domain: &str) -> EchResult<Fetched> {
    let upstream = match pinned {
        Some(addr) => DohUpstream::with_pinned_addr(doh.clone(), addr)?,
        None => DohUpstream::new(doh.clone())?,
    };
    let query = build_query(domain, RecordType::HTTPS)?;
    let wire = upstream.exchange(query).await?;
    let msg = Message::from_vec(&wire)?;

    for record in msg.answers() {
        if let RData::HTTPS(https) = record.data() {
            for (key, value) in https.svc_params() {
                if *key != SvcParamKey::EchConfigList {
                    continue;
                }
                if let SvcParamValue::EchConfigList(list) = value {
                    if !list.0.is_empty() {
                        return Ok(Fetched {
                            bytes: list.0.clone(),
                            ttl: clamp_ttl(record.ttl()),
                        });
                    }
                }
            }
        }
    }

    Err(format!("{} 的 HTTPS RR 没有 ech 参数", domain).into())
}

fn clamp_ttl(ttl: u32) -> Duration {
    if ttl == 0 {
        return DEFAULT_CONFIG_TTL;
    }
    Duration::from_secs(u64::from(ttl)).clamp(MIN_CONFIG_TTL, MAX_CONFIG_TTL)
}

fn build_client_config(bytes: Vec<u8>) -> EchResult<Arc<rustls::ClientConfig>> {
    let ech = EchConfig::new(
        EchConfigListBytes::from(bytes),
        aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
    )
    .map_err(|e| format!("解析 ECHConfigList 失败: {}", e))?;

    let provider = aws_lc_rs::default_provider();
    let config = rustls::ClientConfig::builder_with_provider(provider.into())
        .with_ech(EchMode::Enable(ech))
        .map_err(|e| format!("启用 ECH 失败: {}", e))?
        .with_platform_verifier()
        .map_err(|e| format!("初始化平台证书校验失败: {}", e))?
        .with_no_client_auth();

    Ok(Arc::new(config))
}

fn decode_base64(raw: &str) -> EchResult<Vec<u8>> {
    let raw = raw.trim();
    let engines = [
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
        base64::engine::general_purpose::URL_SAFE,
    ];

    let mut last_error = None;
    for engine in engines {
        match engine.decode(raw) {
            Ok(bytes) if !bytes.is_empty() => return Ok(bytes),
            Ok(_) => last_error = Some("decoded to empty bytes".to_string()),
            Err(e) => last_error = Some(e.to_string()),
        }
    }

    Err(format!(
        "--ech-config base64 解码失败: {}",
        last_error.unwrap_or_default()
    )
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_accepts_standard_and_url_safe() {
        let bytes = decode_base64("aGVsbG8").unwrap();
        assert_eq!(bytes, b"hello");
        let bytes = decode_base64("aGVsbG8=").unwrap();
        assert_eq!(bytes, b"hello");
        let bytes = decode_base64("aGVsbG8").unwrap();
        assert_eq!(bytes, b"hello");
    }

    #[test]
    fn base64_rejects_empty() {
        assert!(decode_base64("").is_err());
    }

    #[test]
    fn ttl_is_clamped() {
        assert_eq!(clamp_ttl(0), DEFAULT_CONFIG_TTL);
        assert_eq!(clamp_ttl(5), MIN_CONFIG_TTL);
        assert_eq!(clamp_ttl(600), Duration::from_secs(600));
        assert_eq!(clamp_ttl(u32::MAX), MAX_CONFIG_TTL);
    }

    #[tokio::test]
    async fn auto_mode_degrades_after_repeated_handshake_failures() {
        let provider = test_provider(EchModeArg::Auto);
        for _ in 0..DEGRADE_AFTER_FAILURES {
            provider.note_handshake_failure().await;
        }

        // 降级窗口内直接报错（调用方会回退 native-tls），不再查 DoH。
        assert!(provider.client_config("worker.invalid").await.is_err());
    }

    #[tokio::test]
    async fn on_mode_never_degrades() {
        let provider = test_provider(EchModeArg::On);
        for _ in 0..DEGRADE_AFTER_FAILURES {
            provider.note_handshake_failure().await;
        }

        let state = provider.inner.state.lock().await;
        assert!(state.degraded_until.is_none());
    }

    fn test_provider(mode: EchModeArg) -> EchProvider {
        // 手工 dummy 配置：只用于状态机测试，不触发网络。
        EchProvider::from_settings(
            EchSettings {
                mode,
                domain: "invalid.example".to_string(),
                doh: None,
                config_b64: Some("aGVsbG8".to_string()),
            },
            &DnsConfig::load(None).unwrap(),
        )
        .unwrap()
    }
}
