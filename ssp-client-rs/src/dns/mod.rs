//! DNS 防泄漏模块。
//!
//! 设计参照（详见《DNS防泄漏设计笔记》）：
#![allow(dead_code)] // 移植的库式接口：部分公共 API 供未来接线（热更新/监听器管理），保持与参考实现接口一致
//! - 管线/缓存/监听器形态抄 clash-rs（`clash-lib/src/app/dns/`）
//! - 边界守卫/字面 IP bootstrap/配置期校验抄 shoes（`src/dns/`）
//! - 上游分组（直连/代理/未知）抄 mihomo 的 `nameserver` + `direct-nameserver`
//!
//! 核心原则：
//! 1. 代理路径域名透传（本地永不解析代理目标）；
//! 2. 路由判定/Direct 连接的解析走 `DnsResolver`，绝不回退系统 DNS（fail-closed）；
//! 3. **解析位置跟随连接出口**：DIRECT 目标用 `direct-nameserver`（国内 DoH，
//!    geo 正确），PROXY/未知目标用 `nameserver`（默认 tunnel:// → Worker DoH，
//!    与出口一致）。这是解决"国内站点被香港解析成海外 CDN IP"的关键；
//! 4. 隧道端点（worker 域名/cf_ip）的解析永不经过本模块 —— bootstrap
//!    边界在 `tunnel::transport::build_ws_connection`，防止解析循环；
//!    `proxy-server-nameserver` 可在建连前用字面 IP DoH 解析 worker 域名；
//! 5. 所有上游结果过禁区守卫（198.18.0.0/15 预留给未来 fake-ip），
//!    防止"合成地址回灌 → 解析环"（shoes guard.rs）。

pub mod cache;
pub mod config;
pub mod guard;
pub mod listener;
pub mod message;
pub mod policy;
pub mod resolver;
pub mod upstream;

pub use config::DnsConfig;
pub use resolver::DnsResolver;

use hickory_proto::op::ResponseCode;
use once_cell::sync::OnceCell;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use log::{error, info, warn};

// ── 全局解析器 / 配置（main 初始化后只读）────────────────────────────────────

static DNS_CONFIG: OnceCell<DnsConfig> = OnceCell::new();
static RESOLVER: OnceCell<Arc<DnsResolver>> = OnceCell::new();

/// main 启动期写入（校验后的 dns.yaml；文件缺失时为内置默认）
pub fn set_dns_config(cfg: DnsConfig) {
    let _ = DNS_CONFIG.set(cfg);
}

pub fn get_dns_config() -> Option<&'static DnsConfig> {
    DNS_CONFIG.get()
}

/// main 启动期写入；proxy 层据此做 fail-closed 直连解析与路由判定
pub fn set_resolver(r: Arc<DnsResolver>) {
    let _ = RESOLVER.set(r);
}

pub fn get_resolver() -> Option<&'static Arc<DnsResolver>> {
    RESOLVER.get()
}

/// 解析结果（含 DNS 响应码）。
///
/// 为什么不直接返回 `Vec<IpAddr>`：本地监听器必须把 NXDOMAIN / NODATA 原样
/// 回给客户端。把 NXDOMAIN 映射成 SERVFAIL 会让浏览器/系统反复重试，
/// 页面里每个广告/统计域名都会拖慢首屏。
#[derive(Debug, Clone, PartialEq)]
pub struct DnsAnswer {
    pub ips: Vec<IpAddr>,
    pub ttl: Duration,
    pub rcode: ResponseCode,
}

impl DnsAnswer {
    pub fn positive(ips: Vec<IpAddr>, ttl: Duration) -> Self {
        Self {
            ips,
            ttl,
            rcode: ResponseCode::NoError,
        }
    }

    pub fn negative(rcode: ResponseCode) -> Self {
        Self {
            ips: Vec::new(),
            ttl: Duration::from_secs(30),
            rcode,
        }
    }

    /// NoError + 无地址（NODATA）：域名存在，但没有该类型的记录。
    pub fn nodata() -> Self {
        Self {
            ips: Vec::new(),
            ttl: Duration::from_secs(30),
            rcode: ResponseCode::NoError,
        }
    }

    pub fn is_positive(&self) -> bool {
        self.rcode == ResponseCode::NoError && !self.ips.is_empty()
    }
}

/// 路由判定结果（与 `proxy::router::RuleAction` 解耦，避免 dns → proxy 的类型依赖）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteClass {
    /// 规则判定直连（用 direct-nameserver 解析，geo 正确）
    Direct,
    /// 规则判定走代理（用 nameserver / proxy-nameserver 解析，与出口一致）
    Proxy,
    /// 没有任何规则命中（用 nameserver 解析）
    Unknown,
}

/// 域名 → 路由类别。由 `ProxyRouter` 实现（纯域名规则匹配，不触发 DNS）。
pub trait RouteClassifier: Send + Sync {
    fn classify_domain(&self, domain: &str) -> RouteClass;
}

/// 构建解析器；`listen` 配置存在时同时启动本地 UDP+TCP 监听器。
///
/// `classifier` 用于把查询域名映射到 direct / proxy 上游组；为 None 时
/// 所有查询都走 `nameserver`（兼容旧行为）。
///
/// 启动期错误（配置非法 / 监听端口被占 / 无可用上游）直接返回，由 `main`
/// 打印人话错误并退出——不静默降级（shoes validate 风格）。
pub async fn start(
    config: DnsConfig,
    tunnel: crate::mux::TunnelDns,
    classifier: Option<Arc<dyn RouteClassifier>>,
) -> Result<Arc<DnsResolver>, DnsError> {
    let resolver = DnsResolver::new(config.clone(), tunnel, classifier).await?;

    if let Some(addr) = config.listen {
        let listener = listener::DnsListener::bind(addr, resolver.clone())
            .await
            .map_err(|e| DnsError(e.to_string()))?;
        info!("🔎 DNS listener enabled on {}", addr);
        tokio::spawn(async move {
            if let Err(e) = listener.run().await {
                error!("DNS listener stopped: {}", e);
            }
        });
    }

    Ok(resolver)
}

/// 建立隧道前解析 worker 域名（`proxy-server-nameserver` / `default-nameserver`）。
///
/// 这就是 mihomo 的 `proxy-server-nameserver`：用**字面 IP 的 DoH** 解析
/// 隧道端点，避免本地系统 DNS 看到 worker 域名（残余泄漏面之一）。
///
/// 返回 None 时调用方回退系统解析（保持原有可用性）。
pub async fn resolve_tunnel_endpoint(
    config: &DnsConfig,
    host: &str,
    port: u16,
) -> Option<SocketAddr> {
    if host.parse::<IpAddr>().is_ok() {
        return None; // 已经是字面 IP，无需解析
    }
    let servers = if config.proxy_server_nameserver.is_empty() {
        config.default_nameserver.clone()
    } else {
        config.proxy_server_nameserver.clone()
    };
    if servers.is_empty() {
        return None;
    }
    let bootstrap = resolver::BootstrapResolver::new(servers);
    match bootstrap.resolve_host(host, port).await {
        Ok(addr) => {
            info!(
                "🔐 Tunnel endpoint {} resolved to {} via bootstrap DoH",
                host, addr
            );
            Some(addr)
        }
        Err(e) => {
            warn!(
                "Tunnel endpoint {} bootstrap failed ({}), falling back to system DNS",
                host, e
            );
            None
        }
    }
}

/// DNS 模块统一错误（Clone 以便 singleflight 共享结果）。
#[derive(Debug, Clone)]
pub struct DnsError(pub String);

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for DnsError {}

/// 真实 DNS 返回了禁区内的地址（可能是解析环/污染）—— shoes `SyntheticDnsAnswer` 对应物。
#[derive(Debug, Clone)]
pub struct SyntheticDnsAnswer;

impl fmt::Display for SyntheticDnsAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "real DNS returned a forbidden address (possible DNS loop)"
        )
    }
}

pub type DnsResult<T> = Result<T, DnsError>;
