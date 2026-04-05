#![allow(unused)]

use crate::{get_args, rules::RuleAction};
use maxminddb::Reader;
use once_cell::sync::OnceCell;
use parking_lot::RwLock;
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::time::sleep;

// ══════════════════════════════════════════════════════════════════════════════
// 路由模式
//   None    → 全部直连
//   Global  → 全部走代理（默认）
//   Country → 目标 IP 属于指定国家时直连，否则走代理
//   Rule    → 使用 rules.yaml 规则引擎
// ══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
enum RoutingMode {
    None,
    Global,
    Country(String),
    Rule,
}

static ROUTING_MODE: OnceCell<RoutingMode> = OnceCell::new();

fn routing_mode() -> &'static RoutingMode {
    ROUTING_MODE.get().unwrap_or(&RoutingMode::Global)
}

fn parse_mode(s: &str) -> RoutingMode {
    match s.to_ascii_lowercase().trim() {
        "none" => RoutingMode::None,
        "global" | "" => RoutingMode::Global,
        "rule" | "rules" => RoutingMode::Rule,
        "bypass_cn" | "cn" => RoutingMode::Country("CN".into()),
        other => {
            let code = other.to_ascii_uppercase();
            if code.len() == 2 && code.chars().all(|c| c.is_ascii_alphabetic()) {
                log::info!("[路由] 直连 {} 国家", code);
                RoutingMode::Country(code)
            } else {
                log::warn!("[路由] 未识别的 routing 参数 {:?}，使用 global", s);
                RoutingMode::Global
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// GeoIP MMDB 管理（加载 / 下载 / 热更新）
// ══════════════════════════════════════════════════════════════════════════════

/// 按顺序尝试的下载镜像
const MIRRORS: &[&str] = &[
    "https://hk.gh-proxy.org/https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb",
    "https://cdn.jsdelivr.net/gh/P3TERX/GeoLite.mmdb@download/GeoLite2-Country.mmdb",
    "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb",
];

const UPDATE_INTERVAL: Duration = Duration::from_secs(24 * 3600);

type MmdbReader = Reader<Vec<u8>>;
static MMDB: OnceCell<RwLock<Option<Arc<MmdbReader>>>> = OnceCell::new();

fn mmdb_cell() -> &'static RwLock<Option<Arc<MmdbReader>>> {
    MMDB.get_or_init(|| RwLock::new(None))
}

/// 从磁盘读取并解析 mmdb，成功后写入全局单例
fn load_mmdb(path: &std::path::Path) {
    match std::fs::read(path) {
        Err(e) => log::error!("[路由] 读取 mmdb 失败: {}", e),
        Ok(data) => match Reader::from_source(data) {
            Err(e) => log::error!("[路由] 解析 mmdb 失败: {}", e),
            Ok(r) => {
                *mmdb_cell().write() = Some(Arc::new(r));
                log::info!("[路由] mmdb 加载完成: {}", relative_to_exe(path));
            }
        },
    }
}

/// 依次尝试各镜像下载 mmdb，全部失败才返回错误；成功后原子替换目标文件
async fn download_mmdb(
    dest: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir)?;
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(90))
        .user_agent(get_args().ua.clone())
        .build()?;

    let tmp = dest.with_extension("tmp");

    for &url in MIRRORS {
        log::debug!("[路由] 尝试下载: {}", url);
        let resp = match client.get(url).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                log::warn!("[路由] HTTP {}: {}", r.status(), url);
                continue;
            }
            Err(e) => {
                log::warn!("[路由] 请求失败 {}: {}", url, e);
                continue;
            }
        };

        let bytes = resp.bytes().await?;
        if bytes.len() < 512 * 1024 {
            log::warn!("[路由] 响应过小 ({} bytes)，跳过: {}", bytes.len(), url);
            continue;
        }

        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, dest)?;
        log::info!(
            "[路由] mmdb 下载完成 ({:.1} MB)",
            bytes.len() as f64 / 1_048_576.0
        );
        return Ok(());
    }

    Err("所有镜像均下载失败".into())
}

/// 后台任务：每 24 小时检查 mmdb 是否过期，过期则重新下载；失败时 1 小时后重试
async fn background_updater(path: PathBuf) {
    loop {
        let age = file_age(&path);
        if age < UPDATE_INTERVAL {
            let wait = UPDATE_INTERVAL - age;
            log::debug!(
                "[路由] mmdb 将在 {:.1}h 后自动更新",
                wait.as_secs_f64() / 3600.0
            );
            sleep(wait).await;
        }

        log::info!("[路由] 后台更新 mmdb…");
        match download_mmdb(&path).await {
            Ok(_) => {
                load_mmdb(&path);
                log::info!("[路由] mmdb 热更新完成");
            }
            Err(e) => {
                log::error!("[路由] mmdb 更新失败: {}，1 小时后重试", e);
                sleep(Duration::from_secs(3600)).await;
            }
        }
    }
}

// ── 路径辅助 ──────────────────────────────────────────────────────────────────

fn mmdb_path() -> PathBuf {
    exe_dir().join("mmdb").join("GeoLite2-Country.mmdb")
}

fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn file_age(path: &std::path::Path) -> Duration {
    std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .unwrap_or(Duration::MAX)
}

fn relative_to_exe(path: &std::path::Path) -> String {
    std::env::current_exe()
        .ok()
        .and_then(|exe| {
            exe.parent()
                .and_then(|base| path.strip_prefix(base).ok())
                .map(|rel| rel.display().to_string())
        })
        .unwrap_or_else(|| path.display().to_string())
}

// ══════════════════════════════════════════════════════════════════════════════
// DNS 解析辅助
//   统一封装带超时的 DNS 查询，并复用 DNS 缓存。
//   缓存写入由调用方决定（避免重复写入）。
// ══════════════════════════════════════════════════════════════════════════════

/// 带超时的 DNS 查询，返回 None 表示解析失败或超时（安全回退：走代理）
async fn dns_resolve(host: &str) -> Option<Vec<SocketAddr>> {
    tokio::time::timeout(
        crate::DNS_QUERY_TIMEOUT,
        tokio::net::lookup_host(format!("{}:0", host)),
    )
    .await
    .ok()?
    .ok()
    .map(|iter| iter.collect())
}

// ══════════════════════════════════════════════════════════════════════════════
// Country 模式：GeoIP 国家匹配
// ══════════════════════════════════════════════════════════════════════════════

/// 查询内存 MMDB，返回 IP 对应的国家代码（大写，如 "CN"）
fn ip_country(ip: IpAddr) -> Option<String> {
    let guard = mmdb_cell().read();
    let reader = guard.as_ref()?;
    let lookup = reader.lookup(ip).ok()?;
    if let Some(country) = lookup.decode::<maxminddb::geoip2::Country>().ok()? {
        country
            .country
            .iso_code
            .map(|c: &str| c.to_ascii_uppercase())
    } else {
        None
    }
}

/// 判断 host 是否属于指定国家（先查缓存，再 DNS 解析）
async fn host_matches_country(host: &str, code: &str) -> bool {
    // 裸 IP：直接查询
    if let Ok(ip) = host.parse::<IpAddr>() {
        return ip_country(ip).as_deref() == Some(code);
    }

    // DNS 缓存命中
    if let Some(addrs) = crate::get_dns_cache().get(host) {
        return addrs
            .iter()
            .any(|a| ip_country(a.ip()).as_deref() == Some(code));
    }

    // DNS 解析（超时/失败 → false，安全回退为走代理）
    match dns_resolve(host).await {
        Some(addrs) => {
            let hit = addrs
                .iter()
                .any(|a| ip_country(a.ip()).as_deref() == Some(code));
            crate::get_dns_cache().set(host.to_string(), addrs);
            hit
        }
        None => false,
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Rule 模式：域名 → IP 回退路由
//   规则引擎优先匹配域名规则；未命中时解析 IP 后再匹配 IP/GeoIP 规则。
// ══════════════════════════════════════════════════════════════════════════════

async fn resolve_action(router: &'static crate::rules::ProxyRouter, host: &str) -> RuleAction {
    // 1. 域名索引直接命中
    let action = router.route_domain(host);
    if action != *router.default_action() {
        return action;
    }

    // 2. 裸 IP：跳过 DNS，直接走 IP 路由
    if let Ok(ip) = host.parse::<IpAddr>() {
        return router.route_ip(&ip);
    }

    // 3. DNS 缓存命中，按已有 IP 路由
    if let Some(addrs) = crate::get_dns_cache().get(host) {
        for addr in &addrs {
            let a = router.route_ip(&addr.ip());
            if a != *router.default_action() {
                return a;
            }
        }
        return action; // 所有 IP 均命中默认动作，返回域名阶段结论
    }

    // 4. DNS 解析后按 IP 路由
    match dns_resolve(host).await {
        Some(addrs) => {
            let result = addrs
                .iter()
                .find_map(|a| {
                    let r = router.route_ip(&a.ip());
                    if r != *router.default_action() {
                        Some(r)
                    } else {
                        None
                    }
                })
                .unwrap_or(action);
            crate::get_dns_cache().set(host.to_string(), addrs);
            result
        }
        None => action, // DNS 失败，沿用域名阶段结论（通常为默认动作）
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 公共接口
// ══════════════════════════════════════════════════════════════════════════════

/// 路由决策结果
pub enum RouteDecision {
    Direct,
    Tunnel,
    Reject,
}

/// 初始化路由模块：按模式加载 mmdb 或 rules.yaml
pub async fn init_routing() {
    let mode = parse_mode(&crate::get_args().routing);
    log::info!("[路由] 模式: {:?}", mode);

    match &mode {
        RoutingMode::Rule => {
            // Rule 模式：加载 rules.yaml 规则引擎
            crate::rules::init_rules().await;
        }
        RoutingMode::Country(_) => {
            // Country 模式：加载 mmdb，并启动后台热更新任务
            let path = mmdb_path();
            if path.exists() {
                load_mmdb(&path);
                if file_age(&path) >= UPDATE_INTERVAL {
                    log::info!("[路由] mmdb 已过期，后台刷新中…");
                }
            } else {
                log::info!("[路由] 未找到 mmdb，开始下载…");
                if let Err(e) = download_mmdb(&path).await {
                    log::error!("[路由] 初始下载失败: {}，后台任务将持续重试", e);
                } else {
                    load_mmdb(&path);
                }
            }
            tokio::spawn(background_updater(path));
        }
        _ => {} // None / Global 无需任何初始化
    }

    ROUTING_MODE.set(mode).ok();
}

/// 判断是否应绕过代理直连（主要供外部在 Country 模式下调用）
pub async fn should_bypass_proxy(host: &str) -> bool {
    match routing_mode() {
        RoutingMode::None => true,
        RoutingMode::Global => false,
        RoutingMode::Country(code) => host_matches_country(host, code).await,
        RoutingMode::Rule => false, // Rule 模式由 get_route_action 统一处理
    }
}

/// 获取 host 的最终路由决策（所有模式统一入口）
pub async fn get_route_action(host: &str) -> RouteDecision {
    match routing_mode() {
        RoutingMode::None => {
            log::debug!("[路由] ⚡ DIRECT(none) {}", host);
            RouteDecision::Direct
        }
        RoutingMode::Global => {
            log::debug!("[路由] 🌐 PROXY(global) {}", host);
            RouteDecision::Tunnel
        }
        RoutingMode::Country(_) => {
            // 复用 should_bypass_proxy，避免重复实现 Country 逻辑
            if should_bypass_proxy(host).await {
                RouteDecision::Direct
            } else {
                RouteDecision::Tunnel
            }
        }
        RoutingMode::Rule => {
            let Some(router) = crate::rules::get_rules_router() else {
                log::warn!("[路由] rules.yaml 未加载，降级为 global");
                return RouteDecision::Tunnel;
            };
            match resolve_action(router, host).await {
                RuleAction::Direct => RouteDecision::Direct,
                RuleAction::Reject => RouteDecision::Reject,
                RuleAction::Proxy | RuleAction::Named(_) => RouteDecision::Tunnel,
            }
        }
    }
}
