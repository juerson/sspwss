//! ssp-core 客户端入口：CLI 定义 + 初始化编排。
//!
//! 模块分层（依赖单向）：
//!   crypto.rs    协议层 —— 帧常量、AEAD 会话、ECDH 握手、重放防护、padding
//!   transport.rs 连接层 —— 端点解析、TLS 双栈（native-tls/rustls+ECH）、WS 升级
//!   mux.rs       复用层 —— sid 逻辑流、连接池、心跳+看门狗、隧道 DNS 端点
//!   proxy.rs     代理层 —— 本地 SOCKS5/HTTP、路由判定、直连/隧道中继
//!   router.rs    规则引擎（clash 风格 rules.yaml，支持 .mrs）
//!   dns/         DNS 防泄漏（上游分组/缓存/监听器）
//!   ech.rs       ECH 配置获取与缓存
//!   mrs.rs       .mrs 二进制规则集解码

mod crypto;
mod dns;
mod ech;
mod mrs;
mod mux;
mod proxy;
mod router;
mod transport;

use clap::Parser;
use ech::{EchModeArg, EchProvider, EchSettings};
use once_cell::sync::OnceCell;
use std::{
    error::Error,
    io::Write,
    path::{Path, PathBuf},
    process,
    sync::Arc,
    time::Duration,
};

/// 建连超时（transport 拨号与 proxy 直连共用）
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

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

    /// 路由模式: rule（默认，读 rules.yaml 规则引擎）、global（全部代理）、none（全部直连）
    #[arg(long, default_value = "rule")]
    routing: String,

    /// DNS 配置文件（防泄漏：上游/分域/本地监听器），不存在时用内置默认（全走隧道）
    #[arg(long, default_value = "dns.yaml")]
    dns: String,

    /// ECH 模式: off=关闭；auto=尝试，失败回退普通 TLS；on=强制 ECH
    #[arg(
        long,
        value_enum,
        default_value = "auto",
        default_missing_value = "on",
        num_args = 0..=1
    )]
    ech: EchModeArg,

    /// ECH 配置来源域名（默认 Cloudflare 共享 public name）
    #[arg(long, default_value = ech::DEFAULT_ECH_DOMAIN)]
    ech_domain: String,

    /// 获取 ECH 配置使用的 DoH（必须是字面 IP，例如 https://223.5.5.5/dns-query）
    #[arg(long)]
    ech_doh: Option<String>,

    /// 手工指定 ECHConfigList（base64）；设置后不再通过 DoH 获取
    #[arg(long)]
    ech_config: Option<String>,

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

/// 路径解析：绝对路径直用，相对路径基于可执行文件目录
fn resolve_path(path: &str) -> PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        return p.to_path_buf();
    }
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join(p)))
        .unwrap_or_else(|| p.to_path_buf())
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
             ./client -l 127.0.0.1:30000 -s your.worker.dev:443 -t YOUR-PSK \
             --ech auto"
        );
        process::exit(1);
    }

    // ── 1. DNS 配置：联网前校验，非法配置直接退出（人话报错，shoes validate 风格）──
    // dns.yaml 不存在 → 内置默认（内部解析全走隧道，不开本地监听器，默认安全）。
    let dns_path = resolve_path(&args.dns);
    let dns_config = match dns::DnsConfig::load(Some(&dns_path)) {
        Ok(cfg) => {
            log::info!(
                "[DNS] 配置: listen={:?}, ipv6={}, nameserver={:?}, direct={:?}, policy={}",
                cfg.listen,
                cfg.ipv6,
                dns::config::describe_upstreams(&cfg.nameserver),
                cfg.direct_nameserver
                    .as_deref()
                    .map(dns::config::describe_upstreams),
                cfg.nameserver_policy.len()
            );
            cfg
        }
        Err(e) => {
            log::error!("DNS 配置错误: {}", e);
            process::exit(1);
        }
    };
    dns::set_dns_config(dns_config.clone());

    // ── 2. 路由：rule 模式按需下载 mmdb + 加载 rules.yaml ────────────────────────
    router::init_routing(&args.routing, "rules.yaml").await;

    // ── 3. ECH：DoH 取 HTTPS RR 的 ech 参数（不经隧道，无循环依赖）──────────────
    let host = transport::get_server_addr_info().host.clone();
    let ech = match args.ech {
        EchModeArg::Off => None,
        mode => {
            let is_auto = mode == EchModeArg::Auto;
            let settings = EchSettings {
                mode,
                domain: args.ech_domain.clone(),
                doh: args.ech_doh.clone(),
                config_b64: args.ech_config.clone(),
            };
            match EchProvider::from_settings(settings, &dns_config) {
                Ok(provider) => match provider.warmup(&host).await {
                    Ok(info) => {
                        log::info!(
                            "[ECH] 就绪: source={} {} bytes",
                            info.source,
                            info.config_len
                        );
                        Some(provider)
                    }
                    Err(e) if is_auto => {
                        log::warn!("[ECH] 启动期不可用，建连时重试/回退普通 TLS: {}", e);
                        Some(provider)
                    }
                    Err(e) => {
                        log::error!("ECH 强制模式启动失败: {}", e);
                        process::exit(1);
                    }
                },
                Err(e) if is_auto => {
                    log::warn!("[ECH] 已禁用: {}", e);
                    None
                }
                Err(e) => {
                    log::error!("ECH 配置错误: {}", e);
                    process::exit(1);
                }
            }
        }
    };
    transport::set_ech_provider(ech);

    // ── 4. DNS 解析器（tunnel:// 上游复用隧道连接池）+ 可选本地 DNS 监听器 ───────
    // 解析器注入路由分类器：DIRECT 目标用 direct-nameserver（国内 DoH，geo 正确），
    // PROXY/未知目标用 nameserver（默认 tunnel://，解析位置跟随出口）。
    let classifier: Option<Arc<dyn dns::RouteClassifier>> = router::get_router()
        .map(|r| r.clone() as Arc<dyn dns::RouteClassifier>);
    match dns::start(dns_config, mux::get_tunnel_dns().clone(), classifier).await {
        Ok(resolver) => dns::set_resolver(resolver),
        Err(e) => {
            log::error!("DNS 初始化失败: {}", e);
            process::exit(1);
        }
    }

    // ── 5. 预热连接池，在第一个请求到来前预建 WS 连接 ────────────────────────────
    let _ = mux::get_mux_pool();

    // ── 6. 本地代理服务 ─────────────────────────────────────────────────────────
    proxy::run_proxy_server(&args.listen).await;

    Ok(())
}
