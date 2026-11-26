//! DNS 配置解析与配置期校验（shoes validate 风格：错误在启动前给出人话报错）。
//!
//! 字段语义对齐 mihomo：
//! - `nameserver`           默认/未知域名上游（默认 `tunnel://`）
//! - `direct-nameserver`    路由判定 DIRECT 的域名用这组上游（国内 DoH）
//! - `proxy-nameserver`     路由判定 PROXY 的域名用这组上游（缺省同 nameserver）
//! - `nameserver-policy`    显式分域覆盖（优先级最高）
//! - `default-nameserver`   引导 DNS：必须字面 IP DoH
//! - `proxy-server-nameserver` 解析 worker 域名（缺省同 default-nameserver）

use crate::dns::guard::Guard;
use ipnetwork::IpNetwork;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;

/// dns.yaml 的 serde 定义（clash 风格 kebab-case 字段）。
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfigDef {
    /// 本地 DNS 监听地址（如 "127.0.0.1:1053"）。缺省不开监听器。
    pub listen: Option<String>,
    /// 是否解析/返回 IPv6（AAAA）
    pub ipv6: bool,
    /// 引导 DNS：仅允许字面 IP 的 DoH（https://223.5.5.5/dns-query），
    /// 用于解析 nameserver 里带域名的 DoH 端点。配置期拒绝域名，杜绝引导递归。
    #[serde(rename = "default-nameserver")]
    pub default_nameserver: Vec<String>,
    /// 解析隧道端点（worker 域名）用的 DoH，必须字面 IP。缺省用 default-nameserver。
    #[serde(rename = "proxy-server-nameserver")]
    pub proxy_server_nameserver: Vec<String>,
    /// 默认上游列表：tunnel://（DnsQuery 帧 → Worker DoH）、https://（DoH 直连）、system://
    pub nameserver: Vec<String>,
    /// 路由判定为 DIRECT 的域名所用上游（国内 DoH，保证 CDN 返回本地节点）
    #[serde(rename = "direct-nameserver")]
    pub direct_nameserver: Vec<String>,
    /// 路由判定为 PROXY 的域名所用上游（缺省同 nameserver）
    #[serde(rename = "proxy-nameserver")]
    pub proxy_nameserver: Vec<String>,
    /// 分域策略：域名模式 → 上游（值可以是单个字符串或字符串列表）
    #[serde(rename = "nameserver-policy")]
    pub nameserver_policy: HashMap<String, OneOrMany>,
    /// 隧道断开/上游全败时是否回退系统 DNS（默认 false = 防泄漏 fail-closed）
    #[serde(rename = "fallback-system")]
    pub fallback_system: bool,
    /// 额外禁区段（自动追加 198.18.0.0/15 fake-ip 预留段）
    #[serde(rename = "forbidden-ranges")]
    pub forbidden_ranges: Vec<String>,
}

/// 单个值或列表（mihomo 的 nameserver-policy 两种写法都支持）。
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn entries(&self) -> Vec<&str> {
        match self {
            OneOrMany::One(s) => vec![s.as_str()],
            OneOrMany::Many(v) => v.iter().map(|s| s.as_str()).collect(),
        }
    }
}

/// DoH 上游描述
#[derive(Debug, Clone, PartialEq)]
pub struct DohSpec {
    /// 完整 URL（如 https://223.5.5.5/dns-query）
    pub url: String,
    /// host 部分（可能是域名或字面 IP）
    pub host: String,
    /// 端口（URL 未写时默认 443）
    pub port: u16,
    /// host 为字面 IP 时存放，字面 IP 上游无需引导解析（结构性防递归）
    pub ip: Option<std::net::IpAddr>,
}

/// 上游规格
#[derive(Debug, Clone, PartialEq)]
pub enum UpstreamSpec {
    /// DnsQuery 帧 → Worker DoH（防泄漏主路径）
    Tunnel,
    /// DoH 直连（HTTPS over TCP，无需 UDP）
    Doh(DohSpec),
    /// 系统 getaddrinfo（仅显式配置时使用；配合 fallback-system 语义）
    System,
}

/// 校验后的 DNS 配置
#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub listen: Option<SocketAddr>,
    pub ipv6: bool,
    pub default_nameserver: Vec<DohSpec>,
    /// 空 → 使用 default_nameserver
    pub proxy_server_nameserver: Vec<DohSpec>,
    pub nameserver: Vec<UpstreamSpec>,
    /// None → 回退 nameserver
    pub direct_nameserver: Option<Vec<UpstreamSpec>>,
    /// None → 回退 nameserver
    pub proxy_nameserver: Option<Vec<UpstreamSpec>>,
    pub nameserver_policy: Vec<(String, Vec<UpstreamSpec>)>,
    pub fallback_system: bool,
    /// 传给 Guard 的禁区段
    pub forbidden: Vec<IpNetwork>,
}

/// 日志用描述（启动时打印各上游组）
pub fn describe_upstreams(ups: &[UpstreamSpec]) -> Vec<String> {
    ups.iter()
        .map(|u| match u {
            UpstreamSpec::Tunnel => "tunnel://".to_string(),
            UpstreamSpec::Doh(d) => d.url.clone(),
            UpstreamSpec::System => "system://".to_string(),
        })
        .collect()
}

/// 内置引导 DNS（字面 IP DoH，官方支持 IP 端点 + IP SAN）：
/// 用于解析 nameserver 里带域名的 DoH 端点。可在 dns.yaml 覆盖。
const DEFAULT_BOOTSTRAP: &str = "https://223.5.5.5/dns-query";

impl DnsConfig {
    /// 从文件加载并校验。文件不存在 → 内置默认（全隧道，默认安全）。
    pub fn load(path: Option<&std::path::Path>) -> Result<Self, String> {
        let Some(path) = path else {
            return Ok(Self::secure_default());
        };
        if !path.exists() {
            return Ok(Self::secure_default());
        }
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("读取 DNS 配置失败 {}: {}", path.display(), e))?;
        if content.trim().is_empty() {
            return Ok(Self::secure_default());
        }
        let def: DnsConfigDef = serde_yaml::from_str(&content).map_err(|e| {
            format!(
                "DNS 配置解析失败 {}: {}\n\
                 字段名参考 dns.yaml 示例。\n\
                 提示：若错误提示某个新字段 unknown field，说明当前运行的是旧版 zks-core.exe\n\
                 （配置比程序新）。请使用最新编译的 zks-core.exe 后重试；\n\
                 Windows 上被复用的旧进程需要先在任务管理器结束，再重新启动。",
                path.display(),
                e
            )
        })?;
        Self::try_from_def(def)
    }

    /// 内置默认：内部解析全走隧道，不开监听器。
    pub fn secure_default() -> Self {
        let bootstrap = match parse_upstream(DEFAULT_BOOTSTRAP) {
            Ok(UpstreamSpec::Doh(doh)) => vec![doh],
            _ => Vec::new(),
        };
        Self {
            listen: None,
            ipv6: false,
            default_nameserver: bootstrap,
            proxy_server_nameserver: Vec::new(),
            nameserver: vec![UpstreamSpec::Tunnel],
            direct_nameserver: None,
            proxy_nameserver: None,
            nameserver_policy: vec![],
            fallback_system: false,
            forbidden: Guard::default_ranges(),
        }
    }

    /// 解析 + 配置期校验。所有错误在这里给出人话报错，启动即失败。
    pub fn try_from_def(def: DnsConfigDef) -> Result<Self, String> {
        let listen = match &def.listen {
            Some(s) => Some(s.parse::<SocketAddr>().map_err(|_| {
                format!(
                    "listen 无效: \"{}\" —— 应为 \"IP:端口\" 形式，例如 \"127.0.0.1:1053\"",
                    s
                )
            })?),
            None => None,
        };

        // 引导 DNS：必须字面 IP DoH（shoes LiteralResolver 思想：结构性禁止递归）
        let default_nameserver = if def.default_nameserver.is_empty() {
            // 缺省即字面 IP DoH（仅用于解析 DoH 域名端点，不会触碰系统 DNS）
            match parse_upstream(DEFAULT_BOOTSTRAP)? {
                UpstreamSpec::Doh(doh) => vec![doh],
                _ => unreachable!("builtin bootstrap must be a DoH literal"),
            }
        } else {
            parse_bootstrap_list(&def.default_nameserver, "default-nameserver")?
        };

        // 隧道端点引导：缺省用 default-nameserver
        let proxy_server_nameserver = if def.proxy_server_nameserver.is_empty() {
            Vec::new()
        } else {
            parse_bootstrap_list(&def.proxy_server_nameserver, "proxy-server-nameserver")?
        };

        // 主上游
        let nameserver = if def.nameserver.is_empty() {
            vec![UpstreamSpec::Tunnel]
        } else {
            parse_upstream_list(&def.nameserver, "nameserver")?
        };

        let direct_nameserver = if def.direct_nameserver.is_empty() {
            None
        } else {
            Some(parse_upstream_list(
                &def.direct_nameserver,
                "direct-nameserver",
            )?)
        };

        let proxy_nameserver = if def.proxy_nameserver.is_empty() {
            None
        } else {
            Some(parse_upstream_list(
                &def.proxy_nameserver,
                "proxy-nameserver",
            )?)
        };

        // 分域策略
        let mut nameserver_policy = Vec::new();
        for (pattern, upstreams) in &def.nameserver_policy {
            validate_pattern(pattern)?;
            let mut specs = Vec::new();
            for s in upstreams.entries() {
                specs.push(parse_upstream(s)?);
            }
            if specs.is_empty() {
                return Err(format!("nameserver-policy \"{}\" 的上游列表为空", pattern));
            }
            nameserver_policy.push((pattern.clone(), specs));
        }

        // 禁区段：内置 fake-ip 预留段 + 用户自定义
        let mut forbidden = Guard::default_ranges();
        for s in &def.forbidden_ranges {
            let net: IpNetwork = s.parse().map_err(|_| {
                format!(
                    "forbidden-ranges 无效: \"{}\" —— 应为 CIDR，例如 \"198.18.0.0/15\"",
                    s
                )
            })?;
            forbidden.push(net);
        }

        Ok(Self {
            listen,
            ipv6: def.ipv6,
            default_nameserver,
            proxy_server_nameserver,
            nameserver,
            direct_nameserver,
            proxy_nameserver,
            nameserver_policy,
            fallback_system: def.fallback_system,
            forbidden,
        })
    }
}

fn parse_upstream_list(list: &[String], field: &str) -> Result<Vec<UpstreamSpec>, String> {
    list.iter()
        .map(|s| parse_upstream(s).map_err(|e| format!("{}: {}", field, e)))
        .collect()
}

/// 引导类上游：只接受字面 IP 的 DoH（拒绝域名/tunnel://system://）
fn parse_bootstrap_list(list: &[String], field: &str) -> Result<Vec<DohSpec>, String> {
    let mut out = Vec::new();
    for s in list {
        let spec = parse_upstream(s)?;
        match spec {
            UpstreamSpec::Doh(doh) if doh.ip.is_some() => out.push(doh),
            UpstreamSpec::Doh(_) => {
                return Err(format!(
                    "{} \"{}\" 含域名 —— 引导 DNS 必须是字面 IP 的 DoH 地址\n\
                     （例如 \"https://223.5.5.5/dns-query\"），否则引导本身会递归依赖本机解析器",
                    field, s
                ));
            }
            UpstreamSpec::Tunnel => {
                return Err(format!(
                    "{} 不支持 tunnel:// —— 引导发生在隧道建立之前",
                    field
                ));
            }
            UpstreamSpec::System => {
                return Err(format!(
                    "{} 不支持 system:// —— 请使用字面 IP 的 DoH",
                    field
                ));
            }
        }
    }
    Ok(out)
}

/// 解析单条上游 URL。仅支持 tunnel://、https://（DoH）、system://。
/// 不支持 udp:// —— 隧道上游走 DnsQuery 帧，直连上游走 DoH(TCP)，全程无 UDP 依赖。
///
/// mihomo 兼容：`https://1.1.1.1/dns-query#节点选择` 里的 `#...` 片段表示
/// "经代理出口查询"。本客户端唯一的代理出口就是隧道，因此等价映射为 `tunnel://`。
pub fn parse_upstream(s: &str) -> Result<UpstreamSpec, String> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("tunnel://") {
        return Ok(UpstreamSpec::Tunnel);
    }
    if s.eq_ignore_ascii_case("system://") {
        return Ok(UpstreamSpec::System);
    }
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("https://") {
        // `#proxy` / `#节点选择`：经代理出口 → 本客户端等价于隧道
        if let Some((_url, fragment)) = s.split_once('#') {
            if !fragment.trim().is_empty() {
                return Ok(UpstreamSpec::Tunnel);
            }
        }
        let rest = &s["https://".len()..];
        let host_part = match rest.find('/') {
            Some(idx) => &rest[..idx],
            None => rest,
        };
        // 处理 [IPv6]:port
        let (host, port) = if let Some(stripped) = host_part.strip_prefix('[') {
            match stripped.find(']') {
                Some(end) => {
                    let h = &stripped[..end];
                    let after = &stripped[end + 1..];
                    let p = after
                        .strip_prefix(':')
                        .and_then(|p| p.parse::<u16>().ok())
                        .unwrap_or(443);
                    (h.to_string(), p)
                }
                None => return Err(format!("DoH 地址无效: \"{}\" —— IPv6 缺少 ']'", s)),
            }
        } else {
            match host_part.rsplit_once(':') {
                Some((h, port)) if port.parse::<u16>().is_ok() => {
                    (h.to_string(), port.parse::<u16>().unwrap_or(443))
                }
                _ => (host_part.to_string(), 443),
            }
        };
        let ip = host.parse::<std::net::IpAddr>().ok();
        if host.is_empty() {
            return Err(format!("DoH 地址无效: \"{}\" —— 缺少主机部分", s));
        }
        return Ok(UpstreamSpec::Doh(DohSpec {
            url: s.to_string(),
            host,
            port,
            ip,
        }));
    }
    Err(format!(
        "不支持的 DNS 上游 \"{}\" —— 仅支持:\n  tunnel://              (DnsQuery 帧 → Worker DoH, 推荐)\n  https://<IP>/dns-query (DoH 直连, TCP)\n  system://              (系统解析, 不防泄漏)",
        s
    ))
}

/// 校验分域模式（与 router 的 DomainPattern 语义对齐的子集）
fn validate_pattern(pattern: &str) -> Result<(), String> {
    let p = pattern.trim().to_lowercase();
    if p.starts_with("geosite:") || p.starts_with("rule-set:") || p.starts_with("geoip:") {
        return Err(format!(
            "nameserver-policy 不支持 \"{}\"（本客户端不内置 geosite 数据库）\n\
             等价做法：用 direct-nameserver 指定国内 DoH —— 路由判定为 DIRECT 的域名\n\
             会自动用那组上游解析，不必逐条枚举域名",
            pattern
        ));
    }
    let p = p.trim_start_matches("+.");
    if p.is_empty() {
        return Err(format!("nameserver-policy 模式无效: \"{}\"", pattern));
    }
    if p.contains('*') && !p.starts_with("*.") {
        return Err(format!(
            "nameserver-policy 模式无效: \"{}\" —— 仅支持 \"*.<域名>\" 形式",
            pattern
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tunnel() {
        assert_eq!(parse_upstream("tunnel://").unwrap(), UpstreamSpec::Tunnel);
    }

    #[test]
    fn parse_system() {
        assert_eq!(parse_upstream("system://").unwrap(), UpstreamSpec::System);
    }

    #[test]
    fn parse_doh_literal_ip() {
        let spec = parse_upstream("https://223.5.5.5/dns-query").unwrap();
        match spec {
            UpstreamSpec::Doh(doh) => {
                assert_eq!(doh.ip, Some("223.5.5.5".parse().unwrap()));
                assert_eq!(doh.host, "223.5.5.5");
            }
            other => panic!("expected Doh, got {:?}", other),
        }
    }

    #[test]
    fn parse_doh_hostname() {
        let spec = parse_upstream("https://dns.alidns.com/dns-query").unwrap();
        match spec {
            UpstreamSpec::Doh(doh) => {
                assert_eq!(doh.ip, None);
                assert_eq!(doh.host, "dns.alidns.com");
            }
            other => panic!("expected Doh, got {:?}", other),
        }
    }

    #[test]
    fn parse_doh_with_proxy_fragment_becomes_tunnel() {
        // mihomo 写法：https://1.1.1.1/dns-query#节点选择 → 经代理出口
        assert_eq!(
            parse_upstream("https://1.1.1.1/dns-query#节点选择").unwrap(),
            UpstreamSpec::Tunnel
        );
        // 空片段的 # 仍按直连 DoH 处理
        assert!(matches!(
            parse_upstream("https://1.1.1.1/dns-query#").unwrap(),
            UpstreamSpec::Doh(_)
        ));
    }

    #[test]
    fn reject_udp_upstream() {
        assert!(parse_upstream("udp://223.5.5.5").is_err());
    }

    #[test]
    fn default_nameserver_rejects_hostname() {
        let def = DnsConfigDef {
            default_nameserver: vec!["https://dns.alidns.com/dns-query".into()],
            ..Default::default()
        };
        let err = DnsConfig::try_from_def(def).unwrap_err();
        assert!(err.contains("字面 IP"), "unexpected error: {}", err);
    }

    #[test]
    fn proxy_server_nameserver_rejects_hostname() {
        let def = DnsConfigDef {
            proxy_server_nameserver: vec!["https://doh.example/dns-query".into()],
            ..Default::default()
        };
        let err = DnsConfig::try_from_def(def).unwrap_err();
        assert!(
            err.contains("proxy-server-nameserver"),
            "unexpected: {}",
            err
        );
    }

    #[test]
    fn default_nameserver_accepts_literal() {
        let def = DnsConfigDef {
            default_nameserver: vec!["https://223.5.5.5/dns-query".into()],
            ..Default::default()
        };
        let cfg = DnsConfig::try_from_def(def).unwrap();
        assert_eq!(cfg.default_nameserver.len(), 1);
    }

    #[test]
    fn empty_nameserver_defaults_to_tunnel() {
        let cfg = DnsConfig::try_from_def(DnsConfigDef::default()).unwrap();
        assert_eq!(cfg.nameserver, vec![UpstreamSpec::Tunnel]);
        assert!(cfg.direct_nameserver.is_none());
        assert!(cfg.proxy_nameserver.is_none());
    }

    #[test]
    fn default_bootstrap_is_literal_doh() {
        // 未配置 default-nameserver 时使用内置字面 IP DoH（结构性防递归）
        let cfg = DnsConfig::try_from_def(DnsConfigDef::default()).unwrap();
        assert_eq!(cfg.default_nameserver.len(), 1);
        assert_eq!(
            cfg.default_nameserver[0].ip,
            Some("223.5.5.5".parse().unwrap())
        );
    }

    #[test]
    fn listen_parse_error_is_human() {
        let def = DnsConfigDef {
            listen: Some("not-an-addr".into()),
            ..Default::default()
        };
        let err = DnsConfig::try_from_def(def).unwrap_err();
        assert!(err.contains("listen"), "unexpected error: {}", err);
    }

    #[test]
    fn yaml_roundtrip_with_policy() {
        let yaml = r#"
listen: "127.0.0.1:1053"
ipv6: false
default-nameserver:
  - "https://223.5.5.5/dns-query"
nameserver:
  - "tunnel://"
direct-nameserver:
  - "https://223.5.5.5/dns-query"
nameserver-policy:
  "+.cn": "https://223.5.5.5/dns-query"
fallback-system: false
"#;
        let def: DnsConfigDef = serde_yaml::from_str(yaml).unwrap();
        let cfg = DnsConfig::try_from_def(def).unwrap();
        assert_eq!(cfg.listen, Some("127.0.0.1:1053".parse().unwrap()));
        assert_eq!(cfg.nameserver_policy.len(), 1);
        assert!(cfg.nameserver_policy[0].0 == "+.cn");
        assert_eq!(cfg.direct_nameserver.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn policy_accepts_list_value() {
        let yaml = r#"
nameserver-policy:
  "+.example.com":
    - "https://223.5.5.5/dns-query"
    - "tunnel://"
"#;
        let def: DnsConfigDef = serde_yaml::from_str(yaml).unwrap();
        let cfg = DnsConfig::try_from_def(def).unwrap();
        assert_eq!(cfg.nameserver_policy[0].1.len(), 2);
    }

    #[test]
    fn geosite_policy_is_rejected_with_guidance() {
        let yaml = r#"
nameserver-policy:
  "geosite:cn": "https://223.5.5.5/dns-query"
"#;
        let def: DnsConfigDef = serde_yaml::from_str(yaml).unwrap();
        let err = DnsConfig::try_from_def(def).unwrap_err();
        assert!(err.contains("direct-nameserver"), "unexpected: {}", err);
    }

    #[test]
    fn unknown_field_rejected() {
        let yaml = "nope: true";
        assert!(serde_yaml::from_str::<DnsConfigDef>(yaml).is_err());
    }
}
