#![allow(dead_code)] // 库式规则引擎：保留完整公共 API（热更新/统计/模式枚举），部分暂未接线
use crate::mrs;
use ahash::AHashMap;
use arc_swap::ArcSwap;
use ipnetwork::IpNetwork;
use once_cell::sync::{Lazy, OnceCell};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    time::{Duration, Instant},
};
use thiserror::Error;
use log::{debug, error, info, warn};

// ── 错误类型 ──────────────────────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum RouterError {
    #[error("Invalid rule format: {0}")]
    InvalidRule(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Rule set '{0}' not found")]
    RuleSetNotFound(String),
    #[error("YAML error: {0}")]
    Yaml(String),
}

// ── 正则缓存：RwLock + AHashMap（读多写少）──────────────────────────────────

static REGEX_CACHE: Lazy<RwLock<AHashMap<String, regex::Regex>>> =
    Lazy::new(|| RwLock::new(AHashMap::new()));

fn regex_matches(pattern: &str, domain: &str) -> bool {
    // 热路径：读锁，多线程并行，无独占
    if let Ok(cache) = REGEX_CACHE.read() {
        if let Some(re) = cache.get(pattern) {
            return re.is_match(domain);
        }
    }
    // 缓存未命中：升级为写锁插入
    let mut cache = REGEX_CACHE.write().unwrap();
    let re = cache.entry(pattern.to_string()).or_insert_with(|| {
        regex::Regex::new(pattern).unwrap_or_else(|_| regex::Regex::new("^.+$").unwrap())
    });
    re.is_match(domain)
}

// ── RuleAction ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    #[serde(rename = "proxy")]
    Proxy,
    #[serde(rename = "direct")]
    Direct,
    #[serde(rename = "reject")]
    Reject,
    Named(Arc<str>),
}

impl RuleAction {
    fn parse(s: &str) -> Self {
        match s.trim().to_uppercase().as_str() {
            "PROXY" => Self::Proxy,
            "DIRECT" => Self::Direct,
            "REJECT" | "BLOCK" | "DENY" => Self::Reject,
            other => Self::Named(Arc::from(other)),
        }
    }
}

// ── 协议 / 域名模式 / 端口匹配器 ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Any,
}

#[derive(Debug, Clone)]
pub enum DomainPattern {
    Exact(String),
    Suffix(String),
    Keyword(String),
    Regex(String),
    Wildcard,
}

#[derive(Debug, Clone)]
pub enum PortMatcher {
    Single(u16),
    Range(u16, u16),
    List(Vec<u16>),
}

impl PortMatcher {
    pub fn matches(&self, port: u16) -> bool {
        match self {
            Self::Single(p) => port == *p,
            Self::Range(lo, hi) => port >= *lo && port <= *hi,
            Self::List(ports) => ports.contains(&port),
        }
    }

    fn parse(s: &str) -> Result<Self, RouterError> {
        if s.contains(',') {
            let ports = s
                .split(',')
                .map(|p| {
                    p.trim()
                        .parse::<u16>()
                        .map_err(|_| RouterError::Parse(format!("Invalid port: {}", p)))
                })
                .collect::<Result<Vec<_>, _>>()?;
            return Ok(Self::List(ports));
        }
        if let Some((lo, hi)) = s.split_once('-') {
            let lo = lo
                .trim()
                .parse::<u16>()
                .map_err(|_| RouterError::Parse(format!("Invalid port range: {}", s)))?;
            let hi = hi
                .trim()
                .parse::<u16>()
                .map_err(|_| RouterError::Parse(format!("Invalid port range: {}", s)))?;
            return Ok(Self::Range(lo, hi));
        }
        let p = s
            .trim()
            .parse::<u16>()
            .map_err(|_| RouterError::Parse(format!("Invalid port: {}", s)))?;
        Ok(Self::Single(p))
    }
}

// ── RuleType / RuleCondition / Rule ──────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum RuleType {
    Domain(DomainPattern),
    Network(IpNetwork),
    Ip(IpAddr),
    SrcNetwork(IpNetwork),
    GeoLocation(String),
    DestPort(PortMatcher),
    SrcPort(PortMatcher),
    ProcessName(String),
    ProcessPath(String),
    Network2(NetworkProtocol),
    And(Vec<RuleCondition>),
    Or(Vec<RuleCondition>),
    Not(Box<RuleCondition>),
    RuleSet(String),
    Final,
}

#[derive(Debug, Clone)]
pub struct RuleCondition {
    pub rule_type: RuleType,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub rule_type: RuleType,
    pub action: RuleAction,
    pub description: Option<String>,
    pub no_resolve: bool,
}

impl Rule {
    pub fn from_str(line: &str) -> Result<Self, RouterError> {
        let parts: Vec<&str> = line.splitn(4, ',').collect();
        if parts.len() < 2 {
            return Err(RouterError::InvalidRule(line.to_string()));
        }

        let type_str = parts[0].trim().to_uppercase();
        let pattern = parts[1].trim();

        let (action_str, extra) = if type_str == "FINAL" || type_str == "MATCH" {
            (pattern.to_string(), "")
        } else if parts.len() >= 3 {
            (
                parts[2].trim().to_string(),
                parts.get(3).copied().unwrap_or("").trim(),
            )
        } else {
            return Err(RouterError::InvalidRule(format!(
                "Too few fields: {}",
                line
            )));
        };

        let action = RuleAction::parse(&action_str);
        let no_resolve = extra.eq_ignore_ascii_case("no-resolve");
        let rule_type = Self::parse_type(&type_str, pattern)?;

        Ok(Rule {
            rule_type,
            action,
            description: None,
            no_resolve,
        })
    }

    fn parse_type(type_str: &str, pattern: &str) -> Result<RuleType, RouterError> {
        Ok(match type_str {
            "DOMAIN" => RuleType::Domain(DomainPattern::Exact(pattern.to_lowercase())),
            "DOMAIN-SUFFIX" => RuleType::Domain(DomainPattern::Suffix(pattern.to_lowercase())),
            "DOMAIN-KEYWORD" => RuleType::Domain(DomainPattern::Keyword(pattern.to_lowercase())),
            "DOMAIN-REGEX" => RuleType::Domain(DomainPattern::Regex(pattern.to_string())),

            "IP-CIDR" | "IP-CIDR6" => {
                let net = pattern.parse::<IpNetwork>().map_err(|e| {
                    RouterError::Parse(format!("Invalid CIDR '{}': {}", pattern, e))
                })?;
                RuleType::Network(net)
            }
            "SRC-IP-CIDR" => {
                let net = pattern.parse::<IpNetwork>().map_err(|e| {
                    RouterError::Parse(format!("Invalid SRC CIDR '{}': {}", pattern, e))
                })?;
                RuleType::SrcNetwork(net)
            }
            "GEOIP" => {
                let cc = pattern.to_uppercase();
                if cc != "LAN" && cc.len() != 2 {
                    return Err(RouterError::Parse(format!(
                        "Invalid country code: {}",
                        pattern
                    )));
                }
                RuleType::GeoLocation(cc)
            }

            "DEST-PORT" | "DST-PORT" => RuleType::DestPort(PortMatcher::parse(pattern)?),
            "SRC-PORT" => RuleType::SrcPort(PortMatcher::parse(pattern)?),

            "PROCESS-NAME" => RuleType::ProcessName(pattern.to_string()),
            "PROCESS-PATH" => RuleType::ProcessPath(pattern.to_string()),

            "NETWORK" => {
                let proto = match pattern.to_uppercase().as_str() {
                    "TCP" => NetworkProtocol::Tcp,
                    "UDP" => NetworkProtocol::Udp,
                    _ => return Err(RouterError::Parse(format!("Unknown protocol: {}", pattern))),
                };
                RuleType::Network2(proto)
            }

            "RULE-SET" => RuleType::RuleSet(pattern.to_string()),

            "AND" => RuleType::And(Self::parse_composite(pattern)?),
            "OR" => RuleType::Or(Self::parse_composite(pattern)?),
            "NOT" => {
                let conds = Self::parse_composite(pattern)?;
                let first = conds
                    .into_iter()
                    .next()
                    .ok_or_else(|| RouterError::Parse("NOT requires one condition".into()))?;
                RuleType::Not(Box::new(first))
            }

            "FINAL" | "MATCH" => RuleType::Final,

            _ => {
                return Err(RouterError::InvalidRule(format!(
                    "Unknown rule type: {}",
                    type_str
                )))
            }
        })
    }

    fn parse_composite(s: &str) -> Result<Vec<RuleCondition>, RouterError> {
        let s = s.trim().trim_start_matches('(').trim_end_matches(')');
        let mut conditions = Vec::new();
        let mut depth = 0i32;
        let mut start = 0usize;

        for (i, &b) in s.as_bytes().iter().enumerate() {
            match b {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        let seg = &s[start..=i];
                        let inner = seg.trim().trim_start_matches('(').trim_end_matches(')');
                        if !inner.is_empty() {
                            if let Some((t, p)) = inner.split_once(',') {
                                if let Ok(rule_type) =
                                    Rule::parse_type(&t.trim().to_uppercase(), p.trim())
                                {
                                    conditions.push(RuleCondition { rule_type });
                                }
                            }
                        }
                        start = i + 1;
                    }
                }
                _ => {}
            }
        }
        Ok(conditions)
    }
}

// ── 后缀检查辅助函数 ────────────────────────────────────────────────────

/// 检查 `domain` 是否等于 `suffix` 或以 `.<suffix>` 结尾
#[inline]
fn domain_has_suffix(domain: &str, suffix: &str) -> bool {
    domain == suffix
        || (domain.len() > suffix.len()
            && domain.ends_with(suffix)
            && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.')
}

/// 该规则谓词是否需要"目标 IP"（即需要把域名解析成地址才能匹配）。
/// 源地址/端口/进程/协议类谓词与 DNS 无关。
fn rule_type_needs_ip(rt: &RuleType) -> bool {
    match rt {
        RuleType::Network(_) | RuleType::Ip(_) | RuleType::GeoLocation(_) => true,
        RuleType::RuleSet(_) => true,
        RuleType::And(conds) | RuleType::Or(conds) => {
            conds.iter().any(|c| rule_type_needs_ip(&c.rule_type))
        }
        RuleType::Not(cond) => rule_type_needs_ip(&cond.rule_type),
        _ => false,
    }
}

// ── DomainIndex：AHashMap 精确匹配 + TLD 分桶后缀 ────────────────────────────

#[derive(Debug, Default)]
struct DomainIndex {
    /// 精确匹配
    exact: AHashMap<String, RuleAction>,
    /// 后缀按 TLD 分桶
    suffix_buckets: AHashMap<String, Vec<(String, RuleAction)>>,
    /// 关键字 / 正则 / 通配符等慢路径规则
    slow: Vec<(DomainPattern, RuleAction)>,
}

impl DomainIndex {
    fn insert(&mut self, pattern: DomainPattern, action: RuleAction) {
        match pattern {
            DomainPattern::Exact(s) => {
                self.exact.entry(s).or_insert(action);
            }
            DomainPattern::Suffix(s) => {
                let tld = s.rsplit('.').next().unwrap_or(&s).to_string();
                self.suffix_buckets
                    .entry(tld)
                    .or_default()
                    .push((s, action));
            }
            other => {
                self.slow.push((other, action));
            }
        }
    }

    fn build(&mut self) {
        // 每个桶内按后缀长度降序，更具体的规则优先
        for bucket in self.suffix_buckets.values_mut() {
            bucket.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        }
    }

    fn lookup(&self, domain: &str) -> Option<&RuleAction> {
        // 条件 lowercase：域名已小写时零分配（实践中占绝大多数）
        let lower_buf;
        let lower = if domain.bytes().any(|b| b.is_ascii_uppercase()) {
            lower_buf = domain.to_lowercase();
            lower_buf.as_str()
        } else {
            domain
        };

        // 1. 精确匹配 O(1)
        if let Some(action) = self.exact.get(lower) {
            return Some(action);
        }

        // 2. 只扫描同 TLD 桶
        let tld = lower.rsplit('.').next().unwrap_or(lower);
        if let Some(bucket) = self.suffix_buckets.get(tld) {
            for (suffix, action) in bucket {
                if domain_has_suffix(lower, suffix) {
                    return Some(action);
                }
            }
        }

        // 3. 慢路径：关键字 / 正则 / 通配符
        for (pattern, action) in &self.slow {
            let matched = match pattern {
                DomainPattern::Wildcard => true,
                DomainPattern::Keyword(kw) => lower.contains(kw.as_str()),
                DomainPattern::Regex(pat) => regex_matches(pat, lower),
                _ => false,
            };
            if matched {
                return Some(action);
            }
        }

        None
    }
}

// ── IpIndex：/32、/128 走 HashMap O(1)，其余 CIDR 线性扫描 ───────────────────

#[derive(Debug, Default)]
struct IpIndex {
    exact_v4: AHashMap<u32, RuleAction>,    // /32  → O(1)
    exact_v6: AHashMap<u128, RuleAction>,   // /128 → O(1)
    networks: Vec<(IpNetwork, RuleAction)>, // 其余 CIDR，按前缀长度降序
}

impl IpIndex {
    fn insert(&mut self, net: IpNetwork, action: RuleAction) {
        match net {
            IpNetwork::V4(n) if n.prefix() == 32 => {
                self.exact_v4.entry(u32::from(n.ip())).or_insert(action);
            }
            IpNetwork::V6(n) if n.prefix() == 128 => {
                self.exact_v6.entry(u128::from(n.ip())).or_insert(action);
            }
            _ => {
                self.networks.push((net, action));
            }
        }
    }

    fn build(&mut self) {
        self.networks
            .sort_by(|a, b| b.0.prefix().cmp(&a.0.prefix()));
    }

    fn lookup(&self, ip: &IpAddr) -> Option<&RuleAction> {
        // 精确命中 O(1)
        match ip {
            IpAddr::V4(v4) => {
                if let Some(a) = self.exact_v4.get(&u32::from(*v4)) {
                    return Some(a);
                }
            }
            IpAddr::V6(v6) => {
                if let Some(a) = self.exact_v6.get(&u128::from(*v6)) {
                    return Some(a);
                }
            }
        }
        // CIDR 线性扫描（已按前缀长度排序，首次命中即最具体规则）
        self.networks
            .iter()
            .find(|(net, _)| net.contains(*ip))
            .map(|(_, a)| a)
    }
}

// ── RuleProvider 配置 ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct RuleProviderConfig {
    #[serde(rename = "type")]
    pub source_type: ProviderSourceType,
    pub behavior: ProviderBehavior,
    pub url: Option<String>,
    pub path: Option<String>,
    pub interval: Option<u64>,
    /// 可选：显式声明规则集格式。缺省按文件头自动识别
    /// （zstd → `.mrs`，`SRS` → sing-box，其余按 UTF-8 文本）。
    #[serde(default)]
    pub format: Option<ProviderFormat>,
}

/// 规则集文件格式。
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProviderFormat {
    #[serde(alias = "yml")]
    Yaml,
    Text,
    Mrs,
    Srs,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProviderSourceType {
    Http,
    File,
    Inline,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProviderBehavior {
    Domain,
    IpCidr,
    Classical,
}

#[derive(Debug, Deserialize, Default)]
struct ProxyConfig {
    #[serde(rename = "rule-providers", default)]
    rule_providers: HashMap<String, RuleProviderConfig>,
    #[serde(default)]
    rules: Vec<String>,
}

// ── RuleSet ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RuleSet {
    pub name: String,
    pub behavior: ProviderBehavior,
    /// Classical 行为下，端口/进程/复合等无法索引的规则
    // classical_rules: Vec<Rule>,
    /// 所有行为均填充这两个索引（Classical 也走索引，消除线性扫描）
    domain_index: Arc<DomainIndex>,
    ip_index: Arc<IpIndex>,
    pub source: RuleSetSource,
    pub loaded_at: Instant,
    pub ttl: Option<Duration>,
    pub rule_count: usize,
}

#[derive(Debug, Clone)]
pub enum RuleSetSource {
    File(PathBuf),
    Url(String),
    Inline,
}

impl RuleSet {
    pub fn is_stale(&self) -> bool {
        self.ttl
            .map(|t| self.loaded_at.elapsed() > t)
            .unwrap_or(false)
    }

    /// 该规则集是否真的含 IP 谓词（决定路由判定是否需要解析域名）。
    /// 空/纯域名的规则集永远不该触发 DNS。
    pub fn requires_resolution(&self) -> bool {
        match self.behavior {
            ProviderBehavior::Domain => false,
            _ => {
                !self.ip_index.networks.is_empty()
                    || !self.ip_index.exact_v4.is_empty()
                    || !self.ip_index.exact_v6.is_empty()
            }
        }
    }

    pub fn parse_content(
        name: &str,
        content: &str,
        behavior: &ProviderBehavior,
        source: RuleSetSource,
        ttl: Option<Duration>,
    ) -> Self {
        let lines = Self::extract_lines(content);

        let mut domain_index = DomainIndex::default();
        let mut ip_index = IpIndex::default();
        let mut classical_rules = Vec::new();

        match behavior {
            ProviderBehavior::Domain => {
                for line in &lines {
                    let (pattern, action) = if let Some(rest) = line.strip_prefix("+.") {
                        (
                            DomainPattern::Suffix(rest.to_lowercase()),
                            RuleAction::Direct,
                        )
                    } else {
                        (
                            DomainPattern::Exact(line.to_lowercase()),
                            RuleAction::Direct,
                        )
                    };
                    domain_index.insert(pattern, action);
                }
                domain_index.build();
            }
            ProviderBehavior::IpCidr => {
                for line in &lines {
                    match line.parse::<IpNetwork>() {
                        Ok(net) => ip_index.insert(net, RuleAction::Direct),
                        Err(_) => warn!("Invalid CIDR in rule set '{}': {}", name, line),
                    }
                }
                ip_index.build();
            }
            ProviderBehavior::Classical => {
                // 域名和 IP 规则走索引；其余（端口/进程/复合）保留在 classical_rules
                for line in &lines {
                    let with_action = format!("{},DIRECT", line);
                    match Rule::from_str(&with_action) {
                        Ok(r) => {
                            let Rule {
                                rule_type,
                                action,
                                description,
                                no_resolve,
                            } = r;
                            match rule_type {
                                RuleType::Domain(p) => {
                                    domain_index.insert(p, action);
                                }
                                RuleType::Network(net) => {
                                    ip_index.insert(net, action);
                                }
                                RuleType::Ip(ip_addr) => {
                                    let prefix = if ip_addr.is_ipv4() { 32 } else { 128 };
                                    if let Ok(net) = IpNetwork::new(ip_addr, prefix) {
                                        ip_index.insert(net, action);
                                    }
                                }
                                rule_type => classical_rules.push(Rule {
                                    rule_type,
                                    action,
                                    description,
                                    no_resolve,
                                }),
                            }
                        }
                        Err(e) => warn!("Classical rule error in '{}' '{}': {}", name, line, e),
                    }
                }
                domain_index.build();
                ip_index.build();
            }
        }

        Self::assemble(
            name,
            behavior,
            domain_index,
            ip_index,
            &classical_rules,
            source,
            ttl,
        )
    }

    /// 按文件内容加载 provider（文本 / Clash YAML / `.mrs`）。
    ///
    /// 格式判定顺序：显式 `format` 配置 → 文件头嗅探
    /// （zstd 帧头 → `.mrs`；明文 `SRS` → sing-box；其余按 UTF-8 文本）。
    pub fn parse_provider_bytes(
        name: &str,
        raw: &[u8],
        behavior: &ProviderBehavior,
        source: RuleSetSource,
        ttl: Option<Duration>,
        format: Option<ProviderFormat>,
    ) -> Result<Self, String> {
        let detected = match format {
            Some(ProviderFormat::Mrs) => mrs::Detected::Mrs,
            Some(ProviderFormat::Srs) => mrs::Detected::Srs,
            Some(ProviderFormat::Yaml) | Some(ProviderFormat::Text) => mrs::Detected::Text,
            None => mrs::detect(raw),
        };

        match detected {
            mrs::Detected::Mrs => Self::parse_mrs(name, raw, behavior, source, ttl),
            mrs::Detected::Srs => Err(
                "不支持 sing-box .srs 规则集；请用 `sing-box rule-set decompile` 转成文本，\
                 或用 mihomo `convert-ruleset` 转成 .mrs"
                    .to_string(),
            ),
            mrs::Detected::Text => {
                let text = std::str::from_utf8(raw)
                    .map_err(|e| format!("规则集不是合法 UTF-8 文本: {}", e))?;
                Ok(Self::parse_content(name, text, behavior, source, ttl))
            }
        }
    }

    fn parse_mrs(
        name: &str,
        raw: &[u8],
        behavior: &ProviderBehavior,
        source: RuleSetSource,
        ttl: Option<Duration>,
    ) -> Result<Self, String> {
        let decoded = mrs::parse(raw).map_err(|e| format!(".mrs 解析失败: {}", e))?;

        let mut domain_index = DomainIndex::default();
        let mut ip_index = IpIndex::default();

        match (decoded.body, behavior) {
            (mrs::MrsBody::Domain(entries), ProviderBehavior::Domain) => {
                let declared = decoded.declared_count;
                if declared != entries.len() {
                    // 不是错误，但说明文件里精确/后缀被合并过，值得留一条线索。
                    debug!(
                        ".mrs '{}': 头部声明 {} 条，trie 展开 {} 条",
                        name,
                        declared,
                        entries.len()
                    );
                }
                for entry in entries {
                    let pattern = if entry.sub_only {
                        DomainPattern::Suffix(entry.name.to_lowercase())
                    } else {
                        DomainPattern::Exact(entry.name.to_lowercase())
                    };
                    domain_index.insert(pattern, RuleAction::Direct);
                }
                domain_index.build();
            }
            (mrs::MrsBody::IpCidr(nets), ProviderBehavior::IpCidr) => {
                for net in nets {
                    ip_index.insert(net, RuleAction::Direct);
                }
                ip_index.build();
            }
            (body, wanted) => {
                return Err(format!(
                    "behavior 不匹配：配置为 {:?}，但 .mrs 文件是 {}",
                    wanted,
                    body.kind()
                ));
            }
        }

        Ok(Self::assemble(
            name,
            behavior,
            domain_index,
            ip_index,
            &[],
            source,
            ttl,
        ))
    }

    /// 用已建好的索引构造 `RuleSet`（文本与 `.mrs` 两条加载路径共用）。
    fn assemble(
        name: &str,
        behavior: &ProviderBehavior,
        domain_index: DomainIndex,
        ip_index: IpIndex,
        classical_rules: &[Rule],
        source: RuleSetSource,
        ttl: Option<Duration>,
    ) -> Self {
        let suffix_count: usize = domain_index.suffix_buckets.values().map(|b| b.len()).sum();
        let rule_count = domain_index.exact.len()
            + suffix_count
            + domain_index.slow.len()
            + ip_index.exact_v4.len()
            + ip_index.exact_v6.len()
            + ip_index.networks.len()
            + classical_rules.len();

        info!(
            "Rule set '{}' loaded {} rules ({:?})",
            name, rule_count, behavior
        );

        RuleSet {
            name: name.to_string(),
            behavior: behavior.clone(),
            // classical_rules,
            domain_index: Arc::new(domain_index),
            ip_index: Arc::new(ip_index),
            source,
            loaded_at: Instant::now(),
            ttl,
            rule_count,
        }
    }

    fn extract_lines(content: &str) -> Vec<String> {
        let has_payload = content.lines().any(|l| l.trim() == "payload:");

        if has_payload {
            let mut in_payload = false;
            let mut lines = Vec::new();
            for raw in content.lines() {
                let trimmed = raw.trim();
                if trimmed == "payload:" {
                    in_payload = true;
                    continue;
                }
                if in_payload {
                    let entry_raw = if let Some(rest) = trimmed.strip_prefix("- ") {
                        rest
                    } else if let Some(rest) = trimmed.strip_prefix('-') {
                        rest
                    } else {
                        if !trimmed.is_empty()
                            && !trimmed.starts_with('#')
                            && !trimmed.starts_with(' ')
                        {
                            break;
                        }
                        continue;
                    };
                    let entry = entry_raw
                        .trim()
                        .trim_matches(|c: char| c == '\'' || c == '"');
                    if !entry.is_empty() {
                        lines.push(entry.to_string());
                    }
                }
            }
            lines
        } else {
            content
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"))
                .map(|l| l.to_string())
                .collect()
        }
    }

    pub fn matches_domain(&self, domain: &str) -> bool {
        match self.behavior {
            // Classical 行为的域名规则已进索引，与 Domain 行为走同一路径
            ProviderBehavior::Domain | ProviderBehavior::Classical => {
                self.domain_index.lookup(domain).is_some()
            }
            ProviderBehavior::IpCidr => false,
        }
    }

    pub fn matches_ip(&self, ip: &IpAddr) -> bool {
        match self.behavior {
            // Classical 行为的 IP 规则已进索引，与 IpCidr 行为走同一路径
            ProviderBehavior::IpCidr | ProviderBehavior::Classical => {
                self.ip_index.lookup(ip).is_some()
            }
            ProviderBehavior::Domain => false,
        }
    }
}

// ── MatchContext ──────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct MatchContext {
    pub src_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub network: Option<NetworkProtocol>,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
}

/// 静态空 ctx，route_domain / route_ip 不再每次在栈上初始化
static EMPTY_CTX: Lazy<MatchContext> = Lazy::new(MatchContext::default);

// ── ProxyRouter ───────────────────────────────────────────────────────────────

pub struct ProxyRouter {
    domain_index: DomainIndex,
    ip_index: IpIndex,
    slow_rules: Vec<Rule>,

    pub default_action: RuleAction,
    rule_sets: Arc<ArcSwap<HashMap<String, RuleSet>>>,
    pub geoip_reader: Option<maxminddb::Reader<Vec<u8>>>,
    /// 是否存在"需要解析域名才能匹配"的 IP 谓词规则（无 no-resolve）。
    /// false 时 `resolve_action` 永不触发 DNS —— 这是防泄漏的第一性原理：
    /// 能不解析就不解析。
    needs_ip_resolution: AtomicBool,
}

impl std::fmt::Debug for ProxyRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let suffix_count: usize = self
            .domain_index
            .suffix_buckets
            .values()
            .map(|b| b.len())
            .sum();
        let ip_total = self.ip_index.networks.len()
            + self.ip_index.exact_v4.len()
            + self.ip_index.exact_v6.len();
        f.debug_struct("ProxyRouter")
            .field("domain_exact", &self.domain_index.exact.len())
            .field("domain_suffix", &suffix_count)
            .field("ip_total", &ip_total)
            .field("slow_rules", &self.slow_rules.len())
            .field("default_action", &self.default_action)
            .finish()
    }
}

// ── 内置规则：Lazy 静态缓存，多次构造 Router 只解析一次 ──────────────────────

static BUILTIN_RULES: Lazy<Vec<Rule>> = Lazy::new(make_builtin_direct_rules);

fn builtin_direct_rules() -> Vec<Rule> {
    BUILTIN_RULES.clone()
}

fn make_builtin_direct_rules() -> Vec<Rule> {
    const CIDRS: &[&str] = &[
        "127.0.0.0/8",
        "::1/128",
        "0.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "fe80::/10",
        "224.0.0.0/4",
        "ff00::/8",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "240.0.0.0/4",
    ];

    const LOCAL_DOMAINS: &[(&str, bool)] = &[
        ("localhost", false),
        ("local", true),
        ("localdomain", true),
        ("internal", true),
        ("lan", true),
        ("home.arpa", true),
    ];

    let mut rules = Vec::with_capacity(CIDRS.len() + LOCAL_DOMAINS.len());

    rules.extend(CIDRS.iter().filter_map(|c| {
        c.parse::<IpNetwork>().ok().map(|net| Rule {
            rule_type: RuleType::Network(net),
            action: RuleAction::Direct,
            description: Some("builtin: private/reserved".into()),
            // 内置私网/保留段不触发本地解析：字面 IP 目标仍然直接命中；
            // 只有用户显式配置了"需要解析"的 IP 规则（无 no-resolve）时
            // 才会走 DnsResolver（见 ProxyRouter::needs_ip_resolution）。
            no_resolve: true,
        })
    }));

    for &(domain, is_suffix) in LOCAL_DOMAINS {
        let pat = if is_suffix {
            DomainPattern::Suffix(domain.to_string())
        } else {
            DomainPattern::Exact(domain.to_string())
        };
        rules.push(Rule {
            rule_type: RuleType::Domain(pat),
            action: RuleAction::Direct,
            description: Some("builtin: local domain".into()),
            no_resolve: true,
        });
    }

    rules
}

// ── Provider 加载辅助 ──────────────────────────────────────────────────────────────────────

async fn fetch_url(url: &str) -> Result<Vec<u8>, RouterError> {
    // 必须按字节读：`.mrs` 是二进制，`.text()` 会破坏内容。
    let bytes = reqwest::get(url)
        .await
        .map_err(|e| RouterError::Network(e.to_string()))?
        .bytes()
        .await
        .map_err(|e| RouterError::Network(e.to_string()))?;
    Ok(bytes.to_vec())
}

async fn load_provider_entry(
    name: &str,
    cfg: &RuleProviderConfig,
    base_dir: &Path,
) -> Option<(String, RuleSet)> {
    let ttl = cfg.interval.map(Duration::from_secs);

    match cfg.source_type {
        ProviderSourceType::Http => {
            let cache_path = cfg.path.as_deref().map(|p| base_dir.join(p));

            let cached = if let Some(ref cp) = cache_path {
                if cp.exists() {
                    tokio::fs::read(cp).await.ok()
                } else {
                    None
                }
            } else {
                None
            };

            let raw: Vec<u8> = if let Some(c) = cached {
                c
            } else if let Some(url) = &cfg.url {
                match fetch_url(url).await {
                    Ok(c) => {
                        if let Some(ref cp) = cache_path {
                            if let Some(parent) = cp.parent() {
                                let _ = tokio::fs::create_dir_all(parent).await;
                            }
                            let _ = tokio::fs::write(cp, &c).await;
                        }
                        c
                    }
                    Err(e) => {
                        warn!("Failed to fetch rule set '{}': {}", name, e);
                        return None;
                    }
                }
            } else {
                warn!("Rule set '{}' has no url and no local cache", name);
                return None;
            };

            let source = RuleSetSource::Url(cfg.url.clone().unwrap_or_default());
            match RuleSet::parse_provider_bytes(name, &raw, &cfg.behavior, source, ttl, cfg.format)
            {
                Ok(set) => Some((name.to_string(), set)),
                Err(e) => {
                    warn!("Failed to parse rule set '{}': {}", name, e);
                    None
                }
            }
        }

        ProviderSourceType::File => {
            let path = cfg.path.as_deref().map(|p| base_dir.join(p))?;
            match tokio::fs::read(&path).await {
                Ok(raw) => match RuleSet::parse_provider_bytes(
                    name,
                    &raw,
                    &cfg.behavior,
                    RuleSetSource::File(path),
                    ttl,
                    cfg.format,
                ) {
                    Ok(set) => Some((name.to_string(), set)),
                    Err(e) => {
                        warn!("Failed to parse rule set file '{}': {}", name, e);
                        None
                    }
                },
                Err(e) => {
                    warn!("Failed to read rule set file '{}': {}", name, e);
                    None
                }
            }
        }

        ProviderSourceType::Inline => None,
    }
}

// ── ProxyRouter impl ──────────────────────────────────────────────────────────

impl ProxyRouter {
    pub async fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, RouterError> {
        let content = tokio::fs::read_to_string(&path).await?;
        let base_dir = path.as_ref().parent().unwrap_or(Path::new("."));
        Self::from_yaml_str(&content, base_dir).await
    }

    pub async fn from_yaml_str(content: &str, base_dir: &Path) -> Result<Self, RouterError> {
        let config: ProxyConfig = serde_yaml::from_str(content)
            .map_err(|e: serde_yaml::Error| RouterError::Yaml(e.to_string()))?;

        let (rule_providers, config_rules) = (config.rule_providers, config.rules);

        // 并发加载所有 provider：从 O(n×RTT) 降至 O(RTT)
        let mut join_set = tokio::task::JoinSet::new();
        for (name, cfg) in rule_providers {
            let base_dir_buf = base_dir.to_path_buf();
            join_set.spawn(async move { load_provider_entry(&name, &cfg, &base_dir_buf).await });
        }

        let mut rule_sets_map: HashMap<String, RuleSet> = HashMap::new();
        while let Some(result) = join_set.join_next().await {
            if let Ok(Some((name, set))) = result {
                rule_sets_map.insert(name, set);
            }
        }
        let rule_sets = Arc::new(ArcSwap::from_pointee(rule_sets_map));

        let mut default_action = RuleAction::Proxy;
        let mut all_rules = builtin_direct_rules();

        for line in &config_rules {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match Rule::from_str(line) {
                Ok(rule) => {
                    if matches!(rule.rule_type, RuleType::Final) {
                        default_action = rule.action.clone();
                    } else {
                        all_rules.push(rule);
                    }
                }
                Err(e) => warn!("Rule parse error '{}': {}", line, e),
            }
        }

        let geoip_reader = Self::load_geoip_database();
        let router = Self::build_indexes(all_rules, default_action, rule_sets, geoip_reader);

        let suffix_count: usize = router
            .domain_index
            .suffix_buckets
            .values()
            .map(|b| b.len())
            .sum();
        let ip_total = router.ip_index.networks.len()
            + router.ip_index.exact_v4.len()
            + router.ip_index.exact_v6.len();

        info!(
            "Router ready — domain exact={}, suffix={}, IPs={}, slow={}, rule_sets={}, needs-resolve={}",
            router.domain_index.exact.len(),
            suffix_count,
            ip_total,
            router.slow_rules.len(),
            router.rule_sets.load().len(),
            router.needs_ip_resolution(),
        );

        Ok(router)
    }

    pub fn from_plain_str(content: &str) -> Result<Self, RouterError> {
        let mut default_action = RuleAction::Proxy;
        let mut all_rules = builtin_direct_rules();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            match Rule::from_str(line) {
                Ok(rule) => {
                    if matches!(rule.rule_type, RuleType::Final) {
                        default_action = rule.action.clone();
                    } else {
                        all_rules.push(rule);
                    }
                }
                Err(e) => warn!("Rule parse error '{}': {}", line, e),
            }
        }

        let geoip_reader = Self::load_geoip_database();
        let router = Self::build_indexes(
            all_rules,
            default_action,
            Arc::new(ArcSwap::from_pointee(HashMap::new())),
            geoip_reader,
        );

        let suffix_count: usize = router
            .domain_index
            .suffix_buckets
            .values()
            .map(|b| b.len())
            .sum();
        let ip_total = router.ip_index.networks.len()
            + router.ip_index.exact_v4.len()
            + router.ip_index.exact_v6.len();

        info!(
            "Router ready — domain exact={}, suffix={}, IPs={}, slow={}",
            router.domain_index.exact.len(),
            suffix_count,
            ip_total,
            router.slow_rules.len(),
        );

        Ok(router)
    }

    fn build_indexes(
        rules: Vec<Rule>,
        default_action: RuleAction,
        rule_sets: Arc<ArcSwap<HashMap<String, RuleSet>>>,
        geoip_reader: Option<maxminddb::Reader<Vec<u8>>>,
    ) -> Self {
        // 先判定"路由是否需要本地解析"：任何无 no-resolve 的 IP 谓词规则
        // 才会触发 DNS。RULE-SET 按 behavior 细化（domain 型永远不需要）。
        let needs_ip_resolution = {
            let sets = rule_sets.load();
            rules.iter().any(|rule| {
                if rule.no_resolve {
                    return false;
                }
                match &rule.rule_type {
                    RuleType::RuleSet(name) => sets
                        .get(name.as_str())
                        .map(|set| set.requires_resolution())
                        .unwrap_or(false),
                    other => rule_type_needs_ip(other),
                }
            })
        };

        let mut domain_index = DomainIndex::default();
        let mut ip_index = IpIndex::default();
        let mut slow_rules = Vec::new();

        for rule in rules {
            // 解构以便在 match 各分支中自由移动各字段
            let Rule {
                rule_type,
                action,
                description,
                no_resolve,
            } = rule;
            match rule_type {
                RuleType::Domain(p) => {
                    domain_index.insert(p, action);
                }
                RuleType::Network(net) => {
                    ip_index.insert(net, action);
                }
                // 单 IP 规则进 exact 哈希表，消除 slow_rules 线性扫描
                RuleType::Ip(ip_addr) => {
                    let prefix = if ip_addr.is_ipv4() { 32 } else { 128 };
                    if let Ok(net) = IpNetwork::new(ip_addr, prefix) {
                        ip_index.insert(net, action);
                    }
                }
                rule_type => {
                    slow_rules.push(Rule {
                        rule_type,
                        action,
                        description,
                        no_resolve,
                    });
                }
            }
        }

        domain_index.build();
        ip_index.build();

        Self {
            domain_index,
            ip_index,
            slow_rules,
            default_action,
            rule_sets,
            geoip_reader,
            needs_ip_resolution: AtomicBool::new(needs_ip_resolution),
        }
    }

    pub async fn load_rule_set_file(
        &self,
        name: &str,
        path: &str,
        behavior: ProviderBehavior,
        ttl: Option<Duration>,
    ) -> Result<(), RouterError> {
        let raw = tokio::fs::read(path).await?;
        let set = RuleSet::parse_provider_bytes(
            name,
            &raw,
            &behavior,
            RuleSetSource::File(path.into()),
            ttl,
            None,
        )
        .map_err(RouterError::Parse)?;
        self.install_rule_set(name, set);
        Ok(())
    }

    pub async fn load_rule_set_url(
        &self,
        name: &str,
        url: &str,
        behavior: ProviderBehavior,
        ttl: Option<Duration>,
    ) -> Result<(), RouterError> {
        let raw = fetch_url(url).await?;
        let set = RuleSet::parse_provider_bytes(
            name,
            &raw,
            &behavior,
            RuleSetSource::Url(url.to_string()),
            ttl,
            None,
        )
        .map_err(RouterError::Parse)?;
        self.install_rule_set(name, set);
        Ok(())
    }

    /// ArcSwap 写：clone map → 插入 → 原子替换指针。
    /// 同时按需把"需要解析"标记置位（IP 型规则集可能带来新的 IP 谓词）。
    fn install_rule_set(&self, name: &str, set: RuleSet) {
        if set.requires_resolution() {
            self.needs_ip_resolution.store(true, Ordering::Relaxed);
        }
        let mut new_map = (**self.rule_sets.load()).clone();
        new_map.insert(name.to_string(), set);
        self.rule_sets.store(Arc::new(new_map));
    }

    pub async fn refresh_stale_rule_sets(&self) {
        // 只 clone 名称列表，减少持锁数据量
        let stale_names: Vec<String> = {
            let sets = self.rule_sets.load();
            sets.values()
                .filter(|s| s.is_stale())
                .map(|s| s.name.clone())
                .collect()
        };

        for name in stale_names {
            let (source, behavior, ttl) = {
                let sets = self.rule_sets.load();
                match sets.get(&name) {
                    Some(s) => (s.source.clone(), s.behavior.clone(), s.ttl),
                    None => continue,
                }
            };
            let result = match &source {
                RuleSetSource::File(p) => {
                    self.load_rule_set_file(&name, p.to_str().unwrap_or(""), behavior, ttl)
                        .await
                }
                RuleSetSource::Url(url) => self.load_rule_set_url(&name, url, behavior, ttl).await,
                RuleSetSource::Inline => continue,
            };
            match result {
                Ok(_) => info!("Refreshed rule set '{}'", name),
                Err(e) => warn!("Failed to refresh rule set '{}': {}", name, e),
            }
        }
    }

    pub fn route_domain(&self, domain: &str) -> RuleAction {
        self.route_domain_opt(domain)
            .unwrap_or_else(|| self.default_action.clone())
    }

    /// 仅域名规则匹配；未命中返回 None（调用方可据此决定是否需要解析 IP）。
    pub fn route_domain_opt(&self, domain: &str) -> Option<RuleAction> {
        if let Some(action) = self.domain_index.lookup(domain) {
            return Some(action.clone());
        }
        for rule in &self.slow_rules {
            if let Some(action) = self.eval_slow_rule(rule, Some(domain), None, &EMPTY_CTX) {
                return Some(action);
            }
        }
        None
    }

    pub fn route_ip(&self, ip: &IpAddr) -> RuleAction {
        self.route_ip_opt(ip)
            .unwrap_or_else(|| self.default_action.clone())
    }

    /// 仅 IP 谓词规则匹配；未命中返回 None。
    pub fn route_ip_opt(&self, ip: &IpAddr) -> Option<RuleAction> {
        if let Some(action) = self.ip_index.lookup(ip) {
            return Some(action.clone());
        }
        for rule in &self.slow_rules {
            if let Some(action) = self.eval_slow_rule(rule, None, Some(ip), &EMPTY_CTX) {
                return Some(action);
            }
        }
        None
    }

    /// 路由判定是否需要把域名解析成 IP（存在无 no-resolve 的 IP 谓词规则）。
    ///
    /// false 时上游调用方**不应**触发任何 DNS 查询（防泄漏第一性原理）。
    pub fn needs_ip_resolution(&self) -> bool {
        self.needs_ip_resolution.load(Ordering::Relaxed)
    }

    pub fn route(
        &self,
        domain: Option<&str>,
        ip: Option<&IpAddr>,
        ctx: &MatchContext,
    ) -> RuleAction {
        if let Some(d) = domain {
            if let Some(action) = self.domain_index.lookup(d) {
                return action.clone();
            }
        }
        if let Some(i) = ip {
            if let Some(action) = self.ip_index.lookup(i) {
                return action.clone();
            }
        }
        for rule in &self.slow_rules {
            // 根据 ctx 字段是否有值，提前跳过必然不匹配的规则
            let skip = match &rule.rule_type {
                RuleType::GeoLocation(_) => ip.is_none(),
                RuleType::DestPort(_) => ctx.dst_port.is_none(),
                RuleType::SrcPort(_) => ctx.src_port.is_none(),
                RuleType::ProcessName(_) => ctx.process_name.is_none(),
                RuleType::ProcessPath(_) => ctx.process_path.is_none(),
                RuleType::Network2(_) => ctx.network.is_none(),
                RuleType::SrcNetwork(_) => ctx.src_ip.is_none(),
                _ => false,
            };
            if skip {
                continue;
            }
            if let Some(action) = self.eval_slow_rule(rule, domain, ip, ctx) {
                return action;
            }
        }
        self.default_action.clone()
    }

    fn eval_slow_rule(
        &self,
        rule: &Rule,
        domain: Option<&str>,
        ip: Option<&IpAddr>,
        ctx: &MatchContext,
    ) -> Option<RuleAction> {
        if self.matches_slow(&rule.rule_type, domain, ip, ctx) {
            Some(rule.action.clone())
        } else {
            None
        }
    }

    fn matches_slow(
        &self,
        rt: &RuleType,
        domain: Option<&str>,
        ip: Option<&IpAddr>,
        ctx: &MatchContext,
    ) -> bool {
        match rt {
            // 进入 slow_rules 的 Domain 规则只有 Keyword/Regex/Wildcard，
            // 不再重复查询 domain_index（已在 route() 快路径中处理）
            RuleType::Domain(p) => domain
                .map(|d| self.matches_domain_pattern(d, p))
                .unwrap_or(false),

            RuleType::Network(net) => ip.map(|a| net.contains(*a)).unwrap_or(false),

            RuleType::Ip(rule_ip) => ip.map(|a| a == rule_ip).unwrap_or(false),

            RuleType::SrcNetwork(net) => ctx.src_ip.map(|a| net.contains(a)).unwrap_or(false),

            RuleType::GeoLocation(cc) => {
                if cc == "LAN" {
                    ip.map(is_private_ip).unwrap_or(false)
                } else {
                    ip.and_then(|a| self.get_ip_country(a))
                        .map(|c| c.eq_ignore_ascii_case(cc))
                        .unwrap_or(false)
                }
            }

            RuleType::DestPort(m) => ctx.dst_port.map(|p| m.matches(p)).unwrap_or(false),
            RuleType::SrcPort(m) => ctx.src_port.map(|p| m.matches(p)).unwrap_or(false),

            RuleType::ProcessName(n) => ctx
                .process_name
                .as_deref()
                .map(|pn| pn.eq_ignore_ascii_case(n))
                .unwrap_or(false),

            RuleType::ProcessPath(p) => ctx
                .process_path
                .as_deref()
                .map(|pp| pp.eq_ignore_ascii_case(p))
                .unwrap_or(false),

            RuleType::Network2(proto) => ctx
                .network
                .as_ref()
                .map(|n| proto == &NetworkProtocol::Any || n == proto)
                .unwrap_or(false),

            RuleType::And(conds) => conds
                .iter()
                .all(|c| self.matches_slow(&c.rule_type, domain, ip, ctx)),

            RuleType::Or(conds) => conds
                .iter()
                .any(|c| self.matches_slow(&c.rule_type, domain, ip, ctx)),

            RuleType::Not(cond) => !self.matches_slow(&cond.rule_type, domain, ip, ctx),

            RuleType::RuleSet(name) => {
                let sets = self.rule_sets.load();
                if let Some(set) = sets.get(name.as_str()) {
                    let dm = domain.map(|d| set.matches_domain(d)).unwrap_or(false);
                    let im = ip.map(|i| set.matches_ip(i)).unwrap_or(false);
                    dm || im
                } else {
                    debug!("RULE-SET '{}' not loaded, skipping", name);
                    false
                }
            }

            RuleType::Final => true,
        }
    }

    fn matches_domain_pattern(&self, domain: &str, pattern: &DomainPattern) -> bool {
        match pattern {
            DomainPattern::Wildcard => true,
            DomainPattern::Exact(p) => domain.eq_ignore_ascii_case(p),
            DomainPattern::Suffix(s) => {
                let d = domain.to_lowercase();
                domain_has_suffix(&d, s)
            }
            DomainPattern::Keyword(kw) => domain.to_lowercase().contains(kw.as_str()),
            DomainPattern::Regex(pat) => regex_matches(pat, domain),
        }
    }

    pub fn get_ip_country(&self, ip: &IpAddr) -> Option<String> {
        let reader = self.geoip_reader.as_ref()?;
        let lookup = reader.lookup(*ip).ok()?;
        if let Some(country) = lookup.decode::<maxminddb::geoip2::Country>().ok()? {
            country.country.iso_code.map(|c: &str| c.to_string())
        } else {
            None
        }
    }

    /*
       GeoLite2-Country.mmdb
       https://github.com/P3TERX/GeoLite.mmdb
       https://github.com/8bitsaver/maxmind-geoip

       Country.mmdb
       https://github.com/runetfreedom/russia-blocked-geoip
       https://github.com/Dreamacro/maxmind-geoip

       Merged-IP.mmdb
       https://github.com/NetworkCats/Merged-IP-Data
    */
    fn load_geoip_database() -> Option<maxminddb::Reader<Vec<u8>>> {
        for path in geoip_candidate_paths() {
            if let Ok(db) = std::fs::read(&path) {
                if let Ok(reader) = maxminddb::Reader::from_source(db) {
                    info!("Loaded GeoIP database from: {}", path.display());
                    return Some(reader);
                }
            }
        }
        info!("GeoIP database not found — GEOIP rules will be skipped");
        None
    }

    pub fn stats(&self) -> RouterStats {
        let suffix_count: usize = self
            .domain_index
            .suffix_buckets
            .values()
            .map(|b| b.len())
            .sum();
        let domain = self.domain_index.exact.len() + suffix_count + self.domain_index.slow.len();
        let ip = self.ip_index.networks.len()
            + self.ip_index.exact_v4.len()
            + self.ip_index.exact_v6.len();

        let (mut port, mut process, mut geoip, mut ruleset, mut composite) = (0usize, 0, 0, 0, 0);
        let (mut proxy_r, mut direct_r, mut reject_r) = (0usize, 0, 0);

        for rule in &self.slow_rules {
            match &rule.action {
                RuleAction::Proxy | RuleAction::Named(_) => proxy_r += 1,
                RuleAction::Direct => direct_r += 1,
                RuleAction::Reject => reject_r += 1,
            }
            match &rule.rule_type {
                RuleType::GeoLocation(_) => geoip += 1,
                RuleType::DestPort(_) | RuleType::SrcPort(_) => port += 1,
                RuleType::ProcessName(_) | RuleType::ProcessPath(_) => process += 1,
                RuleType::RuleSet(_) => ruleset += 1,
                RuleType::And(_) | RuleType::Or(_) | RuleType::Not(_) => composite += 1,
                _ => {}
            }
        }

        let (loaded_sets, total_set_rules) = {
            let sets = self.rule_sets.load();
            (sets.len(), sets.values().map(|s| s.rule_count).sum())
        };

        RouterStats {
            total_rules: domain + ip + self.slow_rules.len(),
            domain_rules: domain,
            ip_rules: ip,
            port_rules: port,
            process_rules: process,
            geoip_rules: geoip,
            ruleset_refs: ruleset,
            composite_rules: composite,
            loaded_rule_sets: loaded_sets,
            total_rule_set_rules: total_set_rules,
            proxy_rules: proxy_r,
            direct_rules: direct_r,
            reject_rules: reject_r,
            default_action: self.default_action.clone(),
        }
    }
}

// ── 工具函数 ──────────────────────────────────────────────────────────────────

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            // 按照 RFC 规范，涵盖所有非公网段
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() || v6.is_unique_local()
        }
    }
}

// ── RouterStats ───────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct RouterStats {
    pub total_rules: usize,
    pub domain_rules: usize,
    pub ip_rules: usize,
    pub port_rules: usize,
    pub process_rules: usize,
    pub geoip_rules: usize,
    pub ruleset_refs: usize,
    pub composite_rules: usize,
    pub loaded_rule_sets: usize,
    pub total_rule_set_rules: usize,
    pub proxy_rules: usize,
    pub direct_rules: usize,
    pub reject_rules: usize,
    pub default_action: RuleAction,
}

// ── RouteClassifier：给 DNS 模块按路由选上游组 ────────────────────────────────
//
// 只做纯域名规则匹配，绝不触发 DNS（`route_domain_opt` 只看 domain 索引和
// 含域名的慢规则）。IP 谓词（cncidr/geoip 等 no-resolve 规则）在这里天然
// 不生效 —— 这正是想要的：DNS 查询发生在拿到 IP 之前。
impl crate::dns::RouteClassifier for ProxyRouter {
    fn classify_domain(&self, domain: &str) -> crate::dns::RouteClass {
        let action = self
            .route_domain_opt(domain)
            .unwrap_or_else(|| self.default_action.clone());
        match action {
            RuleAction::Direct => crate::dns::RouteClass::Direct,
            // 代理组 / REJECT：都不应回退到直连 DNS。
            // REJECT 的域名若被查询，用隧道 DNS 至少不会泄漏给本地 ISP。
            RuleAction::Proxy | RuleAction::Reject | RuleAction::Named(_) => {
                crate::dns::RouteClass::Proxy
            }
        }
    }
}

// ── GeoIP 数据库路径与自动下载 ────────────────────────────────────────────────
//
// zks-client-cli 只查找现成的 mmdb 文件；ssp 客户端面向国内用户，
// 保留原 routing.rs 的按需下载逻辑（GEOIP,CN 规则开箱即用）。
// 下载是普通 HTTPS 静态文件获取，与 DNS 防泄漏路径无关。

/// 按顺序查找的候选路径（可执行文件目录优先，其次工作目录）
fn geoip_candidate_paths() -> Vec<PathBuf> {
    let names = [
        "Merged-IP.mmdb",
        "Country.mmdb",
        "GeoLite2-Country.mmdb",
        "GeoIP2-Country.mmdb",
    ];
    let mut out = Vec::with_capacity(names.len() * 2);
    if let Some(exe_dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
    {
        for name in names {
            out.push(exe_dir.join("mmdb").join(name));
        }
    }
    for name in names {
        out.push(PathBuf::from("mmdb").join(name));
    }
    out
}

/// 按顺序尝试的下载镜像（GeoLite2-Country）
const MMDB_MIRRORS: &[&str] = &[
    "https://hk.gh-proxy.org/https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb",
    "https://cdn.jsdelivr.net/gh/P3TERX/GeoLite.mmdb@download/GeoLite2-Country.mmdb",
    "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb",
];

/// 确保存在可用的 GeoIP 数据库：任一候选路径存在即返回该路径；
/// 全部缺失时按镜像顺序下载到 exe 目录（best-effort，失败只告警不阻塞）。
pub async fn ensure_geoip_db() -> Option<PathBuf> {
    let existing = geoip_candidate_paths().into_iter().find(|p| p.exists());
    if let Some(p) = existing {
        return Some(p);
    }

    let dest = match std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
    {
        Some(dir) => dir.join("mmdb").join("GeoLite2-Country.mmdb"),
        None => PathBuf::from("mmdb").join("GeoLite2-Country.mmdb"),
    };
    info!("GeoIP database not found, downloading GeoLite2-Country …");
    match download_mmdb(&dest).await {
        Ok(()) => Some(dest),
        Err(e) => {
            warn!("GeoIP download failed: {} (GEOIP rules will be skipped)", e);
            None
        }
    }
}

async fn download_mmdb(dest: &Path) -> Result<(), String> {
    if let Some(dir) = dest.parent() {
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| format!("create dir: {}", e))?;
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(90))
        .user_agent(crate::get_args().ua.clone())
        .build()
        .map_err(|e| format!("build client: {}", e))?;

    let tmp = dest.with_extension("tmp");
    for &url in MMDB_MIRRORS {
        debug!("GeoIP mirror: {}", url);
        let resp = match client.get(url).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                warn!("GeoIP http {}: {}", r.status(), url);
                continue;
            }
            Err(e) => {
                warn!("GeoIP request failed {}: {}", url, e);
                continue;
            }
        };
        let bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                warn!("GeoIP body read failed {}: {}", url, e);
                continue;
            }
        };
        if bytes.len() < 512 * 1024 {
            warn!("GeoIP response too small ({} bytes): {}", bytes.len(), url);
            continue;
        }
        tokio::fs::write(&tmp, &bytes)
            .await
            .map_err(|e| format!("write tmp: {}", e))?;
        tokio::fs::rename(&tmp, dest)
            .await
            .map_err(|e| format!("rename: {}", e))?;
        info!(
            "GeoIP database downloaded ({:.1} MB)",
            bytes.len() as f64 / 1_048_576.0
        );
        return Ok(());
    }
    Err("all mirrors failed".into())
}

// ── 全局实例与初始化 ──────────────────────────────────────────────────────────

static ROUTER: OnceCell<Arc<ProxyRouter>> = OnceCell::new();

pub fn get_router() -> Option<&'static Arc<ProxyRouter>> {
    ROUTER.get()
}

/// 路由模式：
///   None   → 全部直连（连接仍经 DnsResolver 解析，fail-closed）
///   Global → 全部走代理
///   Rule   → rules.yaml 规则引擎（默认）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingMode {
    None,
    Global,
    Rule,
}

static ROUTING_MODE: OnceCell<RoutingMode> = OnceCell::new();

pub fn routing_mode() -> RoutingMode {
    *ROUTING_MODE.get().unwrap_or(&RoutingMode::Rule)
}

fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// 初始化路由：按模式加载 rules.yaml（含 GeoIP 数据库按需下载）。
/// 加载失败时降级为全局代理（仅告警，不阻塞启动）。
pub async fn init_routing(routing_arg: &str, rules_file: &str) {
    let mode = match routing_arg.to_ascii_lowercase().trim() {
        "none" => RoutingMode::None,
        "global" | "" => RoutingMode::Global,
        "rule" | "rules" => RoutingMode::Rule,
        other => {
            warn!(
                "未识别的 --routing 参数 {:?}（可选 none/global/rule），使用默认 rule。\
                 \n提示：国家直连请改用规则 \"GEOIP,CN,DIRECT\"。",
                other
            );
            RoutingMode::Rule
        }
    };
    ROUTING_MODE.set(mode).ok();

    match mode {
        RoutingMode::None => info!("[路由] 模式: 全部直连"),
        RoutingMode::Global => info!("[路由] 模式: 全部代理"),
        RoutingMode::Rule => {
            let path = exe_dir().join(rules_file);
            if path.exists() {
                // 只有规则确实使用 GEOIP 时才需要 mmdb：
                // 避免无 GEOIP 规则的配置在启动期被下载阻塞（best-effort，失败不阻塞）
                if let Ok(text) = tokio::fs::read_to_string(&path).await {
                    let uses_geoip = text.lines().any(|l| {
                        let t = l.trim();
                        !t.is_empty()
                            && !t.starts_with('#')
                            && t.to_ascii_uppercase().contains("GEOIP")
                    });
                    if uses_geoip {
                        ensure_geoip_db().await;
                    }
                }

                info!("[路由] 加载规则: {}", path.display());
                match ProxyRouter::from_file(&path).await {
                    Ok(router) => {
                        info!("[路由] 规则加载完成: {:?}", router.stats());
                        let _ = ROUTER.set(Arc::new(router));
                    }
                    Err(e) => {
                        error!("[路由] 规则加载失败: {}（降级为全局代理）", e);
                    }
                }
            } else {
                error!(
                    "[路由] 未找到规则文件 {}（降级为全局代理）。\
                     \n请将 rules.yaml 放到可执行文件同目录，或检查 --routing 参数",
                    path.display()
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router(rules: &str) -> ProxyRouter {
        ProxyRouter::from_plain_str(rules).unwrap()
    }

    #[test]
    fn route_classifier_maps_direct_proxy_and_default() {
        use crate::dns::{RouteClass, RouteClassifier};
        let r = router(
            "DOMAIN-SUFFIX,direct.example,DIRECT\n\
             DOMAIN-SUFFIX,proxy.example,PROXY\n\
             DOMAIN-SUFFIX,blocked.example,REJECT\n\
             FINAL,PROXY",
        );
        assert_eq!(r.classify_domain("a.direct.example"), RouteClass::Direct);
        assert_eq!(r.classify_domain("a.proxy.example"), RouteClass::Proxy);
        // REJECT 视为非直连，避免把被屏蔽域名交给本地 DNS
        assert_eq!(r.classify_domain("blocked.example"), RouteClass::Proxy);
        // 未命中任何规则 → 跟随 FINAL 动作
        assert_eq!(r.classify_domain("unknown.example"), RouteClass::Proxy);
    }

    #[test]
    fn route_classifier_honors_direct_final() {
        use crate::dns::{RouteClass, RouteClassifier};
        let r = router("DOMAIN-SUFFIX,proxy.example,PROXY\nFINAL,DIRECT");
        assert_eq!(r.classify_domain("unknown.example"), RouteClass::Direct);
        assert_eq!(r.classify_domain("proxy.example"), RouteClass::Proxy);
    }

    #[test]
    fn no_resolve_ip_rules_never_trigger_dns() {
        // 用户把 IP 规则都标了 no-resolve → 路由判定绝不需要解析域名
        let r = router(
            "DOMAIN-SUFFIX,a.com,DIRECT\n\
             IP-CIDR,1.1.1.0/24,PROXY,no-resolve\n\
             GEOIP,CN,DIRECT,no-resolve\n\
             FINAL,PROXY",
        );
        assert!(!r.needs_ip_resolution());
        // 域名规则命中：不解析
        assert_eq!(r.route_domain_opt("a.com"), Some(RuleAction::Direct));
        assert_eq!(r.route_domain_opt("www.a.com"), Some(RuleAction::Direct));
        // 未命中的域名：保持 None，由调用方直接使用 default_action
        assert_eq!(r.route_domain_opt("github.com"), None);
        // 字面 IP 仍然能命中 no-resolve 规则（no-resolve 只控制"是否解析"）
        assert_eq!(
            r.route_ip(&"1.1.1.1".parse::<IpAddr>().unwrap()),
            RuleAction::Proxy
        );
    }

    #[test]
    fn ip_rule_without_no_resolve_requires_resolution() {
        let r = router(
            "IP-CIDR,1.1.1.0/24,PROXY\n\
             FINAL,DIRECT",
        );
        assert!(r.needs_ip_resolution());
    }

    #[test]
    fn builtin_private_rules_do_not_require_resolution() {
        // 只有内置私网/保留段 + FINAL 时也不应触发 DNS
        let r = router("FINAL,PROXY");
        assert!(!r.needs_ip_resolution());
        // 但字面私网 IP 仍走 Direct（内置规则）
        assert_eq!(
            r.route_ip(&"10.1.2.3".parse::<IpAddr>().unwrap()),
            RuleAction::Direct
        );
        assert_eq!(
            r.route_ip(&"127.0.0.1".parse::<IpAddr>().unwrap()),
            RuleAction::Direct
        );
    }

    #[test]
    fn route_ip_opt_reports_match_only() {
        let r = router(
            "IP-CIDR,203.0.113.0/24,DIRECT,no-resolve\n\
             FINAL,PROXY",
        );
        assert_eq!(
            r.route_ip_opt(&"203.0.113.5".parse::<IpAddr>().unwrap()),
            Some(RuleAction::Direct)
        );
        assert_eq!(r.route_ip_opt(&"8.8.8.8".parse::<IpAddr>().unwrap()), None);
    }

    #[test]
    fn ruleset_requires_resolution_only_with_ip_entries() {
        let domain_set = RuleSet::parse_content(
            "d",
            "a.com\nb.com",
            &ProviderBehavior::Domain,
            RuleSetSource::Inline,
            None,
        );
        assert!(!domain_set.requires_resolution());

        let ip_set = RuleSet::parse_content(
            "i",
            "1.1.1.0/24",
            &ProviderBehavior::IpCidr,
            RuleSetSource::Inline,
            None,
        );
        assert!(ip_set.requires_resolution());

        // Classical 规则集只有域名时不应触发解析（如 applications.txt）
        let classical_domain = RuleSet::parse_content(
            "c",
            "DOMAIN-SUFFIX,a.com",
            &ProviderBehavior::Classical,
            RuleSetSource::Inline,
            None,
        );
        assert!(!classical_domain.requires_resolution());

        let classical_ip = RuleSet::parse_content(
            "c2",
            "IP-CIDR,2.2.2.0/24",
            &ProviderBehavior::Classical,
            RuleSetSource::Inline,
            None,
        );
        assert!(classical_ip.requires_resolution());
    }

    // ── .mrs 规则集 ──────────────────────────────────────────────────────────

    fn mrs_fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("mrs")
            .join(name)
    }

    fn load_mrs(name: &str, behavior: ProviderBehavior) -> Result<RuleSet, String> {
        let raw = std::fs::read(mrs_fixture(name)).expect("读取 .mrs fixture");
        RuleSet::parse_provider_bytes(name, &raw, &behavior, RuleSetSource::Inline, None, None)
    }

    #[test]
    fn mrs_domain_set_parses_from_bytes() {
        let set = load_mrs("115.mrs", ProviderBehavior::Domain).expect("解析 .mrs domain");
        assert!(!set.requires_resolution(), "纯域名规则集不该触发 DNS");
        // 14 条 +.xxx → 精确 14 + 后缀 14
        assert_eq!(set.rule_count, 28);
        assert!(set.domain_index.lookup("115.com").is_some());
        assert!(set.domain_index.lookup("www.115.com").is_some());
        assert!(set.domain_index.lookup("example.org").is_none());
    }

    #[test]
    fn mrs_ipcidr_set_parses_from_bytes() {
        let set = load_mrs("private.mrs", ProviderBehavior::IpCidr).expect("解析 .mrs ipcidr");
        assert!(set.requires_resolution(), "IP 规则集应触发解析");
        assert!(set
            .ip_index
            .lookup(&"10.1.2.3".parse::<IpAddr>().unwrap())
            .is_some());
        assert!(set
            .ip_index
            .lookup(&"192.168.1.1".parse::<IpAddr>().unwrap())
            .is_some());
        assert!(set
            .ip_index
            .lookup(&"1.1.1.1".parse::<IpAddr>().unwrap())
            .is_none());
    }

    #[test]
    fn mrs_behavior_mismatch_is_rejected() {
        let err = load_mrs("115.mrs", ProviderBehavior::IpCidr).unwrap_err();
        assert!(err.contains("behavior 不匹配"), "unexpected: {}", err);
    }

    #[test]
    fn srs_is_rejected_with_actionable_message() {
        let mut raw = b"SRS".to_vec();
        raw.push(5);
        raw.extend_from_slice(&[0u8; 32]);
        let err = RuleSet::parse_provider_bytes(
            "srs",
            &raw,
            &ProviderBehavior::Domain,
            RuleSetSource::Inline,
            None,
            None,
        )
        .unwrap_err();
        assert!(err.contains(".srs"), "unexpected: {}", err);
    }

    #[test]
    fn explicit_mrs_format_does_not_silently_fall_back_to_text() {
        let err = RuleSet::parse_provider_bytes(
            "x",
            b"payload:\n  - a.com\n",
            &ProviderBehavior::Domain,
            RuleSetSource::Inline,
            None,
            Some(ProviderFormat::Mrs),
        )
        .unwrap_err();
        assert!(err.contains(".mrs"), "unexpected: {}", err);
    }

    #[tokio::test]
    async fn rule_set_rule_routes_with_mrs_provider() {
        let path = mrs_fixture("115.mrs");
        let yaml = format!(
            "rule-providers:\n  \
               ads:\n    \
                 type: file\n    \
                 behavior: domain\n    \
                 path: '{}'\n\
             rules:\n  \
               - RULE-SET,ads,DIRECT\n  \
               - FINAL,PROXY\n",
            path.to_string_lossy().replace('\\', "/")
        );

        let router = ProxyRouter::from_yaml_str(&yaml, Path::new("."))
            .await
            .expect("加载含 .mrs provider 的规则");

        assert!(!router.needs_ip_resolution());
        assert_eq!(router.route_domain_opt("115.com"), Some(RuleAction::Direct));
        assert_eq!(
            router.route_domain_opt("img.115cdn.com"),
            Some(RuleAction::Direct)
        );
        assert_eq!(router.route_domain_opt("example.org"), None);
        assert_eq!(
            router.route(Some("example.org"), None, &EMPTY_CTX),
            RuleAction::Proxy
        );
    }
}
