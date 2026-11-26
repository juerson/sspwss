//! DnsResolver —— DNS 主查询管线（clash-rs EnhancedResolver + mihomo 分组精简版）。
//!
//! 管线：
//!   1. IP 字面量 → 直接返回（不走 DNS，守卫不适用于用户显式目标）
//!   2. nameserver-policy 分域命中 → 对应上游组（优先级最高）
//!   3. 否则按**路由判定**选组：
//!        DIRECT  → direct-nameserver（国内 DoH，geo 正确）
//!        PROXY   → proxy-nameserver（缺省 = nameserver，默认 tunnel://）
//!        UNKNOWN → nameserver
//!   4. 组内竞速（select_ok，10s 总超时）
//!   5. 禁区守卫：结果 ∈ 198.18.0.0/15(+自定义) → SyntheticDnsAnswer 错误
//!   6. 仅成功结果入缓存（响应真实 TTL，钳制 300s）；NXDOMAIN/NODATA 只透传
//!   7. 传输失败且 fallback-system=true（或组内显式 system://）→ 系统 getaddrinfo
//!
//! 关键：**解析位置跟随连接出口**。直连流量从本地出去，就用本地（国内）DNS
//! 解析；代理流量从 Worker 出去，就用隧道 DNS 解析。混用会导致国内 CDN 域名
//! 被解析成海外节点 IP，直连自然又慢又白屏。

use super::cache::DnsCache;
use super::config::{DnsConfig, DohSpec, UpstreamSpec};
use super::guard::Guard;
use super::message;
use super::policy::Policy;
use super::upstream::{race_exchange, DohUpstream, TunnelUpstream, Upstream};
use super::{DnsAnswer, DnsError, DnsResult, RouteClass, RouteClassifier};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use log::{debug, info, warn};

/// 运行时上游条目
pub(crate) enum UpstreamEntry {
    /// wire 级交换（tunnel:// 或 DoH）
    Wire(Box<dyn Upstream>),
    /// 系统 getaddrinfo（显式配置才出现）
    System,
}

pub struct DnsResolver {
    ipv6: bool,
    fallback_system: bool,
    policy: Policy,
    /// 与 policy 条目平行的上游组
    policy_upstreams: Vec<Vec<UpstreamEntry>>,
    default_upstreams: Vec<UpstreamEntry>,
    /// 路由判定 DIRECT 的域名用这组（None → default_upstreams）
    direct_upstreams: Option<Vec<UpstreamEntry>>,
    /// 路由判定 PROXY 的域名用这组（None → default_upstreams）
    proxy_upstreams: Option<Vec<UpstreamEntry>>,
    classifier: Option<Arc<dyn RouteClassifier>>,
    cache: DnsCache,
    guard: Guard,
}

impl DnsResolver {
    /// 从配置构建（内部完成 DoH 域名端点的一次性引导解析）。
    pub async fn new(
        config: DnsConfig,
        tunnel: crate::mux::TunnelDns,
        classifier: Option<Arc<dyn RouteClassifier>>,
    ) -> DnsResult<Arc<Self>> {
        // 引导解析器：仅字面 IP DoH（配置期已校验无域名）
        let bootstrap = BootstrapResolver::new(config.default_nameserver.clone());

        let default_upstreams = build_entries(&config.nameserver, &tunnel, &bootstrap).await?;

        let direct_upstreams = match &config.direct_nameserver {
            Some(specs) => match build_entries(specs, &tunnel, &bootstrap).await {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!("direct-nameserver 不可用，回退 nameserver: {}", e);
                    None
                }
            },
            None => None,
        };

        let proxy_upstreams = match &config.proxy_nameserver {
            Some(specs) => match build_entries(specs, &tunnel, &bootstrap).await {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!("proxy-nameserver 不可用，回退 nameserver: {}", e);
                    None
                }
            },
            None => None,
        };

        let mut policy_upstreams = Vec::with_capacity(config.nameserver_policy.len());
        for (pattern, specs) in &config.nameserver_policy {
            match build_entries(specs, &tunnel, &bootstrap).await {
                Ok(v) => policy_upstreams.push(v),
                Err(e) => {
                    warn!(
                        "nameserver-policy \"{}\" 不可用，该组回退 nameserver: {}",
                        pattern, e
                    );
                    policy_upstreams.push(Vec::new());
                }
            }
        }

        let resolver = Self::from_parts(
            config.ipv6,
            config.fallback_system,
            Policy::new(&config.nameserver_policy),
            policy_upstreams,
            default_upstreams,
            Guard::new(config.forbidden),
        )
        .with_route_upstreams(direct_upstreams, proxy_upstreams)
        .with_classifier_opt(classifier);

        info!(
            "DNS resolver ready — nameserver={:?}, direct={:?}, proxy={:?}, policy={}, ipv6={}, fallback-system={}",
            describe_entries(&resolver.default_upstreams),
            resolver.direct_upstreams.as_deref().map(describe_entries),
            resolver.proxy_upstreams.as_deref().map(describe_entries),
            resolver.policy_len(),
            resolver.ipv6,
            resolver.fallback_system
        );
        Ok(Arc::new(resolver))
    }

    /// 供测试与装配复用的纯组装入口。
    pub(crate) fn from_parts(
        ipv6: bool,
        fallback_system: bool,
        policy: Policy,
        policy_upstreams: Vec<Vec<UpstreamEntry>>,
        default_upstreams: Vec<UpstreamEntry>,
        guard: Guard,
    ) -> Self {
        Self {
            ipv6,
            fallback_system,
            policy,
            policy_upstreams,
            default_upstreams,
            direct_upstreams: None,
            proxy_upstreams: None,
            classifier: None,
            cache: DnsCache::new(),
            guard,
        }
    }

    /// 接线 direct / proxy 上游组（构造期使用）。
    pub(crate) fn with_route_upstreams(
        mut self,
        direct: Option<Vec<UpstreamEntry>>,
        proxy: Option<Vec<UpstreamEntry>>,
    ) -> Self {
        self.direct_upstreams = direct;
        self.proxy_upstreams = proxy;
        self
    }

    /// 接线路由分类器（构造期使用）。
    pub(crate) fn with_classifier_opt(mut self, c: Option<Arc<dyn RouteClassifier>>) -> Self {
        self.classifier = c;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_classifier(mut self, c: Arc<dyn RouteClassifier>) -> Self {
        self.classifier = Some(c);
        self
    }

    pub fn ipv6(&self) -> bool {
        self.ipv6
    }

    pub fn cache(&self) -> &DnsCache {
        &self.cache
    }

    /// 主入口：解析域名 → IP 列表。失败返回 Err（绝不静默回退系统 DNS）。
    pub async fn resolve(&self, name: &str) -> DnsResult<Vec<IpAddr>> {
        let answer = self.resolve_answer(name).await?;
        if answer.rcode != ResponseCode::NoError {
            return Err(DnsError(format!(
                "upstream returned {} for {:?}",
                answer.rcode, name
            )));
        }
        if answer.ips.is_empty() {
            return Err(DnsError(format!("no address for {:?}", name)));
        }
        Ok(answer.ips)
    }

    /// 监听器入口：保留响应码（NXDOMAIN / NODATA 不再被映射成 SERVFAIL）。
    pub async fn resolve_answer(&self, name: &str) -> DnsResult<DnsAnswer> {
        let name = name.trim().trim_end_matches('.');
        if name.is_empty() {
            return Err(DnsError("empty domain name".into()));
        }
        // IP 字面量：用户显式目标，直接返回（这是 IP 匹配路由的既有行为）
        if let Ok(ip) = name.parse::<IpAddr>() {
            return Ok(DnsAnswer::positive(
                vec![ip.to_canonical()],
                Duration::from_secs(3600),
            ));
        }

        let key = name.to_lowercase();
        // 缓存 + singleflight；成功答案由 cache 内部按真实 TTL 写入
        self.cache
            .resolve_via(&key, self.resolve_uncached(name))
            .await
    }

    /// 本地监听器的非 A/AAAA 记录透传（HTTPS/TXT/MX 等原样经隧道转发）。
    /// 分域/路由策略同样生效（按 question 段域名选择上游组）。
    pub async fn exchange_raw(&self, query: Vec<u8>) -> DnsResult<Vec<u8>> {
        let entries: &[UpstreamEntry] = match message::query_name(&query) {
            Some(name) => self.pick_entries(&name),
            None => &self.default_upstreams,
        };
        let wires = wire_refs(entries);
        if wires.is_empty() {
            return Err(DnsError(
                "raw DNS exchange requires tunnel:// or https:// upstream (system:// cannot forward this record type)".into(),
            ));
        }
        race_exchange(&wires, query).await.map(|(bytes, winner)| {
            debug!("DNS raw exchange via {}", winner);
            bytes
        })
    }

    // ── 内部管线 ─────────────────────────────────────────────────────────────

    /// 选择上游组：显式 policy > 路由判定 > 默认组。
    fn pick_entries(&self, name: &str) -> &[UpstreamEntry] {
        if let Some(idx) = self.policy.match_index(name) {
            if let Some(group) = self.policy_upstreams.get(idx) {
                if !group.is_empty() {
                    return group;
                }
            }
        }
        match self.classifier.as_ref().map(|c| c.classify_domain(name)) {
            Some(RouteClass::Direct) => self
                .direct_upstreams
                .as_deref()
                .unwrap_or(&self.default_upstreams),
            Some(RouteClass::Proxy) => self
                .proxy_upstreams
                .as_deref()
                .unwrap_or(&self.default_upstreams),
            _ => &self.default_upstreams,
        }
    }

    async fn resolve_uncached(&self, name: &str) -> DnsResult<DnsAnswer> {
        let entries = self.pick_entries(name);
        let wires = wire_refs(entries);
        let may_fallback =
            entries.iter().any(|e| matches!(e, UpstreamEntry::System)) || self.fallback_system;

        if wires.is_empty() {
            // 上游组全是 system://（显式配置）
            let (ips, ttl) = self.system_lookup(name).await?;
            return Ok(DnsAnswer::positive(ips, ttl));
        }

        let mut qtypes = vec![RecordType::A];
        if self.ipv6 {
            qtypes.push(RecordType::AAAA);
        }

        let mut outcomes: Vec<message::ParsedAnswer> = Vec::with_capacity(qtypes.len());
        let mut last_err: Option<DnsError> = None;
        for qtype in qtypes {
            match self.query_family_answer(&wires, name, qtype).await {
                Ok(parsed) => outcomes.push(parsed),
                Err(e) => last_err = Some(e),
            }
        }

        let Some(first) = outcomes.first() else {
            let err = last_err.unwrap_or_else(|| DnsError("no DNS upstream answered".into()));
            return self.fallback_or_error(name, may_fallback, err).await;
        };
        let rcode = first.rcode;

        let mut ips: Vec<IpAddr> = Vec::new();
        let mut min_ttl: Option<Duration> = None;
        for parsed in &outcomes {
            if parsed.rcode != ResponseCode::NoError {
                continue;
            }
            ips.extend(parsed.ips.iter().copied());
            min_ttl = Some(match min_ttl {
                Some(t) => t.min(parsed.ttl),
                None => parsed.ttl,
            });
        }

        if rcode != ResponseCode::NoError {
            // NXDOMAIN 等是"有效答案"，不是传输失败：不回退、不缓存
            return Ok(DnsAnswer::negative(rcode));
        }
        if ips.is_empty() {
            // NODATA：域名存在但没有该类型记录（例如只有 AAAA/HTTPS）
            return Ok(DnsAnswer::nodata());
        }

        self.guard.check(&ips)?;
        Ok(DnsAnswer::positive(
            ips,
            min_ttl.unwrap_or(Duration::from_secs(60)),
        ))
    }

    async fn query_family_answer(
        &self,
        wires: &[&dyn Upstream],
        name: &str,
        qtype: RecordType,
    ) -> DnsResult<message::ParsedAnswer> {
        let wire = message::build_query(name, qtype)?;
        let (resp, winner) = race_exchange(wires, wire).await?;
        let parsed = message::parse_answer(&resp, qtype)?;
        debug!(
            "DNS {} {} -> {} ips (ttl {:?}, rcode {:?}) via {}",
            qtype,
            name,
            parsed.ips.len(),
            parsed.ttl,
            parsed.rcode,
            winner
        );
        Ok(parsed)
    }

    async fn fallback_or_error(
        &self,
        name: &str,
        may_fallback: bool,
        err: DnsError,
    ) -> DnsResult<DnsAnswer> {
        if may_fallback {
            warn!(
                "DNS upstreams failed ({}), falling back to system resolution — potential leak (fallback-system/system:// enabled)",
                err
            );
            let (ips, ttl) = self.system_lookup(name).await?;
            Ok(DnsAnswer::positive(ips, ttl))
        } else {
            // fail-closed：不回退系统 DNS，绝不泄漏
            Err(err)
        }
    }

    async fn system_lookup(&self, name: &str) -> DnsResult<(Vec<IpAddr>, Duration)> {
        let addrs = tokio::net::lookup_host(format!("{}:0", name))
            .await
            .map_err(|e| DnsError(format!("system resolution for {:?}: {}", name, e)))?;
        let mut ips: Vec<IpAddr> = addrs.map(|a| a.ip().to_canonical()).collect();
        ips.sort();
        ips.dedup();
        self.guard.check(&ips)?;
        if ips.is_empty() {
            return Err(DnsError(format!(
                "system resolution returned no address for {:?}",
                name
            )));
        }
        Ok((ips, Duration::from_secs(60)))
    }

    fn policy_len(&self) -> usize {
        self.policy_upstreams.len()
    }
}

fn wire_refs<'a>(entries: &'a [UpstreamEntry]) -> Vec<&'a dyn Upstream> {
    entries
        .iter()
        .filter_map(|e| match e {
            UpstreamEntry::Wire(u) => Some(u.as_ref() as &dyn Upstream),
            UpstreamEntry::System => None,
        })
        .collect()
}

fn describe_entries(entries: &[UpstreamEntry]) -> Vec<String> {
    entries
        .iter()
        .map(|e| match e {
            UpstreamEntry::Wire(u) => u.describe(),
            UpstreamEntry::System => "system://".to_string(),
        })
        .collect()
}

/// 把 UpstreamSpec 列表实例化为运行时条目（DoH 域名端点在此完成一次性引导）
async fn build_entries(
    specs: &[UpstreamSpec],
    tunnel: &crate::mux::TunnelDns,
    bootstrap: &BootstrapResolver,
) -> DnsResult<Vec<UpstreamEntry>> {
    let mut entries = Vec::with_capacity(specs.len());
    for spec in specs {
        match spec {
            UpstreamSpec::Tunnel => {
                entries.push(UpstreamEntry::Wire(Box::new(TunnelUpstream::new(
                    tunnel.clone(),
                ))));
            }
            UpstreamSpec::Doh(doh) => {
                // 字面 IP：直接用，无引导依赖；域名端点：经引导解析出 IP，
                // 用 reqwest resolve() 钉住（TLS SNI 仍用原域名）
                let upstream = if doh.ip.is_some() {
                    DohUpstream::new(doh.clone())?
                } else {
                    match bootstrap.resolve_host(&doh.host, doh.port).await {
                        Ok(addr) => DohUpstream::with_pinned_addr(doh.clone(), addr)?,
                        Err(e) => {
                            // 单个上游引导失败不应拖垮启动：跳过它，其余上游继续可用。
                            // 若全部失败，下面统一报错（配置期人话提示）。
                            warn!("跳过 DoH 上游 {}: 引导解析失败: {}", doh.url, e);
                            continue;
                        }
                    }
                };
                entries.push(UpstreamEntry::Wire(Box::new(upstream)));
            }
            UpstreamSpec::System => {
                entries.push(UpstreamEntry::System);
            }
        }
    }
    if entries.is_empty() {
        return Err(DnsError(
            "no usable DNS upstream configured (所有上游都不可用，请检查 dns.yaml)".into(),
        ));
    }
    Ok(entries)
}

/// 一次性引导：解析带域名的 DoH 端点 / 隧道端点。
/// 只用字面 IP DoH；无可用引导服务器时才回退系统 getaddrinfo
/// （残余泄漏，一次性，README 文档化）。
pub(crate) struct BootstrapResolver {
    servers: Vec<DohSpec>,
    resolved: tokio::sync::Mutex<std::collections::HashMap<String, SocketAddr>>,
}

impl BootstrapResolver {
    pub(crate) fn new(servers: Vec<DohSpec>) -> Self {
        Self {
            servers,
            resolved: tokio::sync::Mutex::new(Default::default()),
        }
    }

    pub(crate) async fn resolve_host(&self, host: &str, port: u16) -> DnsResult<SocketAddr> {
        {
            let map = self.resolved.lock().await;
            if let Some(addr) = map.get(host) {
                return Ok(*addr);
            }
        }
        let addr = self.resolve_host_uncached(host, port).await?;
        self.resolved.lock().await.insert(host.to_string(), addr);
        Ok(addr)
    }

    async fn resolve_host_uncached(&self, host: &str, port: u16) -> DnsResult<SocketAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }
        // 1) 字面 IP DoH（结构性防递归）
        if !self.servers.is_empty() {
            let wire = message::build_query(host, RecordType::A)?;
            for spec in &self.servers {
                let upstream = DohUpstream::new(spec.clone())?;
                if let Ok(resp) = upstream.exchange(wire.clone()).await {
                    if let Ok((ips, _)) = message::parse_response(&resp, RecordType::A) {
                        if let Some(ip) = ips.first() {
                            info!("Bootstrap: resolved {} -> {} via {}", host, ip, spec.url);
                            return Ok(SocketAddr::new(*ip, port));
                        }
                    }
                }
            }
        }
        // 2) 系统 getaddrinfo 兜底（一次性引导泄漏）
        warn!(
            "Bootstrap: no usable default-nameserver, resolving {} via system DNS (residual leak, one-shot)",
            host
        );
        let mut addrs = tokio::net::lookup_host(format!("{}:{}", host, port))
            .await
            .map_err(|e| DnsError(format!("bootstrap resolve {}: {}", host, e)))?;
        addrs
            .next()
            .ok_or_else(|| DnsError(format!("bootstrap resolve {}: no address", host)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::upstream::Upstream;
    use futures_util::future::BoxFuture;
    use hickory_proto::op::{Message, MessageType, Query};
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{RData, Record, RecordType as HRecordType};
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// 固定答案的假上游；记录被调用次数与最近一次查询类型。
    struct StubUpstream {
        label: &'static str,
        v4: Option<Ipv4Addr>,
        fail: bool,
        calls: Arc<AtomicUsize>,
        last_type: Arc<std::sync::Mutex<Option<HRecordType>>>,
    }

    impl StubUpstream {
        fn new(label: &'static str, v4: Ipv4Addr) -> Self {
            Self {
                label,
                v4: Some(v4),
                fail: false,
                calls: Arc::new(AtomicUsize::new(0)),
                last_type: Arc::new(std::sync::Mutex::new(None)),
            }
        }

        fn failing(label: &'static str) -> Self {
            Self {
                label,
                v4: None,
                fail: true,
                calls: Arc::new(AtomicUsize::new(0)),
                last_type: Arc::new(std::sync::Mutex::new(None)),
            }
        }

        fn forbidden() -> Self {
            Self::new("forbidden://", Ipv4Addr::new(198, 18, 0, 7))
        }
    }

    impl Upstream for StubUpstream {
        fn exchange<'a>(&'a self, query: Vec<u8>) -> BoxFuture<'a, DnsResult<Vec<u8>>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let req = Message::from_vec(&query)
                    .map_err(|e| DnsError(format!("stub parse: {}", e)))?;
                let q = req
                    .queries()
                    .first()
                    .cloned()
                    .ok_or_else(|| DnsError("stub: no question".into()))?;
                *self.last_type.lock().unwrap() = Some(q.query_type());
                if self.fail {
                    return Err(DnsError(format!("{} down", self.label)));
                }

                let mut resp = Message::new();
                resp.set_id(req.id());
                resp.set_message_type(MessageType::Response);
                resp.set_response_code(ResponseCode::NoError);
                resp.add_query(q.clone());
                match (q.query_type(), self.v4) {
                    (HRecordType::A, Some(ip)) => {
                        resp.add_answer(Record::from_rdata(q.name().clone(), 45, RData::A(A(ip))));
                    }
                    (HRecordType::AAAA, Some(ip)) => {
                        // 用 v4-mapped 形式造一个可预测的 AAAA 答案
                        let v6 = std::net::Ipv6Addr::from(
                            u128::from(u32::from(ip))
                                | 0x2001_0db8_0000_0000_0000_0000_0000_0000u128,
                        );
                        resp.add_answer(Record::from_rdata(
                            q.name().clone(),
                            45,
                            RData::AAAA(AAAA(v6)),
                        ));
                    }
                    _ => {}
                }
                resp.to_vec()
                    .map_err(|e| DnsError(format!("stub build: {}", e)))
            })
        }

        fn describe(&self) -> String {
            self.label.to_string()
        }
    }

    /// 固定分类结果（测试用）
    struct FixedClassifier(RouteClass);

    impl RouteClassifier for FixedClassifier {
        fn classify_domain(&self, _domain: &str) -> RouteClass {
            self.0
        }
    }

    fn resolver(entries: Vec<UpstreamEntry>, ipv6: bool) -> DnsResolver {
        DnsResolver::from_parts(
            ipv6,
            false,
            Policy::new(&[]),
            vec![],
            entries,
            Guard::new(Guard::default_ranges()),
        )
    }

    fn wire(entry: StubUpstream) -> UpstreamEntry {
        UpstreamEntry::Wire(Box::new(entry))
    }

    #[tokio::test]
    async fn fails_closed_when_upstream_is_down() {
        let r = resolver(vec![wire(StubUpstream::failing("down"))], false);
        let err = r.resolve("example.com").await.unwrap_err();
        assert!(err.0.contains("down"), "unexpected: {}", err);
        // 失败不缓存
        assert!(r.resolve("example.com").await.is_err());
    }

    #[tokio::test]
    async fn guard_rejects_forbidden_answer() {
        let r = resolver(vec![wire(StubUpstream::forbidden())], false);
        let err = r.resolve("loop.example").await.unwrap_err();
        assert!(err.0.contains("198.18.0.7"), "unexpected: {}", err);
    }

    #[tokio::test]
    async fn second_resolve_hits_cache() {
        let stub = StubUpstream::new("stub://", Ipv4Addr::new(1, 2, 3, 4));
        let calls = stub.calls.clone();
        let r = resolver(vec![wire(stub)], false);

        assert_eq!(
            r.resolve("cache.example").await.unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let _ = r.resolve("cache.example").await.unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "cache must absorb second query"
        );
    }

    #[tokio::test]
    async fn ipv6_disabled_queries_only_a() {
        let stub = StubUpstream::new("stub://", Ipv4Addr::new(5, 6, 7, 8));
        let calls = stub.calls.clone();
        let last_type = stub.last_type.clone();
        let r = resolver(vec![wire(stub)], false);

        let ips = r.resolve("v4only.example").await.unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))]);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(*last_type.lock().unwrap(), Some(HRecordType::A));
    }

    #[tokio::test]
    async fn ipv6_enabled_adds_aaaa_answers() {
        let stub = StubUpstream::new("stub://", Ipv4Addr::new(5, 6, 7, 8));
        let r = resolver(vec![wire(stub)], true);
        let ips = r.resolve("dual.example").await.unwrap();
        assert!(ips.iter().any(|ip| ip.is_ipv4()));
        assert!(ips.iter().any(|ip| ip.is_ipv6()));
    }

    #[tokio::test]
    async fn policy_selects_matching_upstream_group() {
        let cn = StubUpstream::new("cn://", Ipv4Addr::new(10, 0, 0, 1));
        let cn_calls = cn.calls.clone();
        let global = StubUpstream::new("global://", Ipv4Addr::new(20, 0, 0, 1));
        let global_calls = global.calls.clone();

        let policy_defs = vec![("+.cn".to_string(), vec![UpstreamSpec::Tunnel])];
        let r = DnsResolver::from_parts(
            false,
            false,
            Policy::new(&policy_defs),
            vec![vec![wire(cn)]],
            vec![wire(global)],
            Guard::new(Guard::default_ranges()),
        );

        assert_eq!(
            r.resolve("baidu.cn").await.unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]
        );
        assert_eq!(cn_calls.load(Ordering::SeqCst), 1);
        assert_eq!(global_calls.load(Ordering::SeqCst), 0);

        assert_eq!(
            r.resolve("github.com").await.unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(20, 0, 0, 1))]
        );
        assert_eq!(global_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn direct_route_uses_direct_nameserver() {
        let direct = StubUpstream::new("direct://", Ipv4Addr::new(10, 0, 0, 1));
        let direct_calls = direct.calls.clone();
        let default = StubUpstream::new("tunnel://", Ipv4Addr::new(20, 0, 0, 1));
        let default_calls = default.calls.clone();

        let r = resolver(vec![wire(default)], false)
            .with_route_upstreams(Some(vec![wire(direct)]), None)
            .with_classifier(Arc::new(FixedClassifier(RouteClass::Direct)));

        assert_eq!(
            r.resolve("cn.example").await.unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]
        );
        assert_eq!(direct_calls.load(Ordering::SeqCst), 1);
        assert_eq!(default_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn proxy_route_falls_back_to_default_when_group_missing() {
        let default = StubUpstream::new("tunnel://", Ipv4Addr::new(20, 0, 0, 1));
        let default_calls = default.calls.clone();

        let r = resolver(vec![wire(default)], false)
            .with_classifier(Arc::new(FixedClassifier(RouteClass::Proxy)));

        assert_eq!(
            r.resolve("foreign.example").await.unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(20, 0, 0, 1))]
        );
        assert_eq!(default_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn policy_overrides_route_classification() {
        let policied = StubUpstream::new("policy://", Ipv4Addr::new(30, 0, 0, 1));
        let policied_calls = policied.calls.clone();
        let default = StubUpstream::new("tunnel://", Ipv4Addr::new(20, 0, 0, 1));

        let policy_defs = vec![("+.corp".to_string(), vec![UpstreamSpec::System])];
        let r = DnsResolver::from_parts(
            false,
            false,
            Policy::new(&policy_defs),
            vec![vec![wire(policied)]],
            vec![wire(default)],
            Guard::new(Guard::default_ranges()),
        )
        .with_route_upstreams(
            Some(vec![wire(StubUpstream::new(
                "dead://",
                Ipv4Addr::LOCALHOST,
            ))]),
            None,
        )
        .with_classifier(Arc::new(FixedClassifier(RouteClass::Direct)));

        assert_eq!(
            r.resolve("host.corp").await.unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(30, 0, 0, 1))]
        );
        assert_eq!(policied_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn system_only_group_uses_getaddrinfo() {
        // 显式 system:// —— 允许系统解析（用户显式选择）
        let r = resolver(vec![UpstreamEntry::System], false);
        let ips = r.resolve("localhost").await.unwrap();
        assert!(!ips.is_empty());
    }

    #[tokio::test]
    async fn ip_literal_short_circuits() {
        let r = resolver(vec![wire(StubUpstream::failing("never"))], false);
        assert_eq!(
            r.resolve("203.0.113.9").await.unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))]
        );
    }

    #[tokio::test]
    async fn raw_exchange_returns_error_on_empty_upstream() {
        let r = resolver(vec![UpstreamEntry::System], false);
        let q = super::message::build_query("txt.example", HRecordType::TXT).unwrap();
        assert!(r.exchange_raw(q).await.is_err());
    }

    #[tokio::test]
    async fn nodata_is_noerror_not_error() {
        // 上游返回 NOERROR 但无 A 记录 → resolve_answer 给出 NODATA；
        // resolve() 仍然报错（调用方需要地址）
        let r = resolver(vec![UpstreamEntry::Wire(Box::new(NoAnswerUpstream))], false);
        let ans = r.resolve_answer("only-aaaa.example").await.unwrap();
        assert_eq!(ans.rcode, ResponseCode::NoError);
        assert!(ans.ips.is_empty());
        assert!(r.resolve("only-aaaa.example").await.is_err());
    }

    /// 永远返回 NOERROR + 空答案（模拟只有 AAAA/HTTPS 的域名）
    struct NoAnswerUpstream;

    impl Upstream for NoAnswerUpstream {
        fn exchange<'a>(&'a self, query: Vec<u8>) -> BoxFuture<'a, DnsResult<Vec<u8>>> {
            Box::pin(async move {
                let req = Message::from_vec(&query)
                    .map_err(|e| DnsError(format!("stub parse: {}", e)))?;
                let mut resp = Message::new();
                resp.set_id(req.id());
                resp.set_message_type(MessageType::Response);
                resp.set_response_code(ResponseCode::NoError);
                if let Some(q) = req.queries().first() {
                    resp.add_query(q.clone());
                }
                resp.to_vec()
                    .map_err(|e| DnsError(format!("stub build: {}", e)))
            })
        }

        fn describe(&self) -> String {
            "noanswer://".to_string()
        }
    }

    // 抑制未使用告警
    #[allow(dead_code)]
    fn _unused(_q: Query) {}
}
