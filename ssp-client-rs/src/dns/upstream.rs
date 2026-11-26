//! DNS 上游：wire 级 exchange 接口 + 两种实现。
//! - TunnelUpstream：DnsQuery 帧 → Worker DoH（防泄漏主路径，全程 WSS 加密）
//! - DohUpstream：DoH GET 直连（HTTPS over TCP；必须 no_proxy，防止系统代理
//!   指向本客户端自身时形成解析环）
//!
//! 全程无 UDP 依赖 —— 不新增 UdpDatagram 协议，服务端零改动。
//! system:// 兜底不走 wire 接口，由 resolver 直接调 getaddrinfo（见 resolver.rs）。

use super::{config::DohSpec, DnsError, DnsResult};
use futures_util::future::BoxFuture;
use std::time::Duration;

pub trait Upstream: Send + Sync {
    /// 发送原始 DNS wire 查询，返回原始 wire 响应
    fn exchange<'a>(&'a self, query: Vec<u8>) -> BoxFuture<'a, DnsResult<Vec<u8>>>;
    /// 日志用描述
    fn describe(&self) -> String;
}

/// DnsQuery 帧 → Worker DoH
pub struct TunnelUpstream {
    tunnel: crate::mux::TunnelDns,
}

impl TunnelUpstream {
    pub fn new(tunnel: crate::mux::TunnelDns) -> Self {
        Self { tunnel }
    }
}

impl Upstream for TunnelUpstream {
    fn exchange<'a>(&'a self, query: Vec<u8>) -> BoxFuture<'a, DnsResult<Vec<u8>>> {
        Box::pin(async move {
            self.tunnel
                .dns_exchange(query)
                .await
                .map_err(|e| DnsError(format!("tunnel dns: {}", e)))
        })
    }

    fn describe(&self) -> String {
        "tunnel://".to_string()
    }
}

/// DoH GET 直连（RFC 8484）
pub struct DohUpstream {
    client: reqwest::Client,
    spec: DohSpec,
}

impl DohUpstream {
    pub fn new(spec: DohSpec) -> DnsResult<Self> {
        Self::build(spec, None)
    }

    /// 用引导阶段解析出的地址钉住 DoH 端点（TLS SNI/证书校验仍用原域名）。
    /// 这样端点域名只解析一次，且解析走字面 IP DoH 的 default-nameserver，
    /// 运行期不再触发系统 DNS。
    pub fn with_pinned_addr(spec: DohSpec, addr: std::net::SocketAddr) -> DnsResult<Self> {
        Self::build(spec, Some(addr))
    }

    fn build(spec: DohSpec, pinned: Option<std::net::SocketAddr>) -> DnsResult<Self> {
        let mut builder = reqwest::Client::builder()
            .no_proxy() // 关键：绕过系统代理，防止"代理指向自身"成环
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10));
        if let Some(addr) = pinned {
            builder = builder.resolve(&spec.host, addr);
        }
        let client = builder
            .build()
            .map_err(|e| DnsError(format!("build DoH client: {}", e)))?;
        Ok(Self { client, spec })
    }
}

impl Upstream for DohUpstream {
    fn exchange<'a>(&'a self, query: Vec<u8>) -> BoxFuture<'a, DnsResult<Vec<u8>>> {
        Box::pin(async move {
            let url = format!(
                "{}?dns={}",
                self.spec.url,
                super::message::dns_query_to_base64(&query)
            );
            let resp = self
                .client
                .get(&url)
                .header("Accept", "application/dns-message")
                .send()
                .await
                .map_err(|e| DnsError(format!("doh request {}: {}", self.spec.url, e)))?;

            if !resp.status().is_success() {
                return Err(DnsError(format!(
                    "doh {} returned http {}",
                    self.spec.url,
                    resp.status()
                )));
            }
            let body = resp
                .bytes()
                .await
                .map_err(|e| DnsError(format!("doh {} body: {}", self.spec.url, e)))?;
            Ok(body.to_vec())
        })
    }

    fn describe(&self) -> String {
        self.spec.url.clone()
    }
}

/// 组内竞速（clash-rs batch_exchange 风格）：futures select_ok，
/// 首个成功者胜出，总超时默认 10s。空列表返回错误。
/// 返回 (响应 wire bytes, 胜出上游描述)。
pub async fn race_exchange(
    upstreams: &[&dyn Upstream],
    query: Vec<u8>,
) -> DnsResult<(Vec<u8>, String)> {
    race_exchange_with_timeout(upstreams, query, Duration::from_secs(10)).await
}

pub async fn race_exchange_with_timeout(
    upstreams: &[&dyn Upstream],
    query: Vec<u8>,
    total_timeout: Duration,
) -> DnsResult<(Vec<u8>, String)> {
    use futures_util::future::select_ok;
    use futures_util::FutureExt;

    if upstreams.is_empty() {
        return Err(DnsError("no upstream configured".into()));
    }

    let futs = upstreams.iter().map(|u| {
        u.exchange(query.clone())
            .map(|res| res.map(|bytes| (bytes, u.describe())))
    });

    match tokio::time::timeout(total_timeout, select_ok(futs)).await {
        Ok(Ok(((bytes, winner), _rest))) => Ok((bytes, winner)),
        Ok(Err(e)) => Err(DnsError(format!("all upstreams failed: {}", e.0))),
        Err(_) => Err(DnsError(format!(
            "dns exchange timed out ({:?})",
            total_timeout
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    use std::sync::Arc;

    struct CountingUpstream {
        payload: u8,
        delay: Duration,
        fail: bool,
    }

    impl Upstream for CountingUpstream {
        fn exchange<'a>(&'a self, _query: Vec<u8>) -> BoxFuture<'a, DnsResult<Vec<u8>>> {
            Box::pin(async move {
                tokio::time::sleep(self.delay).await;
                if self.fail {
                    Err(DnsError(format!("upstream {} failed", self.payload)))
                } else {
                    Ok(vec![self.payload])
                }
            })
        }
        fn describe(&self) -> String {
            format!("up-{}", self.payload)
        }
    }

    #[tokio::test]
    async fn race_picks_fastest_winner() {
        let slow = CountingUpstream {
            payload: 1,
            delay: Duration::from_millis(300),
            fail: false,
        };
        let fast = CountingUpstream {
            payload: 2,
            delay: Duration::from_millis(10),
            fail: false,
        };
        let ups: Vec<&dyn Upstream> = vec![&slow, &fast];
        let (bytes, winner) = race_exchange_with_timeout(&ups, vec![0], Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(winner, "up-2");
        assert_eq!(bytes, vec![2]);
    }

    #[tokio::test]
    async fn race_falls_back_to_slow_when_fast_fails() {
        let slow = CountingUpstream {
            payload: 1,
            delay: Duration::from_millis(80),
            fail: false,
        };
        let fast_fail = CountingUpstream {
            payload: 2,
            delay: Duration::from_millis(10),
            fail: true,
        };
        let ups: Vec<&dyn Upstream> = vec![&slow, &fast_fail];
        let (_, winner) = race_exchange_with_timeout(&ups, vec![0], Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(winner, "up-1");
    }

    #[tokio::test]
    async fn race_reports_error_when_all_fail() {
        let a = CountingUpstream {
            payload: 1,
            delay: Duration::from_millis(10),
            fail: true,
        };
        let ups: Vec<&dyn Upstream> = vec![&a];
        let err = race_exchange_with_timeout(&ups, vec![0], Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(err.0.contains("failed"));
    }

    #[tokio::test]
    async fn race_timeout() {
        let hung = CountingUpstream {
            payload: 1,
            delay: Duration::from_secs(30),
            fail: false,
        };
        let ups: Vec<&dyn Upstream> = vec![&hung];
        let err = race_exchange_with_timeout(&ups, vec![0], Duration::from_millis(100))
            .await
            .unwrap_err();
        assert!(err.0.contains("timed out"));
    }

    #[tokio::test]
    async fn race_empty_list() {
        let ups: Vec<&dyn Upstream> = vec![];
        assert!(
            race_exchange_with_timeout(&ups, vec![0], Duration::from_secs(1))
                .await
                .is_err()
        );
    }

    // 抑制未使用告警（Arc/AtomicU32 在部分测试组合下未用到）
    #[allow(dead_code)]
    fn _unused(_a: Arc<AtomicU32>) {}
}
