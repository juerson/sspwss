//! 禁区守卫 —— 照抄 shoes `src/dns/guard.rs` 的 RealResolver 思想：
//! 真实 DNS 的任何结果落入禁区段（fake-ip 池预留段 + 显式禁用范围）即报错。
//! 这是防"解析环/合成地址回灌"的最终防线，约 60 行，收益极高。

use super::{DnsError, DnsResult, SyntheticDnsAnswer};
use ipnetwork::IpNetwork;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct Guard {
    forbidden: Vec<IpNetwork>,
}

impl Guard {
    /// 内置禁区：198.18.0.0/15 为未来 fake-ip 池预留段（RFC 2544 benchmark 段，
    /// 真实公网不会使用；上游若返回该段必然是污染或配置错误）。
    pub fn default_ranges() -> Vec<IpNetwork> {
        vec![IpNetwork::V4(
            "198.18.0.0/15".parse().expect("valid builtin cidr"),
        )]
    }

    pub fn new(ranges: Vec<IpNetwork>) -> Self {
        Self { forbidden: ranges }
    }

    /// 单个 IP 检查。命中禁区返回命中的段。
    pub fn violation(&self, ip: IpAddr) -> Option<&IpNetwork> {
        // v4-mapped IPv6 先规范化为 v4 再比对（shoes 用 to_canonical 同款处理）
        let ip = ip.to_canonical();
        self.forbidden.iter().find(|net| net.contains(ip))
    }

    /// 批量检查：任一 IP 命中禁区 → SyntheticDnsAnswer 错误。
    pub fn check(&self, ips: &[IpAddr]) -> DnsResult<()> {
        for ip in ips {
            if let Some(net) = self.violation(*ip) {
                return Err(DnsError(format!(
                    "{}: {} ({})",
                    SyntheticDnsAnswer, ip, net
                )));
            }
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.forbidden.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> Guard {
        Guard::new(Guard::default_ranges())
    }

    #[test]
    fn rejects_fakeip_pool_range() {
        let ip: IpAddr = "198.18.5.5".parse().unwrap();
        assert!(guard().violation(ip).is_some());
        // 198.19.255.255 仍在 /15 内
        let ip: IpAddr = "198.19.255.255".parse().unwrap();
        assert!(guard().violation(ip).is_some());
        // 198.20.0.0 在段外
        let ip: IpAddr = "198.20.0.1".parse().unwrap();
        assert!(guard().violation(ip).is_none());
    }

    #[test]
    fn allows_normal_addresses() {
        let ips: Vec<IpAddr> = ["1.2.3.4", "8.8.8.8", "2606:4700::1111"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        assert!(guard().check(&ips).is_ok());
    }

    #[test]
    fn canonicalizes_v4_mapped_ipv6() {
        // ::ffff:198.18.0.1 是 v4-mapped IPv6，规范化后应命中禁区
        let ip: IpAddr = "::ffff:198.18.0.1".parse().unwrap();
        assert!(guard().violation(ip).is_some());
    }

    #[test]
    fn check_reports_offending_ip() {
        let ips: Vec<IpAddr> = ["1.2.3.4", "198.18.0.9"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let err = guard().check(&ips).unwrap_err();
        assert!(err.0.contains("198.18.0.9"));
    }
}
