//! nameserver-policy 分域匹配。
//!
//! 模式语义（与 router 的 DomainPattern 子集对齐）：
//! - `"+.example.com"` —— example.com 及其所有子域（clash 风格）
//! - `"example.com"`   —— 等价于 +.example.com（后缀匹配）
//! - `"*.example.com"` —— 仅子域（不含裸域）
//! 匹配不区分大小写，忽略结尾的点。
//!
//! `match_index` 返回配置里的原始下标（与 `DnsResolver::policy_upstreams`
//! 平行对齐），空模式会被跳过但不会打乱下标。

use super::config::UpstreamSpec;

#[derive(Debug, Clone)]
pub struct Policy {
    entries: Vec<(Pattern, Vec<UpstreamSpec>, usize)>,
}

#[derive(Debug, Clone)]
enum Pattern {
    /// 域及其子域
    SuffixInclusive(String),
    /// 仅子域
    Subdomains(String),
}

impl Policy {
    pub fn new(defs: &[(String, Vec<UpstreamSpec>)]) -> Self {
        let entries = defs
            .iter()
            .enumerate()
            .filter_map(|(idx, (pattern, spec))| {
                let p = pattern.trim().trim_end_matches('.').to_lowercase();
                if p.is_empty() {
                    return None;
                }
                let pat = if let Some(sub) = p.strip_prefix("*.") {
                    Pattern::Subdomains(sub.to_string())
                } else {
                    let p = p.strip_prefix("+.").unwrap_or(&p).to_string();
                    Pattern::SuffixInclusive(p)
                };
                Some((pat, spec.clone(), idx))
            })
            .collect();
        Self { entries }
    }

    fn find(&self, domain: &str) -> Option<&(Pattern, Vec<UpstreamSpec>, usize)> {
        let d = domain.trim_end_matches('.').to_lowercase();
        if d.is_empty() {
            return None;
        }
        self.entries.iter().find(|(pat, _, _)| match pat {
            Pattern::SuffixInclusive(base) => d == *base || d.ends_with(&format!(".{}", base)),
            Pattern::Subdomains(base) => d.ends_with(&format!(".{}", base)),
        })
    }

    /// 命中配置下标（用于选择上游组）；未命中返回 None（走路由/默认上游组）。
    pub fn match_index(&self, domain: &str) -> Option<usize> {
        self.find(domain).map(|(_, _, idx)| *idx)
    }

    /// 返回该域名命中的第一个分域上游；未命中返回 None。
    pub fn match_upstream(&self, domain: &str) -> Option<&UpstreamSpec> {
        self.find(domain).and_then(|(_, specs, _)| specs.first())
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::config::UpstreamSpec;

    fn policy() -> Policy {
        Policy::new(&[
            ("+.cn".to_string(), vec![UpstreamSpec::Tunnel]),
            ("*.example.com".to_string(), vec![UpstreamSpec::System]),
        ])
    }

    #[test]
    fn suffix_inclusive_matches_domain_and_subdomain() {
        assert!(policy().match_upstream("baidu.cn").is_some());
        assert!(policy().match_upstream("www.baidu.cn").is_some());
        assert!(policy().match_upstream("evil-cn.example.org").is_none());
    }

    #[test]
    fn suffix_does_not_match_prefix_glued() {
        // "notcn" 不是 ".cn" 的子域
        assert!(policy().match_upstream("notcn").is_none());
    }

    #[test]
    fn subdomains_excludes_apex() {
        assert!(policy().match_upstream("a.example.com").is_some());
        assert!(policy().match_upstream("example.com").is_none());
    }

    #[test]
    fn case_insensitive_and_trailing_dot() {
        assert!(policy().match_upstream("WWW.BAIDU.CN.").is_some());
    }

    #[test]
    fn no_match_returns_none() {
        assert!(policy().match_upstream("github.com").is_none());
    }

    #[test]
    fn match_index_maps_to_original_slice() {
        let defs = vec![
            ("".to_string(), vec![UpstreamSpec::System]),
            ("+.cn".to_string(), vec![UpstreamSpec::Tunnel]),
        ];
        let p = Policy::new(&defs);
        // 空模式被跳过，但命中的下标仍是原始下标 1
        assert_eq!(p.match_index("www.baidu.cn"), Some(1));
        assert_eq!(defs[1].1[0], UpstreamSpec::Tunnel);
        assert_eq!(p.match_index("github.com"), None);
    }
}
