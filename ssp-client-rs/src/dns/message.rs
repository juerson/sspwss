//! DNS wire 报文构造与解析（hickory-proto 封装）。
//! 上游全部传原始 wire bytes —— 与 zks-proto 的 DnsQuery/DnsResponse 帧对齐，
//! 也与 Worker 端 DoH (`zks-worker/src/session.rs::resolve_dns_via_doh`) 对齐。

use super::{DnsError, DnsResult};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};

/// 事务 ID 计数器（进程内唯一即可；Worker 端按 question 段缓存并回填事务 ID）
static TXID: AtomicU32 = AtomicU32::new(1);

/// 构造递归查询报文（wire bytes）
pub fn build_query(name: &str, qtype: RecordType) -> DnsResult<Vec<u8>> {
    let mut msg = Message::new();
    msg.set_id((TXID.fetch_add(1, Ordering::SeqCst) & 0xFFFF) as u16);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);

    let mut query = Query::new();
    query.set_name(parse_name(name)?);
    query.set_query_type(qtype);
    msg.add_query(query);

    msg.to_vec()
        .map_err(|e| DnsError(format!("build dns query for {:?}: {}", name, e)))
}

/// 解析域名（小写、去尾点、容忍非法字符的能力交给错误路径）
pub fn parse_name(name: &str) -> DnsResult<Name> {
    let cleaned = name.trim().trim_end_matches('.').to_lowercase();
    if cleaned.is_empty() {
        return Err(DnsError("empty domain name".into()));
    }
    Name::from_utf8(cleaned)
        .map(|n| {
            // 保证 FQDN（相对名会隐式追加 root）
            if n.is_fqdn() {
                n
            } else {
                n.append_domain(&Name::root()).expect("root append")
            }
        })
        .map_err(|e| DnsError(format!("invalid domain name {:?}: {}", name, e)))
}

/// 上游响应的完整解析结果（保留响应码，监听器要原样回 NXDOMAIN/NODATA）。
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedAnswer {
    pub ips: Vec<IpAddr>,
    pub ttl: std::time::Duration,
    pub rcode: ResponseCode,
}

/// 解析上游响应：保留 rcode，不再把 NXDOMAIN / NODATA 混为一谈。
pub fn parse_answer(wire: &[u8], qtype: RecordType) -> DnsResult<ParsedAnswer> {
    let msg =
        Message::from_vec(wire).map_err(|e| DnsError(format!("parse dns response: {}", e)))?;

    if msg.message_type() != MessageType::Response {
        return Err(DnsError("upstream answered with a non-response".into()));
    }
    let rcode = msg.response_code();
    if rcode != ResponseCode::NoError {
        return Ok(ParsedAnswer {
            ips: Vec::new(),
            ttl: std::time::Duration::from_secs(30),
            rcode,
        });
    }

    let mut ips = Vec::new();
    let mut min_ttl = u32::MAX;
    for record in msg.answers() {
        if record.record_type() != qtype {
            continue; // 跳过 CNAME 等无关记录
        }
        let (ip, ttl) = match record.data() {
            RData::A(A(ip)) => (IpAddr::V4(*ip), record.ttl()),
            RData::AAAA(AAAA(ip)) => (IpAddr::V6(*ip), record.ttl()),
            _ => continue,
        };
        ips.push(ip);
        min_ttl = min_ttl.min(ttl);
    }

    let ttl = if min_ttl == u32::MAX {
        // NoError 但无地址（NODATA）：域名存在，只是没有该类型记录
        std::time::Duration::from_secs(30)
    } else {
        std::time::Duration::from_secs(min_ttl as u64)
    };
    Ok(ParsedAnswer { ips, ttl, rcode })
}

/// 兼容包装：失败响应码或空答案视为错误（供 bootstrap 等"必须有地址"的场景用）。
pub fn parse_response(
    wire: &[u8],
    qtype: RecordType,
) -> DnsResult<(Vec<IpAddr>, std::time::Duration)> {
    let parsed = parse_answer(wire, qtype)?;
    if parsed.rcode != ResponseCode::NoError {
        return Err(DnsError(format!("upstream returned {}", parsed.rcode)));
    }
    if parsed.ips.is_empty() {
        return Err(DnsError(format!("no {} answer from upstream", qtype)));
    }
    Ok((parsed.ips, parsed.ttl))
}

/// 按查询构造响应报文（本地监听器用）。TTL 钳制为 60s（clash-rs DEFAULT_DNS_SERVER_TTL）。
pub fn build_response(query: &Message, ips: &[IpAddr]) -> DnsResult<Vec<u8>> {
    let mut resp = Message::new();
    resp.set_id(query.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(query.op_code());
    resp.set_recursion_desired(query.recursion_desired());
    resp.set_recursion_available(true);
    resp.set_response_code(ResponseCode::NoError);
    for q in query.queries() {
        resp.add_query(q.clone());
    }

    for q in query.queries() {
        let name = q.name().clone();
        for ip in ips {
            let record = match ip {
                IpAddr::V4(v4) if q.query_type() == RecordType::A => {
                    Some(Record::from_rdata(name.clone(), 60, RData::A(A(*v4))))
                }
                IpAddr::V6(v6) if q.query_type() == RecordType::AAAA => {
                    Some(Record::from_rdata(name.clone(), 60, RData::AAAA(AAAA(*v6))))
                }
                _ => None,
            };
            if let Some(record) = record {
                resp.add_answer(record);
            }
        }
    }

    resp.to_vec()
        .map_err(|e| DnsError(format!("build dns response: {}", e)))
}

/// 构造 SERVFAIL 响应（保留事务 ID 与问题段）
pub fn build_error_response(query: &Message, code: ResponseCode) -> Vec<u8> {
    let mut resp = Message::new();
    resp.set_id(query.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(query.op_code());
    resp.set_recursion_desired(query.recursion_desired());
    resp.set_response_code(code);
    for q in query.queries() {
        resp.add_query(q.clone());
    }
    resp.to_vec().unwrap_or_default()
}

/// 构造空 NOERROR 响应（AAAA 在 ipv6=false 时的 clash-rs 做法）
pub fn build_empty_noerror_response(query: &Message) -> Vec<u8> {
    build_error_response(query, ResponseCode::NoError)
}

/// 提取查询报文里的第一个 question 域名（分域策略用）。
pub fn query_name(wire: &[u8]) -> Option<String> {
    let msg = Message::from_vec(wire).ok()?;
    msg.queries().first().map(|q| q.name().to_string())
}

/// 把响应报文的事务 ID 改写为指定值（返回新 Vec）。
///
/// 主要用于本地监听器：Worker 的 DoH 缓存在命中时会把响应前两字节改成帧
/// request_id（`zks-worker/src/session.rs`），与客户端 DNS 事务 ID 不同，
/// 必须在回包前改回，否则客户端会丢弃响应。
pub fn rewrite_id(wire: &[u8], id: u16) -> Vec<u8> {
    let mut out = wire.to_vec();
    if out.len() >= 2 {
        out[0] = (id >> 8) as u8;
        out[1] = (id & 0xFF) as u8;
    }
    out
}

/// DoH GET 的 `?dns=` 参数（base64url，无填充 —— RFC 8484）
pub fn dns_query_to_base64(wire: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(wire)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn query_roundtrip() {
        let wire = build_query("Example.COM.", RecordType::A).unwrap();
        let msg = Message::from_vec(&wire).unwrap();
        let q = msg.queries().first().unwrap();
        assert_eq!(q.query_type(), RecordType::A);
        assert_eq!(q.name().to_lowercase().to_string(), "example.com.");
        assert!(msg.recursion_desired());
        assert_eq!(msg.message_type(), MessageType::Query);
    }

    #[test]
    fn parse_name_normalizes() {
        let n = parse_name("WWW.Example.com.").unwrap();
        assert_eq!(n.to_string(), "www.example.com.");
    }

    #[test]
    fn parse_name_rejects_empty_and_garbage() {
        assert!(parse_name("").is_err());
        assert!(parse_name("   ").is_err());
        assert!(parse_name("exa mple.com").is_err());
    }

    fn wire_a_response(name: &str, ips: &[Ipv4Addr], ttl: u32) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(42);
        msg.set_message_type(MessageType::Response);
        let mut q = Query::new();
        q.set_name(parse_name(name).unwrap());
        q.set_query_type(RecordType::A);
        msg.add_query(q.clone());
        for ip in ips {
            msg.add_answer(Record::from_rdata(q.name().clone(), ttl, RData::A(A(*ip))));
        }
        msg.to_vec().unwrap()
    }

    #[test]
    fn parse_response_extracts_ips_and_ttl() {
        let wire = wire_a_response(
            "a.com",
            &[Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(2, 2, 2, 2)],
            120,
        );
        let (ips, ttl) = parse_response(&wire, RecordType::A).unwrap();
        assert_eq!(
            ips,
            vec![
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))
            ]
        );
        assert_eq!(ttl, std::time::Duration::from_secs(120));
    }

    #[test]
    fn parse_response_nxdomain_is_error() {
        let mut msg = Message::new();
        msg.set_id(1);
        msg.set_message_type(MessageType::Response);
        msg.set_response_code(ResponseCode::NXDomain);
        let wire = msg.to_vec().unwrap();
        assert!(parse_response(&wire, RecordType::A).is_err());
    }

    #[test]
    fn parse_response_nodata_is_error() {
        let wire = wire_a_response("a.com", &[], 60);
        assert!(parse_response(&wire, RecordType::A).is_err());
    }

    #[test]
    fn parse_answer_preserves_nxdomain() {
        let mut msg = Message::new();
        msg.set_id(1);
        msg.set_message_type(MessageType::Response);
        msg.set_response_code(ResponseCode::NXDomain);
        let wire = msg.to_vec().unwrap();
        let ans = parse_answer(&wire, RecordType::A).unwrap();
        assert_eq!(ans.rcode, ResponseCode::NXDomain);
        assert!(ans.ips.is_empty());
    }

    #[test]
    fn parse_answer_distinguishes_nodata() {
        // 域名存在但没有 A 记录（只有 AAAA/HTTPS）—— 必须是 NOERROR + 空，
        // 否则监听器会回 SERVFAIL，浏览器会当成解析失败反复重试。
        let wire = wire_a_response("a.com", &[], 60);
        let ans = parse_answer(&wire, RecordType::A).unwrap();
        assert_eq!(ans.rcode, ResponseCode::NoError);
        assert!(ans.ips.is_empty());
    }

    #[test]
    fn build_response_echoes_and_clamps() {
        let query_wire = build_query("a.com", RecordType::A).unwrap();
        let query = Message::from_vec(&query_wire).unwrap();
        let ips = vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))];
        let resp = Message::from_vec(&build_response(&query, &ips).unwrap()).unwrap();
        assert_eq!(resp.id(), query.id());
        assert_eq!(resp.answer_count(), 1);
        assert!(resp.recursion_available());
    }

    #[test]
    fn base64_nopad() {
        let b = dns_query_to_base64(&[0, 1, 254, 255]);
        assert!(!b.contains('+') && !b.contains('/') && !b.contains('='));
    }
}
