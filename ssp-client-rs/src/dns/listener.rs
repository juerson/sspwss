//! 本地 DNS 监听器（UDP + TCP，默认 127.0.0.1:1053）。
//!
//! 形态照 clash-rs `dns/server/`：客户端/系统把 DNS 指向这个端口，所有查询
//! 都进入 `DnsResolver` 管线（默认 tunnel:// → Worker DoH），从而让整机
//! 应用也享受防泄漏路径。
//!
//! 语义：
//! - A/AAAA → resolver（AAAA 在 `ipv6: false` 时回空 NOERROR，clash-rs 做法）
//! - NXDOMAIN / NODATA 原样回传（NODATA = 空 NOERROR），只有**传输失败**才 SERVFAIL
//! - 其它类型（HTTPS/TXT/MX/SVCB…）→ 原始 wire 透传给上游（默认隧道）
//! - 上游失败 → SERVFAIL（绝不回退系统 DNS）
//! - 响应 TTL 钳制 60s（`message::build_response`）
//!
//! 注意：这是纯客户端本地 socket；上游全部走 WSS 帧或 DoH(TCP)，不引入 UDP
//! 隧道依赖，服务端零改动。

use super::{message, DnsResolver};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::RecordType;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use log::{debug, info, warn};

/// UDP DNS 报文上限（含 EDNS0 常见 4096；无 EDNS 时客户端一般 512）
const MAX_UDP_SIZE: usize = 4096;
/// DNS over TCP 的两字节长度前缀上限
const MAX_TCP_SIZE: usize = 65535;
/// 单条 TCP 连接上的读超时（防止半开连接堆积）
const TCP_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub struct DnsListener {
    udp: Arc<UdpSocket>,
    tcp: TcpListener,
    addr: SocketAddr,
    resolver: Arc<DnsResolver>,
}

impl DnsListener {
    /// 绑定 UDP + TCP。两个协议必须都能绑定成功，否则启动失败（配置期报错）。
    ///
    /// 注意：`addr` 端口为 0 时，UDP 先选到实际端口，再让 TCP 绑定同一端口
    /// （测试与"自动选端口"场景下两者必须一致）。
    pub async fn bind(addr: SocketAddr, resolver: Arc<DnsResolver>) -> io::Result<Self> {
        let udp = Arc::new(UdpSocket::bind(addr).await.map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("绑定 DNS UDP 监听器 {}: {}（端口被占用？）", addr, e),
            )
        })?);
        let actual = udp.local_addr().unwrap_or(addr);
        let tcp = TcpListener::bind(actual).await.map_err(|e| {
            io::Error::new(e.kind(), format!("绑定 DNS TCP 监听器 {}: {}", actual, e))
        })?;
        Ok(Self {
            udp,
            tcp,
            addr: actual,
            resolver,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// 常驻运行（UDP 与 TCP 并行；任一循环意外退出则整体返回错误）。
    pub async fn run(self) -> io::Result<()> {
        info!("🔎 Local DNS listener on {} (udp+tcp)", self.addr);

        let (udp_resolver, tcp_resolver) = (self.resolver.clone(), self.resolver);
        let udp = tokio::spawn(run_udp(self.udp, udp_resolver));
        let tcp = tokio::spawn(run_tcp(self.tcp, tcp_resolver));

        tokio::select! {
            r = udp => flatten(r, "udp"),
            r = tcp => flatten(r, "tcp"),
        }
    }
}

fn flatten(r: Result<io::Result<()>, tokio::task::JoinError>, which: &str) -> io::Result<()> {
    match r {
        Ok(inner) => inner,
        Err(e) => Err(io::Error::new(
            io::ErrorKind::Other,
            format!("DNS {} listener task failed: {}", which, e),
        )),
    }
}

async fn run_udp(socket: Arc<UdpSocket>, resolver: Arc<DnsResolver>) -> io::Result<()> {
    let mut buf = vec![0u8; MAX_UDP_SIZE];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let query = buf[..len].to_vec();
        let socket = socket.clone();
        let resolver = resolver.clone();
        tokio::spawn(async move {
            match answer(&resolver, &query).await {
                Some(resp) => {
                    if resp.len() > MAX_UDP_SIZE {
                        // 理论上不会发生：解析结果由我们构造，很小。
                        debug!("DNS UDP response too large ({} bytes), dropped", resp.len());
                        return;
                    }
                    if let Err(e) = socket.send_to(&resp, peer).await {
                        debug!("DNS UDP send to {} failed: {}", peer, e);
                    }
                }
                None => debug!("DNS UDP query from {} ignored (malformed)", peer),
            }
        });
    }
}

async fn run_tcp(listener: TcpListener, resolver: Arc<DnsResolver>) -> io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let resolver = resolver.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_tcp_conn(stream, resolver).await {
                debug!("DNS TCP connection {} closed: {}", peer, e);
            }
        });
    }
}

async fn serve_tcp_conn(mut stream: TcpStream, resolver: Arc<DnsResolver>) -> io::Result<()> {
    loop {
        let len = match tokio::time::timeout(TCP_IDLE_TIMEOUT, stream.read_u16()).await {
            Ok(Ok(len)) => len as usize,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(()),
        };
        if len == 0 || len > MAX_TCP_SIZE {
            return Ok(());
        }
        let mut query = vec![0u8; len];
        stream.read_exact(&mut query).await?;

        let Some(resp) = answer(&resolver, &query).await else {
            continue;
        };
        stream.write_u16(resp.len() as u16).await?;
        stream.write_all(&resp).await?;
        stream.flush().await?;
    }
}

/// 处理一条 wire 查询。返回 None 表示报文无法解析/不是查询（直接丢弃）。
async fn answer(resolver: &DnsResolver, wire: &[u8]) -> Option<Vec<u8>> {
    let query = Message::from_vec(wire).ok()?;
    if query.message_type() != MessageType::Query {
        return None;
    }
    if query.op_code() != OpCode::Query {
        return Some(message::build_error_response(&query, ResponseCode::NotImp));
    }
    let question = query.queries().first()?;
    // Name 的 Display 带尾点；resolver 会自行规范化
    let name = question.name().to_string();
    let qtype = question.query_type();

    match qtype {
        RecordType::A | RecordType::AAAA => {
            if qtype == RecordType::AAAA && !resolver.ipv6() {
                // ipv6: false —— 回空 NOERROR（clash-rs server 做法），
                // 避免客户端因 SERVFAIL 重试或回退系统 DNS。
                return Some(message::build_empty_noerror_response(&query));
            }
            match resolver.resolve_answer(&name).await {
                Ok(answer) => {
                    // NXDOMAIN / SERVFAIL 等原样回传：映射成 SERVFAIL 会让
                    // 浏览器/系统反复重试，页面里每个统计域名都拖慢首屏。
                    if answer.rcode != ResponseCode::NoError {
                        debug!("DNS {} query for {} -> {}", qtype, name, answer.rcode);
                        return Some(message::build_error_response(&query, answer.rcode));
                    }
                    let ips: Vec<IpAddr> = answer
                        .ips
                        .into_iter()
                        .filter(|ip| match qtype {
                            RecordType::A => ip.is_ipv4(),
                            _ => ip.is_ipv6(),
                        })
                        .collect();
                    if ips.is_empty() {
                        // NODATA：域名存在但没有该类型记录 → 空 NOERROR
                        return Some(message::build_empty_noerror_response(&query));
                    }
                    message::build_response(&query, &ips).ok()
                }
                Err(e) => {
                    debug!("DNS {} query for {} failed: {}", qtype, name, e);
                    Some(message::build_error_response(
                        &query,
                        ResponseCode::ServFail,
                    ))
                }
            }
        }
        _ => match resolver.exchange_raw(wire.to_vec()).await {
            Ok(resp) => {
                // Worker DoH 缓存命中时会把 DNS 事务 ID 改写为帧 request_id
                // （zks-worker/src/session.rs），这里统一改回客户端的事务 ID。
                Some(message::rewrite_id(&resp, query.id()))
            }
            Err(e) => {
                warn!("DNS {} query for {} failed: {}", qtype, name, e);
                Some(message::build_error_response(
                    &query,
                    ResponseCode::ServFail,
                ))
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::config::{DohSpec, UpstreamSpec};
    use crate::dns::guard::Guard;
    use crate::dns::policy::Policy;
    use crate::dns::resolver::DnsResolver;
    use crate::dns::upstream::Upstream;
    use crate::dns::DnsResult;
    use futures_util::future::BoxFuture;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    /// 返回固定 A 记录的假上游（不触网）
    struct StubUpstream {
        ip: Ipv4Addr,
        ttl: u32,
        fail: bool,
    }

    impl Upstream for StubUpstream {
        fn exchange<'a>(&'a self, query: Vec<u8>) -> BoxFuture<'a, DnsResult<Vec<u8>>> {
            Box::pin(async move {
                if self.fail {
                    return Err(crate::dns::DnsError("stub upstream down".into()));
                }
                let req =
                    Message::from_vec(&query).map_err(|e| crate::dns::DnsError(e.to_string()))?;
                let q = req.queries().first().unwrap().clone();
                let mut resp = Message::new();
                resp.set_id(req.id());
                resp.set_message_type(MessageType::Response);
                resp.set_response_code(ResponseCode::NoError);
                resp.add_query(q.clone());
                if q.query_type() == RecordType::A {
                    resp.add_answer(Record::from_rdata(
                        q.name().clone(),
                        self.ttl,
                        RData::A(A(self.ip)),
                    ));
                }
                resp.to_vec()
                    .map_err(|e| crate::dns::DnsError(e.to_string()))
            })
        }

        fn describe(&self) -> String {
            "stub://".to_string()
        }
    }

    fn resolver_with(upstream: StubUpstream, ipv6: bool) -> Arc<DnsResolver> {
        let entries = vec![crate::dns::resolver::UpstreamEntry::Wire(Box::new(
            upstream,
        ))];
        Arc::new(DnsResolver::from_parts(
            ipv6,
            false,
            Policy::new(&[]),
            vec![],
            entries,
            Guard::new(Guard::default_ranges()),
        ))
    }

    /// 永远返回指定响应码的假上游（测试 rcode 透传）
    struct RcodeUpstream(ResponseCode);

    impl Upstream for RcodeUpstream {
        fn exchange<'a>(&'a self, query: Vec<u8>) -> BoxFuture<'a, DnsResult<Vec<u8>>> {
            Box::pin(async move {
                let req =
                    Message::from_vec(&query).map_err(|e| crate::dns::DnsError(e.to_string()))?;
                let mut resp = Message::new();
                resp.set_id(req.id());
                resp.set_message_type(MessageType::Response);
                resp.set_response_code(self.0);
                if let Some(q) = req.queries().first() {
                    resp.add_query(q.clone());
                }
                resp.to_vec()
                    .map_err(|e| crate::dns::DnsError(e.to_string()))
            })
        }

        fn describe(&self) -> String {
            "rcode://".to_string()
        }
    }

    fn resolver_with_upstream(upstream: Box<dyn Upstream>, ipv6: bool) -> Arc<DnsResolver> {
        Arc::new(DnsResolver::from_parts(
            ipv6,
            false,
            Policy::new(&[]),
            vec![],
            vec![crate::dns::resolver::UpstreamEntry::Wire(upstream)],
            Guard::new(Guard::default_ranges()),
        ))
    }

    async fn udp_roundtrip(addr: SocketAddr, wire: &[u8]) -> Vec<u8> {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.send_to(wire, addr).await.unwrap();
        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
            .await
            .expect("udp response timeout")
            .unwrap();
        buf.truncate(n);
        buf
    }

    async fn tcp_roundtrip(addr: SocketAddr, wire: &[u8]) -> Vec<u8> {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_u16(wire.len() as u16).await.unwrap();
        s.write_all(wire).await.unwrap();
        let len = s.read_u16().await.unwrap() as usize;
        let mut buf = vec![0u8; len];
        s.read_exact(&mut buf).await.unwrap();
        buf
    }

    fn a_query(name: &str, id: u16) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(id);
        msg.set_message_type(MessageType::Query);
        msg.set_recursion_desired(true);
        let mut q = hickory_proto::op::Query::new();
        q.set_name(Name::from_utf8(name).unwrap());
        q.set_query_type(RecordType::A);
        msg.add_query(q);
        msg.to_vec().unwrap()
    }

    fn aaaa_query(name: &str, id: u16) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(id);
        msg.set_message_type(MessageType::Query);
        let mut q = hickory_proto::op::Query::new();
        q.set_name(Name::from_utf8(name).unwrap());
        q.set_query_type(RecordType::AAAA);
        msg.add_query(q);
        msg.to_vec().unwrap()
    }

    #[tokio::test]
    async fn udp_a_query_roundtrip_with_ttl() {
        let resolver = resolver_with(
            StubUpstream {
                ip: Ipv4Addr::new(93, 184, 216, 34),
                ttl: 30,
                fail: false,
            },
            false,
        );
        let listener = DnsListener::bind("127.0.0.1:0".parse().unwrap(), resolver)
            .await
            .unwrap();
        let addr = listener.local_addr();
        tokio::spawn(listener.run());

        let resp = udp_roundtrip(addr, &a_query("example.com", 0x1234)).await;
        let msg = Message::from_vec(&resp).unwrap();
        assert_eq!(msg.id(), 0x1234);
        assert_eq!(msg.response_code(), ResponseCode::NoError);
        assert_eq!(msg.answer_count(), 1);
        match msg.answers()[0].data() {
            RData::A(A(ip)) => assert_eq!(*ip, Ipv4Addr::new(93, 184, 216, 34)),
            other => panic!("unexpected rdata: {:?}", other),
        }
        assert_eq!(msg.answers()[0].ttl(), 60, "listener clamps TTL to 60s");
    }

    #[tokio::test]
    async fn tcp_a_query_roundtrip() {
        let resolver = resolver_with(
            StubUpstream {
                ip: Ipv4Addr::new(1, 2, 3, 4),
                ttl: 10,
                fail: false,
            },
            false,
        );
        let listener = DnsListener::bind("127.0.0.1:0".parse().unwrap(), resolver)
            .await
            .unwrap();
        let addr = listener.local_addr();
        tokio::spawn(listener.run());

        let resp = tcp_roundtrip(addr, &a_query("tcp.example", 7)).await;
        let msg = Message::from_vec(&resp).unwrap();
        assert_eq!(msg.id(), 7);
        assert_eq!(msg.answer_count(), 1);
    }

    #[tokio::test]
    async fn aaaa_is_empty_noerror_when_ipv6_disabled() {
        let resolver = resolver_with(
            StubUpstream {
                ip: Ipv4Addr::new(1, 2, 3, 4),
                ttl: 10,
                fail: false,
            },
            false,
        );
        let listener = DnsListener::bind("127.0.0.1:0".parse().unwrap(), resolver)
            .await
            .unwrap();
        let addr = listener.local_addr();
        tokio::spawn(listener.run());

        let resp = udp_roundtrip(addr, &aaaa_query("example.com", 9)).await;
        let msg = Message::from_vec(&resp).unwrap();
        assert_eq!(msg.response_code(), ResponseCode::NoError);
        assert_eq!(msg.answer_count(), 0);
    }

    #[tokio::test]
    async fn upstream_failure_yields_servfail_not_system_dns() {
        let resolver = resolver_with(
            StubUpstream {
                ip: Ipv4Addr::new(0, 0, 0, 0),
                ttl: 10,
                fail: true,
            },
            false,
        );
        let listener = DnsListener::bind("127.0.0.1:0".parse().unwrap(), resolver)
            .await
            .unwrap();
        let addr = listener.local_addr();
        tokio::spawn(listener.run());

        let resp = udp_roundtrip(addr, &a_query("localhost", 11)).await;
        let msg = Message::from_vec(&resp).unwrap();
        assert_eq!(msg.response_code(), ResponseCode::ServFail);
        assert_eq!(msg.answer_count(), 0);
    }

    #[tokio::test]
    async fn nxdomain_is_propagated_not_servfail() {
        let resolver =
            resolver_with_upstream(Box::new(RcodeUpstream(ResponseCode::NXDomain)), false);
        let listener = DnsListener::bind("127.0.0.1:0".parse().unwrap(), resolver)
            .await
            .unwrap();
        let addr = listener.local_addr();
        tokio::spawn(listener.run());

        let resp = udp_roundtrip(addr, &a_query("nope.invalid", 21)).await;
        let msg = Message::from_vec(&resp).unwrap();
        assert_eq!(msg.id(), 21);
        assert_eq!(msg.response_code(), ResponseCode::NXDomain);
        assert_eq!(msg.answer_count(), 0);
    }

    #[tokio::test]
    async fn nodata_is_empty_noerror() {
        let resolver =
            resolver_with_upstream(Box::new(RcodeUpstream(ResponseCode::NoError)), false);
        let listener = DnsListener::bind("127.0.0.1:0".parse().unwrap(), resolver)
            .await
            .unwrap();
        let addr = listener.local_addr();
        tokio::spawn(listener.run());

        let resp = udp_roundtrip(addr, &a_query("only-aaaa.example", 22)).await;
        let msg = Message::from_vec(&resp).unwrap();
        assert_eq!(msg.response_code(), ResponseCode::NoError);
        assert_eq!(msg.answer_count(), 0);
    }

    #[test]
    fn doh_spec_unused_smoke() {
        // 保证 DohSpec/UpstreamSpec 在本测试模块里被引用（避免 unused import 告警）
        let spec = DohSpec {
            url: "https://223.5.5.5/dns-query".into(),
            host: "223.5.5.5".into(),
            port: 443,
            ip: Some("223.5.5.5".parse().unwrap()),
        };
        assert!(matches!(UpstreamSpec::Doh(spec), UpstreamSpec::Doh(_)));
    }
}
