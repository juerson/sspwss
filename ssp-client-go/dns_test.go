package main

// DNS 防泄漏模块单元测试 —— 对齐 ssp-client-rs resolver/policy/guard/listener
// 的测试语义：fail-closed、禁区守卫、缓存吸收、分组选择、policy 覆盖、
// NXDOMAIN/NODATA 透传、监听器 rcode 语义、路由分类器。

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ── 测试桩 ───────────────────────────────────────────────────────────────────

// stubUpstream 固定答案的假上游；记录被调用次数与最近一次查询类型
type stubUpstream struct {
	label    string
	v4       net.IP
	ttl      uint32
	fail     bool
	rcode    int
	calls    atomic.Int32
	lastType uint16
}

func newStub(label string, v4 net.IP) *stubUpstream {
	return &stubUpstream{label: label, v4: v4, ttl: 45, rcode: dns.RcodeSuccess}
}

func failingStub(label string) *stubUpstream {
	return &stubUpstream{label: label, fail: true, rcode: dns.RcodeSuccess}
}

func rcodeStub(rcode int) *stubUpstream {
	return &stubUpstream{label: "rcode://", rcode: rcode}
}

func (s *stubUpstream) Exchange(query []byte) ([]byte, error) {
	req := new(dns.Msg)
	if err := req.Unpack(query); err != nil {
		return nil, err
	}
	if len(req.Question) == 0 {
		return nil, errors.New("stub: no question")
	}
	q := req.Question[0]
	s.lastType = q.Qtype
	s.calls.Add(1)
	if s.fail {
		return nil, errors.New(s.label + " down")
	}
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Rcode = s.rcode
	if s.rcode == dns.RcodeSuccess && s.v4 != nil {
		switch q.Qtype {
		case dns.TypeA:
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: s.ttl},
				A:   s.v4.To4(),
			})
		case dns.TypeAAAA:
			// 2001:db8::<v4> 形态的可预测 AAAA 答案
			v6 := make(net.IP, 16)
			v6[0], v6[1], v6[2], v6[3] = 0x20, 0x01, 0x0d, 0xb8
			copy(v6[12:], s.v4.To4())
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: s.ttl},
				AAAA: v6,
			})
		}
	}
	return resp.Pack()
}

func (s *stubUpstream) Describe() string { return s.label }

// mustGuard 测试守卫（内置禁区段）
func mustGuard() *dnsGuard {
	g, err := newDnsGuard(nil)
	if err != nil {
		panic(err)
	}
	return g
}

// testResolver 纯组装入口（不走配置加载/引导）
func testResolver(entries []dnsUpstream, ipv6 bool) *DnsResolver {
	return &DnsResolver{
		ipv6:       ipv6,
		policy:     newDnsPolicy(nil),
		defaultUps: entries,
		cache:      newDnsCache(),
		guard:      mustGuard(),
	}
}

// ── Resolver 行为 ────────────────────────────────────────────────────────────

func TestResolverFailsClosedWhenUpstreamDown(t *testing.T) {
	r := testResolver([]dnsUpstream{failingStub("down")}, false)
	if _, err := r.Resolve("example.com"); err == nil {
		t.Fatal("expected error, got nil")
	}
	// 失败不缓存：第二次仍触发上游
	if _, err := r.Resolve("example.com"); err == nil {
		t.Fatal("expected persistent error (fail-closed)")
	}
}

func TestGuardRejectsForbiddenAnswer(t *testing.T) {
	forbidden := newStub("forbidden://", net.IPv4(198, 18, 0, 7).To4())
	r := testResolver([]dnsUpstream{forbidden}, false)
	_, err := r.Resolve("loop.example")
	if err == nil || !strings.Contains(err.Error(), "198.18.0.7") {
		t.Fatalf("expected forbidden-address error, got %v", err)
	}
}

func TestSecondResolveHitsCache(t *testing.T) {
	stub := newStub("stub://", net.IPv4(1, 2, 3, 4))
	r := testResolver([]dnsUpstream{stub}, false)

	ips, err := r.Resolve("cache.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.IPv4(1, 2, 3, 4).To4()) {
		t.Fatalf("unexpected ips: %v", ips)
	}
	if _, err := r.Resolve("cache.example"); err != nil {
		t.Fatal(err)
	}
	if got := stub.calls.Load(); got != 1 {
		t.Fatalf("cache must absorb second query, calls=%d", got)
	}
}

func TestIPv6DisabledQueriesOnlyA(t *testing.T) {
	stub := newStub("stub://", net.IPv4(5, 6, 7, 8))
	r := testResolver([]dnsUpstream{stub}, false)

	ips, err := r.Resolve("v4only.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0].To4() == nil {
		t.Fatalf("expected single v4, got %v", ips)
	}
	if stub.lastType != dns.TypeA {
		t.Fatalf("expected A query, got type %d", stub.lastType)
	}
	if got := stub.calls.Load(); got != 1 {
		t.Fatalf("expected single exchange, calls=%d", got)
	}
}

func TestIPv6EnabledAddsAAAA(t *testing.T) {
	stub := newStub("stub://", net.IPv4(5, 6, 7, 8))
	r := testResolver([]dnsUpstream{stub}, true)
	ips, err := r.Resolve("dual.example")
	if err != nil {
		t.Fatal(err)
	}
	hasV4, hasV6 := false, false
	for _, ip := range ips {
		if ip.To4() != nil {
			hasV4 = true
		} else {
			hasV6 = true
		}
	}
	if !hasV4 || !hasV6 {
		t.Fatalf("expected both families, got %v", ips)
	}
}

func TestPolicySelectsMatchingUpstreamGroup(t *testing.T) {
	cn := newStub("cn://", net.IPv4(10, 0, 0, 1))
	global := newStub("global://", net.IPv4(20, 0, 0, 1))
	r := testResolver([]dnsUpstream{global}, false)
	r.policy = newDnsPolicy([]policyRuleDef{{Pattern: "+.cn"}})
	r.policyUps = [][]dnsUpstream{{cn}}

	if _, err := r.Resolve("baidu.cn"); err != nil {
		t.Fatal(err)
	}
	if cn.calls.Load() != 1 || global.calls.Load() != 0 {
		t.Fatalf("policy group must win: cn=%d global=%d", cn.calls.Load(), global.calls.Load())
	}

	if _, err := r.Resolve("github.com"); err != nil {
		t.Fatal(err)
	}
	if global.calls.Load() != 1 {
		t.Fatalf("default group must serve non-policy domain, global=%d", global.calls.Load())
	}
}

// fixedClassifier 固定分类结果（测试用）
type fixedClassifier RouteClass

func (f fixedClassifier) ClassifyDomain(string) RouteClass { return RouteClass(f) }

func TestDirectRouteUsesDirectNameserver(t *testing.T) {
	direct := newStub("direct://", net.IPv4(10, 0, 0, 1))
	def := newStub("tunnel://", net.IPv4(20, 0, 0, 1))
	r := testResolver([]dnsUpstream{def}, false)
	r.directUps = []dnsUpstream{direct}
	r.classifier = fixedClassifier(RouteClassDirect)

	if _, err := r.Resolve("cn.example"); err != nil {
		t.Fatal(err)
	}
	if direct.calls.Load() != 1 || def.calls.Load() != 0 {
		t.Fatalf("direct group must win: direct=%d default=%d", direct.calls.Load(), def.calls.Load())
	}
}

func TestProxyRouteFallsBackToDefaultWhenGroupMissing(t *testing.T) {
	def := newStub("tunnel://", net.IPv4(20, 0, 0, 1))
	r := testResolver([]dnsUpstream{def}, false)
	r.classifier = fixedClassifier(RouteClassProxy)

	if _, err := r.Resolve("foreign.example"); err != nil {
		t.Fatal(err)
	}
	if def.calls.Load() != 1 {
		t.Fatalf("default group must serve, calls=%d", def.calls.Load())
	}
}

func TestPolicyOverridesRouteClassification(t *testing.T) {
	policied := newStub("policy://", net.IPv4(30, 0, 0, 1))
	def := newStub("tunnel://", net.IPv4(20, 0, 0, 1))
	dead := newStub("dead://", net.IPv4(127, 0, 0, 1))

	r := testResolver([]dnsUpstream{def}, false)
	r.policy = newDnsPolicy([]policyRuleDef{{Pattern: "+.corp"}})
	r.policyUps = [][]dnsUpstream{{policied}}
	r.directUps = []dnsUpstream{dead}
	r.classifier = fixedClassifier(RouteClassDirect)

	if _, err := r.Resolve("host.corp"); err != nil {
		t.Fatal(err)
	}
	if policied.calls.Load() != 1 || dead.calls.Load() != 0 {
		t.Fatalf("policy must override classification: policy=%d direct=%d", policied.calls.Load(), dead.calls.Load())
	}
}

func TestIPLiteralShortCircuits(t *testing.T) {
	stub := failingStub("never")
	r := testResolver([]dnsUpstream{stub}, false)
	ips, err := r.Resolve("203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.IPv4(203, 0, 113, 9).To4()) {
		t.Fatalf("unexpected ips: %v", ips)
	}
	if stub.calls.Load() != 0 {
		t.Fatalf("ip literal must not touch upstream, calls=%d", stub.calls.Load())
	}
}

func TestNXDomainIsTransmittedNotErrorMapped(t *testing.T) {
	stub := rcodeStub(dns.RcodeNameError)
	r := testResolver([]dnsUpstream{stub}, false)
	ans, err := r.ResolveAnswer("nope.invalid")
	if err != nil {
		t.Fatalf("resolve_answer must carry rcode, got err %v", err)
	}
	if ans.Rcode != dns.RcodeNameError || len(ans.IPs) != 0 {
		t.Fatalf("unexpected answer: %+v", ans)
	}
	// resolve() 仍报错（调用方需要地址）
	if _, err := r.Resolve("nope.invalid"); err == nil {
		t.Fatal("resolve must error on NXDOMAIN")
	}
	// negative 不缓存：两次查询都触达上游
	if got := stub.calls.Load(); got != 2 {
		t.Fatalf("negative answers must not be cached, calls=%d", got)
	}
}

func TestNoDataIsNoErrorNotError(t *testing.T) {
	r := testResolver([]dnsUpstream{rcodeStub(dns.RcodeSuccess)}, false)
	ans, err := r.ResolveAnswer("only-aaaa.example")
	if err != nil {
		t.Fatal(err)
	}
	if ans.Rcode != dns.RcodeSuccess || len(ans.IPs) != 0 {
		t.Fatalf("expected NODATA, got %+v", ans)
	}
	if _, err := r.Resolve("only-aaaa.example"); err == nil {
		t.Fatal("resolve must error on NODATA (caller needs an address)")
	}
}

// ── 守卫 ─────────────────────────────────────────────────────────────────────

func TestGuardDefaultRange(t *testing.T) {
	g := mustGuard()
	if err := g.check([]net.IP{net.IPv4(1, 2, 3, 4), net.ParseIP("2606:4700::1111")}); err != nil {
		t.Fatalf("normal addresses must pass: %v", err)
	}
	if err := g.check([]net.IP{net.ParseIP("198.18.5.5")}); err == nil {
		t.Fatal("fake-ip range must be rejected")
	}
	if err := g.check([]net.IP{net.ParseIP("198.19.255.255")}); err == nil {
		t.Fatal("198.19.255.255 is inside /15")
	}
	if err := g.check([]net.IP{net.ParseIP("198.20.0.1")}); err != nil {
		t.Fatalf("198.20.0.1 is outside /15: %v", err)
	}
}

func TestGuardCanonicalizesV4MappedV6(t *testing.T) {
	g := mustGuard()
	// ::ffff:198.18.0.1 是 v4-mapped IPv6，规范化后应命中禁区
	if err := g.check([]net.IP{net.ParseIP("::ffff:198.18.0.1")}); err == nil {
		t.Fatal("v4-mapped v6 must hit forbidden range")
	}
}

// ── policy 匹配 ──────────────────────────────────────────────────────────────

func TestPolicyMatchSemantics(t *testing.T) {
	p := newDnsPolicy([]policyRuleDef{
		{Pattern: "+.cn"},
		{Pattern: "*.example.com"},
	})
	cases := []struct {
		domain string
		want   int
	}{
		{"baidu.cn", 0},
		{"www.baidu.cn", 0},
		{"evil-cn.example.org", -1},
		{"notcn", -1},
		{"a.example.com", 1},
		{"example.com", -1}, // 子域模式不含裸域
		{"WWW.BAIDU.CN.", 0},
		{"github.com", -1},
	}
	for _, c := range cases {
		if got := p.matchIndex(c.domain); got != c.want {
			t.Errorf("matchIndex(%q)=%d want %d", c.domain, got, c.want)
		}
	}
}

func TestPolicyEmptyPatternKeepsIndex(t *testing.T) {
	// 空模式被跳过，但命中的下标仍是原始下标 1（RS match_index_maps_to_original_slice）
	p := newDnsPolicy([]policyRuleDef{
		{Pattern: ""},
		{Pattern: "+.cn"},
	})
	if got := p.matchIndex("www.baidu.cn"); got != 1 {
		t.Fatalf("matchIndex=%d want 1", got)
	}
}

// ── 配置解析 ─────────────────────────────────────────────────────────────────

func TestParseUpstreamSpec(t *testing.T) {
	spec, err := parseUpstreamSpec("tunnel://")
	if err != nil || spec.kind != upstreamTunnel {
		t.Fatalf("tunnel://: %v %+v", err, spec)
	}
	spec, err = parseUpstreamSpec("system://")
	if err != nil || spec.kind != upstreamSystem {
		t.Fatalf("system://: %v %+v", err, spec)
	}
	spec, err = parseUpstreamSpec("https://223.5.5.5/dns-query")
	if err != nil || spec.kind != upstreamDoh || spec.doh.IP == nil || spec.doh.Host != "223.5.5.5" {
		t.Fatalf("doh literal: %v %+v", err, spec.doh)
	}
	spec, err = parseUpstreamSpec("https://dns.alidns.com/dns-query")
	if err != nil || spec.doh.IP != nil || spec.doh.Host != "dns.alidns.com" {
		t.Fatalf("doh hostname: %v %+v", err, spec.doh)
	}
	// mihomo 兼容：#片段 → 经代理出口 = 隧道
	spec, err = parseUpstreamSpec("https://1.1.1.1/dns-query#节点选择")
	if err != nil || spec.kind != upstreamTunnel {
		t.Fatalf("doh #fragment: %v %+v", err, spec)
	}
	// udp:// 不支持（全程无 UDP 依赖）
	if _, err := parseUpstreamSpec("udp://223.5.5.5"); err == nil {
		t.Fatal("udp:// must be rejected")
	}
}

func TestBootstrapListRejectsHostname(t *testing.T) {
	_, err := parseBootstrapList([]string{"https://dns.alidns.com/dns-query"}, "default-nameserver")
	if err == nil || !strings.Contains(err.Error(), "字面 IP") {
		t.Fatalf("expected literal-IP error, got %v", err)
	}
	if _, err := parseBootstrapList([]string{"tunnel://"}, "default-nameserver"); err == nil {
		t.Fatal("bootstrap must reject tunnel://")
	}
	list, err := parseBootstrapList([]string{"https://223.5.5.5/dns-query"}, "default-nameserver")
	if err != nil || len(list) != 1 {
		t.Fatalf("literal bootstrap must pass: %v %v", list, err)
	}
}

func TestLoadDnsConfigDefaults(t *testing.T) {
	// 文件不存在 → 内置默认（全隧道）
	cfg, err := loadDnsConfig(t.TempDir() + "/nonexistent.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Nameserver) != 1 || cfg.Nameserver[0].kind != upstreamTunnel {
		t.Fatalf("default nameserver must be tunnel://, got %v", describeUpstreamSpecs(cfg.Nameserver))
	}
	if len(cfg.DefaultNameserver) != 1 || cfg.DefaultNameserver[0].IP == nil {
		t.Fatalf("builtin bootstrap must be literal-IP DoH, got %+v", cfg.DefaultNameserver)
	}
	if cfg.DirectNameserver != nil || cfg.ProxyNameserver != nil {
		t.Fatal("default config must not set direct/proxy groups")
	}
}

func TestLoadDnsConfigFullFile(t *testing.T) {
	yamlContent := `
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
  "+.example.com":
    - "tunnel://"
fallback-system: false
`
	path := t.TempDir() + "/dns.yaml"
	if err := writeFile(path, yamlContent); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadDnsConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:1053" {
		t.Fatalf("listen=%q", cfg.Listen)
	}
	if len(cfg.DirectNameserver) != 1 {
		t.Fatalf("direct group missing: %v", describeUpstreamSpecs(cfg.DirectNameserver))
	}
	if len(cfg.NameserverPolicy) != 2 || cfg.NameserverPolicy[0].Pattern != "+.cn" {
		t.Fatalf("policy order broken: %+v", cfg.NameserverPolicy)
	}
	if len(cfg.NameserverPolicy[1].Upstreams) != 1 {
		t.Fatalf("policy list value not accepted: %+v", cfg.NameserverPolicy[1])
	}
}

func TestLoadDnsConfigRejectsUnknownField(t *testing.T) {
	path := t.TempDir() + "/dns.yaml"
	if err := writeFile(path, "nope: true\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDnsConfig(path); err == nil {
		t.Fatal("unknown field must be rejected")
	}
}

func TestLoadDnsConfigRejectsHostnameBootstrap(t *testing.T) {
	path := t.TempDir() + "/dns.yaml"
	if err := writeFile(path, "default-nameserver:\n  - \"https://dns.alidns.com/dns-query\"\n"); err != nil {
		t.Fatal(err)
	}
	_, err := loadDnsConfig(path)
	if err == nil || !strings.Contains(err.Error(), "default-nameserver") {
		t.Fatalf("expected bootstrap validation error, got %v", err)
	}
}

func TestLoadDnsConfigRejectsBadListen(t *testing.T) {
	path := t.TempDir() + "/dns.yaml"
	if err := writeFile(path, "listen: \"not-an-addr\"\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDnsConfig(path); err == nil || !strings.Contains(err.Error(), "listen") {
		t.Fatalf("expected listen error, got %v", err)
	}
}

func TestLoadDnsConfigRejectsGeositePolicy(t *testing.T) {
	path := t.TempDir() + "/dns.yaml"
	if err := writeFile(path, "nameserver-policy:\n  \"geosite:cn\": \"https://223.5.5.5/dns-query\"\n"); err != nil {
		t.Fatal(err)
	}
	_, err := loadDnsConfig(path)
	if err == nil || !strings.Contains(err.Error(), "direct-nameserver") {
		t.Fatalf("expected geosite guidance error, got %v", err)
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

// ── wire 报文 ────────────────────────────────────────────────────────────────

func TestBuildDnsQueryWorkerCompatible(t *testing.T) {
	// worker dnsCacheKey 要求：qdcount==1、查询段无压缩指针（wire 上保留大小写，
	// worker 端自行小写化做缓存键）
	wire, err := buildDnsQuery("Example.COM", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if wire[4] != 0 || wire[5] != 1 {
		t.Fatalf("qdcount must be 1: %x", wire[4:6])
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	if msg.Question[0].Name != "Example.COM." {
		t.Fatalf("unexpected qname: %s", msg.Question[0].Name)
	}
}

func TestParseWireAnswerMinTTL(t *testing.T) {
	q, err := buildDnsQuery("ttl.example", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	req := new(dns.Msg)
	if err := req.Unpack(q); err != nil {
		t.Fatal(err)
	}
	resp := req.SetReply(req)
	resp.Answer = append(resp.Answer,
		&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: net.IPv4(1, 1, 1, 1)},
		&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.IPv4(2, 2, 2, 2)},
	)
	wire, err := resp.Pack()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseWireAnswer(wire, dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.ips) != 2 {
		t.Fatalf("expected 2 ips, got %v", parsed.ips)
	}
	if parsed.ttl != 30*time.Second {
		t.Fatalf("expected min TTL 30s, got %s", parsed.ttl)
	}
}

// ── 监听器语义 ───────────────────────────────────────────────────────────────

func aQueryWire(t *testing.T, name string, id uint16) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA) // SetQuestion 会重置 Id，因此随后再赋值
	m.Id = id
	m.RecursionDesired = true
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func aaaaQueryWire(t *testing.T, name string, id uint16) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeAAAA)
	m.Id = id
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestListenerARoundtripPassthroughTTL(t *testing.T) {
	stub := newStub("stub://", net.IPv4(93, 184, 216, 34)) // TTL 45s ≤ 60s
	r := testResolver([]dnsUpstream{stub}, false)

	resp, ok := answerDnsQuery(r, aQueryWire(t, "example.com", 0x1234))
	if !ok {
		t.Fatal("query dropped")
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(resp); err != nil {
		t.Fatal(err)
	}
	if msg.Id != 0x1234 || msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 {
		t.Fatalf("unexpected response: %+v", msg)
	}
	if msg.Answer[0].Header().Ttl != 45 {
		t.Fatalf("TTL should pass through, got %d", msg.Answer[0].Header().Ttl)
	}
}

func TestListenerClampsTTLOver60(t *testing.T) {
	stub := newStub("stub://", net.IPv4(1, 2, 3, 4))
	stub.ttl = 300 // 超过监听器 60s 上限
	r := testResolver([]dnsUpstream{stub}, false)
	resp, ok := answerDnsQuery(r, aQueryWire(t, "clamp.example", 3))
	if !ok {
		t.Fatal("query dropped")
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(resp); err != nil {
		t.Fatal(err)
	}
	if msg.Answer[0].Header().Ttl != 60 {
		t.Fatalf("listener must clamp TTL to 60s, got %d", msg.Answer[0].Header().Ttl)
	}
}

func TestListenerAAAARespectsIPv6Switch(t *testing.T) {
	r := testResolver([]dnsUpstream{newStub("stub://", net.IPv4(1, 2, 3, 4))}, false)
	resp, ok := answerDnsQuery(r, aaaaQueryWire(t, "example.com", 9))
	if !ok {
		t.Fatal("query dropped")
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(resp); err != nil {
		t.Fatal(err)
	}
	if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 0 {
		t.Fatalf("AAAA with ipv6:false must be empty NOERROR, got rcode=%d answers=%d", msg.Rcode, len(msg.Answer))
	}
}

func TestListenerUpstreamFailureYieldsServfail(t *testing.T) {
	r := testResolver([]dnsUpstream{failingStub("down")}, false)
	resp, ok := answerDnsQuery(r, aQueryWire(t, "localhost", 11))
	if !ok {
		t.Fatal("query dropped")
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(resp); err != nil {
		t.Fatal(err)
	}
	if msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL, got %s", dns.RcodeToString[msg.Rcode])
	}
}

func TestListenerNXDomainPropagated(t *testing.T) {
	r := testResolver([]dnsUpstream{rcodeStub(dns.RcodeNameError)}, false)
	resp, ok := answerDnsQuery(r, aQueryWire(t, "nope.invalid", 21))
	if !ok {
		t.Fatal("query dropped")
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(resp); err != nil {
		t.Fatal(err)
	}
	if msg.Id != 21 || msg.Rcode != dns.RcodeNameError {
		t.Fatalf("NXDOMAIN must propagate: id=%d rcode=%s", msg.Id, dns.RcodeToString[msg.Rcode])
	}
}

// UDP 全链路：serveDnsUDP 往返
func TestUDPRoundtrip(t *testing.T) {
	r := testResolver([]dnsUpstream{newStub("stub://", net.IPv4(1, 2, 3, 4))}, false)
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go serveDnsUDP(udp.(*net.UDPConn), r)

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if _, err := client.WriteTo(aQueryWire(t, "roundtrip.example", 7), udp.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, dnsMaxUDPSize)
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatalf("udp roundtrip failed: %v", err)
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(buf[:n]); err != nil {
		t.Fatal(err)
	}
	if msg.Id != 7 || len(msg.Answer) != 1 {
		t.Fatalf("unexpected response: id=%d answers=%d", msg.Id, len(msg.Answer))
	}
}

// ── 路由分类器 / NeedsIPResolution ───────────────────────────────────────────

func newTestRouter() *ProxyRouter {
	rt := &ProxyRouter{
		domainIndex:    NewDomainIndex(),
		domainTrie:     NewDomainTrieNode(),
		ipIndex:        NewIPIndex(),
		ruleSets:       make(map[string]*RuleSet),
		ruleSetConfigs: make(map[string]RuleProviderConfig),
		defaultAction:  RuleActionProxy,
	}
	rt.initBuiltinRules()
	return rt
}

func TestClassifyDomain(t *testing.T) {
	rt := newTestRouter()
	rt.AddRule(&Rule{ruleType: RuleTypeDomain, action: RuleActionDirect,
		domains: []DomainPattern{{patternType: DomainPatternSuffix, suffix: "direct.example"}}})
	rt.AddRule(&Rule{ruleType: RuleTypeDomain, action: RuleActionProxy,
		domains: []DomainPattern{{patternType: DomainPatternSuffix, suffix: "proxy.example"}}})
	rt.AddRule(&Rule{ruleType: RuleTypeDomain, action: RuleActionReject,
		domains: []DomainPattern{{patternType: DomainPatternExact, exact: "blocked.example"}}})
	rt.AddRule(&Rule{ruleType: RuleTypeDomain, action: RuleActionDirect,
		domains: []DomainPattern{{patternType: DomainPatternKeyword, keyword: "cn-site"}}})

	cases := []struct {
		domain string
		want   RouteClass
	}{
		{"a.direct.example", RouteClassDirect},
		{"a.proxy.example", RouteClassProxy},
		{"blocked.example", RouteClassProxy}, // REJECT 域名被查询时走隧道，不泄漏给本地 ISP
		{"www.cn-site.com", RouteClassDirect},
		{"unknown.example", RouteClassProxy},
		{"localhost", RouteClassDirect}, // 内置本地域名
	}
	for _, c := range cases {
		if got := rt.ClassifyDomain(c.domain); got != c.want {
			t.Errorf("ClassifyDomain(%q)=%v want %v", c.domain, got, c.want)
		}
	}
}

func TestNeedsIPResolution(t *testing.T) {
	rt := newTestRouter()
	// 仅域名规则：不需要解析
	rt.AddRule(&Rule{ruleType: RuleTypeDomain, action: RuleActionDirect,
		domains: []DomainPattern{{patternType: DomainPatternSuffix, suffix: "a.com"}}})
	rt.recomputeNeedsIPResolution()
	if rt.NeedsIPResolution() {
		t.Fatal("domain-only rules must not require resolution")
	}

	// GEOIP 无 no-resolve：需要
	rt.AddRule(&Rule{ruleType: RuleTypeGeoLocation, action: RuleActionDirect, geoIP: "CN"})
	rt.recomputeNeedsIPResolution()
	if !rt.NeedsIPResolution() {
		t.Fatal("GEOIP without no-resolve must require resolution")
	}
}

func TestNeedsIPResolutionNoResolveSkipped(t *testing.T) {
	rt := newTestRouter()
	rt.AddRule(&Rule{ruleType: RuleTypeNetwork, action: RuleActionDirect, noResolve: true,
		ipNets: []string{"1.2.3.0/24"}})
	rt.recomputeNeedsIPResolution()
	if rt.NeedsIPResolution() {
		t.Fatal("no-resolve IP rules must not require resolution")
	}
}

func TestNeedsIPResolutionRuleSetBehavior(t *testing.T) {
	rt := newTestRouter()
	// domain 型规则集：不需要
	domainSet := &RuleSet{Name: "dom", Behavior: BehaviorDomain, Loaded: true, DomainTrie: NewDomainTrieNode()}
	domainSet.DomainTrie.Insert("rs.example", RuleActionNamed)
	rt.ruleSets["dom"] = domainSet
	rt.AddRule(&Rule{ruleType: RuleTypeRuleSet, action: RuleActionProxy, ruleSetName: "dom"})
	rt.recomputeNeedsIPResolution()
	if rt.NeedsIPResolution() {
		t.Fatal("domain-behavior rule-set must not require resolution")
	}

	// ipcidr 型规则集（含 IP 条目）：需要
	ipSet := &RuleSet{Name: "ips", Behavior: BehaviorIpCidr, Loaded: true, IPs: map[string]bool{}}
	ipSet.IPNets = append(ipSet.IPNets, mustParseIPNet("10.0.0.0/8"))
	rt.ruleSets["ips"] = ipSet
	rt.AddRule(&Rule{ruleType: RuleTypeRuleSet, action: RuleActionProxy, ruleSetName: "ips"})
	rt.recomputeNeedsIPResolution()
	if !rt.NeedsIPResolution() {
		t.Fatal("ipcidr rule-set with entries must require resolution")
	}
}

func TestBuiltinPrivateCIDRDoesNotRequireResolution(t *testing.T) {
	rt := newTestRouter()
	rt.recomputeNeedsIPResolution()
	if rt.NeedsIPResolution() {
		t.Fatal("builtin private CIDRs must not require resolution (RS: no_resolve=true)")
	}
	// 但字面私网 IP 仍应直接命中内置规则
	if got := RouteDomainWith(rt, "192.168.1.5", 443); got != RuleActionDirect {
		t.Fatalf("literal private IP must be Direct, got %s", got)
	}
}

// RouteDomainWith 用指定 router 跑 RouteDomain 逻辑（绕过全局单例）
func RouteDomainWith(router *ProxyRouter, domain string, port uint16) RuleAction {
	if ipLit := net.ParseIP(domain); ipLit != nil {
		return router.Route(domain, ipLit, port, ProtoTCP, false)
	}
	return router.Route(domain, nil, port, ProtoTCP, false)
}

func mustParseIPNet(cidr string) *net.IPNet {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(fmt.Sprintf("test cidr %q: %v", cidr, err))
	}
	return n
}
