package main

// DNS 防泄漏解析器 —— 移植自 ssp-client-rs/src/dns/（管线抄 clash-rs，守卫抄
// shoes，上游分组抄 mihomo 的 nameserver + direct-nameserver）。
//
// 管线（DnsResolver.resolveUncached）：
//   1. IP 字面量 → 直接返回（不走 DNS，守卫不适用于用户显式目标）
//   2. nameserver-policy 分域命中 → 对应上游组（优先级最高，保序）
//   3. 否则按路由分类选组：
//        DIRECT → direct-nameserver（国内 DoH，geo 正确）
//        PROXY  → proxy-nameserver（缺省 = nameserver，默认 tunnel://）
//   4. 组内竞速（最先成功者胜出，10s 总超时）
//   5. 禁区守卫：结果 ∈ 198.18.0.0/15(+自定义) → 报错（防解析环/污染回灌）
//   6. 仅成功结果入缓存（响应真实 TTL，钳制 ≤300s）；NXDOMAIN/NODATA 只透传
//   7. 传输失败且 fallback-system=true（或组内显式 system://）→ 系统 getaddrinfo
//
// 关键：**解析位置跟随连接出口**。直连流量从本地出去，就用本地（国内）DNS
// 解析；代理流量从 Worker 出去，就用隧道 DNS 解析。所有路径绝不静默回退
// 系统 DNS（fail-closed）——隧道断开时宁可失败，不泄漏。
//
// 全程无 UDP 依赖：隧道上游走 TYPE_DNS 帧（Worker DoH），直连上游走
// DoH(TCP)，服务端零改动。

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// ── 路由分类（与 router 解耦的最小接口，RS dns::RouteClassifier 对应物）──────

type RouteClass int

const (
	// RouteClassDirect 规则判定直连（用 direct-nameserver 解析，geo 正确）
	RouteClassDirect RouteClass = iota
	// RouteClassProxy 走代理/未命中（用 nameserver / proxy-nameserver，默认 tunnel://）
	RouteClassProxy
)

// RouteClassifier 由 ProxyRouter 实现：纯域名规则匹配，绝不触发 DNS。
type RouteClassifier interface {
	ClassifyDomain(domain string) RouteClass
}

// ── 解析答案 ─────────────────────────────────────────────────────────────────

// DnsAnswer 解析结果（含 DNS 响应码）。
// 不直接返回 []net.IP 的原因：本地监听器必须把 NXDOMAIN / NODATA 原样回给
// 客户端——映射成 SERVFAIL 会让浏览器/系统反复重试，拖慢首屏。
type DnsAnswer struct {
	IPs   []net.IP
	TTL   time.Duration
	Rcode int // miekg/dns 响应码
}

func positiveAnswer(ips []net.IP, ttl time.Duration) DnsAnswer {
	return DnsAnswer{IPs: ips, TTL: ttl, Rcode: dns.RcodeSuccess}
}

func negativeAnswer(rcode int) DnsAnswer {
	return DnsAnswer{IPs: nil, TTL: 30 * time.Second, Rcode: rcode}
}

// nodataAnswer NoError + 无地址：域名存在，但没有该类型的记录。
func nodataAnswer() DnsAnswer {
	return DnsAnswer{IPs: nil, TTL: 30 * time.Second, Rcode: dns.RcodeSuccess}
}

func (a DnsAnswer) isPositive() bool {
	return a.Rcode == dns.RcodeSuccess && len(a.IPs) > 0
}

// canonicalIP v4-mapped IPv6 规范化为 4 字节（::ffff:1.2.3.4 → 1.2.3.4）
func canonicalIP(ip net.IP) net.IP {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip
}

// ── 禁区守卫（shoes guard.rs 对应物）─────────────────────────────────────────

// dnsGuard 真实 DNS 的任何结果落入禁区段（fake-ip 池预留段 + 显式禁用范围）
// 即报错。这是防"解析环/合成地址回灌"的最终防线。
type dnsGuard struct {
	forbidden []*net.IPNet
}

// defaultForbiddenRanges 198.18.0.0/15 为 fake-ip 池预留段（RFC 2544 benchmark
// 段，真实公网不会使用；上游若返回该段必然是污染或配置错误）。
func defaultForbiddenRanges() []*net.IPNet {
	_, n, err := net.ParseCIDR("198.18.0.0/15")
	if err != nil {
		panic("builtin forbidden cidr must parse")
	}
	return []*net.IPNet{n}
}

func newDnsGuard(custom []string) (*dnsGuard, error) {
	ranges := defaultForbiddenRanges()
	for _, s := range custom {
		_, n, err := net.ParseCIDR(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("forbidden-ranges 无效: %q —— 应为 CIDR，例如 \"198.18.0.0/15\"", s)
		}
		ranges = append(ranges, n)
	}
	return &dnsGuard{forbidden: ranges}, nil
}

// check 批量检查：任一 IP 命中禁区 → 错误。
func (g *dnsGuard) check(ips []net.IP) error {
	for _, ip := range ips {
		for _, n := range g.forbidden {
			if n.Contains(ip) { // Contains 对 v4-mapped v6 自动规范化
				return fmt.Errorf("真实 DNS 返回禁区地址 %s（可能存在解析环/污染，命中 %s）", ip, n)
			}
		}
	}
	return nil
}

// ── nameserver-policy 分域匹配（RS policy.rs 对应物，保序）────────────────────
//
// 模式语义：
//   "+.example.com" —— example.com 及其所有子域（clash 风格）
//   "example.com"   —— 等价于 +.example.com（后缀匹配）
//   "*.example.com" —— 仅子域（不含裸域）
// 匹配不区分大小写，忽略结尾的点。

type dnsPolicy struct {
	entries []policyEntry
}

type policyEntry struct {
	subdomainsOnly bool
	base           string
	index          int // 原始配置下标（与 resolver 的 policyUps 平行对齐）
}

func newDnsPolicy(defs []policyRuleDef) *dnsPolicy {
	p := &dnsPolicy{}
	for idx, def := range defs {
		pt := strings.ToLower(strings.TrimSpace(def.Pattern))
		pt = strings.TrimSuffix(pt, ".")
		if pt == "" {
			continue // 空模式跳过但不打乱下标（RS 同款语义）
		}
		e := policyEntry{index: idx}
		if sub, ok := strings.CutPrefix(pt, "*."); ok {
			e.subdomainsOnly, e.base = true, sub
		} else {
			e.base = strings.TrimPrefix(pt, "+.")
		}
		p.entries = append(p.entries, e)
	}
	return p
}

// matchIndex 命中配置下标；未命中返回 -1（走路由/默认上游组）
func (p *dnsPolicy) matchIndex(domain string) int {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if d == "" {
		return -1
	}
	for _, e := range p.entries {
		if e.subdomainsOnly {
			if strings.HasSuffix(d, "."+e.base) {
				return e.index
			}
		} else if d == e.base || strings.HasSuffix(d, "."+e.base) {
			return e.index
		}
	}
	return -1
}

// ── 缓存 + singleflight（RS cache.rs 对应物）─────────────────────────────────
//
// - 仅缓存成功且非空的结果；NXDOMAIN/NODATA/SERVFAIL 不缓存（但响应码原样
//   返回给调用方，监听器据此回正确的 rcode）
// - TTL 取上游响应里的最小记录 TTL，钳制上限 300s
// - 并发同域查询单飞合并：所有 miss 参与者共享一次上游查询的结果

const (
	dnsCacheTTLCap   = 300 * time.Second
	dnsCacheMaxEntry = 4096
)

type dnsCacheEntry struct {
	ips      []net.IP
	inserted time.Time
	ttl      time.Duration
}

func (e dnsCacheEntry) isExpired() bool { return time.Since(e.inserted) >= e.ttl }

type dnsCache struct {
	mu      sync.Mutex
	entries map[string]dnsCacheEntry
	sf      singleflight.Group
}

func newDnsCache() *dnsCache {
	return &dnsCache{entries: make(map[string]dnsCacheEntry)}
}

func (c *dnsCache) lookup(name string) ([]net.IP, time.Duration, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[name]
	if !ok {
		return nil, 0, false
	}
	if e.isExpired() {
		delete(c.entries, name)
		return nil, 0, false
	}
	remaining := e.ttl - time.Since(e.inserted)
	if remaining < time.Second {
		remaining = time.Second
	}
	return e.ips, remaining, true
}

func (c *dnsCache) store(name string, ips []net.IP, ttl time.Duration) {
	if len(ips) == 0 {
		return // 空结果不缓存
	}
	ttl = min(ttl, dnsCacheTTLCap)
	if ttl < time.Second {
		ttl = time.Second
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= dnsCacheMaxEntry {
		// 先清过期；仍满则不再缓存新条目（等待自然淘汰）
		for k, v := range c.entries {
			if v.isExpired() {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= dnsCacheMaxEntry {
			return
		}
	}
	c.entries[name] = dnsCacheEntry{ips: ips, inserted: time.Now(), ttl: ttl}
}

// resolveVia 缓存优先 + singleflight。成功且非空的答案统一写缓存（TTL 来自
// 上游响应），失败/NXDOMAIN/NODATA 只透传、不缓存。
func (c *dnsCache) resolveVia(name string, task func() (DnsAnswer, error)) (DnsAnswer, error) {
	if ips, ttl, ok := c.lookup(name); ok {
		return positiveAnswer(ips, ttl), nil
	}
	v, err, _ := c.sf.Do(name, func() (interface{}, error) {
		// double-check：排队等待期间可能已被并发 leader 写入
		if ips, ttl, ok := c.lookup(name); ok {
			return positiveAnswer(ips, ttl), nil
		}
		ans, err := task()
		if err == nil && ans.isPositive() {
			c.store(name, ans.IPs, ans.TTL)
		}
		return ans, err
	})
	if err != nil {
		return DnsAnswer{}, err
	}
	return v.(DnsAnswer), nil
}

// ── 上游（RS upstream.rs 对应物）─────────────────────────────────────────────

// dnsUpstream wire 级 exchange 接口
type dnsUpstream interface {
	Exchange(wire []byte) ([]byte, error)
	Describe() string
}

// tunnelUpstream TYPE_DNS 帧 → Worker DoH（防泄漏主路径，全程 WSS 加密）
type tunnelUpstream struct{}

func (tunnelUpstream) Exchange(wire []byte) ([]byte, error) {
	return tunnelDNSExchange(wire)
}

func (tunnelUpstream) Describe() string { return "tunnel://" }

// systemUpstream 系统 getaddrinfo（仅显式配置；不支持 wire 交换，仅 resolve 路径）
type systemUpstream struct{}

func (systemUpstream) Exchange([]byte) ([]byte, error) {
	return nil, errors.New("system:// 不支持 wire 交换")
}

func (systemUpstream) Describe() string { return "system://" }

// dohUpstream DoH GET 直连（RFC 8484；HTTPS over TCP）
type dohUpstream struct {
	url    string
	host   string
	client *http.Client
}

// newDohUpstream 构造 DoH 上游。pinned 非空时钉住引导阶段解析出的地址
// （TLS SNI/证书校验仍用原域名）——端点域名只解析一次且走字面 IP DoH 引导，
// 运行期不再触发系统 DNS。
func newDohUpstream(spec DohSpec, pinned string) (*dohUpstream, error) {
	transport := &http.Transport{
		// 关键：绕过系统代理，防止"代理指向本客户端自身"成环
		Proxy:               nil,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 5 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if pinned != "" {
				if _, p, err := net.SplitHostPort(addr); err == nil {
					addr = net.JoinHostPort(pinned, p)
				}
			}
			d := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
			return d.DialContext(ctx, network, addr)
		},
	}
	return &dohUpstream{
		url:    spec.URL,
		host:   spec.Host,
		client: &http.Client{Transport: transport, Timeout: 10 * time.Second},
	}, nil
}

func (u *dohUpstream) Exchange(wire []byte) ([]byte, error) {
	reqURL := u.url + "?dns=" + base64.RawURLEncoding.EncodeToString(wire)
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("doh 构造请求失败 %s: %w", u.url, err)
	}
	req.Header.Set("Accept", "application/dns-message")
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh request %s: %w", u.url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh %s returned http %d", u.url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("doh %s body: %w", u.url, err)
	}
	if len(body) < 12 {
		return nil, fmt.Errorf("doh %s response too short", u.url)
	}
	return body, nil
}

func (u *dohUpstream) Describe() string { return u.url }

// raceExchange 组内竞速（RS select_ok 风格）：并发发往组内全部上游，最先成功
// 者胜出，总超时默认 10s；全部失败返回最后一个错误。
func raceExchange(ups []dnsUpstream, wire []byte) ([]byte, string, error) {
	return raceExchangeWithTimeout(ups, wire, 10*time.Second)
}

func raceExchangeWithTimeout(ups []dnsUpstream, wire []byte, total time.Duration) ([]byte, string, error) {
	if len(ups) == 0 {
		return nil, "", errors.New("no upstream configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), total)
	defer cancel()

	type okResult struct {
		data []byte
		desc string
	}
	okCh := make(chan okResult, len(ups))
	errCh := make(chan error, len(ups))
	for _, u := range ups {
		go func(u dnsUpstream) {
			data, err := u.Exchange(wire)
			if err != nil {
				errCh <- err
			} else {
				okCh <- okResult{data: data, desc: u.Describe()}
			}
		}(u)
	}

	var lastErr error
	fails := 0
	for {
		select {
		case r := <-okCh:
			return r.data, r.desc, nil
		case e := <-errCh:
			lastErr = e
			fails++
			if fails == len(ups) {
				return nil, "", fmt.Errorf("all upstreams failed: %w", lastErr)
			}
		case <-ctx.Done():
			if lastErr != nil {
				return nil, "", fmt.Errorf("dns exchange timed out (%s); last error: %v", total, lastErr)
			}
			return nil, "", fmt.Errorf("dns exchange timed out (%s)", total)
		}
	}
}

// ── wire 报文构造/解析（RS message.rs 对应物，用 miekg/dns）───────────────────

// buildDnsQuery 构造 A/AAAA wire 查询（RD=1，不压缩——worker 缓存键要求
// qdcount==1 且查询段无压缩指针）
func buildDnsQuery(name string, qtype uint16) ([]byte, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype) // SetQuestion 会重置 Id，因此随后再赋值
	m.Id = dns.Id()
	m.RecursionDesired = true
	wire, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("构造 DNS 查询 %s: %w", name, err)
	}
	return wire, nil
}

// parsedWireAnswer 单条查询的解析结果
type parsedWireAnswer struct {
	ips   []net.IP
	ttl   time.Duration
	rcode int
}

// parseWireAnswer 解析 wire 响应：提取 qtype 类型的 A/AAAA 记录与最小 TTL
func parseWireAnswer(wire []byte, qtype uint16) (parsedWireAnswer, error) {
	resp := new(dns.Msg)
	if err := resp.Unpack(wire); err != nil {
		return parsedWireAnswer{}, fmt.Errorf("解析 DNS 响应: %w", err)
	}
	out := parsedWireAnswer{rcode: resp.Rcode}
	minTTL := time.Duration(0)
	for _, rr := range resp.Answer {
		var ip net.IP
		var ttl uint32
		switch t := rr.(type) {
		case *dns.A:
			if qtype != dns.TypeA {
				continue
			}
			ip, ttl = t.A, t.Hdr.Ttl
		case *dns.AAAA:
			if qtype != dns.TypeAAAA {
				continue
			}
			ip, ttl = t.AAAA, t.Hdr.Ttl
		default:
			continue
		}
		if ip == nil {
			continue
		}
		out.ips = append(out.ips, canonicalIP(ip))
		d := time.Duration(ttl) * time.Second
		if minTTL == 0 || d < minTTL {
			minTTL = d
		}
	}
	out.ttl = minTTL
	return out, nil
}

// ── 引导解析器（RS BootstrapResolver 对应物）─────────────────────────────────

// bootstrapResolver 一次性引导：只用字面 IP DoH 解析带域名的 DoH 端点 /
// worker 域名。无可用引导服务器时才回退系统 getaddrinfo（残余泄漏，一次性，
// WARN 日志标注）。字面 IP 上游结构性防递归——引导查询不可能再触发本解析器。
type bootstrapResolver struct {
	servers  []DohSpec
	mu       sync.Mutex
	resolved map[string][]net.IP
}

func newBootstrapResolver(servers []DohSpec) *bootstrapResolver {
	return &bootstrapResolver{
		servers:  servers,
		resolved: make(map[string][]net.IP),
	}
}

// resolveHostIPs 解析域名 → 全部 A 记录（带缓存）
func (b *bootstrapResolver) resolveHostIPs(host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{canonicalIP(ip)}, nil
	}
	b.mu.Lock()
	if ips, ok := b.resolved[host]; ok {
		b.mu.Unlock()
		return ips, nil
	}
	b.mu.Unlock()

	ips, err := b.resolveUncached(host)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.resolved[host] = ips
	b.mu.Unlock()
	return ips, nil
}

// resolveHost 解析域名 → 首个地址（SocketAddr 场景）
func (b *bootstrapResolver) resolveHost(host string) (string, error) {
	ips, err := b.resolveHostIPs(host)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("bootstrap resolve %s: no address", host)
	}
	return ips[0].String(), nil
}

func (b *bootstrapResolver) resolveUncached(host string) ([]net.IP, error) {
	// 1) 字面 IP DoH（结构性防递归）
	if len(b.servers) > 0 {
		wire, err := buildDnsQuery(host, dns.TypeA)
		if err != nil {
			return nil, err
		}
		for _, spec := range b.servers {
			up, err := newDohUpstream(spec, "")
			if err != nil {
				continue
			}
			resp, err := up.Exchange(wire)
			if err != nil {
				logDebug("[DNS] 引导上游 %s 查询 %s 失败: %v", spec.URL, host, err)
				continue
			}
			parsed, err := parseWireAnswer(resp, dns.TypeA)
			if err != nil || parsed.rcode != dns.RcodeSuccess || len(parsed.ips) == 0 {
				continue
			}
			logInfo("[DNS] 引导解析 %s -> %s (via %s)", host, parsed.ips[0], spec.URL)
			return parsed.ips, nil
		}
	}
	// 2) 系统 getaddrinfo 兜底（一次性引导泄漏，文档化）
	logWarn("[DNS] 无可用引导 DoH，用系统 DNS 解析 %s（一次性残余泄漏）", host)
	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil, fmt.Errorf("bootstrap resolve %s: %w", host, err)
	}
	var ips []net.IP
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil {
			ips = append(ips, canonicalIP(ip))
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("bootstrap resolve %s: no address", host)
	}
	return ips, nil
}

// ── 全局解析器（main 启动期写入，之后只读）────────────────────────────────────

var (
	globalDnsConfig   *DnsConfig
	globalDnsResolver *DnsResolver
	globalBootstrap   *bootstrapResolver
)

func setDnsConfig(cfg *DnsConfig) { globalDnsConfig = cfg }
func getDnsConfig() *DnsConfig    { return globalDnsConfig }

func setDnsResolver(r *DnsResolver) { globalDnsResolver = r }
func getDnsResolver() *DnsResolver  { return globalDnsResolver }

// bootstrapResolveHosts 供配置期解析 worker 域名等多地址场景。
// 无引导服务器时回退系统解析（残余泄漏，一次性，WARN 标注）。
func bootstrapResolveHosts(host string) ([]string, error) {
	if globalBootstrap != nil {
		ips, err := globalBootstrap.resolveHostIPs(host)
		if err == nil && len(ips) > 0 {
			out := make([]string, 0, len(ips))
			for _, ip := range ips {
				out = append(out, ip.String())
			}
			return out, nil
		}
		if err != nil {
			logWarn("[DNS] 引导解析 %s 失败，回退系统 DNS（一次性残余泄漏）: %v", host, err)
		}
	}
	return net.LookupHost(host)
}

// newPinnedDoHClient 构造 DoH/HTTP 客户端：禁用系统代理（防"代理指向自身"
// 成环）；域名端点经引导解析后钉住 IP（TLS SNI 仍用原域名）。
func newPinnedDoHClient(rawURL string) (*http.Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	pinned := ""
	if host := u.Hostname(); host != "" && net.ParseIP(host) == nil && globalBootstrap != nil {
		if ip, err := globalBootstrap.resolveHost(host); err == nil {
			pinned = ip
			logDebug("[DNS] 端点 %s 钉住到 %s（经引导 DoH）", host, ip)
		} else {
			logWarn("[DNS] 端点 %s 引导解析失败，回退系统解析（一次性残余泄漏）: %v", host, err)
		}
	}
	transport := &http.Transport{
		Proxy:               nil,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if pinned != "" {
				if _, p, err := net.SplitHostPort(addr); err == nil {
					addr = net.JoinHostPort(pinned, p)
				}
			}
			d := &net.Dialer{Timeout: dialTimeout, KeepAlive: keepAliveInterval}
			return d.DialContext(ctx, network, addr)
		},
	}
	return &http.Client{Timeout: connTimeout, Transport: transport}, nil
}

// ── 主解析器（RS resolver.rs 对应物）─────────────────────────────────────────

type DnsResolver struct {
	ipv6           bool
	fallbackSystem bool
	policy         *dnsPolicy
	// 与 policy 条目平行的上游组（下标 = 配置顺序）
	policyUps  [][]dnsUpstream
	defaultUps []dnsUpstream
	directUps  []dnsUpstream // nil → defaultUps
	proxyUps   []dnsUpstream // nil → defaultUps
	classifier RouteClassifier
	cache      *dnsCache
	guard      *dnsGuard
}

// newDnsResolver 从配置构建（内部完成 DoH 域名端点的一次性引导解析）。
// 默认组构建失败 → 整体失败（启动退出）；direct/proxy/policy 组构建失败 →
// 打 WARN 回退默认组（RS 同款降级语义）。
func newDnsResolver(cfg *DnsConfig, classifier RouteClassifier) (*DnsResolver, error) {
	bootstrap := newBootstrapResolver(cfg.DefaultNameserver)

	defaultUps, err := buildUpstreamEntries(cfg.Nameserver, bootstrap)
	if err != nil {
		return nil, err
	}

	directUps := buildOptionalGroup(cfg.DirectNameserver, bootstrap, "direct-nameserver")
	proxyUps := buildOptionalGroup(cfg.ProxyNameserver, bootstrap, "proxy-nameserver")

	policyUps := make([][]dnsUpstream, 0, len(cfg.NameserverPolicy))
	for _, def := range cfg.NameserverPolicy {
		group, err := buildUpstreamEntries(def.Upstreams, bootstrap)
		if err != nil {
			logWarn("nameserver-policy %q 不可用，该组回退 nameserver: %v", def.Pattern, err)
			group = nil
		}
		policyUps = append(policyUps, group)
	}

	guard, err := newDnsGuard(cfg.ForbiddenRanges)
	if err != nil {
		return nil, err
	}

	r := &DnsResolver{
		ipv6:           cfg.IPv6,
		fallbackSystem: cfg.FallbackSystem,
		policy:         newDnsPolicy(cfg.NameserverPolicy),
		policyUps:      policyUps,
		defaultUps:     defaultUps,
		cache:          newDnsCache(),
		guard:          guard,
		classifier:     classifier,
	}
	if directUps != nil {
		r.directUps = directUps
	}
	if proxyUps != nil {
		r.proxyUps = proxyUps
	}
	logInfo("[DNS] resolver ready — nameserver=%v, direct=%v, proxy=%v, policy=%d, ipv6=%v, fallback-system=%v",
		describeUpstreams(r.defaultUps),
		describeUpstreams(r.directUps),
		describeUpstreams(r.proxyUps),
		len(r.policyUps),
		r.ipv6,
		r.fallbackSystem)
	return r, nil
}

func describeUpstreams(ups []dnsUpstream) []string {
	if ups == nil {
		return nil
	}
	out := make([]string, 0, len(ups))
	for _, u := range ups {
		out = append(out, u.Describe())
	}
	return out
}

// buildUpstreamEntries 把上游规格实例化为运行时条目（DoH 域名端点在此完成
// 一次性引导）。单个上游引导失败跳过（打 WARN），全部失败才报错。
func buildUpstreamEntries(specs []upstreamSpec, bootstrap *bootstrapResolver) ([]dnsUpstream, error) {
	var entries []dnsUpstream
	for _, spec := range specs {
		switch spec.kind {
		case upstreamTunnel:
			entries = append(entries, tunnelUpstream{})
		case upstreamDoh:
			var up *dohUpstream
			var err error
			if spec.doh.IP != nil {
				// 字面 IP：直接用，无引导依赖
				up, err = newDohUpstream(spec.doh, "")
			} else if addr, berr := bootstrap.resolveHost(spec.doh.Host); berr == nil {
				// 域名端点：经引导解析出 IP，钉住（TLS SNI 仍用原域名）
				up, err = newDohUpstream(spec.doh, addr)
			} else {
				logWarn("跳过 DoH 上游 %s: 引导解析失败: %v", spec.doh.URL, berr)
				continue
			}
			if err != nil {
				logWarn("跳过 DoH 上游 %s: %v", spec.doh.URL, err)
				continue
			}
			entries = append(entries, up)
		case upstreamSystem:
			entries = append(entries, systemUpstream{})
		}
	}
	if len(entries) == 0 {
		return nil, errors.New("no usable DNS upstream configured (所有上游都不可用，请检查 dns.yaml)")
	}
	return entries, nil
}

func buildOptionalGroup(specs []upstreamSpec, bootstrap *bootstrapResolver, field string) []dnsUpstream {
	if len(specs) == 0 {
		return nil
	}
	group, err := buildUpstreamEntries(specs, bootstrap)
	if err != nil {
		logWarn("%s 不可用，回退 nameserver: %v", field, err)
		return nil
	}
	return group
}

// pickEntries 选择上游组：显式 policy > 路由分类 > 默认组
func (r *DnsResolver) pickEntries(name string) []dnsUpstream {
	if r.policy != nil {
		if idx := r.policy.matchIndex(name); idx >= 0 && idx < len(r.policyUps) {
			if group := r.policyUps[idx]; len(group) > 0 {
				return group
			}
		}
	}
	if r.classifier != nil {
		switch r.classifier.ClassifyDomain(name) {
		case RouteClassDirect:
			if len(r.directUps) > 0 {
				return r.directUps
			}
		default: // RouteClassProxy
			if len(r.proxyUps) > 0 {
				return r.proxyUps
			}
		}
	}
	return r.defaultUps
}

// Resolve 解析域名 → IP 列表。失败返回 error（绝不静默回退系统 DNS）。
func (r *DnsResolver) Resolve(name string) ([]net.IP, error) {
	ans, err := r.ResolveAnswer(name)
	if err != nil {
		return nil, err
	}
	if ans.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("upstream returned %s for %q", dns.RcodeToString[ans.Rcode], name)
	}
	if len(ans.IPs) == 0 {
		return nil, fmt.Errorf("no address for %q", name)
	}
	return ans.IPs, nil
}

// ResolveAnswer 主入口：缓存 + singleflight + 解析管线，保留响应码。
func (r *DnsResolver) ResolveAnswer(name string) (DnsAnswer, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return DnsAnswer{}, errors.New("empty domain name")
	}
	// IP 字面量：用户显式目标，直接返回（这是 IP 匹配路由的既有行为）
	if ip := net.ParseIP(name); ip != nil {
		return positiveAnswer([]net.IP{canonicalIP(ip)}, time.Hour), nil
	}
	key := strings.ToLower(name)
	return r.cache.resolveVia(key, func() (DnsAnswer, error) {
		return r.resolveUncached(key)
	})
}

// resolveUncached 解析管线（见文件头注释）
func (r *DnsResolver) resolveUncached(name string) (DnsAnswer, error) {
	entries := r.pickEntries(name)
	wires := make([]dnsUpstream, 0, len(entries))
	mayFallback := r.fallbackSystem
	for _, e := range entries {
		if _, isSys := e.(systemUpstream); isSys {
			mayFallback = true // 组内显式 system:// 允许回退（用户显式选择）
			continue
		}
		wires = append(wires, e)
	}

	if len(wires) == 0 {
		// 上游组全是 system://（显式配置）
		ips, ttl, err := r.systemLookup(name)
		if err != nil {
			return DnsAnswer{}, err
		}
		return positiveAnswer(ips, ttl), nil
	}

	qtypes := []uint16{dns.TypeA}
	if r.ipv6 {
		qtypes = append(qtypes, dns.TypeAAAA)
	}

	var outcomes []parsedWireAnswer
	var lastErr error
	for _, qt := range qtypes {
		parsed, err := r.queryFamily(wires, name, qt)
		if err != nil {
			lastErr = err
			continue
		}
		outcomes = append(outcomes, parsed)
	}

	if len(outcomes) == 0 {
		err := lastErr
		if err == nil {
			err = errors.New("no DNS upstream answered")
		}
		if mayFallback {
			logWarn("[DNS] 上游失败 (%v)，回退系统解析 —— 会泄漏（fallback-system/system:// 已启用）", err)
			ips, ttl, serr := r.systemLookup(name)
			if serr != nil {
				return DnsAnswer{}, serr
			}
			return positiveAnswer(ips, ttl), nil
		}
		// fail-closed：不回退系统 DNS，绝不泄漏
		return DnsAnswer{}, err
	}

	first := outcomes[0]
	if first.rcode != dns.RcodeSuccess {
		// NXDOMAIN 等是"有效答案"，不是传输失败：不回退、不缓存
		return negativeAnswer(first.rcode), nil
	}

	var ips []net.IP
	minTTL := time.Duration(0)
	for _, parsed := range outcomes {
		if parsed.rcode != dns.RcodeSuccess {
			continue
		}
		ips = append(ips, parsed.ips...)
		if parsed.ttl > 0 && (minTTL == 0 || parsed.ttl < minTTL) {
			minTTL = parsed.ttl
		}
	}
	if len(ips) == 0 {
		// NODATA：域名存在但没有该类型记录（例如只有 AAAA/HTTPS）
		return nodataAnswer(), nil
	}

	if err := r.guard.check(ips); err != nil {
		return DnsAnswer{}, err
	}
	if minTTL == 0 {
		minTTL = 60 * time.Second
	}
	return positiveAnswer(ips, minTTL), nil
}

func (r *DnsResolver) queryFamily(wires []dnsUpstream, name string, qtype uint16) (parsedWireAnswer, error) {
	wire, err := buildDnsQuery(name, qtype)
	if err != nil {
		return parsedWireAnswer{}, err
	}
	resp, winner, err := raceExchange(wires, wire)
	if err != nil {
		return parsedWireAnswer{}, err
	}
	parsed, err := parseWireAnswer(resp, qtype)
	if err != nil {
		return parsedWireAnswer{}, err
	}
	logDebug("[DNS] %s %s -> %d ips (ttl %s, rcode %s) via %s",
		dns.TypeToString[qtype], name, len(parsed.ips), parsed.ttl, dns.RcodeToString[parsed.rcode], winner)
	return parsed, nil
}

func (r *DnsResolver) systemLookup(name string) ([]net.IP, time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, name)
	if err != nil {
		return nil, 0, fmt.Errorf("system resolution for %q: %w", name, err)
	}
	seen := map[string]bool{}
	var ips []net.IP
	for _, a := range addrs {
		ip := canonicalIP(a.IP)
		if !seen[ip.String()] {
			seen[ip.String()] = true
			ips = append(ips, ip)
		}
	}
	sort.Slice(ips, func(i, j int) bool { return bytesLess(ips[i], ips[j]) })
	if err := r.guard.check(ips); err != nil {
		return nil, 0, err
	}
	if len(ips) == 0 {
		return nil, 0, fmt.Errorf("system resolution returned no address for %q", name)
	}
	return ips, 60 * time.Second, nil
}

func bytesLess(a, b net.IP) bool {
	ab, bb := a.To16(), b.To16()
	for i := range ab {
		if ab[i] != bb[i] {
			return ab[i] < bb[i]
		}
	}
	return false
}

// ExchangeRaw 非 A/AAAA 记录透传（监听器用）：HTTPS/TXT/MX 等原样转发。
// 分域/路由策略同样生效（按 question 段域名选择上游组）。
func (r *DnsResolver) ExchangeRaw(query []byte) ([]byte, error) {
	var entries []dnsUpstream
	msg := new(dns.Msg)
	if err := msg.Unpack(query); err == nil && len(msg.Question) > 0 {
		entries = r.pickEntries(strings.ToLower(msg.Question[0].Name))
	} else {
		entries = r.defaultUps
	}
	var wires []dnsUpstream
	for _, e := range entries {
		if _, isSys := e.(systemUpstream); isSys {
			continue
		}
		wires = append(wires, e)
	}
	if len(wires) == 0 {
		return nil, errors.New("raw DNS exchange requires tunnel:// or https:// upstream (system:// cannot forward this record type)")
	}
	resp, winner, err := raceExchange(wires, query)
	if err != nil {
		return nil, err
	}
	logDebug("[DNS] raw exchange via %s", winner)
	return resp, nil
}

// ── 本地 DNS 监听器（RS listener.rs 对应物，UDP+TCP）──────────────────────────
//
// 客户端/系统把 DNS 指向这个端口，所有查询都进入 DnsResolver 管线（默认
// tunnel:// → Worker DoH），整机应用也享受防泄漏路径。
// 语义：
//   - A/AAAA → resolver（AAAA 在 ipv6: false 时回空 NOERROR，clash-rs 做法）
//   - NXDOMAIN / NODATA 原样回传，只有传输失败才 SERVFAIL
//   - 其它类型（HTTPS/TXT/MX/SVCB…）→ 原始 wire 透传给上游（默认隧道）
//   - 上游失败 → SERVFAIL（绝不回退系统 DNS）
//   - 响应 TTL 钳制 60s

const (
	dnsMaxUDPSize     = 4096
	dnsMaxTCPSize     = 65535
	dnsListenerTTLCap = 60 * time.Second
	dnsTCPIdleTimeout = 30 * time.Second
)

// startDnsListener 绑定 UDP + TCP 并常驻。两个协议都绑定成功才返回（配置期报错）。
func startDnsListener(addr string, resolver *DnsResolver) error {
	udpConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("绑定 DNS UDP 监听器 %s: %w（端口被占用？）", addr, err)
	}
	udp := udpConn.(*net.UDPConn)
	actual := udp.LocalAddr().String()
	tcpListener, err := net.Listen("tcp", actual)
	if err != nil {
		udp.Close()
		return fmt.Errorf("绑定 DNS TCP 监听器 %s: %w", actual, err)
	}
	logInfo("🔎 Local DNS listener on %s (udp+tcp)", actual)
	go serveDnsUDP(udp, resolver)
	go serveDnsTCP(tcpListener, resolver)
	return nil
}

func serveDnsUDP(udp *net.UDPConn, resolver *DnsResolver) {
	buf := make([]byte, dnsMaxUDPSize)
	for {
		n, peer, err := udp.ReadFrom(buf)
		if err != nil {
			logDebug("[DNS] UDP read error: %v", err)
			return
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		go func(peer net.Addr, query []byte) {
			resp, ok := answerDnsQuery(resolver, query)
			if !ok {
				logDebug("[DNS] UDP query from %s ignored (malformed)", peer)
				return
			}
			if _, err := udp.WriteTo(resp, peer); err != nil {
				logDebug("[DNS] UDP send to %s failed: %v", peer, err)
			}
		}(peer, query)
	}
}

func serveDnsTCP(listener net.Listener, resolver *DnsResolver) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			logDebug("[DNS] TCP accept error: %v", err)
			return
		}
		go serveDnsTCPConn(conn, resolver)
	}
}

func serveDnsTCPConn(conn net.Conn, resolver *DnsResolver) {
	defer conn.Close()
	var lenBuf [2]byte
	for {
		conn.SetReadDeadline(time.Now().Add(dnsTCPIdleTimeout))
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return // 空闲超时/对端关闭
		}
		length := int(lenBuf[0])<<8 | int(lenBuf[1])
		if length == 0 || length > dnsMaxTCPSize {
			return
		}
		query := make([]byte, length)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		resp, ok := answerDnsQuery(resolver, query)
		if !ok {
			continue
		}
		if len(resp) > dnsMaxTCPSize {
			continue
		}
		conn.SetWriteDeadline(time.Now().Add(dnsTCPIdleTimeout))
		out := make([]byte, 2+len(resp))
		out[0] = byte(len(resp) >> 8)
		out[1] = byte(len(resp))
		copy(out[2:], resp)
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

// answerDnsQuery 处理一条 wire 查询。返回 false 表示报文无法解析/不是查询（丢弃）。
func answerDnsQuery(resolver *DnsResolver, wire []byte) ([]byte, bool) {
	query := new(dns.Msg)
	if err := query.Unpack(wire); err != nil {
		return nil, false
	}
	if query.Response {
		return nil, false
	}
	if query.Opcode != dns.OpcodeQuery {
		return buildDnsErrorResponse(query, dns.RcodeNotImplemented), true
	}
	if len(query.Question) == 0 {
		return nil, false
	}
	q := query.Question[0]
	name := q.Name

	switch q.Qtype {
	case dns.TypeA, dns.TypeAAAA:
		if q.Qtype == dns.TypeAAAA && !resolver.ipv6 {
			// ipv6: false —— 回空 NOERROR（clash-rs server 做法），避免客户端
			// 因 SERVFAIL 重试或回退系统 DNS
			return buildDnsEmptyResponse(query), true
		}
		ans, err := resolver.ResolveAnswer(name)
		if err != nil {
			logDebug("[DNS] %s query for %s failed: %v", dns.TypeToString[q.Qtype], name, err)
			return buildDnsErrorResponse(query, dns.RcodeServerFailure), true
		}
		if ans.Rcode != dns.RcodeSuccess {
			// NXDOMAIN / SERVFAIL 原样回传：映射成 SERVFAIL 会让浏览器/系统
			// 反复重试，页面里每个统计域名都拖慢首屏
			logDebug("[DNS] %s query for %s -> %s", dns.TypeToString[q.Qtype], name, dns.RcodeToString[ans.Rcode])
			return buildDnsErrorResponse(query, ans.Rcode), true
		}
		var ips []net.IP
		for _, ip := range ans.IPs {
			if q.Qtype == dns.TypeA && ip.To4() != nil {
				ips = append(ips, ip.To4())
			} else if q.Qtype == dns.TypeAAAA && ip.To4() == nil {
				ips = append(ips, ip)
			}
		}
		if len(ips) == 0 {
			// NODATA：域名存在但没有该类型记录 → 空 NOERROR
			return buildDnsEmptyResponse(query), true
		}
		return buildDnsResponse(query, ips, min(ans.TTL, dnsListenerTTLCap)), true
	default:
		respWire, err := resolver.ExchangeRaw(wire)
		if err != nil {
			logWarn("[DNS] %s query for %s failed: %v", dns.TypeToString[q.Qtype], name, err)
			return buildDnsErrorResponse(query, dns.RcodeServerFailure), true
		}
		// Worker 缓存命中路径可能改写事务 ID，统一改回客户端的事务 ID（幂等）
		return rewriteDnsID(respWire, query.Id), true
	}
}

func buildDnsResponse(query *dns.Msg, ips []net.IP, ttl time.Duration) []byte {
	resp := query.SetReply(query)
	resp.RecursionAvailable = true
	ttlSec := uint32(ttl / time.Second)
	if ttlSec == 0 {
		ttlSec = 1
	}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttlSec},
				A:   ip4,
			})
		} else {
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttlSec},
				AAAA: ip,
			})
		}
	}
	wire, err := resp.Pack()
	if err != nil {
		return buildDnsErrorResponse(query, dns.RcodeServerFailure)
	}
	return wire
}

func buildDnsEmptyResponse(query *dns.Msg) []byte {
	resp := query.SetReply(query)
	resp.RecursionAvailable = true
	wire, err := resp.Pack()
	if err != nil {
		return buildDnsErrorResponse(query, dns.RcodeServerFailure)
	}
	return wire
}

func buildDnsErrorResponse(query *dns.Msg, rcode int) []byte {
	resp := query.SetRcode(query, rcode)
	resp.RecursionAvailable = true
	wire, err := resp.Pack()
	if err != nil {
		return nil
	}
	return wire
}

// rewriteDnsID 把响应前 2 字节改写为客户端事务 ID（幂等；len<2 时原样返回）
func rewriteDnsID(resp []byte, id uint16) []byte {
	if len(resp) >= 2 {
		resp[0] = byte(id >> 8)
		resp[1] = byte(id)
	}
	return resp
}
