package main

// DNS 防泄漏配置（dns.yaml）—— 字段语义与 ssp-client-rs 完全兼容（clash 风格
// kebab-case），两版客户端可共用同一份配置文件。移植自 ssp-client-rs/src/dns/config.rs。
//
// 字段语义：
//   - listen                  本地 DNS 监听地址（UDP+TCP）。缺省不开监听器。
//   - ipv6                    是否解析/返回 AAAA。false 时 AAAA 查询回空 NOERROR。
//   - default-nameserver      引导 DNS：必须是字面 IP 的 DoH（配置期校验），
//                             用于解析 nameserver 里带域名的 DoH 端点。
//   - proxy-server-nameserver 解析 worker 域名用的 DoH（必须字面 IP）。
//                             缺省用 default-nameserver；避免系统 DNS 看到 worker 域名。
//   - nameserver              默认/未知上游：tunnel:// / https://.../dns-query / system://
//   - direct-nameserver       路由判定 DIRECT 的域名所用上游（国内 DoH，推荐）
//   - proxy-nameserver        路由判定 PROXY 的域名所用上游（缺省同 nameserver）
//   - nameserver-policy       可选分域覆盖（优先级最高，保序）：
//                             "+.example.com"（域及子域）/ "*.example.com"（仅子域）
//   - fallback-system         上游全败时是否回退系统 DNS。默认 false（防泄漏 fail-closed）。
//   - forbidden-ranges        额外禁区段（自动含 198.18.0.0/15 fake-ip 预留段）
//
// 注意：tunnel:// 需要 worker 端部署 v1.5 的 TYPE_DNS 帧处理
// （ssp-server/worker/worker.js）。未部署时客户端连续超时 2 次会快速失败并提示。
//
// 未知字段 / 非法值在启动期报错退出（shoes validate 风格），绝不静默降级。

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

// 内置引导 DNS（字面 IP DoH，官方支持 IP 端点 + IP SAN）
const defaultBootstrapDoH = "https://223.5.5.5/dns-query"

// ── 上游规格 ─────────────────────────────────────────────────────────────────

// DohSpec DoH 上游描述
type DohSpec struct {
	URL  string // 完整 URL（如 https://223.5.5.5/dns-query）
	Host string // host 部分（可能是域名或字面 IP）
	Port string // URL 未写端口时默认 443
	IP   net.IP // host 为字面 IP 时存放（无需引导解析，结构性防递归）
}

type upstreamKind int

const (
	upstreamTunnel upstreamKind = iota // TYPE_DNS 帧 → Worker DoH（防泄漏主路径）
	upstreamDoh                        // DoH 直连（HTTPS over TCP，无 UDP）
	upstreamSystem                     // 系统 getaddrinfo（仅显式配置；不防泄漏）
)

type upstreamSpec struct {
	kind upstreamKind
	doh  DohSpec // kind == upstreamDoh 时有效
}

func (u upstreamSpec) describe() string {
	switch u.kind {
	case upstreamTunnel:
		return "tunnel://"
	case upstreamSystem:
		return "system://"
	default:
		return u.doh.URL
	}
}

func describeUpstreamSpecs(ups []upstreamSpec) []string {
	out := make([]string, 0, len(ups))
	for _, u := range ups {
		out = append(out, u.describe())
	}
	return out
}

// ── 配置结构 ─────────────────────────────────────────────────────────────────

// policyRuleDef 分域策略条目：Pattern → Upstreams（校验后）；
// UpstreamsRaw 保存 YAML 原始字符串（校验阶段解析为 Upstreams）
type policyRuleDef struct {
	Pattern      string
	Upstreams    []upstreamSpec
	UpstreamsRaw []string
}

// DnsConfig 校验后的 DNS 配置
type DnsConfig struct {
	Listen                string          // 空 = 不开本地监听器
	IPv6                  bool            //
	DefaultNameserver     []DohSpec       // 引导 DNS（字面 IP DoH）
	ProxyServerNameserver []DohSpec       // 空 → 用 DefaultNameserver
	Nameserver            []upstreamSpec  // 默认/未知上游（空缺省 = [tunnel://]）
	DirectNameserver      []upstreamSpec  // 空 → 回退 Nameserver
	ProxyNameserver       []upstreamSpec  // 空 → 回退 Nameserver
	NameserverPolicy      []policyRuleDef // 保序分域覆盖
	FallbackSystem        bool            // 默认 false = fail-closed
	ForbiddenRanges       []string        // 原始 CIDR（守卫再解析；已配置期校验）
}

// effectiveBootstrapServers 解析 worker 域名用的引导服务器（缺省用 default-nameserver）
func (c *DnsConfig) effectiveBootstrapServers() []DohSpec {
	if len(c.ProxyServerNameserver) > 0 {
		return c.ProxyServerNameserver
	}
	return c.DefaultNameserver
}

// ── 加载入口 ─────────────────────────────────────────────────────────────────

// loadDnsConfig 从文件加载并校验。文件不存在/为空 → 内置默认（全隧道，默认安全）。
func loadDnsConfig(path string) (*DnsConfig, error) {
	if path == "" {
		return secureDnsDefault(), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return secureDnsDefault(), nil
		}
		return nil, fmt.Errorf("读取 DNS 配置失败 %s: %w", path, err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return secureDnsDefault(), nil
	}
	cfg, err := decodeDnsConfig(data)
	if err != nil {
		return nil, fmt.Errorf("DNS 配置错误 %s:\n  %w\n  字段名参考 dns.yaml 示例", path, err)
	}
	return cfg, nil
}

// secureDnsDefault 内置默认：内部解析全走隧道，不开监听器。
func secureDnsDefault() *DnsConfig {
	doh := mustParseDohSpec(defaultBootstrapDoH)
	return &DnsConfig{
		Listen:            "",
		IPv6:              false,
		DefaultNameserver: []DohSpec{doh},
		Nameserver:        []upstreamSpec{{kind: upstreamTunnel}},
		ForbiddenRanges:   []string{},
	}
}

// ── YAML 解码（保序 + 未知字段报错）──────────────────────────────────────────

// decodeDnsConfig 手工走 yaml.Node：nameserver-policy 需要保序（map 会打乱），
// 且未知字段要给出人话报错（等价 RS serde 的 deny_unknown_fields）。
func decodeDnsConfig(data []byte) (*DnsConfig, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("YAML 解析失败: %w", err)
	}
	if len(root.Content) == 0 {
		return secureDnsDefault(), nil
	}
	m := root.Content[0]
	if m.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("顶层必须是键值映射")
	}

	var (
		listen         string
		ipv6           bool
		bootstrap      []string
		proxyServer    []string
		nameserver     []string
		direct         []string
		proxy          []string
		fallbackSystem bool
		forbidden      []string
		policyDefs     []policyRuleDef
	)
	seen := map[string]bool{}

	for i := 0; i+1 < len(m.Content); i += 2 {
		keyNode, valNode := m.Content[i], m.Content[i+1]
		key := strings.ToLower(strings.TrimSpace(keyNode.Value))
		if seen[key] {
			return nil, fmt.Errorf("重复字段: %q", keyNode.Value)
		}
		seen[key] = true

		switch key {
		case "listen":
			if valNode.Tag == "!!null" {
				continue
			}
			var s string
			if err := valNode.Decode(&s); err != nil {
				return nil, fmt.Errorf("listen 应为字符串")
			}
			listen = s
		case "ipv6", "fallback-system":
			var b bool
			if err := valNode.Decode(&b); err != nil {
				return nil, fmt.Errorf("%s 应为布尔值", key)
			}
			if key == "ipv6" {
				ipv6 = b
			} else {
				fallbackSystem = b
			}
		case "default-nameserver", "proxy-server-nameserver", "nameserver",
			"direct-nameserver", "proxy-nameserver", "forbidden-ranges":
			list, err := decodeStringList(valNode)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			switch key {
			case "default-nameserver":
				bootstrap = list
			case "proxy-server-nameserver":
				proxyServer = list
			case "nameserver":
				nameserver = list
			case "direct-nameserver":
				direct = list
			case "proxy-nameserver":
				proxy = list
			case "forbidden-ranges":
				forbidden = list
			}
		case "nameserver-policy":
			defs, err := decodePolicy(valNode)
			if err != nil {
				return nil, fmt.Errorf("nameserver-policy: %w", err)
			}
			policyDefs = defs
		default:
			return nil, fmt.Errorf("未知字段: %q —— 若该字段来自更新后的配置，说明当前运行的是旧版客户端", keyNode.Value)
		}
	}

	return buildDnsConfig(buildDnsConfigInput{
		listen:         listen,
		ipv6:           ipv6,
		bootstrap:      bootstrap,
		proxyServer:    proxyServer,
		nameserver:     nameserver,
		direct:         direct,
		proxy:          proxy,
		policyDefs:     policyDefs,
		fallbackSystem: fallbackSystem,
		forbidden:      forbidden,
	})
}

func decodeStringList(node *yaml.Node) ([]string, error) {
	var list []string
	if err := node.Decode(&list); err != nil {
		return nil, fmt.Errorf("应为字符串列表")
	}
	return list, nil
}

// decodePolicy nameserver-policy：域名模式 → 上游（单值或列表），保持配置顺序
func decodePolicy(node *yaml.Node) ([]policyRuleDef, error) {
	if node.Tag == "!!null" {
		return nil, nil
	}
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("应为映射（\"域名模式\": 上游或上游列表）")
	}
	var defs []policyRuleDef
	for i := 0; i+1 < len(node.Content); i += 2 {
		pattern := strings.TrimSpace(node.Content[i].Value)
		valNode := node.Content[i+1]
		var upstreams []string
		switch valNode.Kind {
		case yaml.ScalarNode:
			upstreams = []string{valNode.Value}
		case yaml.SequenceNode:
			var list []string
			if err := valNode.Decode(&list); err != nil {
				return nil, fmt.Errorf("%q 的上游应为字符串或字符串列表", pattern)
			}
			upstreams = list
		default:
			return nil, fmt.Errorf("%q 的上游应为字符串或字符串列表", pattern)
		}
		defs = append(defs, policyRuleDef{Pattern: pattern, UpstreamsRaw: upstreams})
	}
	return defs, nil
}

// ── 校验（RS try_from_def 对应物；所有错误在此给人话提示）────────────────────

type buildDnsConfigInput struct {
	listen         string
	ipv6           bool
	bootstrap      []string
	proxyServer    []string
	nameserver     []string
	direct         []string
	proxy          []string
	policyDefs     []policyRuleDef
	fallbackSystem bool
	forbidden      []string
}

func buildDnsConfig(in buildDnsConfigInput) (*DnsConfig, error) {
	cfg := &DnsConfig{IPv6: in.ipv6, FallbackSystem: in.fallbackSystem}

	// listen：RS 要求 SocketAddr（IP 字面量），域名会导致绑定歧义
	if in.listen != "" {
		host, port, err := net.SplitHostPort(in.listen)
		if err != nil || net.ParseIP(host) == nil {
			return nil, fmt.Errorf("listen 无效: %q —— 应为 \"IP:端口\" 形式，例如 \"127.0.0.1:1053\"", in.listen)
		}
		if _, err := strconv.Atoi(port); err != nil {
			return nil, fmt.Errorf("listen 无效: %q —— 端口非法", in.listen)
		}
		cfg.Listen = in.listen
	}

	// 引导 DNS：必须字面 IP DoH（shoes LiteralResolver 思想：结构性禁止递归）
	if len(in.bootstrap) == 0 {
		doh := mustParseDohSpec(defaultBootstrapDoH)
		cfg.DefaultNameserver = []DohSpec{doh}
	} else {
		list, err := parseBootstrapList(in.bootstrap, "default-nameserver")
		if err != nil {
			return nil, err
		}
		cfg.DefaultNameserver = list
	}

	// 隧道端点引导：缺省用 default-nameserver
	if len(in.proxyServer) > 0 {
		list, err := parseBootstrapList(in.proxyServer, "proxy-server-nameserver")
		if err != nil {
			return nil, err
		}
		cfg.ProxyServerNameserver = list
	}

	// 主上游
	if len(in.nameserver) == 0 {
		cfg.Nameserver = []upstreamSpec{{kind: upstreamTunnel}}
	} else {
		list, err := parseUpstreamList(in.nameserver, "nameserver")
		if err != nil {
			return nil, err
		}
		cfg.Nameserver = list
	}

	if len(in.direct) > 0 {
		list, err := parseUpstreamList(in.direct, "direct-nameserver")
		if err != nil {
			return nil, err
		}
		cfg.DirectNameserver = list
	}
	if len(in.proxy) > 0 {
		list, err := parseUpstreamList(in.proxy, "proxy-nameserver")
		if err != nil {
			return nil, err
		}
		cfg.ProxyNameserver = list
	}

	// 分域策略（保序 + 校验）
	for _, def := range in.policyDefs {
		if err := validatePolicyPattern(def.Pattern); err != nil {
			return nil, err
		}
		specs, err := parseUpstreamList(def.UpstreamsRaw, "nameserver-policy \""+def.Pattern+"\"")
		if err != nil {
			return nil, err
		}
		if len(specs) == 0 {
			return nil, fmt.Errorf("nameserver-policy %q 的上游列表为空", def.Pattern)
		}
		cfg.NameserverPolicy = append(cfg.NameserverPolicy, policyRuleDef{Pattern: def.Pattern, Upstreams: specs})
	}

	// 禁区段：配置期校验 CIDR 合法性（守卫构造时复用）
	for _, s := range in.forbidden {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(s)); err != nil {
			return nil, fmt.Errorf("forbidden-ranges 无效: %q —— 应为 CIDR，例如 \"198.18.0.0/15\"", s)
		}
		cfg.ForbiddenRanges = append(cfg.ForbiddenRanges, strings.TrimSpace(s))
	}

	return cfg, nil
}

// ── 上游 URL 解析 ────────────────────────────────────────────────────────────

// parseUpstreamSpec 解析单条上游。仅支持 tunnel://、https://（DoH）、system://。
// 不支持 udp:// —— 隧道上游走 TYPE_DNS 帧，直连上游走 DoH(TCP)，全程无 UDP 依赖。
//
// mihomo 兼容：`https://1.1.1.1/dns-query#节点选择` 里的 `#...` 片段表示
// "经代理出口查询"。本客户端唯一的代理出口就是隧道，等价映射为 tunnel://。
func parseUpstreamSpec(s string) (upstreamSpec, error) {
	s = strings.TrimSpace(s)
	if strings.EqualFold(s, "tunnel://") {
		return upstreamSpec{kind: upstreamTunnel}, nil
	}
	if strings.EqualFold(s, "system://") {
		return upstreamSpec{kind: upstreamSystem}, nil
	}
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "https://") {
		// `#proxy` / `#节点选择`：经代理出口 → 本客户端等价于隧道
		if idx := strings.IndexByte(s, '#'); idx >= 0 && strings.TrimSpace(s[idx+1:]) != "" {
			return upstreamSpec{kind: upstreamTunnel}, nil
		}
		doh, err := parseDohSpec(s)
		if err != nil {
			return upstreamSpec{}, err
		}
		return upstreamSpec{kind: upstreamDoh, doh: doh}, nil
	}
	return upstreamSpec{}, fmt.Errorf(
		"不支持的 DNS 上游 %q —— 仅支持:\n"+
			"  tunnel://              (TYPE_DNS 帧 → Worker DoH, 推荐)\n"+
			"  https://<IP>/dns-query (DoH 直连, TCP)\n"+
			"  system://              (系统解析, 不防泄漏)", s)
}

func parseDohSpec(s string) (DohSpec, error) {
	rest := s[len("https://"):]
	hostPart := rest
	if idx := strings.IndexByte(rest, '/'); idx >= 0 {
		hostPart = rest[:idx]
	}
	var host, port string
	if strings.HasPrefix(hostPart, "[") {
		end := strings.IndexByte(hostPart, ']')
		if end < 0 {
			return DohSpec{}, fmt.Errorf("DoH 地址无效: %q —— IPv6 缺少 ']'", s)
		}
		host = hostPart[1:end]
		port = "443"
		if after := hostPart[end+1:]; strings.HasPrefix(after, ":") {
			if _, err := strconv.Atoi(after[1:]); err == nil {
				port = after[1:]
			}
		}
	} else if h, p, err := net.SplitHostPort(hostPart); err == nil {
		host, port = h, p
	} else {
		host, port = hostPart, "443"
	}
	if host == "" {
		return DohSpec{}, fmt.Errorf("DoH 地址无效: %q —— 缺少主机部分", s)
	}
	return DohSpec{URL: s, Host: host, Port: port, IP: net.ParseIP(host)}, nil
}

func mustParseDohSpec(s string) DohSpec {
	doh, err := parseDohSpec(s)
	if err != nil {
		panic("builtin bootstrap DoH must parse: " + err.Error())
	}
	return doh
}

func parseUpstreamList(list []string, field string) ([]upstreamSpec, error) {
	out := make([]upstreamSpec, 0, len(list))
	for _, s := range list {
		spec, err := parseUpstreamSpec(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
		out = append(out, spec)
	}
	return out, nil
}

// parseBootstrapList 引导类上游：只接受字面 IP 的 DoH（拒绝域名/tunnel://system://）
func parseBootstrapList(list []string, field string) ([]DohSpec, error) {
	var out []DohSpec
	for _, s := range list {
		spec, err := parseUpstreamSpec(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
		switch {
		case spec.kind == upstreamDoh && spec.doh.IP != nil:
			out = append(out, spec.doh)
		case spec.kind == upstreamDoh:
			return nil, fmt.Errorf(
				"%s %q 含域名 —— 引导 DNS 必须是字面 IP 的 DoH 地址\n"+
					"  （例如 \"https://223.5.5.5/dns-query\"），否则引导本身会递归依赖本机解析器",
				field, s)
		case spec.kind == upstreamTunnel:
			return nil, fmt.Errorf("%s 不支持 tunnel:// —— 引导发生在隧道建立之前", field)
		default:
			return nil, fmt.Errorf("%s 不支持 system:// —— 请使用字面 IP 的 DoH", field)
		}
	}
	return out, nil
}

// validatePolicyPattern 校验分域模式（RS validate_pattern 对应物）
func validatePolicyPattern(pattern string) error {
	p := strings.ToLower(strings.TrimSpace(pattern))
	if strings.HasPrefix(p, "geosite:") || strings.HasPrefix(p, "rule-set:") || strings.HasPrefix(p, "geoip:") {
		return fmt.Errorf(
			"nameserver-policy 不支持 %q（本客户端不内置 geosite 数据库）\n"+
				"  等价做法：用 direct-nameserver 指定国内 DoH —— 路由判定为 DIRECT 的域名\n"+
				"  会自动用那组上游解析，不必逐条枚举域名", pattern)
	}
	p = strings.TrimPrefix(p, "+.")
	if p == "" {
		return fmt.Errorf("nameserver-policy 模式无效: %q", pattern)
	}
	if strings.Contains(p, "*") && !strings.HasPrefix(p, "*.") {
		return fmt.Errorf("nameserver-policy 模式无效: %q —— 仅支持 \"*.<域名>\" 形式", pattern)
	}
	return nil
}
