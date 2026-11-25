package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/geoip2-golang"
	yaml "gopkg.in/yaml.v3"
)

// =============================================================================
// 路由相关类型定义
// =============================================================================

type RuleAction int

const (
	RuleActionProxy RuleAction = iota
	RuleActionDirect
	RuleActionReject
	RuleActionNamed
)

func (a RuleAction) String() string {
	switch a {
	case RuleActionProxy:
		return "PROXY"
	case RuleActionDirect:
		return "DIRECT"
	case RuleActionReject:
		return "REJECT"
	case RuleActionNamed:
		return "NAMED"
	default:
		return "UNKNOWN"
	}
}

type NetworkProtocol int

const (
	ProtoTCP NetworkProtocol = iota
	ProtoUDP
	ProtoAny
)

type DomainPatternType int

const (
	DomainPatternExact DomainPatternType = iota
	DomainPatternSuffix
	DomainPatternKeyword
	DomainPatternRegex
	DomainPatternWildcard
)

type RuleType int

const (
	RuleTypeDomain RuleType = iota
	RuleTypeNetwork
	RuleTypeIP
	RuleTypeSrcNetwork
	RuleTypeGeoLocation
	RuleTypeDestPort
	RuleTypeSrcPort
	RuleTypeProcessName
	RuleTypeProcessPath
	RuleTypeNetwork2
	RuleTypeAnd
	RuleTypeOr
	RuleTypeNot
	RuleTypeRuleSet
	RuleTypeFinal
)

// =============================================================================
// 路由相关结构体定义
// =============================================================================

type Rule struct {
	ruleType    RuleType
	action      RuleAction
	named       string
	pattern     string
	domains     []DomainPattern
	ipNets      []string
	network     NetworkProtocol
	portMatcher *PortMatcher
	geoIP       string
	processName string
	processPath string
	ruleSetName string
	noResolve   bool
	subRules    []*Rule

	compiledRegexp *regexp.Regexp

	ipNet *net.IPNet
}

type ProxyRouter struct {
	domainIndex    *DomainIndex
	domainTrie     *DomainTrieNode
	ipIndex        *IPIndex
	portRules      []*Rule
	networkRules   []*Rule
	slowRules      []*Rule
	ruleSets       map[string]*RuleSet
	ruleSetConfigs map[string]RuleProviderConfig
	defaultAction  RuleAction
	geoipReader    *geoip2.Reader
	cancel         context.CancelFunc

	// 是否存在"无 no-resolve 的 IP 谓词规则"。false 时调用方不应触发任何
	// DNS 查询（防泄漏第一性原理，见 NeedsIPResolution）。
	needsIPResolution atomic.Bool
}

type DomainPattern struct {
	patternType DomainPatternType
	exact       string
	suffix      string
	keyword     string
	regex       *regexp.Regexp
	action      RuleAction
}

type PortMatcher struct {
	mode   int
	single uint16
	lo, hi uint16
	list   []uint16
}

// =============================================================================
// 域名树管理
// =============================================================================

type DomainTrieNode struct {
	children map[string]*DomainTrieNode
	action   RuleAction
	isEnd    bool
}

func NewDomainTrieNode() *DomainTrieNode {
	return &DomainTrieNode{children: make(map[string]*DomainTrieNode)}
}

func (n *DomainTrieNode) Insert(domain string, action RuleAction) {
	domain = strings.ToLower(domain)

	domain = strings.TrimPrefix(domain, ".")
	parts := strings.Split(domain, ".")
	curr := n

	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if part == "" {
			continue
		}
		if _, ok := curr.children[part]; !ok {
			curr.children[part] = NewDomainTrieNode()
		}
		curr = curr.children[part]
	}
	curr.action = action
	curr.isEnd = true
}

func (n *DomainTrieNode) Search(domain string) (RuleAction, bool) {
	if domain == "" {
		return 0, false
	}

	curr := n
	var lastAction RuleAction
	found := false

	end := len(domain)
	for i := len(domain) - 1; i >= -1; i-- {

		if i == -1 || domain[i] == '.' {
			part := domain[i+1 : end]
			if part != "" {
				next, ok := curr.children[part]
				if !ok {

					return lastAction, found
				}
				curr = next

				if curr.isEnd {
					lastAction = curr.action
					found = true

				}
			}
			end = i
		}
	}

	return lastAction, found
}

// =============================================================================
// 端口匹配器
// =============================================================================

func (pm *PortMatcher) Matches(port uint16) bool {
	if pm == nil {
		return true
	}
	switch pm.mode {
	case 0:
		return port == pm.single
	case 1:
		return port >= pm.lo && port <= pm.hi
	case 2:
		for _, p := range pm.list {
			if p == port {
				return true
			}
		}
	}
	return false
}

func ParsePortMatcher(s string) *PortMatcher {
	pm := &PortMatcher{}
	s = strings.TrimSpace(s)

	if strings.Contains(s, "-") {
		parts := strings.Split(s, "-")
		if len(parts) == 2 {
			fmt.Sscanf(strings.TrimSpace(parts[0]), "%d", &pm.lo)
			fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &pm.hi)
			pm.mode = 1
		}
	} else if strings.Contains(s, ",") {
		ports := strings.Split(s, ",")
		for _, p := range ports {
			var port uint16
			fmt.Sscanf(strings.TrimSpace(p), "%d", &port)
			pm.list = append(pm.list, port)
		}
		pm.mode = 2
	} else {
		fmt.Sscanf(s, "%d", &pm.single)
		pm.mode = 0
	}
	return pm
}

// =============================================================================
// 规则解析
// =============================================================================

func parseLogicalRule(line string) *Rule {
	commaIdx := strings.Index(line, ",")
	if commaIdx < 0 {
		return nil
	}
	typeStr := strings.ToUpper(strings.TrimSpace(line[:commaIdx]))
	rest := strings.TrimSpace(line[commaIdx+1:])

	if !strings.HasPrefix(rest, "(") {
		return nil
	}

	depth := 0
	endIdx := -1
	for i := 0; i < len(rest); i++ {
		if rest[i] == '(' {
			depth++
		} else if rest[i] == ')' {
			depth--
			if depth == 0 {
				endIdx = i
				break
			}
		}
	}
	if endIdx < 0 {
		return nil
	}

	subRulesStr := rest[1:endIdx]
	actionPart := strings.TrimSpace(rest[endIdx+1:])
	if strings.HasPrefix(actionPart, ",") {
		actionPart = strings.TrimSpace(actionPart[1:])
	}

	var action RuleAction
	var named string
	switch strings.ToUpper(actionPart) {
	case "PROXY", "":
		action = RuleActionProxy
	case "DIRECT":
		action = RuleActionDirect
	case "REJECT", "BLOCK", "DENY":
		action = RuleActionReject
	default:
		action = RuleActionNamed
		named = strings.ToUpper(actionPart)
	}

	rule := &Rule{action: action, named: named}
	switch typeStr {
	case "AND":
		rule.ruleType = RuleTypeAnd
	case "OR":
		rule.ruleType = RuleTypeOr
	case "NOT":
		rule.ruleType = RuleTypeNot
	default:
		return nil
	}

	rule.subRules = parseSubRules(subRulesStr)
	return rule
}

func parseSubRules(pattern string) []*Rule {
	var subRules []*Rule
	depth := 0
	start := -1

	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '(':
			if depth == 0 {
				start = i + 1
			}
			depth++
		case ')':
			depth--
			if depth == 0 && start >= 0 {
				inner := strings.TrimSpace(pattern[start:i])
				rule := ParseRule(inner)
				if rule != nil {
					subRules = append(subRules, rule)
				}
				start = -1
			}
		}
	}
	return subRules
}

func ParseRule(line string) *Rule {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return nil
	}

	line = strings.TrimPrefix(line, "- ")

	upperLine := strings.ToUpper(line)
	if strings.HasPrefix(upperLine, "AND,") ||
		strings.HasPrefix(upperLine, "OR,") ||
		strings.HasPrefix(upperLine, "NOT,") {
		return parseLogicalRule(line)
	}

	parts := strings.SplitN(line, ",", 4)
	if len(parts) < 2 {
		return nil
	}

	typeStr := strings.ToUpper(strings.TrimSpace(parts[0]))
	pattern := strings.TrimSpace(parts[1])

	var action RuleAction = RuleActionProxy
	var named string
	if len(parts) >= 3 {
		actionStr := strings.ToUpper(strings.TrimSpace(parts[2]))
		switch actionStr {
		case "PROXY":
			action = RuleActionProxy
		case "DIRECT":
			action = RuleActionDirect
		case "REJECT", "BLOCK", "DENY":
			action = RuleActionReject
		default:
			action = RuleActionNamed
			named = actionStr
		}
	}

	var noResolve bool
	if len(parts) >= 4 {
		extra := strings.ToUpper(strings.TrimSpace(parts[3]))
		noResolve = strings.Contains(extra, "NO-RESOLVE")
	}

	rule := &Rule{action: action, named: named, pattern: pattern, noResolve: noResolve}

	switch typeStr {
	case "DOMAIN":
		rule.ruleType = RuleTypeDomain
		rule.domains = append(rule.domains, DomainPattern{
			patternType: DomainPatternExact,
			exact:       strings.ToLower(pattern),
		})

	case "DOMAIN-SUFFIX":
		rule.ruleType = RuleTypeDomain
		rule.domains = append(rule.domains, DomainPattern{patternType: DomainPatternSuffix, suffix: strings.ToLower(pattern)})

	case "DOMAIN-KEYWORD":
		rule.ruleType = RuleTypeDomain
		rule.domains = append(rule.domains, DomainPattern{patternType: DomainPatternKeyword, keyword: strings.ToLower(pattern)})

	case "DOMAIN-REGEX":
		rule.ruleType = RuleTypeDomain

		re, err := regexp.Compile(pattern)
		if err != nil {
			logWarn("[规则] 正则表达式语法错误: %s, %v", pattern, err)
			return nil
		}
		rule.compiledRegexp = re
		rule.domains = append(rule.domains, DomainPattern{
			patternType: DomainPatternRegex,
			regex:       re,
		})

	case "IP-CIDR", "IP-CIDR6":
		rule.ruleType = RuleTypeNetwork
		rule.ipNets = append(rule.ipNets, pattern)

	case "SRC-IP-CIDR":
		rule.ruleType = RuleTypeSrcNetwork
		rule.ipNets = append(rule.ipNets, pattern)

	case "GEOIP":
		rule.ruleType = RuleTypeGeoLocation
		rule.geoIP = strings.ToUpper(pattern)

	case "DEST-PORT", "DST-PORT":
		rule.ruleType = RuleTypeDestPort
		rule.portMatcher = ParsePortMatcher(pattern)

	case "SRC-PORT":
		rule.ruleType = RuleTypeSrcPort
		rule.portMatcher = ParsePortMatcher(pattern)

	case "PROCESS-NAME":
		rule.ruleType = RuleTypeProcessName
		rule.processName = pattern

	case "PROCESS-PATH":
		rule.ruleType = RuleTypeProcessPath
		rule.processPath = pattern

	case "NETWORK":
		rule.ruleType = RuleTypeNetwork2
		switch strings.ToUpper(pattern) {
		case "TCP":
			rule.network = ProtoTCP
		case "UDP":
			rule.network = ProtoUDP
		default:
			rule.network = ProtoAny
		}

	case "RULE-SET":
		rule.ruleType = RuleTypeRuleSet
		rule.ruleSetName = pattern

	case "AND", "OR", "NOT":
		return parseLogicalRule(line)

	case "FINAL", "MATCH":
		rule.ruleType = RuleTypeFinal

	default:
		return nil
	}

	return rule
}

// =============================================================================
// 正则表达式缓存
// =============================================================================

var (
	regexCacheValue atomic.Value
	regexCache      = sync.Map{}
	regexMu         sync.Mutex
	regexCounter    uint64
)

func init() {
	regexCacheValue.Store(&sync.Map{})
}

func regexMatches(pattern, domain string) bool {
	cache := regexCacheValue.Load().(*sync.Map)

	if re, ok := cache.Load(pattern); ok {
		return re.(*regexp.Regexp).MatchString(domain)
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}

	count := atomic.AddUint64(&regexCounter, 1)
	if count > 1000 {
		cleanRegexCache()
	}

	regexCacheValue.Load().(*sync.Map).Store(pattern, re)

	return re.MatchString(domain)
}

func cleanRegexCache() {

	if regexMu.TryLock() {
		defer regexMu.Unlock()

		if atomic.LoadUint64(&regexCounter) <= 1000 {
			return
		}

		regexCacheValue.Store(&sync.Map{})
		atomic.StoreUint64(&regexCounter, 0)
		logDebug("[系统] 正则缓存已达到上限，已执行清空重置")
	}
}

// =============================================================================
// 工具函数
// =============================================================================

func atomicGetAndInc(counter *uint64) uint64 {
	return atomic.AddUint64(counter, 1) - 1
}

func domainHasSuffix(domain, suffix string) bool {

	if domain == "" || suffix == "" {
		return false
	}

	if suffix[0] == '.' {
		suffix = suffix[1:]
	}

	if domain == suffix {
		return true
	}

	dotSuffix := "." + suffix
	if len(domain) > len(dotSuffix) && strings.HasSuffix(domain, dotSuffix) {
		return true
	}

	return false
}

func getTLD(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	return domain
}

func isPrivateIP(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 != nil {
		v := binary.BigEndian.Uint32(ip4)
		return (v >= 0x7F000000 && v <= 0x7FFFFFFF) ||
			(v >= 0x0A000000 && v <= 0x0AFFFFFF) ||
			(v >= 0xAC100000 && v <= 0xAC1FFFFF) ||
			(v >= 0xC0A80000 && v <= 0xC0A8FFFF) ||
			(v >= 0x64400000 && v <= 0x64FFFFFF) ||
			(v >= 0xA9FE0000 && v <= 0xA9FEFFFF)
	}
	bytes := ip.To16()
	if bytes != nil {
		return (bytes[0] == 0xFE && (bytes[1]&0xC0) == 0x80) ||
			bytes[0] == 0xFC || bytes[0] == 0xFD
	}
	return false
}

func relPath(absPath string) string {
	rel, err := filepath.Rel(exeDir, absPath)
	if err != nil {
		return absPath
	}
	return rel
}

// =============================================================================
// 域名索引管理
// =============================================================================

type DomainIndex struct {
	exact         map[string]RuleAction
	suffixBuckets map[string][]string
	suffixActions map[string]RuleAction
	slowPatterns  []DomainPattern
}

func NewDomainIndex() *DomainIndex {
	return &DomainIndex{
		exact:         make(map[string]RuleAction),
		suffixBuckets: make(map[string][]string),
		suffixActions: make(map[string]RuleAction),
		slowPatterns:  make([]DomainPattern, 0),
	}
}

func (idx *DomainIndex) Insert(dp DomainPattern, action RuleAction) {
	switch dp.patternType {
	case DomainPatternExact:
		idx.exact[dp.exact] = action
	case DomainPatternSuffix:
		tld := getTLD(dp.suffix)
		idx.suffixBuckets[tld] = append(idx.suffixBuckets[tld], dp.suffix)
		idx.suffixActions[dp.suffix] = action
	case DomainPatternKeyword, DomainPatternRegex, DomainPatternWildcard:
		dp.action = action
		idx.slowPatterns = append(idx.slowPatterns, dp)
	}
}

func (idx *DomainIndex) Build() {
	for _, bucket := range idx.suffixBuckets {
		sort.Slice(bucket, func(i, j int) bool {
			return len(bucket[i]) > len(bucket[j])
		})
	}
}

func (idx *DomainIndex) Lookup(domain string) (RuleAction, bool) {
	domain = strings.ToLower(domain)

	if action, ok := idx.exact[domain]; ok {
		return action, true
	}

	tld := getTLD(domain)
	if bucket, ok := idx.suffixBuckets[tld]; ok {
		for _, suffix := range bucket {
			if domainHasSuffix(domain, suffix) {
				if action, ok := idx.suffixActions[suffix]; ok {
					return action, true
				}
			}
		}
	}

	for _, dp := range idx.slowPatterns {
		switch dp.patternType {
		case DomainPatternWildcard:
			return dp.action, true
		case DomainPatternKeyword:
			if strings.Contains(domain, dp.keyword) {
				return dp.action, true
			}
		case DomainPatternRegex:
			if dp.regex != nil && dp.regex.MatchString(domain) {
				return dp.action, true
			}
		}
	}

	return RuleActionProxy, false
}

// =============================================================================
// IP 索引管理
// =============================================================================

type IPRangeEntry struct {
	start  uint32
	end    uint32
	action RuleAction
}

type IPRangeV6Entry struct {
	start  [16]byte
	end    [16]byte
	action RuleAction
}

type IPIndex struct {
	cidrs   []IPRangeEntry
	cidrsV6 []IPRangeV6Entry
	exactV4 map[uint32]RuleAction
	exactV6 map[[16]byte]RuleAction
}

func NewIPIndex() *IPIndex {
	return &IPIndex{
		exactV4: make(map[uint32]RuleAction),
		exactV6: make(map[[16]byte]RuleAction),
	}
}

func (idx *IPIndex) Insert(cidrStr string, action RuleAction) bool {
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return false
	}

	if ip4 := ipNet.IP.To4(); ip4 != nil {
		if ones, _ := ipNet.Mask.Size(); ones == 32 {
			idx.exactV4[binary.BigEndian.Uint32(ip4)] = action
			return true
		}
		start := binary.BigEndian.Uint32(ip4)
		mask := binary.BigEndian.Uint32(ipNet.Mask)
		end := start | ^mask
		idx.cidrs = append(idx.cidrs, IPRangeEntry{start, end, action})
	} else {

		ip16 := ipNet.IP.To16()
		if ip16 != nil {
			if ones, _ := ipNet.Mask.Size(); ones == 128 {

				var key [16]byte
				copy(key[:], ip16)
				idx.exactV6[key] = action
				return true
			}

			var start, end [16]byte
			copy(start[:], ip16)
			for i := 0; i < 16; i++ {
				end[i] = start[i] | ^ipNet.Mask[i]
			}
			idx.cidrsV6 = append(idx.cidrsV6, IPRangeV6Entry{start, end, action})
		}
	}
	return true
}

func (idx *IPIndex) Build() {
	sort.Slice(idx.cidrs, func(i, j int) bool {
		return idx.cidrs[i].start < idx.cidrs[j].start
	})
}

func (idx *IPIndex) Contains(ip net.IP, cidrStr string) bool {
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return false
	}
	return ipNet.Contains(ip)
}

func (idx *IPIndex) Lookup(ip net.IP) (RuleAction, bool) {

	if ip4 := ip.To4(); ip4 != nil {
		v := binary.BigEndian.Uint32(ip4)
		if action, ok := idx.exactV4[v]; ok {
			return action, true
		}

		i := sort.Search(len(idx.cidrs), func(j int) bool {
			return idx.cidrs[j].start > v
		})
		if i > 0 && idx.cidrs[i-1].end >= v {
			return idx.cidrs[i-1].action, true
		}
	} else {

		ip16 := ip.To16()
		if ip16 == nil {
			return RuleActionProxy, false
		}

		var key [16]byte
		copy(key[:], ip16)
		if action, ok := idx.exactV6[key]; ok {
			return action, true
		}

		for _, entry := range idx.cidrsV6 {

			if bytes.Compare(ip16, entry.start[:]) >= 0 && bytes.Compare(ip16, entry.end[:]) <= 0 {
				return entry.action, true
			}
		}
	}
	return RuleActionProxy, false
}

// =============================================================================
// 规则集管理
// =============================================================================

type ProviderSourceType int

const (
	ProviderHTTP ProviderSourceType = iota
	ProviderFile
	ProviderInline
)

type ProviderBehavior int

const (
	BehaviorDomain ProviderBehavior = iota
	BehaviorIpCidr
	BehaviorClassical
)

func behaviorName(b ProviderBehavior) string {
	switch b {
	case BehaviorDomain:
		return "domain"
	case BehaviorIpCidr:
		return "ipcidr"
	case BehaviorClassical:
		return "classical"
	}
	return "unknown"
}

type RuleProvider struct {
	sourceType ProviderSourceType
	behavior   ProviderBehavior
	url        string
	path       string
	interval   time.Duration
}

type RuleSetSource int

const (
	RuleSetFile RuleSetSource = iota
	RuleSetURL
	RuleSetInline
)

type RuleSet struct {
	Name     string
	Behavior ProviderBehavior

	DomainTrie *DomainTrieNode
	IPs        map[string]bool
	IPNets     []*net.IPNet
	Source     RuleSetSource
	SourcePath string
	Loaded     bool
	LoadedAt   time.Time
	// .mrs 精确域名（mihomo 语义：仅匹配该域本身，不含子域）。
	// 后缀类条目（源文件的 "+.x" / ".x"）进 DomainTrie。
	exactDomains map[string]bool
}

type ProxyConfig struct {
	RuleProviders map[string]RuleProviderConfig `yaml:"rule-providers"`
	Rules         []string                      `yaml:"rules"`
}

type RuleProviderConfig struct {
	Type     string `yaml:"type"`
	Behavior string `yaml:"behavior"`
	URL      string `yaml:"url,omitempty"`
	Path     string `yaml:"path,omitempty"`
	Interval int    `yaml:"interval,omitempty"`
	// 可选：显式声明规则集格式（mrs/yaml/text）。缺省按文件头自动识别
	// （zstd 帧头 → .mrs，明文 SRS → sing-box，其余按 UTF-8 文本）
	Format string `yaml:"format,omitempty"`
}

func (rs *RuleSet) MatchesDomain(domain string) bool {
	if !rs.Loaded {
		return false
	}
	domain = strings.ToLower(domain)
	if rs.exactDomains != nil && rs.exactDomains[domain] {
		return true
	}
	if rs.DomainTrie == nil {
		return false
	}

	_, found := rs.DomainTrie.Search(domain)
	return found
}

// parseRuleSetBytes 按文件内容加载 provider（文本 / Clash YAML / .mrs）。
// 格式判定顺序：显式 format 配置 → 文件头嗅探。
func parseRuleSetBytes(name string, raw []byte, behavior ProviderBehavior) (*RuleSet, error) {
	switch detectRuleFormat(raw) {
	case mrsDetectedMrs:
		return parseRuleSetMrs(name, raw, behavior)
	case mrsDetectedSrs:
		return nil, fmt.Errorf("不支持 sing-box .srs 规则集；请用 `sing-box rule-set decompile` 转成文本，或用 mihomo `convert-ruleset` 转成 .mrs")
	default:
		rs := &RuleSet{
			Name:         name,
			Behavior:     behavior,
			DomainTrie:   NewDomainTrieNode(),
			IPs:          make(map[string]bool),
			exactDomains: make(map[string]bool),
			Loaded:       true,
			LoadedAt:     time.Now(),
		}
		processRuleSetLines(string(raw), rs)
		logInfo("[路由] 规则集 %s 已加载（文本，%d 条 IP、域名 trie %d 节点）", name, len(rs.IPNets), len(rs.DomainTrie.children))
		return rs, nil
	}
}

// parseRuleSetMrs 解码 .mrs 并按 behavior 填充规则集（RS parse_mrs 对应物）
func parseRuleSetMrs(name string, raw []byte, behavior ProviderBehavior) (*RuleSet, error) {
	decoded, err := mrsParse(raw)
	if err != nil {
		return nil, fmt.Errorf(".mrs 解析失败: %w", err)
	}

	rs := &RuleSet{
		Name:         name,
		Behavior:     behavior,
		DomainTrie:   NewDomainTrieNode(),
		IPs:          make(map[string]bool),
		exactDomains: make(map[string]bool),
		Loaded:       true,
		LoadedAt:     time.Now(),
	}

	switch {
	case decoded.kind == mrsKindDomain && behavior == BehaviorDomain:
		if decoded.declaredCount != len(decoded.domains) {
			// 不是错误，但说明文件里精确/后缀被合并过，值得留一条线索
			logDebug("[路由] .mrs %s: 头部声明 %d 条，trie 展开 %d 条", name, decoded.declaredCount, len(decoded.domains))
		}
		for _, entry := range decoded.domains {
			lower := strings.ToLower(entry.name)
			if entry.subOnly {
				// ".x"（仅子域）：后缀匹配
				rs.DomainTrie.Insert(lower, RuleActionNamed)
			} else {
				// 精确域名：仅匹配域本身（mihomo 语义）
				rs.exactDomains[lower] = true
			}
		}
	case decoded.kind == mrsKindIP && behavior == BehaviorIpCidr:
		for _, ipNet := range decoded.nets {
			rs.IPs[ipNet.String()] = true
			rs.IPNets = append(rs.IPNets, ipNet)
		}
	default:
		return nil, fmt.Errorf("behavior 不匹配：配置为 %s，但 .mrs 文件是 %s", behaviorName(behavior), decoded.kind)
	}

	logInfo("[路由] 规则集 %s 已加载 %d 条 (%s, .mrs)", name, decoded.declaredCount, behaviorName(behavior))
	return rs, nil
}

func (rs *RuleSet) MatchesIP(ip net.IP) bool {
	if !rs.Loaded {
		return false
	}

	if rs.IPs[ip.String()] {
		return true
	}

	for _, ipNet := range rs.IPNets {
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}

func parseRuleSetEntry(raw string) string {
	line := strings.TrimSpace(raw)
	if line == "payload:" || (!strings.HasPrefix(line, "-") && strings.HasSuffix(line, ":")) {
		return ""
	}
	if strings.HasPrefix(line, "- ") {
		line = strings.TrimSpace(line[2:])
	}
	line = strings.Trim(line, `'"`)
	return strings.TrimSpace(line)
}

// =============================================================================
// 代理路由器
// =============================================================================

func NewProxyRouter() *ProxyRouter {
	ctx, cancel := context.WithCancel(context.Background())
	router := &ProxyRouter{
		domainIndex:    NewDomainIndex(),
		domainTrie:     NewDomainTrieNode(),
		ipIndex:        NewIPIndex(),
		portRules:      make([]*Rule, 0),
		networkRules:   make([]*Rule, 0),
		slowRules:      make([]*Rule, 0),
		ruleSets:       make(map[string]*RuleSet),
		ruleSetConfigs: make(map[string]RuleProviderConfig),
		defaultAction:  RuleActionProxy,
		cancel:         cancel,
	}
	router.initBuiltinRules()
	router.loadGeoIPDatabase()

	go router.startRuleSetAutoUpdate(ctx)
	return router
}

func (r *ProxyRouter) initBuiltinRules() {
	privateCIDRs := []string{
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
	}

	for _, cidr := range privateCIDRs {
		r.ipIndex.Insert(cidr, RuleActionDirect)
	}

	localDomains := []string{
		"localhost",
		"local",
		"localdomain",
		"internal",
		"lan",
		"home.arpa",
	}

	for _, domain := range localDomains {
		r.domainIndex.exact[domain] = RuleActionDirect
	}

	r.ipIndex.Build()
}

func (r *ProxyRouter) AddRule(rule *Rule) {
	if rule == nil {
		return
	}

	if rule.ruleType == RuleTypeDomain {
		for _, dp := range rule.domains {
			switch dp.patternType {
			case DomainPatternExact:
				r.domainIndex.exact[dp.exact] = rule.action
			case DomainPatternSuffix:

				r.domainTrie.Insert(dp.suffix, rule.action)
			case DomainPatternRegex:

				if dp.regex != nil {
					rule.compiledRegexp = dp.regex
				}
				r.slowRules = append(r.slowRules, rule)
			default:
				r.slowRules = append(r.slowRules, rule)
			}
		}
		return
	}

	switch rule.ruleType {
	case RuleTypeNetwork, RuleTypeSrcNetwork, RuleTypeIP:
		for _, cidr := range rule.ipNets {
			r.ipIndex.Insert(cidr, rule.action)
		}
		r.networkRules = append(r.networkRules, rule)
	case RuleTypeDestPort, RuleTypeSrcPort:
		r.portRules = append(r.portRules, rule)
	default:

		r.slowRules = append(r.slowRules, rule)
	}
}

func (r *ProxyRouter) SetDefaultAction(action RuleAction) {
	r.defaultAction = action
}

func (r *ProxyRouter) Route(domain string, ip net.IP, dstPort uint16, network NetworkProtocol, resolved bool) RuleAction {

	domain = strings.ToLower(domain)

	if domain != "" {
		if action, ok := r.domainIndex.exact[domain]; ok {
			return action
		}

		if action, ok := r.domainTrie.Search(domain); ok {
			return action
		}
	}

	if ip != nil {
		if action, ok := r.ipIndex.Lookup(ip); ok {
			return action
		}
	}

	for _, rule := range r.portRules {
		if rule.portMatcher != nil && rule.portMatcher.Matches(dstPort) {
			return rule.action
		}
	}

	for _, rule := range r.slowRules {
		action := r.evalRule(rule, domain, ip, dstPort, network, resolved)
		if action >= 0 {
			return action
		}
	}

	return r.defaultAction
}

func (r *ProxyRouter) evalRule(rule *Rule, domain string, ip net.IP, dstPort uint16, network NetworkProtocol, resolved bool) RuleAction {
	if rule == nil {
		return -1
	}

	switch rule.ruleType {
	case RuleTypeDomain:

		for _, dp := range rule.domains {
			switch dp.patternType {
			case DomainPatternKeyword:
				if strings.Contains(domain, dp.keyword) {
					return rule.action
				}
			case DomainPatternRegex:

				if rule.compiledRegexp != nil && rule.compiledRegexp.MatchString(domain) {
					return rule.action
				}
			}
		}

	case RuleTypeNetwork:

		if ip != nil {
			for _, cidrStr := range rule.ipNets {
				if r.ipIndex.Contains(ip, cidrStr) {
					return rule.action
				}
			}
		}

	case RuleTypeIP:
		if ip != nil {
			parsedIP := net.ParseIP(rule.pattern)
			if parsedIP != nil && parsedIP.Equal(ip) {
				return rule.action
			}
		}

	case RuleTypeSrcNetwork:

	case RuleTypeGeoLocation:
		if rule.noResolve && (ip == nil || resolved) {
			return -1
		}
		if ip != nil {
			if rule.geoIP == "LAN" && isPrivateIP(ip) {
				return RuleActionDirect
			}
			// 国家判定仅依赖 mmdb（GeoLite2-Country 等）；无数据库时 GEOIP
			// 规则跳过（启动日志会提示），不再回退 chn_ip.txt 国 IP 列表
			if country := r.getIPCountry(ip); country != "" {
				if strings.EqualFold(rule.geoIP, country) {
					return rule.action
				}
			}
		}

	case RuleTypeDestPort:
		if rule.portMatcher != nil && rule.portMatcher.Matches(dstPort) {
			return rule.action
		}

	case RuleTypeSrcPort:

	case RuleTypeProcessName:

	case RuleTypeProcessPath:

	case RuleTypeNetwork2:
		if rule.network == ProtoAny || rule.network == network {
			return rule.action
		}

	case RuleTypeRuleSet:
		if rule.noResolve && resolved {
			return -1
		}
		rs, ok := r.ruleSets[rule.ruleSetName]
		if !ok || !rs.Loaded {
			return -1
		}

		if domain != "" {
			if rs.MatchesDomain(domain) {
				return rule.action
			}
		}

		if ip != nil {
			if rs.MatchesIP(ip) {
				return rule.action
			}
		}

	case RuleTypeFinal:
		return rule.action

	case RuleTypeAnd:

		for _, subRule := range rule.subRules {
			if r.evalRule(subRule, domain, ip, dstPort, network, resolved) < 0 {
				return -1
			}
		}
		return rule.action

	case RuleTypeOr:

		for _, subRule := range rule.subRules {
			if r.evalRule(subRule, domain, ip, dstPort, network, resolved) >= 0 {
				return rule.action
			}
		}
		return -1

	case RuleTypeNot:

		for _, subRule := range rule.subRules {
			if r.evalRule(subRule, domain, ip, dstPort, network, resolved) >= 0 {
				return -1
			}
		}
		return rule.action
	}

	return -1
}

func (r *ProxyRouter) LoadRuleSet(name, path string, behavior ProviderBehavior) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	rs, err := parseRuleSetBytes(name, data, behavior)
	if err != nil {
		return err
	}
	rs.SourcePath = path

	r.ruleSets[name] = rs
	return nil
}

func (r *ProxyRouter) downloadRuleSet(name, url, path string, behavior ProviderBehavior) error {
	return r.downloadRuleSetWithForce(name, url, path, behavior, false)
}

func (r *ProxyRouter) downloadRuleSetWithForce(name, url, path string, behavior ProviderBehavior, force bool) error {
	if !force {
		if info, err := os.Stat(path); err == nil {
			if time.Since(info.ModTime()) < 24*time.Hour {
				logInfo("[路由] 使用缓存规则集 %s（最后更新: %v）", name, info.ModTime().Format("15:04:05"))
				return r.LoadRuleSet(name, path, behavior)
			}
		}
	}

	logInfo("[路由] 下载规则集 %s 从 %s", name, url)
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("下载失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败，状态码: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		logWarn("[路由] 保存缓存文件失败: %v", err)
	}

	rs, err := parseRuleSetBytes(name, data, behavior)
	if err != nil {
		return err
	}
	rs.Source = RuleSetURL
	rs.SourcePath = path

	r.ruleSets[name] = rs
	logInfo("[路由] 下载规则集 %s 完成", name)
	return nil
}

// =============================================================================
// 配置解析
// =============================================================================

func (r *ProxyRouter) ParseYAML(content string, baseDir string) {
	var config ProxyConfig
	if err := yaml.Unmarshal([]byte(content), &config); err != nil {
		logWarn("[路由] YAML解析失败: %v", err)
		return
	}

	for name, provider := range config.RuleProviders {
		r.ruleSetConfigs[name] = provider

		var behavior ProviderBehavior
		switch strings.ToLower(provider.Behavior) {
		case "domain":
			behavior = BehaviorDomain
		case "ipcidr":
			behavior = BehaviorIpCidr
		default:
			behavior = BehaviorClassical
		}

		if provider.URL != "" && provider.Path != "" {
			path := provider.Path
			if !filepath.IsAbs(path) {
				path = filepath.Join(exeDir, path)
			}

			if err := r.downloadRuleSet(name, provider.URL, path, behavior); err != nil {
				logWarn("[路由] 下载规则集失败 %s: %v", name, err)
				if _, err := os.Stat(path); err == nil {
					if err := r.LoadRuleSet(name, path, behavior); err != nil {
						logWarn("[路由] 加载缓存规则集失败 %s: %v", path, err)
					}
				}
			}
		} else if provider.Path != "" {
			path := provider.Path
			if !filepath.IsAbs(path) {
				path = filepath.Join(exeDir, path)
			}

			if err := r.LoadRuleSet(name, path, behavior); err != nil {
				logWarn("[路由] 加载规则集文件失败 %s: %v", path, err)
			}
		}
	}

	for _, ruleLine := range config.Rules {
		rule := ParseRule(ruleLine)
		if rule != nil {
			if rule.ruleType == RuleTypeFinal {
				r.SetDefaultAction(rule.action)
				logInfo("[路由] 默认动作: %s", rule.action.String())
			} else {
				r.AddRule(rule)
			}
		}
	}

	logInfo("[路由] YAML配置加载完成，规则集: %d, 规则: %d", len(config.RuleProviders), len(config.Rules))

	r.domainIndex.Build()
	r.ipIndex.Build()
	r.recomputeNeedsIPResolution()
}

func (r *ProxyRouter) ParseYAMLWithProviders(content string, baseDir string, providers map[string]RuleProvider) {
	for name, provider := range providers {
		if provider.path != "" {
			path := provider.path
			if !filepath.IsAbs(path) {
				path = filepath.Join(baseDir, path)
			}
			behavior := BehaviorDomain
			if provider.behavior == BehaviorIpCidr {
				behavior = BehaviorIpCidr
			}
			if err := r.LoadRuleSet(name, path, behavior); err != nil {
				logWarn("[路由] 加载规则集文件失败 %s: %v", path, err)
			}
		}
	}

	inRules := false
	for _, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "rules:" {
			inRules = true
			continue
		}
		if !inRules {
			continue
		}

		if !strings.HasPrefix(line, "-") && strings.HasSuffix(line, ":") {
			break
		}
		if strings.HasPrefix(line, "- ") {
			rule := ParseRule(line)
			if rule != nil {
				if rule.ruleType == RuleTypeFinal {
					r.SetDefaultAction(rule.action)
					logInfo("[路由] 默认动作: %s", rule.action.String())
				} else {
					r.AddRule(rule)
				}
			}
		}
	}

	r.domainIndex.Build()
	r.ipIndex.Build()
	r.recomputeNeedsIPResolution()
}

func (r *ProxyRouter) ParseRules(content string) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		rule := ParseRule(line)
		if rule != nil {
			if rule.ruleType == RuleTypeFinal {
				r.SetDefaultAction(rule.action)
			} else {
				r.AddRule(rule)
			}
		}
	}
	r.recomputeNeedsIPResolution()
}

// =============================================================================
// 全局路由管理
// =============================================================================

var (
	globalRouter *ProxyRouter
	routerMu     sync.RWMutex
)

func GetRouter() *ProxyRouter {
	routerMu.RLock()
	defer routerMu.RUnlock()
	return globalRouter
}

func InitRouter(mode string, configPath string) {
	router := NewProxyRouter()

	switch mode {
	case "global":
		router.SetDefaultAction(RuleActionProxy)
		logInfo("[路由] 模式: global (全部代理)")

	case "bypass_cn":
		router.SetDefaultAction(RuleActionProxy)
		router.AddRule(&Rule{
			ruleType: RuleTypeGeoLocation,
			action:   RuleActionDirect,
			geoIP:    "CN",
		})
		logInfo("[路由] 模式: bypass_cn (绕过中国IP)")

	case "none":
		router.SetDefaultAction(RuleActionDirect)
		logInfo("[路由] 模式: none (全部直连)")

	case "rule":
		if configPath != "" {
			router.loadConfigFile(configPath)
		}

		if router.defaultAction == 0 {
			router.SetDefaultAction(RuleActionProxy)
		}
		logInfo("[路由] 模式: rule (自定义规则), 默认动作: %s", router.defaultAction.String())

		// 规则未加载（rules.yaml 未找到/为空）时表现为"全局代理"，明确告警
		// 提示放好规则文件，避免误以为分流已生效
		if len(router.ruleSets) == 0 && len(router.domainTrie.children) == 0 &&
			len(router.slowRules) == 0 && len(router.networkRules) == 0 && len(router.portRules) == 0 {
			logWarn("[路由] 未加载到任何自定义规则（找不到或为空: %s），全部流量将按默认动作 %s 处理——请把 rules.yaml 与 ruleset/ 放到可执行文件同目录",
				configPath, router.defaultAction.String())
		}

	default:
		if _, err := os.Stat(mode); err == nil {
			router.loadConfigFile(mode)
		} else {
			router.SetDefaultAction(RuleActionProxy)
		}
	}

	routerMu.Lock()
	if globalRouter != nil && globalRouter.cancel != nil {
		globalRouter.cancel() // 停掉旧 goroutine
	}
	globalRouter = router
	routerMu.Unlock()

	router.recomputeNeedsIPResolution()
}

func (r *ProxyRouter) loadConfigFile(path string) {
	var absPath string
	if filepath.IsAbs(path) {
		absPath = path
	} else {
		tryPaths := []string{
			filepath.Join(exeDir, path),
			path,
		}
		var err error
		for _, p := range tryPaths {
			if _, err = os.Stat(p); err == nil {
				absPath = p
				break
			}
		}
		if absPath == "" {
			logWarn("[路由] 配置文件未找到: %s (尝试了: %v)", path, tryPaths)
			return
		}
	}
	data, err := os.ReadFile(absPath)
	if err != nil {
		logWarn("[路由] 读取配置文件失败: %v", err)
		return
	}

	content := string(data)
	dir := filepath.Dir(absPath)

	if strings.HasSuffix(absPath, ".yaml") || strings.HasSuffix(absPath, ".yml") {
		r.ParseYAML(content, dir)
		logInfo("[路由] 从YAML文件加载规则: %s", relPath(absPath))
	} else {
		r.ParseRules(content)
		logInfo("[路由] 从文件加载规则: %s", relPath(absPath))
	}
}

// =============================================================================
// 路由分类（DNS 上游选组依据，移植自 ssp-client-rs router.rs）
// =============================================================================

// ClassifyDomain 纯域名规则匹配（绝不触发 DNS）：
// 命中 DIRECT 域名规则 → RouteClassDirect；其余（含未命中→defaultAction，
// PROXY/REJECT/NAMED）→ RouteClassProxy。REJECT 的域名若被查询，用隧道 DNS
// 至少不会泄漏给本地 ISP。
func (r *ProxyRouter) ClassifyDomain(domain string) RouteClass {
	action, ok := r.routeDomainOpt(domain)
	if !ok {
		action = r.defaultAction
	}
	if action == RuleActionDirect {
		return RouteClassDirect
	}
	return RouteClassProxy
}

// routeDomainOpt 仅域名规则匹配；未命中返回 false（调用方可据此决定是否需要
// 解析 IP）。与 RS route_domain_opt 对齐：只看域名索引和"仅凭域名即可判定"
// 的慢规则（DOMAIN-KEYWORD/REGEX、RULE-SET 域名行为、AND/OR/NOT 组合）。
// IP 谓词（cncidr/geoip 等）在这里天然不生效——DNS 查询发生在拿到 IP 之前。
func (r *ProxyRouter) routeDomainOpt(domain string) (RuleAction, bool) {
	domain = strings.ToLower(domain)
	if domain == "" {
		return 0, false
	}
	if action, ok := r.domainIndex.exact[domain]; ok {
		return action, true
	}
	if action, ok := r.domainTrie.Search(domain); ok {
		return action, true
	}
	for _, rule := range r.slowRules {
		switch rule.ruleType {
		case RuleTypeDomain:
			for _, dp := range rule.domains {
				switch dp.patternType {
				case DomainPatternKeyword:
					if strings.Contains(domain, dp.keyword) {
						return rule.action, true
					}
				case DomainPatternRegex:
					if rule.compiledRegexp != nil && rule.compiledRegexp.MatchString(domain) {
						return rule.action, true
					}
				}
			}
		case RuleTypeRuleSet:
			if rs, ok := r.ruleSets[rule.ruleSetName]; ok && rs.Loaded && rs.MatchesDomain(domain) {
				return rule.action, true
			}
		case RuleTypeAnd, RuleTypeOr, RuleTypeNot:
			if action, ok := r.evalDomainLogical(rule, domain); ok {
				return action, true
			}
		}
	}
	return 0, false
}

// evalDomainLogical 域名阶段的逻辑规则求值：子规则里仅"凭域名即可判定"的
// 谓词参与；IP/端口谓词不触发 DNS → 视为不匹配
func (r *ProxyRouter) evalDomainLogical(rule *Rule, domain string) (RuleAction, bool) {
	switch rule.ruleType {
	case RuleTypeAnd:
		for _, sub := range rule.subRules {
			if _, ok := r.evalDomainSub(sub, domain); !ok {
				return 0, false
			}
		}
		return rule.action, true
	case RuleTypeOr:
		for _, sub := range rule.subRules {
			if _, ok := r.evalDomainSub(sub, domain); ok {
				return rule.action, true
			}
		}
		return 0, false
	case RuleTypeNot:
		for _, sub := range rule.subRules {
			if _, ok := r.evalDomainSub(sub, domain); ok {
				return 0, false
			}
		}
		return rule.action, true
	}
	return 0, false
}

func (r *ProxyRouter) evalDomainSub(rule *Rule, domain string) (RuleAction, bool) {
	switch rule.ruleType {
	case RuleTypeDomain:
		for _, dp := range rule.domains {
			switch dp.patternType {
			case DomainPatternKeyword:
				if strings.Contains(domain, dp.keyword) {
					return rule.action, true
				}
			case DomainPatternRegex:
				if rule.compiledRegexp != nil && rule.compiledRegexp.MatchString(domain) {
					return rule.action, true
				}
			}
		}
	case RuleTypeRuleSet:
		if rs, ok := r.ruleSets[rule.ruleSetName]; ok && rs.Loaded && rs.MatchesDomain(domain) {
			return rule.action, true
		}
	case RuleTypeAnd, RuleTypeOr, RuleTypeNot:
		return r.evalDomainLogical(rule, domain)
	}
	return 0, false
}

// NeedsIPResolution 路由是否存在"无 no-resolve 的 IP 谓词规则"。
// false 时调用方不应触发任何 DNS 查询（防泄漏第一性原理）。
func (r *ProxyRouter) NeedsIPResolution() bool {
	return r.needsIPResolution.Load()
}

// ruleNeedsIP 单条规则是否为需要解析的 IP 谓词（RS rule_type_needs_ip 对应物）
func (r *ProxyRouter) ruleNeedsIP(rule *Rule) bool {
	if rule == nil || rule.noResolve {
		return false
	}
	switch rule.ruleType {
	case RuleTypeNetwork, RuleTypeIP:
		return true
	case RuleTypeGeoLocation:
		return true
	case RuleTypeRuleSet:
		if rs, ok := r.ruleSets[rule.ruleSetName]; ok && rs.Loaded {
			return rs.requiresResolution()
		}
		return false
	case RuleTypeAnd, RuleTypeOr, RuleTypeNot:
		for _, sub := range rule.subRules {
			if r.ruleNeedsIP(sub) {
				return true
			}
		}
		return false
	}
	return false
}

// recomputeNeedsIPResolution 重新扫描规则集，更新"需要解析"标记。
// 规则加载完成 / 规则集热更新后调用。
func (r *ProxyRouter) recomputeNeedsIPResolution() {
	need := false
	for _, rule := range r.networkRules {
		if r.ruleNeedsIP(rule) {
			need = true
			break
		}
	}
	if !need {
		for _, rule := range r.slowRules {
			if r.ruleNeedsIP(rule) {
				need = true
				break
			}
		}
	}
	r.needsIPResolution.Store(need)
	logInfo("[路由] needs-ip-resolution=%v", need)
}

// requiresResolution 规则集是否含 IP 谓词（domain 型规则集永远不需要解析）
func (rs *RuleSet) requiresResolution() bool {
	if rs.Behavior == BehaviorDomain {
		return false
	}
	return len(rs.IPs) > 0 || len(rs.IPNets) > 0
}

// =============================================================================
// 路由决策（防泄漏关键路径）
// =============================================================================

// RouteDomain 路由判定：域名规则 → 字面 IP 规则 → （需要时）DnsResolver 解析
// 后按 IP 判定。解析走 DnsResolver（DIRECT → direct-nameserver，PROXY/未知 →
// tunnel://），fail-closed：解析失败保留域名阶段结论，绝不回退系统 DNS。
func RouteDomain(domain string, ip net.IP, port uint16) RuleAction {
	router := GetRouter()
	if router == nil {
		return RuleActionProxy
	}

	if ip != nil {
		return router.Route(domain, ip, port, ProtoTCP, false)
	}

	if domain == "" {
		return router.defaultAction
	}

	// 字面 IP：走 IP 规则（无需解析，对应 RS resolve_action 第 2 步）
	if ipLit := net.ParseIP(domain); ipLit != nil {
		return router.Route(domain, ipLit, port, ProtoTCP, false)
	}

	{
		action := router.Route(domain, nil, port, ProtoTCP, false)
		if action != router.defaultAction {
			logDebug("[路由] 域名预匹配命中: %s -> %s (跳过解析)", domain, action.String())
			return action
		}

		// 路由不存在"需要解析"的 IP 谓词规则：保持域名阶段结论，绝不触发 DNS
		if !router.NeedsIPResolution() {
			return router.defaultAction
		}
	}

	resolver := getDnsResolver()
	if resolver == nil {
		logDebug("[路由] DNS 解析器未就绪，%s 保留域名规则结果", domain)
		return router.defaultAction
	}

	ips, err := resolver.Resolve(domain)
	if err != nil {
		// fail-closed：隧道断开/上游失败时，绝不静默改用系统 DNS
		logDebug("[路由] %s 解析失败 (%v), 保留域名规则结果", domain, err)
		return router.defaultAction
	}

	for _, addr := range ips {
		action := router.Route(domain, addr, port, ProtoTCP, true)
		if action != router.defaultAction {
			return action
		}
	}

	return router.defaultAction
}

// =============================================================================
// GeoIP 管理
// =============================================================================

func (r *ProxyRouter) loadGeoIPDatabase() {
	dbPaths := []string{
		filepath.Join(exeDir, "mmdb", "Merged-IP.mmdb"),
		filepath.Join(exeDir, "mmdb", "Country.mmdb"),
		filepath.Join(exeDir, "mmdb", "GeoLite2-Country.mmdb"),
		filepath.Join(exeDir, "mmdb", "GeoIP2-Country.mmdb"),
	}

	for _, path := range dbPaths {
		if db, err := geoip2.Open(path); err == nil {
			r.geoipReader = db
			logInfo("[路由] GeoIP 数据库加载成功: %s", relPath(path))
			return
		}
	}

	logWarn("[路由] GeoIP 数据库未找到，GEOIP 规则将被跳过")
}

func (r *ProxyRouter) getIPCountry(ip net.IP) string {
	if r.geoipReader == nil {
		return ""
	}

	record, err := r.geoipReader.Country(ip)
	if err != nil {
		return ""
	}

	return record.Country.IsoCode
}

func (r *ProxyRouter) startRuleSetAutoUpdate(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done(): // 收到取消信号，退出
			logDebug("[路由] 规则集自动更新已停止")
			return
		case <-ticker.C:
			r.updateStaleRuleSets()
		}
	}
}

func (r *ProxyRouter) updateStaleRuleSets() {
	for name, rs := range r.ruleSets {
		if rs.Source == RuleSetURL {
			config, exists := r.ruleSetConfigs[name]
			if !exists {
				continue
			}

			interval := time.Duration(config.Interval) * time.Second
			if interval == 0 {
				interval = 24 * time.Hour
			}

			if time.Since(rs.LoadedAt) > interval {
				logInfo("[路由] 更新规则集: %s (间隔: %v)", name, interval)

				if err := r.downloadRuleSetWithForce(name, config.URL, rs.SourcePath, rs.Behavior, true); err != nil {
					logWarn("[路由] 更新规则集失败 %s: %v", name, err)
				} else {
					logInfo("[路由] 规则集更新成功: %s", name)
					// IP 型规则集可能带来新的 IP 谓词：更新"需要解析"标记
					if rs.requiresResolution() {
						r.needsIPResolution.Store(true)
					}
				}
			}
		}
	}
}

func processRuleSetLines(data string, rs *RuleSet) {
	for _, raw := range strings.Split(data, "\n") {
		line := parseRuleSetEntry(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if rs.Behavior == BehaviorClassical {
			rule := ParseRule(line)
			if rule == nil {
				continue
			}
			for _, dp := range rule.domains {
				switch dp.patternType {
				case DomainPatternExact:
					rs.DomainTrie.Insert(dp.exact, RuleActionNamed)
				case DomainPatternSuffix:
					rs.DomainTrie.Insert(dp.suffix, RuleActionNamed)
				}
			}
			for _, cidr := range rule.ipNets {
				rs.IPs[cidr] = true
				if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
					rs.IPNets = append(rs.IPNets, ipNet)
				}
			}
			continue
		}
		if strings.HasPrefix(line, "+.") {
			rs.DomainTrie.Insert(strings.TrimPrefix(line, "+."), RuleActionNamed)
		} else if _, ipNet, err := net.ParseCIDR(line); err == nil {
			rs.IPs[line] = true
			rs.IPNets = append(rs.IPNets, ipNet)
		} else if ip := net.ParseIP(line); ip != nil {
			rs.IPs[ip.String()] = true
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			if _, ipNet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), bits)); err == nil {
				rs.IPNets = append(rs.IPNets, ipNet)
			}
		} else {
			rs.DomainTrie.Insert(line, RuleActionNamed)
		}
	}
}
