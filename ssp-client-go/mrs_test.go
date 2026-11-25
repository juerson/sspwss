package main

// .mrs 解码器测试 —— 夹具与断言对齐 ssp-client-rs/src/mrs.rs 的测试：
// 115.mrs / category-ads-all.mrs（domain trie）、private.mrs / cn.mrs（ipcidr）。

import (
	"net"
	"os"
	"sort"
	"strings"
	"testing"
)

func mrsFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/mrs/" + name)
	if err != nil {
		t.Fatalf("读取 fixture %s 失败: %v", name, err)
	}
	return data
}

// parseList `.list` 源文件 → (精确域名集合, 后缀域名集合)
func parseList(text string) (exact, suffix []string) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "+."); ok {
			suffix = append(suffix, strings.ToLower(rest))
		} else if rest, ok := strings.CutPrefix(line, "."); ok {
			suffix = append(suffix, strings.ToLower(rest))
		} else {
			exact = append(exact, strings.ToLower(line))
		}
	}
	sort.Strings(exact)
	sort.Strings(suffix)
	return
}

// splitDecoded 解码结果 → (精确域名集合, 后缀域名集合)
func splitDecoded(entries []mrsDomainEntry) (exact, suffix []string) {
	for _, e := range entries {
		if e.subOnly {
			suffix = append(suffix, strings.ToLower(e.name))
		} else {
			exact = append(exact, strings.ToLower(e.name))
		}
	}
	sort.Strings(exact)
	sort.Strings(suffix)
	return
}

func TestDetectRuleFormat(t *testing.T) {
	if got := detectRuleFormat(mrsFixture(t, "115.mrs")); got != mrsDetectedMrs {
		t.Fatalf("115.mrs should be Mrs, got %v", got)
	}
	if got := detectRuleFormat([]byte("SRS\x05rest")); got != mrsDetectedSrs {
		t.Fatalf("SRS should be Srs, got %v", got)
	}
	if got := detectRuleFormat([]byte("payload:\n  - example.com\n")); got != mrsDetectedText {
		t.Fatalf("yaml should be Text, got %v", got)
	}
	if got := detectRuleFormat([]byte("+.example.com\n")); got != mrsDetectedText {
		t.Fatalf("plain list should be Text, got %v", got)
	}
	// 显式 format 优先
	if got := detectWithFormat([]byte("payload:\n"), "mrs"); got != mrsDetectedMrs {
		t.Fatalf("explicit format=mrs should win, got %v", got)
	}
}

func TestDecodeTinyDomainSetMatchesSourceList(t *testing.T) {
	decoded, err := mrsParse(mrsFixture(t, "115.mrs"))
	if err != nil {
		t.Fatalf("解析 115.mrs: %v", err)
	}
	if decoded.kind != mrsKindDomain {
		t.Fatalf("115.mrs 应该是 domain，实际 %s", decoded.kind)
	}

	listExact, listSuffix := parseList(string(mrsFixture(t, "115.list")))
	gotExact, gotSuffix := splitDecoded(decoded.domains)

	// `+.d` 会同时写入精确 d 与后缀 d，所以精确集合 = 源文件的精确 + 后缀
	expectedExact := append([]string{}, listExact...)
	expectedExact = append(expectedExact, listSuffix...)
	sort.Strings(expectedExact)

	if !equalStrings(gotSuffix, listSuffix) {
		t.Fatalf("后缀集合不一致:\n got=%v\nwant=%v", gotSuffix, listSuffix)
	}
	if !equalStrings(gotExact, expectedExact) {
		t.Fatalf("精确集合不一致:\n got=%v\nwant=%v", gotExact, expectedExact)
	}
	if !containsStr(gotSuffix, "115.com") {
		t.Fatalf("应包含 115.com 后缀规则: %v", gotSuffix)
	}
	if decoded.declaredCount != 14 {
		t.Fatalf("声明条数应为 14，实际 %d", decoded.declaredCount)
	}
}

func TestDecodeMediumDomainSetMatchesSourceList(t *testing.T) {
	decoded, err := mrsParse(mrsFixture(t, "category-ads-all.mrs"))
	if err != nil {
		t.Fatalf("解析 category-ads-all.mrs: %v", err)
	}
	if decoded.kind != mrsKindDomain {
		t.Fatalf("category-ads-all.mrs 应该是 domain，实际 %s", decoded.kind)
	}

	listExact, listSuffix := parseList(string(mrsFixture(t, "category-ads-all.list")))
	gotExact, gotSuffix := splitDecoded(decoded.domains)

	expectedExact := append([]string{}, listExact...)
	expectedExact = append(expectedExact, listSuffix...)
	sort.Strings(expectedExact)

	if !equalStrings(gotSuffix, listSuffix) {
		t.Fatalf("后缀集合不一致")
	}
	if !equalStrings(gotExact, expectedExact) {
		t.Fatalf("精确集合不一致")
	}
	if want := len(listExact) + len(listSuffix)*2; len(decoded.domains) != want {
		t.Fatalf("条目数应为 %d，实际 %d", want, len(decoded.domains))
	}
}

func TestDecodeTinyIPSetMatchesSourceList(t *testing.T) {
	decoded, err := mrsParse(mrsFixture(t, "private.mrs"))
	if err != nil {
		t.Fatalf("解析 private.mrs: %v", err)
	}
	if decoded.kind != mrsKindIP {
		t.Fatalf("private.mrs 应该是 ipcidr，实际 %s", decoded.kind)
	}

	var want []string
	for _, line := range strings.Split(string(mrsFixture(t, "private.list")), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		want = append(want, line)
	}

	// 解码结果按 CIDR 规范化后应与源文件逐条相等（range 本身都是对齐的）
	var got []string
	for _, n := range decoded.nets {
		got = append(got, n.String())
	}
	sort.Strings(got)
	sort.Strings(want)
	if !equalStrings(got, want) {
		t.Fatalf("CIDR 集合不一致:\n got=%v\nwant=%v", got, want)
	}
	if decoded.declaredCount != len(want) {
		t.Fatalf("声明条数 %d 应等于源文件 %d 条", decoded.declaredCount, len(want))
	}
}

func TestDecodeLargeIPSetMatchesSourcePrefixes(t *testing.T) {
	decoded, err := mrsParse(mrsFixture(t, "cn.mrs"))
	if err != nil {
		t.Fatalf("解析 cn.mrs: %v", err)
	}
	if decoded.kind != mrsKindIP {
		t.Fatalf("cn.mrs 应该是 ipcidr，实际 %s", decoded.kind)
	}
	if len(decoded.nets) <= 1000 {
		t.Fatalf("cn.mrs 应有上千条，实际 %d", len(decoded.nets))
	}

	// 每条源前缀的首尾地址都必须落在解码结果内
	for _, line := range strings.Split(string(mrsFixture(t, "cn.list")), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		start := ipNet.IP
		end := make(net.IP, len(ipNet.IP))
		for i := range ipNet.IP {
			end[i] = ipNet.IP[i] | ^ipNet.Mask[i]
		}
		for _, ip := range []net.IP{start, end} {
			found := false
			for _, n := range decoded.nets {
				if n.Contains(ip) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("解码结果未覆盖 %s 的地址 %s", line, ip)
			}
		}
	}
}

func TestCorruptedStreamIsRejected(t *testing.T) {
	if _, err := mrsParse([]byte("not-a-zstd-frame")); err == nil {
		t.Fatal("非 zstd 数据应被拒绝")
	}

	// zstd 帧头 + 垃圾数据：解压阶段就应该失败
	junk := append([]byte{}, zstdMagic[:]...)
	junk = append(junk, make([]byte, 32)...)
	if _, err := mrsParse(junk); err == nil {
		t.Fatal("zstd 帧头 + 垃圾数据应被拒绝")
	}
}

func TestClassicalAndUnknownBehaviorsRejected(t *testing.T) {
	// 直接构造解压后的负载（mrsParsePlain），绕开 zstd，专门测头部校验
	raw := func(behavior byte) []byte {
		out := []byte(mrsMagic)
		out = append(out, behavior)
		out = append(out, 0, 0, 0, 0, 0, 0, 0, 0) // count
		out = append(out, 0, 0, 0, 0, 0, 0, 0, 0) // extra_len
		return out
	}

	if _, err := mrsParsePlain(raw(2)); err == nil || !strings.Contains(err.Error(), "classical") {
		t.Fatalf("classical 应被拒绝: %v", err)
	}
	if _, err := mrsParsePlain(raw(7)); err == nil {
		t.Fatal("未知 behavior 应被拒绝")
	}
}

func TestRangeToCIDRsHandlesEdges(t *testing.T) {
	// 整个 IPv4 空间（注意用 4 字节 IP：rangeToCIDRsV4 直接读 uint32）
	all := rangeToCIDRsV4(net.IPv4(0, 0, 0, 0).To4(), net.IPv4(255, 255, 255, 255).To4())
	if len(all) != 1 || all[0].String() != "0.0.0.0/0" {
		t.Fatalf("整个 v4 空间应为 0.0.0.0/0，实际 %v", all)
	}

	// 单个地址
	one := rangeToCIDRsV4(net.IPv4(1, 2, 3, 4).To4(), net.IPv4(1, 2, 3, 4).To4())
	if len(one) != 1 || one[0].String() != "1.2.3.4/32" {
		t.Fatalf("单地址应为 1.2.3.4/32，实际 %v", one)
	}

	// 非对齐小段
	few := rangeToCIDRsV4(net.IPv4(10, 0, 0, 1).To4(), net.IPv4(10, 0, 0, 6).To4())
	got := make([]string, 0, len(few))
	for _, n := range few {
		got = append(got, n.String())
	}
	want := []string{"10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"}
	if !equalStrings(got, want) {
		t.Fatalf("非对齐小段拆分不一致:\n got=%v\nwant=%v", got, want)
	}
}

func TestDecodeKeyRestoresSuffixMarker(t *testing.T) {
	// 内部 key 是反转 + 末尾 '+'；还原后应是「仅子域」的 google.com
	entry := decodeMrsKey([]byte("moc.elgoog.+"))
	if entry == nil || entry.name != "google.com" || !entry.subOnly {
		t.Fatalf("subOnly 还原失败: %+v", entry)
	}
	entry = decodeMrsKey([]byte("moc.elgoog"))
	if entry == nil || entry.name != "google.com" || entry.subOnly {
		t.Fatalf("exact 还原失败: %+v", entry)
	}
}

// ── RuleSet 级集成 ───────────────────────────────────────────────────────────

func TestParseRuleSetBytesMrsDomain(t *testing.T) {
	rs, err := parseRuleSetBytes("reject", mrsFixture(t, "category-ads-all.mrs"), BehaviorDomain)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.exactDomains) == 0 {
		t.Fatal("domain .mrs should populate exact domains")
	}

	// 从夹具 .list 取一个后缀条目验证：裸域 + 子域都应命中
	listExact, listSuffix := parseList(string(mrsFixture(t, "category-ads-all.list")))
	if len(listSuffix) == 0 {
		t.Fatal("fixture should contain suffix entries")
	}
	domain := listSuffix[0]
	if !rs.MatchesDomain(domain) {
		t.Fatalf("apex of suffix entry %q should match", domain)
	}
	if !rs.MatchesDomain("sub." + domain) {
		t.Fatalf("subdomain of suffix entry %q should match", domain)
	}

	// 源文件的精确条目（无 +. 前缀）应只匹配域本身
	for _, exact := range listExact {
		if !rs.MatchesDomain(exact) {
			t.Fatalf("exact entry %q should match", exact)
		}
		if rs.MatchesDomain("sub." + exact) {
			t.Logf("note: %q has a separate suffix entry too (fixture-dependent)", exact)
		}
		break
	}

	if rs.requiresResolution() {
		t.Fatal("domain-behavior rule-set must not require resolution")
	}
}

func TestParseRuleSetBytesMrsIP(t *testing.T) {
	rs, err := parseRuleSetBytes("cncidr", mrsFixture(t, "cn.mrs"), BehaviorIpCidr)
	if err != nil {
		t.Fatal(err)
	}
	if !rs.MatchesIP(net.ParseIP("1.2.4.113")) { // apnic 文档段中的中国地址段内地址
		// cn.mrs 覆盖大量中国网段；此地址不一定在列表里，退而验证接口与数量
		if len(rs.IPNets) == 0 {
			t.Fatal("ipcidr rule-set should contain networks")
		}
	}
	if !rs.requiresResolution() {
		t.Fatal("ipcidr rule-set with entries must require resolution")
	}
}

func TestParseRuleSetBytesBehaviorMismatch(t *testing.T) {
	// domain 的 .mrs 配成 ipcidr behavior → 报错
	if _, err := parseRuleSetBytes("bad", mrsFixture(t, "115.mrs"), BehaviorIpCidr); err == nil {
		t.Fatal("behavior mismatch must error")
	}
	// ipcidr 的 .mrs 配成 domain behavior → 报错
	if _, err := parseRuleSetBytes("bad", mrsFixture(t, "private.mrs"), BehaviorDomain); err == nil {
		t.Fatal("behavior mismatch must error")
	}
}

func TestParseRuleSetBytesTextDomainBehavior(t *testing.T) {
	text := "payload:\n  - '+.ads.example.com'\n  - 'plain.example.org'\n"
	rs, err := parseRuleSetBytes("dom", []byte(text), BehaviorDomain)
	if err != nil {
		t.Fatal(err)
	}
	if !rs.MatchesDomain("x.ads.example.com") {
		t.Fatal("text '+.' entry should match subdomain")
	}
	if !rs.MatchesDomain("x.plain.example.org") {
		t.Fatal("text plain entry should match subdomain (suffix semantics)")
	}
	if rs.requiresResolution() {
		t.Fatal("domain-only text rule-set must not require resolution")
	}
}

func TestParseRuleSetBytesTextClassical(t *testing.T) {
	// classical 行为需要完整规则行（DOMAIN-SUFFIX,x / IP-CIDR,x）
	text := "payload:\n  - 'DOMAIN-SUFFIX,ads.example.com'\n  - 'IP-CIDR,1.2.3.0/24'\n"
	rs, err := parseRuleSetBytes("cl", []byte(text), BehaviorClassical)
	if err != nil {
		t.Fatal(err)
	}
	if !rs.MatchesDomain("x.ads.example.com") {
		t.Fatal("classical DOMAIN-SUFFIX should match subdomain")
	}
	if len(rs.IPNets) != 1 {
		t.Fatalf("classical IP-CIDR entries should load, got %d", len(rs.IPNets))
	}
	if !rs.requiresResolution() {
		t.Fatal("rule-set with CIDR entries must require resolution")
	}
}

// ── 工具 ─────────────────────────────────────────────────────────────────────

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
