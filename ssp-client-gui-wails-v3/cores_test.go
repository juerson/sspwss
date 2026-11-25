package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBuildGoArgs(t *testing.T) {
	s := Server{
		Server: "a.b.com:443", Listen: "127.0.0.1:30000", Token: "tk",
		IP: "1.2.3.4", Fallback: "5.6.7.8", UA: "ua-agent",
		DNS: "dns.alidns.com/dns-query", ECH: "cloudflare-ech.com",
		UseECH: "true", RoutingMode: "rule", LogLevel: "INFO",
	}
	got, skipped := buildGoArgs(s)
	want := []string{
		"-f", "a.b.com:443", "-l", "127.0.0.1:30000", "-token", "tk",
		"-ip", "1.2.3.4", "-fallback", "5.6.7.8", "-ua", "ua-agent",
		"-dns", "dns.alidns.com/dns-query", "-ech", "cloudflare-ech.com",
		"-use-ech", "-routing", "rule", "-loglevel", "INFO",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildGoArgs:\n got  %v\n want %v", got, want)
	}
	if len(skipped) != 0 {
		t.Fatalf("全部字段有值时不应有未传项: %v", skipped)
	}
}

func TestBuildGoArgsECHOff(t *testing.T) {
	s := Server{
		Server: "a:443", Token: "t", Listen: "127.0.0.1:30000", IP: "1.2.3.4",
		Fallback: "5.6.7.8", UA: "ua", DNS: "d", UseECH: "false",
		RoutingMode: "global", LogLevel: "WARN",
	}
	got, skipped := buildGoArgs(s)
	want := []string{"-f", "a:443", "-l", "127.0.0.1:30000", "-token", "t", "-ip", "1.2.3.4",
		"-fallback", "5.6.7.8", "-ua", "ua", "-dns", "d", "-routing", "global", "-loglevel", "WARN"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildGoArgs(ech off):\n got  %v\n want %v", got, want)
	}
	if !reflect.DeepEqual(skipped, []string{"-ech(ECH未启用)", "-use-ech(ECH未启用)"}) {
		t.Fatalf("ECH 关闭未传说明不符: %v", skipped)
	}
}

func TestBuildGoArgsEmptyFieldsSkipped(t *testing.T) {
	// 空字段跳过，且未传项要列出
	s := Server{Server: "a:443", Token: "t", Listen: "", IP: "", UseECH: "true", ECH: ""}
	got, skipped := buildGoArgs(s)
	want := []string{"-f", "a:443", "-token", "t", "-use-ech"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildGoArgs(空字段):\n got  %v\n want %v", got, want)
	}
	for _, flag := range []string{"-l", "-ip", "-fallback", "-ua", "-dns", "-ech"} {
		found := false
		for _, sk := range skipped {
			if strings.HasPrefix(sk, flag+"(") || sk == flag {
				found = true
			}
		}
		if !found {
			t.Fatalf("空值 -%s 应出现在未传列表: %v", flag, skipped)
		}
	}
}

func TestBuildRsArgs(t *testing.T) {
	s := Server{
		Server: "a.b.com:443", Listen: "127.0.0.1:30000", Token: "tk",
		IP: "1.2.3.4", Fallback: "5.6.7.8", UA: "ua-agent",
		UseECH: "true", ECH: "cloudflare-ech.com", RoutingMode: "rule", LogLevel: "DEBUG",
		DNS: "https://223.5.5.5/dns-query",
	}
	got, skipped := buildRsArgs(s)
	want := []string{
		"-s", "a.b.com:443", "-l", "127.0.0.1:30000", "--token", "tk",
		"--ip", "1.2.3.4", "--fallback", "5.6.7.8", "--ua", "ua-agent",
		"--routing", "rule", "--ech", "auto", "--ech-domain", "cloudflare-ech.com",
		"--ech-doh", "https://223.5.5.5/dns-query",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildRsArgs:\n got  %v\n want %v", got, want)
	}
	// Rust 版没有 -loglevel，日志级别走 RUST_LOG 环境变量
	env := buildRsEnv(s)
	if len(env) != 1 || env[0][0] != "RUST_LOG" || env[0][1] != "debug" {
		t.Fatalf("buildRsEnv: got %v", env)
	}
	if len(skipped) != 0 {
		t.Fatalf("全字段有值 + IP DoH 时不应有未传项: %v", skipped)
	}
}

func TestBuildRsArgsECHOff(t *testing.T) {
	s := Server{
		Server: "a:443", Token: "t", Listen: "127.0.0.1:30000", IP: "1.2.3.4",
		Fallback: "5.6.7.8", UA: "ua", UseECH: "false", RoutingMode: "rule", LogLevel: "INFO",
	}
	got, skipped := buildRsArgs(s)
	want := []string{"-s", "a:443", "-l", "127.0.0.1:30000", "--token", "t", "--ip", "1.2.3.4",
		"--fallback", "5.6.7.8", "--ua", "ua", "--routing", "rule", "--ech", "off"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildRsArgs(ech off):\n got  %v\n want %v", got, want)
	}
	if !reflect.DeepEqual(skipped, []string{"--ech-domain(ECH未启用)", "--ech-doh(ECH未启用)"}) {
		t.Fatalf("ECH 关闭未传说明不符: %v", skipped)
	}
}

func TestBuildRsArgsRoutingBypassCN(t *testing.T) {
	// bypass_cn 在 normalize 中自动迁移为 rule（见 TestNormalizeMigratesBypassCN）
	s := Server{Server: "a:443", Token: "t", RoutingMode: "bypass_cn"}
	got, _ := buildRsArgs(s)
	want := []string{"-s", "a:443", "--token", "t", "--routing", "bypass_cn", "--ech", "off"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildRsArgs(bypass_cn):\n got  %v\n want %v", got, want)
	}
}

func TestBuildRsArgsDoHDomainAndIP(t *testing.T) {
	// DOH地址 域名与字面 IP 都直传（Rust 核心现在支持域名，内部引导解析并钉住端点）
	base := Server{
		Server: "a:443", Token: "t", Listen: "127.0.0.1:30000", IP: "1.2.3.4",
		Fallback: "5.6.7.8", UA: "ua", UseECH: "true", ECH: "e", RoutingMode: "rule",
	}
	got, _ := buildRsArgs(withDNS(base, "https://dns.alidns.com/dns-query"))
	if !strings.HasSuffix(strings.Join(got, " "), "--ech-doh https://dns.alidns.com/dns-query") {
		t.Fatalf("域名 DoH 应直传: %v", got)
	}
	got, _ = buildRsArgs(withDNS(base, "https://223.5.5.5/dns-query"))
	if !strings.HasSuffix(strings.Join(got, " "), "--ech-doh https://223.5.5.5/dns-query") {
		t.Fatalf("IP DoH 应直传: %v", got)
	}
	// 空 DOH地址 → 未传列表
	_, skipped := buildRsArgs(withDNS(base, ""))
	if len(skipped) != 1 || skipped[0] != "--ech-doh" {
		t.Fatalf("空 DOH地址 应出现在未传列表: %v", skipped)
	}
	// 无 scheme → normalize 自动补 https://
	b := base
	b.DNS = "dns.alidns.com/dns-query"
	b.normalize()
	got, _ = buildRsArgs(b)
	if !strings.Contains(strings.Join(got, " "), "--ech-doh https://dns.alidns.com/dns-query") {
		t.Fatalf("normalize 应为无 scheme 的 DOH地址 补 https://: %v", got)
	}
}

func withDNS(s Server, dns string) Server {
	s.DNS = dns
	return s
}

func TestNormalizeMigratesBypassCN(t *testing.T) {
	// bypass_cn 选项已移除，旧配置自动迁移为 rule（rules.yaml 规则引擎覆盖绕过大陆场景）
	s := Server{RoutingMode: "bypass_cn"}
	s.normalize()
	if s.RoutingMode != "rule" {
		t.Fatalf("bypass_cn 应迁移为 rule，实际 %q", s.RoutingMode)
	}
}

func TestFindCoresInPriority(t *testing.T) {
	// 注册表顺序 = 默认优先级：两个核心共存时 Rust 版排在最前
	dir := t.TempDir()
	for _, name := range []string{"ssp-core.exe", "ssp-rs.exe"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("dummy"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := findCoresIn(dir)
	if len(got) != 2 {
		t.Fatalf("应找到 2 个核心，实际 %d: %+v", len(got), got)
	}
	if got[0].Name != "ssp-rs.exe" || got[0].Kind != "rs" {
		t.Fatalf("默认应优先 Rust 核心，实际 %+v", got[0])
	}
	if got[1].Name != "ssp-core.exe" || got[1].Kind != "go" {
		t.Fatalf("第二应为 Go 核心，实际 %+v", got[1])
	}
}

func TestFindCoresInSingle(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "core.exe"), []byte("dummy"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := findCoresIn(dir)
	if len(got) != 1 || got[0].Kind != "go" || got[0].Name != "core.exe" {
		t.Fatalf("只应找到 Go 核心 core.exe，实际 %+v", got)
	}
}

func TestFindCoresInEmpty(t *testing.T) {
	if got := findCoresIn(t.TempDir()); len(got) != 0 {
		t.Fatalf("空目录不应找到核心，实际 %+v", got)
	}
}

func TestFindCoreDef(t *testing.T) {
	if d := findCoreDef("rs"); d == nil || d.Kind != "rs" {
		t.Fatal("应找到 rs 定义")
	}
	if d := findCoreDef("go"); d == nil || d.Kind != "go" {
		t.Fatal("应找到 go 定义")
	}
	if d := findCoreDef("unknown"); d != nil {
		t.Fatal("未知类型应返回 nil")
	}
}
