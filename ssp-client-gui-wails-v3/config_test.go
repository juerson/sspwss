package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestConfigRoundTrip(t *testing.T) {
	cfg := &ConfigData{
		Servers: []Server{{
			ID: "id-1", Name: "节点A", Server: "w.dev:443", Listen: "127.0.0.1:30000",
			Token: "tk", IP: "1.2.3.4", Fallback: "5.6.7.8", UA: "ua",
			DNS: "dns.alidns.com/dns-query", ECH: "cloudflare-ech.com",
			RoutingMode: "rule", LogLevel: "INFO", UseECH: "true",
		}},
		CurrentServerID: "id-1",
		LastState:       &LastState{WasRunning: true, SystemProxyEnabled: true},
		Core:            "ssp-rs.exe",
		Window:          &WindowState{X: 120, Y: 80, Width: 840, Height: 720},
	}
	p := filepath.Join(t.TempDir(), "config.json")
	if err := writeConfigAt(cfg, p); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var back ConfigData
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	back.normalize()
	// DNS 无 scheme 时 normalize 自动补 https://（新行为）
	if back.Servers[0].DNS != "https://dns.alidns.com/dns-query" {
		t.Fatalf("DNS 应自动补 https:// 前缀: %q", back.Servers[0].DNS)
	}
	back.Servers[0].DNS = "dns.alidns.com/dns-query" // 还原后再比较其余字段
	if len(back.Servers) != 1 || back.Servers[0] != cfg.Servers[0] {
		t.Fatalf("round trip 不一致:\n got  %+v\n want %+v", back.Servers, cfg.Servers)
	}
	if back.Core != "ssp-rs.exe" {
		t.Fatalf("core 字段丢失: %q", back.Core)
	}
	if back.Window == nil || back.Window.X != 120 || back.Window.Height != 720 {
		t.Fatalf("window 字段丢失或不一致: %+v", back.Window)
	}
	if back.LastState == nil || !back.LastState.WasRunning || !back.LastState.SystemProxyEnabled {
		t.Fatalf("last_state 不一致: %+v", back.LastState)
	}
	// 中文不转义、无 HTML 转义
	if strings.Contains(string(data), "\\u") {
		t.Fatalf("中文不应被转义: %s", data)
	}
}

func TestCompatOldConfig(t *testing.T) {
	old := `{
  "servers": [
    {
      "id": "3f2a",
      "name": "默认服务器",
      "server": "worker.x.workers.dev:443",
      "listen": "127.0.0.1:30000",
      "token": "psk",
      "ip": "r2.dev",
      "fallback": "",
      "ua": "Mozilla/5.0",
      "dns": "dns.alidns.com/dns-query",
      "ech": "cloudflare-ech.com",
      "routing_mode": "rule",
      "loglevel": "INFO",
      "use_ech": "true"
    }
  ],
  "current_server_id": "3f2a",
  "last_state": {
    "was_running": false,
    "system_proxy_enabled": true,
    "auto_start_checked": false,
    "preferred_mode": 0,
    "auto_start_hide_checked": false
  }
}`
	var cfg ConfigData
	if err := json.Unmarshal([]byte(old), &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.normalize()
	if len(cfg.Servers) != 1 || cfg.Servers[0].Name != "默认服务器" {
		t.Fatalf("旧配置解析失败: %+v", cfg)
	}
	if cfg.CurrentServerID != "3f2a" || cfg.LastState.SystemProxyEnabled != true {
		t.Fatalf("旧配置字段不一致: %+v", cfg)
	}
}

func TestNormalize(t *testing.T) {
	s := Server{}
	s.normalize()
	if s.LogLevel != "INFO" || s.UseECH != "true" || s.RoutingMode != "rule" {
		t.Fatalf("normalize 默认值错误: %+v", s)
	}
}

func TestGenerateRandomPort(t *testing.T) {
	for i := 0; i < 20; i++ {
		p := generateRandomPort()
		n, err := strconv.Atoi(p)
		if err != nil || n < 1024 || n > 9999 {
			t.Fatalf("端口超出范围: %q", p)
		}
	}
}

func TestParseListen(t *testing.T) {
	host, port, err := parseListen("127.0.0.1:30000")
	if err != nil || host != "127.0.0.1" || port != 30000 {
		t.Fatalf("parseListen 失败: %v %v %v", host, port, err)
	}
	host, port, err = parseListen("http://localhost:8443")
	if err != nil || host != "localhost" || port != 8443 {
		t.Fatalf("parseListen(http) 失败: %v %v %v", host, port, err)
	}
	if _, _, err := parseListen(""); err == nil {
		t.Fatal("空监听地址应报错")
	}
	if _, _, err := parseListen("localhost"); err == nil {
		t.Fatal("无端口应报错")
	}
}

func TestDefaultBrowserUA(t *testing.T) {
	// 只要求不 panic；返回空串也是合法结果（未知浏览器）
	_ = defaultBrowserUA()
}

func TestRandName(t *testing.T) {
	name := randName()
	if len(name) < 3 || name[:3] != "No." {
		t.Fatalf("默认名格式错误: %q", name)
	}
}
