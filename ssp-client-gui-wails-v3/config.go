package main

import (
	"bytes"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// ==============================================================================
// 配置
// 字段名、类型保持一致（全部字符串，use_ech 是 "true"/"false" 字符串）。
// 仅新增顶层字段 core（记住选中的核心 exe 名）。
// ==============================================================================

type Server struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Server      string `json:"server"`
	Listen      string `json:"listen"`
	Token       string `json:"token"`
	IP          string `json:"ip"`
	Fallback    string `json:"fallback"`
	UA          string `json:"ua"`
	DNS         string `json:"dns"`
	ECH         string `json:"ech"`
	RoutingMode string `json:"routing_mode"`
	LogLevel    string `json:"loglevel"`
	UseECH      string `json:"use_ech"`
}

type LastState struct {
	WasRunning           bool `json:"was_running"`
	SystemProxyEnabled   bool `json:"system_proxy_enabled"`
	AutoStartChecked     bool `json:"auto_start_checked"`
	PreferredMode        int  `json:"preferred_mode"`
	AutoStartHideChecked bool `json:"auto_start_hide_checked"`
}

// WindowState 记住上次窗口位置和大小（新增字段；旧版 C# GUI 忽略未知字段，双向兼容）
type WindowState struct {
	X      int `json:"x"`
	Y      int `json:"y"`
	Width  int `json:"width"`
	Height int `json:"height"`
}

type ConfigData struct {
	Servers         []Server     `json:"servers"`
	CurrentServerID string       `json:"current_server_id"`
	LastState       *LastState   `json:"last_state"`
	Core            string       `json:"core"`             // 新增字段：上次选中的核心 exe 名
	Window          *WindowState `json:"window,omitempty"` // 新增字段：上次窗口位置和大小
}

// configPaths 配置文件查找顺序：exe 同目录优先，其次 AppData
func configPaths() []string {
	return []string{
		filepath.Join(getExeDir(), "config.json"),
		filepath.Join(os.Getenv("APPDATA"), "SSP Workers", "config.json"),
	}
}

func getExeDir() string {
	if p, err := os.Executable(); err == nil {
		return filepath.Dir(p)
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

func newGUID() string {
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	s := hex.EncodeToString(b)
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}

// normalize 补齐旧配置可能缺失的字段
// - bypass_cn 选项已从界面移除（规则引擎 rule 模式已覆盖绕过大陆场景），自动映射为 rule
// - DOH地址 无 scheme 时补 https://（旧版默认值无 scheme；Go/Rust 的 DoH 客户端都需要完整 URL）
func (s *Server) normalize() {
	if s.LogLevel == "" {
		s.LogLevel = "INFO"
	}
	if s.UseECH == "" {
		s.UseECH = "true"
	}
	if s.RoutingMode == "" || s.RoutingMode == "bypass_cn" {
		s.RoutingMode = "rule"
	}
	if s.DNS != "" && !strings.Contains(s.DNS, "://") {
		s.DNS = "https://" + s.DNS
	}
}

func (c *ConfigData) normalize() {
	if c.LastState == nil {
		c.LastState = &LastState{}
	}
	for i := range c.Servers {
		c.Servers[i].normalize()
	}
}

// loadConfig 加载配置：exe 同目录 config.json 优先，其次 %APPDATA%\SSP Workers\config.json；
// 都不存在时在 AppData 创建默认配置。返回 (配置, 实际路径, 是否新建了默认配置, 错误)。
func loadConfig() (*ConfigData, string, bool, error) {
	paths := configPaths()
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var cfg ConfigData
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, p, false, fmt.Errorf("配置文件解析失败 %s: %w", p, err)
		}
		cfg.normalize()
		return &cfg, p, false, nil
	}
	cfg := createDefaultConfig()
	if dir := filepath.Dir(paths[1]); dir != "" {
		_ = os.MkdirAll(dir, 0o755)
		_ = writeConfigAt(cfg, paths[1])
	}
	return cfg, paths[1], true, nil
}

// saveConfig 写回配置：写到已存在的配置文件；都不存在时写到 AppData
func saveConfig(cfg *ConfigData) error {
	path := ""
	for _, p := range configPaths() {
		if _, err := os.Stat(p); err == nil {
			path = p
			break
		}
	}
	if path == "" {
		path = configPaths()[1]
		if dir := filepath.Dir(path); dir != "" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
		}
	}
	return writeConfigAt(cfg, path)
}

// writeConfigAt 写配置文件（缩进 2 空格、不转义中文）
func writeConfigAt(cfg *ConfigData, path string) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// createDefaultConfig 默认配置
func createDefaultConfig() *ConfigData {
	id := newGUID()
	srv := Server{
		ID:          id,
		Name:        "默认服务器",
		Server:      "worker.username.workers.dev:443",
		Listen:      "127.0.0.1:" + generateRandomPort(),
		Token:       "",
		IP:          "r2.dev,104.18.12.1,104.18.44.0/24",
		DNS:         "https://dns.alidns.com/dns-query",
		Fallback:    "",
		UA:          defaultBrowserUA(),
		ECH:         "cloudflare-ech.com",
		LogLevel:    "INFO",
		UseECH:      "false",
		RoutingMode: "rule",
	}
	srv.normalize()
	return &ConfigData{
		Servers:         []Server{srv},
		CurrentServerID: id,
		LastState:       &LastState{},
	}
}

// generateRandomPort 随机可用端口：1024–9999，最多尝试 50 次，失败则由系统分配
func generateRandomPort() string {
	for i := 0; i < 50; i++ {
		port := 1024 + rand.IntN(8976)
		if isPortAvailable(port) {
			return strconv.Itoa(port)
		}
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "30000"
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return strconv.Itoa(port)
}

func isPortAvailable(port int) bool {
	l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

func regGetString(root registry.Key, path, name string) string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return v
}

// defaultBrowserUA 从注册表探测默认浏览器并构造 UA
func defaultBrowserUA() string {
	const base = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
	progId := strings.ToLower(regGetString(registry.CURRENT_USER,
		`Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice`, "ProgId"))
	switch {
	case strings.Contains(progId, "chrome"):
		v := regGetString(registry.CURRENT_USER, `Software\Google\Chrome\BLBeacon`, "version")
		major := "120"
		if v != "" {
			major = strings.Split(v, ".")[0]
		}
		return base + "Chrome/" + major + ".0.0.0 Safari/537.36"
	case strings.Contains(progId, "edge") || progId == "msedgehtm" || strings.HasPrefix(progId, "appx"):
		v := regGetString(registry.CURRENT_USER, `Software\Microsoft\Edge\BLBeacon`, "version")
		major := "120"
		if v != "" {
			major = strings.Split(v, ".")[0]
		}
		return base + "Chrome/" + major + ".0.0.0 Safari/537.36 Edg/" + major + ".0.0.0"
	}
	return ""
}
