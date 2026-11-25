package main

import (
	"os"
	"path/filepath"
	"strings"
)

// ==============================================================================
// 核心注册表 —— 唯一需要维护的文件
//
// - 改名：只改对应条目的 ExeNames
// - 增删核心：增删条目即可（再配一个 BuildArgs），其余代码零改动
// - 条目顺序 = 默认优先级：多个核心共存时排在前面的被默认选中（当前默认 Rust 版）
// ==============================================================================

type CoreDef struct {
	ExeNames []string // 识别的 exe 名（含 .exe 后缀），按优先级排序
	Kind     string   // "go" / "rs"，决定命令行参数风格
	// BuildArgs 由服务器配置构造命令行参数（不含 exe 路径）。
	// 第二个返回值是"配置里有值但未传给核心"的参数说明列表（空值跳过/ECH 未启用/DOH 非 IP 等），
	// 用于启动日志，方便核对每一项是否传入。
	BuildArgs func(s Server) (args []string, skipped []string)
	BuildEnv  func(s Server) [][2]string // 附加环境变量，可为 nil
}

var coreRegistry = []CoreDef{
	{
		ExeNames:  []string{"ssp-rs.exe", "sspcore-rs.exe"},
		Kind:      "rs",
		BuildArgs: buildRsArgs,
		BuildEnv:  buildRsEnv,
	},
	{
		ExeNames:  []string{"ssp-core.exe", "ssp-go.exe", "ssp.exe", "core.exe"},
		Kind:      "go",
		BuildArgs: buildGoArgs,
	},
}

// kindLabel 核心类型的显示名
func kindLabel(kind string) string {
	if kind == "rs" {
		return "Rust"
	}
	return "Go"
}

// CoreInfo 扫描到的可用核心
type CoreInfo struct {
	Name string `json:"name"` // exe 文件名
	Kind string `json:"kind"` // go / rs
	Path string `json:"path"` // 完整路径
}

// findCores 扫描 exe 所在目录，返回存在的核心（按注册表优先级排序）
func findCores() []CoreInfo {
	return findCoresIn(getExeDir())
}

// findCoresIn 在指定目录扫描核心（独立出来便于测试）
func findCoresIn(dir string) []CoreInfo {
	var out []CoreInfo
	for _, def := range coreRegistry {
		for _, name := range def.ExeNames {
			p := filepath.Join(dir, name)
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				out = append(out, CoreInfo{Name: name, Kind: def.Kind, Path: p})
			}
		}
	}
	return out
}

func findCoreDef(kind string) *CoreDef {
	for i := range coreRegistry {
		if coreRegistry[i].Kind == kind {
			return &coreRegistry[i]
		}
	}
	return nil
}

func findCoreInfo(name string) *CoreInfo {
	for _, c := range findCores() {
		if c.Name == name {
			c := c
			return &c
		}
	}
	return nil
}

// ==============================================================================
// 参数构造
// ==============================================================================

// buildGoArgs Go 版核心（flag 风格，单横线）。
// 注意：Go 客户端的 -dns 是 ECH 查询 DoH 服务器，不是 dns.yaml 路径（那是 -dns-config）。
func buildGoArgs(s Server) (args []string, skipped []string) {
	args = []string{}
	add := func(flag, val string) {
		if val != "" {
			args = append(args, flag, val)
		} else {
			skipped = append(skipped, flag)
		}
	}
	add("-f", s.Server)
	add("-l", s.Listen)
	add("-token", s.Token)
	add("-ip", s.IP)
	add("-fallback", s.Fallback)
	add("-ua", s.UA)
	add("-dns", s.DNS)
	if s.UseECH == "true" {
		add("-ech", s.ECH)
		args = append(args, "-use-ech")
	} else {
		skipped = append(skipped, "-ech(ECH未启用)", "-use-ech(ECH未启用)")
	}
	add("-routing", s.RoutingMode)
	add("-loglevel", s.LogLevel)
	return args, skipped
}

// buildRsArgs Rust 版核心（clap 风格）。
// 注意：Rust 客户端的 --dns 是 dns.yaml 路径（与配置里 DOH地址 字段语义不同，不传，用其内置默认）；
// --ech auto = 尝试 ECH 失败回退普通 TLS，off = 关闭；ECH 域名用 --ech-domain；
// --ech-doh 支持域名或字面 IP（域名时 Rust 核心内部做引导解析并钉住端点，与 Go 版行为统一）。
func buildRsArgs(s Server) (args []string, skipped []string) {
	args = []string{}
	add := func(flag, val string) {
		if val != "" {
			args = append(args, flag, val)
		} else {
			skipped = append(skipped, flag)
		}
	}
	add("-s", s.Server)
	add("-l", s.Listen)
	add("--token", s.Token)
	add("--ip", s.IP)
	add("--fallback", s.Fallback)
	add("--ua", s.UA)
	add("--routing", s.RoutingMode)
	if s.UseECH == "true" {
		args = append(args, "--ech", "auto")
		add("--ech-domain", s.ECH)
		// normalize 已为 DOH地址 补 https:// 前缀；Rust 核心支持域名（内部引导解析）与字面 IP
		add("--ech-doh", s.DNS)
	} else {
		args = append(args, "--ech", "off")
		skipped = append(skipped, "--ech-domain(ECH未启用)", "--ech-doh(ECH未启用)")
	}
	return args, skipped
}

// buildRsEnv Rust 版没有 -loglevel 参数，日志级别通过 RUST_LOG 环境变量控制
func buildRsEnv(s Server) [][2]string {
	level := strings.ToLower(strings.TrimSpace(s.LogLevel))
	switch level {
	case "debug", "info", "warn", "error":
	default:
		level = "info"
	}
	return [][2]string{{"RUST_LOG", level}}
}
