package main

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ==============================================================================
// 系统代理 —— 直接写注册表，再通知 WinINet 刷新
// ==============================================================================

const internetSettingsPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

var (
	wininet               = windows.NewLazySystemDLL("wininet.dll")
	procInternetSetOption = wininet.NewProc("InternetSetOptionW")
)

const (
	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
)

func refreshSystemSettings() {
	procInternetSetOption.Call(0, internetOptionSettingsChanged, 0, 0)
	procInternetSetOption.Call(0, internetOptionRefresh, 0, 0)
}

// parseListen 把 "host:port" 解析成 host 与 port（无 scheme 时按 http:// 处理）
func parseListen(listen string) (string, int, error) {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		return "", 0, fmt.Errorf("监听地址为空")
	}
	if !strings.Contains(listen, "://") {
		listen = "http://" + listen
	}
	u, err := url.Parse(listen)
	if err != nil {
		return "", 0, err
	}
	if u.Hostname() == "" || u.Port() == "" {
		return "", 0, fmt.Errorf("监听地址格式无效: %s", listen)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port <= 0 {
		return "", 0, fmt.Errorf("端口无效: %s", u.Port())
	}
	return u.Hostname(), port, nil
}

// setSystemProxy 启用/禁用系统代理。启用时先强制关一次再开（50ms 间隔）。
func setSystemProxy(listen string, enabled bool) error {
	host, port, err := parseListen(listen)
	if err != nil {
		return err
	}

	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer func() { _ = key.Close() }()

	// 先关闭（清掉 ProxyServer），保证状态切换生效
	if err := key.SetDWordValue("ProxyEnable", 0); err != nil {
		return err
	}
	_ = key.DeleteValue("ProxyServer") // 不存在时报错可忽略
	refreshSystemSettings()

	if !enabled {
		return nil
	}

	time.Sleep(50 * time.Millisecond) // 给 WinINet 一个状态切换点

	if err := key.SetDWordValue("ProxyEnable", 1); err != nil {
		return err
	}
	if err := key.SetStringValue("ProxyServer", fmt.Sprintf("%s:%d", host, port)); err != nil {
		return err
	}
	refreshSystemSettings()
	return nil
}
