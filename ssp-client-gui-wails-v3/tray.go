package main

import (
	"github.com/wailsapp/wails/v3/pkg/application"
)

// ==============================================================================
// 系统托盘 —— Wails v3 原生托盘（不再依赖第三方 systray 库）
// 显示/隐藏 | 启动服务、停止服务 | ☑开启系统代理、☑开机启动 |
// 服务器选择子菜单（当前项打勾、运行中禁用） | 退出
// 所有回调异步执行，避免托盘消息循环线程与应用状态锁互相等待。
// ==============================================================================

func (a *App) initTray() {
	tray := application.Get().SystemTray.New()
	tray.SetIcon(a.trayIcon)
	tray.SetTooltip("SSP Workers Client")
	tray.OnClick(func() { go a.toggleWindow() })
	tray.OnDoubleClick(func() { go a.toggleWindow() })
	tray.OnRightClick(func() { tray.OpenMenu() })
	a.tray = tray
	a.trayInited = true
	a.rebuildTrayMenu()
	tray.Show()
}

// rebuildTrayMenu 重建托盘菜单（初始 + 服务器列表变化时；运行中不会发生增删改）
func (a *App) rebuildTrayMenu() {
	if a.tray == nil {
		return
	}
	a.mu.Lock()
	proxyOn := a.cfg.LastState.SystemProxyEnabled
	autoOn := a.cfg.LastState.AutoStartChecked
	currentID := a.cfg.CurrentServerID
	servers := make([]Server, len(a.cfg.Servers))
	copy(servers, a.cfg.Servers)
	a.mu.Unlock()

	menu := application.Get().NewMenu()
	miShow := menu.Add("显示/隐藏")
	miShow.OnClick(func(*application.Context) { go a.toggleWindow() })
	menu.AddSeparator()

	miStart := menu.Add("启动服务")
	miStart.OnClick(func(*application.Context) { go func() { _ = a.StartCore() }() })
	miStop := menu.Add("停止服务")
	miStop.OnClick(func(*application.Context) { go a.StopCore() })
	menu.AddSeparator()

	miProxy := menu.AddCheckbox("开启系统代理", proxyOn)
	miProxy.OnClick(func(*application.Context) { go a.toggleSystemProxy() })
	miAuto := menu.AddCheckbox("开机启动", autoOn)
	miAuto.OnClick(func(*application.Context) { go a.toggleAutoStart() })
	menu.AddSeparator()

	miServers := menu.AddSubmenu("服务器选择")
	var serverItems []*application.MenuItem
	for _, srv := range servers {
		item := miServers.AddCheckbox(srv.Name, srv.ID == currentID)
		sid := srv.ID
		item.OnClick(func(*application.Context) {
			go func() {
				// 运行中禁止切换（点击时再次确认）
				if a.proc.isRunning() {
					return
				}
				_, _ = a.SelectServer(sid)
			}()
		})
		serverItems = append(serverItems, item)
	}
	menu.AddSeparator()
	miExit := menu.Add("退出")
	miExit.OnClick(func(*application.Context) { go a.quitApp() })

	a.tray.SetMenu(menu)
	a.mu.Lock()
	a.miStart = miStart
	a.miStop = miStop
	a.miProxy = miProxy
	a.miAuto = miAuto
	a.serverItems = serverItems
	a.mu.Unlock()

	a.syncTray()
}

// syncTray 按当前状态同步托盘菜单项（快照后调用菜单 API，不持有应用锁）
func (a *App) syncTray() {
	a.mu.Lock()
	if !a.trayInited {
		a.mu.Unlock()
		return
	}
	running := a.running
	proxyOn := a.cfg.LastState.SystemProxyEnabled
	autoOn := a.cfg.LastState.AutoStartChecked
	currentID := a.cfg.CurrentServerID
	servers := make([]Server, len(a.cfg.Servers))
	copy(servers, a.cfg.Servers)
	miStart, miStop, miProxy, miAuto := a.miStart, a.miStop, a.miProxy, a.miAuto
	serverItems := make([]*application.MenuItem, len(a.serverItems))
	copy(serverItems, a.serverItems)
	a.mu.Unlock()

	if miStart != nil {
		if running {
			miStart.SetEnabled(false)
		} else {
			miStart.SetEnabled(true)
		}
	}
	if miStop != nil {
		if running {
			miStop.SetEnabled(true)
		} else {
			miStop.SetEnabled(false)
		}
	}
	if miProxy != nil {
		miProxy.SetChecked(proxyOn)
	}
	if miAuto != nil {
		miAuto.SetChecked(autoOn)
	}
	for i, item := range serverItems {
		if i >= len(servers) {
			break
		}
		item.SetChecked(servers[i].ID == currentID)
		item.SetEnabled(!running)
	}
}

func (a *App) toggleSystemProxy() {
	a.mu.Lock()
	enabled := !a.cfg.LastState.SystemProxyEnabled
	a.mu.Unlock()
	a.SetSystemProxy(enabled)
}

func (a *App) toggleAutoStart() {
	a.mu.Lock()
	enabled := !a.cfg.LastState.AutoStartChecked
	a.mu.Unlock()
	a.SetAutoStart(enabled)
}
