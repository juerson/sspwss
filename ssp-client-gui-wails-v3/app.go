package main

import (
	"context"
	"fmt"
	"log"
	"math/rand/v2"
	"strconv"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
)

// ==============================================================================
// 应用服务：配置状态管理 + 绑定给前端的方法 + 托盘/窗口生命周期
// （Wails v3：App 注册为 Service，导出方法自动绑定到前端，前端用 Call.ByName 调用）
// ==============================================================================

// UIState 发送给前端的完整界面状态
type UIState struct {
	Running       bool          `json:"running"`
	Dirty         bool          `json:"dirty"`
	Servers       []ServerBrief `json:"servers"`
	CurrentServer *Server       `json:"currentServer"`
	LastState     *LastState    `json:"lastState"`
	Cores         []CoreInfo    `json:"cores"`
	SelectedCore  string        `json:"selectedCore"`
	Notice        string        `json:"notice,omitempty"` // 一次性提示（前端显示后即弃）
}

type ServerBrief struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type App struct {
	mu           sync.Mutex
	cfg          *ConfigData
	cfgCreated   bool
	running      bool
	dirty        bool
	selectedCore string
	proc         *coreManager

	win           application.Window
	windowVisible bool
	quitting      bool // 托盘"退出"置位后，窗口关闭事件放行

	pendingNotice string // 待发送给前端的一次性提示

	// 数据库管理窗口（dbwindows.go，mu 保护；懒创建，关闭即隐藏）
	csvWin  application.Window
	cidrWin application.Window

	// 数据库单例（dbwindows.go；首次使用时按需打开）
	dbOnce, cidbOnce sync.Once
	pdb              *proxyDB
	pdbErr           error
	cdb              *cidrDB
	cdbErr           error

	trayIcon []byte
	// 托盘控件引用（tray.go 使用，mu 保护）
	tray        *application.SystemTray
	trayInited  bool
	miStart     *application.MenuItem
	miStop      *application.MenuItem
	miProxy     *application.MenuItem
	miAuto      *application.MenuItem
	serverItems []*application.MenuItem
}

func NewApp(icon []byte, cfg *ConfigData, created bool) *App {
	return &App{
		trayIcon:      icon,
		cfg:           cfg,
		cfgCreated:    created,
		proc:          newCoreManager(),
		windowVisible: false, // 窗口以 Hidden 创建，ServiceStartup 显示
	}
}

// SetWindow main.go 创建窗口后注入
func (a *App) SetWindow(win application.Window) {
	a.win = win
}

// ==============================================================================
// 服务生命周期
// ==============================================================================

func (a *App) ServiceStartup(ctx context.Context, options application.ServiceOptions) error {
	// v3 启动顺序：ServiceStartup → pendingRun（窗口在此之后自动显示）。
	// 位置/大小已在创建时用上次记录的 X/Y/W/H 指定，无需手动 Show。
	a.mu.Lock()
	a.windowVisible = true
	a.mu.Unlock()

	if a.cfgCreated {
		a.setNotice("已创建默认配置文件")
	}

	a.initTray()

	// 有意修正：旧版启动时不会重新应用系统代理（事件被抑制），代理注册表可能残留旧端口。
	// 这里按上次状态重新应用一次。
	if a.cfg.LastState.SystemProxyEnabled {
		if srv := a.currentServer(); srv != nil {
			if err := setSystemProxy(srv.Listen, true); err != nil {
				a.appendLog("设置系统代理失败: " + err.Error())
			}
		}
	}

	// 启动恢复：was_running → 2 秒后自动启动；
	// 若同时勾选了开机启动+隐藏窗体 → 再等 3 秒确认已启动后隐藏窗口。
	if a.cfg.LastState.WasRunning {
		a.mu.Lock()
		autoStart := a.cfg.LastState.AutoStartChecked
		autoHide := a.cfg.LastState.AutoStartHideChecked
		a.mu.Unlock()
		time.AfterFunc(2*time.Second, func() {
			if a.quitting || a.proc.isRunning() {
				return
			}
			if err := a.StartCore(); err != nil {
				log.Println("自动恢复启动失败:", err)
				return
			}
			if autoStart && autoHide {
				time.AfterFunc(3*time.Second, func() {
					if a.proc.isRunning() {
						a.win.Hide()
						a.mu.Lock()
						a.windowVisible = false
						a.mu.Unlock()
					}
				})
			}
		})
	}

	a.emitState()
	return nil
}

// ServiceShutdown 应用退出时兜底停止核心进程
func (a *App) ServiceShutdown() {
	a.proc.stop()
}

// onWindowClosing X 按钮（events.WindowClosing）：
// 隐藏到托盘（脏标记时发事件由前端确认后隐藏）；托盘"退出"置位 quitting 放行
func (a *App) onWindowClosing(e *application.WindowEvent) {
	a.mu.Lock()
	quitting := a.quitting
	a.mu.Unlock()
	if quitting {
		return // 放行关闭，应用正在退出
	}
	e.Cancel()
	a.saveWindowState()
	a.mu.Lock()
	visible := a.windowVisible
	a.mu.Unlock()
	if !visible {
		return
	}
	if a.dirty {
		application.Get().Event.Emit("close-requested")
		return // 前端确认后调用 HideWindow
	}
	a.mu.Lock()
	a.windowVisible = false
	a.mu.Unlock()
	a.win.Hide()
}

// onSecondInstanceLaunch 单实例锁回调：再次双击 exe 时不新开窗口，
// 由已运行实例把窗口唤起到前台（托盘隐藏的显示、最小化的还原）
func (a *App) onSecondInstanceLaunch(_ application.SecondInstanceData) {
	a.showWindow()
}

// ==============================================================================
// 状态构建与同步
// ==============================================================================

func (a *App) currentServer() *Server {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.currentServerLocked()
}

func (a *App) currentServerLocked() *Server {
	for i := range a.cfg.Servers {
		if a.cfg.Servers[i].ID == a.cfg.CurrentServerID {
			return &a.cfg.Servers[i]
		}
	}
	// current_server_id 无效时回退到第一个服务器
	if len(a.cfg.Servers) > 0 {
		return &a.cfg.Servers[0]
	}
	return nil
}

// resolveCoreLocked 校验当前核心选择；无效时按注册表优先级回退（Rust 优先）
func (a *App) resolveCoreLocked() string {
	cores := findCores()
	if len(cores) == 0 {
		return ""
	}
	for _, c := range cores {
		if c.Name == a.selectedCore {
			return c.Name
		}
	}
	return cores[0].Name
}

func (a *App) buildState() UIState {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := UIState{
		Running:      a.running,
		Dirty:        a.dirty,
		SelectedCore: a.resolveCoreLocked(),
		LastState:    a.cfg.LastState,
		Cores:        findCores(),
		Notice:       a.pendingNotice,
	}
	a.pendingNotice = ""
	for i := range a.cfg.Servers {
		st.Servers = append(st.Servers, ServerBrief{ID: a.cfg.Servers[i].ID, Name: a.cfg.Servers[i].Name})
	}
	if srv := a.currentServerLocked(); srv != nil {
		cp := *srv
		st.CurrentServer = &cp
	}
	return st
}

func (a *App) emitState() {
	st := a.buildState()
	application.Get().Event.Emit("state", st)
	a.syncTray()
}

// appendLog 后台线程安全地向日志窗口追加一行
func (a *App) appendLog(line string) {
	application.Get().Event.Emit("log", line)
}

// setNotice 设置一次性提示（随下一次状态事件发给前端）
func (a *App) setNotice(msg string) {
	a.mu.Lock()
	a.pendingNotice = msg
	a.mu.Unlock()
}

// ==============================================================================
// 绑定给前端的方法（前端通过 Call.ByName("main.App.<方法名>") 调用）
// ==============================================================================

// GetState 获取完整状态（前端初始化时调用）
func (a *App) GetState() UIState {
	st := a.buildState()
	// 修正失效的核心选择并静默保存
	a.mu.Lock()
	if len(st.Cores) > 0 && st.SelectedCore != a.selectedCore {
		a.selectedCore = st.SelectedCore
		a.cfg.Core = a.selectedCore
		_ = saveConfig(a.cfg)
	}
	a.mu.Unlock()
	return st
}

// SelectServer 切换当前服务器（运行中禁止，切换后丢弃未保存的编辑）
func (a *App) SelectServer(id string) (UIState, error) {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return a.buildState(), fmt.Errorf("运行中不能切换服务器，请先停止")
	}
	found := false
	for i := range a.cfg.Servers {
		if a.cfg.Servers[i].ID == id {
			a.cfg.CurrentServerID = id
			found = true
			break
		}
	}
	if !found {
		a.mu.Unlock()
		return a.buildState(), fmt.Errorf("服务器不存在")
	}
	a.dirty = false
	err := saveConfig(a.cfg)
	// 切换服务器后若系统代理开启，代理跟随新的监听地址
	if err == nil && a.cfg.LastState.SystemProxyEnabled {
		if srv := a.currentServerLocked(); srv != nil {
			if perr := setSystemProxy(srv.Listen, true); perr != nil {
				a.mu.Unlock()
				a.appendLog("设置系统代理失败: " + perr.Error())
				a.emitState()
				return a.buildState(), nil
			}
		}
	}
	a.mu.Unlock()
	a.emitState()
	return a.buildState(), err
}

// SaveCurrentServer 把表单字段写回当前服务器（保存按钮，运行中也允许）
func (a *App) SaveCurrentServer(s Server) (UIState, error) {
	a.mu.Lock()
	cur := a.currentServerLocked()
	if cur == nil {
		a.mu.Unlock()
		a.setNotice("没有可保存的服务器")
		return a.buildState(), fmt.Errorf("没有可保存的服务器")
	}
	cur.Server = s.Server
	cur.Listen = s.Listen
	cur.Token = s.Token
	cur.IP = s.IP
	cur.Fallback = s.Fallback
	cur.UA = s.UA
	cur.DNS = s.DNS
	cur.ECH = s.ECH
	cur.RoutingMode = s.RoutingMode
	cur.LogLevel = s.LogLevel
	cur.UseECH = s.UseECH
	cur.normalize()
	err := saveConfig(a.cfg)
	a.dirty = false
	a.mu.Unlock()

	if err != nil {
		a.setNotice("保存失败：" + err.Error())
		a.appendLog("保存失败: " + err.Error())
	}
	a.emitState()
	return a.buildState(), err
}

// AddServer 新增服务器（复制当前服务器的大部分参数，UA 重新探测，监听端口重新分配）
func (a *App) AddServer(name string) (UIState, error) {
	if name == "" {
		return a.buildState(), fmt.Errorf("服务器名称不能为空")
	}
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return a.buildState(), fmt.Errorf("运行中不能新增服务器，请先停止")
	}
	id := newGUID()
	ns := Server{
		ID:     id,
		Name:   name,
		Listen: "127.0.0.1:" + generateRandomPort(),
		UA:     defaultBrowserUA(),
	}
	if cur := a.currentServerLocked(); cur != nil {
		ns.Server = cur.Server
		ns.Token = cur.Token
		ns.IP = cur.IP
		ns.Fallback = cur.Fallback
		ns.DNS = cur.DNS
		ns.ECH = cur.ECH
		ns.UseECH = cur.UseECH
		ns.RoutingMode = cur.RoutingMode
		ns.LogLevel = cur.LogLevel
	}
	ns.normalize()
	a.cfg.Servers = append(a.cfg.Servers, ns)
	a.cfg.CurrentServerID = id
	a.dirty = false
	err := saveConfig(a.cfg)
	a.mu.Unlock()

	if err != nil {
		a.setNotice("保存失败：" + err.Error())
	}
	a.rebuildTrayMenu()
	a.emitState()
	return a.buildState(), err
}

// RenameServer 重命名服务器
func (a *App) RenameServer(id string, name string) (UIState, error) {
	if name == "" {
		return a.buildState(), fmt.Errorf("服务器名称不能为空")
	}
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return a.buildState(), fmt.Errorf("运行中不能重命名，请先停止")
	}
	found := false
	for i := range a.cfg.Servers {
		if a.cfg.Servers[i].ID == id {
			a.cfg.Servers[i].Name = name
			found = true
			break
		}
	}
	if !found {
		a.mu.Unlock()
		return a.buildState(), fmt.Errorf("服务器不存在")
	}
	err := saveConfig(a.cfg)
	a.mu.Unlock()

	if err != nil {
		a.setNotice("保存失败：" + err.Error())
	}
	a.rebuildTrayMenu()
	a.emitState()
	return a.buildState(), err
}

// DeleteServer 删除服务器（确认对话框由前端弹出）
func (a *App) DeleteServer(id string) (UIState, error) {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return a.buildState(), fmt.Errorf("运行中不能删除服务器，请先停止")
	}
	found := false
	for i := range a.cfg.Servers {
		if a.cfg.Servers[i].ID == id {
			found = true
			break
		}
	}
	a.mu.Unlock()
	if !found {
		return a.buildState(), fmt.Errorf("服务器不存在")
	}

	a.mu.Lock()
	remaining := a.cfg.Servers[:0]
	for _, srv := range a.cfg.Servers {
		if srv.ID != id {
			remaining = append(remaining, srv)
		}
	}
	a.cfg.Servers = remaining
	if a.cfg.CurrentServerID == id {
		if len(a.cfg.Servers) > 0 {
			a.cfg.CurrentServerID = a.cfg.Servers[0].ID
		} else {
			a.cfg.CurrentServerID = ""
		}
	}
	a.dirty = false
	err := saveConfig(a.cfg)
	a.mu.Unlock()

	if err != nil {
		a.setNotice("保存失败：" + err.Error())
	}
	a.rebuildTrayMenu()
	a.emitState()
	return a.buildState(), err
}

// SetCore 切换核心（运行中冻结，与其它控件一致）
func (a *App) SetCore(name string) (UIState, error) {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return a.buildState(), fmt.Errorf("运行中不能切换核心，请先停止")
	}
	valid := false
	for _, c := range findCores() {
		if c.Name == name {
			valid = true
			break
		}
	}
	if !valid {
		a.mu.Unlock()
		return a.buildState(), fmt.Errorf("核心不存在: %s", name)
	}
	a.selectedCore = name
	a.cfg.Core = name
	err := saveConfig(a.cfg)
	a.mu.Unlock()

	if err != nil {
		a.setNotice("保存失败：" + err.Error())
	}
	a.emitState()
	return a.buildState(), err
}

// SetSystemProxy 开关系统代理（勾选框与托盘共用；失败写日志，状态仍按用户意图记录）
func (a *App) SetSystemProxy(enabled bool) UIState {
	listen := ""
	if srv := a.currentServer(); srv != nil {
		listen = srv.Listen
	}
	if err := setSystemProxy(listen, enabled); err != nil {
		a.appendLog("设置系统代理失败: " + err.Error())
	}
	a.mu.Lock()
	a.cfg.LastState.SystemProxyEnabled = enabled
	_ = saveConfig(a.cfg)
	a.mu.Unlock()
	a.emitState()
	return a.buildState()
}

// SetAutoStart 开关开机自启
func (a *App) SetAutoStart(enabled bool) UIState {
	if err := setAutoStart(enabled); err != nil {
		a.appendLog("设置开机启动失败: " + err.Error())
	}
	a.mu.Lock()
	a.cfg.LastState.AutoStartChecked = enabled
	_ = saveConfig(a.cfg)
	a.mu.Unlock()
	a.emitState()
	return a.buildState()
}

// SetAutoStartHide 开关"隐藏窗体"（勾选时强制开启自启）
func (a *App) SetAutoStartHide(enabled bool) UIState {
	a.mu.Lock()
	a.cfg.LastState.AutoStartHideChecked = enabled
	needAutoStart := enabled && !a.cfg.LastState.AutoStartChecked
	_ = saveConfig(a.cfg)
	a.mu.Unlock()
	if needAutoStart {
		return a.SetAutoStart(true)
	}
	a.emitState()
	return a.buildState()
}

// StartCore 启动当前选中的核心
func (a *App) StartCore() error {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return nil
	}
	coreName := a.resolveCoreLocked()
	if coreName == "" {
		a.mu.Unlock()
		msg := "未找到可执行程序 ssp-rs.exe、sspcore-rs.exe、ssp-core.exe、ssp-go.exe、ssp.exe、core.exe 中任意一个"
		a.setNotice(msg)
		a.appendLog(msg)
		return fmt.Errorf("%s", msg)
	}
	srv := a.currentServerLocked()
	if srv == nil || srv.Server == "" || srv.Token == "" {
		a.mu.Unlock()
		a.setNotice("必须填写服务器地址和身份令牌")
		return fmt.Errorf("必须填写服务器地址和身份令牌")
	}
	srvCopy := *srv
	// 修正保存的核心选择
	a.selectedCore = coreName
	a.cfg.Core = coreName
	_ = saveConfig(a.cfg)
	a.mu.Unlock()

	info := findCoreInfo(coreName)
	if info == nil {
		a.setNotice("未找到核心: " + coreName)
		return fmt.Errorf("未找到核心: %s", coreName)
	}

	err := a.proc.start(*info, srvCopy, a.appendLog, a.onProcExit)
	if err != nil {
		a.setNotice("启动失败：" + err.Error())
		a.appendLog("启动失败: " + err.Error())
		return err
	}

	a.mu.Lock()
	a.running = true
	a.cfg.LastState.WasRunning = true
	_ = saveConfig(a.cfg)
	a.mu.Unlock()
	a.emitState()
	return nil
}

// StopCore 停止核心（状态由 onProcExit 统一处理）
func (a *App) StopCore() {
	if !a.proc.isRunning() {
		return
	}
	a.proc.stop()
}

// onProcExit 核心进程退出（含手动停止、异常退出）
func (a *App) onProcExit() {
	a.mu.Lock()
	if !a.running {
		a.mu.Unlock()
		return
	}
	a.running = false
	a.cfg.LastState.WasRunning = false
	_ = saveConfig(a.cfg)
	a.mu.Unlock()

	a.appendLog("")
	a.appendLog("=============== 内核进程已经结束 ===============")
	a.emitState()
}

// SetDirty 前端通知脏标记状态（用于关闭确认；打字时高频调用，不发事件）
func (a *App) SetDirty(dirty bool) {
	a.mu.Lock()
	a.dirty = dirty
	a.mu.Unlock()
}

// HideWindow 前端确认后隐藏到托盘
func (a *App) HideWindow() {
	a.mu.Lock()
	a.windowVisible = false
	a.mu.Unlock()
	a.win.Hide()
}

// ==============================================================================
// 窗口 / 托盘 / 退出
// ==============================================================================

// showWindow 显示窗口并带到前台（托盘唤起、单实例二次启动共用）
func (a *App) showWindow() {
	a.win.Show()
	if a.win.IsMinimised() {
		a.win.Restore()
	}
	a.win.Focus()
	nudgeRepaint(a.win)
	a.mu.Lock()
	a.windowVisible = true
	a.mu.Unlock()
}

// nudgeRepaint 修复 WebView2 隐藏→显示的偶发白屏：wails v3.1.0 在 hide() 时会
// chromium.Hide() 挂起渲染（进入效率模式），show() 恢复可见性后渲染器有概率
// 不重绘，内容白屏直到下次无效化。做 ±1px 尺寸微调强制 WM_SIZE → 重新布局/重绘；
// 因显示与渲染器恢复存在竞态，延迟再补一次微调（窗口已被再次隐藏则跳过）。
func nudgeRepaint(win application.Window) {
	do := func() {
		w, h := win.Size()
		if w <= 1 || h <= 1 {
			return
		}
		win.SetSize(w+1, h)
		win.SetSize(w, h)
	}
	do()
	time.AfterFunc(150*time.Millisecond, func() {
		if win.IsVisible() {
			do()
		}
	})
}

// toggleWindow 托盘左键/双击：显示↔隐藏
func (a *App) toggleWindow() {
	a.mu.Lock()
	visible := a.windowVisible
	a.windowVisible = !visible
	a.mu.Unlock()
	if visible {
		a.win.Hide()
	} else {
		a.showWindow()
	}
}

// quitApp 托盘"退出"：记住窗口状态 → 杀核心 → 放行退出
func (a *App) quitApp() {
	a.mu.Lock()
	a.quitting = true
	a.mu.Unlock()
	a.saveWindowState()
	a.proc.stop()
	application.Get().Quit()
}

// saveWindowState 把当前窗口位置和大小写入配置（关闭窗口时调用）。
// 窗口隐藏到托盘时不保存（位置没变过）；也防御最小化时 Windows 记录的负坐标与异常尺寸。
func (a *App) saveWindowState() {
	a.mu.Lock()
	visible := a.windowVisible
	a.mu.Unlock()
	if !visible {
		return
	}
	x, y := a.win.Position()
	w, h := a.win.Size()
	// 最小化时可能返回 -21333 / -32000 之类的坐标和 158x26 之类的尺寸，不能写回配置
	if w < 200 || h < 200 || !positionOnScreen(x, y) {
		return
	}
	a.mu.Lock()
	a.cfg.Window = &WindowState{X: x, Y: y, Width: w, Height: h}
	_ = saveConfig(a.cfg)
	a.mu.Unlock()
}

// positionOnScreen 粗略判断坐标是否落在屏幕范围内
// （防拔显示器导致离屏 + 最小化 -32000 垃圾坐标；所有屏幕按并排近似拼接检查）
func positionOnScreen(x, y int) bool {
	if x < -200 || x >= 10000 || y < -100 || y >= 10000 {
		return false
	}
	screens := application.Get().Screen.GetAll()
	if len(screens) == 0 {
		return true // 枚举不到就信任配置
	}
	totalW, maxH := 0, 0
	for _, s := range screens {
		totalW += s.Size.Width
		if s.Size.Height > maxH {
			maxH = s.Size.Height
		}
	}
	return x < totalW && y < maxH
}

// randName 新增服务器对话框的默认名
func randName() string {
	return "No." + strconv.Itoa(1000+rand.IntN(9000))
}
