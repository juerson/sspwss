package main

import (
	"embed"
	"io/fs"
	"log"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed assets/app.ico
var trayIcon []byte

// init 显式遍历一次嵌入的前端资产：
// 1) 充当链接器强引用，防止 DCE 把"仅以 io/fs 接口形式引用"的 embed 数据
//    当作死代码剔除（否则 exe 会渲染 Wails 的 "Missing index.html" 默认错误页）；
// 2) 充当构建自检：资产没打进包里时快速失败，而不是运行后白屏。
func init() {
	found := false
	err := fs.WalkDir(assets, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == "index.html" {
			found = true
		}
		return err
	})
	if err != nil || !found {
		log.Fatal("前端资产 (frontend/dist/index.html) 未嵌入，请重新构建：wails3 build")
	}
}

func main() {
	// 先加载配置：窗口初始位置/大小直接用上次记录（无记录、无效或离屏 → 默认居中）
	cfg, _, created, _ := loadConfig()
	app := NewApp(trayIcon, cfg, created)

	wa := application.New(application.Options{
		Name:        "SSP Workers Client",
		Description: "SSP Workers 客户端 GUI（Go + Wails v3，兼容 Go/Rust 双核心）",
		Services: []application.Service{
			application.NewService(app),
		},
		// 单实例锁：设备上只允许运行一个程序实例。重复启动（双击 exe）时
		// 第二个进程把信息发给已运行实例后立即退出，由已运行实例把窗口
		// 唤起到前台（托盘隐藏、最小化的窗口都会被显示出来）。
		SingleInstance: &application.SingleInstanceOptions{
			UniqueID:               "SSP-Workers-Client-GUI-Instance",
			OnSecondInstanceLaunch: app.onSecondInstanceLaunch,
		},
		// 托盘"退出"设置 quitting 标志后才放行退出
		ShouldQuit: func() bool { return app.quitting },
		Assets: application.AssetOptions{
			// 官方示例姿势（badge）：AssetFileServerFS 自动定位 frontend/dist；
			// /wails/runtime 由 webview 请求层统一服务，不依赖 Handler 选择
			Handler: application.AssetFileServerFS(assets),
		},
	})

	winOpts := application.WebviewWindowOptions{
		Name:            "main",
		Title:           "SSP Workers Client",
		Width:           840,
		Height:          720,
		MinWidth:        640,
		MinHeight:       520,
		URL:             "/",
		// 显式背景色：未加载完成前不显示默认黑底
		BackgroundColour: application.NewRGB(255, 255, 255),
		InitialPosition:  application.WindowCentered,
		// 注意：v3 的启动顺序是 ServiceStartup → pendingRun（窗口创建/显示）。
		// 窗口在托盘/代理等服务状态就绪后由框架自动显示，因此不能用 Hidden。
	}
	// 有有效的上次窗口记录 → 创建时就定位（无闪烁）
	if ws := cfg.Window; ws != nil && ws.Width >= 640 && ws.Height >= 520 && positionOnScreen(ws.X, ws.Y) {
		winOpts.InitialPosition = application.WindowXY
		winOpts.X = ws.X
		winOpts.Y = ws.Y
		winOpts.Width = ws.Width
		winOpts.Height = ws.Height
	}
	win := wa.Window.NewWithOptions(winOpts)
	app.SetWindow(win)

	// X 按钮 = 隐藏到托盘（脏标记时由前端确认后隐藏）；托盘"退出"放行关闭。
	// 必须用 RegisterHook（hooks 阶段同步执行，e.Cancel() 后 wails 内置的
	// 默认销毁监听不会运行）；OnWindowEvent 注册的监听在销毁之后并发执行，拦不住。
	win.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		app.onWindowClosing(e)
	})

	if err := wa.Run(); err != nil {
		println("启动失败:", err.Error())
	}
}
