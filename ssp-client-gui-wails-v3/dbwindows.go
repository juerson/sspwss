package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

// ==============================================================================
// 数据库管理窗口 —— ProxyIP（Csv）与 优选地址（Cidrs）
// 复刻旧版 C# 的 Csv.cs / Cidrs.cs 两个窗体：分页浏览、搜索、内置源/自定义 URL
// 下载、本地文件合并、选中删除、清空、去重、备注编辑、随机 IP。
// 前端页面 csv.html / cidrs.html 通过 Call.ByName 调用本文件绑定的方法。
// ==============================================================================

const dbPageSize = 500

// DbPage 分页查询结果（rows 列结构与窗口对应：Csv 为 id,ip,port,country,org；Cidrs 为 id,cidr,remark）
type DbPage struct {
	Rows  [][]any `json:"rows"`
	Total int     `json:"total"`
	Page  int     `json:"page"`
	Pages int     `json:"pages"`
}

// DbResult 写操作结果（前端 toast 展示）
type DbResult struct {
	Processed int    `json:"processed"` // 本次处理条数
	Inserted  int    `json:"inserted"`  // 实际新增条数
	Removed   int    `json:"removed"`   // 去重/删除条数
	Total     int    `json:"total"`     // 操作后的总条数
	Message   string `json:"message"`   // 附加说明
}

// dbWindowDef 窗口定义（懒创建 + 关闭即隐藏，与主窗口的托盘化一致）
type dbWindowDef struct {
	name    string
	title   string
	url     string
	width   int
	height  int
	minW    int
	minH    int
	htmlURL string
}

var (
	csvWindowDef = dbWindowDef{name: "csv", title: "ProxyIP管理", url: "/csv.html",
		width: 1020, height: 760, minW: 780, minH: 540}
	cidrWindowDef = dbWindowDef{name: "cidrs", title: "优选地址管理", url: "/cidrs.html",
		width: 960, height: 700, minW: 720, minH: 520}
)

// openDbWindow 懒创建或唤起窗口；创建时注册"关闭即隐藏"钩子（应用退出时放行销毁）
func (a *App) openDbWindow(field *application.Window, def dbWindowDef) error {
	a.mu.Lock()
	existing := *field
	a.mu.Unlock()

	if existing != nil {
		existing.Show()
		if existing.IsMinimised() {
			existing.Restore()
		}
		existing.Focus()
		nudgeRepaint(existing) // 隐藏→显示偶发白屏：强制一次重绘
		return nil
	}

	win := application.Get().Window.NewWithOptions(application.WebviewWindowOptions{
		Name:             def.name,
		Title:            def.title,
		Width:            def.width,
		Height:           def.height,
		MinWidth:         def.minW,
		MinHeight:        def.minH,
		URL:              def.url,
		BackgroundColour: application.NewRGB(255, 255, 255),
		InitialPosition:  application.WindowCentered,
	})
	win.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		a.mu.Lock()
		quitting := a.quitting
		a.mu.Unlock()
		if quitting {
			return // 应用退出：放行销毁
		}
		e.Cancel()
		win.Hide()
	})

	a.mu.Lock()
	if *field == nil {
		*field = win
	}
	a.mu.Unlock()
	return nil
}

// OpenCsvWindow 打开（或唤起）ProxyIP 管理窗口
func (a *App) OpenCsvWindow() error { return a.openDbWindow(&a.csvWin, csvWindowDef) }

// OpenCidrsWindow 打开（或唤起）优选地址管理窗口
func (a *App) OpenCidrsWindow() error { return a.openDbWindow(&a.cidrWin, cidrWindowDef) }

// ==============================================================================
// 数据库单例（首次使用时按需打开，不拖慢主窗口启动）
// ==============================================================================

func (a *App) proxyDBInstance() (*proxyDB, error) {
	a.dbOnce.Do(func() {
		a.pdbErr = nil
		a.pdb, a.pdbErr = newProxyDB(dbFilePath("proxyip.db"))
	})
	return a.pdb, a.pdbErr
}

func (a *App) cidrDBInstance() (*cidrDB, error) {
	a.cidbOnce.Do(func() {
		a.cdbErr = nil
		a.cdb, a.cdbErr = newCidrDB(dbFilePath("cidrs.db"))
	})
	return a.cdb, a.cdbErr
}

// ==============================================================================
// Csv 窗口（ProxyIP）绑定方法
// ==============================================================================

// CsvGetPage 分页浏览/搜索。search 为空时浏览全部；column ∈ {IP,Port,Country,Organization,全部}；
// mode ∈ {模糊匹配,精准匹配}
func (a *App) CsvGetPage(page int, search string, column string, mode string) (DbPage, error) {
	db, err := a.proxyDBInstance()
	if err != nil {
		return DbPage{}, err
	}
	if page < 1 {
		page = 1
	}
	total, err := db.Count(search, column, mode)
	if err != nil {
		return DbPage{}, err
	}
	pages := (total + dbPageSize - 1) / dbPageSize
	if pages < 1 {
		pages = 1
	}
	if page > pages {
		page = pages
	}
	rows, err := db.Page(page, dbPageSize, search, column, mode)
	if err != nil {
		return DbPage{}, err
	}
	return DbPage{Rows: proxyRowsToAny(rows), Total: total, Page: page, Pages: pages}, nil
}

func proxyRowsToAny(rows []proxyRow) [][]any {
	out := make([][]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, []any{r.ID, r.IP, r.Port, r.Country, r.Org})
	}
	return out
}

// CsvBuiltinDownload 下载内置数据源并写入（overwrite=true 覆盖写入）
func (a *App) CsvBuiltinDownload(overwrite bool) (DbResult, error) {
	var lists [][][4]string
	for _, u := range csvBuiltinURLs {
		content, err := downloadURL(u)
		if err != nil {
			continue // 单个源失败不影响其它源
		}
		if parsed := parseCSVData(content); len(parsed) > 0 {
			lists = append(lists, parsed)
		}
	}
	data := mergeCSVFirst(lists)
	if len(data) == 0 {
		return DbResult{}, fmt.Errorf("内置源未获取到有效数据")
	}
	return a.insertProxyData(data, overwrite)
}

// CsvUrlDownload 从自定义 URL 下载 CSV 数据并写入
func (a *App) CsvUrlDownload(rawURL string, overwrite bool) (DbResult, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return DbResult{}, fmt.Errorf("请输入下载链接")
	}
	if _, err := url.ParseRequestURI(rawURL); err != nil {
		return DbResult{}, fmt.Errorf("下载链接无效")
	}
	content, err := downloadURL(rawURL)
	if err != nil {
		return DbResult{}, fmt.Errorf("下载失败: %w", err)
	}
	data := parseCSVData(content)
	if len(data) == 0 {
		return DbResult{}, fmt.Errorf("未解析到有效数据")
	}
	return a.insertProxyData(data, overwrite)
}

// CsvMergeFiles 弹出多选文件对话框，合并本地 CSV 数据
func (a *App) CsvMergeFiles(overwrite bool) (DbResult, error) {
	paths, err := openDataFiles("选择要合并的CSV数据", "CSV数据", "*.csv;*.txt", a.csvWin)
	if err != nil {
		return DbResult{}, err
	}
	var data [][4]string
	for _, p := range paths {
		content, err := os.ReadFile(p)
		if err != nil {
			return DbResult{}, fmt.Errorf("读取文件失败 %s: %w", filepath.Base(p), err)
		}
		data = append(data, parseCSVData(string(content))...)
	}
	if len(data) == 0 {
		return DbResult{}, fmt.Errorf("未解析到有效数据")
	}
	return a.insertProxyData(data, overwrite)
}

func (a *App) insertProxyData(data [][4]string, overwrite bool) (DbResult, error) {
	db, err := a.proxyDBInstance()
	if err != nil {
		return DbResult{}, err
	}
	var inserted int
	if overwrite {
		inserted, err = db.InsertOverwrite(data)
	} else {
		inserted, err = db.InsertOrIgnore(data)
	}
	if err != nil {
		return DbResult{}, err
	}
	total, err := db.Count("", "", "")
	if err != nil {
		return DbResult{}, err
	}
	return DbResult{Processed: len(data), Inserted: inserted, Total: total}, nil
}

// CsvDeleteRows 删除选中行（按行 Id）
func (a *App) CsvDeleteRows(ids []int64) (DbResult, error) {
	db, err := a.proxyDBInstance()
	if err != nil {
		return DbResult{}, err
	}
	if err := db.DeleteByIDs(ids); err != nil {
		return DbResult{}, err
	}
	total, err := db.Count("", "", "")
	if err != nil {
		return DbResult{}, err
	}
	return DbResult{Removed: len(ids), Total: total}, nil
}

// CsvClearAll 清空全部数据
func (a *App) CsvClearAll() (DbResult, error) {
	db, err := a.proxyDBInstance()
	if err != nil {
		return DbResult{}, err
	}
	if err := db.ClearAll(); err != nil {
		return DbResult{}, err
	}
	return DbResult{Total: 0}, nil
}

// CsvRemoveDuplicates 一键去重（保留每个 IP:Port 的首条），返回删除条数
func (a *App) CsvRemoveDuplicates() (DbResult, error) {
	db, err := a.proxyDBInstance()
	if err != nil {
		return DbResult{}, err
	}
	removed, err := db.RemoveDuplicates()
	if err != nil {
		return DbResult{}, err
	}
	total, err := db.Count("", "", "")
	if err != nil {
		return DbResult{}, err
	}
	return DbResult{Removed: removed, Total: total}, nil
}

// ==============================================================================
// Cidrs 窗口（优选地址）绑定方法
// ==============================================================================

// CidrGetPage 分页浏览/搜索（关键字模糊匹配 CIDR 与备注）
func (a *App) CidrGetPage(page int, search string) (DbPage, error) {
	db, err := a.cidrDBInstance()
	if err != nil {
		return DbPage{}, err
	}
	if page < 1 {
		page = 1
	}
	total, err := db.Count(search)
	if err != nil {
		return DbPage{}, err
	}
	pages := (total + dbPageSize - 1) / dbPageSize
	if pages < 1 {
		pages = 1
	}
	if page > pages {
		page = pages
	}
	rows, err := db.Page(page, dbPageSize, search)
	if err != nil {
		return DbPage{}, err
	}
	out := make([][]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, []any{r.ID, r.CIDR, r.Remark})
	}
	return DbPage{Rows: out, Total: total, Page: page, Pages: pages}, nil
}

// CidrBuiltinDownload 下载内置源（Cloudflare IPv4 + GitHub Release）并写入
func (a *App) CidrBuiltinDownload(overwrite bool) (DbResult, error) {
	var all []string
	seen := make(map[string]bool)
	for _, u := range cidrBuiltinURLs() {
		content, err := downloadURL(u)
		if err != nil {
			continue
		}
		for _, c := range parseAndConvertCidrData(content) {
			if !seen[c] {
				seen[c] = true
				all = append(all, c)
			}
		}
	}
	if len(all) == 0 {
		return DbResult{}, fmt.Errorf("内置源未获取到有效数据")
	}
	return a.insertCidrData(all, overwrite)
}

// CidrUrlDownload 从自定义 URL 下载 CIDR 数据并写入
func (a *App) CidrUrlDownload(rawURL string, overwrite bool) (DbResult, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return DbResult{}, fmt.Errorf("请输入下载链接")
	}
	if _, err := url.ParseRequestURI(rawURL); err != nil {
		return DbResult{}, fmt.Errorf("下载链接无效")
	}
	content, err := downloadURL(rawURL)
	if err != nil {
		return DbResult{}, fmt.Errorf("下载失败: %w", err)
	}
	cidrs := parseAndConvertCidrData(content)
	if len(cidrs) == 0 {
		return DbResult{}, fmt.Errorf("未获取到有效数据")
	}
	return a.insertCidrData(cidrs, overwrite)
}

// CidrMergeFiles 弹出多选文件对话框，导入本地 CIDR 文件
func (a *App) CidrMergeFiles(overwrite bool) (DbResult, error) {
	paths, err := openDataFiles("选择要导入的 CIDR 文件", "文本文件", "*.txt", a.cidrWin)
	if err != nil {
		return DbResult{}, err
	}
	var all []string
	seen := make(map[string]bool)
	for _, p := range paths {
		content, err := os.ReadFile(p)
		if err != nil {
			return DbResult{}, fmt.Errorf("读取文件失败 %s: %w", filepath.Base(p), err)
		}
		for _, c := range parseAndConvertCidrData(string(content)) {
			if !seen[c] {
				seen[c] = true
				all = append(all, c)
			}
		}
	}
	if len(all) == 0 {
		return DbResult{}, fmt.Errorf("未解析到有效数据")
	}
	return a.insertCidrData(all, overwrite)
}

func (a *App) insertCidrData(cidrs []string, overwrite bool) (DbResult, error) {
	db, err := a.cidrDBInstance()
	if err != nil {
		return DbResult{}, err
	}
	data := make([][2]string, 0, len(cidrs))
	for _, c := range cidrs {
		data = append(data, [2]string{c, ""})
	}
	var inserted int
	if overwrite {
		inserted, err = db.InsertOverwrite(data)
	} else {
		inserted, err = db.InsertOrIgnore(data)
	}
	if err != nil {
		return DbResult{}, err
	}
	total, err := db.Count("")
	if err != nil {
		return DbResult{}, err
	}
	return DbResult{Processed: len(cidrs), Inserted: inserted, Total: total}, nil
}

// CidrDeleteRows 删除选中行（按行 Id）
func (a *App) CidrDeleteRows(ids []int64) (DbResult, error) {
	db, err := a.cidrDBInstance()
	if err != nil {
		return DbResult{}, err
	}
	if err := db.DeleteByIDs(ids); err != nil {
		return DbResult{}, err
	}
	total, err := db.Count("")
	if err != nil {
		return DbResult{}, err
	}
	return DbResult{Removed: len(ids), Total: total}, nil
}

// CidrClearAll 清空全部数据
func (a *App) CidrClearAll() (DbResult, error) {
	db, err := a.cidrDBInstance()
	if err != nil {
		return DbResult{}, err
	}
	if err := db.ClearAll(); err != nil {
		return DbResult{}, err
	}
	return DbResult{Total: 0}, nil
}

// CidrRemoveDuplicates 一键去重（保留每个 CIDR 的首条），返回删除条数
func (a *App) CidrRemoveDuplicates() (DbResult, error) {
	db, err := a.cidrDBInstance()
	if err != nil {
		return DbResult{}, err
	}
	removed, err := db.RemoveDuplicates()
	if err != nil {
		return DbResult{}, err
	}
	total, err := db.Count("")
	if err != nil {
		return DbResult{}, err
	}
	return DbResult{Removed: removed, Total: total}, nil
}

// CidrUpdateRemark 更新备注（前端单元格编辑，失焦保存）
func (a *App) CidrUpdateRemark(id int64, remark string) error {
	db, err := a.cidrDBInstance()
	if err != nil {
		return err
	}
	return db.UpdateRemark(id, remark)
}

// CidrRandomIP 从指定 CIDR 网段随机取一个 IP 并写入剪贴板由前端完成，这里只生成
func (a *App) CidrRandomIP(cidr string) (string, error) {
	ip := randomIPFromCIDR(strings.TrimSpace(cidr))
	if ip == "" {
		return "", fmt.Errorf("无法从该地址生成随机 IP")
	}
	return ip, nil
}

// CopyText 写系统剪贴板（子窗口复制 IP:Port / CIDR / 随机 IP 用）。
// 注意：必须走 Go 侧剪贴板 —— v3 前端运行时没有 ClipboardSetText 导出，
// 浏览器 navigator.clipboard 在 WebView2 中的权限也不可靠。
func (a *App) CopyText(text string) bool {
	return application.Get().Clipboard.SetText(text)
}

// fillFieldTargets 子窗口"复制并填充"允许写入的主窗口字段（白名单）
var fillFieldTargets = map[string]bool{
	"fallback": true, // 主窗口 ProxyIP 输入框
	"ip":       true, // 主窗口 优选地址 输入框
}

// CopyAndFill 复制到剪贴板，同时广播 fill-field 事件让主窗口把值填进
// 对应输入框（覆盖原内容；主窗口收到后标记未保存，由用户自行点保存）。
// 仅允许 fillFieldTargets 白名单内的字段，防止任意事件填错目标。
func (a *App) CopyAndFill(field, value string) bool {
	if !fillFieldTargets[field] {
		return false
	}
	ok := application.Get().Clipboard.SetText(value)
	application.Get().Event.Emit("fill-field", map[string]string{"field": field, "value": value})
	return ok
}

// ==============================================================================
// 文件选择对话框
// ==============================================================================

func openDataFiles(title, filterName, pattern string, attach application.Window) ([]string, error) {
	// 多选由 PromptForMultipleSelection 隐式启用（v3 的链式构造无 AllowsMultipleSelection 方法）
	dlg := application.Get().Dialog.OpenFile().
		CanChooseFiles(true).
		AddFilter(filterName, pattern).
		AddFilter("所有文件", "*.*").
		SetTitle(title)
	if attach != nil {
		dlg.AttachToWindow(attach)
	}
	paths, err := dlg.PromptForMultipleSelection()
	if err != nil {
		return nil, fmt.Errorf("打开文件对话框失败: %w", err)
	}
	if len(paths) == 0 {
		return nil, nil // 用户取消
	}
	return paths, nil
}
