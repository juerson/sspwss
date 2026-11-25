# SSP Workers Client GUI（Go + Wails v3）

用 Go + **Wails v3**（2026-10-26 稳定版）重写的统一 GUI，**同时兼容 Go 版（ssp-core.exe）和 Rust 版（ssp-rs.exe）客户端核心**，替代原来的两个 C# WinForms 项目（`ssp-client-go-gui`、`ssp-client-rs-gui`）。

## 特性

- **单实例**：设备上只允许运行一个程序实例（v3 `SingleInstanceOptions` 单实例锁）。重复双击 exe 不会新开窗口——已运行实例会把窗口唤起到前台（托盘隐藏、最小化的都会显示出来）
- **双核心共存与选择**：两个核心 exe 放在同一目录即可，GUI 自动扫描并在"核心"下拉框中列出；默认选中 **Rust 版**，可随时切换
- **运行中冻结**：核心选择、服务器选择等控件在运行中锁定（与旧版行为一致），停止后再切换
- **配置完全兼容**：沿用旧版 `config.json` 的路径与格式（exe 同目录优先，其次 `%APPDATA%\SSP Workers\config.json`），旧配置直接可用；新增顶层字段 `core`（记住核心选择）和 `window`（记住窗口位置/大小），旧版 C# GUI 会忽略未知字段，双向兼容
- **记住窗口位置**：正常关闭窗口后，下次打开还在上次的位置和大小；记录无效或显示器拔掉导致离屏时自动回退默认居中
- **原生系统托盘**（v3 内置，无第三方库）：含服务器选择子菜单、启动/停止、系统代理/开机自启开关
- 界面紧凑自适应：窗口可自由缩放/最大化，内容按 840x620 设计，常规屏幕字体保持原始大小，窗口更小时才整体等比缩小（小屏启动自动适配）
- 系统代理（注册表 + WinINet 刷新）、开机自启、密文输入、保存* 脏标记、日志截断等行为均与旧版一致
- **数据库管理窗口（二期已实现）**：点击主界面参数设置里的 **ProxyIP** / **优选地址** 标签（酒红色）打开对应管理窗口，独立窗口、懒创建、关闭即隐藏可反复唤起
- 单 exe 约 16MB（含纯 Go SQLite），无需安装 .NET；界面由系统自带的 WebView2 渲染

## 双核心参数适配

参数构造集中在 **`cores.go`**（核心注册表）——以后改名或增删核心只需要改这一个文件：

```go
var coreRegistry = []CoreDef{
    {ExeNames: []string{"ssp-rs.exe", "sspcore-rs.exe"}, Kind: "rs", ...},   // 排在前 → 默认选中
    {ExeNames: []string{"ssp-core.exe", "ssp-go.exe", "ssp.exe", "core.exe"}, Kind: "go", ...},
}
```

| 配置字段 | Go 核心 | Rust 核心 |
|---|---|---|
| 服务器地址 | `-f "..."` | `-s "..."` |
| 监听地址 | `-l "..."` | `-l "..."` |
| 令牌 | `-token "..."` | `--token "..."` |
| 优选IP / ProxyIP / UA | `-ip` / `-fallback` / `-ua` | `--ip` / `--fallback` / `--ua` |
| DOH地址 | `-dns "..."`（ECH 查询 DoH，域名/IP 均可） | 仅字面 IP 时传 `--ech-doh "..."`（域名时跳过，用 Rust 内置默认） |
| ECH地址 | use_ech=true 时 `-ech "..."` | use_ech=true 时 `--ech-domain "..."` |
| 开启ECH | true → 裸 `-use-ech` | true → `--ech auto`，false → `--ech off` |
| 路由规则 | `-routing "..."`（rule/global/none） | `--routing "..."`（rule/global/none） |
| 日志级别 | `-loglevel "..."` | `RUST_LOG` 环境变量（GUI 自动映射） |

## 数据库管理窗口（二期）

对应旧版 C# 的 `Csv.cs`（ProxyIP管理）与 `Cidrs.cs`（优选地址管理）两个窗体，功能一一对应：

| | ProxyIP 窗口（csv.html） | 优选地址窗口（cidrs.html） |
|---|---|---|
| 数据库 | exe 同目录 `data\proxyip.db`（旧 C# 版文件直接沿用） | exe 同目录 `data\cidrs.db` |
| 列 | # / IP / Port / Country / Organization | # / CIDR 地址 / 备注（可编辑，失焦保存） |
| 搜索 | 按列（IP/Port/Country/Organization/全部）× 模糊/精准 | 关键字模糊匹配 CIDR 与备注 |
| 分页 | 每页 500 行，`<` / `>` 翻页 | 同左（按前两段数值排序，与旧版一致） |
| 数据获取 | 内置源下载 / 自定义 URL / 合并本地 CSV | 内置源下载 / 自定义 URL / 导入本地 txt |
| 维护 | 删除选中行（≤500 行）、删除重复行、清空全部 | 选中删除、一键去重、清空全部 |
| 点击技巧 | 点行号复制 `IP:Port` 并自动填充主窗口 ProxyIP 输入框（覆盖原内容，标记未保存） | 点行号复制 CIDR 并自动填充主窗口优选地址输入框；点 CIDR 单元格随机生成网段内 IP 并复制 |

- 写入方式：`追加写入(会去重)`（(IP,Port) / CIDR 唯一索引去重）/ `覆盖写入(先清空)`
- 首次打开时数据库为空会**自动执行内置源下载**（与旧版一致）
- SQLite 驱动为 `modernc.org/sqlite`（纯 Go，无 CGO）；表结构与索引和旧版完全相同，
  旧版 C# GUI 已生成的数据库文件可直接使用

### 内置数据源（URL 变更）

旧版走 `https://hk.gh-proxy.org/` 前置代理（代理前缀 + GitHub 地址），该代理已失效；
现改为**直连 GitHub** 后段地址：

- ProxyIP：`FoolVPN-ID/Nautica` proxyList.txt、`papapapapdelesia/Emilia` Country-ALIVE.txt、`tubesteer/proxy_ip` alive.txt
- 优选地址：Cloudflare ips-v4 + `compassvpn/cf-tools` 最新 Release 的 `all_cdn_v4.txt`（经 api.github.com 解析 tag）

## 开发环境要求

- Go 1.25+（纯 Go 编译，无 CGO/MinGW）
- Windows 10/11（自带 WebView2 运行时）
- **无需 Node.js/npm**（前端为纯静态文件，见 `frontend/dist`）

## 构建方法

需要一次性安装 Wails v3 CLI（纯 Go，无 Node/npm）：

```
go install github.com/wailsapp/wails/v3/cmd/wails3@latest
```

生产构建（无黑框 `-H windowsgui`、`production` tag、图标/版本/DPI 清单自动生成嵌入）：

```
wails3 build          # 产物 build/bin/SSP Workers Client.exe
```

调试构建（保留控制台窗口，可看 Wails INF 日志与前端 println 输出）：

```
wails3 task dev       # 产物 build/bin/SSP Workers Client-dev.exe
```

> 注意：直接 `go build` 也能编译，但会缺 `-H windowsgui`（出现黑色控制台窗口），
> 且 Go 链接器可能把仅以 io/fs 接口引用的 embed 前端资产当作死代码剔除
> （渲染 "Missing index.html" 错误页）。main.go 的 init() 已内置资产自检防护，
> 缺资产时会报 "前端资产未嵌入" 而不是白屏/黑屏。

## 使用方法

1. 将核心 exe（Go 版编译产物 `ssp-core.exe` 和/或 Rust 版编译产物 `ssp-rs.exe`）放到与 GUI exe 同一目录
2. 运行 GUI：首次运行自动创建默认配置；在"核心"下拉框选择要使用的核心（默认 Rust），填好服务器地址与令牌后启动
3. 关闭窗口 = 隐藏到托盘（左键/双击托盘图标显示/隐藏）；托盘"退出"才真正退出

## 项目结构

```
ssp-client-gui/
├── main.go          # v3 入口：application.New、窗口创建（含位置恢复）、单实例锁、关闭拦截、embed 自检
├── app.go           # 服务（绑定方法/事件/启动恢复/窗口位置记忆）
├── config.go        # config.json 兼容层（旧字段 + 新增 core/window 字段）
├── cores.go         # ★ 核心注册表：改名/增删核心只改这个文件
├── client.go        # 核心进程启动/停止（CREATE_NO_WINDOW 防黑框、taskkill 整树）、日志流
├── systemproxy.go   # 系统代理（注册表 + InternetSetOption）
├── autostart.go     # 开机自启（HKCU\...\Run）
├── tray.go          # v3 原生系统托盘
├── database.go      # SQLite 双库（data\proxyip.db / data\cidrs.db，表结构与旧 C# 版一致）
├── csvdata.go       # CSV/CIDR 解析、内置源下载（GitHub 直连）、CIDR→/24 拆分、随机 IP
├── dbwindows.go     # ★ 数据库管理窗口生命周期 + 绑定方法（Csv/Cidrs 全部操作）
├── *_test.go        # 参数构造/核心扫描/配置兼容/进程管理/资产服务/解析与数据库测试
├── frontend/dist/   # 纯静态前端（ESM import /wails/runtime.js）
│   ├── index.html / main.js     # 主窗口（含"数据库管理"入口链接）
│   ├── csv.html / csv.js        # ProxyIP 管理窗口
│   ├── cidrs.html / cidrs.js    # 优选地址管理窗口
│   └── dbwin.js                 # 两窗口共享的 toast/确认/剪贴板辅助
├── Taskfile.yml     # wails3 build/dev 任务定义
├── build/windows/   # icon.ico、wails.exe.manifest（permonitorv2）、info.json
└── assets/app.ico   # 托盘与 exe 图标源
```

## 与旧版 C# GUI 的差异

- 新增：单实例锁（重复启动唤起已运行实例）、双核心选择下拉（运行中冻结）、界面紧凑自适应、记住窗口位置
- 新增：核心子进程以 `CREATE_NO_WINDOW` 启动、停止时 taskkill 同样隐藏，不再弹出黑色控制台窗口（旧 C# 版等效 CreateNoWindow）
- 新增：启动核心时在日志中逐项打印完整命令行参数（**令牌打码**、RUST_LOG 环境变量、空值/ECH未启用/DOH非IP 等"未传"项及原因），便于核对每一项是否传给核心
- 修正：启动时按 `last_state.system_proxy_enabled` 重新应用系统代理（旧版因事件抑制不会重放，注册表可能残留旧端口）；启动前校验服务器地址与令牌（旧版交给核心报错）
- 修正：托盘唤起 / 子窗口重复打开的偶发白屏 —— WebView2 隐藏时渲染被挂起（效率模式），恢复可见后渲染器有概率不重绘；唤起后强制 ±1px 尺寸微调触发重绘（立即 + 150ms 兜底各一次）
- 移除：路由规则中的"绕过中国大陆"（bypass_cn）选项 —— 规则引擎 rule 模式已覆盖该场景，旧配置里的 bypass_cn 自动迁移为 rule；日志区改为弹性高度（更矮）
- 内置数据源直连 GitHub（旧版 hk.gh-proxy.org 前置代理已失效）；内置源合并去重、覆盖/追加写入、去重保留首条等行为与旧版一致
- 移除："最小化到托盘"气泡提示（纯装饰）
- 旧版的"异常退出自动重启"原本就未实现（README 过期描述），本版同样不实现

## 测试

```
go test ./...
```
覆盖：双核心参数构造、核心扫描优先级、配置 round-trip 与旧配置兼容（含 core/window 新字段）、bypass_cn 自动迁移、DOH 域名/IP 分流、进程启动/停止/整树杀、CSV/CIDR 解析与 /24 拆分、随机 IP 归属网段、SQLite 双库 round-trip（分页/搜索/去重/删除/覆盖写入）、数据库窗口页面资产嵌入等。
