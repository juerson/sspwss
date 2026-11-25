using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace SSPWorkersGUI
{
    public partial class App : Form
    {
        #region 字段和属性
        private NotifyIcon? notifyIcon;
        private Process? _runningProcess; // 当前运行的进程
        private ConfigData? configData; // 配置数据
        private bool _dirty = false; // 是否有未保存的修改
        private bool _loading = false; // 是否正在加载配置，防止触发事件
        private ComboBoxItem? previousItem;

        // 托盘菜单项引用，用于状态同步
        private ToolStripMenuItem? _trayMenuServerGroup;
        private ToolStripMenuItem? _trayMenuProxyItem;
        private ToolStripMenuItem? _trayMenuAutoStartItem;
        private ToolStripMenuItem? _trayMenuStartItem;
        private ToolStripMenuItem? _trayMenuStopItem;

        // 路由规则映射（有序：rule 为默认推荐项）
        private readonly (string Id, string Name)[] routingModes =
        {
            ("global", "全局模式"),
            ("rule", "规则模式"),
            ("none", "直连模式"),
        };

        // 日记级别映射
        private readonly Dictionary<string, string> logLevelMap = new()
        {
            { "DEBUG", "DEBUG" },
            { "INFO", "INFO" },
            { "WARN", "WARN" },
            { "ERROR", "ERROR" },
        };

        // 是否开启ECH映射
        private readonly Dictionary<string, string> enableECHMap = new()
        {
            { "true", "启用" },
            { "false", "禁用" },
        };

        // 支持的内核列表（只在程序目录中实际存在时才加入下拉框）
        // ssp-rs 优先，存在时排在第一位并作为默认选中
        private readonly (string FileName, string Description)[] supportedCores =
        {
            ("ssp-rs.exe", "ssp-rs.exe（Rust）"),
            ("ssp-core.exe", "ssp-core.exe（Go）"),
        };

        // 配置读取选项：兼容尾随逗号与注释
        private static readonly JsonSerializerOptions jsonReadOptions = new()
        {
            AllowTrailingCommas = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
        };
        #endregion

        #region 窗体初始化和事件处理
        public App()
        {
            InitializeComponent();
            this.StartPosition = FormStartPosition.CenterScreen;
            InitTray();

            textBoxToken.EnablePasswordToggle();
            textBoxServer.EnablePasswordToggle();
            textBoxIp.EnablePasswordToggle();
            textBoxFallback.EnablePasswordToggle();

            this.FormClosing += Form1_FormClosing;
            this.FormClosed += Form1_FormClosed;
            this.Resize += Form1_Resize;

            // 初始化顺序：路由框 -> 隐藏启动框 -> 内核框 -> 加载配置 -> 绑定事件 -> 填充状态
            InitializeRoutingComboBox();
            InitializeLogLevelComboBox();
            InitializeEnableECHComboBox();
            InitializeAutoStartHideCheckBox();
            InitializeCoreComboBox();
            LoadConfig();
            BindDirtyEvents();
            FillLastState();

            // 初始化托盘菜单状态同步
            SyncTrayMenuInitialState();
        }

        // 加载图标
        private Icon? LoadIcon()
        {
            try
            {
                var assembly = typeof(App).Assembly;
                var resourceNames = assembly.GetManifestResourceNames();

                string[] possibleNames =
                {
                    "SSPWorkersGUI.app.ico",
                    "SSPWorkersGUI.logo.ico",
                    "app.ico",
                    "logo.ico",
                };

                foreach (string name in possibleNames)
                {
                    if (resourceNames.Contains(name))
                    {
                        var stream = assembly.GetManifestResourceStream(name);
                        if (stream != null)
                        {
                            return new Icon(stream);
                        }
                    }
                }
            }
            catch
            {
                // 如果加载嵌入图标失败，尝试从文件加载
                string icoPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "app.ico");
                if (File.Exists(icoPath))
                {
                    return new Icon(icoPath);
                }
            }
            return null;
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            this.CenterToScreen();

            // 设置窗体图标
            var icon = LoadIcon();
            if (icon != null)
            {
                this.Icon = icon;
            }
        }

        // 关闭窗体最小化到托盘
        private void Form1_FormClosing(object? sender, FormClosingEventArgs e)
        {
            if (e.CloseReason == CloseReason.UserClosing)
            {
                // 1. 检查未保存更改
                if (_dirty)
                {
                    var result = MessageBox.Show(
                        "有未保存的更改，确定要退出吗？",
                        "提示",
                        MessageBoxButtons.YesNo,
                        MessageBoxIcon.Warning
                    );

                    if (result == DialogResult.No)
                    {
                        e.Cancel = true;
                        return;
                    }
                }

                // 2. 在隐藏父窗体前，关闭所有属于“我”的子窗体
                var ownedForms = this.OwnedForms.ToList(); // 获取当前窗体拥有的所有子窗体快照
                foreach (var subForm in ownedForms)
                {
                    subForm.Close();
                }

                // 3. 执行隐藏逻辑
                e.Cancel = true;
                this.Hide();
                notifyIcon?.ShowBalloonTip(1000, "提示", "程序已最小化到托盘", ToolTipIcon.Info);
            }
        }

        // 窗体真正关闭（程序退出）时，执行两个库的 WAL 检查点，避免 data 目录残留 -wal/-shm 文件
        private void Form1_FormClosed(object? sender, FormClosedEventArgs e)
        {
            try
            {
                DatabaseHelper.Instance.CheckpointWal();
                CidrDatabaseHelper.Instance.CheckpointWal();
            }
            catch
            {
                // 检查点失败不阻断退出，SQLite 下次打开时会自动恢复
            }
        }

        // 接收其他实例发来的“显示窗口”消息（用于防止多开）
        protected override void WndProc(ref Message m)
        {
            if (SingleInstance.ActivateMessage != 0 && m.Msg == SingleInstance.ActivateMessage)
            {
                ShowAndActivateWindow();
                return;
            }

            base.WndProc(ref m);
        }

        // 把窗口从托盘/最小化状态恢复并显示到最前面
        private void ShowAndActivateWindow()
        {
            if (!this.Visible)
            {
                this.Show();
            }

            if (this.WindowState == FormWindowState.Minimized)
            {
                this.WindowState = FormWindowState.Normal;
            }

            this.Activate();
            this.BringToFront();

            // 再抢一次前台，确保窗口浮到最上层
            SetForegroundWindow(this.Handle);
        }

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        // 调整大小，正常最小化到任务栏
        private void Form1_Resize(object? sender, EventArgs e)
        {
            // 隐藏窗体
            // if (this.WindowState == FormWindowState.Minimized)
            // {
            //     this.Hide();
            // }
        }
        #endregion

        #region UI组件初始化
        // 初始化路由模式下拉框
        private void InitializeRoutingComboBox()
        {
            comboBoxRouting.Items.Clear();

            foreach (var (id, name) in routingModes)
            {
                comboBoxRouting.Items.Add(new RoutingModeItem { Id = id, Name = name });
            }

            // 默认选择规则分流（与 ssp-client-rs / ssp-client-go 默认一致）
            SelectRoutingMode("rule");
        }

        // 按路由模式 Id 选中下拉框项；找不到时保持默认（第一项）
        private void SelectRoutingMode(string routingId)
        {
            for (int i = 0; i < comboBoxRouting.Items.Count; i++)
            {
                if (comboBoxRouting.Items[i] is RoutingModeItem item && item.Id == routingId)
                {
                    comboBoxRouting.SelectedIndex = i;
                    return;
                }
            }
            if (comboBoxRouting.Items.Count > 0 && comboBoxRouting.SelectedIndex < 0)
            {
                comboBoxRouting.SelectedIndex = 0;
            }
        }

        // 初始化日志级别下拉框
        private void InitializeLogLevelComboBox()
        {
            comboBoxLogLevel.Items.Clear();

            foreach (var kvp in logLevelMap)
            {
                comboBoxLogLevel.Items.Add(new LogLevelItem { Id = kvp.Key, Name = kvp.Value });
            }

            // 默认选择INFO
            for (int i = 0; i < comboBoxLogLevel.Items.Count; i++)
            {
                if (comboBoxLogLevel.Items[i] is LogLevelItem item && item.Id == "INFO")
                {
                    comboBoxLogLevel.SelectedIndex = i;
                    break;
                }
            }
        }

        // 初始化是否开启ECH下拉框
        private void InitializeEnableECHComboBox()
        {
            comboBoxEnableECH.Items.Clear();

            foreach (var kvp in enableECHMap)
            {
                comboBoxEnableECH.Items.Add(new EnableECHItem { Id = kvp.Key, Name = kvp.Value });
            }

            // 默认选择启用
            for (int i = 0; i < comboBoxEnableECH.Items.Count; i++)
            {
                if (comboBoxEnableECH.Items[i] is EnableECHItem item && item.Id == "true")
                {
                    comboBoxEnableECH.SelectedIndex = i;
                    break;
                }
            }
        }

        // 初始化隐藏启动CheckBox
        private void InitializeAutoStartHideCheckBox()
        {
            // 初始状态为未勾选，等待开机启动CheckBox勾选
            checkBoxAutoStartHide.Checked = false;
            checkBoxAutoStartHide.Enabled = false;
        }

        // 自动识别程序目录中存在的内核，只有实际存在才加入下拉框
        private void InitializeCoreComboBox()
        {
            comboBoxCore.Items.Clear();

            foreach (var (fileName, description) in supportedCores)
            {
                string? fullPath = FindCorePath(fileName);
                if (fullPath != null)
                {
                    comboBoxCore.Items.Add(
                        new CoreItem
                        {
                            FileName = fileName,
                            FullPath = fullPath,
                            Name = description,
                        }
                    );
                }
            }

            if (comboBoxCore.Items.Count > 0)
            {
                comboBoxCore.SelectedIndex = 0;
            }
        }

        // 查找内核文件：优先程序目录，其次当前目录，最后向上查找（方便开发时直接运行）
        private static string? FindCorePath(string fileName)
        {
            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            string? FindIn(string? directory)
            {
                if (string.IsNullOrEmpty(directory))
                    return null;

                string fullPath = Path.GetFullPath(Path.Combine(directory, fileName));
                if (!visited.Add(fullPath))
                    return null;

                return File.Exists(fullPath) ? fullPath : null;
            }

            string? direct = FindIn(Application.StartupPath);
            if (direct != null)
                return direct;

            direct = FindIn(Environment.CurrentDirectory);
            if (direct != null)
                return direct;

            // 开发环境（bin\Debug 等）允许向上查找项目目录中的内核
            if (
                !Application.StartupPath.Contains(
                    $"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}",
                    StringComparison.OrdinalIgnoreCase
                )
            )
            {
                return null;
            }

            DirectoryInfo? dir = new DirectoryInfo(Application.StartupPath);
            for (int i = 0; i < 4; i++)
            {
                dir = dir.Parent;
                if (dir == null)
                    break;

                direct = FindIn(dir.FullName);
                if (direct != null)
                    return direct;
            }

            return null;
        }

        // 选择内核：ssp-rs 存在时始终默认选中它；否则按配置恢复或使用第一项
        private void SelectCore(string? coreFileName)
        {
            if (comboBoxCore.Items.Count == 0)
                return;

            // ssp-rs 优先
            for (int i = 0; i < comboBoxCore.Items.Count; i++)
            {
                if (
                    comboBoxCore.Items[i] is CoreItem rsItem
                    && string.Equals(
                        rsItem.FileName,
                        "ssp-rs.exe",
                        StringComparison.OrdinalIgnoreCase
                    )
                )
                {
                    comboBoxCore.SelectedIndex = i;
                    if (configData != null)
                        configData.core = rsItem.FileName;
                    return;
                }
            }

            if (comboBoxCore.SelectedIndex < 0)
            {
                comboBoxCore.SelectedIndex = 0;
            }

            if (!string.IsNullOrWhiteSpace(coreFileName))
            {
                string fileName = Path.GetFileName(coreFileName.Trim());

                for (int i = 0; i < comboBoxCore.Items.Count; i++)
                {
                    if (
                        comboBoxCore.Items[i] is CoreItem item
                        && string.Equals(item.FileName, fileName, StringComparison.OrdinalIgnoreCase)
                    )
                    {
                        comboBoxCore.SelectedIndex = i;
                        if (configData != null)
                            configData.core = item.FileName;
                        return;
                    }
                }
            }

            // 配置中的内核在当前目录不存在：使用实际存在的第一项
            if (configData != null && comboBoxCore.SelectedItem is CoreItem fallbackItem)
            {
                configData.core = fallbackItem.FileName;
            }
        }

        // 内核选择变化时写入配置（保留其他未保存的编辑状态）
        private void ComboBoxCore_SelectedIndexChanged(object? sender, EventArgs e)
        {
            if (_loading || configData == null)
                return;

            if (comboBoxCore.SelectedItem is CoreItem item)
            {
                configData.core = item.FileName;
                SaveConfigToFile(false);
            }
        }

        private void BindDirtyEvents()
        {
            textBoxServer.TextChanged += AnyTextBox_TextChanged;
            textBoxToken.TextChanged += AnyTextBox_TextChanged;
            textBoxListen.TextChanged += AnyTextBox_TextChanged;
            textBoxDns.TextChanged += AnyTextBox_TextChanged;
            textBoxEch.TextChanged += AnyTextBox_TextChanged;
            textBoxIp.TextChanged += AnyTextBox_TextChanged;
            textBoxFallback.TextChanged += AnyTextBox_TextChanged;
            textBoxUA.TextChanged += AnyTextBox_TextChanged;
            comboBoxRouting.SelectedIndexChanged += AnyTextBox_TextChanged;
            comboBoxLogLevel.SelectedIndexChanged += AnyTextBox_TextChanged;
            comboBoxEnableECH.SelectedIndexChanged += AnyTextBox_TextChanged;
            comboBoxCore.SelectedIndexChanged += ComboBoxCore_SelectedIndexChanged;
        }
        #endregion

        #region 日志和进程管理
        private void AppendLog(string text)
        {
            if (textBoxLog.InvokeRequired)
            {
                textBoxLog.BeginInvoke(new Action<string>(AppendLog), text);
                return;
            }

            // 检查用户是否正在查看历史日志（不在底部）
            bool isAtBottom = textBoxLog.SelectionStart >= textBoxLog.TextLength - 100;

            // 限制日志长度，防止内存爆满
            const int maxLogLines = 1000;
            const int maxLogLength = 50000;

            // 添加新日志
            textBoxLog.AppendText(text + Environment.NewLine);

            // 检查并限制日志长度
            if (textBoxLog.Lines.Length > maxLogLines || textBoxLog.TextLength > maxLogLength)
            {
                // 保留最后的一半日志
                var lines = textBoxLog.Lines;
                var keepLines = Math.Min(maxLogLines / 2, lines.Length / 2);
                var startIndex = lines.Length - keepLines;

                if (startIndex > 0)
                {
                    var newLines = lines.Skip(startIndex).ToArray();
                    textBoxLog.Lines = newLines;

                    // 添加截断提示
                    textBoxLog.AppendText(
                        $"[日志已截断，保留最后{keepLines}行]{Environment.NewLine}"
                    );
                }
            }

            // 只有在用户原本在底部时才自动滚动
            if (isAtBottom)
            {
                textBoxLog.SelectionStart = textBoxLog.TextLength;
                textBoxLog.ScrollToCaret();
            }
        }

        // 杀掉进程
        private void KillRunningProcess()
        {
            if (_runningProcess == null)
                return;

            try
            {
                // 检查进程是否仍在运行
                if (!_runningProcess.HasExited)
                {
                    // 对于控制台程序，CloseMainWindow() 无效，直接尝试优雅关闭
                    try
                    {
                        // 先尝试发送 Ctrl+C 信号进行优雅关闭
                        _runningProcess.StandardInput?.WriteLine("exit");

                        // 等待 2 秒让程序优雅退出
                        if (!_runningProcess.WaitForExit(2000))
                        {
                            _runningProcess.Kill(true); // true：连子进程一起杀
                        }
                    }
                    catch (InvalidOperationException)
                    {
                        // 如果 StandardInput 不可用，直接强制关闭
                        _runningProcess.Kill(true);
                    }
                }
            }
            catch (Exception ex)
            {
                AppendLog($"停止进程时发生错误: {ex.Message}");
            }
            finally
            {
                _runningProcess?.Dispose();
                _runningProcess = null;
            }
        }
        #endregion

        #region 托盘菜单管理
        private void InitTray()
        {
            var tray = new NotifyIcon();

            // 设置托盘图标
            var icon = LoadIcon();
            if (icon != null)
            {
                tray.Icon = icon;
            }

            tray.Text = "SSP Workers Client";
            tray.Visible = true;

            // 双击托盘图标显示/隐藏窗体
            tray.DoubleClick += (_, __) =>
            {
                ToggleWindowVisibility();
            };

            var menu = new ContextMenuStrip();

            // 设置菜单字体大小，例如 11pt，默认是 9pt 左右
            menu.Font = new Font("Microsoft YaHei", 11, FontStyle.Regular);

            // 1. 显示/隐藏菜单项（最开头）
            var showHideMenuItem = new ToolStripMenuItem("显示/隐藏");
            showHideMenuItem.Click += (_, __) =>
            {
                ToggleWindowVisibility();
            };
            menu.Items.Add(showHideMenuItem);
            menu.Items.Add(new ToolStripSeparator());

            // 2. 启动控制菜单项（顶层）
            var startMenuItem = new ToolStripMenuItem("启动服务");
            startMenuItem.Enabled = buttonStart.Enabled;
            startMenuItem.Click += (_, __) =>
            {
                if (buttonStart.Enabled)
                    ButtonStart_Click(this, EventArgs.Empty);
            };
            menu.Items.Add(startMenuItem);

            var stopMenuItem = new ToolStripMenuItem("停止服务");
            stopMenuItem.Enabled = buttonStop.Enabled;
            stopMenuItem.Click += (_, __) =>
            {
                if (buttonStop.Enabled)
                    ButtonStop_Click(this, EventArgs.Empty);
            };
            menu.Items.Add(stopMenuItem);
            menu.Items.Add(new ToolStripSeparator());

            // 3. 系统设置菜单项（顶层，带状态图标）
            var proxyMenuItem = new ToolStripMenuItem("开启系统代理");
            proxyMenuItem.Checked = checkBoxSystemProxy.Checked;
            proxyMenuItem.Click += (_, __) =>
            {
                checkBoxSystemProxy.Checked = !checkBoxSystemProxy.Checked;
                proxyMenuItem.Checked = checkBoxSystemProxy.Checked;
                SetSystemProxy(checkBoxSystemProxy.Checked);
            };
            menu.Items.Add(proxyMenuItem);

            var autoStartMenuItem = new ToolStripMenuItem("开机启动");
            autoStartMenuItem.Checked = checkBoxAutoStart.Checked;
            autoStartMenuItem.Click += (_, __) =>
            {
                checkBoxAutoStart.Checked = !checkBoxAutoStart.Checked;
                autoStartMenuItem.Checked = checkBoxAutoStart.Checked;
                SetAutoStart(checkBoxAutoStart.Checked);
            };
            menu.Items.Add(autoStartMenuItem);
            menu.Items.Add(new ToolStripSeparator());

            // 4. 服务器选择分组
            var serverGroup = new ToolStripMenuItem("服务器选择");
            // 服务器选择主菜单项始终保持可用，子菜单项根据运行状态控制
            menu.Items.Add(serverGroup);

            // 添加服务器选择菜单项
            RefreshTrayServerMenu(serverGroup);

            // 5. 分隔线
            menu.Items.Add(new ToolStripSeparator());

            // 6. 退出菜单项
            var exitMenuItem = new ToolStripMenuItem("退出");
            exitMenuItem.Click += (_, __) =>
            {
                KillRunningProcess();
                tray.Visible = false; // 先隐藏托盘
                Application.Exit();
            };
            menu.Items.Add(exitMenuItem);

            // 保存托盘菜单项引用以便更新
            _trayMenuServerGroup = serverGroup;
            _trayMenuProxyItem = proxyMenuItem;
            _trayMenuAutoStartItem = autoStartMenuItem;
            _trayMenuStartItem = startMenuItem;
            _trayMenuStopItem = stopMenuItem;

            tray.ContextMenuStrip = menu;
            notifyIcon = tray; // 保存引用
        }

        // 切换窗口显示/隐藏状态
        private void ToggleWindowVisibility()
        {
            if (this.Visible)
            {
                this.Hide();
            }
            else
            {
                this.Show();
                this.WindowState = FormWindowState.Normal;
                this.BringToFront();
            }
        }

        // 同步托盘菜单初始状态
        private void SyncTrayMenuInitialState()
        {
            // 同步系统代理状态
            if (_trayMenuProxyItem != null)
                _trayMenuProxyItem.Checked = checkBoxSystemProxy.Checked;

            // 同步开机启动状态
            if (_trayMenuAutoStartItem != null)
                _trayMenuAutoStartItem.Checked = checkBoxAutoStart.Checked;

            // 同步启动/停止状态
            if (_trayMenuStartItem != null)
                _trayMenuStartItem.Enabled = buttonStart.Enabled;
            if (_trayMenuStopItem != null)
                _trayMenuStopItem.Enabled = buttonStop.Enabled;

            // 同步服务器选择状态
            if (_trayMenuServerGroup != null)
            {
                RefreshTrayServerMenu(_trayMenuServerGroup);
                // 服务器选择主菜单项始终保持可用，不根据运行状态禁用
                _trayMenuServerGroup.Enabled = true;
            }
        }

        // 刷新托盘服务器菜单
        private void RefreshTrayServerMenu(ToolStripMenuItem serverGroup)
        {
            serverGroup.DropDownItems.Clear();

            if (configData?.servers == null)
                return;

            // 检查运行状态
            bool isRunning = _runningProcess != null && !_runningProcess.HasExited;

            foreach (var server in configData.servers)
            {
                var serverMenuItem = new ToolStripMenuItem(server.name);
                serverMenuItem.Checked = server.id == configData.current_server_id;

                serverMenuItem.Enabled = !isRunning; // 运行时禁用选择

                serverMenuItem.Click += (_, __) =>
                {
                    // 在点击时重新检查运行状态
                    bool currentlyRunning = _runningProcess != null && !_runningProcess.HasExited;
                    if (currentlyRunning)
                        return; // 运行时不允许切换

                    // 更新UI界面
                    var item = comboBoxServer
                        .Items.Cast<ComboBoxItem>()
                        .FirstOrDefault(x => x.Id == server.id);
                    if (item != null)
                    {
                        _loading = true;
                        comboBoxServer.SelectedItem = item;
                        configData!.current_server_id = item.Id;
                        FillServerDetails(item.ServerInfo);
                        previousItem = item;
                        _loading = false;

                        // 静默保存配置
                        SaveConfigToFile(false);
                    }

                    // 更新托盘菜单状态
                    RefreshTrayServerMenu(serverGroup);
                };
                serverGroup.DropDownItems.Add(serverMenuItem);
            }
        }
        #endregion

        #region 配置文件管理
        // 读取配置
        private void LoadConfig()
        {
            // 定义配置文件查找路径数组
            string[] configPaths =
            {
                Path.Combine(Application.StartupPath, "config.json"), // 主程序的根目录
                Path.Combine( // AppData目录
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "SSP Workers",
                    "config.json"
                ),
            };

            // 按优先级查找配置文件
            string configPath = string.Empty;
            foreach (string path in configPaths)
            {
                if (File.Exists(path))
                {
                    configPath = path;
                    break;
                }
            }

            // 如果没有找到任何配置文件，创建默认配置
            if (string.IsNullOrEmpty(configPath))
            {
                configPath = configPaths[1]; // 使用AppData路径
                CreateDefaultConfig(configPath);
            }

            var json = File.ReadAllText(configPath);
            try
            {
                configData = ParseConfig(json);
            }
            catch (JsonException ex)
            {
                MessageBox.Show("配置文件格式错误：" + ex.Message);
                return;
            }

            if (configData == null)
            {
                MessageBox.Show("配置文件内容为空");
                return;
            }

            // 补全 / 修正 window：配置缺失，或记录了最小化时的负坐标（如 -21333）时改为居中
            if (EnsureWindowConfig(configData))
            {
                SaveConfigToFile(false);
            }

            comboBoxServer.Items.Clear();

            if (configData.servers == null)
            {
                MessageBox.Show("servers 配置为空");
                return;
            }

            // 恢复上次选择的内核（只恢复当前目录中真实存在的内核）
            SelectCore(configData.core);

            foreach (var s in configData.servers)
            {
                comboBoxServer.Items.Add(
                    new ComboBoxItem
                    {
                        Id = s.id,
                        Name = s.name,
                        ServerInfo = s,
                    }
                );
            }

            var currentItem = comboBoxServer
                .Items.Cast<ComboBoxItem>()
                .FirstOrDefault(x => x.Id == configData.current_server_id);

            if (currentItem != null)
            {
                comboBoxServer.SelectedItem = currentItem;
                FillServerDetails(currentItem.ServerInfo);
                previousItem = currentItem; // 初始化 previousItem
            }

            comboBoxServer.SelectedIndexChanged += ComboBox1_SelectedIndexChanged;
        }

        // 解析配置；兼容某些外部程序写入时对象属性之间漏掉逗号的历史文件
        private static ConfigData? ParseConfig(string json)
        {
            try
            {
                return JsonSerializer.Deserialize<ConfigData>(json, jsonReadOptions);
            }
            catch (JsonException)
            {
                // 在 "} 换行 "属性名"" 之间补一个逗号
                string repaired = Regex.Replace(json, @"\}(\s*"")", "},$1");
                return JsonSerializer.Deserialize<ConfigData>(repaired, jsonReadOptions);
            }
        }

        // 补全 / 修正 window 字段。
        // window 有效（坐标在屏幕内、尺寸合理）时原样保留；
        // 缺失或记录了最小化时的负坐标（如 -21333）时，改为居中，返回 true 表示需要写回文件。
        private bool EnsureWindowConfig(ConfigData config)
        {
            if (
                TryReadWindow(config.window, out int x, out int y, out int width, out int height)
                && IsWindowUsable(x, y, width, height)
            )
            {
                return false;
            }

            // 尺寸也无效时使用当前窗体的尺寸；同时不低于 Wails 端可接受的最小尺寸
            int useWidth;
            int useHeight;
            if (width < 200 || height < 200)
            {
                useWidth = Math.Max(this.Width, 640);
                useHeight = Math.Max(this.Height, 520);
            }
            else
            {
                useWidth = width;
                useHeight = height;
            }

            Rectangle bounds = GetCenteredWindowBounds(useWidth, useHeight);
            config.window = JsonSerializer.SerializeToElement(
                new
                {
                    x = bounds.X,
                    y = bounds.Y,
                    width = bounds.Width,
                    height = bounds.Height,
                }
            );

            return true;
        }

        // 读取 window 对象中的 x/y/width/height（必须是整数）
        private static bool TryReadWindow(
            JsonElement? element,
            out int x,
            out int y,
            out int width,
            out int height
        )
        {
            x = 0;
            y = 0;
            width = 0;
            height = 0;

            if (element is not JsonElement value || value.ValueKind != JsonValueKind.Object)
                return false;

            return value.TryGetProperty("x", out JsonElement jx)
                && jx.TryGetInt32(out x)
                && value.TryGetProperty("y", out JsonElement jy)
                && jy.TryGetInt32(out y)
                && value.TryGetProperty("width", out JsonElement jw)
                && jw.TryGetInt32(out width)
                && value.TryGetProperty("height", out JsonElement jh)
                && jh.TryGetInt32(out height);
        }

        // window 坐标是否可用：尺寸不能过小，坐标不能是负数/最小化坐标，且必须与某个屏幕相交
        private static bool IsWindowUsable(int x, int y, int width, int height)
        {
            if (width < 200 || height < 200)
                return false;

            // 最小化时 Windows 会返回 -21333 / -32000 之类的坐标
            if (x <= -200 || y <= -100)
                return false;

            var rect = new Rectangle(x, y, width, height);
            return Screen.AllScreens.Any(screen => screen.WorkingArea.IntersectsWith(rect));
        }

        // 按给定尺寸计算主屏工作区内的居中位置
        private static Rectangle GetCenteredWindowBounds(int? width = null, int? height = null)
        {
            int w = width is > 0 ? width.Value : 700;
            int h = height is > 0 ? height.Value : 720;

            Rectangle area = Screen.PrimaryScreen?.WorkingArea ?? SystemInformation.WorkingArea;
            int x = area.Left + Math.Max(0, (area.Width - w) / 2);
            int y = area.Top + Math.Max(0, (area.Height - h) / 2);

            return new Rectangle(x, y, w, h);
        }

        // 创建默认配置
        private void CreateDefaultConfig(string configPath)
        {
            // 确保目录存在
            string directory = Path.GetDirectoryName(configPath)!;
            if (!Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            // 生成UUID和随机端口
            string serverId = Guid.NewGuid().ToString();
            int randomPort = GenerateRandomPort();

            // 创建默认配置数据
            configData = new ConfigData
            {
                current_server_id = serverId,
                servers = new[]
                {
                    new Server
                    {
                        id = serverId,
                        name = "默认服务器",
                        server = "worker.username.workers.dev:443",
                        listen = $"127.0.0.1:{randomPort}",
                        token = "",
                        ip = "www.visa.com,104.18.13.155,104.18.12.0/24",
                        dns = "https://223.5.5.5/dns-query",
                        fallback = "",
                        ua = GetDefaultBrowserUA(),
                        ech = "cloudflare-ech.com",
                        loglevel = "INFO",
                        use_ech = "false",
                        routing_mode = "rule",
                    },
                },
                last_state = new LastState
                {
                    system_proxy_enabled = false,
                    auto_start_checked = false,
                    was_running = false,
                },
            };

            // 默认内核：取当前目录中第一个真实存在的内核
            if (comboBoxCore.SelectedItem is CoreItem defaultCore)
            {
                configData.core = defaultCore.FileName;
            }

            // 新配置没有历史窗口记录：写入居中坐标，避免出现 -21333 之类的负值
            EnsureWindowConfig(configData);

            // 保存默认配置到文件
            var options = new JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            };

            string json = JsonSerializer.Serialize(configData, options);
            File.WriteAllText(configPath, json);

            MessageBox.Show("已创建默认配置文件");
        }

        // 生成随机端口，避开5位数字端口（10000-65535）
        private int GenerateRandomPort()
        {
            Random random = new Random();
            int port;

            // 尝试生成4位数字端口（1024-9999）
            int attempts = 0;
            do
            {
                port = random.Next(1024, 10000); // 1024-9999范围
                attempts++;

                // 检查端口是否可用
                if (IsPortAvailable(port))
                {
                    return port;
                }
            } while (attempts < 50); // 最多尝试50次

            // 如果4位端口都用完了，使用系统分配
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();

            return port;
        }

        // 检查端口是否可用
        private bool IsPortAvailable(int port)
        {
            try
            {
                using var listener = new TcpListener(IPAddress.Loopback, port);
                listener.Start();
                listener.Stop();
                return true;
            }
            catch
            {
                return false;
            }
        }

        private void SaveConfigToFile()
        {
            SaveConfigToFile(true);
        }

        private void SaveConfigToFile(bool showMessage)
        {
            try
            {
                // 定义配置文件查找路径数组
                string[] configPaths =
                {
                    Path.Combine(Application.StartupPath, "config.json"), // 根目录
                    Path.Combine( // AppData目录
                        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                        "SSP Workers",
                        "config.json"
                    ),
                };

                // 按优先级查找现有配置文件，保存到相同位置
                string configPath = string.Empty;
                foreach (string path in configPaths)
                {
                    if (File.Exists(path))
                    {
                        configPath = path;
                        break;
                    }
                }

                // 如果都没有找到，默认保存到AppData
                if (string.IsNullOrEmpty(configPath))
                {
                    configPath = configPaths[1];
                }

                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                };

                string json = JsonSerializer.Serialize(configData, options);
                File.WriteAllText(configPath, json);

                if (showMessage)
                {
                    MessageBox.Show("保存成功");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("保存失败：" + ex.Message);
            }
        }
        #endregion

        #region 服务器管理
        private void ComboBox1_SelectedIndexChanged(object? sender, EventArgs e)
        {
            if (comboBoxServer.SelectedItem is not ComboBoxItem item)
                return;

            _loading = true;
            configData!.current_server_id = item.Id;

            // FillServerDetails 内部也会设置 _loading = true
            FillServerDetails(item.ServerInfo);

            previousItem = item;
            _loading = false;

            // 重置保存状态，去掉"*"号
            _dirty = false;
            buttonSave.Text = "保存";

            // 同步托盘菜单
            if (_trayMenuServerGroup != null)
            {
                RefreshTrayServerMenu(_trayMenuServerGroup);
            }

            // 静默保存配置（只保存当前服务器ID）
            SaveConfigToFile(false);
        }

        private void FillServerDetails(Server server)
        {
            _loading = true; // 屏蔽 TextChanged

            textBoxServer.Text = server.server;
            textBoxListen.Text = server.listen;
            textBoxToken.Text = server.token;
            textBoxIp.Text = server.ip;
            textBoxDns.Text = server.dns;
            textBoxEch.Text = server.ech;
            textBoxFallback.Text = server.fallback;
            textBoxUA.Text = server.ua;

            // 设置日志级别下拉框
            var logLevelText = server.loglevel ?? "INFO";
            foreach (var item in comboBoxLogLevel.Items)
            {
                if (item is LogLevelItem logLevelItem && logLevelItem.Id == logLevelText)
                {
                    comboBoxLogLevel.SelectedItem = item;
                    break;
                }
            }

            // 设置是否开启ECH下拉框
            var enableECHText = server.use_ech ?? "true";
            foreach (var item in comboBoxEnableECH.Items)
            {
                if (item is EnableECHItem enableECHItem && enableECHItem.Id == enableECHText)
                {
                    comboBoxEnableECH.SelectedItem = item;
                    break;
                }
            }

            // 设置路由规则下拉框（未设置/未知值时保持默认 rule）
            SelectRoutingMode(server.routing_mode);

            _dirty = false; // 刚加载的数据不算修改
            _loading = false;

            // 如果系统代理已启用，重新设置以使用新的监听地址
            if (checkBoxSystemProxy.Checked && !string.IsNullOrEmpty(server.listen))
            {
                SetSystemProxy(true);
            }
        }

        private void SaveCurrentServer()
        {
            if (comboBoxServer.SelectedItem is not ComboBoxItem item)
                return;

            _loading = true; // 防止触发TextChanged事件

            var server = item.ServerInfo;
            // 保存界面数据到服务器对象
            server.server = textBoxServer.Text;
            server.listen = textBoxListen.Text;
            server.token = textBoxToken.Text;
            server.ip = textBoxIp.Text;
            server.dns = textBoxDns.Text;
            server.ech = textBoxEch.Text;
            server.fallback = textBoxFallback.Text;
            server.ua = textBoxUA.Text;

            // 保存日志级别
            if (comboBoxLogLevel.SelectedItem is LogLevelItem logLevelItem)
            {
                server.loglevel = logLevelItem.Id;
            }

            // 保存是否开启ECH
            if (comboBoxEnableECH.SelectedItem is EnableECHItem enableECHItem)
            {
                server.use_ech = enableECHItem.Id;
            }

            // 保存路由模式
            if (comboBoxRouting.SelectedItem is RoutingModeItem routingItem)
            {
                server.routing_mode = routingItem.Id;
            }

            // 刷新ComboBox显示，不触发SelectedIndexChanged事件
            int idx = comboBoxServer.SelectedIndex;
            comboBoxServer.BeginUpdate();
            comboBoxServer.Items[idx] = comboBoxServer.Items[idx];
            comboBoxServer.EndUpdate();
        }

        // 保存 last_state 状态
        private void SaveLastState()
        {
            if (configData?.last_state == null)
                return;

            configData.last_state.system_proxy_enabled = checkBoxSystemProxy.Checked;
            configData.last_state.auto_start_checked = checkBoxAutoStart.Checked;
            configData.last_state.was_running = !buttonStart.Enabled; // 如果开始按钮不可用，说明正在运行
        }
        #endregion

        #region 状态管理和界面事件
        private void FillLastState()
        {
            if (configData?.last_state == null)
                return;

            _loading = true;

            checkBoxSystemProxy.Checked = configData.last_state.system_proxy_enabled;

            checkBoxAutoStart.Checked = configData.last_state.auto_start_checked;

            // 设置隐藏启动选项
            checkBoxAutoStartHide.Checked = configData.last_state.auto_start_hide_checked;

            // 控制隐藏启动CheckBox启用状态
            checkBoxAutoStartHide.Enabled = checkBoxAutoStart.Checked;

            // 检查是否需要自动启动（上次关闭时正在运行）
            if (configData.last_state.was_running)
            {
                // 延迟2秒后自动启动服务
                var timer = new System.Windows.Forms.Timer();
                timer.Interval = 2000;
                timer.Tick += (s, e) =>
                {
                    timer.Stop();
                    timer.Dispose();

                    if (buttonStart.Enabled)
                    {
                        ButtonStart_Click(this, EventArgs.Empty);

                        // 启动后检查是否需要隐藏窗体
                        if (
                            checkBoxAutoStart.Checked
                            && configData.last_state.auto_start_hide_checked
                        )
                        {
                            var hideTimer = new System.Windows.Forms.Timer();
                            hideTimer.Interval = 3000; // 3秒后检查服务状态
                            hideTimer.Tick += (hs, he) =>
                            {
                                hideTimer.Stop();
                                hideTimer.Dispose();

                                // 检查服务是否真正启动成功
                                if (!buttonStart.Enabled && buttonStop.Enabled)
                                {
                                    this.Hide();
                                    // AppendLog("开机启动模式：窗体已隐藏");
                                }
                            };
                            hideTimer.Start();
                        }
                    }
                };
                timer.Start();
            }

            _loading = false;
        }

        private void ButtonSave_Click(object sender, EventArgs e)
        {
            _loading = true; // 防止触发TextChanged事件
            SaveCurrentServer(); // 保存服务器配置
            SaveLastState(); // 保存界面状态
            SaveConfigToFile(); // 写入文件
            _dirty = false; // 标记为已保存
            buttonSave.Text = "保存";
            _loading = false;
        }

        private void AnyTextBox_TextChanged(object? sender, EventArgs e)
        {
            if (_loading)
                return; // 加载时不触发
            _dirty = true; // 标记为未保存

            buttonSave.Text = "保存*";
        }

        private void CheckBoxAutoStartHide_CheckedChanged(object sender, EventArgs e)
        {
            if (_loading)
                return;

            if (configData?.last_state != null)
            {
                configData.last_state.auto_start_hide_checked = checkBoxAutoStartHide.Checked;
                SaveConfigToFile(false);
            }

            // 开机启动是否隐藏窗体
            if (checkBoxAutoStartHide.Checked)
            {
                checkBoxAutoStart.Checked = true;
            }
        }

        private void CheckBoxSystemProxy_CheckedChanged(object sender, EventArgs e)
        {
            if (_loading)
                return;
            if (configData?.last_state == null)
                return;

            configData.last_state.system_proxy_enabled = checkBoxSystemProxy.Checked;

            // 实际设置系统代理
            SetSystemProxy(checkBoxSystemProxy.Checked);

            // 同步托盘菜单状态
            if (_trayMenuProxyItem != null)
                _trayMenuProxyItem.Checked = checkBoxSystemProxy.Checked;

            // 同步服务器子菜单状态
            if (_trayMenuServerGroup != null)
                RefreshTrayServerMenu(_trayMenuServerGroup);

            SaveConfigToFile(false);
        }

        private void CheckBoxAutoStart_CheckedChanged(object sender, EventArgs e)
        {
            if (_loading)
                return;
            if (configData?.last_state == null)
                return;

            configData.last_state.auto_start_checked = checkBoxAutoStart.Checked;

            // 控制隐藏启动CheckBox启用状态
            checkBoxAutoStartHide.Enabled = checkBoxAutoStart.Checked;

            // 实际设置开机启动
            SetAutoStart(checkBoxAutoStart.Checked);

            // 同步托盘菜单状态
            if (_trayMenuAutoStartItem != null)
                _trayMenuAutoStartItem.Checked = checkBoxAutoStart.Checked;

            // 同步服务器子菜单状态
            if (_trayMenuServerGroup != null)
                RefreshTrayServerMenu(_trayMenuServerGroup);

            SaveConfigToFile(false);
        }

        private void LinkClearLog_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            textBoxLog.Clear();
        }
        #endregion

        #region 服务器操作对话框
        // 显示输入对话框
        private string? ShowInputDialog(string title, string labelText, string defaultText)
        {
            using (var form = new Form())
            {
                form.Text = title;
                form.Size = new Size(320, 200);
                form.FormBorderStyle = FormBorderStyle.FixedDialog;
                form.MaximizeBox = false;
                form.MinimizeBox = false;
                form.StartPosition = FormStartPosition.CenterParent;

                var label = new Label
                {
                    Text = labelText,
                    TextAlign = ContentAlignment.MiddleLeft,
                    Location = new Point(20, 20),
                    Size = new Size(256, 23),
                };

                var textBox = new TextBox
                {
                    Location = new Point(20, 50),
                    Size = new Size(256, 23),
                    Text = defaultText,
                };

                var buttonOK = new Button
                {
                    Text = "确定",
                    Location = new Point(80, 90),
                    Size = new Size(75, 36),
                    DialogResult = DialogResult.OK,
                    Enabled = !string.IsNullOrWhiteSpace(defaultText), // 默认文本非空才可用
                };

                var buttonCancel = new Button
                {
                    Text = "取消",
                    Location = new Point(165, 90),
                    Size = new Size(75, 36),
                    DialogResult = DialogResult.Cancel,
                };

                // 动态禁用确定按钮 + 文本为空时红色边框提示
                void UpdateButtonAndBorder()
                {
                    bool hasText = !string.IsNullOrWhiteSpace(textBox.Text);
                    buttonOK.Enabled = hasText;
                    textBox.BackColor = hasText ? SystemColors.Window : Color.MistyRose; // 空文本变淡红
                }

                textBox.TextChanged += (s, e) => UpdateButtonAndBorder();
                UpdateButtonAndBorder(); // 初始化状态

                form.Controls.AddRange(new Control[] { label, textBox, buttonOK, buttonCancel });
                form.AcceptButton = buttonOK;
                form.CancelButton = buttonCancel;

                if (form.ShowDialog() == DialogResult.OK)
                {
                    return textBox.Text;
                }
                return null;
            }
        }

        // 重命名按钮点击事件
        private void ButtonRename_Click(object? sender, EventArgs e)
        {
            if (comboBoxServer.SelectedItem is not ComboBoxItem item)
                return;

            string? newName = ShowInputDialog("重命名服务器", "请输入新的服务器名称:", item.Name);
            if (newName == null)
                return;

            _loading = true;

            // 更新服务器名称
            var server = item.ServerInfo;
            server.name = newName;
            item.Name = newName;

            // 刷新下拉框显示
            int idx = comboBoxServer.SelectedIndex;
            comboBoxServer.BeginUpdate();
            comboBoxServer.Items[idx] = comboBoxServer.Items[idx];
            comboBoxServer.EndUpdate();

            _loading = false;
            _dirty = true;
            buttonSave.Text = "保存*";

            // 同步托盘菜单
            if (_trayMenuServerGroup != null)
            {
                RefreshTrayServerMenu(_trayMenuServerGroup);
            }

            // 自动保存重命名操作
            SaveConfigToFile(false);
            _dirty = false;
            buttonSave.Text = "保存";
        }

        // 新增按钮点击事件
        private void ButtonAdd_Click(object? sender, EventArgs e)
        {
            if (comboBoxServer.SelectedItem is not ComboBoxItem currentItem)
                return;

            _loading = true;

            string? newName = ShowInputDialog(
                "新增服务器",
                "服务器名称:",
                "No." + new Random().Next(1000, 9999).ToString()
            );
            if (newName == null)
            {
                _loading = false;
                return;
            }

            // 获取当前服务器作为模板
            var currentServer = currentItem.ServerInfo;

            // 生成UUID和随机端口
            string serverId = Guid.NewGuid().ToString();
            int randomPort = GenerateRandomPort();

            // 创建新服务器（复制当前服务器参数）
            var newServer = new Server
            {
                id = serverId,
                name = newName,
                server = currentServer.server,
                listen = $"127.0.0.1:{randomPort}", // 重新生成监听端口
                token = currentServer.token,
                ip = currentServer.ip,
                fallback = currentServer.fallback,
                ua = GetDefaultBrowserUA(),
                dns = currentServer.dns,
                ech = currentServer.ech,
                loglevel = currentServer.loglevel ?? "INFO",
                use_ech = currentServer.use_ech,
                routing_mode = currentServer.routing_mode,
            };

            // 添加到配置
            var newServers = configData!.servers?.ToList() ?? new List<Server>();
            newServers.Add(newServer);
            configData.servers = newServers.ToArray();

            // 添加到下拉框
            var newItem = new ComboBoxItem
            {
                Id = serverId,
                Name = newName,
                ServerInfo = newServer,
            };
            comboBoxServer.Items.Add(newItem);

            // 切换到新服务器
            comboBoxServer.SelectedItem = newItem;

            // 同步托盘菜单
            if (_trayMenuServerGroup != null)
            {
                RefreshTrayServerMenu(_trayMenuServerGroup);
            }

            // 自动保存新增操作
            SaveConfigToFile(false);
            _loading = false;
        }

        // 删除按钮点击事件
        private void ButtonDelete_Click(object? sender, EventArgs e)
        {
            if (comboBoxServer.SelectedItem is not ComboBoxItem currentItem)
                return;

            // 确认删除
            var result = MessageBox.Show(
                $"确定要删除服务器 \"{currentItem.Name}\" 吗？\n\n此操作不可撤销。",
                "确认删除",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning
            );

            if (result != DialogResult.Yes)
                return;

            _loading = true;

            // 从配置列表中删除
            var serverList = configData!.servers?.ToList() ?? new List<Server>();
            serverList.RemoveAll(s => s.id == currentItem.Id);
            configData.servers = serverList.ToArray();

            // 从下拉框中删除
            comboBoxServer.Items.Remove(currentItem);

            // 如果删除的是当前选中的服务器，需要重新选择
            if (configData.current_server_id == currentItem.Id)
            {
                // 如果还有其他服务器，选择第一个
                if (comboBoxServer.Items.Count > 0)
                {
                    comboBoxServer.SelectedIndex = 0;
                    if (comboBoxServer.SelectedItem is ComboBoxItem firstItem)
                    {
                        configData.current_server_id = firstItem.Id;
                        previousItem = firstItem;
                        FillServerDetails(firstItem.ServerInfo);
                    }
                }
                else
                {
                    // 如果没有服务器了，清空当前ID
                    configData.current_server_id = string.Empty;
                    previousItem = null;
                    // 清空所有输入框
                    ClearServerFields();
                }
            }

            _loading = false;
            _dirty = true;
            buttonSave.Text = "保存*";

            // 同步托盘菜单
            if (_trayMenuServerGroup != null)
            {
                RefreshTrayServerMenu(_trayMenuServerGroup);
            }

            // 自动保存删除操作
            SaveConfigToFile(false);
            _dirty = false;
            buttonSave.Text = "保存";
        }

        // 清空服务器字段
        private void ClearServerFields()
        {
            textBoxServer.Text = string.Empty;
            textBoxListen.Text = string.Empty;
            textBoxToken.Text = string.Empty;
            textBoxIp.Text = string.Empty;
            textBoxDns.Text = string.Empty;
            textBoxEch.Text = string.Empty;
            textBoxFallback.Text = string.Empty;
            textBoxUA.Text = string.Empty;
            comboBoxRouting.SelectedIndex = 0;
        }
        #endregion

        #region Chrome/Edge 浏览器的 User-Agent值获取

        private static string GetDefaultBrowserUA()
        {
            try
            {
                // 获取系统默认浏览器的ProgId
                using var uc = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice"
                );
                string? progId = uc?.GetValue("ProgId")?.ToString();
                if (string.IsNullOrEmpty(progId))
                    return "";

                string lowerProgId = progId.ToLower();
                bool isEdge =
                    lowerProgId.Contains("edge")
                    || lowerProgId == "msedgehtm"
                    || lowerProgId.StartsWith("appx");
                bool isChrome = lowerProgId.Contains("chrome");

                // 根据默认浏览器类型获取对应的UA
                if (isChrome)
                {
                    using var chromeKey = Registry.CurrentUser.OpenSubKey(
                        @"Software\Google\Chrome\BLBeacon"
                    );
                    if (chromeKey != null)
                    {
                        string? chromeVersion = chromeKey.GetValue("version")?.ToString();
                        if (!string.IsNullOrEmpty(chromeVersion))
                        {
                            int major = int.TryParse(chromeVersion.Split('.')[0], out var m)
                                ? m
                                : 120;
                            string uaVersion = $"{major}.0.0.0";
                            string platform = "Windows NT 10.0; Win64; x64";
                            return $"Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{uaVersion} Safari/537.36";
                        }
                    }
                }
                else if (isEdge)
                {
                    using var edgeKey = Registry.CurrentUser.OpenSubKey(
                        @"Software\Microsoft\Edge\BLBeacon"
                    );
                    if (edgeKey != null)
                    {
                        string? edgeVersion = edgeKey.GetValue("version")?.ToString();
                        if (!string.IsNullOrEmpty(edgeVersion))
                        {
                            int major = int.TryParse(edgeVersion.Split('.')[0], out var m)
                                ? m
                                : 120;
                            string uaVersion = $"{major}.0.0.0";
                            string platform = "Windows NT 10.0; Win64; x64";
                            string baseUA =
                                $"Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{uaVersion} Safari/537.36";
                            return $"{baseUA} Edg/{uaVersion}";
                        }
                    }
                }
            }
            catch { }

            return ""; // fallback
        }

        #endregion

        #region 系统设置和进程启动
        // 设置系统代理
        private void SetSystemProxy(bool enabled)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                    true
                );

                if (key == null)
                    return;

                if (!enabled)
                {
                    // 真正禁用代理
                    key.SetValue("ProxyEnable", 0);
                    key.DeleteValue("ProxyServer", false);

                    RefreshSystemSettings();
                    return;
                }

                // enabled == true：切换 / 设置代理
                if (comboBoxServer.SelectedItem is not ComboBoxItem item)
                    return;

                string listen = item.ServerInfo.listen;
                // 解析监听地址 -> host 和 port
                if (!TryParseListen(listen, out var host, out var port))
                    return;

                // 重新组装监听地址
                string proxy = $"{host}:{port}";

                // 1. 先 disable（模拟用户取消勾选）
                key.SetValue("ProxyEnable", 0);
                key.DeleteValue("ProxyServer", false);

                RefreshSystemSettings();

                Thread.Sleep(50); // 给 WinINet 一个状态切换点，50ms 稳定兼容性最优

                // 2. 再 enable + 写新地址（模拟重新勾选）
                key.SetValue("ProxyEnable", 1);
                key.SetValue("ProxyServer", proxy);

                RefreshSystemSettings();
            }
            catch (Exception ex)
            {
                AppendLog($"设置系统代理失败: {ex.Message}");
            }
        }

        private bool TryParseListen(string listen, out string host, out int port)
        {
            host = "";
            port = 0;

            if (string.IsNullOrWhiteSpace(listen))
                return false;

            if (!listen.Contains("://"))
                listen = "http://" + listen;

            if (!Uri.TryCreate(listen, UriKind.Absolute, out var uri))
                return false;

            host = uri.Host;
            port = uri.Port;

            return port > 0;
        }

        // 强制刷新系统设置
        private void RefreshSystemSettings()
        {
            InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);
        }

        // 设置开机启动
        private void SetAutoStart(bool enabled)
        {
            try
            {
                string appName = "SSP Workers Client";
                string appPath = Application.ExecutablePath;

                using (
                    var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                        @"Software\Microsoft\Windows\CurrentVersion\Run",
                        true
                    )
                )
                {
                    if (enabled)
                    {
                        // 添加开机启动项
                        key?.SetValue(appName, $"\"{appPath}\"");
                    }
                    else
                    {
                        // 删除开机启动项
                        key?.DeleteValue(appName, false);
                    }
                }
            }
            catch (Exception ex)
            {
                AppendLog($"设置开机启动失败: {ex.Message}");
            }
        }

        [System.Runtime.InteropServices.DllImport("wininet.dll")]
        private static extern bool InternetSetOption(
            IntPtr hInternet,
            int dwOption,
            IntPtr lpBuffer,
            int dwBufferLength
        );

        private async void ButtonStart_Click(object sender, EventArgs e)
        {
            textBoxLog.Clear();
            KillRunningProcess();

            // 从“选择内核”下拉框取当前内核（下拉框只列真实存在的内核）
            string exePath = string.Empty;
            string coreFileName = string.Empty;

            if (comboBoxCore.SelectedItem is CoreItem coreItem)
            {
                coreFileName = coreItem.FileName;
                exePath = coreItem.FullPath;
            }

            // 下拉框为空或文件被删除时，提示用户
            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
            {
                exePath = FindCorePath(coreFileName) ?? string.Empty;
            }

            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
            {
                MessageBox.Show(
                    $"未找到可执行程序 {string.Join("、", supportedCores.Select(c => c.FileName))}，请将内核放到程序目录后重新打开。"
                );
                return;
            }

            string exeArgs;

            // 根据当前服务器配置和所选内核构建参数
            if (comboBoxServer.SelectedItem is ComboBoxItem currentItem)
            {
                exeArgs = BuildCoreArguments(currentItem.ServerInfo, coreFileName);
            }
            else
            {
                exeArgs = "-h";
            }

            // ======= Process 配置 =======
            /*
            // 方案1：通过PowerShell执行外部exe
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -Command \"$OutputEncoding=[Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8; & '{exePath}' {exeArgs}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            */

            // 方案2：直接执行外部exe
            var psi = new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = exeArgs,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };

            _runningProcess = new Process { StartInfo = psi, EnableRaisingEvents = true };

            _runningProcess.OutputDataReceived += (_, e2) =>
            {
                if (!string.IsNullOrEmpty(e2.Data))
                    AppendLog(e2.Data);
            };

            _runningProcess.ErrorDataReceived += (_, e2) =>
            {
                if (!string.IsNullOrEmpty(e2.Data))
                    AppendLog(e2.Data);
            };

            _runningProcess.Start();
            _runningProcess.BeginOutputReadLine();
            _runningProcess.BeginErrorReadLine();

            // 在进程启动后再设置运行状态，确保_runningProcess不为null
            SetRunningState(true);

            await _runningProcess.WaitForExitAsync();

            _runningProcess = null;
            SetRunningState(false);

            AppendLog(
                $"{Environment.NewLine}=============== 内核进程已经结束 ==============={Environment.NewLine}"
            );
        }

        private void ButtonStop_Click(object sender, EventArgs e)
        {
            buttonStop.Enabled = false;
            KillRunningProcess();
            SetRunningState(false);
        }

        // 按内核类型构建命令行参数
        // ssp-core.exe (Go)：-f -l -token -ip -fallback -ua -dns -ech -routing -loglevel -use-ech
        // ssp-rs.exe  (Rust)：--server --listen --token --ip --fallback --ua --routing --ech-domain --ech on/off
        private static string BuildCoreArguments(Server server, string coreFileName)
        {
            var args = new List<string>();
            bool useEch = string.Equals(
                server.use_ech,
                "true",
                StringComparison.OrdinalIgnoreCase
            );
            string coreName = (coreFileName ?? string.Empty).ToLowerInvariant();

            if (coreName.Contains("ssp-rs"))
            {
                // Rust 内核：--server 与 --token 是必填项，即使为空也要传
                args.Add($"--server \"{server.server}\"");
                AddArg(args, "--listen", server.listen);
                args.Add($"--token \"{server.token}\"");
                AddArg(args, "--ip", server.ip);
                AddArg(args, "--fallback", server.fallback);
                AddArg(args, "--ua", server.ua);

                // ssp-rs 只支持 rule / global / none，bypass_cn 等不支持的取值直接忽略（用内核默认 rule）
                string routing = server.routing_mode;
                if (
                    string.Equals(routing, "rule", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(routing, "global", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(routing, "none", StringComparison.OrdinalIgnoreCase)
                )
                {
                    AddArg(args, "--routing", routing);
                }

                AddArg(args, "--ech-domain", server.ech);

                // 界面的 DOH地址 对应 ssp-rs 的 --ech-doh（获取 ECH 配置使用的 DoH）
                AddArg(args, "--ech-doh", server.dns);

                // use_ech 在 JSON 中保持 "true"/"false" 字符串，转成 Rust 内核的 on/off
                args.Add(useEch ? "--ech on" : "--ech off");

                // ssp-rs 的 --dns 是 dns.yaml 配置文件路径，界面没有对应字段，忽略；
                // loglevel 同样不被 ssp-rs 使用，忽略
            }
            else
            {
                // Go 内核 ssp-core.exe
                AddArg(args, "-f", server.server);
                AddArg(args, "-l", server.listen);
                AddArg(args, "-token", server.token);
                AddArg(args, "-ip", server.ip);
                AddArg(args, "-fallback", server.fallback);
                AddArg(args, "-ua", server.ua);
                AddArg(args, "-dns", server.dns);
                AddArg(args, "-ech", server.ech);
                AddArg(args, "-routing", server.routing_mode);
                AddArg(args, "-loglevel", server.loglevel);

                // Go 的 flag.BoolVar：只有传递 -use-ech 才表示启用，
                // 不能传 -use-ech=false（会被误认为已启用）
                if (useEch)
                {
                    args.Add("-use-ech");
                }
            }

            return string.Join(" ", args);
        }

        private static void AddArg(List<string> args, string flag, string? value)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                args.Add($"{flag} \"{value}\"");
            }
        }

        // 供 Cidrs 子窗口行头点击时调用：未冻结(非ReadOnly)时替换填入优选地址
        public bool TryFillIp(string text)
        {
            if (textBoxIp.ReadOnly || string.IsNullOrEmpty(text))
                return false;
            textBoxIp.Text = text;
            return true;
        }

        // 供 Csv 子窗口行头点击时调用：未冻结(非ReadOnly)时替换填入ProxyIP
        public bool TryFillProxyIp(string text)
        {
            if (textBoxFallback.ReadOnly || string.IsNullOrEmpty(text))
                return false;
            textBoxFallback.Text = text;
            return true;
        }

        private void SetRunningState(bool running)
        {
            buttonStart.Enabled = !running;
            buttonStop.Enabled = running;

            // 运行时禁用参数编辑
            textBoxServer.ReadOnly = running;
            textBoxListen.ReadOnly = running;
            textBoxToken.ReadOnly = running;
            textBoxIp.ReadOnly = running;
            textBoxDns.ReadOnly = running;
            textBoxEch.ReadOnly = running;
            textBoxFallback.ReadOnly = running;
            textBoxUA.ReadOnly = running;
            comboBoxRouting.Enabled = !running;
            comboBoxLogLevel.Enabled = !running;
            comboBoxEnableECH.Enabled = !running;
            comboBoxCore.Enabled = !running;
            comboBoxServer.Enabled = !running;
            buttonAdd.Enabled = !running; // 新增按钮
            buttonRename.Enabled = !running; // 重命名按钮
            buttonDel.Enabled = !running; // 删除按钮

            // 同步托盘菜单状态
            if (_trayMenuStartItem != null)
                _trayMenuStartItem.Enabled = !running;
            if (_trayMenuStopItem != null)
                _trayMenuStopItem.Enabled = running;

            // 刷新服务器子菜单项的状态
            if (_trayMenuServerGroup != null)
                RefreshTrayServerMenu(_trayMenuServerGroup);

            // 更新运行状态到配置中
            if (configData?.last_state != null)
            {
                configData.last_state.was_running = running;

                // 静默保存到文件
                SaveConfigToFile(false);
            }
        }
        #endregion

        #region 窗体跳转
        private void linkLabelCsv_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            ShowOrActivateForm<Csv>();
        }

        private void linkLabelCidrs_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            ShowOrActivateForm<Cidrs>();
        }

        private void ShowOrActivateForm<T>() where T : Form, new()
        {
            // 1. 查找是否已打开（通用查找 T 类型的窗体）
            var existingForm = Application.OpenForms.OfType<T>().FirstOrDefault();
            if (existingForm != null)
            {
                existingForm.Activate();    // 已经有了就直接置顶
                if (existingForm.WindowState == FormWindowState.Minimized)
                    existingForm.WindowState = FormWindowState.Normal;
                return;
            }

            // 2. 只有不存在时才创建
            T form = new T();
            form.StartPosition = FormStartPosition.Manual;

            // --- 核心居中计算（通用） ---
            // 理想坐标
            int x = this.Location.X + (this.Width - form.Width) / 2;
            int y = this.Location.Y + (this.Height - form.Height) / 2;
            // 获取当前屏幕边界（避开任务栏）
            var area = Screen.FromControl(this).WorkingArea;
            // x: 左右边界修正; y: 上下边界修正
            x = Math.Max(area.Left, Math.Min(x, area.Right - form.Width));
            y = Math.Max(area.Top, Math.Min(y, area.Bottom - form.Height));

            form.Location = new Point(x, y);

            // 3. 非模态显示并建立所有者关系
            form.Show(this); // 传入 this 保证子窗体浮在父窗体上方，且不阻塞操作
        }
        #endregion
    }

    #region 扩展方法和数据模型
    // TextBox 扩展方法：密码框显示/隐藏
    public static class TextBoxExtensions
    {
        public static void EnablePasswordToggle(this TextBox tb)
        {
            if (tb == null)
                return;

            tb.UseSystemPasswordChar = true;

            tb.Enter += (_, __) => tb.UseSystemPasswordChar = false;
            tb.Leave += (_, __) => tb.UseSystemPasswordChar = true;
        }
    }

    // 路由模式下拉框项
    public class RoutingModeItem
    {
        public required string Id { get; set; } // 路由模式ID：global/bypass_cn/rule/none
        public required string Name { get; set; } // 显示名称：全局模式/绕过中国大陆/mihomo规则/不使用

        public override string ToString() => Name;
    }

    // 日志级别下拉框项
    public class LogLevelItem
    {
        public required string Id { get; set; } // 日志级别ID：DEBUG/INFO/WARN/ERROR
        public required string Name { get; set; } // 显示名称：DEBUG/INFO/WARN/ERROR

        public override string ToString() => Name;
    }

    // 是否开启ECH下拉框项
    public class EnableECHItem
    {
        public required string Id { get; set; } // 是否开启ECH ID：true/false
        public required string Name { get; set; } // 显示名称：启用/禁用

        public override string ToString() => Name;
    }

    // 内核下拉框项
    public class CoreItem
    {
        public required string FileName { get; set; } // 内核文件名：ssp-core.exe / ssp-rs.exe
        public required string FullPath { get; set; } // 内核实际路径
        public required string Name { get; set; } // 显示名称

        public override string ToString() => Name;
    }

    // JSON配置文件结构
    public class ConfigData
    {
        public Server[]? servers { get; set; } // 服务器列表
        public string? current_server_id { get; set; } // 当前选中的服务器ID
        public LastState? last_state { get; set; } // 上次运行时的状态

        // 上次选择的内核文件名（保持 string 类型，供其他程序使用）
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? core { get; set; }

        // 窗口位置尺寸：本程序不使用，原样读入并原样写回（数值类型不变）
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public JsonElement? window { get; set; }

        // 未知字段原样保留，避免破坏其他程序写入的数据
        [JsonExtensionData]
        public Dictionary<string, JsonElement>? extension_data { get; set; }
    }

    // 下拉框绑定项
    public class ComboBoxItem
    {
        public required string Id { get; set; } // 服务器ID
        public required string Name { get; set; } // 服务器名称
        public required Server ServerInfo { get; set; } // 服务器详细信息

        public override string ToString() => Name;
    }

    // 应用程序上次运行状态
    public class LastState
    {
        public bool was_running { get; set; } = false; // 上次是否正在运行
        public bool system_proxy_enabled { get; set; } = false; // 系统代理是否启用
        public bool auto_start_checked { get; set; } = false; // 开机启动是否勾选
        public int preferred_mode { get; set; } = 0; // 保留字段，兼容其他版本
        public bool auto_start_hide_checked { get; set; } = false; // 隐藏启动是否勾选

        // 未知字段原样保留
        [JsonExtensionData]
        public Dictionary<string, JsonElement>? extension_data { get; set; }
    }

    // 服务器配置
    public class Server
    {
        public string id { get; set; } = string.Empty; // 服务器唯一标识
        public string name { get; set; } = string.Empty; // 服务器名称
        public string server { get; set; } = string.Empty; // 服务器地址
        public string listen { get; set; } = string.Empty; // 监听地址
        public string token { get; set; } = string.Empty; // 身份令牌
        public string ip { get; set; } = string.Empty; // 优选IP地址
        public string fallback { get; set; } = string.Empty; // PROXYIP/CF_FALLBACK_IPS
        public string ua { get; set; } = string.Empty; // User-Agent
        public string dns { get; set; } = string.Empty; // DNS服务器
        public string ech { get; set; } = string.Empty; // ECH配置
        public string routing_mode { get; set; } = string.Empty; // 路由模式
        public string loglevel { get; set; } = "INFO"; // 日志级别
        public string use_ech { get; set; } = "false"; // 是否开启ECH

        // 未知字段原样保留
        [JsonExtensionData]
        public Dictionary<string, JsonElement>? extension_data { get; set; }
    }
    #endregion
}
