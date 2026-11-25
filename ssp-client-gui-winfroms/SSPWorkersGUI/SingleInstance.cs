using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SSPWorkersGUI
{
    /// <summary>
    /// 单实例控制：防止重复打开程序，并在二次启动时把已打开的窗口显示到最前面
    /// </summary>
    internal static class SingleInstance
    {
        // 互斥体名称（仅当前用户会话有效，多用户登录时各自可以运行一个）
        private const string MutexName = "SSPWorkerClient_SingleInstance_Mutex";

        // 主窗口标题，与 App.Designer.cs 中的 Text 保持一致
        private const string WindowTitle = "SSP Workers Client";

        // 二次启动时用来通知已有实例显示窗口的自定义消息
        // RegisterWindowMessage 在同一会话内对不同进程返回相同的消息ID
        internal static readonly int ActivateMessage = RegisterWindowMessage("SSPWorkerClient_ActivateWindow");

        private const int SW_RESTORE = 9;
        private const int SW_SHOW = 5;
        private const int ASFW_ANY = -1;

        private static Mutex? _mutex;

        /// <summary>
        /// 获取单实例锁。返回 true 表示当前是唯一实例，可以继续启动。
        /// </summary>
        public static bool TryAcquire()
        {
            _mutex = new Mutex(true, MutexName, out bool createdNew);

            if (createdNew)
            {
                return true;
            }

            // 已存在实例：释放本次申请句柄，交给调用方去激活旧窗口
            _mutex.Dispose();
            _mutex = null;
            return false;
        }

        /// <summary>
        /// 激活已经运行的程序窗口；找不到时静默返回。
        /// </summary>
        public static void ActivateExistingInstance()
        {
            // 首次启动的实例可能还在创建窗口，最多重试约 5 秒
            for (int i = 0; i < 50; i++)
            {
                IntPtr hWnd = FindAppWindow();
                if (hWnd != IntPtr.Zero)
                {
                    // 允许已有实例抢前台，否则 SetForegroundWindow 可能被系统拦截
                    AllowSetForegroundWindow(ASFW_ANY);

                    // 通知已有实例自己显示窗口（窗口隐藏到托盘时也能正确恢复）
                    if (ActivateMessage != 0)
                    {
                        PostMessage(hWnd, ActivateMessage, IntPtr.Zero, IntPtr.Zero);
                    }

                    // 窗口最小化时先恢复
                    if (IsIconic(hWnd))
                    {
                        ShowWindow(hWnd, SW_RESTORE);
                    }
                    else if (!IsWindowVisible(hWnd))
                    {
                        ShowWindow(hWnd, SW_SHOW);
                    }

                    ForceForeground(hWnd);
                    return;
                }

                Thread.Sleep(100);
            }
        }

        // 查找本程序的已运行窗口
        private static IntPtr FindAppWindow()
        {
            // 优先按窗口标题查找（隐藏到托盘时窗口依然存在）
            IntPtr hWnd = FindWindow(null, WindowTitle);
            if (hWnd != IntPtr.Zero)
            {
                return hWnd;
            }

            // 兜底：枚举顶层窗口，按可执行文件路径匹配
            string currentPath = Environment.ProcessPath ?? string.Empty;
            IntPtr found = IntPtr.Zero;

            EnumWindows((hwnd, _) =>
            {
                GetWindowThreadProcessId(hwnd, out uint pid);

                if (pid == (uint)Environment.ProcessId)
                {
                    return true;
                }

                try
                {
                    using var process = Process.GetProcessById((int)pid);
                    string? path = process.MainModule?.FileName;

                    if (!string.IsNullOrEmpty(path) &&
                        string.Equals(path, currentPath, StringComparison.OrdinalIgnoreCase))
                    {
                        found = hwnd;
                        return false; // 找到即停止枚举
                    }
                }
                catch
                {
                    // 无权限读取其他进程时忽略
                }

                return true;
            }, IntPtr.Zero);

            return found;
        }

        // 抢前台焦点
        private static void ForceForeground(IntPtr hWnd)
        {
            IntPtr foreground = GetForegroundWindow();
            uint foregroundThreadId = foreground == IntPtr.Zero
                ? 0
                : GetWindowThreadProcessId(foreground, out _);
            uint currentThreadId = GetCurrentThreadId();

            bool attached = false;

            try
            {
                // 把当前线程的输入队列附加到前台线程，绕过系统的前台锁定
                if (foregroundThreadId != 0 && foregroundThreadId != currentThreadId)
                {
                    attached = AttachThreadInput(currentThreadId, foregroundThreadId, true);
                }

                SetForegroundWindow(hWnd);
                BringWindowToTop(hWnd);
            }
            finally
            {
                if (attached)
                {
                    AttachThreadInput(currentThreadId, foregroundThreadId, false);
                }
            }
        }

        #region Win32 API
        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr FindWindow(string? lpClassName, string lpWindowName);

        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll")]
        private static extern bool IsIconic(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool BringWindowToTop(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int RegisterWindowMessage(string lpString);

        [DllImport("user32.dll")]
        private static extern bool PostMessage(IntPtr hWnd, int Msg, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool AllowSetForegroundWindow(int dwProcessId);
        #endregion
    }
}
