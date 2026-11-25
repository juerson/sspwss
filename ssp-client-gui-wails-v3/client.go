package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/windows"
)

// ==============================================================================
// 客户端核心进程管理（同一时间最多一个核心进程）
// ==============================================================================

type coreManager struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	running bool
}

func newCoreManager() *coreManager {
	return &coreManager{}
}

// buildEnvFor 合并系统环境变量与核心定义的附加环境变量（BuildEnv 可为 nil）
func buildEnvFor(def *CoreDef, s Server) []string {
	env := os.Environ()
	if def.BuildEnv != nil {
		for _, kv := range def.BuildEnv(s) {
			env = append(env, kv[0]+"="+kv[1])
		}
	}
	return env
}

// start 启动核心进程。onLog/onExit 由 app 层提供，可能从后台 goroutine 调用。
func (m *coreManager) start(info CoreInfo, s Server, onLog func(string), onExit func()) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("核心已在运行")
	}
	def := findCoreDef(info.Kind)
	if def == nil {
		m.mu.Unlock()
		return fmt.Errorf("未知核心类型: %s", info.Kind)
	}
	// args, skipped := def.BuildArgs(s)
	args, _ := def.BuildArgs(s)
	env := buildEnvFor(def, s)
	dir := filepath.Dir(info.Path)
	m.mu.Unlock()

	// 把将要执行的完整命令行参数逐项打印到日志（令牌打码），
	// 便于核对每一项（ECH 地址、DOH、路由等）是否传给了核心
	// onLog("启动核心: " + info.Path + "（" + kindLabel(info.Kind) + "）")
	// for _, line := range formatArgsLines(args) {
	// 	onLog("  " + line)
	// }
	// if def.BuildEnv != nil {
	// 	for _, kv := range def.BuildEnv(s) {
	// 		onLog("  环境变量: " + kv[0] + "=" + kv[1])
	// 	}
	// }
	// if len(skipped) > 0 {
	// 	onLog("  未传（空值/未启用）: " + strings.Join(skipped, " "))
	// }

	return m.startCmd(info.Path, dir, args, env, onLog, onExit)
}

// formatArgsLines 把扁平参数数组格式化为逐项可读行（flag + 值）。
// 令牌值打码；值统一加引号展示；裸开关（如 -use-ech）单独一行。
func formatArgsLines(args []string) []string {
	var lines []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case !strings.HasPrefix(a, "-"):
			// 理论上不会出现（首项必为 flag），保险起见原样输出
			lines = append(lines, a)
		case i+1 < len(args) && !strings.HasPrefix(args[i+1], "-"):
			// 带值参数
			if strings.Contains(strings.ToLower(a), "token") {
				lines = append(lines, a+" ***（已隐藏）")
			} else {
				lines = append(lines, a+" \""+args[i+1]+"\"")
			}
			i++
		default:
			// 裸开关
			lines = append(lines, a)
		}
	}
	return lines
}

// startCmd 启动任意命令（独立出来便于用真实子进程测试启动/杀树/日志流）
func (m *coreManager) startCmd(path, dir string, args, env []string, onLog func(string), onExit func()) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("核心已在运行")
	}
	cmd := exec.Command(path, args...)
	hideConsole(cmd)
	// 辅助文件（rules.yaml/dns.yaml/ruleset 等）都相对于核心 exe 所在目录解析，把工作目录也设过去
	cmd.Dir = dir
	cmd.Env = env

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		m.mu.Unlock()
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		m.mu.Unlock()
		return err
	}
	if err := cmd.Start(); err != nil {
		m.mu.Unlock()
		return fmt.Errorf("启动核心失败: %w", err)
	}

	m.cmd = cmd
	m.running = true
	m.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)
	go m.pump(stdout, onLog, &wg)
	go m.pump(stderr, onLog, &wg)

	go func() {
		_ = cmd.Wait()
		wg.Wait() // 等日志管道读完，避免丢失最后的输出
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
		onExit()
	}()
	return nil
}

func (m *coreManager) pump(r io.Reader, onLog func(string), wg *sync.WaitGroup) {
	defer wg.Done()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line != "" {
			onLog(line)
		}
	}
}

// isRunning 当前是否有核心进程在运行
func (m *coreManager) isRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// stop 终止核心进程（整棵进程树）。
// 运行状态与结束日志由 start 里的 onExit 回调统一处理。
func (m *coreManager) stop() {
	m.mu.Lock()
	cmd := m.cmd
	running := m.running
	m.mu.Unlock()
	if !running || cmd == nil || cmd.Process == nil {
		return
	}
	killTree(cmd.Process.Pid)
}

// hideConsole 对控制台子程序（核心 exe、taskkill 等）设置隐藏窗口标志。
// GUI 程序启动控制台子进程时 Windows 会给它弹一个黑色控制台窗口（点停止时一闪而过的黑框），
// CREATE_NO_WINDOW 让子进程不创建任何窗口；
// 核心日志仍通过管道正常读取。
func hideConsole(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
}

// killTree 强制结束整棵进程树（旧版的 stdin "exit" 优雅退出路径从未生效，实际总是强杀）
func killTree(pid int) {
	cmd := exec.Command("taskkill", "/PID", strconv.Itoa(pid), "/T", "/F")
	hideConsole(cmd) // 不加这个，点"停止"时 taskkill 会闪一下黑色命令框
	_ = cmd.Run()
}
