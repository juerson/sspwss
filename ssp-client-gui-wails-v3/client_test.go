package main

import (
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestFormatArgsLines 命令行日志格式化：成对参数、裸开关、令牌打码
func TestFormatArgsLines(t *testing.T) {
	args := []string{
		"-f", "a.b.com:443",
		"-token", "super-secret-psk",
		"-use-ech",
		"-ech", "cloudflare-ech.com",
		"--ech", "off",
	}
	got := formatArgsLines(args)
	want := []string{
		`-f "a.b.com:443"`,
		`-token ***（已隐藏）`,
		`-use-ech`,
		`-ech "cloudflare-ech.com"`,
		`--ech "off"`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("formatArgsLines:\n got  %v\n want %v", got, want)
	}
}

// TestBuildEnvFor 两种核心的环境变量构造（Go 条目 BuildEnv 为 nil，不得 panic）
func TestBuildEnvFor(t *testing.T) {
	goDef := findCoreDef("go")
	env := buildEnvFor(goDef, Server{LogLevel: "DEBUG"})
	if len(env) == 0 {
		t.Fatal("至少应包含系统环境变量")
	}
	rsDef := findCoreDef("rs")
	env = buildEnvFor(rsDef, Server{LogLevel: "DEBUG"})
	found := false
	for _, kv := range env {
		if kv == "RUST_LOG=debug" {
			found = true
		}
	}
	if !found {
		t.Fatalf("RUST_LOG=debug 未注入: %v", env)
	}
}

// TestCoreManagerStartBothKinds 用真实 exe 路径走 start() 全流程（覆盖 BuildEnv nil 分支）
func TestCoreManagerStartBothKinds(t *testing.T) {
	for _, kind := range []string{"go", "rs"} {
		m := newCoreManager()
		exitCh := make(chan struct{})
		// ping 在 Windows 上对未知参数会立刻报错退出，但足以覆盖 start() 的完整路径
		err := m.start(CoreInfo{Path: "ping.exe", Kind: kind}, Server{},
			func(string) {}, func() { close(exitCh) })
		if err != nil {
			t.Fatalf("kind=%s 启动失败: %v", kind, err)
		}
		select {
		case <-exitCh:
		case <-time.After(5 * time.Second):
			m.stop()
			t.Fatalf("kind=%s 进程未退出", kind)
		}
	}
}

// TestCoreManagerLifecycle 用真实子进程验证：启动 → 日志流 → taskkill 整树杀掉 → onExit 触发
func TestCoreManagerLifecycle(t *testing.T) {
	m := newCoreManager()

	var mu sync.Mutex
	var lines []string
	exitCh := make(chan struct{})
	onLog := func(line string) {
		mu.Lock()
		lines = append(lines, line)
		mu.Unlock()
	}
	onExit := func() { close(exitCh) }

	// ping 持续输出多行，模拟长期运行的核心
	err := m.startCmd("ping", "", []string{"-n", "10", "127.0.0.1"}, nil, onLog, onExit)
	if err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	if !m.isRunning() {
		t.Fatal("启动后 isRunning 应为 true")
	}

	// 等日志出现
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(lines)
		mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("5 秒内未收到任何日志输出")
		}
		time.Sleep(100 * time.Millisecond)
	}

	// 停止（taskkill 整树）
	m.stop()

	select {
	case <-exitCh:
	case <-time.After(5 * time.Second):
		t.Fatal("stop 后 onExit 未触发")
	}
	if m.isRunning() {
		t.Fatal("退出后 isRunning 应为 false")
	}

	// 重复 stop 不应 panic / 不应误触发
	m.stop()
}

// TestCoreManagerStopNoProcess 空管理器 stop 不应出错
func TestCoreManagerStopNoProcess(t *testing.T) {
	m := newCoreManager()
	m.stop()
	if m.isRunning() {
		t.Fatal("空管理器不应在运行")
	}
}

// TestKillTreeNothing 杀一个不存在的 PID 不应 panic
func TestKillTreeNothing(t *testing.T) {
	killTree(0)
}

// TestCoreManagerDoubleStart 同一管理器不能同时跑两个进程
func TestCoreManagerDoubleStart(t *testing.T) {
	m := newCoreManager()
	defer m.stop()
	if err := m.startCmd("ping", "", []string{"-n", "60", "127.0.0.1"}, nil, func(string) {}, func() {}); err != nil {
		t.Fatalf("第一次启动失败: %v", err)
	}
	if err := m.startCmd("ping", "", []string{"-n", "60", "127.0.0.1"}, nil, func(string) {}, func() {}); err == nil {
		t.Fatal("第二次启动应报错")
	}
}

// TestTreeKill 杀父进程应连子进程一起杀（taskkill /T）
func TestTreeKill(t *testing.T) {
	// cmd /c "ping -n 60 127.0.0.1" 会产生子进程 ping
	m := newCoreManager()
	onExit := make(chan struct{})
	if err := m.startCmd("cmd", "", []string{"/c", "ping -n 60 127.0.0.1"}, nil, func(string) {}, func() { close(onExit) }); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	m.stop()
	select {
	case <-onExit:
	case <-time.After(5 * time.Second):
		t.Fatal("树杀后 onExit 未触发")
	}
	// 子进程 ping 也应已退出（tasklist 输出中不应再出现 ping.exe）
	time.Sleep(500 * time.Millisecond)
	out, _ := exec.Command("tasklist", "/FI", "IMAGENAME eq ping.exe", "/FO", "CSV").CombinedOutput()
	if strings.Contains(string(out), "ping.exe") {
		t.Fatalf("子进程 ping.exe 未被整树杀掉: %s", out)
	}
}
