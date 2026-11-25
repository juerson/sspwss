package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wailsapp/wails/v3/pkg/application"
)

// TestAssetServerServesIndex 验证嵌入的前端资产能被资产服务器正确服务
// （防止再次出现 "Missing index.html" 默认错误页）
func TestAssetServerServesIndex(t *testing.T) {
	handler := application.BundledAssetFileServer(assets)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / 应为 200，实际 %d，body: %s", rec.Code, body[:min(300, len(body))])
	}
	if !strings.Contains(body, "<!DOCTYPE html>") || strings.Contains(body, "Missing index.html") {
		t.Fatalf("首页内容异常: %s", body[:min(300, len(body))])
	}

	// main.js / style.css 也要能服务到
	for _, path := range []string{"/main.js", "/style.css"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
			t.Fatalf("GET %s 应为 200 且非空，实际 %d, %d 字节", path, rec.Code, rec.Body.Len())
		}
	}
}

// TestAssetServerServesDbWindows 验证数据库管理窗口页面与其脚本已嵌入
func TestAssetServerServesDbWindows(t *testing.T) {
	handler := application.BundledAssetFileServer(assets)

	for _, path := range []string{"/csv.html", "/cidrs.html", "/dbwin.js", "/csv.js", "/cidrs.js"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
			t.Fatalf("GET %s 应为 200 且非空，实际 %d, %d 字节", path, rec.Code, rec.Body.Len())
		}
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/csv.html", nil))
	if !strings.Contains(rec.Body.String(), "ProxyIP管理") {
		t.Fatal("csv.html 内容异常（应包含窗口标题）")
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/cidrs.html", nil))
	if !strings.Contains(rec.Body.String(), "优选地址管理") {
		t.Fatal("cidrs.html 内容异常（应包含窗口标题）")
	}
}

// TestAssetServerServesRuntime 验证 v3 运行时 /wails/runtime.js 可访问（前端 ESM 依赖它）
func TestAssetServerServesRuntime(t *testing.T) {
	handler := application.BundledAssetFileServer(assets)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wails/runtime.js", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /wails/runtime.js 应为 200，实际 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ByName") {
		t.Fatal("runtime.js 内容异常（应包含 Call.ByName 实现）")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
