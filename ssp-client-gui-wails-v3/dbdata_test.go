package main

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// ==============================================================================
// 解析逻辑（csvdata.go）
// ==============================================================================

func TestParseCSVData(t *testing.T) {
	content := "1.1.1.1,443,US,Cloudflare, Inc\r\n2.2.2.2,80 , CN  ,\nbadline\nonlyone\n3.3.3.3,8080,JP\n"
	rows := parseCSVData(content)
	if len(rows) != 3 {
		t.Fatalf("应解析出 3 行，得到 %d: %v", len(rows), rows)
	}
	if rows[0] != [4]string{"1.1.1.1", "443", "US", "Cloudflare, Inc"} {
		t.Fatalf("第 1 行 Organization 应保留逗号: %v", rows[0])
	}
	if rows[1] != [4]string{"2.2.2.2", "80", "CN", ""} {
		t.Fatalf("第 2 行应补齐空列: %v", rows[1])
	}
	if rows[2] != [4]string{"3.3.3.3", "8080", "JP", ""} {
		t.Fatalf("第 3 行: %v", rows[2])
	}
}

func TestMergeCSVFirst(t *testing.T) {
	a := parseCSVData("1.1.1.1,1,X\n2.2.2.2,2,Y\n")
	b := parseCSVData("2.2.2.2,2,OTHER\n3.3.3.3,3,Z\n")
	merged := mergeCSVFirst([][]([4]string){a, b})
	if len(merged) != 3 {
		t.Fatalf("合并去重后应为 3 行: %v", merged)
	}
	if merged[1] != [4]string{"2.2.2.2", "2", "Y", ""} {
		t.Fatalf("重复 IP:Port 应保留先出现的数据源: %v", merged[1])
	}
}

func TestNormalizeCIDR(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":        "1.2.3.4/32",
		"1.2.3.4/24":     "1.2.3.4/24",
		" 1.2.3.4 / 24 ": "1.2.3.4/24",
		"1.2.3.4/33":     "",
		"1.2.3/24":       "",
		"1.2.3.256/24":   "",
		"::1/128":        "", // IPv6 在 parseAndConvertCidrData 层跳过，此处规范化失败返回空
	}
	for in, want := range cases {
		if got := normalizeCIDR(in); got != want {
			t.Errorf("normalizeCIDR(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestConvertToMax24(t *testing.T) {
	if got := convertToMax24("1.2.3.4/24"); len(got) != 1 || got[0] != "1.2.3.4/24" {
		t.Fatalf("/24 不应拆分: %v", got)
	}
	got := convertToMax24("10.1.0.0/16")
	if len(got) != 256 {
		t.Fatalf("/16 应拆出 256 个 /24，得到 %d", len(got))
	}
	if got[0] != "10.1.0.0/24" || got[255] != "10.1.255.0/24" {
		t.Fatalf("/16 拆分范围错误: 首=%s 末=%s", got[0], got[255])
	}
}

func TestParseAndConvertCidrData(t *testing.T) {
	content := "1.2.3.4\n10.0.0.0/16, 20.0.0.0/8-ish\n2001:db8::/32\n2.2.2.2/24\n1.2.3.4\n"
	got := parseAndConvertCidrData(content)
	// 1.2.3.4→/32；10.0.0.0/16→256 个 /24；"20.0.0.0/8-ish" 非法跳过；IPv6 跳过；2.2.2.2/24；1.2.3.4 重复去重
	if len(got) != 258 {
		t.Fatalf("应得到 258 条，得到 %d", len(got))
	}
	if got[0] != "1.2.3.4/32" {
		t.Fatalf("首条应为 1.2.3.4/32: %v", got[0])
	}
}

func TestRandomIPFromCIDR(t *testing.T) {
	for i := 0; i < 200; i++ {
		ip := randomIPFromCIDR("10.1.2.0/24")
		if !strings.HasPrefix(ip, "10.1.2.") {
			t.Fatalf("随机 IP %s 不在 10.1.2.0/24 内", ip)
		}
	}
	for i := 0; i < 200; i++ {
		ip := randomIPFromCIDR("192.168.5.77/24")
		if !strings.HasPrefix(ip, "192.168.5.") {
			t.Fatalf("随机 IP %s 不在 192.168.5.0/24 内（写主机位时不应跨网段）", ip)
		}
	}
	if randomIPFromCIDR("not-a-cidr") != "" {
		t.Fatal("非法 CIDR 应返回空串")
	}
}

// ==============================================================================
// 数据库层（database.go）
// ==============================================================================

func newTestProxyDB(t *testing.T) *proxyDB {
	t.Helper()
	db, err := newProxyDB(filepath.Join(t.TempDir(), "proxyip.db"))
	if err != nil {
		t.Fatalf("创建 ProxyIP 库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func newTestCidrDB(t *testing.T) *cidrDB {
	t.Helper()
	db, err := newCidrDB(filepath.Join(t.TempDir(), "cidrs.db"))
	if err != nil {
		t.Fatalf("创建 CIDR 库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestProxyDBRoundTrip(t *testing.T) {
	db := newTestProxyDB(t)

	data := make([][4]string, 0, 600)
	for i := 0; i < 600; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		data = append(data, [4]string{ip, strconv.Itoa(8000 + i), "CN", "org"})
	}
	inserted, err := db.InsertOrIgnore(data)
	if err != nil || inserted != 600 {
		t.Fatalf("首次插入应新增 600 条: inserted=%d err=%v", inserted, err)
	}

	// 追加同样数据：唯一索引去重，新增 0
	inserted, err = db.InsertOrIgnore(data)
	if err != nil || inserted != 0 {
		t.Fatalf("重复插入应新增 0 条: inserted=%d err=%v", inserted, err)
	}

	total, err := db.Count("", "", "")
	if err != nil || total != 600 {
		t.Fatalf("总数应为 600: %d err=%v", total, err)
	}

	// 分页
	page1, err := db.Page(1, dbPageSize, "", "", "")
	if err != nil || len(page1) != dbPageSize {
		t.Fatalf("第 1 页应为 %d 行: %d err=%v", dbPageSize, len(page1), err)
	}
	page2, err := db.Page(2, dbPageSize, "", "", "")
	if err != nil || len(page2) != 100 {
		t.Fatalf("第 2 页应为 100 行: %d err=%v", len(page2), err)
	}

	// 搜索：模糊与精准
	if n, err := db.Count("10.0.", "IP", "模糊匹配"); err != nil || n != 600 {
		t.Fatalf("IP 模糊搜索应命中 600: %d err=%v", n, err)
	}
	if n, err := db.Count("8000", "Port", "模糊匹配"); err != nil || n != 1 {
		t.Fatalf("端口模糊搜索应命中 1: %d err=%v", n, err)
	}
	if n, err := db.Count("8000", "Port", "精准匹配"); err != nil || n != 1 {
		t.Fatalf("端口精准搜索应命中 1: %d err=%v", n, err)
	}
	if n, err := db.Count("99999", "Port", "精准匹配"); err != nil || n != 0 {
		t.Fatalf("精准搜索不应命中不存在的值: %d err=%v", n, err)
	}
	if n, err := db.Count("10.0.0.1", "全部", "精准匹配"); err != nil || n != 1 {
		t.Fatalf("全部+精准搜索应命中 1: %d err=%v", n, err)
	}

	// 删除
	ids := []int64{}
	for _, r := range page1 {
		ids = append(ids, r.ID)
	}
	if err := db.DeleteByIDs(ids); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if total, _ = db.Count("", "", ""); total != 100 {
		t.Fatalf("删除后总数应为 100: %d", total)
	}

	// 覆盖写入
	inserted, err = db.InsertOverwrite(data[:50])
	if err != nil || inserted != 50 {
		t.Fatalf("覆盖写入应写入 50 条: %d err=%v", inserted, err)
	}
	if total, _ = db.Count("", "", ""); total != 50 {
		t.Fatalf("覆盖后总数应为 50: %d", total)
	}

	// 去重（唯一索引下无重复，应返回 0）
	if removed, err := db.RemoveDuplicates(); err != nil || removed != 0 {
		t.Fatalf("RemoveDuplicates 应为 0: %d err=%v", removed, err)
	}
}

func TestCidrDBRoundTrip(t *testing.T) {
	db := newTestCidrDB(t)

	cidrs := [][2]string{{"10.0.0.0/24", ""}, {"2.0.0.0/24", ""}, {"100.0.0.0/24", ""}}
	inserted, err := db.InsertOrIgnore(cidrs)
	if err != nil || inserted != 3 {
		t.Fatalf("首次插入应新增 3 条: %d err=%v", inserted, err)
	}

	// 排序按前两段数值（2 < 10 < 100）
	rows, err := db.Page(1, dbPageSize, "")
	if err != nil || len(rows) != 3 {
		t.Fatalf("分页应返回 3 行: %d err=%v", len(rows), err)
	}
	if rows[0].CIDR != "2.0.0.0/24" || rows[1].CIDR != "10.0.0.0/24" || rows[2].CIDR != "100.0.0.0/24" {
		t.Fatalf("排序错误: %v %v %v", rows[0].CIDR, rows[1].CIDR, rows[2].CIDR)
	}

	// 备注编辑
	if err := db.UpdateRemark(rows[0].ID, "测试备注"); err != nil {
		t.Fatalf("更新备注失败: %v", err)
	}
	if n, _ := db.Count("测试"); n != 1 {
		t.Fatalf("按备注搜索应命中 1: %d", n)
	}

	// 去重
	inserted, _ = db.InsertOrIgnore(cidrs)
	if inserted != 0 {
		t.Fatalf("重复 CIDR 应被忽略: %d", inserted)
	}
	if removed, err := db.RemoveDuplicates(); err != nil || removed != 0 {
		t.Fatalf("RemoveDuplicates 应为 0: %d err=%v", removed, err)
	}

	// 清空
	if err := db.ClearAll(); err != nil {
		t.Fatalf("清空失败: %v", err)
	}
	if total, _ := db.Count(""); total != 0 {
		t.Fatalf("清空后应为 0: %d", total)
	}
}
