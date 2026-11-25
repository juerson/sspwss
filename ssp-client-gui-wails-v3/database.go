package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	_ "modernc.org/sqlite" // 纯 Go SQLite（无 CGO），与构建约束一致
)

// ==============================================================================
// 数据库层
// 同样的表结构、索引、排序规则与文件位置（exe 同目录 data\proxyip.db / data\cidrs.db），
// 旧版 C# GUI 已生成的数据库文件可直接沿用。
// ==============================================================================

// dbFilePath 解析数据库文件位置：exe 同目录 data\ 优先，
// 目录无法创建/不可写（如 Program Files）时回退 %APPDATA%\SSP Workers\data。
func dbFilePath(name string) string {
	dir := filepath.Join(getExeDir(), "data")
	if dbDirWritable(dir) {
		return filepath.Join(dir, name)
	}
	dir = filepath.Join(os.Getenv("APPDATA"), "SSP Workers", "data")
	_ = os.MkdirAll(dir, 0o755)
	return filepath.Join(dir, name)
}

func dbDirWritable(dir string) bool {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false
	}
	probe := filepath.Join(dir, ".write-probe")
	f, err := os.Create(probe)
	if err != nil {
		return false
	}
	_ = f.Close()
	_ = os.Remove(probe)
	return true
}

// openDB 打开（并按需初始化）一个 SQLite 库。
// 单连接 + busy_timeout：所有操作都是短事务，串行化即可，避免并发写冲突。
func openDB(path string, initSQL string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{
		"PRAGMA busy_timeout = 5000",
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA cache_size = -200000",
		"PRAGMA temp_store = MEMORY",
		"PRAGMA mmap_size = 536870912",
	} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("设置 %s 失败: %w", pragma, err)
		}
	}
	if _, err := db.Exec(initSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("初始化表结构失败: %w", err)
	}
	return db, nil
}

const proxyDBSchema = `
CREATE TABLE IF NOT EXISTS ProxyIP (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    IP TEXT NOT NULL,
    Port TEXT NOT NULL,
    Country TEXT,
    Organization TEXT
);
CREATE INDEX IF NOT EXISTS idx_ip ON ProxyIP(IP);
CREATE INDEX IF NOT EXISTS idx_country ON ProxyIP(Country);
CREATE INDEX IF NOT EXISTS idx_org ON ProxyIP(Organization);
CREATE INDEX IF NOT EXISTS idx_port ON ProxyIP(Port);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ip_port ON ProxyIP(IP, Port);
CREATE INDEX IF NOT EXISTS idx_id_order ON ProxyIP(Id);
`

const cidrDBSchema = `
CREATE TABLE IF NOT EXISTS CIDRs (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    CIDR TEXT NOT NULL UNIQUE,
    Remark TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_cidr ON CIDRs(CIDR);
CREATE INDEX IF NOT EXISTS idx_remark ON CIDRs(Remark);
CREATE INDEX IF NOT EXISTS idx_search ON CIDRs(CIDR, Remark);
`

// ==============================================================================
// ProxyIP 库（Csv 窗口）
// ==============================================================================

type proxyRow struct {
	ID      int64
	IP      string
	Port    string
	Country string
	Org     string
}

type proxyDB struct {
	mu sync.Mutex
	db *sql.DB
}

func newProxyDB(path string) (*proxyDB, error) {
	db, err := openDB(path, proxyDBSchema)
	if err != nil {
		return nil, err
	}
	return &proxyDB{db: db}, nil
}

func (p *proxyDB) Close() error {
	if p.db != nil {
		return p.db.Close()
	}
	return nil
}

// csvSearchCondition 构造搜索条件（列名白名单拼接，值始终参数化）
func csvSearchCondition(search, column, mode string) (string, []any) {
	search = strings.TrimSpace(search)
	if search == "" {
		return "", nil
	}
	valid := map[string]bool{"IP": true, "Port": true, "Country": true, "Organization": true}
	exact := mode == "精准匹配"
	if valid[column] {
		if exact {
			return "WHERE " + column + " = ?", []any{search}
		}
		return "WHERE " + column + " LIKE ?", []any{"%" + search + "%"}
	}
	// 全部
	if exact {
		return "WHERE IP = ? OR Port = ? OR Country = ? OR Organization = ?",
			[]any{search, search, search, search}
	}
	pat := "%" + search + "%"
	return "WHERE IP LIKE ? OR Port LIKE ? OR Country LIKE ? OR Organization LIKE ?",
		[]any{pat, pat, pat, pat}
}

func (p *proxyDB) Count(search, column, mode string) (int, error) {
	where, args := csvSearchCondition(search, column, mode)
	var n int
	err := p.db.QueryRow("SELECT COUNT(*) FROM ProxyIP "+where, args...).Scan(&n)
	return n, err
}

const proxyPageSelect = "SELECT Id, IP, Port, COALESCE(Country, ' '), COALESCE(Organization, ' ') FROM ProxyIP "

func (p *proxyDB) Page(page, pageSize int, search, column, mode string) ([]proxyRow, error) {
	where, args := csvSearchCondition(search, column, mode)
	q := proxyPageSelect + where + " ORDER BY Id LIMIT ? OFFSET ?"
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := p.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProxyRows(rows)
}

func scanProxyRows(rows *sql.Rows) ([]proxyRow, error) {
	var out []proxyRow
	for rows.Next() {
		var r proxyRow
		if err := rows.Scan(&r.ID, &r.IP, &r.Port, &r.Country, &r.Org); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// InsertOrIgnore 追加写入（(IP,Port) 唯一索引去重），返回实际新增条数
func (p *proxyDB) InsertOrIgnore(data [][4]string) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.insertOrIgnoreLocked(data)
}

func (p *proxyDB) insertOrIgnoreLocked(data [][4]string) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	tx, err := p.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	before, err := countIn(tx, "ProxyIP")
	if err != nil {
		return 0, err
	}
	stmt, err := tx.Prepare("INSERT OR IGNORE INTO ProxyIP (IP, Port, Country, Organization) VALUES (?, ?, ?, ?)")
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	for _, r := range data {
		if _, err := stmt.Exec(r[0], r[1], r[2], r[3]); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	after, err := countIn(p.db, "ProxyIP")
	if err != nil {
		return 0, err
	}
	return after - before, nil
}

// InsertOverwrite 覆盖写入（先清空）
func (p *proxyDB) InsertOverwrite(data [][4]string) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := p.db.Exec("DELETE FROM ProxyIP"); err != nil {
		return 0, err
	}
	return p.insertOrIgnoreLocked(data)
}

func (p *proxyDB) DeleteByIDs(ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return deleteIn(p.db, "ProxyIP", ids)
}

// RemoveDuplicates 只保留每个 IP:Port 组合的首条记录，返回删除条数
func (p *proxyDB) RemoveDuplicates() (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var before, after int
	tx, err := p.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := tx.QueryRow("SELECT COUNT(*) FROM ProxyIP").Scan(&before); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`DELETE FROM ProxyIP WHERE Id NOT IN (SELECT MIN(Id) FROM ProxyIP GROUP BY IP, Port)`); err != nil {
		return 0, err
	}
	if err := tx.QueryRow("SELECT COUNT(*) FROM ProxyIP").Scan(&after); err != nil {
		return 0, err
	}
	return before - after, tx.Commit()
}

func (p *proxyDB) ClearAll() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, err := p.db.Exec("DELETE FROM ProxyIP")
	return err
}

// ==============================================================================
// CIDR 库（优选地址窗口）
// ==============================================================================

type cidrRow struct {
	ID     int64
	CIDR   string
	Remark string
}

type cidrDB struct {
	mu sync.Mutex
	db *sql.DB
}

func newCidrDB(path string) (*cidrDB, error) {
	db, err := openDB(path, cidrDBSchema)
	if err != nil {
		return nil, err
	}
	return &cidrDB{db: db}, nil
}

func (c *cidrDB) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}

// cidrPageSelect 按前两段数值排序（与旧版 C# 的 p1,p2 排序一致）
const cidrPageSelect = `SELECT Id, CIDR, COALESCE(Remark, ' '),
    CAST(SUBSTR(CIDR, 1, INSTR(CIDR, '.') - 1) AS INTEGER) as p1,
    CAST(SUBSTR(CIDR, INSTR(CIDR, '.') + 1, INSTR(SUBSTR(CIDR, INSTR(CIDR, '.') + 1), '.') - 1) AS INTEGER) as p2
    FROM CIDRs `

func (c *cidrDB) Count(search string) (int, error) {
	where, args := cidrSearchCondition(search)
	var n int
	err := c.db.QueryRow("SELECT COUNT(*) FROM CIDRs "+where, args...).Scan(&n)
	return n, err
}

func cidrSearchCondition(search string) (string, []any) {
	search = strings.TrimSpace(search)
	if search == "" {
		return "", nil
	}
	pat := "%" + search + "%"
	// SQL 里 CIDR 与 Remark 各有一个占位符，参数需传两份
	return "WHERE CIDR LIKE ? OR Remark LIKE ?", []any{pat, pat}
}

func (c *cidrDB) Page(page, pageSize int, search string) ([]cidrRow, error) {
	where, args := cidrSearchCondition(search)
	q := cidrPageSelect + where + " ORDER BY p1, p2 LIMIT ? OFFSET ?"
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := c.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []cidrRow
	for rows.Next() {
		var r cidrRow
		var p1, p2 any
		if err := rows.Scan(&r.ID, &r.CIDR, &r.Remark, &p1, &p2); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// InsertOrIgnore 追加写入（CIDR 唯一去重），插入前按 IP 数值+掩码排序，返回实际新增条数
func (c *cidrDB) InsertOrIgnore(cidrs [][2]string) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.insertOrIgnoreLocked(cidrs)
}

func (c *cidrDB) insertOrIgnoreLocked(cidrs [][2]string) (int, error) {
	if len(cidrs) == 0 {
		return 0, nil
	}
	sortCIDRs(cidrs)
	tx, err := c.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	before, err := countIn(tx, "CIDRs")
	if err != nil {
		return 0, err
	}
	stmt, err := tx.Prepare("INSERT OR IGNORE INTO CIDRs (CIDR, Remark) VALUES (?, ?)")
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	for _, r := range cidrs {
		if _, err := stmt.Exec(r[0], r[1]); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	after, err := countIn(c.db, "CIDRs")
	if err != nil {
		return 0, err
	}
	return after - before, nil
}

// InsertOverwrite 覆盖写入（先清空）
func (c *cidrDB) InsertOverwrite(cidrs [][2]string) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.db.Exec("DELETE FROM CIDRs"); err != nil {
		return 0, err
	}
	return c.insertOrIgnoreLocked(cidrs)
}

func (c *cidrDB) DeleteByIDs(ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return deleteIn(c.db, "CIDRs", ids)
}

// RemoveDuplicates 只保留每个 CIDR 的首条记录，返回删除条数
func (c *cidrDB) RemoveDuplicates() (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var before, after int
	tx, err := c.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := tx.QueryRow("SELECT COUNT(*) FROM CIDRs").Scan(&before); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`DELETE FROM CIDRs WHERE Id NOT IN (SELECT MIN(Id) FROM CIDRs GROUP BY CIDR)`); err != nil {
		return 0, err
	}
	if err := tx.QueryRow("SELECT COUNT(*) FROM CIDRs").Scan(&after); err != nil {
		return 0, err
	}
	return before - after, tx.Commit()
}

func (c *cidrDB) ClearAll() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.db.Exec("DELETE FROM CIDRs")
	return err
}

func (c *cidrDB) UpdateRemark(id int64, remark string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.db.Exec("UPDATE CIDRs SET Remark = ? WHERE Id = ?", remark, id)
	return err
}

// ==============================================================================
// 共享 SQL 辅助
// ==============================================================================

func countIn(q interface{ QueryRow(string, ...any) *sql.Row }, table string) (int, error) {
	var n int
	err := q.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n)
	return n, err
}

// deleteIn 按 Id 列表删除（分批参数化，避免拼接注入与变量数上限）
func deleteIn(db *sql.DB, table string, ids []int64) error {
	const batch = 500
	for start := 0; start < len(ids); start += batch {
		end := min(start+batch, len(ids))
		var sb strings.Builder
		args := make([]any, 0, end-start)
		sb.WriteString("DELETE FROM " + table + " WHERE Id IN (")
		for i := start; i < end; i++ {
			if i > start {
				sb.WriteString(",")
			}
			sb.WriteString("?")
			args = append(args, ids[i])
		}
		sb.WriteString(")")
		if _, err := db.Exec(sb.String(), args...); err != nil {
			return err
		}
	}
	return nil
}

// sortCIDRs 按 IP 数值 + 掩码升序
func sortCIDRs(cidrs [][2]string) {
	keyOf := func(cidr string) uint64 {
		base, mask, ok := splitCIDR(cidr)
		if !ok {
			return 0xFFFFFFFF00000020 // 解析失败：排到最后（IP 最大、掩码 /32）
		}
		return uint64(base)<<32 | uint64(mask)
	}
	sort.SliceStable(cidrs, func(i, j int) bool {
		return keyOf(cidrs[i][0]) < keyOf(cidrs[j][0])
	})
}

// splitCIDR 把 "a.b.c.d/m" 解析为 32 位网络地址与掩码（m 缺省 32）
func splitCIDR(cidr string) (uint32, int, bool) {
	slash := strings.IndexByte(cidr, '/')
	ipPart, maskPart := cidr, ""
	if slash >= 0 {
		ipPart, maskPart = cidr[:slash], cidr[slash+1:]
	}
	oct := strings.Split(ipPart, ".")
	if len(oct) != 4 {
		return 0, 0, false
	}
	var ip uint32
	for _, o := range oct {
		n := 0
		if o == "" || len(o) > 3 {
			return 0, 0, false
		}
		for _, ch := range o {
			if ch < '0' || ch > '9' {
				return 0, 0, false
			}
			n = n*10 + int(ch-'0')
		}
		if n > 255 {
			return 0, 0, false
		}
		ip = ip<<8 | uint32(n)
	}
	mask := 32
	if maskPart != "" {
		m := 0
		for _, ch := range maskPart {
			if ch < '0' || ch > '9' {
				return 0, 0, false
			}
			m = m*10 + int(ch-'0')
			if m > 32 {
				return 0, 0, false
			}
		}
		mask = m
	}
	return ip, mask, true
}
