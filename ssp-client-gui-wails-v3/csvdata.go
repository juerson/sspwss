package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const downloadTimeout = 30 * time.Second

// maxDownloadSize 下载内容上限 50MB，防异常大响应撑爆内存
const maxDownloadSize = 50 << 20

// csvBuiltinURLs Csv 窗口内置数据源（按顺序去重，先出现的源优先）
var csvBuiltinURLs = []string{
	"https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/proxyList.txt",
	"https://raw.githubusercontent.com/papapapapdelesia/Emilia/refs/heads/main/Data/Country-ALIVE.txt",
	"https://raw.githubusercontent.com/tubesteer/proxy_ip/refs/heads/main/alive.txt",
}

// githubReleaseSource Cidrs 窗口的 GitHub Release 数据源
type githubReleaseSource struct {
	owner    string
	repo     string
	fileName string
}

var cidrGithubSources = []githubReleaseSource{
	{owner: "compassvpn", repo: "cf-tools", fileName: "all_cdn_v4.txt"},
}

const cloudflareIPv4URL = "https://www.cloudflare.com/ips-v4"

// githubUserAgent（api.github.com 必须带 UA）
const githubUserAgent = "ECHWorkersGUI"

// downloadURL 下载文本内容（30 秒超时，50MB 上限）
func downloadURL(url string) (string, error) {
	client := &http.Client{Timeout: downloadTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDownloadSize))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// latestReleaseAssetURL 查询 GitHub 最新 release 的资产下载地址（直连）
func latestReleaseAssetURL(s githubReleaseSource) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet,
		"https://api.github.com/repos/"+s.owner+"/"+s.repo+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", githubUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var out struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", err
	}
	if out.TagName == "" {
		return "", fmt.Errorf("release tag_name 为空")
	}
	return fmt.Sprintf("https://github.com/%s/%s/releases/download/%s/%s",
		s.owner, s.repo, out.TagName, s.fileName), nil
}

// cidrBuiltinURLs 内置源地址列表：Cloudflare IPv4 + GitHub Release 资产
func cidrBuiltinURLs() []string {
	urls := []string{cloudflareIPv4URL}
	for _, s := range cidrGithubSources {
		if u, err := latestReleaseAssetURL(s); err == nil {
			urls = append(urls, u)
		}
	}
	return urls
}

// ==============================================================================
// CSV 数据解析（ProxyIP 列表：ip,port,country,organization）
// ==============================================================================

// parseCSVData 解析 CSV/文本内容为 4 列数据（IP, Port, Country, Org）。
// Organization 含逗号时把第 4 列之后的所有片段重新拼回。
func parseCSVData(content string) [][4]string {
	var out [][4]string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}
		var row [4]string
		row[0] = strings.TrimSpace(parts[0])
		row[1] = strings.TrimSpace(parts[1])
		if len(parts) > 2 {
			row[2] = strings.TrimSpace(parts[2])
		}
		if len(parts) > 3 {
			row[3] = strings.TrimSpace(strings.Join(parts[3:], ","))
		}
		out = append(out, row)
	}
	return out
}

// mergeCSVFirst 按源顺序合并去重：IP:Port 首次出现者优先
func mergeCSVFirst(lists [][][4]string) [][4]string {
	seen := make(map[string]bool)
	var out [][4]string
	for _, list := range lists {
		for _, row := range list {
			k := row[0] + ":" + row[1]
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, row)
		}
	}
	return out
}

// ==============================================================================
// CIDR 数据解析（规范化 + 拆分为最大 /24）
// ==============================================================================

var cidrSplitPattern = regexp.MustCompile(`[\s,;\t]+`)
var cidrPattern = regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)/(\d+)$`)

func isValidIPv4(ip string) bool {
	oct := strings.Split(ip, ".")
	if len(oct) != 4 {
		return false
	}
	for _, o := range oct {
		if o == "" || len(o) > 3 {
			return false
		}
		n := 0
		for _, ch := range o {
			if ch < '0' || ch > '9' {
				return false
			}
			n = n*10 + int(ch-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

func isIPv6(s string) bool {
	return strings.Contains(s, ":")
}

// normalizeCIDR 规范化为 "a.b.c.d/m"：裸 IP 补 /32；非法返回空串
func normalizeCIDR(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Join(strings.Fields(s), " ")
	if s == "" {
		return ""
	}
	if strings.Contains(s, "/") {
		parts := strings.SplitN(s, "/", 2)
		if len(parts) != 2 {
			return ""
		}
		ipPart, maskPart := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if !isValidIPv4(ipPart) || maskPart == "" {
			return ""
		}
		mask := 0
		for _, ch := range maskPart {
			if ch < '0' || ch > '9' {
				return ""
			}
			mask = mask*10 + int(ch-'0')
			if mask > 32 {
				return ""
			}
		}
		return fmt.Sprintf("%s/%d", ipPart, mask)
	}
	if !isValidIPv4(s) {
		return ""
	}
	return s + "/32"
}

// convertToMax24 把大于 /24 的网段拆成多个 /24（掩码小于 /16 时按第三段展开到 255 为止）
func convertToMax24(cidr string) []string {
	m := cidrPattern.FindStringSubmatch(cidr)
	if m == nil {
		return nil
	}
	base, mask, _ := splitCIDR(cidr)
	if mask >= 24 {
		return []string{cidr}
	}
	hostBits := 32 - mask
	subnetCount := 1 << uint(hostBits-8)
	oct2 := int(base >> 16 & 0xFF)
	oct3 := int(base >> 8 & 0xFF)
	oct1 := int(base >> 24 & 0xFF)
	var out []string
	for i := 0; i < subnetCount; i++ {
		third := oct3 + i
		if third > 255 {
			break
		}
		out = append(out, fmt.Sprintf("%d.%d.%d.0/24", oct1, oct2, third))
	}
	return out
}

// parseAndConvertCidrData 解析文本内容为 /24 规范 CIDR 列表（跳过 IPv6、去重）
func parseAndConvertCidrData(content string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		for _, part := range cidrSplitPattern.Split(line, -1) {
			if part == "" || isIPv6(part) {
				continue
			}
			normalized := normalizeCIDR(part)
			if normalized == "" {
				continue
			}
			for _, c := range convertToMax24(normalized) {
				if !seen[c] {
					seen[c] = true
					out = append(out, c)
				}
			}
		}
	}
	return out
}

// randomIPFromCIDR 从 CIDR 网段内随机取一个地址（含网络/广播地址）
func randomIPFromCIDR(cidr string) string {
	base, mask, ok := splitCIDR(cidr)
	if !ok {
		return ""
	}
	hostBits := 32 - mask
	network := base & maskBits(mask)
	if hostBits <= 0 {
		return dottedIP(network)
	}
	// 偏移限制在 32 位以内，超大网段（如 /0）在低 32 位内随机
	if hostBits > 32 {
		hostBits = 32
	}
	offset := rand.Uint64N(1 << uint(hostBits))
	return dottedIP(network + uint32(offset))
}

// maskBits 掩码位数 → 32 位掩码（maskBits(24) = 0xFFFFFF00）
func maskBits(mask int) uint32 {
	if mask <= 0 {
		return 0
	}
	if mask >= 32 {
		return 0xFFFFFFFF
	}
	return ^uint32(0) << uint(32-mask)
}

func dottedIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip>>24&0xFF, ip>>16&0xFF, ip>>8&0xFF, ip&0xFF)
}
