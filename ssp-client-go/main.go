package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/sync/singleflight"
)

// =============================================================================
// 全局变量和配置
// =============================================================================

var (
	listenAddr     string
	serverAddr     string
	serverIP       string
	pskHex         string
	enableECH      bool
	enableDNSCache bool
	enableIPList   bool
	ipListURL      string
	enableECHRetry bool
	echRetryMode   string
	enableDebug    bool
	token          string
	dnsServer      string
	echDomain      string
	routingMode    string
	ruleConfigPath string
	dnsConfigPath  string
	userAgent      string
	fallbackTarget string
	logLevelStr    string
	useECH         bool

	connectionFailureCount int32
	maxConnectionFailures  int32 = 5
)

func init() {
	flag.StringVar(&listenAddr, "l", "127.0.0.1:30000", "代理监听地址")
	flag.StringVar(&serverAddr, "f", "", "worker地址 (格式: your.worker.dev:443)")
	flag.StringVar(&serverIP, "ip", "", "本地IP，多IP用逗号分隔")
	flag.StringVar(&token, "token", "", "身份验证令牌(PSK)")
	flag.StringVar(&dnsServer, "dns", "https://223.5.5.5/dns-query", "ECH查询DoH服务器")
	flag.StringVar(&echDomain, "ech", "cloudflare-ech.com", "ECH查询域名")
	flag.StringVar(&routingMode, "routing", "rule", "路由模式: bypass_cn / rule(默认，rules.yaml 规则引擎) global none")
	flag.StringVar(&ruleConfigPath, "rule-config", "rules.yaml", "规则配置文件路径")
	flag.StringVar(&dnsConfigPath, "dns-config", "dns.yaml", "DNS防泄漏配置文件路径")
	flag.StringVar(&userAgent, "ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36", "自定义User-Agent")
	flag.StringVar(&fallbackTarget, "fallback", "", "备用连接目标，逗号分隔多个IP:Port")
	flag.StringVar(&logLevelStr, "loglevel", "INFO", "日志级别: DEBUG, INFO, WARN, ERROR")
	flag.BoolVar(&useECH, "use-ech", false, "是否启用ECH")
}

// resolveExeRelative 路径解析：绝对路径直用，相对路径基于可执行文件目录
func resolveExeRelative(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(exeDir, path)
}

// =============================================================================
// 主函数和程序入口
// =============================================================================

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime)

	setLogLevel(logLevelStr)
	logInfo("日志级别设置为: %s", logLevelStr)

	if token == "" || serverAddr == "" {
		log.Fatal("必须指定 -f 服务端地址 和 -token 令牌\n示例:\n  ./client -l 127.0.0.1:30000 -f your.worker.dev:443 -token YOUR-PSK")
	}

	// ── 1. DNS 配置：联网前校验，非法配置直接退出 ──────────────────────────────
	// dns.yaml 不存在 → 内置默认（内部解析全走隧道，不开本地监听器，默认安全）。
	dnsCfg, err := loadDnsConfig(resolveExeRelative(dnsConfigPath))
	if err != nil {
		logError("%v", err)
		os.Exit(1)
	}
	setDnsConfig(dnsCfg)
	logInfo("[DNS] 配置: listen=%q, ipv6=%v, nameserver=%v, direct=%v, policy=%d",
		dnsCfg.Listen, dnsCfg.IPv6,
		describeUpstreamSpecs(dnsCfg.Nameserver),
		describeUpstreamSpecs(dnsCfg.DirectNameserver),
		len(dnsCfg.NameserverPolicy))

	// ── 2. 引导解析器（字面 IP DoH）：解析 worker 域名 / DoH 域名端点 ───────────
	// 隧道端点的解析永不经过主解析器，防止解析循环（bootstrap 边界）
	globalBootstrap = newBootstrapResolver(dnsCfg.effectiveBootstrapServers())

	// ── 3. IP 池：-ip 里的域名经引导 DoH 解析，系统 DNS 不接触 worker 域名 ─────
	initCFCIDRPool()

	initServerIPList()

	if serverCIDRPool.Count() == 0 {
		logInfo("[配置] 用户IP池为空，将使用内置CF轮换池")
	}

	// ── 4. ECH：DoH 取 HTTPS RR 的 ech 参数（不经隧道，无循环依赖）─────────────
	if useECH {
		logInfo("[启动] 获取 ECH 配置...")
		if err := updateECH(); err != nil {
			logInfo("[启动] ECH 获取失败: %v", err)
		}

		go func() {
			ticker := time.NewTicker(echRefreshPeriod)
			defer ticker.Stop()
			for range ticker.C {
				if err := updateECH(); err != nil {
					logWarn("[ECH] 定期刷新失败（将在下次重试）: %v", err)
				} else {
					logInfo("[ECH] 定期刷新成功")
				}
			}
		}()
	} else {
		logInfo("[启动] ECH 已禁用")
	}

	// ── 5. 路由：加载规则引擎（顺带统计是否存在需要解析的 IP 谓词规则）─────────
	// rule 模式读 rules.yaml（clash 风格规则文件）；国内 IP 判定走 GEOIP(mmdb)。
	InitRouter(routingMode, ruleConfigPath)

	// ── 6. DNS 解析器（tunnel:// 上游复用隧道连接池）────────────────────────────
	// 解析器注入路由分类器：DIRECT 目标用 direct-nameserver（国内 DoH，geo 正确），
	// PROXY/未知目标用 nameserver（默认 tunnel://，解析位置跟随出口）。
	var classifier RouteClassifier
	if rt := GetRouter(); rt != nil {
		classifier = rt
	}
	resolver, err := newDnsResolver(dnsCfg, classifier)
	if err != nil {
		logError("DNS 初始化失败: %v", err)
		os.Exit(1)
	}
	setDnsResolver(resolver)

	// ── 7. 可选本地 DNS 监听器（UDP+TCP）：系统/浏览器可把 DNS 指向此端口 ──────
	if dnsCfg.Listen != "" {
		if err := startDnsListener(dnsCfg.Listen, resolver); err != nil {
			logError("DNS 监听器启动失败: %v", err)
			os.Exit(1)
		}
	}

	// ── 8. 连接池预热，在第一个请求到来前预建 WS 连接 ──────────────────────────
	// 保持 3 条热空闲连接（RS POOL_SIZE=3 同款）：突发并发时零拨号等待
	go func() {
		ticker := time.NewTicker(poolWarmUpInterval)
		defer ticker.Stop()
		for range ticker.C {
			globalPool.warmUp(3)
		}
	}()

	runProxyServer(listenAddr)
}

// =============================================================================
// 常量定义
// =============================================================================

const (
	connTimeout          = 10 * time.Second
	dialTimeout          = 10 * time.Second
	wsHandshakeTimeout   = 10 * time.Second
	waitServerPubTimeout = 5 * time.Second
	keepAliveInterval    = 30 * time.Second
	handlerDeadline      = 30 * time.Second
	wsReadDeadline       = 60 * time.Second

	wsMaxReconnect     = 5
	reconnectBaseDelay = 1 * time.Second
	reconnectMaxDelay  = 30 * time.Second
	heartbeatTimeout   = 60 * time.Second
	heartbeatInterval  = 15 * time.Second

	poolWarmUpInterval = 10 * time.Second

	dnsCacheTTL      = 5 * time.Minute
	echRefreshPeriod = 6 * time.Hour
	dnsQueryTimeout  = 500 * time.Millisecond

	timeWindowSec = 300

	TYPE_DATA  = 0x01
	TYPE_OPEN  = 0x02
	TYPE_CLOSE = 0x03
	TYPE_DNS   = 0x04 // v1.5：DNS 查询帧（payload = reqId(2B) + wire query），sid=0
	TYPE_HEART = 0x05
	NONCE_SIZE = 12
	TAG_SIZE   = 16
)

// =============================================================================
// CIDR 池管理
// =============================================================================

func initCFCIDRPool() {
	defaultCFCIDRs := []string{
		"173.245.48.0/20",
		"103.21.244.0/22",
		"103.22.200.0/22",
		"103.31.4.0/22",
		"141.101.64.0/18",
		"108.162.192.0/18",
		"190.93.240.0/20",
		"188.114.96.0/20",
		"197.234.240.0/22",
		"198.41.128.0/17",
		"162.158.0.0/15",
		"104.16.0.0/13",
		"104.24.0.0/14",
		"172.64.0.0/13",
		"131.0.72.0/22",
	}
	for _, cidr := range defaultCFCIDRs {
		_ = cfCIDRPool.AddCIDR(cidr)
	}
	logInfo("[配置] CF CIDR 池初始化完成，共 %d 个网段", cfCIDRPool.Count())
}

type CIDRPool struct {
	cidrs []*net.IPNet
	index atomic.Uint32
	name  string
}

func (p *CIDRPool) AddCIDR(cidrStr string) error {

	if !strings.Contains(cidrStr, "/") {

		if strings.Contains(cidrStr, ":") {
			cidrStr += "/128"
		} else {
			cidrStr += "/32"
		}
	}
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return fmt.Errorf("无效 CIDR %q: %w", cidrStr, err)
	}
	p.cidrs = append(p.cidrs, ipNet)
	logDebug("[池-%s] 添加 CIDR: %s", p.name, cidrStr)
	return nil
}

func (p *CIDRPool) GetRandomIP() string {
	if len(p.cidrs) == 0 {
		return ""
	}
	idx := p.index.Add(1) - 1
	cidr := p.cidrs[int(idx)%len(p.cidrs)]

	return randomIPFromCIDR(cidr)
}

func (p *CIDRPool) Count() int {
	return len(p.cidrs)
}

var (
	cfCIDRPool     = &CIDRPool{name: "CF"}
	serverCIDRPool = &CIDRPool{name: "Server"}
)

var (
	ipRand   = rand.New(rand.NewSource(time.Now().UnixNano()))
	ipRandMu sync.Mutex
)

func randomIPFromCIDR(cidr *net.IPNet) string {
	ip := cidr.IP.To4()
	if ip == nil {
		return cidr.IP.String()
	}

	ones, bits := cidr.Mask.Size()
	if ones == 32 {
		return ip.String()
	}

	hostBits := uint32(bits - ones)
	ipInt := binary.BigEndian.Uint32(ip)
	maskInt := binary.BigEndian.Uint32([]byte(cidr.Mask))
	networkPart := ipInt & maskInt

	var minHost, maxHost uint32 = 0, (1 << hostBits) - 1
	if hostBits >= 2 {
		minHost, maxHost = 1, (1<<hostBits)-2
	}
	rangeSize := maxHost - minHost + 1

	ipRandMu.Lock()
	randVal := ipRand.Uint32()
	ipRandMu.Unlock()
	hostPart := minHost + (randVal % rangeSize)

	newIPInt := networkPart | hostPart
	newIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(newIP, newIPInt)
	return newIP.String()
}

func initServerIPList() {
	if serverIP == "" {
		return
	}
	parts := strings.Split(serverIP, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		if isDomain(p) {
			logInfo("[配置] 检测到域名: %s，将进行DNS解析", p)
			// 经引导 DoH（proxy-server-nameserver/default-nameserver）解析 worker
			// 域名：系统 DNS 不再看到隧道端点（防残余泄漏面）
			ips, err := bootstrapResolveHosts(p)
			if err == nil && len(ips) > 0 {
				for _, ip := range ips {
					if err := serverCIDRPool.AddCIDR(ip); err != nil {
						logWarn("[配置] 跳过域名解析的IP %q: %v", ip, err)
					}
				}
				logInfo("[配置] 域名 %s 解析到 %d 个IP地址", p, len(ips))
			} else {
				logWarn("[配置] 域名解析失败 %q: %v", p, err)
			}
		} else {
			if err := serverCIDRPool.AddCIDR(p); err != nil {
				logWarn("[配置] 跳过非法 IP/CIDR %q: %v", p, err)
			}
		}
	}
	logInfo("[配置] 服务端 IP 池初始化完成，共 %d 个网段", serverCIDRPool.Count())
}

func isDomain(s string) bool {
	if strings.Contains(s, "/") {
		return false
	}
	if strings.Contains(s, ":") {
		return false
	}
	return strings.ContainsAny(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

// =============================================================================
// 日志系统
// =============================================================================

type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
)

var logLevel = INFO
var logLevelName = map[LogLevel]string{
	DEBUG: "DEBUG",
	INFO:  "INFO",
	WARN:  "WARN",
	ERROR: "ERROR",
}

func setLogLevel(level string) {
	switch level {
	case "DEBUG":
		logLevel = DEBUG
	case "INFO":
		logLevel = INFO
	case "WARN":
		logLevel = WARN
	case "ERROR":
		logLevel = ERROR
	default:
		logLevel = INFO
	}
}

func logDebug(format string, v ...any) {
	if logLevel <= DEBUG {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func logInfo(format string, v ...any) {
	if logLevel <= INFO {
		log.Printf("[INFO] "+format, v...)
	}
}

func logWarn(format string, v ...any) {
	if logLevel <= WARN {
		log.Printf("[WARN] "+format, v...)
	}
}

func logError(format string, v ...any) {
	if logLevel <= ERROR {
		log.Printf("[ERROR] "+format, v...)
	}
}

// =============================================================================
// DNS 缓存系统
// =============================================================================
// DNS 解析统一走 dns.go 的 DnsResolver
// （真实 TTL + singleflight + 失败不缓存），路由 IP 匹配与直连建连共用同一份
// resolver 缓存，避免重复查询消耗 worker 子请求预算。

// =============================================================================
// 重放攻击防护
// =============================================================================

const (
	shardCount = 32
)

type replayShard struct {
	mu     sync.RWMutex
	seen   map[uint64]int64
	maxAge time.Duration
}

type ReplayWindow struct {
	shards    [shardCount]*replayShard
	maxAge    time.Duration
	cleanThr  int
	cleanTick uint64
}

func NewReplayWindow(maxAge time.Duration) *ReplayWindow {
	rw := &ReplayWindow{
		maxAge:   maxAge,
		cleanThr: 500,
	}
	for i := 0; i < shardCount; i++ {
		rw.shards[i] = &replayShard{
			seen:   make(map[uint64]int64),
			maxAge: maxAge,
		}
	}
	return rw
}

func (r *ReplayWindow) getShardIndex(nonce uint64) int {
	return int(nonce % shardCount)
}

func (r *ReplayWindow) Check(n uint64) bool {
	shardIdx := r.getShardIndex(n)
	shard := r.shards[shardIdx]

	shard.mu.RLock()
	if _, exists := shard.seen[n]; exists {
		shard.mu.RUnlock()
		return false
	}
	shard.mu.RUnlock()

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if _, exists := shard.seen[n]; exists {
		return false
	}

	now := time.Now().Unix()
	shard.seen[n] = now

	r.cleanTick++
	if r.cleanTick%shardCount == uint64(shardIdx) && len(shard.seen) > r.cleanThr/shardCount {
		for nonce, t := range shard.seen {
			if now-t > int64(r.maxAge/time.Second) {
				delete(shard.seen, nonce)
			}
		}
	}

	return true
}

// =============================================================================
// 握手加密系统
// =============================================================================

type Handshake struct {
	psk           []byte
	sharedSecret  []byte
	privateKey    *ecdh.PrivateKey
	publicKey     *ecdh.PublicKey
	handshakeAEAD cipher.AEAD
}

func NewHandshake(psk []byte) (*Handshake, error) {
	priv, err := ecdh.X25519().GenerateKey(cryptoRand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keygen: %w", err)
	}

	hkdfKey := make([]byte, 32)
	if _, err := io.ReadFull(
		hkdf.New(sha256.New, psk, make([]byte, 16), []byte("sspv1.4-handshake")),
		hkdfKey,
	); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}

	aead, err := newAEAD(hkdfKey)
	if err != nil {
		return nil, err
	}

	return &Handshake{
		psk:           psk,
		privateKey:    priv,
		publicKey:     priv.PublicKey(),
		handshakeAEAD: aead,
	}, nil
}

func (h *Handshake) DecryptPeerPubKey(data []byte) ([]byte, error) {
	if len(data) < NONCE_SIZE+TAG_SIZE {
		return nil, errors.New("handshake packet too short")
	}
	plain, err := h.handshakeAEAD.Open(nil, data[:NONCE_SIZE], data[NONCE_SIZE:], nil)
	if err != nil {
		return nil, err
	}
	if len(plain) < 32 {
		return nil, errors.New("handshake plaintext too short")
	}
	return plain[:32], nil
}

func (h *Handshake) EncryptOwnPubKey() ([]byte, error) {
	nonce := make([]byte, NONCE_SIZE)
	if _, err := cryptoRand.Read(nonce); err != nil {
		return nil, err
	}

	var padLen int
	padLenN, err := cryptoRand.Int(cryptoRand.Reader, big.NewInt(32))
	if err != nil {
		padLen = 20
		logDebug("[握手] 随机填充长度生成失败，使用默认值: %d", padLen)
	} else {
		padLen = 16 + int(padLenN.Int64())
		logDebug("[握手] 随机填充长度: %d", padLen)
	}

	plain := make([]byte, 32+padLen)
	copy(plain, h.publicKey.Bytes())
	if _, err := cryptoRand.Read(plain[32:]); err != nil {
		return nil, err
	}
	ct := h.handshakeAEAD.Seal(nil, nonce, plain, nil)
	result := make([]byte, NONCE_SIZE+len(ct))
	copy(result, nonce)
	copy(result[NONCE_SIZE:], ct)

	logDebug("[握手] ClientHello加密长度: %d (填充:%d)", len(result), padLen)
	return result, nil
}

func (h *Handshake) DeriveSharedSecret(peerPubKey []byte) error {
	pub, err := ecdh.X25519().NewPublicKey(peerPubKey)
	if err != nil {
		return err
	}
	shared, err := h.privateKey.ECDH(pub)
	if err != nil {
		return err
	}
	h.sharedSecret = shared
	return nil
}

func (h *Handshake) deriveSessionSalt() ([]byte, error) {
	if len(h.sharedSecret) == 0 {
		return nil, errors.New("shared secret not derived")
	}
	r := hkdf.New(sha256.New, h.sharedSecret, h.psk, []byte("sspv1.4-salt"))
	salt := make([]byte, 16)
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

func (h *Handshake) deriveSessionKeys(salt []byte) (txKey, rxKey []byte, err error) {
	rxKey, err = h.deriveKey(h.sharedSecret, salt, "sspv1.4-tx")
	if err != nil {
		return nil, nil, err
	}
	txKey, err = h.deriveKey(h.sharedSecret, salt, "sspv1.4-rx")
	if err != nil {
		clearBytes(rxKey)
		return nil, nil, err
	}
	return txKey, rxKey, nil
}

func (h *Handshake) deriveKey(ikm, salt []byte, purpose string) ([]byte, error) {
	info := make([]byte, 0, len(purpose)+1+len(salt))
	info = append(info, purpose...)
	info = append(info, 0)
	info = append(info, salt...)
	defer clearBytes(info)

	r := hkdf.New(sha256.New, ikm, h.psk, info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		clearBytes(key)
		return nil, err
	}
	return key, nil
}

func (h *Handshake) Complete() (*Session, error) {
	salt, err := h.deriveSessionSalt()
	if err != nil {
		return nil, err
	}

	txKey, rxKey, err := h.deriveSessionKeys(salt)
	if err != nil {
		return nil, err
	}

	txAEAD, err := newAEAD(txKey)
	if err != nil {
		return nil, err
	}
	rxAEAD, err := newAEAD(rxKey)
	if err != nil {
		return nil, err
	}

	clearBytes(txKey)
	clearBytes(rxKey)
	clearBytes(h.psk)
	h.psk = nil
	clearBytes(h.sharedSecret)
	h.sharedSecret = nil

	if h.privateKey != nil {
		h.privateKey = nil
	}

	return &Session{
		txAEAD:        txAEAD,
		rxAEAD:        rxAEAD,
		salt:          salt[:4],
		timeWindowSec: 300,
		replay:        *NewReplayWindow(5 * time.Minute),
	}, nil
}

// =============================================================================
// 会话管理和加密
// =============================================================================

type Session struct {
	txAEAD        cipher.AEAD
	rxAEAD        cipher.AEAD
	salt          []byte
	nonceCounter  atomic.Uint64
	replay        ReplayWindow
	timeWindowSec int64
}

var framePool = sync.Pool{
	New: func() any {

		b := make([]byte, 32*1024)
		return &b
	},
}

func (s *Session) EncryptToBuffer(msgType, streamID byte, payload []byte, outBuf *[]byte) (int, error) {
	if s.txAEAD == nil || s.salt == nil {
		return 0, errors.New("session not initialized")
	}

	var b [1]byte
	cryptoRand.Read(b[:])
	padLen := int(b[0] & 0x7F)
	frameLen := 8 + len(payload) + padLen
	totalNeeded := NONCE_SIZE + frameLen + TAG_SIZE

	if len(*outBuf) < totalNeeded {
		*outBuf = make([]byte, totalNeeded)
	}

	nonce := (*outBuf)[:NONCE_SIZE]
	binary.BigEndian.PutUint64(nonce[:8], s.nonceCounter.Add(1)-1)
	copy(nonce[8:], s.salt)

	plaintext := (*outBuf)[NONCE_SIZE : NONCE_SIZE+frameLen]
	plaintext[0] = msgType
	plaintext[1] = streamID
	binary.BigEndian.PutUint32(plaintext[2:6], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint16(plaintext[6:8], uint16(len(payload)))
	copy(plaintext[8:], payload)
	if padLen > 0 {
		cryptoRand.Read(plaintext[8+len(payload):])
	}

	s.txAEAD.Seal((*outBuf)[NONCE_SIZE:NONCE_SIZE], nonce, plaintext, nil)

	return totalNeeded, nil
}

func (s *Session) Encrypt(msgType, streamID byte, payload []byte) ([]byte, error) {
	if s.txAEAD == nil || s.salt == nil {
		return nil, errors.New("session not initialized")
	}

	plain, err := s.buildFrame(msgType, streamID, payload)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, NONCE_SIZE)
	binary.BigEndian.PutUint64(nonce[:8], s.nonceCounter.Add(1)-1)
	copy(nonce[8:], s.salt)

	ct := s.txAEAD.Seal(nonce, nonce, plain, nil)
	return ct, nil
}

func (s *Session) buildFrame(msgType, streamID byte, payload []byte) ([]byte, error) {
	var b [1]byte
	if _, err := cryptoRand.Read(b[:]); err != nil {
		return nil, err
	}
	padLen := int(b[0] & 0x7F)

	frame := make([]byte, 8+len(payload)+padLen)
	frame[0] = msgType
	frame[1] = streamID
	binary.BigEndian.PutUint32(frame[2:6], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint16(frame[6:8], uint16(len(payload)))
	copy(frame[8:], payload)
	if padLen > 0 {
		if _, err := cryptoRand.Read(frame[8+len(payload):]); err != nil {
			return nil, err
		}
	}
	return frame, nil
}

func (s *Session) Decrypt(data []byte) (byte, byte, []byte, error) {
	if s.rxAEAD == nil {
		return 0, 0, nil, errors.New("session not initialized")
	}
	if len(data) < NONCE_SIZE+TAG_SIZE {
		return 0, 0, nil, errors.New("frame too short")
	}

	nonce := data[:NONCE_SIZE]
	plaintext, err := s.rxAEAD.Open(nil, nonce, data[NONCE_SIZE:], nil)
	if err != nil {
		return 0, 0, nil, err
	}

	if err := s.checkReplay(plaintext, nonce); err != nil {
		return 0, 0, nil, err
	}

	return parseSSPFrame(plaintext)
}

func (s *Session) checkReplay(plaintext, nonce []byte) error {
	if len(plaintext) < 8 {
		return errors.New("plaintext too short")
	}
	timestamp := int64(binary.BigEndian.Uint32(plaintext[2:6]))
	now := time.Now().Unix()

	if abs(now-timestamp) > s.timeWindowSec {
		return errors.New("timestamp out of window")
	}
	n := binary.BigEndian.Uint64(nonce[:8])

	ok := s.replay.Check(n)

	if !ok {
		return errors.New("replay detected")
	}
	return nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func randIntN(n int) int {
	if n <= 0 {
		return 0
	}
	v, _ := cryptoRand.Int(cryptoRand.Reader, big.NewInt(int64(n)))
	return int(v.Int64())
}

func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func isValidTarget(s string) bool {
	if strings.ContainsRune(s, '|') || strings.ContainsRune(s, '\x00') {
		return false
	}

	if host, _, err := net.SplitHostPort(s); err == nil {
		return host != ""
	}

	bare := s
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		bare = s[1 : len(s)-1]
	}

	if net.ParseIP(bare) != nil {
		return true
	}
	return bare != "" && !strings.ContainsAny(bare, " \t\r\n")
}

const OPEN_PAYLOAD_MIN = 256

func buildOpenPayload(primaryTarget string) []byte {
	parts := []string{primaryTarget}
	for _, fb := range strings.Split(fallbackTarget, ",") {
		fb = strings.TrimSpace(fb)
		if fb == "" {
			continue
		}
		if !isValidTarget(fb) {
			logDebug("[配置] 跳过非法 fallback 地址: %q", fb)
			continue
		}
		parts = append(parts, fb)
	}
	raw := []byte(strings.Join(parts, "|"))

	if len(raw) < OPEN_PAYLOAD_MIN {
		pad := make([]byte, OPEN_PAYLOAD_MIN-len(raw)-1)
		if _, err := cryptoRand.Read(pad); err != nil {
			pad = pad[:0]
		}
		raw = append(raw, 0x00)
		raw = append(raw, pad...)
	}
	return raw
}

func parseSSPFrame(data []byte) (byte, byte, []byte, error) {
	if len(data) < 8 {
		return 0, 0, nil, errors.New("frame too short")
	}

	payloadLen := int(binary.BigEndian.Uint16(data[6:8]))
	end := 8 + payloadLen

	if payloadLen < 0 || end > len(data) {
		return 0, 0, nil, errors.New("invalid frame length")
	}

	return data[0], data[1], data[8:end], nil
}

// =============================================================================
// ECH (Encrypted Client Hello) 管理
// =============================================================================

var echManager struct {
	sync.RWMutex
	data []byte
}

func buildDNSLabels(domain string) (labels []byte) {
	for _, part := range strings.Split(domain, ".") {
		labels = append(labels, byte(len(part)))
		labels = append(labels, part...)
	}
	return append(labels, 0)
}

var echConfig atomic.Pointer[[]byte]
var echRejectedCount int32
var lastECHRejectTime int64

func updateECH() error {
	dohURL := dnsServer
	if !strings.Contains(dohURL, "://") {
		dohURL = "https://" + dohURL
	}
	query := append([]byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}, buildDNSLabels(echDomain)...)
	query = append(query, 0, 65, 0, 1)

	req, err := http.NewRequest("GET", dohURL+"?dns="+base64.RawURLEncoding.EncodeToString(query), nil)
	if err != nil {
		return fmt.Errorf("构造 DoH 请求失败: %w", err)
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", userAgent)

	// 域名端点经引导 DoH 解析并钉住 IP（TLS SNI 仍用原域名）；
	// 禁用系统代理，防止解析环/流量绕道
	client, err := newPinnedDoHClient(dohURL)
	if err != nil {
		return fmt.Errorf("构造 DoH 客户端失败: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	rawECH, err := extractECH(body)
	if err != nil {
		return err
	}
	echManager.Lock()
	echManager.data = rawECH
	echManager.Unlock()
	logDebug("[ECH] 配置加载成功 (%d bytes)", len(rawECH))
	echConfig.Store(&rawECH)

	atomic.StoreInt32(&echRejectedCount, 0)
	atomic.StoreInt64(&lastECHRejectTime, 0)
	logInfo("[ECH] 配置已更新，重置拒绝计数器")

	return nil
}

func extractECH(resp []byte) ([]byte, error) {
	if len(resp) < 12 {
		return nil, errors.New("DNS 响应过短")
	}
	ansCount := int(binary.BigEndian.Uint16(resp[6:8]))
	if ansCount == 0 {
		return nil, errors.New("DNS 未返回记录")
	}

	off := 12
	for off < len(resp) {
		b := resp[off]
		if b == 0 {
			off++
			break
		}
		next := off + int(b) + 1
		if next >= len(resp) {
			return nil, errors.New("DNS Question Name 越界")
		}
		off = next
	}
	off += 4

	for i := 0; i < ansCount; i++ {
		if off+12 > len(resp) {
			break
		}
		if resp[off]&0xC0 == 0xC0 {
			off += 2
		} else {
			for off < len(resp) {
				b := resp[off]
				if b == 0 {
					off++
					break
				}
				next := off + int(b) + 1
				if next >= len(resp) {
					return nil, errors.New("DNS Answer Name 越界")
				}
				off = next
			}
		}
		if off+10 > len(resp) {
			break
		}
		rtype := binary.BigEndian.Uint16(resp[off : off+2])
		rdLen := int(binary.BigEndian.Uint16(resp[off+8 : off+10]))
		off += 10

		if rtype == 65 && off+rdLen <= len(resp) {
			if ech, ok := parseHTTPSRdataECH(resp[off : off+rdLen]); ok {
				return ech, nil
			}
		}
		off += rdLen
	}
	return nil, errors.New("未在 HTTPS 记录中找到 ECH")
}

func parseHTTPSRdataECH(data []byte) ([]byte, bool) {
	if len(data) < 3 {
		return nil, false
	}
	pOff := 2
	for pOff < len(data) {
		b := data[pOff]
		if b == 0 {
			pOff++
			break
		}
		if b&0xC0 == 0xC0 {
			pOff += 2
			break
		}
		next := pOff + int(b) + 1
		if next > len(data) {
			return nil, false
		}
		pOff = next
	}
	for pOff+4 <= len(data) {
		key := binary.BigEndian.Uint16(data[pOff : pOff+2])
		vLen := int(binary.BigEndian.Uint16(data[pOff+2 : pOff+4]))
		pOff += 4
		if pOff+vLen > len(data) {
			break
		}
		if key == 5 {
			return data[pOff : pOff+vLen], true
		}
		pOff += vLen
	}
	return nil, false
}

// =============================================================================
// TLS 配置和连接管理
// =============================================================================

func buildUTLSConfig(host string) (*utls.Config, error) {
	uconfig := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: false,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	return uconfig, nil
}

func buildTLSConfig(host string) (*tls.Config, error) {

	if !useECH {
		return &tls.Config{
			MinVersion:         tls.VersionTLS13,
			ServerName:         host,
			InsecureSkipVerify: false,
		}, nil
	}

	rejectedCount := atomic.LoadInt32(&echRejectedCount)
	lastReject := atomic.LoadInt64(&lastECHRejectTime)
	if rejectedCount >= 3 && time.Since(time.Unix(lastReject, 0)) < 5*time.Minute {
		logWarn("[TLS] ECH频繁被拒绝，暂时降级为普通TLS (拒绝次数: %d)", rejectedCount)
		return &tls.Config{
			MinVersion:         tls.VersionTLS13,
			ServerName:         host,
			InsecureSkipVerify: false,
		}, nil
	}

	ptr := echConfig.Load()
	if ptr == nil || len(*ptr) == 0 {
		logWarn("[TLS] ECH 启用但配置为空，降级为普通 TLS")
		return &tls.Config{
			MinVersion:         tls.VersionTLS13,
			ServerName:         host,
			InsecureSkipVerify: false,
		}, nil
	}

	ech := append([]byte(nil), (*ptr)...)

	cfg := &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		ServerName:                     host,
		InsecureSkipVerify:             false,
		EncryptedClientHelloConfigList: ech,
		EncryptedClientHelloRejectionVerify: func(state tls.ConnectionState) error {
			atomic.AddInt32(&echRejectedCount, 1)
			atomic.StoreInt64(&lastECHRejectTime, time.Now().Unix())

			logWarn("[TLS] ECH被服务端拒绝，自动降级为普通TLS连接 (总拒绝次数: %d)",
				atomic.LoadInt32(&echRejectedCount))
			return nil
		},
	}
	return cfg, nil
}

func parseServerAddr(addr string) (host, port string, err error) {
	if idx := strings.Index(addr, "/"); idx != -1 {
		addr = addr[:idx]
	}
	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		return "", "", fmt.Errorf("无效的服务器地址格式: %w", err)
	}
	return host, port, nil
}

// =============================================================================
// WebSocket 连接管理
// =============================================================================

func dialWebSocketWithECH(maxRetries int) (*websocket.Conn, *Session, error) {
	host, port, err := parseServerAddr(serverAddr)
	if err != nil {
		return nil, nil, err
	}
	wsURL := fmt.Sprintf("wss://%s:%s/", host, port)
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		if attempt > 1 {
			backoff := time.Duration(1<<uint(attempt-2)) * reconnectBaseDelay
			if backoff > reconnectMaxDelay {
				backoff = reconnectMaxDelay
			}
			logDebug("[连接] 第 %d 次重试，等待 %v...", attempt, backoff)
			time.Sleep(backoff)
		}

		var currentServerIP string

		if serverCIDRPool.Count() > 0 {
			currentServerIP = serverCIDRPool.GetRandomIP()
			logDebug("[连接] 从用户池获取 IP: %s", currentServerIP)
		} else {
			currentServerIP = cfCIDRPool.GetRandomIP()
			logDebug("[连接] 从CF池获取 IP: %s", currentServerIP)
		}

		conn, session, err := attemptDialWithIP(wsURL, host, currentServerIP)
		if err == nil {
			atomic.StoreInt32(&connectionFailureCount, 0)
			return conn, session, nil
		}
		lastErr = err
		logDebug("[连接] 第 %d 次失败: %v", attempt, err)
	}

	failCount := atomic.AddInt32(&connectionFailureCount, 1)
	logWarn("[连接] 连接失败，连续失败次数: %d/%d", failCount, maxConnectionFailures)

	if failCount >= maxConnectionFailures {
		logError("[连接] 连续失败 %d 次，程序将退出", failCount)
		os.Exit(1)
	}

	return nil, nil, fmt.Errorf("连接失败，已达最大重试次数：%w", lastErr)
}

// ----------------------------------------------------------------------------------

var (
	baseDialer = &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: keepAliveInterval,
	}
	wsDialer = &websocket.Dialer{
		NetDial:          baseDialer.Dial,
		HandshakeTimeout: wsHandshakeTimeout,
	}
)

func attemptDialWithIP(wsURL, host, dialIP string) (*websocket.Conn, *Session, error) {
	tlsCfg, err := buildTLSConfig(host)
	if err != nil {
		return nil, nil, err
	}

	dialer := *wsDialer
	dialer.TLSClientConfig = tlsCfg
	dialer.ReadBufferSize = 32768
	dialer.WriteBufferSize = 32768
	dialer.NetDial = func(network, address string) (net.Conn, error) {
		if dialIP != "" {
			_, p, _ := net.SplitHostPort(address)
			address = net.JoinHostPort(dialIP, p)
			logDebug("[连接] 直连 IP: %s", address)
		}
		return baseDialer.Dial(network, address)
	}

	protocols := []string{"json", "soap", "chat", "stream", "mqtt", "wamp"}
	selectedProtocol := protocols[randIntN(len(protocols))]
	logDebug("[连接] 使用 WebSocket 协议伪装：%s (ECH:%v)", selectedProtocol, useECH)

	wsConn, _, err := dialer.Dial(wsURL, http.Header{
		"User-Agent":             {userAgent},
		"Origin":                 {fmt.Sprintf("https://%s", host)},
		"Sec-WebSocket-Protocol": {selectedProtocol},
	})
	if err != nil {
		return nil, nil, err
	}

	session, err := performHandshake(wsConn)
	if err != nil {
		wsConn.Close()
		return nil, nil, err
	}

	return wsConn, session, nil
}

func performHandshake(wsConn *websocket.Conn) (*Session, error) {
	hs, err := NewHandshake([]byte(token))
	if err != nil {
		return nil, fmt.Errorf("握手初始化: %w", err)
	}

	clientPubEnc, err := hs.EncryptOwnPubKey()
	if err != nil {
		return nil, fmt.Errorf("加密客户端公钥: %w", err)
	}
	if err := wsConn.WriteMessage(websocket.BinaryMessage, clientPubEnc); err != nil {
		return nil, errors.New("发送客户端公钥失败")
	}

	wsConn.SetReadDeadline(time.Now().Add(waitServerPubTimeout))
	_, serverPubEnc, err := wsConn.ReadMessage()
	wsConn.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, fmt.Errorf("读取服务端公钥: %w", err)
	}

	serverPubKey, err := hs.DecryptPeerPubKey(serverPubEnc)
	if err != nil || len(serverPubKey) < 32 {
		return nil, errors.New("解密服务端公钥失败")
	}

	if err := hs.DeriveSharedSecret(serverPubKey); err != nil {
		return nil, fmt.Errorf("派生共享密钥: %w", err)
	}

	return hs.Complete()
}

// =============================================================================
// 代理服务器
// =============================================================================

func runProxyServer(addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("[代理] 监听失败: %v", err)
	}
	defer listener.Close()
	logInfo("[代理] 监听 %s -> %s", addr, maskServerAddrWithOptions(serverAddr, "*****"))
	if serverIP != "" {
		logInfo("[代理] 固定-ip参数: %s", serverIP)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			logDebug("[代理] Accept 错误: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(handlerDeadline))

	var buf [1]byte
	if _, err := conn.Read(buf[:]); err != nil {
		return
	}
	b := buf[0]
	clientAddr := conn.RemoteAddr().String()

	switch {
	case b == 0x05:
		handleSOCKS5(conn, clientAddr)
	case (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z'):
		handleHTTP(conn, clientAddr, b)
	default:
		logWarn("[代理] 未知协议 0x%02x from %s", b, clientAddr)
	}
}

// =============================================================================
// 工具函数
// =============================================================================

func maskServerAddrWithOptions(addr, mask string) string {
	if addr == "" {
		return mask
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return maskHost(addr, mask)
	}

	maskedHost := maskHost(host, mask)
	if port != "" {
		return maskedHost + ":" + port
	}
	return maskedHost
}

func maskHost(host string, mask string) string {
	if host == "" {
		return mask
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return mask + host
	}

	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		parts := strings.Split(host, ".")
		if len(parts) == 4 {
			for i := 0; i < len(parts)-1; i++ {
				parts[i] = mask
			}
			return strings.Join(parts, ".")
		}
		return mask
	}

	if strings.HasSuffix(host, ".workers.dev") || strings.HasSuffix(host, ".pages.dev") {
		if idx := strings.LastIndex(host, "."); idx > 0 {
			secondIdx := strings.LastIndex(host[:idx], ".")
			if secondIdx > 0 {
				return mask + host[secondIdx:]
			}
		}
		return mask + "." + host
	}

	if idx := strings.LastIndex(host, "."); idx > 0 {
		secondIdx := strings.LastIndex(host[:idx], ".")
		if secondIdx > 0 {
			domainPart := host[secondIdx+1 : idx]
			if len(domainPart) > 0 {
				return host[:secondIdx+1] + mask + string(domainPart[len(domainPart)-1]) + host[idx:]
			}
		} else {
			domainPart := host[:idx]
			if len(domainPart) > 0 {
				return mask + string(domainPart[len(domainPart)-1]) + host[idx:]
			}
		}
	}

	return mask
}

func handleSOCKS5(conn net.Conn, clientAddr string) {
	buf := make([]byte, 256)

	if _, err := io.ReadFull(conn, buf[:1]); err != nil {
		return
	}
	nMethods := int(buf[0])
	if nMethods == 0 {
		conn.Write([]byte{0x05, 0xFF})
		return
	}
	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	command, atyp := buf[1], buf[3]

	var host string
	switch atyp {
	case 0x01:
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 0x03:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		n := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:n]); err != nil {
			return
		}
		host = string(buf[:n])
	case 0x04:
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(buf[:2])
	target := net.JoinHostPort(host, fmt.Sprint(port))

	if command != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	logDebug("[SOCKS5] %s -> %s", clientAddr, target)

	var err error
	switch getRouteAction(host, port) {
	case RuleActionReject:
		logInfo("🚫 %s -> %s (已拒绝)", clientAddr, target)
		conn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	case RuleActionDirect:
		logInfo("⚡ %s -> %s", clientAddr, target)
		err = handleDirectConnection(conn, target, clientAddr, 1, []byte{})
	default:
		logInfo("🌐 %s -> %s", clientAddr, target)
		err = tunnelGeneric(conn, target, 1, nil)
	}
	if err != nil && !isNormalCloseError(err) {
		logWarn("[SOCKS5] %s 错误: %v", clientAddr, err)
	}
}

func isNormalCloseError(err error) bool {
	if err == nil || errors.Is(err, io.EOF) {
		return true
	}
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		return true
	}
	s := err.Error()
	for _, k := range []string{"broken pipe", "connection reset", "normal closure"} {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

const maxHeaderBytes = 64 * 1024

func handleHTTP(conn net.Conn, clientAddr string, firstByte byte) {
	reader := bufio.NewReaderSize(
		io.MultiReader(bytes.NewReader([]byte{firstByte}), io.LimitReader(conn, maxHeaderBytes)),
		4096,
	)

	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}
	method, requestURL := parts[0], parts[1]

	var host string
	var headerBuf strings.Builder
	for {
		hLine, err := reader.ReadString('\n')
		if err != nil || hLine == "\r\n" || hLine == "\n" || hLine == "" {
			break
		}
		headerBuf.WriteString(hLine)
		if strings.HasPrefix(strings.ToLower(hLine), "host:") {
			host = strings.TrimSpace(hLine[5:])
		}
	}

	var extra []byte
	if n := reader.Buffered(); n > 0 {
		extra = make([]byte, n)
		_, _ = io.ReadFull(reader, extra)
	}

	if method == "CONNECT" {
		logDebug("[HTTP] CONNECT %s <- %s", requestURL, clientAddr)

		targetHost, targetPort, _ := net.SplitHostPort(requestURL)
		if targetHost == "" {
			targetHost = requestURL
		}
		port := uint16(443)
		if p, err := strconv.ParseUint(targetPort, 10, 16); err == nil {
			port = uint16(p)
		}

		switch getRouteAction(targetHost, port) {
		case RuleActionReject:
			logInfo("🚫 %s -> %s (已拒绝)", clientAddr, requestURL)
			conn.Write([]byte("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"))
		case RuleActionDirect:
			logInfo("⚡ %s -> %s", clientAddr, requestURL)
			_ = handleDirectConnection(conn, requestURL, clientAddr, 2, extra)
		default:
			logInfo("🌐 %s -> %s", clientAddr, requestURL)
			_ = tunnelGeneric(conn, requestURL, 2, extra)
		}
		return
	}

	if host == "" {
		return
	}

	target := host
	if !strings.Contains(target, ":") {
		target += ":80"
	}

	var rawReq strings.Builder
	rawReq.WriteString(line)
	rawReq.WriteString(headerBuf.String())
	rawReq.WriteString("\r\n")

	rawBytes := []byte(rawReq.String())
	firstPayload := make([]byte, len(rawBytes)+len(extra))
	copy(firstPayload, rawBytes)
	copy(firstPayload[len(rawBytes):], extra)

	targetHost, targetPort, _ := net.SplitHostPort(target)
	if targetHost == "" {
		targetHost = host
	}
	httpPort := uint16(80)
	if p, err := strconv.ParseUint(targetPort, 10, 16); err == nil {
		httpPort = uint16(p)
	}

	switch getRouteAction(targetHost, httpPort) {
	case RuleActionReject:
		logInfo("🚫 %s -> %s (已拒绝)", clientAddr, target)
		response := "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"
		conn.Write([]byte(response))
		return
	case RuleActionDirect:
		logInfo("⚡ %s -> %s", clientAddr, target)
		_ = handleDirectConnection(conn, target, clientAddr, 3, firstPayload)
	default: // PROXY
		logInfo("🌐 %s -> %s", clientAddr, target)
		_ = tunnelGeneric(conn, target, 3, firstPayload)
	}
}

func handleDirectConnection(conn net.Conn, target, clientAddr string, mode int, firstPayload []byte) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		port = "80"
		if mode == 2 {
			port = "443"
		}
	}

	// 域名必须经 DnsResolver 解析（fail-closed：失败即拒绝，绝不走系统解析）
	ips, err := resolveHostIPs(host)
	if err != nil {
		sendErrorResponse(conn, mode)
		return fmt.Errorf("直连解析 %s: %w", host, err)
	}

	targetConn, err := dialIPRacing(ips, port, dialTimeout)
	if err != nil {
		sendErrorResponse(conn, mode)
		return fmt.Errorf("直连失败: %w", err)
	}
	defer targetConn.Close()

	if err := sendSuccessResponse(conn, mode); err != nil {
		return err
	}

	_ = conn.SetDeadline(time.Time{})
	_ = targetConn.SetDeadline(time.Time{})

	if len(firstPayload) > 0 {
		if _, err := targetConn.Write(firstPayload); err != nil {
			return err
		}
	}

	done := make(chan struct{}, 2)
	go func() {
		_, err := io.Copy(targetConn, conn)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		if err != nil && !isNormalCloseError(err) {
			logDebug("[直连] 转发错误 (Local->Remote): %v", err)
		}
		done <- struct{}{}
	}()
	go func() {
		_, err := io.Copy(conn, targetConn)
		if err != nil && !isNormalCloseError(err) {
			logDebug("[直连] 转发错误 (Remote->Local): %v", err)
		}
		done <- struct{}{}
	}()
	<-done
	logDebug("[直连] 断开: %s -> %s", clientAddr, target)
	return nil
}

var ioBufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 32*1024)
		return &buf
	},
}

func sendErrorResponse(conn net.Conn, mode int) {
	if mode == 1 {
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	} else {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
	}
}

func sendSuccessResponse(conn net.Conn, mode int) error {
	switch mode {
	case 1:
		_, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return err
	case 2:
		_, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		return err
	default:
		return nil
	}
}

type ipRange struct {
	start uint32
	end   uint32
}

type ipRangeV6 struct {
	start [16]byte
	end   [16]byte
}

var (
	chinaIPRanges   atomic.Pointer[[]ipRange]
	chinaIPV6Ranges atomic.Pointer[[]ipRangeV6]

	exeDir        = getExeDir()
	ipv4LocalFile = filepath.Join(exeDir, "chn_ip.txt")
	ipv6LocalFile = filepath.Join(exeDir, "chn_ip_v6.txt")

	ipv4Mirrors = []string{
		"https://raw.githubusercontent.com/Hackl0us/GeoIP2-CN/refs/heads/release/CN-ip-cidr.txt",
		"https://cdn.jsdelivr.net/gh/Hackl0us/GeoIP2-CN@release/CN-ip-cidr.txt",
		"https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt",
		"https://cdn.jsdelivr.net/gh/misakaio/chnroutes2@master/chnroutes.txt",
		"https://ruleset.skk.moe/Clash/ip/china_ip.txt",
	}

	ipv6Mirrors = []string{
		"https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china6.txt",
		"https://cdn.jsdelivr.net/gh/gaoyifan/china-operator-ip@ip-lists/china6.txt",
	}
)

func getExeDir() string {
	if path, err := os.Executable(); err == nil {
		return filepath.Dir(path)
	}
	return "."
}

// =============================================================================
// 路由和DNS管理
// =============================================================================

func getRouteAction(host string, port uint16) RuleAction {
	switch routingMode {
	case "none":
		return RuleActionDirect
	case "global":
		return RuleActionProxy
	default:
		// bypass_cn、rule 模式
		return RouteDomain(host, nil, port)
	}
}

// resolveHostIPs 直连/路由的域名解析（fail-closed）：
//   - 字面 IP / localhost → 不触发 DNS；
//   - 其它域名 → DnsResolver（按路由分类选组：DIRECT → direct-nameserver，
//     PROXY/未知 → tunnel://）；解析器未接线或解析失败一律报错，
//     绝不回退系统解析（防泄漏第一性原理）。
func resolveHostIPs(host string) ([]net.IP, error) {
	host = strings.TrimPrefix(strings.TrimPrefix(host, "["), "]")
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{canonicalIP(ip)}, nil
	}
	if strings.EqualFold(host, "localhost") {
		// 本地回环：绝不该把 localhost 送去远端 DoH
		return []net.IP{net.IPv4(127, 0, 0, 1), net.ParseIP("::1").To16()}, nil
	}
	resolver := getDnsResolver()
	if resolver == nil {
		return nil, fmt.Errorf("DNS 解析器未接线 (fail-closed)")
	}
	return resolver.Resolve(host)
}

// dialIPRacing 多地址并行竞速拨号（happy eyeballs 简化版）：geo 不符的第一个
// IP 不再拖住整个连接，避免 10s 干等变白屏。
func dialIPRacing(ips []net.IP, port string, timeout time.Duration) (net.Conn, error) {
	if len(ips) == 0 {
		return nil, fmt.Errorf("没有可用地址")
	}
	type dialResult struct {
		conn net.Conn
		err  error
	}
	ch := make(chan dialResult, len(ips))
	for _, ip := range ips {
		go func(ip net.IP) {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), port), timeout)
			if conn != nil {
				if tc, ok := conn.(*net.TCPConn); ok {
					// 直连出口关 Nagle：交互式流量（TLS 握手小包、SSH）最多可省 200ms
					_ = tc.SetNoDelay(true)
				}
			}
			ch <- dialResult{conn: conn, err: err}
		}(ip)
	}

	var lastErr error
	for i := 0; i < len(ips); i++ {
		r := <-ch
		if r.err == nil {
			// 竞速期间可能有其它成功连接，后台回收（通道有缓冲，不会阻塞）
			go func(remaining int) {
				for j := 0; j < remaining; j++ {
					extra := <-ch
					if extra.conn != nil {
						extra.conn.Close()
					}
				}
			}(len(ips) - i - 1)
			return r.conn, nil
		}
		lastErr = r.err
	}
	return nil, lastErr
}

const (
	maxPoolConns = 50
	// 单连接并发流上限：对齐 worker MAX_CONNECTIONS=32（留余量）。
	// 旧值 10 会迫使高并发场景（网页加载 30+ 连接）频繁同步拨新连接，
	// 每次 TLS+WS+握手要 2~3 个 RTT，是"不如 RS 版流畅"的主要原因之一。
	maxStreamsPerConn = 24
	// 单连接累计服役流数：主动退役点。worker 免费计划每会话只有 45 个
	// 子请求预算（每次 OPEN 消耗 1 个），40 提前退役避免 OPEN 被 worker
	// 拒绝后的无效往返；退役后由连接池预热自动补位。
	maxTotalServed = 40

	// 隧道 DNS（TYPE_DNS 帧）
	dnsExchangeTimeout  = 10 * time.Second // 单次 DNS 帧交换超时
	dnsUnsupportedLimit = 2                // 连续超时 N 次判定 worker 未部署 DNS 帧
	maxInflightDNS      = 64               // DNS 帧并发上限（与 worker DNS_MAX_INFLIGHT 对齐）
)

// ── 隧道 DNS（TYPE_DNS 帧，sid=0，不占流 ID 空间）────────────────────────────

// dnsReply 单次 DNS 帧交换的应答
type dnsReply struct {
	data []byte
	err  error
}

// dnsReqIDCounter DNS reqId 分配（进程内原子递增，u16 回绕）
var dnsReqIDCounter uint32

// registerDNS 登记 in-flight DNS 请求，返回 reqId 与应答通道。
// reqId 分配与登记同锁（防止回绕碰撞时双写同 ID）。
func (pc *pooledConn) registerDNS() (uint16, chan dnsReply, error) {
	ch := make(chan dnsReply, 1)
	pc.dnsMu.Lock()
	defer pc.dnsMu.Unlock()
	if pc.dead {
		return 0, nil, errors.New("连接已关闭")
	}
	for i := 0; i < 0xFFFF; i++ {
		id := uint16(atomic.AddUint32(&dnsReqIDCounter, 1) & 0xFFFF)
		if id == 0 {
			continue
		}
		if _, ok := pc.dnsPending[id]; ok {
			continue
		}
		pc.dnsPending[id] = ch
		return id, ch, nil
	}
	return 0, nil, errors.New("DNS reqId 耗尽")
}

func (pc *pooledConn) completeDNS(reqID uint16, resp []byte) {
	pc.dnsMu.Lock()
	ch, ok := pc.dnsPending[reqID]
	if ok {
		delete(pc.dnsPending, reqID)
	}
	pc.dnsMu.Unlock()
	if ok {
		ch <- dnsReply{data: resp}
	}
}

func (pc *pooledConn) removeDNS(reqID uint16) {
	pc.dnsMu.Lock()
	delete(pc.dnsPending, reqID)
	pc.dnsMu.Unlock()
}

// failAllDNS 连接死亡时失败所有在途 DNS 请求（防止请求挂死到超时）
func (pc *pooledConn) failAllDNS(reason string) {
	pc.dnsMu.Lock()
	pending := pc.dnsPending
	pc.dnsPending = make(map[uint16]chan dnsReply)
	pc.dnsMu.Unlock()
	for _, ch := range pending {
		ch <- dnsReply{err: errors.New(reason)}
	}
}

// dnsExchange 经该连接发一次 DNS 帧并等待响应
func (pc *pooledConn) dnsExchange(query []byte, timeout time.Duration) ([]byte, error) {
	reqID, ch, err := pc.registerDNS()
	if err != nil {
		return nil, err
	}

	payload := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(payload, reqID)
	copy(payload[2:], query)

	if err := pc.writeFrame(TYPE_DNS, 0, payload); err != nil {
		pc.removeDNS(reqID)
		// 发送失败说明连接已坏：标记死亡并回收，避免下次再选中它
		pc.closeConnection()
		return nil, fmt.Errorf("WS 无法发送 DNS 帧: %w", err)
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.data, r.err
	case <-timer.C:
		pc.removeDNS(reqID)
		return nil, errors.New("DNS 查询超时（若持续出现，说明 worker 未部署 DNS 帧，请更新 ssp-server/worker/worker.js 并重新部署）")
	}
}

func (pc *pooledConn) isAlive() bool {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return !pc.dead
}

var (
	dnsInflightSem = make(chan struct{}, maxInflightDNS)
	dnsUnsupported atomic.Int32 // 连续超时计数（成功即清零；≥2 快速失败）
)

// pickDNSConn 从池里挑一条活连接承载 DNS 帧（DNS 不 allocStream，
// 有存量流的连接同样可用）；池空则现拨一条。
func pickDNSConn() (*pooledConn, error) {
	globalPool.mu.RLock()
	for _, c := range globalPool.conns {
		if c.isAlive() {
			globalPool.mu.RUnlock()
			return c, nil
		}
	}
	globalPool.mu.RUnlock()
	return globalPool.createNewConn()
}

// tunnelDNSExchange DNS wire 查询 → wire 响应（经 TYPE_DNS 帧 → Worker DoH）。
// 并发槽位限制 + 连续超时判定 worker 未部署 DNS 帧（快速失败，避免每个查询
// 干等 10s）。移植自 ssp-client-rs mux.rs TunnelDns。
func tunnelDNSExchange(query []byte) ([]byte, error) {
	if dnsUnsupported.Load() >= dnsUnsupportedLimit {
		return nil, errors.New("worker 不支持 DNS 帧（DNS 查询已连续超时），请更新 ssp-server/worker/worker.js 并重新部署")
	}
	dnsInflightSem <- struct{}{}
	defer func() { <-dnsInflightSem }()

	pc, err := pickDNSConn()
	if err != nil {
		return nil, fmt.Errorf("DNS 隧道连接不可用: %w", err)
	}
	data, err := pc.dnsExchange(query, dnsExchangeTimeout)
	if err != nil {
		if strings.Contains(err.Error(), "超时") {
			if n := dnsUnsupported.Add(1); n == dnsUnsupportedLimit {
				logWarn("[DNS] 隧道 DNS 连续超时，判定 worker 未部署 DNS 帧；后续查询将快速失败")
			}
		}
		return nil, err
	}
	dnsUnsupported.Store(0)
	return data, nil
}

// =============================================================================
// 流管理和多路复用
// =============================================================================

// streamState 逻辑流接收队列 —— unbounded（RS mpsc::Unbounded 同款语义）。
//
// 关键：readLoop 派发数据帧**绝不丢弃**。旧实现用 32 帧缓冲 channel、满了静默
// 丢弃，丢一帧内层 TCP 字节流就损坏（TLS 记录 MAC 失败），浏览器只能中断重连
// —— 表现为下载/网页卡顿。队列容量仅受内存限制，消费端（relay）通常及时排空。
type streamState struct {
	mu     sync.Mutex
	queue  [][]byte
	notify chan struct{} // cap 1：队列从空到非空的通知
	once   sync.Once
	closed chan struct{}
}

func newStreamState() *streamState {
	return &streamState{notify: make(chan struct{}, 1), closed: make(chan struct{})}
}

func (ss *streamState) push(data []byte) {
	ss.mu.Lock()
	ss.queue = append(ss.queue, data)
	ss.mu.Unlock()
	select {
	case ss.notify <- struct{}{}:
	default:
	}
}

// tryPop 非阻塞取一条
func (ss *streamState) tryPop() ([]byte, bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if len(ss.queue) == 0 {
		return nil, false
	}
	data := ss.queue[0]
	ss.queue[0] = nil
	ss.queue = ss.queue[1:]
	return data, true
}

// pop 阻塞取一条；ctx 取消时提前返回 (nil, false)。
// 流关闭后仍排空队列中已收到的数据（RS mpsc 语义），排空才返回 false。
func (ss *streamState) pop(ctx context.Context) ([]byte, bool) {
	for {
		if data, ok := ss.tryPop(); ok {
			return data, true
		}
		select {
		case <-ss.notify:
			// 回到循环 tryPop（可能已被并发取走）
		case <-ss.closed:
			// 关闭后排空残余，防止丢已收数据
			if data, ok := ss.tryPop(); ok {
				return data, true
			}
			return nil, false
		case <-ctx.Done():
			return nil, false
		}
	}
}

func (ss *streamState) closeStream() {
	ss.once.Do(func() { close(ss.closed) })
}

type pooledConn struct {
	ws      *websocket.Conn
	session *Session
	writeMu sync.Mutex

	mu          sync.Mutex
	streams     map[byte]*streamState
	nextSID     uint32
	dead        bool
	totalServed int

	// 隧道 DNS：在途请求表（reqId → 应答通道）。DNS 帧固定 sid=0，
	// 不占流 ID 空间、不受 maxStreamsPerConn 约束。
	dnsMu      sync.Mutex
	dnsPending map[uint16]chan dnsReply
}

func (pc *pooledConn) allocStream() (byte, *streamState, bool) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if pc.dead {
		return 0, nil, false
	}

	if pc.totalServed >= maxTotalServed {

		if len(pc.streams) == 0 {
			pc.dead = true
			go pc.ws.Close()
		}
		return 0, nil, false
	}

	if len(pc.streams) >= maxStreamsPerConn {
		return 0, nil, false
	}

	for i := 0; i < 254; i++ {
		pc.nextSID++
		sid := byte((pc.nextSID % 254) + 1)
		if _, used := pc.streams[sid]; !used {
			ss := newStreamState()
			pc.streams[sid] = ss
			pc.totalServed++
			return sid, ss, true
		}
	}
	return 0, nil, false
}

func (pc *pooledConn) readLoop() {
	stopHeartbeat := make(chan struct{})
	go pc.heartbeatLoop(stopHeartbeat)

	for {
		pc.ws.SetReadDeadline(time.Now().Add(wsReadDeadline))
		_, raw, err := pc.ws.ReadMessage()
		if err != nil {
			pc.mu.Lock()
			served := pc.totalServed
			pc.mu.Unlock()
			logDebug("[池] 连接断开(累计服务 %d 条流)", served)
			break
		}
		msgType, sid, payload, err := pc.session.Decrypt(raw)
		if err != nil {
			continue
		}
		pc.mu.Lock()
		ss := pc.streams[sid]
		pc.mu.Unlock()

		switch msgType {
		case TYPE_DATA, TYPE_HEART:
			if ss != nil {
				// unbounded 队列：绝不丢帧（丢帧=内层 TCP 流损坏→卡顿断连）
				ss.push(payload)
			}
		case TYPE_CLOSE:
			if ss != nil {
				pc.freeStream(sid)
			}
		case TYPE_DNS:
			// v1.5 DNS 帧：payload = reqId(2B BE) + wire 响应
			if len(payload) >= 2 {
				pc.completeDNS(binary.BigEndian.Uint16(payload[:2]), payload[2:])
			}
		}
	}

	close(stopHeartbeat)

	pc.mu.Lock()
	pc.dead = true
	sids := make([]byte, 0, len(pc.streams))
	for sid := range pc.streams {
		sids = append(sids, sid)
	}
	pc.mu.Unlock()
	pc.failAllDNS("隧道已断开")

	for _, sid := range sids {
		pc.freeStream(sid)
	}
	pc.ws.Close()
}

func (pc *pooledConn) heartbeatLoop(stop <-chan struct{}) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:

			pc.writeMu.Lock()
			err := pc.ws.WriteMessage(websocket.PingMessage, []byte("ping"))
			pc.writeMu.Unlock()
			if err != nil {
				logDebug("[池] WebSocket Ping 发送失败: %v", err)
				return
			}

			if err := pc.writeFrame(TYPE_HEART, 0, nil); err != nil {
				logDebug("[池] 应用心跳发送失败: %v", err)
				return
			}
			logDebug("[池] 心跳发送成功 (Ping + HEART)")
		}
	}
}

func (pc *pooledConn) freeStream(sid byte) {
	pc.mu.Lock()
	ss, ok := pc.streams[sid]
	if ok {
		delete(pc.streams, sid)
	}
	pc.mu.Unlock()
	if ok {
		ss.closeStream()

		globalPool.cond.Broadcast()
	}
}

func (pc *pooledConn) writeFrame(msgType, sid byte, payload []byte) error {
	obj := framePool.Get()

	var bufPtr *[]byte

	switch v := obj.(type) {
	case *[]byte:
		bufPtr = v
	case []byte:

		bufPtr = &v
	default:

		tmp := make([]byte, 32*1024)
		bufPtr = &tmp
	}

	defer framePool.Put(bufPtr)

	n, err := pc.session.EncryptToBuffer(msgType, sid, payload, bufPtr)
	if err != nil {
		return err
	}

	pc.writeMu.Lock()
	defer pc.writeMu.Unlock()
	return pc.ws.WriteMessage(websocket.BinaryMessage, (*bufPtr)[:n])
}

func tunnelGeneric(conn net.Conn, target string, respType int, firstFrame []byte) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	openPayload := buildOpenPayload(target)
	pc, sid, ss, err := acquireStream()
	if err != nil {
		sendErrorResponse(conn, respType)
		return err
	}
	defer pc.freeStream(sid)

	if err := pc.writeFrame(TYPE_OPEN, sid, openPayload); err != nil {
		sendErrorResponse(conn, respType)
		return err
	}

	// 等待服务端 OPEN ACK（worker 开流成功会先回一个空 DATA 帧）。
	// 若先到的已是真实数据帧，也照常转发（ACK 帧与数据帧在同一条 WS 连接上有序）。
	ackWait := time.NewTimer(10 * time.Second)
	var ackData []byte
waitAck:
	for {
		if d, ok := ss.tryPop(); ok {
			ackData = d
			break waitAck
		}
		select {
		case <-ss.notify:
			// loop 回去 tryPop
		case <-ss.closed:
			sendErrorResponse(conn, respType)
			return errors.New("server rejected")
		case <-ctx.Done():
			return errors.New("context canceled")
		case <-ackWait.C:
			sendErrorResponse(conn, respType)
			return errors.New("handshake timeout")
		}
	}

	if err := sendSuccessResponse(conn, respType); err != nil {
		return err
	}

	if len(ackData) > 0 {
		// ACK 帧本应为空；若先到了真实数据（极端竞速），转发给客户端
		if _, err := conn.Write(ackData); err != nil {
			return err
		}
	}

	if len(firstFrame) > 0 {
		_ = pc.writeFrame(TYPE_DATA, sid, firstFrame)
	}

	conn.SetDeadline(time.Time{})
	errChan := make(chan error, 2)

	go func() {
		defer cancel()
		bufPtr := ioBufferPool.Get().(*[]byte)
		defer ioBufferPool.Put(bufPtr)
		buf := *bufPtr

		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if werr := pc.writeFrame(TYPE_DATA, sid, buf[:n]); werr != nil {
					errChan <- werr
					return
				}
			}
			if err != nil {
				errChan <- err
				return
			}
		}
	}()

	go func() {
		defer cancel()
		// Worker → 客户端：阻塞排空队列（流关闭后先排空残余再 EOF）
		for {
			data, ok := ss.pop(ctx)
			if !ok {
				errChan <- io.EOF
				return
			}
			if len(data) > 0 {
				if _, err := conn.Write(data); err != nil {
					errChan <- err
					return
				}
			}
		}
	}()

	select {
	case err = <-errChan:
	case <-ctx.Done():
		err = ctx.Err()
	}

	_ = pc.writeFrame(TYPE_CLOSE, sid, nil)
	return err
}

func acquireStream() (*pooledConn, byte, *streamState, error) {
	deadline := time.Now().Add(8 * time.Second)

	for retries := 0; retries < 3; retries++ {

		if time.Now().After(deadline) {
			return nil, 0, nil, errors.New("acquire stream timeout")
		}

		pc, err := globalPool.getConn()
		if err != nil {
			return nil, 0, nil, err
		}
		sid, ss, ok := pc.allocStream()
		if ok {
			return pc, sid, ss, nil
		}

		pc.mu.Lock()
		pc.totalServed = maxTotalServed
		pc.mu.Unlock()

		if retries < 2 {
			time.Sleep(50 * time.Millisecond)
		}
	}
	return nil, 0, nil, errors.New("no available stream slot")
}

// =============================================================================
// WebSocket 连接池管理
// =============================================================================

type wsPool struct {
	mu        sync.RWMutex
	conns     []*pooledConn
	dialGroup singleflight.Group
	cleaning  uint32
	cond      *sync.Cond
}

var globalPool = &wsPool{
	cond: sync.NewCond(&sync.Mutex{}),
}

func (p *wsPool) getConn() (*pooledConn, error) {
	deadline := time.Now().Add(5 * time.Second)
	consecutiveFailures := 0

	for time.Now().Before(deadline) {

		if conn := p.findAvailableConn(); conn != nil {
			consecutiveFailures = 0
			return conn, nil
		}

		if p.shouldCreateNewConn() {
			conn, err := p.createNewConn()
			if err == nil {
				consecutiveFailures = 0
				return conn, nil
			}

			consecutiveFailures++
			logDebug("[池] 连接创建失败 (%d次连续): %v", consecutiveFailures, err)

			if consecutiveFailures >= 3 {
				timeout := time.NewTimer(2 * time.Second)
				defer timeout.Stop()

				p.cond.L.Lock()
				select {
				case <-timeout.C:

					p.cond.L.Unlock()
					continue
				default:

					go func() {
						time.Sleep(2 * time.Second)
						p.cond.Broadcast()
					}()
					p.cond.Wait()
					p.cond.L.Unlock()
					continue
				}
			}
		}

		p.cleanupDeadConnectionsAsync()

		p.cond.L.Lock()
		remaining := time.Until(deadline)
		if remaining <= 0 {
			p.cond.L.Unlock()
			break
		}

		go func() {
			time.Sleep(min(100*time.Millisecond, remaining))
			p.cond.Broadcast()
		}()
		p.cond.Wait()
		p.cond.L.Unlock()
	}
	return nil, errors.New("获取连接超时")
}

func (p *wsPool) findAvailableConn() *pooledConn {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, c := range p.conns {
		c.mu.Lock()
		idle := !c.dead && len(c.streams) == 0 && c.totalServed < maxTotalServed
		c.mu.Unlock()
		if idle {
			return c
		}
	}

	var bestConn *pooledConn
	minStreams := int(^uint(0) >> 1)
	for _, c := range p.conns {
		c.mu.Lock()
		hasCap := !c.dead && len(c.streams) < maxStreamsPerConn && c.totalServed < maxTotalServed
		streamCount := len(c.streams)
		c.mu.Unlock()
		if hasCap && streamCount < minStreams {
			minStreams = streamCount
			bestConn = c
		}
	}
	return bestConn
}

func (p *wsPool) shouldCreateNewConn() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.conns) < maxPoolConns
}

func (p *wsPool) createNewConn() (*pooledConn, error) {
	v, err, _ := p.dialGroup.Do("dial_new_conn", func() (any, error) {

		p.mu.Lock()
		if len(p.conns) >= maxPoolConns {
			p.mu.Unlock()
			return nil, errors.New("pool full")
		}
		p.mu.Unlock()

		ws, session, err := dialWebSocketWithECH(3)
		if err != nil {
			return nil, err
		}

		pc := newPooledConn(ws, session)

		p.mu.Lock()
		defer p.mu.Unlock()
		if len(p.conns) < maxPoolConns {
			p.conns = append(p.conns, pc)

			p.cond.Broadcast()
			return pc, nil
		} else {
			pc.closeConnection()
			return nil, errors.New("pool full")
		}
	})

	if err != nil {
		return nil, err
	}
	return v.(*pooledConn), nil
}

func (p *wsPool) cleanupDeadConnectionsAsync() {
	if !atomic.CompareAndSwapUint32(&p.cleaning, 0, 1) {

		return
	}

	go func() {
		defer atomic.StoreUint32(&p.cleaning, 0)

		p.mu.Lock()
		defer p.mu.Unlock()

		alive := p.conns[:0]
		connChanged := false
		for _, c := range p.conns {
			c.mu.Lock()
			retired := c.totalServed >= maxTotalServed && len(c.streams) == 0
			if retired && !c.dead {
				c.dead = true
				go c.ws.Close()
				connChanged = true
			}
			dead := c.dead
			c.mu.Unlock()
			if !dead {
				alive = append(alive, c)
			}
		}
		p.conns = alive

		if connChanged {
			p.cond.Broadcast()
		}
	}()
}

func (pc *pooledConn) closeConnection() {
	pc.mu.Lock()
	pc.dead = true
	pc.mu.Unlock()
	pc.failAllDNS("隧道已断开")
	if pc.ws != nil {
		pc.ws.Close()
	}
}

func (p *wsPool) warmUp(n int) {
	p.mu.Lock()

	idle := 0
	for _, c := range p.conns {
		c.mu.Lock()
		if !c.dead && c.totalServed < maxTotalServed && len(c.streams) == 0 {
			idle++
		}
		c.mu.Unlock()
	}

	if idle >= n || len(p.conns) >= maxPoolConns {
		p.mu.Unlock()
		return
	}

	need := n - idle
	if len(p.conns)+need > maxPoolConns {
		need = maxPoolConns - len(p.conns)
	}
	p.mu.Unlock()

	logDebug("[池] 预热：当前空闲 %d/%d，需新建 %d 个连接...", idle, len(p.conns), need)

	maxConcurrentDial := 3
	semaphore := make(chan struct{}, maxConcurrentDial)

	for i := 0; i < need; i++ {
		go func(index int) {

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			delay := time.Duration(index) * 200 * time.Millisecond
			time.Sleep(delay)

			ws, session, err := dialWebSocketWithECH(3)
			if err != nil {
				logDebug("[池] 预热拨号失败：%v", err)
				return
			}

			p.mu.Lock()
			if len(p.conns) < maxPoolConns {
				pc := newPooledConn(ws, session)
				p.conns = append(p.conns, pc)

				p.cond.Broadcast()
				logDebug("[池] 预热成功：连接池大小 %d/%d", len(p.conns), maxPoolConns)
			} else {

				ws.Close()
			}
			p.mu.Unlock()
		}(i)
	}
}

func newPooledConn(ws *websocket.Conn, session *Session) *pooledConn {
	pc := &pooledConn{
		ws:         ws,
		session:    session,
		streams:    make(map[byte]*streamState),
		dnsPending: make(map[uint16]chan dnsReply),
	}

	ws.SetPongHandler(func(string) error {
		logDebug("[池] 收到 Pong")
		return nil
	})
	go pc.readLoop()
	return pc
}
