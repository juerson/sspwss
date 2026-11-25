package main

// `.mrs`（mihomo rule-set v1 二进制）解码器 —— 移植自 ssp-client-rs/src/mrs.rs。
//
// 只有 `domain` / `ipcidr` 两种 behavior 有 MRS 编码，`classical` 没有。
//
// 容器（mihomo `rules/provider/mrs_reader.go`）：整文件用 zstd 压缩，解压后依次是
//
//	"MRS\x01" | behavior(1) | count(i64 BE) | extra_len(i64 BE) | extra(count 字节) | body
//
//   - behavior: 0 = domain，1 = ipcidr，2 = classical（MRS 不支持）
//   - count: 规则条数（仅用于统计，解码时以 body 的实际内容为准）
//   - extra: 预留字段，跳过
//
// body 的两种编码：
//   - domain：succinct trie（`component/trie/domain_set_bin.go`）
//   - ipcidr：IP range 列表（`component/cidr/ipcidr_set_bin.go`）
//
// 注意：domain trie 里的 key 是**逐 rune 反转**的字符串，后缀规则会在末尾多一个
// `'+'` 标记（见 `trie.DomainSetBuilder::insert`），解码时必须按同样的规则还原，
// 否则会把 `+.google.com` 误判成精确域名。

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"
	"net"
	"strings"

	kpzstd "github.com/klauspost/compress/zstd"
)

// MRS 解压后的文件头（mihomo `MrsMagicBytes`）
const mrsMagic = "MRS\x01"

// zstd 帧头；MRS 外层固定是 zstd，可据此在不解压的情况下识别
var zstdMagic = [4]byte{0x28, 0xB5, 0x2F, 0xFD}

// sing-box 规则集（.srs）的明文魔数
const srsMagic = "SRS"

// domain 的 trie 最大深度（DNS 名最长 253 字节，留足余量）
const maxTrieDepth = 512

// 解压后的体积上限，防止畸形/恶意文件把内存撑爆
const maxDecompressedBytes = 256 << 20

// ── 格式识别 ─────────────────────────────────────────────────────────────────

type mrsDetected int

const (
	mrsDetectedMrs  mrsDetected = iota // zstd 帧头 → 尝试按 MRS 解析
	mrsDetectedSrs                     // 明文 SRS → sing-box 规则集（不支持）
	mrsDetectedText                    // 其它 → 按 UTF-8 文本处理
)

// detectRuleFormat 按文件头识别格式。MRS 的魔数在 zstd 内部，所以只能先看 zstd 帧头。
func detectRuleFormat(raw []byte) mrsDetected {
	if len(raw) >= 4 && raw[0] == zstdMagic[0] && raw[1] == zstdMagic[1] && raw[2] == zstdMagic[2] && raw[3] == zstdMagic[3] {
		return mrsDetectedMrs
	}
	if bytes.HasPrefix(raw, []byte(srsMagic)) {
		return mrsDetectedSrs
	}
	return mrsDetectedText
}

// detectWithFormat 显式 format 配置优先，缺省按文件头嗅探
func detectWithFormat(raw []byte, format string) mrsDetected {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "mrs":
		return mrsDetectedMrs
	case "srs":
		return mrsDetectedSrs
	case "yaml", "yml", "text":
		return mrsDetectedText
	default:
		return detectRuleFormat(raw)
	}
}

// ── 解码结果 ─────────────────────────────────────────────────────────────────

// mrsDomainEntry 一条域名规则。subOnly 对应 mihomo 的 `.domain`（仅子域），
// 不带 subOnly 的对应精确域名。
type mrsDomainEntry struct {
	name    string
	subOnly bool
}

type mrsBodyKind int

const (
	mrsKindDomain mrsBodyKind = iota
	mrsKindIP
)

func (k mrsBodyKind) String() string {
	if k == mrsKindDomain {
		return "domain"
	}
	return "ipcidr"
}

type mrsDecoded struct {
	declaredCount int
	kind          mrsBodyKind
	domains       []mrsDomainEntry // kind == mrsKindDomain
	nets          []*net.IPNet     // kind == mrsKindIP
}

// mrsParse 解析一个完整的 .mrs 文件（zstd 压缩态）
func mrsParse(raw []byte) (*mrsDecoded, error) {
	plain, err := mrsDecompress(raw)
	if err != nil {
		return nil, err
	}
	return mrsParsePlain(plain)
}

// mrsParsePlain 解析解压后的 MRS 负载（测试可绕开 zstd 直接测头部校验）
func mrsParsePlain(plain []byte) (*mrsDecoded, error) {
	cur := &mrsCursor{buf: plain}

	if got, err := cur.take(4); err != nil || string(got) != mrsMagic {
		return nil, fmt.Errorf("格式错误: 不是 MRS v1 文件（魔数不匹配）")
	}

	behavior, err := cur.u8()
	if err != nil {
		return nil, err
	}
	declaredCount, err := cur.i64()
	if err != nil {
		return nil, err
	}
	if declaredCount < 0 {
		return nil, fmt.Errorf("格式错误: 规则条数为负: %d", declaredCount)
	}

	extraLen, err := cur.i64()
	if err != nil {
		return nil, err
	}
	if extraLen < 0 {
		return nil, fmt.Errorf("格式错误: extra 长度为负: %d", extraLen)
	}
	if err := cur.skip(int(extraLen)); err != nil {
		return nil, err
	}

	out := &mrsDecoded{declaredCount: int(declaredCount)}
	switch behavior {
	case 0:
		out.kind = mrsKindDomain
		out.domains, err = decodeMrsDomainSet(cur)
	case 1:
		out.kind = mrsKindIP
		out.nets, err = decodeMrsIPSet(cur)
	case 2:
		return nil, fmt.Errorf("格式错误: MRS 不支持 classical behavior（mihomo 只导出 domain/ipcidr）")
	default:
		return nil, fmt.Errorf("格式错误: 未知 behavior: %d（支持 0=domain, 1=ipcidr）", behavior)
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

// mrsDecompress zstd 解压（限制解压后体积，防畸形文件撑爆内存）
func mrsDecompress(raw []byte) ([]byte, error) {
	decoder, err := kpzstd.NewReader(nil,
		kpzstd.WithDecoderConcurrency(1),
		kpzstd.WithDecoderMaxMemory(maxDecompressedBytes+1<<20),
	)
	if err != nil {
		return nil, fmt.Errorf("zstd 解压失败: %w", err)
	}
	defer decoder.Close()
	out, err := decoder.DecodeAll(raw, nil)
	if err != nil {
		return nil, fmt.Errorf("zstd 解压失败: %w", err)
	}
	if len(out) > maxDecompressedBytes {
		return nil, fmt.Errorf("zstd 解压失败: 解压后超过 %d 字节上限", maxDecompressedBytes)
	}
	return out, nil
}

// ── 字节游标 ─────────────────────────────────────────────────────────────────

type mrsCursor struct {
	buf []byte
	pos int
}

func (c *mrsCursor) take(n int) ([]byte, error) {
	if n < 0 || c.pos+n > len(c.buf) || c.pos+n < c.pos {
		return nil, fmt.Errorf("数据在偏移 %d 处被截断", c.pos)
	}
	s := c.buf[c.pos : c.pos+n]
	c.pos += n
	return s, nil
}

func (c *mrsCursor) skip(n int) error {
	_, err := c.take(n)
	return err
}

func (c *mrsCursor) u8() (byte, error) {
	b, err := c.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (c *mrsCursor) u64() (uint64, error) {
	b, err := c.take(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}

func (c *mrsCursor) i64() (int64, error) {
	v, err := c.u64()
	return int64(v), err
}

// ── 128 位无符号整数（IPv6 range 运算用，Go 无 u128）─────────────────────────

type u128 struct {
	hi, lo uint64
}

func u128FromBytes(b [16]byte) u128 {
	return u128{
		hi: binary.BigEndian.Uint64(b[:8]),
		lo: binary.BigEndian.Uint64(b[8:]),
	}
}

func (a u128) bytes16() [16]byte {
	var out [16]byte
	binary.BigEndian.PutUint64(out[:8], a.hi)
	binary.BigEndian.PutUint64(out[8:], a.lo)
	return out
}

func (a u128) cmp(b u128) int {
	if a.hi != b.hi {
		if a.hi < b.hi {
			return -1
		}
		return 1
	}
	if a.lo != b.lo {
		if a.lo < b.lo {
			return -1
		}
		return 1
	}
	return 0
}

func (a u128) isZero() bool { return a.hi == 0 && a.lo == 0 }

// add 带回绕加法
func (a u128) add(b u128) u128 {
	lo, carry := bits.Add64(a.lo, b.lo, 0)
	hi, _ := bits.Add64(a.hi, b.hi, carry)
	return u128{hi: hi, lo: lo}
}

// sub 带回绕减法
func (a u128) sub(b u128) u128 {
	lo, borrow := bits.Sub64(a.lo, b.lo, 0)
	hi, _ := bits.Sub64(a.hi, b.hi, borrow)
	return u128{hi: hi, lo: lo}
}

func (a u128) trailingZeros() int {
	if a.lo != 0 {
		return bits.TrailingZeros64(a.lo)
	}
	if a.hi != 0 {
		return 64 + bits.TrailingZeros64(a.hi)
	}
	return 128
}

func (a u128) leadingZeros() int {
	if a.hi != 0 {
		return bits.LeadingZeros64(a.hi)
	}
	if a.lo != 0 {
		return 64 + bits.LeadingZeros64(a.lo)
	}
	return 128
}

// u128ShlOne 计算 1 << n（n ∈ [0, 127]；n=128 会溢出，调用方须先排除）
func u128ShlOne(n uint) u128 {
	if n == 0 {
		return u128{hi: 0, lo: 1}
	}
	if n < 64 {
		return u128{hi: 0, lo: 1 << n}
	}
	return u128{hi: 1 << (n - 64), lo: 0}
}

// ── ipcidr body ─────────────────────────────────────────────────────────────

// decodeMrsIPSet `component/cidr/ipcidr_set_bin.go`：version(1) + range 数(i64) + 每条 from/to 各 16 字节
func decodeMrsIPSet(cur *mrsCursor) ([]*net.IPNet, error) {
	version, err := cur.u8()
	if err != nil {
		return nil, err
	}
	if version != 1 {
		return nil, fmt.Errorf("格式错误: ipcidr 版本不支持: %d", version)
	}

	count, err := cur.i64()
	if err != nil {
		return nil, err
	}
	if count < 0 {
		return nil, fmt.Errorf("格式错误: ipcidr range 数为负: %d", count)
	}

	// 每条 range 至少 32 字节，先做一个粗校验，避免被巨大 count 拖死
	remaining := len(cur.buf) - cur.pos
	if remaining < 0 {
		remaining = 0
	}
	if int(count) > remaining/32 {
		return nil, fmt.Errorf("格式错误: ipcidr range 数 %d 超出剩余数据（%d 字节）", count, remaining)
	}

	var out []*net.IPNet
	for i := 0; i < int(count); i++ {
		fromRaw, err := cur.take(16)
		if err != nil {
			return nil, err
		}
		toRaw, err := cur.take(16)
		if err != nil {
			return nil, err
		}
		nets, err := mrsRangeToCIDRs(addrFrom16(fromRaw), addrFrom16(toRaw))
		if err != nil {
			return nil, err
		}
		out = append(out, nets...)
	}
	return out, nil
}

// addrFrom16 16 字节地址 → net.IP；IPv4 以 `::ffff:a.b.c.d` 形式存储（mihomo 用 `As16()`）
func addrFrom16(b []byte) net.IP {
	var a [16]byte
	copy(a[:], b[:16])
	isV4Mapped := true
	for i := 0; i < 10; i++ {
		if a[i] != 0 {
			isV4Mapped = false
			break
		}
	}
	if isV4Mapped && a[10] == 0xFF && a[11] == 0xFF {
		return net.IPv4(a[12], a[13], a[14], a[15]).To4()
	}
	ip := make(net.IP, 16)
	copy(ip, a[:])
	return ip
}

// mrsRangeToCIDRs IP range → 最小 CIDR 列表（等价于 netipx.IPRange.Prefixes()）
func mrsRangeToCIDRs(from, to net.IP) ([]*net.IPNet, error) {
	if f4 := from.To4(); f4 != nil {
		t4 := to.To4()
		if t4 == nil {
			return nil, fmt.Errorf("格式错误: IP range 的两端地址族不一致")
		}
		return rangeToCIDRsV4(f4, t4), nil
	}
	if to.To4() != nil {
		return nil, fmt.Errorf("格式错误: IP range 的两端地址族不一致")
	}
	return rangeToCIDRsV6(from.To16(), to.To16()), nil
}

func rangeToCIDRsV4(from, to net.IP) []*net.IPNet {
	cur := uint64(binary.BigEndian.Uint32(from))
	end := uint64(binary.BigEndian.Uint32(to))
	var out []*net.IPNet

	for cur <= end {
		// 当前地址能对齐到的最大块
		alignBits := uint(32)
		if cur != 0 {
			alignBits = uint(bits.TrailingZeros64(cur))
		}
		// 剩余地址数能覆盖的最大 2 的幂
		remaining := end - cur + 1
		sizeBits := uint(63 - bits.LeadingZeros64(remaining))
		if sizeBits > alignBits {
			sizeBits = alignBits
		}

		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, uint32(cur))
		out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(32-int(sizeBits), 32)})
		cur += 1 << sizeBits
	}
	return out
}

func rangeToCIDRsV6(from, to []byte) []*net.IPNet {
	cur := u128FromBytes([16]byte(from))
	end := u128FromBytes([16]byte(to))
	one := u128{hi: 0, lo: 1}
	var out []*net.IPNet

	for {
		if cur.cmp(end) > 0 {
			break
		}
		// 当前地址能对齐到的最大块
		alignBits := uint(128)
		if !cur.isZero() {
			alignBits = uint(cur.trailingZeros())
		}
		// `end - cur + 1` 在整段地址空间时会回绕成 0，此时按 2^128 处理
		remaining := end.sub(cur).add(one)
		sizeBits := uint(128)
		if !remaining.isZero() {
			sizeBits = uint(127 - remaining.leadingZeros())
		}
		if sizeBits > alignBits {
			sizeBits = alignBits
		}

		ip := cur.bytes16()
		out = append(out, &net.IPNet{IP: ip[:], Mask: net.CIDRMask(128-int(sizeBits), 128)})

		if sizeBits == 128 {
			break
		}
		// 最后一段可能正好结束在 2^128：此时 +2^bits 会回绕成 0，直接结束
		next := cur.add(u128ShlOne(sizeBits))
		if next.isZero() {
			break
		}
		cur = next
	}
	return out
}

// ── domain body（succinct trie）───────────────────────────────────────────────

// mrsDomainTrie `component/trie/domain_set_bin.go` 的内存形式
type mrsDomainTrie struct {
	// 每个节点是否为"终止节点"（对应一个 key）
	leaves []uint64
	// 每个节点子边的分隔位图：0 = 该位置有一个子边，1 = 该节点结束
	labelBitmap []uint64
	// 所有子边的标签，按节点顺序拼接
	labels []byte
	// labelBitmap 中每个 1 的位置（select 索引）
	ones []uint32
}

func parseMrsDomainTrie(cur *mrsCursor) (*mrsDomainTrie, error) {
	version, err := cur.u8()
	if err != nil {
		return nil, err
	}
	if version != 1 {
		return nil, fmt.Errorf("格式错误: domain trie 版本不支持: %d", version)
	}

	leaves, err := readMrsU64Vec(cur, "leaves")
	if err != nil {
		return nil, err
	}
	labelBitmap, err := readMrsU64Vec(cur, "labelBitmap")
	if err != nil {
		return nil, err
	}
	labels, err := readMrsBytes(cur, "labels")
	if err != nil {
		return nil, err
	}
	if len(labelBitmap) == 0 {
		return nil, fmt.Errorf("域名集合损坏: labelBitmap 为空")
	}

	var ones []uint32
	for wordIdx, word := range labelBitmap {
		if word == 0 {
			continue
		}
		for bit := 0; bit < 64; bit++ {
			if (word>>uint(bit))&1 == 1 {
				ones = append(ones, uint32(wordIdx*64+bit))
			}
		}
	}

	return &mrsDomainTrie{leaves: leaves, labelBitmap: labelBitmap, labels: labels, ones: ones}, nil
}

func mrsTrieBit(bitmap []uint64, index int) (bool, error) {
	if index < 0 || index/64 >= len(bitmap) {
		return false, fmt.Errorf("域名集合损坏: 位图下标越界: %d", index)
	}
	return (bitmap[index/64]>>uint(index%64))&1 == 1, nil
}

// select1 第 index 个 1 的位置（0-based）
func (t *mrsDomainTrie) select1(index int) (int, error) {
	if index < 0 || index >= len(t.ones) {
		return 0, fmt.Errorf("域名集合损坏: select 下标越界: %d", index)
	}
	return int(t.ones[index]), nil
}

// walk 遍历出所有 key（与 mihomo `DomainSet::keys` 完全一致的走法）
func (t *mrsDomainTrie) walk() ([]mrsDomainEntry, error) {
	// 正常情况下 key 数量 = leaves 里被置位的节点数，不可能超过 labelBitmap 位数
	budget := len(t.labelBitmap) * 64
	var out []mrsDomainEntry
	path := make([]byte, 0, 64)
	err := t.visit(0, 0, &path, &out, &budget, 0)
	return out, err
}

func (t *mrsDomainTrie) visit(nodeID, start int, path *[]byte, out *[]mrsDomainEntry, budget *int, depth int) error {
	if depth > maxTrieDepth {
		return fmt.Errorf("域名集合损坏: trie 深度超过 %d", maxTrieDepth)
	}

	if leaf, err := mrsTrieBit(t.leaves, nodeID); err != nil {
		return err
	} else if leaf {
		if *budget == 0 {
			return fmt.Errorf("域名集合损坏: key 数量异常，疑似数据损坏")
		}
		*budget--
		if entry := decodeMrsKey(*path); entry != nil {
			*out = append(*out, *entry)
		}
	}

	bm := start
	for {
		isEnd, err := mrsTrieBit(t.labelBitmap, bm)
		if err != nil {
			return err
		}
		if isEnd {
			return nil
		}

		labelIdx := bm - nodeID
		if labelIdx < 0 {
			return fmt.Errorf("域名集合损坏: 标签下标为负: %d - %d", bm, nodeID)
		}
		if labelIdx >= len(t.labels) {
			return fmt.Errorf("域名集合损坏: 标签下标越界: %d", labelIdx)
		}
		label := t.labels[labelIdx]

		childID := bm - nodeID + 1
		if childID <= 0 {
			return fmt.Errorf("域名集合损坏: 子节点下标为 0")
		}
		pos, err := t.select1(childID - 1)
		if err != nil {
			return err
		}
		childStart := pos + 1

		*path = append(*path, label)
		if err := t.visit(childID, childStart, path, out, budget, depth+1); err != nil {
			return err
		}
		*path = (*path)[:len(*path)-1]

		bm++
	}
}

func readMrsU64Vec(cur *mrsCursor, what string) ([]uint64, error) {
	length, err := cur.i64()
	if err != nil {
		return nil, err
	}
	if length < 0 {
		return nil, fmt.Errorf("格式错误: %s 长度为负: %d", what, length)
	}
	remaining := len(cur.buf) - cur.pos
	if remaining < 0 {
		remaining = 0
	}
	if int(length) > remaining/8 {
		return nil, fmt.Errorf("格式错误: %s 长度 %d 超出剩余数据（%d 字节）", what, length, remaining)
	}
	out := make([]uint64, 0, length)
	for i := 0; i < int(length); i++ {
		v, err := cur.u64()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func readMrsBytes(cur *mrsCursor, what string) ([]byte, error) {
	length, err := cur.i64()
	if err != nil {
		return nil, err
	}
	if length < 0 {
		return nil, fmt.Errorf("格式错误: %s 长度为负: %d", what, length)
	}
	return cur.take(int(length))
}

// decodeMrsKey 还原一个 trie key：内部是逐 rune 反转的字符串，后缀规则末尾多一个 `'+'`。
//
// 与 mihomo `DomainSet::Foreach` 一致：先去尾部 `'+'`，再按 rune 反转。
// 以 `.` 开头的结果表示"仅匹配子域"。
func decodeMrsKey(path []byte) *mrsDomainEntry {
	key := string(path)
	key = strings.TrimSuffix(key, "+")
	// 逐 rune 反转与 Go 的 utils.Reverse 对齐（非 ASCII 只有按 rune 反转才正确）
	runes := []rune(key)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	domain := string(runes)

	if rest, ok := strings.CutPrefix(domain, "."); ok {
		if rest == "" {
			return nil
		}
		return &mrsDomainEntry{name: rest, subOnly: true}
	}
	if domain == "" {
		return nil
	}
	return &mrsDomainEntry{name: domain, subOnly: false}
}

func decodeMrsDomainSet(cur *mrsCursor) ([]mrsDomainEntry, error) {
	trie, err := parseMrsDomainTrie(cur)
	if err != nil {
		return nil, err
	}
	return trie.walk()
}
