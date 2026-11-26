//! `.mrs`（mihomo rule-set v1 二进制）解码器。
//!
//! 只有 `domain` / `ipcidr` 两种 behavior 有 MRS 编码，`classical` 没有。
//!
//! 容器（`rules/provider/mrs_reader.go`）：整文件用 zstd 压缩，解压后依次是
//!
//! ```text
//! "MRS\x01" | behavior(1) | count(i64 BE) | extra_len(i64 BE) | extra(count 字节) | body
//! ```
//!
//! - `behavior`: 0 = domain，1 = ipcidr，2 = classical（MRS 不支持）
//! - `count`: 规则条数（仅用于统计，解码时以 body 的实际内容为准）
//! - `extra`: 预留字段，跳过
//!
//! body 的两种编码：
//! - domain：succinct trie（`component/trie/domain_set_bin.go`）
//! - ipcidr：IP range 列表（`component/cidr/ipcidr_set_bin.go`）
//!
//! 注意：domain trie 里的 key 是**逐 rune 反转**的字符串，后缀规则会在末尾多一个
//! `'+'` 标记（见 `trie.DomainSetBuilder::insert`），解码时必须按同样的规则还原，
//! 否则会把 `+.google.com` 误判成精确域名。

use std::fmt;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnetwork::IpNetwork;

/// MRS 解压后的文件头（`MrsMagicBytes`）。
const MRS_MAGIC: &[u8; 4] = b"MRS\x01";
/// zstd 帧头；MRS 外层固定是 zstd，可据此在不解压的情况下识别。
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
/// sing-box 规则集（`.srs`）的明文魔数。
const SRS_MAGIC: &[u8; 3] = b"SRS";

/// domain 的 trie 最大深度（DNS 名最长 253 字节，留足余量）。
const MAX_TRIE_DEPTH: usize = 512;
/// 解压后的体积上限，防止畸形/恶意文件把内存撑爆。
const MAX_DECOMPRESSED_BYTES: usize = 256 * 1024 * 1024;

// ── 格式识别 ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detected {
    /// zstd 帧头 → 尝试按 MRS 解析。
    Mrs,
    /// 明文 `SRS` → sing-box 规则集（不支持）。
    Srs,
    /// 其它 → 按 UTF-8 文本处理。
    Text,
}

/// 按文件头识别格式。MRS 的魔数在 zstd 内部，所以只能先看 zstd 帧头。
pub fn detect(bytes: &[u8]) -> Detected {
    if bytes.starts_with(&ZSTD_MAGIC) {
        Detected::Mrs
    } else if bytes.starts_with(SRS_MAGIC) {
        Detected::Srs
    } else {
        Detected::Text
    }
}

// ── 错误 ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum MrsError {
    Zstd(String),
    Format(String),
    Truncated(usize),
    Trie(String),
}

impl fmt::Display for MrsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MrsError::Zstd(e) => write!(f, "zstd 解压失败: {}", e),
            MrsError::Format(e) => write!(f, "格式错误: {}", e),
            MrsError::Truncated(pos) => write!(f, "数据在偏移 {} 处被截断", pos),
            MrsError::Trie(e) => write!(f, "域名集合损坏: {}", e),
        }
    }
}

impl std::error::Error for MrsError {}

// ── 解码结果 ─────────────────────────────────────────────────────────────────

/// 一条域名规则。`sub_only` 对应 mihomo 的 `.domain`（仅子域），
/// 不带 `sub_only` 的对应精确域名。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainEntry {
    pub name: String,
    pub sub_only: bool,
}

#[derive(Debug)]
pub enum MrsBody {
    Domain(Vec<DomainEntry>),
    IpCidr(Vec<IpNetwork>),
}

impl MrsBody {
    pub fn kind(&self) -> &'static str {
        match self {
            MrsBody::Domain(_) => "domain",
            MrsBody::IpCidr(_) => "ipcidr",
        }
    }
}

#[derive(Debug)]
pub struct Decoded {
    /// 文件里声明的规则条数。
    pub declared_count: usize,
    pub body: MrsBody,
}

// ── 入口 ─────────────────────────────────────────────────────────────────────

/// 解析一个完整的 `.mrs` 文件（zstd 压缩态）。
pub fn parse(bytes: &[u8]) -> Result<Decoded, MrsError> {
    let raw = decompress(bytes)?;
    parse_decompressed(&raw)
}

fn decompress(bytes: &[u8]) -> Result<Vec<u8>, MrsError> {
    let decoder = ruzstd::decoding::StreamingDecoder::new(bytes)
        .map_err(|e| MrsError::Zstd(e.to_string()))?;
    let mut out = Vec::new();
    // `.take()` 同时限制了解压后的内存占用
    decoder
        .take(MAX_DECOMPRESSED_BYTES as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| MrsError::Zstd(e.to_string()))?;
    if out.len() > MAX_DECOMPRESSED_BYTES {
        return Err(MrsError::Zstd(format!(
            "解压后超过 {} 字节上限",
            MAX_DECOMPRESSED_BYTES
        )));
    }
    Ok(out)
}

fn parse_decompressed(raw: &[u8]) -> Result<Decoded, MrsError> {
    let mut cur = Cursor::new(raw);

    if cur.take(4)? != MRS_MAGIC {
        return Err(MrsError::Format("不是 MRS v1 文件（魔数不匹配）".into()));
    }

    let behavior = cur.u8()?;
    let declared_count = cur.i64()?;
    if declared_count < 0 {
        return Err(MrsError::Format(format!(
            "规则条数为负: {}",
            declared_count
        )));
    }

    let extra_len = cur.i64()?;
    if extra_len < 0 {
        return Err(MrsError::Format(format!("extra 长度为负: {}", extra_len)));
    }
    cur.skip(extra_len as usize)?;

    let body = match behavior {
        0 => MrsBody::Domain(decode_domain_set(&mut cur)?),
        1 => MrsBody::IpCidr(decode_ip_set(&mut cur)?),
        2 => {
            return Err(MrsError::Format(
                "MRS 不支持 classical behavior（mihomo 只导出 domain/ipcidr）".into(),
            ))
        }
        other => {
            return Err(MrsError::Format(format!(
                "未知 behavior: {}（支持 0=domain, 1=ipcidr）",
                other
            )))
        }
    };

    Ok(Decoded {
        declared_count: declared_count as usize,
        body,
    })
}

// ── 字节游标 ─────────────────────────────────────────────────────────────────

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], MrsError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(MrsError::Truncated(self.pos))?;
        if end > self.buf.len() {
            return Err(MrsError::Truncated(self.pos));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn skip(&mut self, n: usize) -> Result<(), MrsError> {
        self.take(n).map(|_| ())
    }

    fn u8(&mut self) -> Result<u8, MrsError> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, MrsError> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn i64(&mut self) -> Result<i64, MrsError> {
        Ok(self.u64()? as i64)
    }
}

// ── ipcidr body ─────────────────────────────────────────────────────────────

/// `component/cidr/ipcidr_set_bin.go`：version(1) + range 数(i64) + 每条 from/to 各 16 字节。
fn decode_ip_set(cur: &mut Cursor<'_>) -> Result<Vec<IpNetwork>, MrsError> {
    let version = cur.u8()?;
    if version != 1 {
        return Err(MrsError::Format(format!("ipcidr 版本不支持: {}", version)));
    }

    let count = cur.i64()?;
    if count < 0 {
        return Err(MrsError::Format(format!("ipcidr range 数为负: {}", count)));
    }

    // 每条 range 至少 32 字节，先做一个粗校验，避免被巨大 count 拖死。
    let remaining = cur.buf.len().saturating_sub(cur.pos);
    if (count as usize) > remaining / 32 {
        return Err(MrsError::Format(format!(
            "ipcidr range 数 {} 超出剩余数据（{} 字节）",
            count, remaining
        )));
    }

    let mut out = Vec::new();
    for _ in 0..count {
        let from = addr_from_16(cur.take(16)?);
        let to = addr_from_16(cur.take(16)?);
        out.extend(range_to_cidrs(from, to)?);
    }
    Ok(out)
}

/// 16 字节地址 → IpAddr；IPv4 以 `::ffff:a.b.c.d` 形式存储（mihomo 用 `As16()`）。
fn addr_from_16(bytes: &[u8]) -> IpAddr {
    let mut a = [0u8; 16];
    a.copy_from_slice(&bytes[..16]);
    let is_v4_mapped = a[..10].iter().all(|&b| b == 0) && a[10] == 0xFF && a[11] == 0xFF;
    if is_v4_mapped {
        IpAddr::V4(Ipv4Addr::new(a[12], a[13], a[14], a[15]))
    } else {
        IpAddr::V6(Ipv6Addr::from(a))
    }
}

/// IP range → 最小 CIDR 列表（等价于 `netipx.IPRange.Prefixes()`）。
fn range_to_cidrs(from: IpAddr, to: IpAddr) -> Result<Vec<IpNetwork>, MrsError> {
    match (from, to) {
        (IpAddr::V4(from), IpAddr::V4(to)) => Ok(range_to_cidrs_v4(from, to)),
        (IpAddr::V6(from), IpAddr::V6(to)) => Ok(range_to_cidrs_v6(from, to)),
        _ => Err(MrsError::Format("IP range 的两端地址族不一致".into())),
    }
}

fn range_to_cidrs_v4(from: Ipv4Addr, to: Ipv4Addr) -> Vec<IpNetwork> {
    let mut cur = u32::from(from) as u64;
    let end = u32::from(to) as u64;
    let mut out = Vec::new();

    while cur <= end {
        // 当前地址能对齐到的最大块
        let align_bits = if cur == 0 { 32 } else { cur.trailing_zeros() };
        // 剩余地址数能覆盖的最大 2 的幂
        let remaining = end - cur + 1;
        let size_bits = 63 - remaining.leading_zeros();
        let bits = align_bits.min(size_bits);

        if let Ok(net) = IpNetwork::new(IpAddr::V4(Ipv4Addr::from(cur as u32)), (32 - bits) as u8) {
            out.push(net);
        }
        cur += 1u64 << bits;
    }
    out
}

fn range_to_cidrs_v6(from: Ipv6Addr, to: Ipv6Addr) -> Vec<IpNetwork> {
    let mut cur = u128::from(from);
    let end = u128::from(to);
    let mut out = Vec::new();

    loop {
        if cur > end {
            break;
        }
        let align_bits = if cur == 0 { 128 } else { cur.trailing_zeros() };
        // `end - cur + 1` 在整段地址空间时会溢出成 0，此时按 2^128 处理
        let remaining = (end - cur).wrapping_add(1);
        let size_bits = if remaining == 0 {
            128
        } else {
            127 - remaining.leading_zeros()
        };
        let bits = align_bits.min(size_bits);

        if let Ok(net) = IpNetwork::new(IpAddr::V6(Ipv6Addr::from(cur)), (128 - bits) as u8) {
            out.push(net);
        }
        if bits == 128 {
            break;
        }
        // 最后一段可能正好结束在 2^128：此时 +2^bits 会回绕成 0，直接结束。
        let next = cur.wrapping_add(1u128 << bits);
        if next == 0 {
            break;
        }
        cur = next;
    }
    out
}

// ── domain body（succinct trie）───────────────────────────────────────────────

/// `component/trie/domain_set_bin.go` 的内存形式。
struct DomainTrie {
    /// 每个节点是否为"终止节点"（对应一个 key）。
    leaves: Vec<u64>,
    /// 每个节点子边的分隔位图：0 = 该位置有一个子边，1 = 该节点结束。
    label_bitmap: Vec<u64>,
    /// 所有子边的标签，按节点顺序拼接。
    labels: Vec<u8>,
    /// label_bitmap 中每个 1 的位置（`select` 索引）。
    ones: Vec<u32>,
}

impl DomainTrie {
    fn parse(cur: &mut Cursor<'_>) -> Result<Self, MrsError> {
        let version = cur.u8()?;
        if version != 1 {
            return Err(MrsError::Format(format!(
                "domain trie 版本不支持: {}",
                version
            )));
        }

        let leaves = read_u64_vec(cur, "leaves")?;
        let label_bitmap = read_u64_vec(cur, "labelBitmap")?;
        let labels = read_bytes(cur, "labels")?;

        if label_bitmap.is_empty() {
            return Err(MrsError::Trie("labelBitmap 为空".into()));
        }

        let mut ones = Vec::new();
        for word_idx in 0..label_bitmap.len() {
            let word = label_bitmap[word_idx];
            if word == 0 {
                continue;
            }
            for bit in 0..64 {
                if (word >> bit) & 1 == 1 {
                    ones.push((word_idx * 64 + bit) as u32);
                }
            }
        }

        Ok(Self {
            leaves,
            label_bitmap,
            labels,
            ones,
        })
    }

    fn bit(bitmap: &[u64], index: usize) -> Result<bool, MrsError> {
        let word = *bitmap
            .get(index / 64)
            .ok_or_else(|| MrsError::Trie(format!("位图下标越界: {}", index)))?;
        Ok((word >> (index % 64)) & 1 == 1)
    }

    /// 第 `index` 个 1 的位置（0-based）。
    fn select(&self, index: usize) -> Result<usize, MrsError> {
        self.ones
            .get(index)
            .map(|&v| v as usize)
            .ok_or_else(|| MrsError::Trie(format!("select 下标越界: {}", index)))
    }

    /// 遍历出所有 key（与 `DomainSet::keys` 完全一致的走法）。
    fn walk(&self) -> Result<Vec<DomainEntry>, MrsError> {
        // 正常情况下 key 数量 = leaves 里被置位的节点数，不可能超过 labelBitmap 位数。
        let mut budget = self.label_bitmap.len() * 64;
        let mut out = Vec::new();
        let mut path = Vec::with_capacity(64);
        self.visit(0, 0, &mut path, &mut out, &mut budget, 0)?;
        Ok(out)
    }

    fn visit(
        &self,
        node_id: usize,
        start: usize,
        path: &mut Vec<u8>,
        out: &mut Vec<DomainEntry>,
        budget: &mut usize,
        depth: usize,
    ) -> Result<(), MrsError> {
        if depth > MAX_TRIE_DEPTH {
            return Err(MrsError::Trie(format!("trie 深度超过 {}", MAX_TRIE_DEPTH)));
        }

        if Self::bit(&self.leaves, node_id)? {
            if *budget == 0 {
                return Err(MrsError::Trie("key 数量异常，疑似数据损坏".into()));
            }
            *budget -= 1;
            if let Some(entry) = decode_key(path) {
                out.push(entry);
            }
        }

        let mut bm = start;
        loop {
            if Self::bit(&self.label_bitmap, bm)? {
                return Ok(());
            }

            let label_idx = bm
                .checked_sub(node_id)
                .ok_or_else(|| MrsError::Trie(format!("标签下标为负: {} - {}", bm, node_id)))?;
            let label = *self
                .labels
                .get(label_idx)
                .ok_or_else(|| MrsError::Trie(format!("标签下标越界: {}", label_idx)))?;

            let child_id = bm
                .checked_sub(node_id)
                .and_then(|x| x.checked_add(1))
                .ok_or_else(|| MrsError::Trie("子节点下标溢出".into()))?;
            let child_start = self
                .select(
                    child_id
                        .checked_sub(1)
                        .ok_or_else(|| MrsError::Trie("子节点下标为 0".into()))?,
                )?
                .checked_add(1)
                .ok_or_else(|| MrsError::Trie("子节点起始位置溢出".into()))?;

            path.push(label);
            self.visit(child_id, child_start, path, out, budget, depth + 1)?;
            path.pop();

            bm += 1;
        }
    }
}

fn read_u64_vec(cur: &mut Cursor<'_>, what: &str) -> Result<Vec<u64>, MrsError> {
    let len = cur.i64()?;
    if len < 0 {
        return Err(MrsError::Format(format!("{} 长度为负: {}", what, len)));
    }
    let remaining = cur.buf.len().saturating_sub(cur.pos);
    if (len as usize) > remaining / 8 {
        return Err(MrsError::Format(format!(
            "{} 长度 {} 超出剩余数据（{} 字节）",
            what, len, remaining
        )));
    }
    let mut out = Vec::with_capacity(len as usize);
    for _ in 0..len {
        out.push(cur.u64()?);
    }
    Ok(out)
}

fn read_bytes(cur: &mut Cursor<'_>, what: &str) -> Result<Vec<u8>, MrsError> {
    let len = cur.i64()?;
    if len < 0 {
        return Err(MrsError::Format(format!("{} 长度为负: {}", what, len)));
    }
    Ok(cur.take(len as usize)?.to_vec())
}

/// 还原一个 trie key：内部是逐 rune 反转的字符串，后缀规则末尾多一个 `'+'`。
///
/// 与 `DomainSet::Foreach` 一致：先去尾部 `'+'`，再按 rune 反转。
/// 以 `.` 开头的结果表示"仅匹配子域"。
fn decode_key(path: &[u8]) -> Option<DomainEntry> {
    let key = std::str::from_utf8(path).ok()?;
    let key = key.strip_suffix('+').unwrap_or(key);
    // 逐 rune 反转与 Go 的 utils.Reverse 对齐（非 ASCII 只有按 rune 反转才正确）
    let domain: String = key.chars().rev().collect();

    if let Some(rest) = domain.strip_prefix('.') {
        if rest.is_empty() {
            return None;
        }
        Some(DomainEntry {
            name: rest.to_string(),
            sub_only: true,
        })
    } else if domain.is_empty() {
        None
    } else {
        Some(DomainEntry {
            name: domain,
            sub_only: false,
        })
    }
}

fn decode_domain_set(cur: &mut Cursor<'_>) -> Result<Vec<DomainEntry>, MrsError> {
    let trie = DomainTrie::parse(cur)?;
    trie.walk()
}

// ── 测试 ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("mrs")
            .join(name)
    }

    fn read_fixture(name: &str) -> Vec<u8> {
        std::fs::read(fixture(name)).unwrap_or_else(|e| panic!("读取 fixture {} 失败: {}", name, e))
    }

    /// `.list` 源文件 → (精确域名集合, 后缀域名集合)。
    fn parse_list(text: &str) -> (Vec<String>, Vec<String>) {
        let mut exact = Vec::new();
        let mut suffix = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("+.") {
                suffix.push(rest.to_lowercase());
            } else if let Some(rest) = line.strip_prefix('.') {
                suffix.push(rest.to_lowercase());
            } else {
                exact.push(line.to_lowercase());
            }
        }
        exact.sort();
        suffix.sort();
        (exact, suffix)
    }

    /// 解码结果 → (精确域名集合, 后缀域名集合)。
    fn split_decoded(entries: &[DomainEntry]) -> (Vec<String>, Vec<String>) {
        let mut exact = Vec::new();
        let mut suffix = Vec::new();
        for e in entries {
            if e.sub_only {
                suffix.push(e.name.to_lowercase());
            } else {
                exact.push(e.name.to_lowercase());
            }
        }
        exact.sort();
        suffix.sort();
        (exact, suffix)
    }

    #[test]
    fn detect_recognises_all_three_formats() {
        assert_eq!(detect(&read_fixture("115.mrs")), Detected::Mrs);
        assert_eq!(detect(b"SRS\x05rest"), Detected::Srs);
        assert_eq!(detect(b"payload:\n  - example.com\n"), Detected::Text);
        assert_eq!(detect(b"+.example.com\n"), Detected::Text);
    }

    #[test]
    fn decode_tiny_domain_set_matches_source_list() {
        let decoded = parse(&read_fixture("115.mrs")).expect("解析 115.mrs");
        let MrsBody::Domain(entries) = decoded.body else {
            panic!("115.mrs 应该是 domain");
        };

        let (list_exact, list_suffix) =
            parse_list(&std::fs::read_to_string(fixture("115.list")).unwrap());
        let (got_exact, got_suffix) = split_decoded(&entries);

        // `+.d` 会同时写入精确 d 与后缀 d，所以精确集合 = 源文件的精确 + 后缀。
        let mut expected_exact = list_exact.clone();
        expected_exact.extend(list_suffix.iter().cloned());
        expected_exact.sort();

        assert_eq!(got_suffix, list_suffix, "后缀集合不一致");
        assert_eq!(got_exact, expected_exact, "精确集合不一致");
        assert!(
            got_suffix.contains(&"115.com".to_string()),
            "应包含 115.com 后缀规则: {:?}",
            got_suffix
        );
        assert_eq!(decoded.declared_count, 14, "声明条数");
    }

    #[test]
    fn decode_medium_domain_set_matches_source_list() {
        let decoded =
            parse(&read_fixture("category-ads-all.mrs")).expect("解析 category-ads-all.mrs");
        let MrsBody::Domain(entries) = decoded.body else {
            panic!("category-ads-all.mrs 应该是 domain");
        };

        let (list_exact, list_suffix) =
            parse_list(&std::fs::read_to_string(fixture("category-ads-all.list")).unwrap());
        let (got_exact, got_suffix) = split_decoded(&entries);

        let mut expected_exact = list_exact.clone();
        expected_exact.extend(list_suffix.iter().cloned());
        expected_exact.sort();

        assert_eq!(got_suffix, list_suffix, "后缀集合不一致");
        assert_eq!(got_exact, expected_exact, "精确集合不一致");
        assert_eq!(entries.len(), list_exact.len() + list_suffix.len() * 2);
    }

    #[test]
    fn decode_tiny_ip_set_matches_source_list() {
        let decoded = parse(&read_fixture("private.mrs")).expect("解析 private.mrs");
        let MrsBody::IpCidr(nets) = decoded.body else {
            panic!("private.mrs 应该是 ipcidr");
        };

        let list: Vec<IpNetwork> = std::fs::read_to_string(fixture("private.list"))
            .unwrap()
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| {
                l.parse::<IpNetwork>()
                    .unwrap_or_else(|e| panic!("非法 CIDR {}: {}", l, e))
            })
            .collect();

        // 解码结果按 CIDR 规范化后应与源文件逐条相等（range 本身都是对齐的）。
        let mut got: Vec<String> = nets.iter().map(|n| n.to_string()).collect();
        let mut want: Vec<String> = list.iter().map(|n| n.to_string()).collect();
        got.sort();
        want.sort();
        assert_eq!(got, want);
        assert_eq!(decoded.declared_count, list.len());
    }

    #[test]
    fn decode_large_ip_set_matches_source_prefixes() {
        let decoded = parse(&read_fixture("cn.mrs")).expect("解析 cn.mrs");
        let MrsBody::IpCidr(nets) = decoded.body else {
            panic!("cn.mrs 应该是 ipcidr");
        };
        assert!(nets.len() > 1000, "cn.mrs 应有上千条，实际 {}", nets.len());

        // 每条源前缀的首尾地址都必须落在解码结果内。
        for line in std::fs::read_to_string(fixture("cn.list")).unwrap().lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Ok(net) = line.parse::<IpNetwork>() else {
                continue;
            };
            for ip in [net.network(), net.broadcast()] {
                assert!(
                    nets.iter().any(|n| n.contains(ip)),
                    "解码结果未覆盖 {} 的地址 {}",
                    line,
                    ip
                );
            }
        }
    }

    #[test]
    fn corrupted_stream_is_rejected() {
        assert!(parse(b"not-a-zstd-frame").is_err());

        // zstd 帧头 + 垃圾数据：解压阶段就应该失败
        let mut junk = ZSTD_MAGIC.to_vec();
        junk.extend_from_slice(&[0u8; 32]);
        assert!(parse(&junk).is_err());
    }

    #[test]
    fn classical_and_unknown_behaviors_are_rejected() {
        // 直接构造解压后的负载，绕开压缩，专门测头部校验
        let mut raw = MRS_MAGIC.to_vec();
        raw.push(2); // classical
        raw.extend_from_slice(&0i64.to_be_bytes());
        raw.extend_from_slice(&0i64.to_be_bytes());
        let msg = parse_decompressed(&raw).unwrap_err().to_string();
        assert!(msg.contains("classical"), "unexpected: {}", msg);

        let mut raw = MRS_MAGIC.to_vec();
        raw.push(7); // 未知
        raw.extend_from_slice(&0i64.to_be_bytes());
        raw.extend_from_slice(&0i64.to_be_bytes());
        assert!(parse_decompressed(&raw).is_err());
    }

    #[test]
    fn range_to_cidrs_handles_edges() {
        // 整个 IPv4 空间
        let all = range_to_cidrs(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::BROADCAST),
        )
        .unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].to_string(), "0.0.0.0/0");

        // 单个地址
        let one = range_to_cidrs(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        )
        .unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].to_string(), "1.2.3.4/32");

        // 非对齐小段
        let few = range_to_cidrs(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6)),
        )
        .unwrap();
        let got: Vec<String> = few.iter().map(|n| n.to_string()).collect();
        assert_eq!(
            got,
            vec!["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"]
        );
    }

    #[test]
    fn decode_key_restores_suffix_marker() {
        // 内部 key 是反转 + 末尾 '+'；还原后应是「仅子域」的 google.com
        let entry = decode_key(b"moc.elgoog.+").unwrap();
        assert_eq!(entry.name, "google.com");
        assert!(entry.sub_only);

        let entry = decode_key(b"moc.elgoog").unwrap();
        assert_eq!(entry.name, "google.com");
        assert!(!entry.sub_only);
    }
}
