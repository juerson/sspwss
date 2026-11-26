import { connect } from 'cloudflare:sockets';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// ==================== 1. 配置与常量 ====================
const CONFIG = {
  LOG_LEVEL: 'ERROR',           // DEBUG, INFO, WARN, ERROR
  LOG_MODULES: ['SESSION', 'REPLAY', 'ERROR'],
  HANDSHAKE_TIMEOUT: 10000,    // 握手超时 10s
  CONNECT_TIMEOUT: 5000,       // 后端连接超时 5s
  CHUNK_SIZE: 16 * 1024,       // 数据分片 16KB
  REPLAY_WINDOW_SEC: 300,      // 重放保护时间窗口 5min
  STREAM_IDLE_TIMEOUT: 60000,  // 流空闲超时 60s
  SESSION_IDLE_TIMEOUT: 300000, // 会话空闲超时 5分钟
  DOH_URL: 'https://1.1.1.1/dns-query', // DNS 帧上游（可用 env.DOHDNS_URL 覆盖）
  DNS_CACHE_MAX: 1024,         // DNS 响应缓存条目上限
  DNS_TTL_SEC: 60,             // DNS 响应缓存时长（固定值，不解析记录级 TTL）
  DNS_MAX_INFLIGHT: 64,        // 单会话并发 DoH 上限，超出直接 SERVFAIL
  // 子请求预算：每次 connect()/DoH fetch() 都算 1 个子请求，免费计划每条
  // WS 会话（invocation）一生只有 50 个。达到阈值后拒绝新流（客户端换槽），
  // 存量流继续，空闲后优雅回收会话（客户端自动重拨获得全新预算）。
  // 付费计划可用 env.SUBREQUEST_BUDGET 调高（如 900）。
  SUBREQUEST_BUDGET: 45,
  // 单会话流量预算（字节）：CPU 中位数 ≈ 字节数 ÷ AES 吞吐，限制每会话
  // 转发字节即限制仪表盘 CPU 数值（128MB ≈ 100~200ms CPU）。
  // 预算任一项（子请求/流量）耗尽：拒绝新流 + 存量流排空后回收会话。
  // 付费计划可用 env.BYTES_BUDGET 调大（单位 MB）。
  BYTES_BUDGET: 128 * 1024 * 1024,
};

// 缓存常用编码结果
const CACHED_INFO = {
  handshake: encoder.encode('sspv1.4-handshake'),
  salt: encoder.encode('sspv1.4-salt'),
  tx: encoder.encode('sspv1.4-tx'),
  rx: encoder.encode('sspv1.4-rx'),
};

// ==================== 全局 Buffer 池（减少 GC） ====================
const BUFFER_POOL = (() => {
  const pool = [];
  const MAX_POOL_SIZE = 8;
  const POOL_MAX_SIZE = 65536;

  return {
    acquire(size) {
      const idx = pool.findIndex(buf => buf.length >= size && buf.length <= size * 2);
      if (idx >= 0) {
        const buf = pool.splice(idx, 1)[0];
        buf.fill(0);
        return buf;
      }
      const allocSize = size < 1024 ? 1024 : Math.pow(2, Math.ceil(Math.log2(size)));
      return new Uint8Array(Math.min(allocSize, POOL_MAX_SIZE));
    },
    release(buf) {
      if (!buf || pool.length >= MAX_POOL_SIZE) return;
      if (buf.length >= 256 && buf.length <= 16384) {
        buf.fill(0);
        pool.push(buf);
      }
    }
  };
})();

// ==================== 协议定义 ====================
const PROTOCOL = {
  TYPE_DATA: 0x01,
  TYPE_OPEN: 0x02,
  TYPE_CLOSE: 0x03,
  TYPE_DNS: 0x04,   // v1.5: DNS 查询帧（payload = reqId(2B) + DNS wire query）
  TYPE_HEART: 0x05,
  HEADER_LEN: 8,
};

// ==================== 2. 工具函数 ====================
const log = (() => {
  const levels = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };
  const minLevel = levels[CONFIG.LOG_LEVEL] ?? 3;
  const enabled = new Set(CONFIG.LOG_MODULES);
  const fns = { DEBUG: console.log, INFO: console.log, WARN: console.warn, ERROR: console.error };

  return (module, level, ...args) => {
    if (!enabled.has(module) || levels[level] < minLevel) return;
    fns[level]?.(`[${module}]`, ...args);
  };
})();

// 将 WebSocket 二进制消息统一为 Uint8Array。
// compatibility_date >= 2026-03-17 时 binaryType 默认是 "blob"（e.data 为 Blob），
// 旧日期下是 ArrayBuffer。这里同时兼容 Blob / ArrayBuffer / TypedArray，
// 保证升级兼容日期后握手与数据帧不会被静默丢弃。
const toBytes = async (data) => {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  if (typeof Blob !== 'undefined' && data instanceof Blob) return new Uint8Array(await data.arrayBuffer());
  return new Uint8Array(data);
};

const parseAddr = (addr) => {
  if (addr.startsWith('[')) {
    const end = addr.indexOf(']');
    if (end > 0) {
      const host = addr.slice(1, end);
      const port = addr.charAt(end + 1) === ':' ? parseInt(addr.slice(end + 2)) || 443 : 443;
      return [host, port];
    }
  }
  const colon = addr.lastIndexOf(':');
  if (colon > 0) {
    const port = parseInt(addr.slice(colon + 1));
    if (!isNaN(port)) return [addr.slice(0, colon), port];
  }
  return [addr, 443];
};

// ==================== DNS wire 辅助 ====================
// 从 DNS 查询报文提取 "qname|qtype" 缓存键；解析失败返回 null（不缓存）。
function dnsCacheKey(query) {
  if (query.length < 17) return null; // 头部 12B + 终止符 + qtype/qclass 4B
  const qdcount = (query[4] << 8) | query[5];
  if (qdcount !== 1) return null;
  let pos = 12;
  const labels = [];
  while (pos < query.length) {
    const len = query[pos];
    if (len === 0) { pos += 1; break; }
    if (len & 0xC0) return null; // 查询段不允许压缩指针
    if (pos + 1 + len > query.length) return null;
    for (let i = 0; i < len; i++) {
      const c = query[pos + 1 + i];
      labels.push(c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : String.fromCharCode(c));
    }
    labels.push('.');
    pos += 1 + len;
  }
  if (pos + 4 > query.length) return null;
  const qtype = (query[pos] << 8) | query[pos + 1];
  return `${labels.join('')}|${qtype}`;
}

// 用查询报文构造 SERVFAIL 响应（保留 ID / RD 位，回包让客户端快速失败而非等超时）
function dnsServfail(query) {
  const out = new Uint8Array(Math.min(query.length, 12));
  out.set(query.subarray(0, out.length));
  out[2] = 0x81; // QR=1, RD=1
  out[3] = 0x82; // RA=1, RCODE=2 (SERVFAIL)
  out[6] = 0; out[7] = 0; out[8] = 0; out[9] = 0; out[10] = 0; out[11] = 0;
  return out;
}

// ==================== 3. 密码学模块 ====================
class SSPCrypto {
  constructor(psk) {
    this.psk = encoder.encode(psk);
    this.nonceCounter = 0n;
    this.handshakeKey = null;
    this.txKey = null;
    this.rxKey = null;
    this.fixedSuffix = null;
    this.randomPool = crypto.getRandomValues(new Uint8Array(256));
    this.poolPtr = 0;
    this._privateKey = null;
    this._publicKey = null;
    this.sharedSecret = null;
    this.replay = new ReplayProtection(CONFIG.REPLAY_WINDOW_SEC);
  }

  async init() {
    const keyPair = /** @type {CryptoKeyPair} */(await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']));
    this._privateKey = keyPair.privateKey;
    this._publicKey = keyPair.publicKey;
    const pskKey = await crypto.subtle.importKey('raw', this.psk, 'HKDF', false, ['deriveKey']);
    this.handshakeKey = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(16), info: CACHED_INFO.handshake },
      pskKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }

  async exportPublicKey() {
    return new Uint8Array(/** @type {ArrayBuffer} */(await crypto.subtle.exportKey('raw', this._publicKey)));
  }

  async deriveSharedSecret(peerPublicKey) {
    const importedKey = await crypto.subtle.importKey('raw', peerPublicKey, { name: 'X25519' }, false, []);
    const bits = await crypto.subtle.deriveBits(/** @type {any} */({ name: 'X25519', public: importedKey }), this._privateKey, 256);
    this.sharedSecret = new Uint8Array(bits);
  }

  async initSessionKeys() {
    if (!this.sharedSecret) throw new Error('No shared secret');
    const sharedKey = await crypto.subtle.importKey('raw', this.sharedSecret, 'HKDF', false, ['deriveBits', 'deriveKey']);
    const saltBits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: this.psk, info: CACHED_INFO.salt }, sharedKey, 128
    );
    const sessionSalt = new Uint8Array(saltBits);
    this.fixedSuffix = sessionSalt.slice(0, 4);
    this.txKey = await this._deriveKey(sharedKey, this.psk, sessionSalt, 'tx');
    this.rxKey = await this._deriveKey(sharedKey, this.psk, sessionSalt, 'rx');
    this.psk = null; this.sharedSecret = null; // 清理敏感数据
  }

  async _deriveKey(sharedKey, psk, salt, purpose) {
    const prefix = purpose === 'tx' ? CACHED_INFO.tx : CACHED_INFO.rx;
    const info = new Uint8Array(prefix.length + 1 + salt.length);
    info.set(prefix);
    info[prefix.length] = 0; // '\x00' => null bytes
    info.set(salt, prefix.length + 1);
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: psk, info },
      sharedKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }

  // 握手加密（AES-GCM + 随机 padding）
  async encryptHandshake(data) {
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const padLen = 16 + (crypto.getRandomValues(new Uint8Array(1))[0] % 32);
    const plain = new Uint8Array(data.length + padLen);
    plain.set(data); crypto.getRandomValues(plain.subarray(data.length));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, this.handshakeKey, plain);
    const out = new Uint8Array(12 + ciphertext.byteLength);
    out.set(nonce); out.set(new Uint8Array(ciphertext), 12);
    return out;
  }

  async decryptHandshake(data) {
    if (data.length < 28) return null;
    try {
      const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.slice(0, 12) }, this.handshakeKey, data.slice(12));
      const bytes = new Uint8Array(plain);
      return bytes.length >= 32 ? bytes.slice(0, 32) : null;
    } catch { return null; }
  }

  // 数据加密（集成 Buffer 池 + 只加密有效部分）
  async packAndEncrypt(type, streamID, payload = new Uint8Array(0)) {
    const ts = Math.floor(Date.now() / 1000);
    const maxPad = 127;
    const plainSize = PROTOCOL.HEADER_LEN + payload.length + maxPad;
    let plain = BUFFER_POOL.acquire(plainSize);

    // 构建帧头
    const view = new DataView(plain.buffer, plain.byteOffset, plain.length);
    plain[0] = type; plain[1] = streamID;
    view.setUint32(2, ts, false); view.setUint16(6, payload.length, false);
    plain.set(payload, 8);

    // 随机 padding
    const padLen = crypto.getRandomValues(new Uint8Array(1))[0] & 0x7F;
    if (padLen > 0) {
      if (this.poolPtr + padLen > 256) { this.poolPtr = 0; crypto.getRandomValues(this.randomPool); }
      plain.set(this.randomPool.subarray(this.poolPtr, this.poolPtr + padLen), 8 + payload.length);
      this.poolPtr += padLen;
    }

    // Nonce: counter + fixed suffix
    const nonce = new Uint8Array(12);
    new DataView(nonce.buffer).setBigUint64(0, this.nonceCounter++, false);
    nonce.set(this.fixedSuffix, 8);

    try {
      const encryptLen = PROTOCOL.HEADER_LEN + payload.length + padLen;
      const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce }, this.txKey, plain.subarray(0, encryptLen)
      );
      const res = new Uint8Array(12 + ciphertext.byteLength);
      res.set(nonce); res.set(new Uint8Array(ciphertext), 12);
      return res;
    } finally {
      BUFFER_POOL.release(plain); // 异步释放 buffer
    }
  }

  async decryptData(data) {
    if (data.length < 28) return null;
    try {
      const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.slice(0, 12) }, this.rxKey, data.slice(12));
      const bytes = new Uint8Array(plain);
      if (!this.replay.check(bytes, data.slice(0, 12))) return null;
      return bytes;
    } catch { return null; }
  }
}

// ==================== 4. 重放保护 ====================
class ReplayProtection {
  constructor(timeWindowSec) {
    this.recentMask = 0n;
    this.maxSeen = 0n;
    this.init = false;
    this.timeWindowSec = timeWindowSec;
  }

  check(plain, nonce) {
    if (plain.length < 8) return false;

    // 时间窗口验证（核心安全）
    const ts = new DataView(plain.buffer).getUint32(2, false);
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - ts) > this.timeWindowSec) {
      log('REPLAY', 'WARN', `Time window exceeded: ${Math.abs(now - ts)}s`);
      return false;
    }

    const n = new DataView(nonce.buffer).getBigUint64(0, false);
    if (!this.init) { this.init = true; this.maxSeen = n; return true; }

    // 新 nonce：更新最大值
    if (n > this.maxSeen) {
      if (n - this.maxSeen > 1000n) this.recentMask = 0n; // 大跳跃重置
      this.maxSeen = n;
      return true;
    }

    // 旧 nonce：检查 64 位窗口内是否重复
    const diff = this.maxSeen - n;
    if (diff >= 64n) return true; // 超出跟踪范围，时间窗口已兜底
    const bit = 1n << diff;
    if ((this.recentMask & bit) !== 0n) {
      log('REPLAY', 'WARN', `Replay detected (diff=${diff})`);
      return false;
    }
    this.recentMask |= bit;
    return true;
  }
}

// ==================== 5. 会话管理 ====================
class Session {
  constructor(ws, psk, fallbackIPs, dohUrl, maxConnections) {
    this.ws = ws;
    this.crypto = new SSPCrypto(psk);
    this.fallbackIPs = fallbackIPs;
    this.dohUrl = dohUrl;
    this.streams = new Map();
    this.state = 0;
    this.timer = null;
    this.activeConnections = 0;  // 当前活跃连接数
    this.MAX_CONNECTIONS = maxConnections; // 每会话并发流上限（env.MAX_CONNECTIONS 可覆盖，默认 32）
    this.subrequests = 0;        // 会话累计子请求数（connect + DoH fetch）
    this.bytesRelayed = 0;       // 会话累计转发字节（双向）——流量预算依据
    this.dnsInflight = 0;        // 并发 DoH 计数
    this.dnsCache = new Map();   // "qname|qtype" -> { resp, expire }
    this.streamActivity = new Map(); // 记录每个流的最后活动时间
    this.lastSessionActivity = Date.now(); // 会话整体最后活动时间
    this._startIdleChecker();      // 启动空闲检查器
  }

  _startIdleChecker() {
    // 每30秒检查一次僵尸流和会话空闲
    this.idleCheckTimer = setInterval(() => {
      const now = Date.now();
      // 检查流空闲
      for (const [sid, lastActivity] of this.streamActivity) {
        if (now - lastActivity > CONFIG.STREAM_IDLE_TIMEOUT) {
          log('SESSION', 'WARN', `Stream ${sid} idle timeout, closing`);
          this._closeStream(sid);
        }
      }
      // 如果会话整体空闲超过5分钟，关闭整个会话
      if (now - this.lastSessionActivity > CONFIG.SESSION_IDLE_TIMEOUT && this.streams.size === 0) {
        log('SESSION', 'WARN', 'Session idle timeout, closing');
        this._close('Session idle timeout');
      }
    }, 30000);
  }

  _updateActivity(sid) {
    const now = Date.now();
    this.lastSessionActivity = now;
    if (sid !== 0) { // sid=0 是心跳包，不记录到特定流
      this.streamActivity.set(sid, now);
    }
  }

  async start() {
    await this.crypto.init();
    this._setHandshakeTimeout();
    // 帧处理串行化（FIFO）：decryptData 是异步的，若并发处理，同一流内
    // 多个 DATA 帧的解密完成顺序不保证 → 数据乱序写入 socket → 内层 TLS
    // 校验失败、页面挂掉。用 promise 链保证按到达顺序逐帧处理。
    this._queue = Promise.resolve();
    this.ws.addEventListener('message', (e) => {
      this._queue = this._queue.then(() => this._onMessage(e.data)).catch(() => { });
    });
    this.ws.addEventListener('close', () => this._cleanup());
    this.ws.addEventListener('error', () => this._cleanup());
  }

  _setHandshakeTimeout() {
    this.timer = setTimeout(() => { if (this.state !== 2) this._close('Handshake timeout'); }, CONFIG.HANDSHAKE_TIMEOUT);
  }

  async _onMessage(data) {
    // 兼容最新兼容日期（binaryType 默认 blob）与旧日期（arraybuffer）
    data = await toBytes(data);
    if (this.state === 0) {
      this.state = 1;
      try {
        const pubKey = await this.crypto.decryptHandshake(new Uint8Array(data));
        if (!pubKey) throw new Error('Invalid handshake');
        await this.crypto.deriveSharedSecret(pubKey);
        const myPubKey = await this.crypto.exportPublicKey();
        this.ws.send(await this.crypto.encryptHandshake(myPubKey));
        await this.crypto.initSessionKeys();
        this.state = 2; clearTimeout(this.timer);
        log('SESSION', 'INFO', 'Handshake OK');
      } catch (e) {
        log('SESSION', 'ERROR', 'Handshake failed:', e.message);
        this._close('Handshake error');
      }
      return;
    }
    if (this.state !== 2) return;

    const plain = await this.crypto.decryptData(new Uint8Array(data));
    if (!plain) return;
    const frame = this._unpackFrame(plain);
    if (!frame) return;

    try {
      switch (frame.type) {
        case PROTOCOL.TYPE_OPEN: await this._handleOpen(frame); break;
        case PROTOCOL.TYPE_DATA: await this._handleData(frame); break;
        case PROTOCOL.TYPE_CLOSE: this._closeStream(frame.sid); break;
        case PROTOCOL.TYPE_DNS: await this._handleDns(frame); break;
        case PROTOCOL.TYPE_HEART:
          // 心跳包：更新会话活动时间，防止空闲超时
          this._updateActivity(frame.sid);
          this._sendFrame(PROTOCOL.TYPE_HEART, frame.sid);
          break;
      }
    } catch (e) {
      log('ERROR', 'WARN', `Stream ${frame.sid} error:`, e.message);
      this._sendFrame(PROTOCOL.TYPE_CLOSE, frame.sid);
    }
  }

  _unpackFrame(data) {
    if (data.length < PROTOCOL.HEADER_LEN) return null;
    const view = new DataView(data.buffer);
    const len = view.getUint16(6, false);
    if (data.length < PROTOCOL.HEADER_LEN + len) return null;
    return { type: data[0], sid: data[1], payload: data.slice(8, 8 + len) };
  }

  async _handleOpen(frame) {
    // 检查同时连接数
    if (this.activeConnections >= this.MAX_CONNECTIONS) {
      // 连接数已满，拒绝新流
      this._sendFrame(PROTOCOL.TYPE_CLOSE, frame.sid);
      return;
    }
    // 会话预算（子请求/流量任一耗尽）：拒绝新流并调度回收（存量流继续，客户端换槽/重拨）
    if (this._budgetExceeded()) {
      log('SESSION', 'WARN', `Session budget exhausted (subrequests=${this.subrequests}/${CONFIG.SUBREQUEST_BUDGET}, bytes=${(this.bytesRelayed / 1048576).toFixed(1)}MB), refusing new streams`);
      this._scheduleRecycle();
      this._sendFrame(PROTOCOL.TYPE_CLOSE, frame.sid);
      return;
    }
    this.activeConnections++;
    this._updateActivity(frame.sid); // 记录活动时间

    const raw = decoder.decode(frame.payload);
    const trimmed = raw.includes('\x00') ? raw.slice(0, raw.indexOf('\x00')) : raw;
    // 客户端目标 = [主目标, ...客户端 fallback]。客户端携带至少一个 fallback 时
    // 完全覆盖：不使用 worker 端兜底（含 env CF_FALLBACK_IPS / 内置列表）；
    // 未携带时才追加 worker 端 fallbackIPs 作为兜底。
    const clientTargets = trimmed.split('|').map(s => s.trim()).filter(Boolean);
    const targets = clientTargets.length > 1
      ? clientTargets
      : [...clientTargets, ...this.fallbackIPs];

    let socket = null;
    for (const addr of targets) {
      // 每次 connect() 调用都消耗 1 个子请求（无论成败）
      this.subrequests++;
      try {
        const [host, port] = parseAddr(addr);
        const s = connect({ hostname: host, port });
        await Promise.race([s.opened, new Promise((_, r) => setTimeout(() => r(new Error('Timeout')), CONFIG.CONNECT_TIMEOUT))]);
        socket = s; break;
      } catch (e) { }
    }
    if (!socket) {
      this.activeConnections--;  // 连接失败，释放计数
      this.streamActivity.delete(frame.sid);
      throw new Error('Connection failed');
    }

    const reader = socket.readable.getReader();
    const writer = socket.writable.getWriter();
    this.streams.set(frame.sid, { socket, reader, writer });
    this._sendFrame(PROTOCOL.TYPE_DATA, frame.sid);
    this._pumpStream(frame.sid, reader);
  }

  // 会话预算是否耗尽（子请求或流量任一）
  _budgetExceeded() {
    return this.subrequests >= CONFIG.SUBREQUEST_BUDGET
      || this.bytesRelayed >= CONFIG.BYTES_BUDGET;
  }

  // 累计转发字节（双向），达到流量预算时调度回收
  _addBytes(n) {
    this.bytesRelayed += n;
    if (this.bytesRelayed >= CONFIG.BYTES_BUDGET) {
      log('SESSION', 'WARN', `Byte budget reached (${(this.bytesRelayed / 1048576).toFixed(1)}MB), refusing new streams, draining`);
      this._scheduleRecycle();
    }
  }

  async _handleData(frame) {
    const stream = this.streams.get(frame.sid);
    if (stream?.writer) {
      this._updateActivity(frame.sid); // 更新活动时间
      this._addBytes(frame.payload.length); // 客户端 → 目标方向流量
      await stream.writer.write(frame.payload).catch(() => { });
    }
  }

  // DNS 查询帧：payload = reqId(2B BE) + DNS wire query。
  // 响应帧 payload = reqId(2B BE) + wire response，事务 ID 改写为查询自身的 ID，
  // 因此客户端缓存命中/竞速路径无需再做改写。sid 固定 0（与心跳一致，不占流 ID）。
  async _handleDns(frame) {
    if (frame.payload.length < 14) return; // reqId(2) + 最短合法查询(12B 头)
    const reqId = (frame.payload[0] << 8) | frame.payload[1];
    const query = frame.payload.slice(2);
    this._updateActivity(frame.sid); // sid=0 → 仅记会话活动，防纯 DNS 会话被空闲回收

    try {
      const resp = await this._resolveDns(query);
      if (resp.length >= 2) { resp[0] = query[0]; resp[1] = query[1]; }
      // 响应 payload = reqId(2B) + DNS wire response（客户端按前 2 字节关联请求）
      const out = new Uint8Array(2 + resp.length);
      out[0] = frame.payload[0]; out[1] = frame.payload[1];
      out.set(resp, 2);
      this._sendFrame(PROTOCOL.TYPE_DNS, frame.sid, out);
    } catch (e) {
      log('ERROR', 'WARN', `DNS query failed:`, e.message);
      const fail = dnsServfail(query);
      const out = new Uint8Array(2 + fail.length);
      out[0] = frame.payload[0]; out[1] = frame.payload[1];
      out.set(fail, 2);
      this._sendFrame(PROTOCOL.TYPE_DNS, frame.sid, out);
    }
  }

  async _resolveDns(query) {
    // 并发上限：超出直接 SERVFAIL，防止恶意客户端打爆 Worker 的 fetch 配额
    if (this.dnsInflight >= CONFIG.DNS_MAX_INFLIGHT) {
      throw new Error('too many inflight dns queries');
    }
    const key = dnsCacheKey(query);
    if (key) {
      const hit = this.dnsCache.get(key);
      if (hit && hit.expire > Date.now()) return hit.resp.slice();
      this.dnsCache.delete(key);
    }

    this.dnsInflight++;
    // DoH fetch 同样消耗子请求预算
    this.subrequests++;
    let resp;
    try {
      const r = await fetch(this.dohUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message' },
        body: query,
      });
      if (!r.ok) throw new Error(`DoH http ${r.status}`);
      resp = new Uint8Array(await r.arrayBuffer());
      if (resp.length < 12) throw new Error('DoH response too short');
    } finally {
      this.dnsInflight--;
    }

    // 仅缓存成功响应（RCODE=0）；NXDOMAIN/SERVFAIL 不缓存，交由客户端决定重试节奏
    if (key && (resp[3] & 0x0F) === 0) {
      if (this.dnsCache.size >= CONFIG.DNS_CACHE_MAX) {
        // 简单清理：先淘汰过期项，仍满则清空重建（缓存非关键路径，宁可少存）
        const now = Date.now();
        for (const [k, v] of this.dnsCache) {
          if (v.expire <= now) this.dnsCache.delete(k);
        }
        if (this.dnsCache.size >= CONFIG.DNS_CACHE_MAX) this.dnsCache.clear();
      }
      this.dnsCache.set(key, { resp: resp.slice(), expire: Date.now() + CONFIG.DNS_TTL_SEC * 1000 });
    }
    return resp;
  }

  async _pumpStream(sid, reader) {
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        this._updateActivity(sid); // 更新活动时间（收到数据）
        this._addBytes(value.length); // 目标 → 客户端方向流量
        if (value.length <= CONFIG.CHUNK_SIZE) {
          this._sendFrame(PROTOCOL.TYPE_DATA, sid, value);
        } else {
          for (let i = 0; i < value.length; i += CONFIG.CHUNK_SIZE) {
            const end = Math.min(i + CONFIG.CHUNK_SIZE, value.length);
            // subarray 是零拷贝视图，开销很小，主要是加密开销
            await this._sendFrame(PROTOCOL.TYPE_DATA, sid, value.subarray(i, end));
          }
        }
      }
    } catch (e) { log('ERROR', 'WARN', `Stream ${sid} pump error`); }
    finally { this._closeStream(sid); }
  }

  // 会话预算耗尽后的回收：拒绝新流，等存量流自然排空（下载不中断）再优雅
  // 关闭，客户端自动重拨获得全新预算。无需强制兜底：空闲流会被 60s 流空闲
  // 检查回收，长下载跑完后 streams 清空即触发；客户端还会在连续被拒后自动
  // 重拨该槽（旧客户端兜底），毒化窗口不会永久化。
  _scheduleRecycle() {
    if (this._recycleTimer) return;
    log('SESSION', 'WARN', `Session recycling scheduled (subrequests=${this.subrequests}/${CONFIG.SUBREQUEST_BUDGET}, bytes=${(this.bytesRelayed / 1048576).toFixed(1)}MB)`);
    const drain = setInterval(() => {
      if (this.state !== 2 || this.streams.size === 0) {
        clearInterval(drain);
        this._recycleTimer = null;
        log('SESSION', 'WARN', 'Recycling session for fresh budget');
        this._close('Session budget exhausted, recycling');
      }
    }, 5000);
    this._recycleTimer = drain;
  }

  _closeStream(sid) {
    const stream = this.streams.get(sid);
    if (stream) {
      this.activeConnections = Math.max(0, this.activeConnections - 1); // 释放连接数
      this.streamActivity.delete(sid); // 清除活动时间记录
      stream.writer?.close().catch(() => { });
      stream.reader?.cancel().catch(() => { });
      stream.socket.close();
      this.streams.delete(sid);
      this._sendFrame(PROTOCOL.TYPE_CLOSE, sid);
    }
  }

  _sendFrame(type, sid, payload = new Uint8Array(0)) {
    if (this.ws.readyState === 1) {
      this.crypto.packAndEncrypt(type, sid, payload).then(buf => this.ws.send(buf)).catch(() => { });
    }
  }

  _close(reason = 'Closed') {
    if (this.state === -1) return;
    this.state = -1;
    clearTimeout(this.timer);
    if (this.idleCheckTimer) {
      clearInterval(this.idleCheckTimer);
      this.idleCheckTimer = null;
    }
    this._cleanup();
    try { this.ws.close(1000, reason); } catch { }
  }

  _cleanup() {
    if (this.idleCheckTimer) {
      clearInterval(this.idleCheckTimer);
      this.idleCheckTimer = null;
    }
    if (this._recycleTimer) {
      clearInterval(this._recycleTimer);
      this._recycleTimer = null;
    }
    for (const sid of this.streams.keys()) this._closeStream(sid);
    this.streamActivity.clear();
  }
}

export default {
  async fetch(req, env, ctx) {
    if (req.headers.get('Upgrade') !== 'websocket') {
      return new Response(null, { status: 404 });
    }

    const psk = env.PSK || 'aB3#9dkf8!2jQpL4s8xZyW7v1UeR0mN2';
    const fallbackIPs = env.CF_FALLBACK_IPS?.split(',').filter(Boolean) || [];
    const dohUrl = env.DOHDNS_URL || CONFIG.DOH_URL;
    // 每会话并发流上限与日志级别均可用环境变量覆盖
    CONFIG.LOG_LEVEL = env.LOG_LEVEL || CONFIG.LOG_LEVEL;
    CONFIG.SUBREQUEST_BUDGET = parseInt(env.SUBREQUEST_BUDGET) || CONFIG.SUBREQUEST_BUDGET;
    // 流量预算以 MB 为单位配置
    CONFIG.BYTES_BUDGET = (parseInt(env.BYTES_BUDGET) || 128) * 1024 * 1024;
    const maxConnections = parseInt(env.MAX_CONNECTIONS) || 32;

    const [client, server] = Object.values(new WebSocketPair());
    // 显式保持二进制帧为 ArrayBuffer：最新兼容日期默认改为 Blob
    server.binaryType = 'arraybuffer';
    server.accept();
    const session = new Session(server, psk, fallbackIPs, dohUrl, maxConnections);
    ctx.waitUntil(session.start().catch(() => { try { server.close(); } catch { } }));

    return new Response(null, { status: 101, webSocket: client });
  }
};