import { DurableObject } from "cloudflare:workers";
import { connect } from 'cloudflare:sockets';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// ==================== 1. 配置与常量 ====================
const CONFIG = {
	LOG_LEVEL: 'DEBUG',
	LOG_MODULES: ['SESSION', 'REPLAY', 'ERROR'],
	HANDSHAKE_TIMEOUT: 10000,
	CONNECT_TIMEOUT: 5000,
	CHUNK_SIZE: 16 * 1024,
	REPLAY_WINDOW_SEC: 300,
	STREAM_IDLE_TIMEOUT: 60000,

	// 会话空闲超时 30 分钟
	// 客户端每 30s 发心跳，lastSessionActivity 会一直刷新，
	// 正常情况下此超时不会触发
	SESSION_IDLE_TIMEOUT: 1800000, // 30 分钟

	// 空闲检查间隔60s
	IDLE_CHECK_INTERVAL: 60000,
};

// 缓存常用编码结果
const CACHED_INFO = {
	handshake: encoder.encode('sspv1.4-handshake'),
	salt: encoder.encode('sspv1.4-salt'),
	tx: encoder.encode('sspv1.4-tx'),
	rx: encoder.encode('sspv1.4-rx'),
};

// 全局 Buffer 池（减少 GC）
const BUFFER_POOL = (() => {
	const pool = [];
	const MAX_POOL_SIZE = 8;
	const POOL_MAX_SIZE = 65536;
	return {
		acquire(size) {
			const idx = pool.findIndex(buf => buf.length >= size && buf.length <= size * 2);
			if (idx >= 0) { const buf = pool.splice(idx, 1)[0]; buf.fill(0); return buf; }
			const allocSize = size < 1024 ? 1024 : Math.pow(2, Math.ceil(Math.log2(size)));
			return new Uint8Array(Math.min(allocSize, POOL_MAX_SIZE));
		},
		release(buf) {
			if (!buf || pool.length >= MAX_POOL_SIZE) return;
			if (buf.length >= 256 && buf.length <= 16384) { buf.fill(0); pool.push(buf); }
		}
	};
})();

const PROTOCOL = {
	TYPE_DATA: 0x01,
	TYPE_OPEN: 0x02,
	TYPE_CLOSE: 0x03,
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
		const keyPair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
		this._privateKey = keyPair.privateKey;
		this._publicKey = keyPair.publicKey;
		const pskKey = await crypto.subtle.importKey('raw', this.psk, 'HKDF', false, ['deriveKey']);
		this.handshakeKey = await crypto.subtle.deriveKey(
			{ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(16), info: CACHED_INFO.handshake },
			pskKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
		);
	}

	async exportPublicKey() {
		return new Uint8Array(await crypto.subtle.exportKey('raw', this._publicKey));
	}

	async deriveSharedSecret(peerPublicKey) {
		const importedKey = await crypto.subtle.importKey('raw', peerPublicKey, { name: 'X25519' }, false, []);
		const bits = await crypto.subtle.deriveBits({ name: 'X25519', public: importedKey }, this._privateKey, 256);
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
		this.psk = null; this.sharedSecret = null;
	}

	async _deriveKey(sharedKey, psk, salt, purpose) {
		const prefix = purpose === 'tx' ? CACHED_INFO.tx : CACHED_INFO.rx;
		const info = new Uint8Array(prefix.length + 1 + salt.length);
		info.set(prefix); info[prefix.length] = 0; info.set(salt, prefix.length + 1);
		return crypto.subtle.deriveKey(
			{ name: 'HKDF', hash: 'SHA-256', salt: psk, info },
			sharedKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
		);
	}

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

	async packAndEncrypt(type, streamID, payload = new Uint8Array(0)) {
		const ts = Math.floor(Date.now() / 1000);
		const maxPad = 127;
		const plainSize = PROTOCOL.HEADER_LEN + payload.length + maxPad;
		let plain = BUFFER_POOL.acquire(plainSize);
		const view = new DataView(plain.buffer, plain.byteOffset, plain.length);
		plain[0] = type; plain[1] = streamID;
		view.setUint32(2, ts, false); view.setUint16(6, payload.length, false);
		plain.set(payload, 8);
		const padLen = crypto.getRandomValues(new Uint8Array(1))[0] & 0x7F;
		if (padLen > 0) {
			if (this.poolPtr + padLen > 256) { this.poolPtr = 0; crypto.getRandomValues(this.randomPool); }
			plain.set(this.randomPool.subarray(this.poolPtr, this.poolPtr + padLen), 8 + payload.length);
			this.poolPtr += padLen;
		}
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
			BUFFER_POOL.release(plain);
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
		this.recentMask = 0n; this.maxSeen = 0n; this.init = false;
		this.timeWindowSec = timeWindowSec;
	}
	check(plain, nonce) {
		if (plain.length < 8) return false;
		const ts = new DataView(plain.buffer).getUint32(2, false);
		const now = Math.floor(Date.now() / 1000);
		if (Math.abs(now - ts) > this.timeWindowSec) {
			log('REPLAY', 'WARN', `Time window exceeded: ${Math.abs(now - ts)}s`); return false;
		}
		const n = new DataView(nonce.buffer).getBigUint64(0, false);
		if (!this.init) { this.init = true; this.maxSeen = n; return true; }
		if (n > this.maxSeen) {
			if (n - this.maxSeen > 1000n) this.recentMask = 0n;
			this.maxSeen = n; return true;
		}
		const diff = this.maxSeen - n;
		if (diff >= 64n) return true;
		const bit = 1n << diff;
		if ((this.recentMask & bit) !== 0n) { log('REPLAY', 'WARN', `Replay detected (diff=${diff})`); return false; }
		this.recentMask |= bit;
		return true;
	}
}

// ==================== 5. 会话管理 ====================
class Session {
	constructor(ws, psk, fallbackIPs) {
		this.ws = ws;
		this.crypto = new SSPCrypto(psk);
		this.fallbackIPs = fallbackIPs;
		this.streams = new Map();
		this.state = 0;
		this.timer = null;
		this.activeConnections = 0;
		this.MAX_CONNECTIONS = 20;
		this.streamActivity = new Map();
		this.lastSessionActivity = Date.now();
		this._startIdleChecker();
	}

	_startIdleChecker() {
		this.idleCheckTimer = setInterval(() => {
			const now = Date.now();
			for (const [sid, lastActivity] of this.streamActivity) {
				if (now - lastActivity > CONFIG.STREAM_IDLE_TIMEOUT) {
					log('SESSION', 'WARN', `Stream ${sid} idle timeout, closing`);
					this._closeStream(sid);
				}
			}
			if (now - this.lastSessionActivity > CONFIG.SESSION_IDLE_TIMEOUT && this.streams.size === 0) {
				log('SESSION', 'WARN', 'Session idle timeout, closing');
				this._close('Session idle timeout');
			}
		}, CONFIG.IDLE_CHECK_INTERVAL); // 60s
	}

	_updateActivity(sid) {
		const now = Date.now();
		this.lastSessionActivity = now;
		if (sid !== 0) this.streamActivity.set(sid, now);
	}

	async start() {
		await this.crypto.init();
		this._setHandshakeTimeout();
		this.ws.addEventListener('message', (e) => this._onMessage(e.data));
		this.ws.addEventListener('close', () => this._cleanup());
		this.ws.addEventListener('error', () => this._cleanup());
	}

	_setHandshakeTimeout() {
		this.timer = setTimeout(() => { if (this.state !== 2) this._close('Handshake timeout'); }, CONFIG.HANDSHAKE_TIMEOUT);
	}

	async _onMessage(data) {
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
				case PROTOCOL.TYPE_HEART:
					// 心跳：刷新 lastSessionActivity（sid=0 不记录到流活动表）
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
		if (this.activeConnections >= this.MAX_CONNECTIONS) {
			this._sendFrame(PROTOCOL.TYPE_CLOSE, frame.sid);
			return;
		}
		this.activeConnections++;
		this._updateActivity(frame.sid);

		const raw = decoder.decode(frame.payload);
		const trimmed = raw.includes('\x00') ? raw.slice(0, raw.indexOf('\x00')) : raw;
		const targets = [...trimmed.split('|').map(s => s.trim()).filter(Boolean), ...this.fallbackIPs];

		let socket = null;
		for (const addr of targets) {
			try {
				const [host, port] = parseAddr(addr);
				const s = connect({ hostname: host, port });
				await Promise.race([s.opened, new Promise((_, r) => setTimeout(() => r(new Error('Timeout')), CONFIG.CONNECT_TIMEOUT))]);
				socket = s; break;
			} catch (e) { }
		}
		if (!socket) {
			this.activeConnections--;
			this.streamActivity.delete(frame.sid);
			throw new Error('Connection failed');
		}

		const reader = socket.readable.getReader();
		const writer = socket.writable.getWriter();
		this.streams.set(frame.sid, { socket, reader, writer });
		this._sendFrame(PROTOCOL.TYPE_DATA, frame.sid); // ACK: 空 DATA 帧
		this._pumpStream(frame.sid, reader);
	}

	async _handleData(frame) {
		const stream = this.streams.get(frame.sid);
		if (stream?.writer) {
			this._updateActivity(frame.sid);
			await stream.writer.write(frame.payload).catch(() => { });
		}
	}

	async _pumpStream(sid, reader) {
		try {
			while (true) {
				const { done, value } = await reader.read();
				if (done) break;
				this._updateActivity(sid);
				if (value.length <= CONFIG.CHUNK_SIZE) {
					this._sendFrame(PROTOCOL.TYPE_DATA, sid, value);
				} else {
					for (let i = 0; i < value.length; i += CONFIG.CHUNK_SIZE) {
						await this._sendFrame(PROTOCOL.TYPE_DATA, sid, value.subarray(i, Math.min(i + CONFIG.CHUNK_SIZE, value.length)));
					}
				}
			}
		} catch (e) { log('ERROR', 'WARN', `Stream ${sid} pump error`); }
		finally { this._closeStream(sid); }
	}

	_closeStream(sid) {
		const stream = this.streams.get(sid);
		if (stream) {
			this.activeConnections = Math.max(0, this.activeConnections - 1);
			this.streamActivity.delete(sid);
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
		if (this.idleCheckTimer) { clearInterval(this.idleCheckTimer); this.idleCheckTimer = null; }
		this._cleanup();
		try { this.ws.close(1000, reason); } catch { }
	}

	_cleanup() {
		if (this.idleCheckTimer) { clearInterval(this.idleCheckTimer); this.idleCheckTimer = null; }
		for (const sid of this.streams.keys()) this._closeStream(sid);
		this.streamActivity.clear();
	}
}

// ==================== 6. Durable Object ====================
export class MyDurableObject extends DurableObject {
	constructor(ctx, env) {
		super(ctx, env);
		this.ctx = ctx;
		this.psk = env.PSK || 'aB3#9dkf8!2jQpL4s8xZyW7v1UeR0mN2';
		this.fallbackIPs = env.CF_FALLBACK_IPS?.split(',').filter(Boolean) || [];
	}

	async fetch(request) {
		if (request.headers.get('Upgrade') !== 'websocket') return new Response(null, { status: 404 });
		const [client, server] = Object.values(new WebSocketPair());
		server.accept();
		const session = new Session(server, this.psk, this.fallbackIPs);
		this.ctx.waitUntil(session.start().catch(() => { try { server.close(); } catch { } }));
		return new Response(null, { status: 101, webSocket: client });
	}
}

export default {
	async fetch(request, env, ctx) {
		const pathname = new URL(request.url).pathname;
		if (request.headers.get('Upgrade') !== 'websocket') {
			return pathname === '/'
				? new Response('hello world!', { status: 200 })
				: new Response('404 Not Found!', { status: 404 });
		}
		const id = env.MY_DURABLE_OBJECT.idFromName(pathname);
		const stub = env.MY_DURABLE_OBJECT.get(id);
		return await stub.fetch(request);
	}
};