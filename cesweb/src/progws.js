// src/progws.js - bridge a browser WebSocket to a compute instance over
// /ces/lua/1 on the GATEWAY's own wallet. The subsidized, transparent scope (no
// user key), the WebSocket sibling of the /i/ HTTP proxy.
//
// cesweb is the browser's TLS/WS peer, so it necessarily terminates the WebSocket
// wire protocol (Node `ws`: handshake, masking, framing). The Lua program behind
// the proxy never sees RFC 6455 - it gets discrete MESSAGES, framed over the
// CesPlex byte stream as [u32 BE len][payload]:
//   frame 0  (cesweb -> program): the WS handshake request (request-line +
//            selected headers), so the program can route by path / authenticate.
//   frame 1..N: message payloads, each direction.
// A program payload is delivered to the browser as a text WS message (binary
// frames are not supported). Message boundaries are the frame; the CesPlex
// stream itself is boundary-less.
//
// A socket is long-lived, so the ChannelMeter bills the gateway for the whole
// session. The pool is therefore bounded exactly like the /dev terminal: global
// + per-IP caps, idle + lifetime timeouts, per-connection rate/size limits.

import { spawn } from 'node:child_process';

const num = (v, d) => { const n = parseInt(v, 10); return Number.isFinite(n) ? n : d; };

// [u32 BE len][payload]
function frame(payload) {
  const buf = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const hdr = Buffer.allocUnsafe(4);
  hdr.writeUInt32BE(buf.length, 0);
  return Buffer.concat([hdr, buf]);
}

export class ProgWsManager {
  constructor(opts = {}) {
    this.cesh = opts.cesh || 'cesh';
    this.resolve = opts.resolve;                       // async (target) => {rpcPort, serverKey}
    this.allowHost = opts.allowHost || (() => true);
    this.walletOpts = opts.walletOpts || {};
    this.log = opts.log || (() => {});
    // Game/app sockets, not user-key terminals: many legit players share one IP
    // (carrier NAT, a LAN, localhost testing), so the per-IP cap is generous.
    this.maxTotal = num(process.env.CESWEB_MAX_WS, 64);
    this.maxPerIp = num(process.env.CESWEB_MAX_WS_PER_IP, 16);
    this.idleMs   = num(process.env.CESWEB_WS_IDLE_MS, num(process.env.CESWEB_TERM_IDLE_MS, 600000));
    this.maxMs    = num(process.env.CESWEB_WS_MAX_MS, num(process.env.CESWEB_TERM_MAX_MS, 1800000));
    this.inputBps = num(process.env.CESWEB_WS_INPUT_BPS, 65536);      // per-second input ceiling
    this.maxMsg   = num(process.env.CESWEB_WS_MAX_MSG, 65536);        // single message cap, both ways
    this.maxBytes = num(process.env.CESWEB_WS_MAX_BYTES, 64 * 1024 * 1024);
    this.outBufCap = num(process.env.CESWEB_WS_OUT_BUF, 1024 * 1024);
    this.sessions = new Set();
    this.perIp = new Map();
  }

  count() { return this.sessions.size; }

  // ws is already accepted (101). target = { host, cesPort, pid, handshake }
  // (handshake = raw request text for frame 0). meta.ip drives the per-IP cap.
  handle(ws, target, meta) {
    if (this.sessions.size >= this.maxTotal) return this._reject(ws, 'gateway socket pool is full');
    const ipN = this.perIp.get(meta.ip) || 0;
    if (ipN >= this.maxPerIp) return this._reject(ws, 'too many sockets from your address');
    if (!this.allowHost(target.host)) return this._reject(ws, `server ${target.host} is not allowed`);

    const s = {
      ws, meta, target, child: null, down: false, rxBuf: Buffer.alloc(0), pending: [],
      started: Date.now(), lastActive: Date.now(),
      winStart: Date.now(), winBytes: 0, totalIn: 0, totalOut: 0, timer: null,
    };
    this.sessions.add(s);
    this.perIp.set(meta.ip, ipN + 1);
    this.log(`ws slot open (${this.sessions.size}/${this.maxTotal}) ${target.host}/${target.pid}`);

    ws.on('message', (data) => this._onWsMessage(s, data));
    ws.on('close', () => this._teardown(s, 'client closed'));
    ws.on('error', () => this._teardown(s, 'client error'));
    s.timer = setInterval(() => {
      const now = Date.now();
      if (now - s.lastActive > this.idleMs) this._teardown(s, 'idle timeout');
      else if (now - s.started > this.maxMs) this._teardown(s, 'session lifetime reached');
    }, 5000);
    if (s.timer.unref) s.timer.unref();

    this._spawn(s);
  }

  async _spawn(s) {
    let info;
    try { info = await this.resolve(`${s.target.host}:${s.target.cesPort}`); }
    catch { return this._teardown(s, `can't reach ${s.target.host}:${s.target.cesPort}`); }
    if (s.down) return;
    if (!info || !info.rpcPort) return this._teardown(s, 'server has no compute service');

    const env = { ...process.env };
    if (this.walletOpts.walletInline) env.CESH_WALLET = this.walletOpts.walletInline;
    const args = [];
    if (this.walletOpts.walletFile) args.push('--wallet', this.walletOpts.walletFile);
    args.push('dial', String(s.target.pid), '--server', `${s.target.host}:${s.target.cesPort}`,
              '--rpc-port', String(info.rpcPort));
    if (info.serverKey) args.push('--server-key', info.serverKey);

    let child;
    try { child = spawn(this.cesh, args, { env }); }
    catch { return this._teardown(s, 'failed to start cesh'); }
    s.child = child;
    child.stdin.on('error', () => {});  // contain async EPIPE if the child exits mid-write
    child.stdout.on('data', (d) => this._fromProgram(s, d));
    child.stderr.on('data', () => {});
    child.on('close', () => this._teardown(s, 'session ended'));
    child.on('error', () => this._teardown(s, 'cesh error'));
    try { child.stdin.write(frame(s.target.handshake || '')); } catch {}   // frame 0: handshake
    for (const f of s.pending) { try { child.stdin.write(f); } catch {} }  // messages that beat the dial
    s.pending = [];
  }

  _onWsMessage(s, data) {
    if (s.down) return;
    s.lastActive = Date.now();
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    if (buf.length > this.maxMsg) return this._teardown(s, 'message too large');
    const now = Date.now();
    if (now - s.winStart >= 1000) { s.winStart = now; s.winBytes = 0; }
    s.winBytes += buf.length;
    if (s.winBytes > this.inputBps) return this._teardown(s, 'input rate exceeded');
    s.totalIn += buf.length;
    if (s.totalIn > this.maxBytes) return this._teardown(s, 'input limit reached');
    const f = frame(buf);
    if (s.child) { try { s.child.stdin.write(f); } catch {} }
    else s.pending.push(f);          // arrived before the dial is up; flushed after frame 0
  }

  // De-frame [u32 len][payload] from the program; each payload -> one text WS msg.
  _fromProgram(s, d) {
    if (s.down) return;
    s.lastActive = Date.now();
    s.totalOut += d.length;
    if (s.totalOut > this.maxBytes) return this._teardown(s, 'output limit reached');
    s.rxBuf = s.rxBuf.length ? Buffer.concat([s.rxBuf, d]) : d;
    for (;;) {
      if (s.rxBuf.length < 4) return;
      const len = s.rxBuf.readUInt32BE(0);
      if (len > this.maxMsg) return this._teardown(s, 'program message too large');
      if (s.rxBuf.length < 4 + len) return;
      const payload = s.rxBuf.subarray(4, 4 + len);
      s.rxBuf = Buffer.from(s.rxBuf.subarray(4 + len));   // detach: don't pin the big chunk
      if (s.ws.bufferedAmount > this.outBufCap) return this._teardown(s, 'client too slow');
      try { s.ws.send(payload.toString('utf8')); } catch {}
    }
  }

  _reject(ws, text) { try { ws.close(1013, text.slice(0, 120)); } catch {} }

  _teardown(s, reason) {
    if (s.down) return;
    s.down = true;
    if (s.timer) clearInterval(s.timer);
    if (s.child) { try { s.child.kill('SIGTERM'); } catch {} s.child = null; }
    try { s.ws.close(); } catch {}
    this.sessions.delete(s);
    const n = (this.perIp.get(s.meta.ip) || 1) - 1;
    if (n <= 0) this.perIp.delete(s.meta.ip); else this.perIp.set(s.meta.ip, n);
    this.log(`ws ${s.target.host || '?'}/${s.target.pid || '?'}: ${reason}`);
  }

  stop() { for (const s of [...this.sessions]) this._teardown(s, 'gateway shutting down'); }
}
