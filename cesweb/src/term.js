// src/term.js — web terminal session manager (pure signature relay).
//
// The browser holds the key and signs the CesPlex bind + ATTACH itself (native
// WebCrypto Ed25519 — see the terminal page). cesweb NEVER sees the private key:
// it only relays the browser's signatures into `cesh dial <pid> --extsign`.
//
// The target (server host:port + instance pid) is NOT in the URL — it rides the
// hello frame, because the session runs on the user's own key and so isn't
// namespaced to a server. The host is allow-checked here on hello.
//
// WS protocol (browser ↔ cesweb). Text frames = JSON control; binary frames =
// raw terminal bytes.
//   browser → {t:"hello", pubkey, time, bindSig, host, cesPort, pid}
//   cesweb  spawns cesh dial <pid> --extsign --server host:port, writes BIND <time> <bindSig>
//   cesh    → TOKEN <sessionToken>   → cesweb → browser {t:"token", token}
//   browser → {t:"attachSig", sig}                     (browser signed ATTACH)
//   cesweb  writes  ATTACH <sig>;  cesh → READY  → cesweb → browser {t:"ready"}
//   then raw: browser keystrokes (binary) → cesh stdin; program bytes → browser
// cesweb status lines ride text frames as {_cesweb, _end}.
//
// A dial is a persisted process + RUDP channel, so the pool is bounded: global +
// per-IP caps, idle + max-lifetime timeouts, and live-traffic limits (a
// WebSocket escapes nginx's per-request limits, so cesweb meters it here).

import { spawn } from 'node:child_process';

const HEX64 = /^[0-9a-fA-F]{64}$/;
const HEX130 = /^[0-9a-fA-F]{130}$/;   // 65-byte signature (tag + 64)
const HOSTRE = /^[A-Za-z0-9_.\-:]+$/;  // hostname/ip; no spaces or shell metachars
const num = (v, d) => { const n = parseInt(v, 10); return Number.isFinite(n) ? n : d; };

export class TerminalManager {
  constructor(opts = {}) {
    this.cesh = opts.cesh || 'cesh';
    this.resolve = opts.resolve;          // async (target) => {rpcPort, serverKey}
    this.allowHost = opts.allowHost || (() => true);   // (host) => bool
    this.log = opts.log || (() => {});
    this.maxTotal = num(process.env.CESWEB_MAX_TERMINALS, 8);
    this.maxPerIp = num(process.env.CESWEB_MAX_TERMINALS_PER_IP, 2);
    this.idleMs   = num(process.env.CESWEB_TERM_IDLE_MS, 600000);
    this.maxMs    = num(process.env.CESWEB_TERM_MAX_MS, 1800000);
    this.inputBps = num(process.env.CESWEB_TERM_INPUT_BPS, 2048);
    this.maxMsg   = num(process.env.CESWEB_TERM_MAX_MSG, 4096);
    this.maxBytes = num(process.env.CESWEB_TERM_MAX_BYTES, 4 * 1024 * 1024);
    this.outBufCap = num(process.env.CESWEB_TERM_OUT_BUF, 1024 * 1024);
    this.sessions = new Set();
    this.perIp = new Map();
  }

  count() { return this.sessions.size; }

  handle(ws, meta) {
    if (this.sessions.size >= this.maxTotal)
      return this._reject(ws, 'gateway terminal pool is full — try again shortly');
    const ipN = this.perIp.get(meta.ip) || 0;
    if (ipN >= this.maxPerIp)
      return this._reject(ws, 'too many terminals open from your address');

    const s = {
      ws, meta, child: null, down: false,
      phase: 'hello',                   // hello → token → attachsig → ready → raw
      ctrlBuf: Buffer.alloc(0), inQueue: [],
      started: Date.now(), lastActive: Date.now(),
      winStart: Date.now(), winBytes: 0, totalIn: 0, totalOut: 0, timer: null,
    };
    this.sessions.add(s);
    this.perIp.set(meta.ip, ipN + 1);
    this.log(`term slot open (${this.sessions.size}/${this.maxTotal}) from ${meta.ip}`);

    ws.on('message', (data, isBinary) => this._onWsMessage(s, data, isBinary));
    ws.on('close', () => this._teardown(s, 'connection closed'));
    ws.on('error', () => this._teardown(s, 'connection error'));

    s.timer = setInterval(() => {
      const now = Date.now();
      if (now - s.lastActive > this.idleMs) this._teardown(s, 'idle timeout');
      else if (now - s.started > this.maxMs) this._teardown(s, 'session lifetime reached');
    }, 5000);
    if (s.timer.unref) s.timer.unref();
  }

  _onWsMessage(s, data, isBinary) {
    if (s.down) return;
    s.lastActive = Date.now();
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    if (buf.length > this.maxMsg) return this._teardown(s, 'frame too large');

    if (isBinary) return this._onTerminalInput(s, buf);

    let msg;
    try { msg = JSON.parse(buf.toString('utf8')); } catch { return this._teardown(s, 'bad control frame'); }

    if (s.phase === 'hello') {
      if (msg.t !== 'hello') return this._teardown(s, 'expected hello');
      if (!HEX64.test(msg.pubkey || '')) return this._teardown(s, 'bad pubkey');
      if (!HEX130.test(msg.bindSig || '')) return this._teardown(s, 'bad bind signature');
      const time = Number(msg.time);
      if (!Number.isFinite(time) || time <= 0) return this._teardown(s, 'bad time');
      // Target (server + pid) rides the hello frame, not the URL.
      const host = String(msg.host || '').trim();
      if (!host || !HOSTRE.test(host)) return this._teardown(s, 'bad or missing server host');
      if (!this.allowHost(host)) return this._teardown(s, `server ${host} is not allowed by this gateway`);
      const cesPort = Number(msg.cesPort);
      if (!Number.isInteger(cesPort) || cesPort < 1 || cesPort > 65535)
        return this._teardown(s, 'bad server port');
      const pid = String(msg.pid || '');
      if (!/^\d+$/.test(pid)) return this._teardown(s, 'bad instance id (pid)');
      s.pubkey = msg.pubkey.toLowerCase();
      s.time = Math.trunc(time);
      s.bindSig = msg.bindSig.toLowerCase();
      s.host = host;
      s.cesPort = cesPort;
      s.pid = pid;
      this._spawn(s);
      return;
    }
    if (s.phase === 'attachsig') {
      if (msg.t !== 'attachSig') return this._teardown(s, 'expected attachSig');
      if (!HEX130.test(msg.sig || '')) return this._teardown(s, 'bad attach signature');
      try { s.child.stdin.write(`ATTACH ${msg.sig.toLowerCase()}\n`); } catch {}
      s.phase = 'ready';                // awaiting cesh READY
      return;
    }
    return this._teardown(s, 'unexpected control frame in phase ' + s.phase);
  }

  _onTerminalInput(s, buf) {
    if (s.phase !== 'raw') { s.inQueue.push(buf); return; }   // before READY: hold
    const now = Date.now();
    if (now - s.winStart >= 1000) { s.winStart = now; s.winBytes = 0; }
    s.winBytes += buf.length;
    if (s.winBytes > this.inputBps) return this._teardown(s, 'input rate exceeded');
    s.totalIn += buf.length;
    if (s.totalIn > this.maxBytes) return this._teardown(s, 'input limit reached');
    try { s.child.stdin.write(buf); } catch {}
  }

  async _spawn(s) {
    let info;
    try { info = await this.resolve(`${s.host}:${s.cesPort}`); }
    catch { return this._teardown(s, `can't reach ${s.host}:${s.cesPort}`); }
    if (s.down) return;
    if (!info || !info.rpcPort) return this._teardown(s, 'server has no compute service');

    const args = ['dial', s.pid, '--extsign', '--pubkey', s.pubkey,
                  '--server', `${s.host}:${s.cesPort}`, '--rpc-port', String(info.rpcPort)];
    if (info.serverKey) args.push('--server-key', info.serverKey);
    this.log(`term ${s.host}:${s.cesPort}/${s.pid} dialing`);

    let child;
    try { child = spawn(this.cesh, args); }   // no key anywhere near this process
    catch { return this._teardown(s, 'failed to start cesh'); }
    s.child = child;
    s.phase = 'token';
    child.stdout.on('data', (d) => this._onCeshStdout(s, d));
    child.stderr.on('data', (d) => this._status(s, d.toString().trim()));
    child.on('close', (code) => this._teardown(s, `session ended (cesh exit ${code})`));
    child.on('error', () => this._teardown(s, 'cesh error'));
    try { child.stdin.write(`BIND ${s.time} ${s.bindSig}\n`); } catch {}
  }

  _onCeshStdout(s, d) {
    if (s.down) return;
    if (s.phase === 'raw') return this._fromProgram(s, d);
    s.ctrlBuf = Buffer.concat([s.ctrlBuf, d]);
    let nl;
    while (s.phase !== 'raw' && (nl = s.ctrlBuf.indexOf(0x0a)) >= 0) {
      const line = s.ctrlBuf.slice(0, nl).toString('utf8').trim();
      s.ctrlBuf = s.ctrlBuf.slice(nl + 1);
      this._onCeshControl(s, line);
    }
    if (s.phase === 'raw' && s.ctrlBuf.length) {
      const rest = s.ctrlBuf; s.ctrlBuf = Buffer.alloc(0);
      this._fromProgram(s, rest);
    }
  }

  _onCeshControl(s, line) {
    if (!line) return;
    if (line.startsWith('ERR')) return this._teardown(s, 'cesh: ' + line.slice(3).trim());

    if (s.phase === 'token' && line.startsWith('TOKEN')) {
      const tok = line.split(/\s+/)[1];
      if (!tok) return this._teardown(s, 'bad TOKEN from cesh');
      s.phase = 'attachsig';
      try { s.ws.send(JSON.stringify({ t: 'token', token: tok })); } catch {}
      return;
    }
    if (s.phase === 'ready' && line.startsWith('READY')) {
      s.phase = 'raw';
      try { s.ws.send(JSON.stringify({ t: 'ready' })); } catch {}
      for (const b of s.inQueue) { try { s.child.stdin.write(b); } catch {} }
      s.inQueue = [];
      return;
    }
    this._teardown(s, 'unexpected cesh line in phase ' + s.phase + ': ' + line.slice(0, 40));
  }

  _fromProgram(s, d) {
    if (s.down) return;
    s.lastActive = Date.now();
    s.totalOut += d.length;
    if (s.totalOut > this.maxBytes) return this._teardown(s, 'output limit reached');
    if (s.ws.bufferedAmount > this.outBufCap) return this._teardown(s, 'client too slow');
    try { s.ws.send(d, { binary: true }); } catch {}
  }

  _status(s, text) { if (text) { try { s.ws.send(JSON.stringify({ _cesweb: text })); } catch {} } }

  _reject(ws, text) {
    try { ws.send(JSON.stringify({ _cesweb: text, _end: true })); } catch {}
    try { ws.close(1013, text.slice(0, 120)); } catch {}
  }

  _teardown(s, reason) {
    if (s.down) return;
    s.down = true;
    if (s.timer) clearInterval(s.timer);
    if (s.child) { try { s.child.kill('SIGTERM'); } catch {} s.child = null; }
    try { s.ws.send(JSON.stringify({ _cesweb: reason, _end: true })); } catch {}
    try { s.ws.close(); } catch {}
    this.sessions.delete(s);
    const n = (this.perIp.get(s.meta.ip) || 1) - 1;
    if (n <= 0) this.perIp.delete(s.meta.ip); else this.perIp.set(s.meta.ip, n);
    this.log(`term ${s.host || '?'}/${s.pid || '?'}: ${reason}`);
  }

  stop() { for (const s of [...this.sessions]) this._teardown(s, 'gateway shutting down'); }
}
