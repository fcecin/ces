// engine.js — filesystem-backed content cache. One worker, no RAM index.
//
// The cache IS the filesystem: content lives at cache/<host>/<cesPath>, and the
// file's own size + mtime ARE its metadata (mtime <- the CES file's modifiedUs).
// There is NO in-RAM index of cached files — a million files cost zero RAM here;
// the OS owns them. The only RAM the cache uses is a small bounded "freshness"
// map that throttles revalidation, plus the in-flight jobs.
//
// ONE fetch worker (maxInflight=1). Cache hits are served straight off disk and
// are NOT worker-gated, so hot content is naturally parallel (the web server can
// even serve it without us). Misses queue and wait — that's the resolving page.
//
// Eviction is insertion-driven and disk-bounded: before caching, the worker
// checks free space (statfs, O(1)); only if the disk is low does it walk and
// delete files idle longer than maxAge, stopping the instant enough is freed
// (usually without finishing the walk). If it reaches the end still short, it
// deletes the oldest it saw. RAM stays flat; CPU is spent only under disk
// pressure; latency under load is unbounded by design (people wait).
//
// A file<->directory type change is the server's signed staleness signal: the
// stale node is removed and replaced. Hosts must be DNS names (IP literals
// rejected) so the cache dir is the name verbatim — no lossy rewrite, no
// collisions.

import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import dns from 'node:dns/promises';
import { ping, stat as ceshStat, spawnFileGet } from './cesh.js';

export const State = {
  RESOLVING: 'resolving', STATTING: 'statting', QUEUED: 'queued',
  DOWNLOADING: 'downloading', READY: 'ready', FAILED: 'failed',
};

export class Engine {
  constructor(opts = {}) {
    this.cesh = opts.cesh || 'cesh';
    this.cacheDir = opts.cacheDir || path.join(process.cwd(), 'cache');
    this.walletOpts = opts.walletOpts || {};
    this.defaultCesPort = opts.defaultCesPort ?? 53830;
    this.maxFileBytes = opts.maxFileBytes ?? (1024 * 1024 * 1024);   // refuse one giant file
    this.minFreeBytes = opts.minFreeBytes ?? (2 * 1024 * 1024 * 1024); // keep this much disk free
    this.maxAgeMs = opts.maxAgeMs ?? 86400000;                       // idle longer than this => freely evictable
    this.maxScan = opts.maxScan ?? 1000000;                          // cap the eviction walk's RAM (files listed)
    this.minScan = opts.minScan ?? 1000;                             // never early-stop before this many seen (small caches => full eval)
    this.freeBytesFn = opts.freeBytesFn || null;                     // test hook; default = statfs
    this.maxInflight = opts.maxInflight ?? 1;                        // ONE worker
    this.validateTtlMs = opts.validateTtlMs ?? 15000;
    this.maxFreshEntries = opts.maxFreshEntries ?? 16384;            // bounded revalidation-throttle map
    this.resolveTtlMs = opts.resolveTtlMs ?? 60000;
    this.maxResolveEntries = opts.maxResolveEntries ?? 4096;
    this.maxStatusItems = opts.maxStatusItems ?? 200;
    this.allowPrivateHosts = opts.allowPrivateHosts ?? false;
    this.getTimeoutMs = opts.getTimeoutMs ?? 900000;
    this.stallTimeoutMs = opts.stallTimeoutMs ?? 60000;
    this.failTtlMs = opts.failTtlMs ?? 10000;
    this.progressIntervalMs = opts.progressIntervalMs ?? 1000;
    this.log = opts.log || ((...a) => console.error('[engine]', ...a));

    this.hosts = new Map();        // resolve cache (bounded LRU)
    this.jobs = new Map();         // in-flight foreground fetch / recent failure
    this.fresh = new Map();        // fsPath -> lastValidatedMs (bounded LRU throttle)
    this.revalidating = new Set();
    this.metrics = { hits: 0, misses: 0 };
    this.active = 0;
    this.waiters = [];
    this.timers = [];
    this.stopped = false;
  }

  // ---- lifecycle ---------------------------------------------------------

  start() {
    fs.mkdirSync(this.cacheDir, { recursive: true });
    const t = setInterval(() => this._progressTick(), this.progressIntervalMs);
    this.timers = [t];
    this.timers.forEach((x) => x.unref && x.unref());
    return this;
  }

  stop() {
    this.stopped = true;
    this.timers.forEach((t) => clearInterval(t));
    this.timers = [];
    for (const j of this.jobs.values()) if (j.child) { try { j.child.kill('SIGKILL'); } catch {} }
  }

  // ---- the responder's single entry point (cheap + synchronous) ----------

  requestContent(host, cesPort, cesPath) {
    const fsPath = this._fsPath(host, cesPort, cesPath);
    if (!fsPath) return this._snap(State.FAILED, { host, cesPath, errKind: 'badname' });

    const key = `${host}:${cesPort}\0${cesPath}`;
    const job = this.jobs.get(key);
    if (job) {
      if (job.state === State.FAILED && Date.now() - job.failedMs > this.failTtlMs) this.jobs.delete(key);
      else return this._jobSnap(job);
    }

    let st = null;
    try { st = fs.statSync(fsPath); } catch { /* ENOENT / ENOTDIR -> not servable */ }
    if (st && st.isFile()) {
      this.metrics.hits++;                       // OS bumps atime on serve -> the FS is the LRU
      const v = this.fresh.get(fsPath) || 0;
      if (Date.now() - v > this.validateTtlMs) this._revalidate(host, cesPort, cesPath, fsPath);
      return this._snap(State.READY, { host, cesPath, file: fsPath, size: st.size, wantSize: st.size });
    }

    this.metrics.misses++;
    const j = {
      key, host, cesPort, cesPath, target: `${host}:${cesPort}`, fsPath,
      state: State.QUEUED, gotBytes: 0, wantSize: 0, child: null,
    };
    this.jobs.set(key, j);
    this._runJob(j);
    return this._jobSnap(j);
  }

  _snap(state, o) {
    return {
      state, file: o.file, cesPath: o.cesPath, host: o.host,
      size: o.size || 0, gotBytes: o.gotBytes || 0, wantSize: o.wantSize || 0,
      errKind: o.errKind, queueAhead: this.waiters.length,
    };
  }
  _jobSnap(j) {
    return this._snap(j.state, { host: j.host, cesPath: j.cesPath, gotBytes: j.gotBytes, wantSize: j.wantSize, errKind: j.errKind });
  }

  // ---- the one fetch worker ----------------------------------------------

  async _runJob(j) {
    try {
      j.state = State.RESOLVING;
      let info;
      try { info = await this._resolveHost(j.target); } catch { return this._failJob(j, 'unreachable'); }
      if (!info || !info.rpcPort) return this._failJob(j, 'nofileservice');

      j.state = State.STATTING;
      const st = await ceshStat(this.cesh, j.target, info.rpcPort, j.cesPath, info.serverKey, this.walletOpts);
      if (!st.ok) return this._failJob(j, st.errKind);
      if (st.size > this.maxFileBytes) return this._failJob(j, 'toobig');

      let cur; try { cur = fs.statSync(j.fsPath); } catch {}
      if (cur && cur.isFile() && this._matches(cur, st)) {   // already current (raced)
        this._freshTouch(j.fsPath); this.jobs.delete(j.key); return;
      }

      j.wantSize = st.size;
      j.state = State.QUEUED;
      await this._acquire();                                 // wait for the worker
      try {
        if (this.stopped) { this.jobs.delete(j.key); return; }
        j.state = State.DOWNLOADING;
        j.gotBytes = 0; j.startedMs = Date.now(); j.lastProgressMs = Date.now();

        await this._ensureRoom(st.size);                     // evict only if the disk is low
        this._mkdirp(path.dirname(j.fsPath));                // invalidates a stale file ancestor

        const part = j.fsPath + '.part';
        try { fs.unlinkSync(part); } catch {}
        const { child, done } = spawnFileGet(this.cesh, j.target, info.rpcPort, j.cesPath, info.serverKey, part, this.walletOpts);
        j.child = child;
        const r = await done; j.child = null;
        if (!r.ok) { try { fs.unlinkSync(part); } catch {} return this._failJob(j, r.errKind || 'error'); }

        if (this._swapIn(part, j.fsPath) < 0) { try { fs.unlinkSync(part); } catch {} return this._failJob(j, 'error'); }
        this._setMtime(j.fsPath, st.modifiedUs);
        this._freshTouch(j.fsPath);
        this.jobs.delete(j.key);
      } finally {
        this._release();
      }
    } catch (e) {
      this.log('job error', (e && e.stack) || e);
      this._failJob(j, 'error');
    }
  }

  _failJob(j, kind) {
    j.state = State.FAILED; j.errKind = kind || 'error'; j.failedMs = Date.now();
    j.gotBytes = 0; j.wantSize = 0;
  }

  // ---- background revalidation of a READY file ---------------------------
  //
  // The file keeps serving the whole time. STAT is cheap and not worker-gated;
  // only an actual refill (size/mtime changed) takes the worker.
  async _revalidate(host, cesPort, cesPath, fsPath) {
    if (this.revalidating.has(fsPath)) return;
    this.revalidating.add(fsPath);
    try {
      const target = `${host}:${cesPort}`;
      let info;
      try { info = await this._resolveHost(target); } catch { return this._freshTouch(fsPath); }
      if (!info || !info.rpcPort) return this._freshTouch(fsPath);

      const st = await ceshStat(this.cesh, target, info.rpcPort, cesPath, info.serverKey, this.walletOpts);
      if (!st.ok) {
        if (st.errKind === 'notfound') { try { fs.unlinkSync(fsPath); } catch {} this.fresh.delete(fsPath); }
        else this._freshTouch(fsPath);
        return;
      }
      if (st.size > this.maxFileBytes) return this._freshTouch(fsPath);
      let cur; try { cur = fs.statSync(fsPath); } catch {}
      if (cur && cur.isFile() && this._matches(cur, st)) return this._freshTouch(fsPath);

      await this._acquire();
      try {
        if (this.stopped) return;
        await this._ensureRoom(st.size);
        const part = fsPath + '.part';
        try { fs.unlinkSync(part); } catch {}
        const { done } = spawnFileGet(this.cesh, target, info.rpcPort, cesPath, info.serverKey, part, this.walletOpts);
        const r = await done;
        if (!r.ok) { try { fs.unlinkSync(part); } catch {} return this._freshTouch(fsPath); }
        if (this._swapIn(part, fsPath) < 0) { try { fs.unlinkSync(part); } catch {} return this._freshTouch(fsPath); }
        this._setMtime(fsPath, st.modifiedUs);
        this._freshTouch(fsPath);
      } finally {
        this._release();
      }
    } catch (e) {
      this.log('revalidate error', (e && e.stack) || e);
      this._freshTouch(fsPath);
    } finally {
      this.revalidating.delete(fsPath);
    }
  }

  // ---- eviction: disk-bounded, age-first, on the worker ------------------

  _freeBytes() {
    if (this.freeBytesFn) return this.freeBytesFn();
    try { const s = fs.statfsSync(this.cacheDir); return s.bavail * s.bsize; } catch { return -1; }
  }

  // Ensure `incoming` more bytes fit while keeping minFreeBytes free. Only walks
  // when the disk is actually low. It LISTS files (never deletes mid-walk) and
  // stops when either (a) it has listed enough idle (>maxAge) bytes to cover the
  // need AND seen at least minScan files (so small caches get a full eval),
  // (b) it hits maxScan (RAM guard), or (c) the walk ends. Then it deletes
  // oldest-first until the need is met — preferring idle files, falling back to
  // reaping the oldest recent ones.
  async _ensureRoom(incoming) {
    let free = this._freeBytes();
    if (free < 0) return;                                   // statfs unavailable -> best effort
    const target = this.minFreeBytes + incoming;
    if (free >= target) return;                             // room already
    const needed = target - free;

    const cutoff = Date.now() - this.maxAgeMs;
    const list = [];                                        // {p, atimeMs, size}; bounded by maxScan
    let reclaimable = 0;                                    // listed bytes idle > maxAge
    const stack = [{ dir: this.cacheDir, depth: 0 }];
    walk:
    while (stack.length) {
      const { dir, depth } = stack.pop();
      let ents; try { ents = await fsp.readdir(dir, { withFileTypes: true }); } catch { continue; }
      for (const e of ents) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) { stack.push({ dir: p, depth: depth + 1 }); continue; }
        if (e.name.endsWith('.part')) { if (!this._activePart(p)) { try { await fsp.unlink(p); } catch {} } continue; }
        if (depth === 0) continue;                          // stray root file (not content)
        let st; try { st = await fsp.stat(p); } catch { continue; }
        list.push({ p, atimeMs: st.atimeMs, size: st.size });
        if (st.atimeMs < cutoff) reclaimable += st.size;
        if ((list.length >= this.minScan && reclaimable >= needed) || list.length >= this.maxScan) break walk;
      }
    }

    const pool = reclaimable >= needed ? list.filter((f) => f.atimeMs < cutoff) : list;
    pool.sort((a, b) => a.atimeMs - b.atimeMs);             // oldest first
    let freed = 0;
    for (const f of pool) {
      if (freed >= needed) break;
      try { await fsp.unlink(f.p); freed += f.size; this.fresh.delete(f.p); } catch {}
    }
  }

  _activePart(p) {
    const base = p.slice(0, -5);
    if (this.revalidating.has(base)) return true;
    for (const j of this.jobs.values()) if (j.fsPath === base) return true;
    return false;
  }

  _freshTouch(fsPath) {
    if (this.fresh.has(fsPath)) this.fresh.delete(fsPath);
    this.fresh.set(fsPath, Date.now());
    if (this.fresh.size > this.maxFreshEntries) { const k = this.fresh.keys().next().value; this.fresh.delete(k); }
  }

  // Atomically move `part` onto `dest`; remove a stale DIRECTORY at dest. -1 fail.
  _swapIn(part, dest) {
    let cur; try { cur = fs.statSync(dest); } catch {}
    if (cur && cur.isDirectory()) this._rmrf(dest);
    try { fs.renameSync(part, dest); return 0; }
    catch (e) {
      if (e.code === 'EISDIR' || e.code === 'ENOTEMPTY' || e.code === 'EEXIST') {
        this._rmrf(dest);
        try { fs.renameSync(part, dest); return 0; } catch { return -1; }
      }
      return -1;
    }
  }

  // ---- path mapping (security-critical) ----------------------------------

  _fsPath(host, cesPort, cesPath) {
    const hostSeg = this._safeHost(host, cesPort);
    if (!hostSeg) return null;
    if (typeof cesPath !== 'string' || cesPath.indexOf('\0') >= 0 || cesPath.endsWith('/')) return null;
    const segs = cesPath.split('/').filter((s) => s.length);
    if (!segs.length) return null;
    for (const s of segs) if (s === '.' || s === '..' || s.length > 255) return null;
    const root = path.join(this.cacheDir, hostSeg);
    const full = path.join(root, ...segs);
    const rel = path.relative(root, full);
    if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) return null;
    return full;
  }

  // DNS hostnames only — IP literals rejected. A name is filesystem-safe, so the
  // cache dir is the name verbatim: no lossy rewrite, no collisions.
  _safeHost(host, cesPort) {
    if (typeof host !== 'string' || !host) return null;
    const h = host.toLowerCase();
    if (h.length > 253 || h.includes('..')) return null;
    if (h.includes(':')) return null;                                 // reject IPv6 literals
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return null;               // reject IPv4 literals
    if (!/^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/.test(h)) return null;  // DNS-safe charset
    return (cesPort && cesPort !== this.defaultCesPort) ? `${h}-${cesPort}` : h;
  }

  // mkdir -p, removing a stale FILE component where a directory is now needed.
  _mkdirp(dir) {
    for (let i = 0; i < 64; i++) {
      try { fs.mkdirSync(dir, { recursive: true }); return; }
      catch (e) {
        if (e.code !== 'ENOTDIR' && e.code !== 'EEXIST') throw e;
        const rel = path.relative(this.cacheDir, dir);
        if (rel.startsWith('..') || path.isAbsolute(rel)) throw e;
        let cur = this.cacheDir, removed = false;
        for (const p of rel.split(path.sep)) {
          cur = path.join(cur, p);
          let st; try { st = fs.statSync(cur); } catch { break; }
          if (st.isFile()) { try { fs.unlinkSync(cur); } catch {} this.fresh.delete(cur); removed = true; break; }
        }
        if (!removed) throw e;
      }
    }
  }

  _rmrf(p) { try { fs.rmSync(p, { recursive: true, force: true }); } catch {} }
  _setMtime(p, modifiedUs) { try { fs.utimesSync(p, new Date(), (Number(modifiedUs) || 0) / 1e6); } catch {} }
  _matches(st, ces) {
    return st.size === ces.size && Math.abs(Math.round(st.mtimeMs * 1000) - (Number(ces.modifiedUs) || 0)) <= 1;
  }

  // ---- one worker --------------------------------------------------------

  _acquire() {
    if (this.active < this.maxInflight) { this.active++; return Promise.resolve(); }
    return new Promise((res) => this.waiters.push(res));
  }
  _release() { const next = this.waiters.shift(); if (next) next(); else this.active--; }

  // ---- progress sampling + stall reaper (powers the live page) -----------

  _progressTick() {
    if (this.stopped) return;
    const now = Date.now();
    for (const j of this.jobs.values()) {
      if (!j.child) continue;
      try { const s = fs.statSync(j.fsPath + '.part').size; if (s > (j.gotBytes || 0)) { j.gotBytes = s; j.lastProgressMs = now; } } catch {}
      if (now - j.startedMs > this.getTimeoutMs || now - j.lastProgressMs > this.stallTimeoutMs) {
        this.log(`killing stalled fetch ${j.cesPath} (${fmtBytes(j.gotBytes || 0)})`);
        try { j.child.kill('SIGKILL'); } catch {}
      }
    }
  }

  // ---- per-host resolve (rpcPort + serverKey), cached + coalesced + LRU ---

  async _assertRoutable(target) {
    if (this.allowPrivateHosts) return;
    const host = hostOf(target);
    let addrs;
    try { addrs = await dns.lookup(host, { all: true }); }
    catch { throw new Error(`cannot resolve ${host}`); }
    if (!addrs.length) throw new Error(`no address for ${host}`);
    for (const a of addrs) if (!isGloballyRoutable(a.address)) throw new Error(`${host} resolves to non-routable ${a.address} — refused`);
  }

  _resolveHost(target) {
    const now = Date.now();
    const c = this.hosts.get(target);
    if (c && c.serverKey && (now - c.ts) < this.resolveTtlMs) { c.used = now; return Promise.resolve(c); }
    if (c && c._inflight) return c._inflight;
    const p = this._assertRoutable(target)
      .then(() => ping(this.cesh, target, this.walletOpts))
      .then((info) => {
        const ts = Date.now();
        const ent = { rpcPort: info.rpcPort, serverKey: info.serverPublicKey, ts, used: ts };
        this.hosts.set(target, ent); this._evictResolveCache(); return ent;
      }, (err) => {
        const ts = Date.now();
        this.hosts.set(target, { error: 'unreachable', ts, used: ts }); this._evictResolveCache(); throw err;
      });
    this.hosts.set(target, { ...(c || { ts: 0 }), _inflight: p });
    p.then(() => {}, () => {}).finally(() => {
      const cur = this.hosts.get(target);
      if (cur && cur._inflight === p) delete cur._inflight;
    });
    return p;
  }

  _evictResolveCache() {
    let over = this.hosts.size - this.maxResolveEntries;
    if (over <= 0) return;
    const cands = [...this.hosts.entries()].filter(([, v]) => !v._inflight)
      .sort((a, b) => (a[1].used || a[1].ts || 0) - (b[1].used || b[1].ts || 0));
    for (const [k] of cands) { if (over <= 0) break; this.hosts.delete(k); over--; }
  }

  async resolve(target) { return this._resolveHost(target); }

  // ---- introspection -----------------------------------------------------
  stats() {
    const items = [];
    let live = 0;
    for (const j of this.jobs.values()) {
      live++;
      if (items.length < this.maxStatusItems) items.push({
        host: j.host, cesPath: j.cesPath, state: j.state,
        size: 0, gotBytes: j.gotBytes || 0, wantSize: j.wantSize || 0, errKind: j.errKind,
      });
    }
    return {
      freeBytes: this._freeBytes(), minFreeBytes: this.minFreeBytes, maxFileBytes: this.maxFileBytes,
      active: this.active, queued: this.waiters.length,
      hits: this.metrics.hits, misses: this.metrics.misses, resolveEntries: this.hosts.size,
      live, itemsTruncated: live > items.length, items,
    };
  }
}

export function hostOf(target) {
  if (target.startsWith('[')) return target.slice(1, target.indexOf(']'));
  const i = target.lastIndexOf(':');
  return i > 0 ? target.slice(0, i) : target;
}

export function isGloballyRoutable(ip) {
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (v4) {
    const o = v4.slice(1).map(Number);
    if (o.some((x) => x > 255)) return false;
    const [a, b] = o;
    if (a === 0 || a === 10 || a === 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 192 && b === 0 && (o[2] === 0 || o[2] === 2)) return false;
    if (a === 198 && (b === 18 || b === 19)) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a >= 224) return false;
    return true;
  }
  const s = ip.toLowerCase();
  if (s === '::1' || s === '::') return false;
  if (/^fe[89ab]/.test(s)) return false;
  if (/^f[cd]/.test(s)) return false;
  if (s.startsWith('ff')) return false;
  const mapped = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(s);
  if (mapped) return isGloballyRoutable(mapped[1]);
  return true;
}

export function fmtBytes(n) {
  n = Number(n) || 0;
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${i === 0 ? n : n.toFixed(1)} ${u[i]}`;
}
