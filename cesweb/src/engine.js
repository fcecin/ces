// cesweb engine — the content state machine.
//
// The HTTP responder NEVER fetches, evicts, validates, or blocks; it only reads
// a content entry's current state and either streams a ready cache file or
// renders a sitrep/error page. ALL the work — resolving servers, statting,
// downloading (with live progress), revalidating, refilling, evicting, and
// recovering from faults at boot — happens HERE, on the engine's own timers,
// off the request path. The engine is the single owner of the cache directory,
// the in-memory content index, and every cesh child process. It is designed to
// stay consistent across crashes: state is reconstructed from disk on start,
// and every transition is fault-tolerant (a dead/stalled cesh, a truncated
// part-file, an unreachable host — none of them wedge the machine).
//
// Content key = sha256(serverKey \0 cesPath) — the CES server's pubkey (learned
// via ping), NOT the host string, so the same server reached as a DNS name, an
// IPv4, or an IPv6 shares one entry instead of a full copy per spelling. It is
// irreversible, so an entry recovered from disk at boot is "dormant ready": it
// can be SERVED (we have its bytes) but cannot be revalidated/refilled until a
// live request resolves a host to that serverKey and re-attaches the identity.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import { ping, stat as ceshStat, spawnFileGet } from './cesh.js';

// What the responder switches on. READY => serve the cache file; FAILED =>
// error page; everything else => a sitrep page that auto-refreshes.
export const State = {
  RESOLVING: 'resolving',     // pinging the host for its rpc port + key
  STATTING: 'statting',       // cheap STAT to learn size / mtime
  QUEUED: 'queued',           // waiting for a download slot (inflight cap)
  DOWNLOADING: 'downloading', // cesh file get running; gotBytes/wantSize live
  READY: 'ready',             // cache file present + (re)validated
  FAILED: 'failed',           // errKind set; retried after failTtlMs
};

const HEX64 = /^[0-9a-f]{64}$/;

export class Engine {
  constructor(opts = {}) {
    this.cesh = opts.cesh || 'cesh';
    this.cacheDir = opts.cacheDir || path.join(process.cwd(), 'cache');
    this.walletOpts = opts.walletOpts || {};
    this.maxCacheBytes = opts.maxCacheBytes ?? (4 * 1024 * 1024 * 1024); // 4 GiB
    // A single cacheable file must fit inside the whole cache, else eviction
    // can never get under the cap and we'd thrash re-downloading it forever.
    this.maxFileBytes = Math.min(opts.maxFileBytes ?? (1024 * 1024 * 1024), this.maxCacheBytes);
    this.lowWaterPct = opts.lowWaterPct ?? 90;     // evict down to this % of cap
    this.maxInflight = opts.maxInflight ?? 8;      // concurrent downloads
    this.validateTtlMs = opts.validateTtlMs ?? 15000;
    this.resolveTtlMs = opts.resolveTtlMs ?? 60000;
    // Hard cap on the resolve cache (host:port -> identity). The host-spelling
    // key space is unbounded and caller-controlled on the open `/<host>/` form,
    // so — like the content cache — it is size-capped with LRU eviction rather
    // than left to grow. Evicting a resolved host is safe: it just re-pings.
    this.maxResolveEntries = opts.maxResolveEntries ?? 4096;
    // SSRF guard: refuse hosts that resolve to a non-globally-routable address
    // (loopback, RFC1918, link-local, CGNAT, …) so a crafted URL can't aim the
    // gateway at localhost or the internal network. Off only for tests/localdemo.
    this.allowPrivateHosts = opts.allowPrivateHosts ?? false;
    this.getTimeoutMs = opts.getTimeoutMs ?? 900000;   // hard cap on a fill
    this.stallTimeoutMs = opts.stallTimeoutMs ?? 60000; // no-progress kill
    this.failTtlMs = opts.failTtlMs ?? 10000;          // cache failures briefly
    this.evictIntervalMs = opts.evictIntervalMs ?? 30000;
    this.progressIntervalMs = opts.progressIntervalMs ?? 1000;
    this.log = opts.log || ((...a) => console.error('[engine]', ...a));

    this.entries = new Map();  // hash -> entry
    this.hosts = new Map();    // "host:port" -> { rpcPort, serverKey, ts, _inflight? }
    this.totalBytes = 0;
    this.metrics = { hits: 0, misses: 0, dedupSaves: 0 };  // cache serves / fetches / copies avoided by identity-dedup
    this.active = 0;           // download slots in use
    this.waiters = [];         // FIFO of resolve fns waiting for a slot
    this.timers = [];
    this.stopped = false;
  }

  // ---- lifecycle ---------------------------------------------------------

  start() {
    fs.mkdirSync(this.cacheDir, { recursive: true });
    this._recover();
    const t1 = setInterval(() => this._progressTick(), this.progressIntervalMs);
    const t2 = setInterval(() => {
      try { this._pruneStale(); this._evictIfNeeded(); } catch (e) { this.log('maint tick', e); }
    }, this.evictIntervalMs);
    this.timers = [t1, t2];
    // Don't let the engine's heartbeat keep a test process alive.
    this.timers.forEach((t) => t.unref && t.unref());
    return this;
  }

  stop() {
    this.stopped = true;
    this.timers.forEach((t) => clearInterval(t));
    this.timers = [];
    for (const e of this.entries.values()) {
      if (e.child) { try { e.child.kill('SIGKILL'); } catch {} }
    }
  }

  // Rebuild the index from disk. Cached files survive restarts; orphaned
  // part/tmp files (an interrupted fill) and metas without data are swept.
  _recover() {
    let files;
    try { files = fs.readdirSync(this.cacheDir); } catch { return; }
    const data = new Set(), metas = new Set();
    for (const f of files) {
      if (HEX64.test(f)) data.add(f);
      else if (f.endsWith('.meta') && HEX64.test(f.slice(0, -5))) metas.add(f.slice(0, -5));
      else if (f.endsWith('.part') || f.includes('.tmp')) {
        try { fs.unlinkSync(path.join(this.cacheDir, f)); } catch {}
      }
    }
    const now = Date.now();
    for (const hash of data) {
      const file = path.join(this.cacheDir, hash);
      let size;
      try { size = fs.statSync(file).size; } catch { continue; }
      let modifiedUs = 0;
      if (metas.has(hash)) {
        try { modifiedUs = Number(JSON.parse(fs.readFileSync(file + '.meta', 'utf8')).modifiedUs) || 0; } catch {}
      }
      // Dormant ready: serveable now; revalidatable once a request re-attaches
      // the host/path that hashes to `hash`.
      this.entries.set(hash, {
        hash, file, state: State.READY,
        size, modifiedUs, validatedMs: 0, lastAccess: now, hits: 0,
      });
      this.totalBytes += size;
    }
    for (const hash of metas) {
      if (!data.has(hash)) { try { fs.unlinkSync(path.join(this.cacheDir, hash + '.meta')); } catch {} }
    }
    this.log(`recovered ${this.entries.size} cached files, ${fmtBytes(this.totalBytes)}`);
  }

  // ---- the responder's single entry point --------------------------------

  // Cheap + synchronous. Returns a snapshot of the content's current state and,
  // when needed, KICKS background work (never awaits it). The responder calls
  // this and renders the snapshot — that is the whole web path.
  //
  // Cache identity is the CES server's PUBKEY (learned via ping), NOT the host
  // string: a DNS name, its IPv4, and its IPv6 all ping the same server and so
  // share ONE cache entry instead of a full copy per spelling. That needs the
  // host resolved first; until then we report RESOLVING and let the resolve's
  // continuation materialize the entry (so it makes progress with no further
  // request). A failed resolve is reported as FAILED, not an infinite RESOLVING.
  requestContent(host, cesPort, cesPath) {
    const target = `${host}:${cesPort}`;
    const now = Date.now();
    const r = this.hosts.get(target);

    if (r && r.serverKey) { r.used = now; return this._serveByKey(r.serverKey, host, cesPort, cesPath, target); }
    if (r && r.error && (now - r.ts) < this.failTtlMs) { r.used = now; return this._fakeSnap(State.FAILED, host, cesPath, r.error); }

    this._resolveHost(target)
      .then((ent) => { if (ent && ent.serverKey) this._serveByKey(ent.serverKey, host, cesPort, cesPath, target); })
      .catch(() => {});
    return this._fakeSnap(State.RESOLVING, host, cesPath);
  }

  // Snapshot for a state with no content entry yet (resolving / resolve-failed).
  _fakeSnap(state, host, cesPath, errKind) {
    return { state, file: undefined, cesPath, host, size: 0, gotBytes: 0, wantSize: 0,
             errKind, queueAhead: this.waiters.length };
  }

  // Get-or-create the content entry keyed by (serverKey, cesPath) and return its
  // snapshot, driving background work as needed. Idempotent — safe to call from
  // a poll OR from a resolve continuation.
  _serveByKey(serverKey, host, cesPort, cesPath, target) {
    const hash = crypto.createHash('sha256').update(serverKey + '\0' + cesPath).digest('hex');
    const now = Date.now();
    let e = this.entries.get(hash);

    if (!e) {
      this.metrics.misses++;
      e = { hash, host, cesPort, cesPath, target, serverKey,
            file: path.join(this.cacheDir, hash), spellings: new Set([target]),
            state: State.RESOLVING, hits: 0, lastAccess: now };
      this.entries.set(hash, e);
      this._drive(e);
      return this._snap(e);
    }

    // Re-attach identity to a dormant (recovered) entry; track the freshest
    // target that reached this server (any spelling resolving to its key).
    if (!e.serverKey) { e.cesPath = cesPath; e.serverKey = serverKey; }
    e.host = host; e.cesPort = cesPort; e.target = target;
    e.lastAccess = now;

    // A new host spelling reusing this entry is a full copy the dedup avoided.
    if (!e.spellings) e.spellings = new Set();
    if (!e.spellings.has(target)) { e.spellings.add(target); if (e.spellings.size > 1) this.metrics.dedupSaves++; }

    if (e.state === State.READY) {
      // Self-heal: if the cache file vanished out from under us (operator rm,
      // disk loss), forget it and re-fetch instead of serving a hole.
      if (!fs.existsSync(e.file)) {
        this.totalBytes -= (e.size || 0);
        e.state = State.RESOLVING; e.size = undefined; e.validatedMs = 0;
        this._drive(e);
        return this._snap(e);
      }
      e.hits = (e.hits || 0) + 1;
      this.metrics.hits++;
      if ((now - (e.validatedMs || 0)) > this.validateTtlMs && !e.revalidating) this._revalidate(e);
      return this._snap(e);
    }
    if (e.state === State.FAILED) {
      if ((now - (e.failedMs || 0)) > this.failTtlMs) { e.state = State.RESOLVING; e.errKind = undefined; this._drive(e); }
      return this._snap(e);
    }
    // resolving / statting / queued / downloading — just report progress.
    return this._snap(e);
  }

  _snap(e) {
    return {
      state: e.state, file: e.file, cesPath: e.cesPath, host: e.host,
      size: e.size || 0, gotBytes: e.gotBytes || 0, wantSize: e.wantSize || e.size || 0,
      errKind: e.errKind, queueAhead: this.waiters.length,
    };
  }

  // ---- first-fetch pipeline (state visible: resolving→…→downloading→ready) -

  async _drive(e) {
    if (e.driving) return;
    e.driving = true;
    try {
      e.state = State.RESOLVING;
      let host;
      try { host = await this._resolveHost(e.target); }
      catch { return this._fail(e, 'unreachable'); }
      if (!host || !host.rpcPort) return this._fail(e, 'nofileservice');
      e.rpcPort = host.rpcPort; e.serverKey = host.serverKey;

      e.state = State.STATTING;
      const st = await ceshStat(this.cesh, e.target, e.rpcPort, e.cesPath, e.serverKey, this.walletOpts);
      if (!st.ok) return this._fail(e, st.errKind);
      if (st.size > this.maxFileBytes) return this._fail(e, 'toobig');

      // A recovered file whose bytes still match upstream: validate, don't refetch.
      if (fs.existsSync(e.file) && e.size === st.size && e.modifiedUs === st.modifiedUs) {
        return this._ready(e, st.size, st.modifiedUs);
      }

      e.wantSize = st.size;
      await this._runDownload(e, { refill: false, modifiedUs: st.modifiedUs });
    } catch (err) {
      this.log('drive error', err && err.stack || err);
      this._fail(e, 'error');
    } finally {
      e.driving = false;
    }
  }

  // ---- background revalidation of an already-ready entry ------------------
  //
  // State stays READY the whole time: the old cache file keeps serving while we
  // re-stat and (only if it changed) refill in the background, swapping the
  // file atomically when the new copy is complete. A transient error keeps the
  // old copy; an upstream deletion drops it (consistent with the origin).
  async _revalidate(e) {
    if (e.revalidating) return;
    e.revalidating = true;
    try {
      let host;
      try { host = await this._resolveHost(e.target); }
      catch { e.validatedMs = Date.now(); return; }   // network blip → keep serving
      if (!host || !host.rpcPort) { e.validatedMs = Date.now(); return; }
      e.rpcPort = host.rpcPort; e.serverKey = host.serverKey;

      const st = await ceshStat(this.cesh, e.target, e.rpcPort, e.cesPath, e.serverKey, this.walletOpts);
      if (!st.ok) {
        if (st.errKind === 'notfound') return this._evict(e);  // gone upstream → drop
        e.validatedMs = Date.now();                            // transient → keep
        return;
      }
      if (st.size === e.size && st.modifiedUs === e.modifiedUs) { e.validatedMs = Date.now(); return; }
      if (st.size > this.maxFileBytes) { e.validatedMs = Date.now(); return; } // too big now → keep old

      e.wantSize = st.size;
      await this._runDownload(e, { refill: true, modifiedUs: st.modifiedUs });
      e.validatedMs = Date.now();
    } catch (err) {
      this.log('revalidate error', err && err.stack || err);
      e.validatedMs = Date.now();
    } finally {
      e.revalidating = false;
    }
  }

  // ---- the download itself (shared by first-fetch and refill) -------------

  async _runDownload(e, { refill, modifiedUs }) {
    if (!refill) e.state = State.QUEUED;
    await this._acquire();
    try {
      if (this.stopped) return;
      if (!refill) e.state = State.DOWNLOADING;  // refill stays READY (serves old)
      const part = e.file + '.part';
      try { fs.unlinkSync(part); } catch {}
      e.gotBytes = 0; e.startedMs = Date.now(); e.lastProgressMs = Date.now();

      const { child, done } = spawnFileGet(this.cesh, e.target, e.rpcPort, e.cesPath, e.serverKey, part, this.walletOpts);
      e.child = child;
      const r = await done;
      e.child = null;

      if (r.ok) {
        let realSize;
        try { realSize = fs.statSync(part).size; } catch { realSize = e.wantSize || 0; }
        try { fs.renameSync(part, e.file); }
        catch (er) { try { fs.unlinkSync(part); } catch {} if (!refill) this._fail(e, 'error'); return; }
        const oldSize = refill ? (e.size || 0) : 0;
        this.totalBytes += realSize - oldSize;
        this._writeMeta(e.file, { size: realSize, modifiedUs });
        this._ready(e, realSize, modifiedUs);
        this._evictIfNeeded();
      } else {
        try { fs.unlinkSync(part); } catch {}
        if (!refill) this._fail(e, r.errKind || 'error');  // refill fail → keep old READY
      }
    } finally {
      this._release();
    }
  }

  _ready(e, size, modifiedUs) {
    e.state = State.READY;
    e.size = size; e.modifiedUs = modifiedUs;
    e.validatedMs = Date.now(); e.lastAccess = Date.now();
    e.gotBytes = undefined; e.wantSize = undefined; e.errKind = undefined;
  }

  _fail(e, kind) {
    e.state = State.FAILED; e.errKind = kind || 'error'; e.failedMs = Date.now();
    e.gotBytes = undefined; e.wantSize = undefined;
  }

  // ---- download-slot semaphore (caps concurrent fills) -------------------

  _acquire() {
    if (this.active < this.maxInflight) { this.active++; return Promise.resolve(); }
    return new Promise((res) => this.waiters.push(res));
  }
  _release() {
    const next = this.waiters.shift();
    if (next) next();          // hand the slot straight to a waiter (active steady)
    else this.active--;        // slot freed
  }

  // ---- progress sampling + stall/timeout reaper --------------------------

  _progressTick() {
    if (this.stopped) return;
    const now = Date.now();
    for (const e of this.entries.values()) {
      if (!e.child) continue;
      try {
        const s = fs.statSync(e.file + '.part').size;
        if (s > (e.gotBytes || 0)) { e.gotBytes = s; e.lastProgressMs = now; }
      } catch {}
      if (now - e.startedMs > this.getTimeoutMs || now - e.lastProgressMs > this.stallTimeoutMs) {
        this.log(`killing stalled fetch ${e.cesPath} (${fmtBytes(e.gotBytes || 0)})`);
        try { e.child.kill('SIGKILL'); } catch {}   // → done resolves non-zero → handled
      }
    }
  }

  // ---- cache eviction (least-recently-used first; async, never on web path) -
  //
  // LRU, not LFU: a file just filled has the freshest lastAccess and so is
  // evicted last — evicting by raw hit-count would target the brand-new file
  // (hits 0) and thrash. Hits break ties (the less-popular of two equally-stale
  // files goes first), honoring "evict the least-requested" without the churn.

  _evictIfNeeded() {
    if (this.totalBytes <= this.maxCacheBytes) return;
    const low = this.maxCacheBytes * (this.lowWaterPct / 100);
    const cands = [...this.entries.values()]
      .filter((e) => e.state === State.READY && !e.revalidating && !e.child)
      .sort((a, b) => (a.lastAccess - b.lastAccess) || (a.hits - b.hits));
    for (const e of cands) {
      if (this.totalBytes <= low) break;
      this.log(`evicting ${e.cesPath || e.hash} (${fmtBytes(e.size || 0)}, hits=${e.hits || 0})`);
      this._evict(e);
    }
  }

  _evict(e) {
    try { fs.unlinkSync(e.file); } catch {}            // safe mid-stream: open fds keep the inode
    try { fs.unlinkSync(e.file + '.meta'); } catch {}
    this.totalBytes -= (e.size || 0);
    if (this.totalBytes < 0) this.totalBytes = 0;
    this.entries.delete(e.hash);
  }

  // Drop FAILED entries nobody has asked about recently, so path-scanning can't
  // grow the index without bound (a fresh request just re-creates + re-drives).
  _pruneStale() {
    const now = Date.now();
    const cutoff = Math.max(60000, this.failTtlMs * 5);
    for (const e of this.entries.values()) {
      if (e.state === State.FAILED && (now - (e.lastAccess || 0)) > cutoff) this.entries.delete(e.hash);
    }
  }

  // ---- per-host resolve (rpcPort + serverKey), cached + coalesced ---------

  // Reject a target whose host resolves to anything not globally routable.
  // Checks EVERY resolved address (so a name with one public + one private A
  // record can't smuggle the private one past us).
  async _assertRoutable(target) {
    if (this.allowPrivateHosts) return;
    const host = hostOf(target);
    let addrs;
    try { addrs = await dns.lookup(host, { all: true }); }
    catch { throw new Error(`cannot resolve ${host}`); }
    if (!addrs.length) throw new Error(`no address for ${host}`);
    for (const a of addrs) {
      if (!isGloballyRoutable(a.address))
        throw new Error(`${host} resolves to non-routable ${a.address} — refused`);
    }
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
        this.hosts.set(target, ent);
        this._evictResolveCache();
        return ent;
      }, (err) => {
        // Record the failure so requestContent reports FAILED instead of looping
        // on RESOLVING; cleared by a retry after failTtl.
        const ts = Date.now();
        this.hosts.set(target, { error: 'unreachable', ts, used: ts });
        this._evictResolveCache();
        throw err;
      });
    this.hosts.set(target, { ...(c || { ts: 0 }), _inflight: p });
    p.then(() => {}, () => {}).finally(() => {
      const cur = this.hosts.get(target);
      if (cur && cur._inflight === p) delete cur._inflight;
    });
    return p;
  }

  // Keep the resolve cache under its hard cap, dropping least-recently-used
  // entries (never an in-flight resolve). Re-resolving an evicted host is safe.
  _evictResolveCache() {
    let over = this.hosts.size - this.maxResolveEntries;
    if (over <= 0) return;
    const cands = [...this.hosts.entries()]
      .filter(([, v]) => !v._inflight)
      .sort((a, b) => (a[1].used || a[1].ts || 0) - (b[1].used || b[1].ts || 0));
    for (const [k] of cands) {
      if (over <= 0) break;
      this.hosts.delete(k);
      over--;
    }
  }

  _writeMeta(file, m) {
    try { fs.writeFileSync(file + '.meta', JSON.stringify({ size: m.size, modifiedUs: m.modifiedUs })); } catch {}
  }

  // Resolve a target's {rpcPort, serverKey} via the cached ping. Public so the
  // terminal manager reuses the same resolve cache as the content engine.
  async resolve(target) { return this._resolveHost(target); }

  // ---- introspection (status endpoint + tests) ---------------------------

  stats() {
    return {
      totalBytes: this.totalBytes, maxCacheBytes: this.maxCacheBytes, maxFileBytes: this.maxFileBytes,
      active: this.active, queued: this.waiters.length, entries: this.entries.size,
      hits: this.metrics.hits, misses: this.metrics.misses, dedupSaves: this.metrics.dedupSaves,
      resolveEntries: this.hosts.size,
      items: [...this.entries.values()].map((e) => ({
        host: e.host, cesPath: e.cesPath, state: e.state,
        size: e.size || 0, gotBytes: e.gotBytes || 0, wantSize: e.wantSize || 0,
        hits: e.hits || 0, errKind: e.errKind,
      })),
    };
  }
}

// Host out of a "host:port" / "[ipv6]:port" / "host" target.
export function hostOf(target) {
  if (target.startsWith('[')) return target.slice(1, target.indexOf(']'));
  const i = target.lastIndexOf(':');
  return i > 0 ? target.slice(0, i) : target;
}

// Is `ip` a globally-routable unicast address? Conservative: anything we don't
// recognize as global is treated as NOT routable only for the families we
// understand; unknown formats default to routable (DNS already vouched it).
export function isGloballyRoutable(ip) {
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (v4) {
    const o = v4.slice(1).map(Number);
    if (o.some((x) => x > 255)) return false;
    const [a, b] = o;
    if (a === 0) return false;                          // 0.0.0.0/8 "this host"
    if (a === 10) return false;                         // RFC1918
    if (a === 127) return false;                        // loopback
    if (a === 169 && b === 254) return false;           // link-local
    if (a === 172 && b >= 16 && b <= 31) return false;  // RFC1918
    if (a === 192 && b === 168) return false;           // RFC1918
    if (a === 192 && b === 0 && o[2] === 0) return false; // 192.0.0.0/24
    if (a === 192 && b === 0 && o[2] === 2) return false;  // TEST-NET-1
    if (a === 198 && (b === 18 || b === 19)) return false; // benchmark
    if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT 100.64/10
    if (a >= 224) return false;                         // multicast + reserved
    return true;
  }
  const s = ip.toLowerCase();
  if (s === '::1' || s === '::') return false;          // loopback / unspecified
  if (/^fe[89ab]/.test(s)) return false;               // fe80::/10 link-local
  if (/^f[cd]/.test(s)) return false;                  // fc00::/7 unique-local
  if (s.startsWith('ff')) return false;                // multicast
  const mapped = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(s);
  if (mapped) return isGloballyRoutable(mapped[1]);    // IPv4-mapped
  return true;
}

export function fmtBytes(n) {
  n = Number(n) || 0;
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${i === 0 ? n : n.toFixed(1)} ${u[i]}`;
}
