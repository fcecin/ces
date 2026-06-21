// Engine = the filesystem-backed content cache (one worker, no RAM index).
// Content lives at cache/<host>/<cesPath>; size+mtime are its metadata; the
// OS atime is the LRU; eviction is disk-bounded and age-first. Run: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { State } from '../src/engine.js';
import { tmpDir, writeFixture, makeEngine, waitState, waitFor, sleep } from './util.mjs';

const H = 'localhost', P = 53830;
const cpath = (cache, ...segs) => path.join(cache, H, ...segs);
const DAY = 86400000;

function setup(fixture, opts) {
  const cache = tmpDir();
  const fx = writeFixture(cache, fixture);
  const engine = makeEngine(cache, fx, opts);
  return { cache, fx, engine };
}

// write a file under cache/<host>/p with a controlled size + idle age (atime).
function mkFile(cache, name, bytes, ageMs) {
  const dir = cpath(cache, 'p'); fs.mkdirSync(dir, { recursive: true });
  const p = path.join(dir, name);
  fs.writeFileSync(p, Buffer.alloc(bytes));
  const t = (Date.now() - ageMs) / 1000; fs.utimesSync(p, t, t);
  return p;
}

test('fetch: resolving -> ready, content cached at its readable host/path', async () => {
  const { cache, engine } = setup({ files: { '/p/a.txt': { bytes: 'hello world', modifiedUs: 100 } } });
  try {
    const first = engine.requestContent(H, P, '/p/a.txt');
    assert.equal(first.state, State.RESOLVING);
    const ready = await waitState(engine, H, P, '/p/a.txt', State.READY);
    assert.equal(ready.size, 11);
    assert.equal(ready.file, cpath(cache, 'p', 'a.txt'));
    assert.equal(fs.readFileSync(ready.file, 'utf8'), 'hello world');
  } finally { engine.stop(); }
});

test('missing file -> FAILED notfound', async () => {
  const { engine } = setup({ files: { '/p/gone.txt': { statError: 'FILE_NOT_FOUND' } } });
  try { assert.equal((await waitState(engine, H, P, '/p/gone.txt', State.FAILED)).errKind, 'notfound'); }
  finally { engine.stop(); }
});

test('payment failure on read -> FAILED poor', async () => {
  const { engine } = setup({ files: { '/p/x.bin': { size: 50, getError: 'INSUFFICIENT_BALANCE' } } });
  try { assert.equal((await waitState(engine, H, P, '/p/x.bin', State.FAILED)).errKind, 'poor'); }
  finally { engine.stop(); }
});

test('oversize file is rejected at STAT (no download) -> FAILED toobig', async () => {
  const { engine } = setup({ files: { '/p/huge.bin': { size: 10_000 } } }, { maxFileBytes: 1000 });
  try { assert.equal((await waitState(engine, H, P, '/p/huge.bin', State.FAILED)).errKind, 'toobig'); }
  finally { engine.stop(); }
});

test('unreachable host -> FAILED unreachable', async () => {
  const { engine } = setup({ ping: { fail: true }, files: {} });
  try { assert.equal((await waitState(engine, H, P, '/p/a.txt', State.FAILED)).errKind, 'unreachable'); }
  finally { engine.stop(); }
});

test('slow download exposes live DOWNLOADING progress, then READY', async () => {
  const size = 400_000;
  const { engine } = setup({ files: { '/p/slow.bin': { size, fill: 'drip', dripBytes: 50_000, dripMs: 50 } } });
  try {
    const mid = await waitFor(() => {
      const s = engine.requestContent(H, P, '/p/slow.bin');
      return (s.state === State.DOWNLOADING && s.gotBytes > 0 && s.gotBytes < size) ? s : false;
    });
    assert.equal(mid.wantSize, size);
    assert.equal((await waitState(engine, H, P, '/p/slow.bin', State.READY, { timeout: 8000 })).size, size);
  } finally { engine.stop(); }
});

test('stalled download is reaped -> FAILED', async () => {
  const { engine } = setup({ files: { '/p/hang.bin': { size: 500_000, fill: 'stall' } } },
    { stallTimeoutMs: 200, progressIntervalMs: 40 });
  try { assert.ok((await waitState(engine, H, P, '/p/hang.bin', State.FAILED, { timeout: 5000 })).errKind); }
  finally { engine.stop(); }
});

test('one worker: a second miss QUEUES behind the first', async () => {
  const { engine } = setup({
    files: {
      '/p/d1.bin': { size: 300_000, fill: 'drip', dripBytes: 30_000, dripMs: 60 },
      '/p/d2.bin': { size: 300_000, fill: 'drip', dripBytes: 30_000, dripMs: 60 },
    },
  }, { maxInflight: 1 });
  try {
    engine.requestContent(H, P, '/p/d1.bin');
    engine.requestContent(H, P, '/p/d2.bin');
    await waitFor(() => engine.stats().items.some((i) => i.state === State.QUEUED));
    await waitState(engine, H, P, '/p/d1.bin', State.READY, { timeout: 8000 });
    await waitState(engine, H, P, '/p/d2.bin', State.READY, { timeout: 8000 });
  } finally { engine.stop(); }
});

test('eviction: idle>maxAge files are nuked first, stopping once enough is freed', async () => {
  const { cache, engine } = setup({ files: {} },
    { minFreeBytes: 1000, maxAgeMs: DAY, evictBatch: 8, freeBytesFn: () => 0 });
  try {
    const oldA = mkFile(cache, 'old-a.bin', 600, 2 * DAY);   // idle 2d -> candidate
    const oldB = mkFile(cache, 'old-b.bin', 600, 3 * DAY);   // idle 3d -> candidate
    const fresh = mkFile(cache, 'fresh.bin', 600, 60_000);   // idle 1m -> keep
    await engine._ensureRoom(0);                             // free 0, target 1000
    assert.ok(!fs.existsSync(oldA) && !fs.existsSync(oldB), 'idle files nuked');
    assert.ok(fs.existsSync(fresh), 'fresh file kept');
  } finally { engine.stop(); }
});

test('eviction falls back to deleting the oldest when nothing is past maxAge', async () => {
  const { cache, engine } = setup({ files: {} },
    { minFreeBytes: 1000, maxAgeMs: 7 * DAY, evictBatch: 8, freeBytesFn: () => 0 });
  try {
    const older = mkFile(cache, 'older.bin', 1200, 3600_000);  // 1h, oldest, 1200B
    const newer = mkFile(cache, 'newer.bin', 600, 60_000);     // 1m, newest
    await engine._ensureRoom(0);                               // no candidates -> oldest-first fallback
    assert.ok(!fs.existsSync(older), 'oldest evicted in fallback');
    assert.ok(fs.existsSync(newer), 'newer kept');
  } finally { engine.stop(); }
});

test('eviction does nothing when the disk has room', async () => {
  const { cache, engine } = setup({ files: {} },
    { minFreeBytes: 1000, maxAgeMs: DAY, freeBytesFn: () => 1_000_000 });
  try {
    const f = mkFile(cache, 'keep.bin', 600, 5 * DAY);   // ancient but disk has room
    await engine._ensureRoom(0);
    assert.ok(fs.existsSync(f), 'nothing evicted while under the free-space target');
  } finally { engine.stop(); }
});

test('revalidation refills changed content while staying READY (serves old until swap)', async () => {
  const { cache, engine } = setup({ files: { '/p/c.txt': { bytes: 'AAAAA', modifiedUs: 100 } } },
    { validateTtlMs: 40 });
  try {
    const r1 = await waitState(engine, H, P, '/p/c.txt', State.READY);
    assert.equal(fs.readFileSync(r1.file, 'utf8'), 'AAAAA');
    writeFixture(cache, { files: { '/p/c.txt': { bytes: 'BBBBBBBBBB', modifiedUs: 200 } } });
    await sleep(60);
    let everNotReady = false;
    await waitFor(() => {
      if (engine.requestContent(H, P, '/p/c.txt').state !== State.READY) everNotReady = true;
      return fs.readFileSync(r1.file, 'utf8') === 'BBBBBBBBBB';
    }, { timeout: 5000 });
    assert.equal(everNotReady, false, 'stayed READY throughout refill');
  } finally { engine.stop(); }
});

test('a same-size content change is still detected (mtime <- modifiedUs)', async () => {
  const { cache, engine } = setup({ files: { '/p/s.txt': { bytes: 'AAAAA', modifiedUs: 100 } } },
    { validateTtlMs: 40 });
  try {
    const r = await waitState(engine, H, P, '/p/s.txt', State.READY);
    writeFixture(cache, { files: { '/p/s.txt': { bytes: 'BBBBB', modifiedUs: 200 } } });
    await sleep(60);
    await waitFor(() => { engine.requestContent(H, P, '/p/s.txt'); return fs.readFileSync(r.file, 'utf8') === 'BBBBB'; },
      { timeout: 5000 });
  } finally { engine.stop(); }
});

test('upstream deletion on revalidation drops the cache file', async () => {
  const { cache, engine } = setup({ files: { '/p/d.txt': { bytes: 'gone soon', modifiedUs: 1 } } },
    { validateTtlMs: 40 });
  try {
    const r = await waitState(engine, H, P, '/p/d.txt', State.READY);
    writeFixture(cache, { files: { '/p/d.txt': { statError: 'FILE_NOT_FOUND' } } });
    await sleep(60);
    await waitState(engine, H, P, '/p/d.txt', State.FAILED, { timeout: 5000 });
    assert.ok(!fs.existsSync(r.file), 'cache file removed (consistent with origin)');
  } finally { engine.stop(); }
});

test('self-heal: a cache file deleted out from under the engine is re-fetched', async () => {
  const { engine } = setup({ files: { '/p/h.txt': { bytes: 'healme', modifiedUs: 5 } } });
  try {
    const r = await waitState(engine, H, P, '/p/h.txt', State.READY);
    fs.unlinkSync(r.file);
    assert.notEqual(engine.requestContent(H, P, '/p/h.txt').state, State.READY);
    const r2 = await waitState(engine, H, P, '/p/h.txt', State.READY);
    assert.equal(fs.readFileSync(r2.file, 'utf8'), 'healme');
  } finally { engine.stop(); }
});

test('recovery: a fresh engine serves the on-disk cache instantly, no refetch', async () => {
  const cache = tmpDir();
  const fx = writeFixture(cache, { files: { '/p/keep.txt': { bytes: 'persist me', modifiedUs: 7 } } });
  const e1 = makeEngine(cache, fx);
  let file;
  try { file = (await waitState(e1, H, P, '/p/keep.txt', State.READY)).file; } finally { e1.stop(); }
  const e2 = makeEngine(cache, fx);
  try {
    assert.equal(e2.requestContent(H, P, '/p/keep.txt').state, State.READY);   // on disk -> instant
    assert.equal(fs.readFileSync(file, 'utf8'), 'persist me');
  } finally { e2.stop(); }
});

test('content is stored under the readable per-host tree (no hashes)', async () => {
  const { cache, engine } = setup({ files: { '/s/welcome/index.html': { bytes: '<h1>hi</h1>', modifiedUs: 1 } } });
  try {
    await waitState(engine, H, P, '/s/welcome/index.html', State.READY);
    assert.ok(fs.existsSync(cpath(cache, 's', 'welcome', 'index.html')));
    assert.deepEqual(fs.readdirSync(cpath(cache, 's')), ['welcome']);
  } finally { engine.stop(); }
});

test('path traversal is refused, never escapes the cache dir', async () => {
  const { cache, engine } = setup({ files: {} });
  try {
    const s = engine.requestContent(H, P, '/p/../../../../etc/passwd');
    assert.equal(s.state, State.FAILED);
    assert.equal(s.errKind, 'badname');
    assert.ok(!fs.existsSync(path.join(cache, 'etc')));
  } finally { engine.stop(); }
});

test('IP-literal hosts are rejected — DNS names only', async () => {
  const { cache, engine } = setup({ files: { '/p/a.txt': { bytes: 'x', modifiedUs: 1 } } });
  try {
    for (const ip of ['1.2.3.4', '127.0.0.1', '2001:db8::1']) {
      const s = engine.requestContent(ip, P, '/p/a.txt');
      assert.equal(s.state, State.FAILED, `${ip} rejected`);
      assert.equal(s.errKind, 'badname');
    }
    await waitState(engine, 'ok.example', P, '/p/a.txt', State.READY);
    assert.ok(!fs.existsSync(path.join(cache, '1.2.3.4')));
  } finally { engine.stop(); }
});

test('a file<->directory type change invalidates the stale cached node', async () => {
  const { cache, engine } = setup({ files: { '/p/a': { bytes: 'iamfile', modifiedUs: 1 } } });
  try {
    const r1 = await waitState(engine, H, P, '/p/a', State.READY);
    assert.equal(fs.readFileSync(r1.file, 'utf8'), 'iamfile');
    assert.ok(fs.statSync(cpath(cache, 'p', 'a')).isFile());

    writeFixture(cache, { files: { '/p/a/b': { bytes: 'iamchild', modifiedUs: 2 } } });
    const r2 = await waitState(engine, H, P, '/p/a/b', State.READY);
    assert.equal(fs.readFileSync(r2.file, 'utf8'), 'iamchild');
    assert.ok(fs.statSync(cpath(cache, 'p', 'a')).isDirectory(), 'stale file replaced by a dir');

    writeFixture(cache, { files: { '/p/a': { bytes: 'fileagain', modifiedUs: 3 } } });
    const r3 = await waitState(engine, H, P, '/p/a', State.READY);
    assert.equal(fs.readFileSync(r3.file, 'utf8'), 'fileagain');
    assert.ok(fs.statSync(cpath(cache, 'p', 'a')).isFile(), 'stale dir replaced by a file');
  } finally { engine.stop(); }
});

test('metrics: hits and misses track cache serves vs fetches', async () => {
  const { engine } = setup({ files: { '/p/m.txt': { bytes: 'metric me', modifiedUs: 1 } } });
  try {
    await waitState(engine, H, P, '/p/m.txt', State.READY);   // miss
    await waitState(engine, H, P, '/p/m.txt', State.READY);   // hit
    const s = engine.stats();
    assert.equal(s.misses, 1);
    assert.ok(s.hits >= 1);
  } finally { engine.stop(); }
});

test('resolve cache is bounded (LRU cap); evicting it is safe (re-resolve)', async () => {
  const { engine } = setup({
    ping: { serverKey: 'ef'.repeat(32), rpcPort: 40000 },
    files: { '/p/b.txt': { bytes: 'bounded', modifiedUs: 1 } },
  }, { maxResolveEntries: 3 });
  try {
    for (let i = 0; i < 10; i++) await waitState(engine, `h${i}.example`, P, '/p/b.txt', State.READY);
    assert.ok(engine.stats().resolveEntries <= 3, `capped, got ${engine.stats().resolveEntries}`);
    assert.equal(fs.readFileSync((await waitState(engine, 'h0.example', P, '/p/b.txt', State.READY)).file, 'utf8'), 'bounded');
  } finally { engine.stop(); }
});

test('status items lists live/in-flight entries only', async () => {
  const files = { '/p/slow.bin': { size: 200_000, fill: 'drip', dripBytes: 20_000, dripMs: 50 } };
  for (let i = 0; i < 3; i++) files[`/p/r${i}.txt`] = { bytes: 'xxxxxxxxxx', modifiedUs: 1 };
  const { engine } = setup({ files });
  try {
    for (let i = 0; i < 3; i++) await waitState(engine, H, P, `/p/r${i}.txt`, State.READY);
    await waitFor(() => {
      const st = engine.requestContent(H, P, '/p/slow.bin').state;
      return st === State.DOWNLOADING || st === State.QUEUED;
    });
    const s = engine.stats();
    assert.ok(s.items.length <= 1, 'only the live fetch is listed');
    assert.ok(s.items.every((i) => i.state !== 'ready'));
    assert.ok(s.items.some((i) => i.cesPath === '/p/slow.bin'));
  } finally { engine.stop(); }
});
