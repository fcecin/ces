// Engine = the content state machine. These tests drive it directly against the
// fake cesh and assert the states it walks through and the cache it maintains.
// Run with: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { State } from '../src/engine.js';
import { tmpDir, writeFixture, makeEngine, waitState, waitFor, sleep } from './util.mjs';

const H = 'localhost', P = 53830;

function setup(fixture, opts) {
  const cache = tmpDir();
  const fx = writeFixture(cache, fixture);
  const engine = makeEngine(cache, fx, opts);
  return { cache, fx, engine };
}

test('fetch: resolving → ready, with correct cached bytes', async () => {
  const { engine } = setup({ files: { '/p/a.txt': { bytes: 'hello world', modifiedUs: 100 } } });
  try {
    const first = engine.requestContent(H, P, '/p/a.txt');
    assert.equal(first.state, State.RESOLVING);                 // returns immediately, not blocking
    const ready = await waitState(engine, H, P, '/p/a.txt', State.READY);
    assert.equal(ready.size, 11);
    assert.equal(fs.readFileSync(ready.file, 'utf8'), 'hello world');
    assert.equal(engine.totalBytes, 11);
  } finally { engine.stop(); }
});

test('missing file → FAILED notfound', async () => {
  const { engine } = setup({ files: { '/p/gone.txt': { statError: 'FILE_NOT_FOUND' } } });
  try {
    const s = await waitState(engine, H, P, '/p/gone.txt', State.FAILED);
    assert.equal(s.errKind, 'notfound');
  } finally { engine.stop(); }
});

test('payment failure on read → FAILED poor', async () => {
  const { engine } = setup({ files: { '/p/x.bin': { size: 50, getError: 'INSUFFICIENT_BALANCE' } } });
  try {
    const s = await waitState(engine, H, P, '/p/x.bin', State.FAILED);
    assert.equal(s.errKind, 'poor');
  } finally { engine.stop(); }
});

test('oversize file is rejected at STAT (no download) → FAILED toobig', async () => {
  const { engine } = setup({ files: { '/p/huge.bin': { size: 10_000 } } }, { maxFileBytes: 1000 });
  try {
    const s = await waitState(engine, H, P, '/p/huge.bin', State.FAILED);
    assert.equal(s.errKind, 'toobig');
    assert.equal(engine.totalBytes, 0);
  } finally { engine.stop(); }
});

test('unreachable host → FAILED unreachable', async () => {
  const { engine } = setup({ ping: { fail: true }, files: {} });
  try {
    const s = await waitState(engine, H, P, '/p/a.txt', State.FAILED);
    assert.equal(s.errKind, 'unreachable');
  } finally { engine.stop(); }
});

test('slow download exposes live DOWNLOADING progress, then READY', async () => {
  const size = 400_000;
  const { engine } = setup({
    files: { '/p/slow.bin': { size, fill: 'drip', dripBytes: 50_000, dripMs: 50 } },
  });
  try {
    // Catch it mid-flight with a partial byte count below the full size.
    const mid = await waitFor(() => {
      const s = engine.requestContent(H, P, '/p/slow.bin');
      return (s.state === State.DOWNLOADING && s.gotBytes > 0 && s.gotBytes < size) ? s : false;
    });
    assert.equal(mid.wantSize, size);
    const ready = await waitState(engine, H, P, '/p/slow.bin', State.READY, { timeout: 8000 });
    assert.equal(ready.size, size);
  } finally { engine.stop(); }
});

test('stalled download is reaped → FAILED', async () => {
  const { engine } = setup(
    { files: { '/p/hang.bin': { size: 500_000, fill: 'stall' } } },
    { stallTimeoutMs: 200, progressIntervalMs: 40 },
  );
  try {
    const s = await waitState(engine, H, P, '/p/hang.bin', State.FAILED, { timeout: 5000 });
    assert.ok(s.errKind);                       // killed child → non-zero exit → failed
  } finally { engine.stop(); }
});

test('inflight cap queues extra downloads (QUEUED visible)', async () => {
  const { engine } = setup({
    files: {
      '/p/d1.bin': { size: 300_000, fill: 'drip', dripBytes: 30_000, dripMs: 60 },
      '/p/d2.bin': { size: 300_000, fill: 'drip', dripBytes: 30_000, dripMs: 60 },
    },
  }, { maxInflight: 1 });
  try {
    engine.requestContent(H, P, '/p/d1.bin');
    engine.requestContent(H, P, '/p/d2.bin');
    // With one slot, exactly one downloads while the other waits — assert that
    // *a* file is QUEUED (which one wins the slot is a race).
    await waitFor(() => engine.stats().items.some((i) => i.state === State.QUEUED));
    await waitState(engine, H, P, '/p/d1.bin', State.READY, { timeout: 8000 });
    await waitState(engine, H, P, '/p/d2.bin', State.READY, { timeout: 8000 });
  } finally { engine.stop(); }
});

test('eviction: cap enforced, least-recent evicted, newest survives', async () => {
  // cap 300k, low-water 90% (270k). Three 200k files can't coexist.
  const mk = (n) => ({ [`/p/f${n}.bin`]: { size: 200_000 } });
  const { engine } = setup({ files: { ...mk(1), ...mk(2), ...mk(3) } },
    { maxCacheBytes: 300_000, lowWaterPct: 90 });
  try {
    await waitState(engine, H, P, '/p/f1.bin', State.READY);
    await waitState(engine, H, P, '/p/f2.bin', State.READY);
    await waitState(engine, H, P, '/p/f3.bin', State.READY);
    assert.ok(engine.totalBytes <= 300_000, `total ${engine.totalBytes}`);
    const items = engine.stats().items.map((i) => i.cesPath);
    assert.ok(items.includes('/p/f3.bin'), 'newest survives');
    assert.ok(!items.includes('/p/f1.bin'), 'oldest evicted');
  } finally { engine.stop(); }
});

test('revalidation refills changed content while staying READY (serves old until swap)', async () => {
  const { cache, fx, engine } = setup(
    { files: { '/p/c.txt': { bytes: 'AAAAA', modifiedUs: 100 } } },
    { validateTtlMs: 40 },
  );
  try {
    const r1 = await waitState(engine, H, P, '/p/c.txt', State.READY);
    assert.equal(fs.readFileSync(r1.file, 'utf8'), 'AAAAA');

    // Origin changes; fake cesh reads the fixture fresh on its next call.
    writeFixture(cache, { files: { '/p/c.txt': { bytes: 'BBBBBBBBBB', modifiedUs: 200 } } });
    await sleep(60);                            // let the validate TTL lapse

    // It must NEVER drop out of READY during the background refill.
    let everNotReady = false;
    await waitFor(() => {
      const s = engine.requestContent(H, P, '/p/c.txt');
      if (s.state !== State.READY) everNotReady = true;
      return fs.readFileSync(r1.file, 'utf8') === 'BBBBBBBBBB';
    }, { timeout: 5000 });
    assert.equal(everNotReady, false, 'stayed READY throughout refill');
    assert.equal(engine.totalBytes, 10);
  } finally { engine.stop(); }
});

test('upstream deletion on revalidation evicts the cache (consistent with origin)', async () => {
  const { cache, engine } = setup(
    { files: { '/p/d.txt': { bytes: 'gone soon', modifiedUs: 1 } } },
    { validateTtlMs: 40 },
  );
  try {
    await waitState(engine, H, P, '/p/d.txt', State.READY);
    writeFixture(cache, { files: { '/p/d.txt': { statError: 'FILE_NOT_FOUND' } } });
    await sleep(60);
    // Next request triggers revalidation; the entry is dropped, so it re-drives
    // and lands on a real 404.
    await waitState(engine, H, P, '/p/d.txt', State.FAILED, { timeout: 5000 });
    assert.equal(engine.totalBytes, 0);
  } finally { engine.stop(); }
});

test('self-heal: a cache file deleted out from under the engine is re-fetched', async () => {
  const { engine } = setup({ files: { '/p/h.txt': { bytes: 'healme', modifiedUs: 5 } } });
  try {
    const r = await waitState(engine, H, P, '/p/h.txt', State.READY);
    fs.unlinkSync(r.file);                          // yank the cache file (operator rm / disk loss)
    const after = engine.requestContent(H, P, '/p/h.txt');
    assert.notEqual(after.state, State.READY);      // notices the hole, re-drives instead of serving it
    const r2 = await waitState(engine, H, P, '/p/h.txt', State.READY);
    assert.equal(fs.readFileSync(r2.file, 'utf8'), 'healme');
    assert.equal(engine.totalBytes, 6);
  } finally { engine.stop(); }
});

test('recovery: a fresh engine reloads the cache from disk', async () => {
  const cache = tmpDir();
  const fx = writeFixture(cache, { files: { '/p/keep.txt': { bytes: 'persist me', modifiedUs: 7 } } });
  const e1 = makeEngine(cache, fx);
  let file;
  try {
    const r = await waitState(e1, H, P, '/p/keep.txt', State.READY);
    file = r.file;
  } finally { e1.stop(); }

  // Orphan a part-file to prove recovery sweeps it.
  fs.writeFileSync(path.join(cache, 'deadbeef.part'), 'junk');

  const e2 = makeEngine(cache, fx);
  try {
    assert.equal(e2.totalBytes, 10);
    const s = e2.requestContent(H, P, '/p/keep.txt');
    assert.equal(s.state, State.READY);         // immediately serveable, no refetch
    assert.equal(fs.readFileSync(file, 'utf8'), 'persist me');
    assert.ok(!fs.existsSync(path.join(cache, 'deadbeef.part')), 'orphan part swept');
  } finally { e2.stop(); }
});
