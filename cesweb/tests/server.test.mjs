// Black-box test of the HTTP responder: spawn the real src/server.js as a
// subprocess wired to the fake cesh, and drive it over HTTP. Proves the wiring
// end to end — sitrep-then-content, Range serving, the status endpoint, and the
// error mappings (404 / 402 / 403 / 400). Run with: node --test

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { tmpDir, writeFixture, SERVER, FAKECESH, sleep } from './util.mjs';

let child, base;

before(async () => {
  const cache = tmpDir();
  const fx = writeFixture(cache, {
    ping: { rpcPort: 40000, serverKey: 'ab'.repeat(32) },
    files: {
      '/p/a.txt': { bytes: 'hello world', modifiedUs: 100 },
      '/p/gone.txt': { statError: 'FILE_NOT_FOUND' },
      '/p/poor.bin': { size: 50, getError: 'INSUFFICIENT_BALANCE' },
    },
  });
  child = spawn('node', [SERVER], {
    env: {
      ...process.env,
      FAKECESH_FIXTURE: fx,
      CESWEB_PORT: '0',                 // OS-assigned; we read it back from the log
      CESWEB_BIND: '127.0.0.1',
      CESWEB_CESH: FAKECESH,
      CESWEB_CACHE_DIR: cache,
      CESWEB_DEFAULT_HOST: 'localhost',
      CESWEB_DEFAULT_CES_PORT: '53830',
      CESWEB_ALLOW_HOSTS: 'localhost',
      CESWEB_ALLOW_PRIVATE_HOSTS: '1',   // the harness talks to localhost
    },
  });
  const port = await new Promise((resolve, reject) => {
    let buf = '';
    const to = setTimeout(() => reject(new Error('server did not start: ' + buf)), 5000);
    child.stderr.on('data', (d) => {
      buf += d.toString();
      const m = buf.match(/http:\/\/127\.0\.0\.1:(\d+)/);
      if (m) { clearTimeout(to); resolve(parseInt(m[1], 10)); }
    });
  });
  base = `http://127.0.0.1:${port}`;
});

after(() => { if (child) child.kill('SIGKILL'); });

async function get(p, headers) {
  const r = await fetch(base + p, { headers });
  return {
    status: r.status,
    ct: r.headers.get('content-type') || '',
    cr: r.headers.get('content-range'),
    ar: r.headers.get('accept-ranges'),
    body: await r.text(),
  };
}
async function poll(p, until, { timeout = 8000, interval = 50 } = {}) {
  const t0 = Date.now();
  for (;;) {
    const r = await get(p);
    if (until(r)) return r;
    if (Date.now() - t0 > timeout) throw new Error('poll timeout: ' + JSON.stringify(r).slice(0, 200));
    await sleep(interval);
  }
}

test('cold request shows the resolving page (10s client countdown, no stale bytes), then content', async () => {
  const first = await get('/p/a.txt');                 // first hit: host not yet resolved
  assert.equal(first.status, 200);
  assert.match(first.ct, /text\/html/);                // a page, not the file yet
  assert.match(first.body, /Resolving cache entry/);   // the resolving page
  assert.match(first.body, /id=cesweb-cd>10</);        // client-side 10s countdown element
  assert.match(first.body, /location\.reload/);        // retries client-side, not a meta-refresh
  assert.doesNotMatch(first.body, /hello world/);      // never serves stale/partial content
  const ready = await poll('/p/a.txt', (r) => r.ct.includes('text/plain'));
  assert.equal(ready.body, 'hello world');
});

test('warm file serves a byte range (206)', async () => {
  await poll('/p/a.txt', (r) => r.ct.includes('text/plain'));   // ensure warm
  const r = await get('/p/a.txt', { Range: 'bytes=0-4' });
  assert.equal(r.status, 206);
  assert.equal(r.cr, 'bytes 0-4/11');
  assert.equal(r.ar, 'bytes');
  assert.equal(r.body, 'hello');
});

test('status endpoint reports engine state as JSON (at /status)', async () => {
  const r = await get('/status');
  assert.equal(r.status, 200);
  assert.match(r.ct, /application\/json/);
  const j = JSON.parse(r.body);
  assert.ok(Array.isArray(j.items));                          // live-only; cache itself is not enumerated
  assert.ok(typeof j.freeBytes === 'number' && typeof j.hits === 'number');
  const old = await get('/__cesweb/status');     // moved off the old gateway-internal prefix
  assert.notEqual(old.status, 200);
});

test('missing file → 404', async () => {
  const r = await poll('/p/gone.txt', (x) => x.status === 404);
  assert.equal(r.status, 404);
});

test('out-of-credits → 402', async () => {
  const r = await poll('/p/poor.bin', (x) => x.status === 402);
  assert.equal(r.status, 402);
});

test('disallowed host → 403', async () => {
  const r = await get('/evil.com/p/a.txt');
  assert.equal(r.status, 403);
});

test('non-zone path → 400', async () => {
  const r = await get('/localhost/notazone');
  assert.equal(r.status, 400);
});

// The open `/<ces-host>/<path>` form (a browser pointing the gateway at a CES
// server named in the URL), with NO allowlist — proves the feature end to end:
// a DNS-named server is fetched + served; an IP host is refused at the engine
// (400 badname), not merely by an allowlist.
test('open form: a DNS-named CES host is served; an IP host is refused (400)', async () => {
  const cache = tmpDir();
  const fx = writeFixture(cache, {
    ping: { rpcPort: 40000, serverKey: 'ab'.repeat(32) },
    files: { '/p/a.txt': { bytes: 'open world', modifiedUs: 1 } },
  });
  const child2 = spawn('node', [SERVER], {
    env: {
      ...process.env, FAKECESH_FIXTURE: fx, CESWEB_PORT: '0', CESWEB_BIND: '127.0.0.1',
      CESWEB_CESH: FAKECESH, CESWEB_CACHE_DIR: cache,
      CESWEB_ALLOW_HOSTS: '',               // OPEN: any host the URL names
      CESWEB_ALLOW_PRIVATE_HOSTS: '1',      // the fake cesh stands in for resolution
    },
  });
  const port2 = await new Promise((resolve, reject) => {
    let buf = ''; const to = setTimeout(() => reject(new Error('no start: ' + buf)), 5000);
    child2.stderr.on('data', (d) => { buf += d.toString(); const m = buf.match(/http:\/\/127\.0\.0\.1:(\d+)/); if (m) { clearTimeout(to); resolve(parseInt(m[1], 10)); } });
  });
  const b2 = `http://127.0.0.1:${port2}`;
  const g2 = async (p) => { const r = await fetch(b2 + p); return { status: r.status, ct: r.headers.get('content-type') || '', body: await r.text() }; };
  try {
    const ready = await (async () => {
      const t0 = Date.now();
      for (;;) { const r = await g2('/ok.example/p/a.txt'); if (r.ct.includes('text/plain')) return r; if (Date.now() - t0 > 8000) throw new Error('timeout ' + JSON.stringify(r).slice(0, 120)); await sleep(50); }
    })();
    assert.equal(ready.body, 'open world');                       // DNS-named open fetch works
    assert.ok(fs.existsSync(path.join(cache, 'ok.example', 'p', 'a.txt')), 'cached under the DNS-named tree');
    const ip = await g2('/1.2.3.4/p/a.txt');                      // IP host refused at the engine, not an allowlist
    assert.equal(ip.status, 400);
  } finally { child2.kill('SIGKILL'); }
});
