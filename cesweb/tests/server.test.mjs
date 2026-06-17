// Black-box test of the HTTP responder: spawn the real src/server.js as a
// subprocess wired to the fake cesh, and drive it over HTTP. Proves the wiring
// end to end — sitrep-then-content, Range serving, the status endpoint, and the
// error mappings (404 / 402 / 403 / 400). Run with: node --test

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
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

test('cold request returns a sitrep, then the real content after refresh', async () => {
  const first = await get('/p/a.txt');
  assert.equal(first.status, 200);
  assert.match(first.ct, /text\/html/);          // a progress/sitrep page, not the file yet
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

test('status endpoint reports engine state as JSON', async () => {
  const r = await get('/__cesweb/status');
  assert.equal(r.status, 200);
  assert.match(r.ct, /application\/json/);
  const j = JSON.parse(r.body);
  assert.ok(Array.isArray(j.items));
  assert.ok(j.items.some((i) => i.cesPath === '/p/a.txt'));
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
