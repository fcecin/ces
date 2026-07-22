// Interactive test of the program WebSocket bridge (/i/... upgraded to WS):
// spawn a cesweb wired to a fake cesh that plays a WS echo program, connect a
// real WebSocket client through the gateway, and prove framed messages
// round-trip both ways AND that the handshake context (subpath + query) reaches
// the program. This is the interactive counterpart to the one-shot /i/ HTTP
// proxy test in server.test.mjs. Run with: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { WebSocket } from 'ws';
import { tmpDir, writeFixture, SERVER, FAKECESH, sleep } from './util.mjs';

async function startServer(fixture) {
  const cache = tmpDir();
  const fx = writeFixture(cache, fixture);
  const child = spawn('node', [SERVER], {
    env: {
      ...process.env, FAKECESH_FIXTURE: fx, CESWEB_PORT: '0', CESWEB_BIND: '127.0.0.1',
      CESWEB_CESH: FAKECESH, CESWEB_CACHE_DIR: cache,
      CESWEB_DEFAULT_HOST: 'localhost', CESWEB_DEFAULT_CES_PORT: '53830',
      CESWEB_ALLOW_HOSTS: 'localhost', CESWEB_ALLOW_PRIVATE_HOSTS: '1',
    },
  });
  const port = await new Promise((resolve, reject) => {
    let buf = ''; const to = setTimeout(() => reject(new Error('no start: ' + buf)), 5000);
    child.stderr.on('data', (d) => {
      buf += d.toString();
      const m = buf.match(/http:\/\/127\.0\.0\.1:(\d+)/);
      if (m) { clearTimeout(to); resolve(parseInt(m[1], 10)); }
    });
  });
  return { child, port };
}

async function until(pred, ms = 3000) {
  const t0 = Date.now();
  while (!pred()) { if (Date.now() - t0 > ms) return false; await sleep(20); }
  return true;
}

test('program websocket bridges framed messages both ways + handshake context', async () => {
  const { child, port } = await startServer({
    ping: { rpcPort: 40000, serverKey: 'ab'.repeat(32) },
    dial: { wsEcho: true },
  });
  try {
    const got = [];
    const ws = new WebSocket(`ws://127.0.0.1:${port}/i/localhost/12345/game?x=1`);
    await new Promise((res, rej) => { ws.on('open', res); ws.on('error', rej); });
    ws.on('message', (d) => got.push(d.toString()));

    // Frame 0 (the handshake) reached the program: it echoed the request-line,
    // proving the subpath + query survive the bridge.
    assert.ok(await until(() => got.some((m) => m.startsWith('hs:'))), 'no handshake echo: ' + JSON.stringify(got));
    assert.ok(got.includes('hs:GET /game?x=1 HTTP/1.1'), 'program saw subpath+query: ' + JSON.stringify(got));

    // Messages round-trip through the [u32 len][payload] framing, in order.
    ws.send('ping');
    ws.send('pong');
    assert.ok(await until(() => got.includes('echo:ping') && got.includes('echo:pong')),
      'no echoes: ' + JSON.stringify(got));

    ws.close();
  } finally { child.kill('SIGKILL'); }
});

test('program websocket on a disallowed host is refused (no upgrade)', async () => {
  const { child, port } = await startServer({
    ping: { rpcPort: 40000, serverKey: 'ab'.repeat(32) },
    dial: { wsEcho: true },
  });
  try {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/i/evil.com/12345/game`);
    const outcome = await new Promise((res) => {
      ws.on('open', () => res('open'));
      ws.on('error', () => res('error'));
      ws.on('close', () => res('close'));
    });
    assert.notEqual(outcome, 'open');   // allow-list destroys the socket pre-upgrade
  } finally { child.kill('SIGKILL'); }
});
