// Web terminal: black-box test of the relay. The browser signs (here the test
// client signs, via cessign — same crypto); cesweb only relays signatures into
// `cesh dial --extsign` (the fake cesh runs the handshake but doesn't verify
// sigs — cessign.test + the dice e2e validate the crypto). Run with: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { WebSocket } from 'ws';
import { pubkeyHex, signBind, signAttach } from '../src/cessign.js';
import { tmpDir, writeFixture, SERVER, FAKECESH, waitFor } from './util.mjs';

const KEY = '00' + 'cd'.repeat(32);   // ed25519 decorated private key
const PID = '123';

function startServer(extraEnv = {}) {
  const cache = tmpDir();
  const fx = writeFixture(cache, {
    ping: { rpcPort: 40000, serverKey: 'ab'.repeat(32) },
    dial: { greeting: 'DICE READY' },
  });
  const child = spawn('node', [SERVER], { env: {
    ...process.env, FAKECESH_FIXTURE: fx,
    CESWEB_PORT: '0', CESWEB_BIND: '127.0.0.1', CESWEB_CESH: FAKECESH,
    CESWEB_CACHE_DIR: cache, CESWEB_DEFAULT_HOST: 'localhost',
    CESWEB_DEFAULT_CES_PORT: '53830', CESWEB_ALLOW_HOSTS: 'localhost',
    CESWEB_ALLOW_PRIVATE_HOSTS: '1',   // the harness dials localhost
    ...extraEnv,
  } });
  const port = new Promise((res, rej) => {
    let buf = '';
    const to = setTimeout(() => rej(new Error('server did not start: ' + buf)), 5000);
    child.stderr.on('data', (d) => {
      buf += d.toString();
      const m = buf.match(/http:\/\/127\.0\.0\.1:(\d+)/);
      if (m) { clearTimeout(to); res(parseInt(m[1], 10)); }
    });
  });
  return { child, port, stop: () => { try { child.kill('SIGKILL'); } catch {} } };
}

// A client that drives the browser side: signs the bind on open (sending the
// target server + pid in the hello frame), signs ATTACH when the token comes
// back, records program bytes (binary) + control (text).
function connect(port, { key = KEY, pid = PID, host = 'localhost', cesPort = 53830 } = {}) {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/dev/dial`);
  const ctrl = [], prog = [];
  let resolveReady, rejectReady;
  const readyP = new Promise((res, rej) => { resolveReady = res; rejectReady = rej; });
  ws.on('open', () => {
    const time = Date.now() * 1000;
    ws.send(JSON.stringify({ t: 'hello', pubkey: pubkeyHex(key), time,
      bindSig: signBind(key, '/ces/lua/1', time), host, cesPort, pid: String(pid) }));
  });
  ws.on('message', (data, isBinary) => {
    if (isBinary) { prog.push(data.toString('utf8')); return; }
    let m; try { m = JSON.parse(data.toString('utf8')); } catch { return; }
    if (m.t === 'token') { ws.send(JSON.stringify({ t: 'attachSig', sig: signAttach(key, Number(pid), m.token) })); return; }
    if (m.t === 'ready') { resolveReady(); return; }
    ctrl.push(m);
    if (m._end) rejectReady(new Error(m._cesweb || 'ended'));
  });
  ws.on('error', (e) => rejectReady(e));
  return {
    ws, ctrl, prog, readyP,
    sendLine: (l) => ws.send(Buffer.from(l + '\n')),   // terminal input = binary frame
    progText: () => prog.join(''),
  };
}

test('browser signs → relay → greeting → echo (the dice-via-web path)', async () => {
  const srv = startServer();
  const port = await srv.port;
  try {
    const c = connect(port);
    await c.readyP;                                              // hello → token → attachSig → ready
    await waitFor(() => c.progText().includes('DICE READY'));    // program greeting
    c.sendLine('hello');
    await waitFor(() => c.progText().includes('echo: hello'));   // round-trip through cesh
    c.ws.close();
  } finally { srv.stop(); }
});

test('a malformed first frame is rejected', async () => {
  const srv = startServer();
  const port = await srv.port;
  try {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/dev/dial`);
    const ended = await new Promise((res) => {
      ws.on('open', () => ws.send('not json'));
      ws.on('message', (d, bin) => { if (!bin) { try { const m = JSON.parse(d.toString()); if (m._end) res(m._cesweb); } catch {} } });
      ws.on('close', () => res('closed'));
    });
    assert.ok(ended);   // ended with a reason, no crash
  } finally { srv.stop(); }
});

test('pool cap rejects beyond the limit', async () => {
  const srv = startServer({ CESWEB_MAX_TERMINALS: '1' });
  const port = await srv.port;
  try {
    const a = connect(port);
    await a.readyP;                                  // a holds the only slot
    const b = new WebSocket(`ws://127.0.0.1:${port}/dev/dial`);
    const reason = await new Promise((res) => {
      b.on('message', (d, bin) => { if (!bin) { try { const m = JSON.parse(d.toString()); if (m._end) res(m._cesweb); } catch {} } });
      b.on('close', () => res('closed'));
    });
    assert.match(reason, /full/);
    a.ws.close(); b.close();
  } finally { srv.stop(); }
});

test('a disallowed host (named in the hello frame) is rejected', async () => {
  const srv = startServer();
  const port = await srv.port;
  try {
    // The target server is in the hello frame now, so the allow-check happens
    // there: the upgrade succeeds, then the disallowed host is refused.
    const c = connect(port, { host: 'evil.com' });
    const reason = await c.readyP.then(() => null, (e) => e.message);
    assert.match(reason || '', /not allowed/);
  } finally { srv.stop(); }
});
