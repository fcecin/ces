// Web terminal: black-box test of the relay. The browser signs (here the test
// client signs, via cessign — same crypto); cesweb only relays signatures into
// `cesh dial --extsign` (the fake cesh runs the handshake but doesn't verify
// sigs — cessign.test + the dice e2e validate the crypto). Run with: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { WebSocket } from 'ws';
import { pubkeyHex, bindDigest, signBind, signAttach } from '../src/cessign.js';
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

// A client that drives the browser side: sends the target server + pid in the
// hello frame, signs the bind and the ATTACH when the server hello comes back,
// records program bytes (binary) + control (text). The fake cesh checks both
// signatures over the hello that it sent.
function connect(port, { key = KEY, pid = PID, host = 'localhost', cesPort = 53830 } = {}) {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/dev/dial`);
  const ctrl = [], prog = [];
  let resolveReady, rejectReady;
  const readyP = new Promise((res, rej) => { resolveReady = res; rejectReady = rej; });
  ws.on('open', () => {
    ws.send(JSON.stringify({ t: 'hello', pubkey: pubkeyHex(key), host, cesPort, pid: String(pid) }));
  });
  ws.on('message', (data, isBinary) => {
    if (isBinary) { prog.push(data.toString('utf8')); return; }
    let m; try { m = JSON.parse(data.toString('utf8')); } catch { return; }
    if (m.t === 'serverHello') {
      const time = Date.now() * 1000;
      const d = bindDigest('/ces/lua/1', time, pubkeyHex(key), m.serverKey, m.challenge);
      ws.send(JSON.stringify({ t: 'sigs', time,
        bindSig: signBind(key, '/ces/lua/1', time, m.serverKey, m.challenge),
        attachSig: signAttach(key, Number(pid), d) }));
      return;
    }
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
    await c.readyP;                                  // hello → serverHello → sigs → ready
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

test('the server hello reaches the browser with its challenge as a string', async () => {
  const srv = startServer();
  const port = await srv.port;
  try {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/dev/dial`);
    const hello = await new Promise((res, rej) => {
      ws.on('open', () => ws.send(JSON.stringify({ t: 'hello', pubkey: pubkeyHex(KEY),
        host: 'localhost', cesPort: 53830, pid: PID })));
      ws.on('message', (d, bin) => {
        if (bin) return;
        const m = JSON.parse(d.toString());
        if (m.t === 'serverHello') res(m);
        else if (m._end) rej(new Error(m._cesweb));
      });
    });
    assert.equal(hello.serverKey, 'ab'.repeat(32));
    assert.equal(hello.challenge, '9223372036854775809');   // above 2^53, intact
    ws.close();
  } finally { srv.stop(); }
});

test('signatures sent before the server hello are refused', async () => {
  const srv = startServer();
  const port = await srv.port;
  try {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/dev/dial`);
    const reason = await new Promise((res) => {
      ws.on('open', () => {
        ws.send(JSON.stringify({ t: 'hello', pubkey: pubkeyHex(KEY),
          host: 'localhost', cesPort: 53830, pid: PID }));
        ws.send(JSON.stringify({ t: 'sigs', time: Date.now() * 1000,
          bindSig: '00'.repeat(65), attachSig: '00'.repeat(65) }));
      });
      ws.on('message', (d, bin) => {
        if (bin) return;
        try { const m = JSON.parse(d.toString()); if (m._end) res(m._cesweb); } catch {}
      });
      ws.on('close', () => res('closed'));
    });
    assert.match(reason, /unexpected control frame/);
  } finally { srv.stop(); }
});

test('a bind signed for another challenge fails at cesh', async () => {
  const srv = startServer();
  const port = await srv.port;
  try {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/dev/dial`);
    const reason = await new Promise((res) => {
      ws.on('open', () => ws.send(JSON.stringify({ t: 'hello', pubkey: pubkeyHex(KEY),
        host: 'localhost', cesPort: 53830, pid: PID })));
      ws.on('message', (d, bin) => {
        if (bin) return;
        const m = JSON.parse(d.toString());
        if (m.t === 'serverHello') {
          const other = (BigInt(m.challenge) + 1n).toString();
          const time = Date.now() * 1000;
          const d = bindDigest('/ces/lua/1', time, pubkeyHex(KEY), m.serverKey, other);
          ws.send(JSON.stringify({ t: 'sigs', time,
            bindSig: signBind(KEY, '/ces/lua/1', time, m.serverKey, other),
            attachSig: signAttach(KEY, Number(PID), d) }));
        } else if (m._end) res(m._cesweb);
      });
    });
    assert.match(reason, /ERR bind|bind:/);
  } finally { srv.stop(); }
});
