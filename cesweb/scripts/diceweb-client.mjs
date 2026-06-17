// Browser simulator for the diceweb e2e. Signs the CesPlex bind + ATTACH itself
// (via cessign — the exact crypto the browser's WebCrypto path produces) and
// drives the relay protocol: hello{pubkey,time,bindSig} → token → attachSig →
// ready → raw. The private key is NEVER sent to cesweb. Then it reads dice's
// house from the greeting, bets via cesh, and plays — a full round whose
// signatures a real CES server cryptographically verifies.
// Env: WS_PORT WS_PID WS_KEY CESH WALLET CES_PORT. Global WebSocket (Node ≥ 21).
import { spawn } from 'node:child_process';
import { pubkeyHex, signBind, signAttach } from '../src/cessign.js';

const { WS_PORT, WS_PID, WS_KEY, CESH, WALLET, CES_PORT } = process.env;
const ws = new WebSocket(`ws://127.0.0.1:${WS_PORT}/dev/dial`);
ws.binaryType = 'arraybuffer';
let prog = '';
const dec = new TextDecoder(), enc = new TextEncoder();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const waitFor = async (re, ms = 8000) => {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { const m = prog.match(re); if (m) return m; await sleep(100); }
  throw new Error('timeout waiting for ' + re);
};
const cesh = (...args) => new Promise((res, rej) => {
  const c = spawn(CESH, ['-r', WALLET, '--server', `localhost:${CES_PORT}`, '-a', '@0', ...args], { stdio: 'inherit' });
  c.on('close', (code) => code === 0 ? res() : rej(new Error('cesh ' + args[0] + ' rc=' + code)));
  c.on('error', rej);
});

ws.onmessage = async (ev) => {
  if (typeof ev.data === 'string') {
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    if (m.t === 'token') { ws.send(JSON.stringify({ t: 'attachSig', sig: signAttach(WS_KEY, Number(WS_PID), m.token) })); return; }
    if (m.t === 'ready') { runRound(); return; }
    if (m._cesweb) console.error('[ctrl]', m._cesweb);
    return;
  }
  const t = dec.decode(ev.data); prog += t; process.stdout.write(t);
};
ws.onopen = () => {
  const time = Date.now() * 1000;
  ws.send(JSON.stringify({ t: 'hello', pubkey: pubkeyHex(WS_KEY), time,
    bindSig: signBind(WS_KEY, '/ces/lua/1', time),
    host: 'localhost', cesPort: Number(CES_PORT), pid: String(WS_PID) }));
};
async function runRound() {
  try {
    const m = await waitFor(/house pubkey:\s*([0-9a-f]{64})/i);
    console.error('[client] dice house =', m[1]);
    await cesh('transfer', m[1], '100');
    await sleep(400);
    ws.send(enc.encode('play\n'));
    await waitFor(/heads|tails|won|win|lost|lose|paid|no pending/i, 8000);
    await sleep(600);
  } catch (e) { console.error('[client]', e.message); }
  ws.close();
}
ws.onclose = () => {
  const played = /heads|tails|won|win|lost|lose|paid/i.test(prog);
  console.error(`\n[diceweb] a round resolved over the web: ${played}`);
  process.exit(played ? 0 : 2);
};
ws.onerror = (e) => { console.error('[diceweb] ws error', e?.message || e); process.exit(3); };
