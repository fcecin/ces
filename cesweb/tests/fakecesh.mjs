#!/usr/bin/env node
// A controllable stand-in for the `cesh` CLI in pipe mode (-q), used by the
// cesweb test harness. cesweb's engine is a content state machine that drives
// `cesh` as a child process; this fake lets a test script script that child's
// behavior deterministically — ping success/failure, stat results, download
// speed/stall/failure, upstream changes — WITHOUT a real CES server.
//
// Behavior is read fresh on every invocation from the JSON fixture at
// $FAKECESH_FIXTURE (each cesh call is its own process, so a test can rewrite
// the fixture between calls to simulate the origin changing). Fixture shape:
//
//   {
//     "ping": { "rpcPort": 40000, "serverKey": "<64hex>" }   // or { "fail": true }
//     "files": {
//       "/p/a.txt":     { "bytes": "hello", "modifiedUs": 100 },
//       "/p/gone.txt":  { "statError": "FILE_NOT_FOUND" },
//       "/p/poor.txt":  { "size": 5, "getError": "INSUFFICIENT_BALANCE" },
//       "/p/big.bin":   { "size": 1048576 },                  // generated 'a' bytes
//       "/p/slow.bin":  { "size": 524288, "fill": "drip", "dripBytes": 65536, "dripMs": 60 },
//       "/p/hang.bin":  { "size": 524288, "fill": "stall" }   // never finishes; engine kills it
//     }
//   }

import fs from 'node:fs';
import crypto from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bindDigest } from '../src/cessign.js';

const argv = process.argv.slice(2);
const fx = (() => {
  try { return JSON.parse(fs.readFileSync(process.env.FAKECESH_FIXTURE, 'utf8')); }
  catch { return {}; }
})();

function fail(name) { process.stderr.write((name || 'ERROR') + '\n'); process.exit(1); }
const sizeOf = (f) => (f.size != null ? f.size : (f.bytes != null ? Buffer.byteLength(f.bytes) : 0));
const bytesOf = (f) => (f.bytes != null ? Buffer.from(f.bytes) : Buffer.alloc(sizeOf(f), 0x61));

if (argv.includes('keys')) {                 // `keys list -p` -> <priv> (<pub>)
  const pub = (fx.ping && fx.ping.serverKey) || 'ab'.repeat(32);
  process.stdout.end('00' + 'cd'.repeat(32) + ' (' + pub + ')\n');
} else if (argv.includes('ping')) {
  if (fx.ping && fx.ping.fail) fail('UNREACHABLE');
  process.stdout.end(JSON.stringify({
    status: 'ok',
    serverPublicKey: (fx.ping && fx.ping.serverKey) || 'ab'.repeat(32),
    rpcPort: (fx.ping && fx.ping.rpcPort) || 40000,
  }));
} else if (argv.includes('dial')) {
  // Simulate `cesh dial <pid>` into a line-REPL Lua program (dice-like): emit a
  // greeting, then echo each input line. With --extsign, first run the control
  // handshake (HELLO, then BIND and ATTACH → READY) — sigs are not verified
  // here; this is a stand-in. The fixture's `dial` block can tweak the greeting
  // or force a fail.
  const pid = argv[argv.indexOf('dial') + 1] || '?';
  const d = fx.dial || {};
  if (d.fail) fail(d.fail === true ? 'COMPUTE_INSTANCE_NOT_FOUND' : d.fail);
  if (d.http != null) {
    // HTTP web-server program stand-in: consume the request, answer once, then
    // close (Connection: close -> the dialer sees EOF). Mirrors a Lua program
    // that frames HTTP over ces.conn. No --extsign control lines on this path
    // (the gateway's /i/ route dials on its own wallet, not the user's key).
    let answered = false, rbuf = '';
    const answer = () => {
      if (answered) return; answered = true;
      const respond = () => { process.stdout.write(d.http); process.stdout.end(() => process.exit(0)); };
      if (d.httpDelayMs) setTimeout(respond, d.httpDelayMs); else respond();
    };
    process.stdin.on('data', (c) => { rbuf += c.toString('latin1'); if (rbuf.includes('\r\n\r\n')) answer(); });
    process.stdin.on('end', answer);
  } else if (d.wsEcho) {
    // WebSocket program stand-in: read [u32 len][payload] frames off the CesPlex
    // stream; frame 0 is the handshake (reply hs:<request-line>), then echo each
    // message as echo:<msg>. Proves framing + handshake context + round-trip.
    let rx = Buffer.alloc(0), gotHs = false;
    const send = (str) => {
      const p = Buffer.from(str, 'utf8'); const h = Buffer.allocUnsafe(4);
      h.writeUInt32BE(p.length, 0); process.stdout.write(Buffer.concat([h, p]));
    };
    process.stdin.on('data', (c) => {
      rx = Buffer.concat([rx, c]);
      for (;;) {
        if (rx.length < 4) break;
        const len = rx.readUInt32BE(0);
        if (rx.length < 4 + len) break;
        const payload = rx.subarray(4, 4 + len).toString('utf8');
        rx = rx.subarray(4 + len);
        if (!gotHs) { gotHs = true; send('hs:' + payload.split('\r\n')[0]); }
        else send('echo:' + payload);
      }
    });
    process.stdin.on('end', () => process.exit(0));
  } else {
    const extsign = argv.includes('--extsign');
    const greet = () => process.stdout.write((d.greeting || `fakecesh dial pid=${pid} ready`) + '\n');
    let state = extsign ? 'bind' : 'repl';
    // The server hello. Its challenge is above 2^53, so a relay that turns it
    // into a Number breaks the signatures, and the checks below fail.
    const SERVER_KEY = 'ab'.repeat(32), CHALLENGE = 9223372036854775809n;
    const clientPub = argv[argv.indexOf('--pubkey') + 1] || '';
    // Check an ed25519 signature (65 hex bytes, tag 0x00) as the server does.
    const sigOk = (sigHex, digest) => {
      const sig = Buffer.from(sigHex || '', 'hex');
      return sig.length === 65 && sig[0] === 0x00 &&
        ed25519.verify(sig.subarray(1), digest, Buffer.from(clientPub, 'hex'));
    };
    if (!extsign) greet();
    else process.stdout.write(`HELLO ${SERVER_KEY} ${CHALLENGE}\n`);
    let buf = '';
    let boundDigest = null;   // of the BIND; the ATTACH signs it
    process.stdin.on('data', (c) => {
      buf += c.toString();
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl).replace(/\r$/, '');
        buf = buf.slice(nl + 1);
        if (state === 'bind') {
          if (!line.startsWith('BIND ')) { process.stdout.write('ERR expected BIND\n'); process.exit(1); }
          const [, time, sig] = line.split(' ');
          boundDigest = bindDigest('/ces/lua/1', BigInt(time), clientPub, SERVER_KEY, CHALLENGE);
          if (!sigOk(sig, boundDigest)) {
            process.stdout.write('ERR bind: the server refused the bind\n'); process.exit(4);
          }
          state = 'attach';
        } else if (state === 'attach') {
          if (!line.startsWith('ATTACH ')) { process.stdout.write('ERR expected ATTACH\n'); process.exit(1); }
          const be64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
          const attachDigest = crypto.createHash('sha256')
            .update(Buffer.concat([Buffer.from([0x01]), be64(pid), boundDigest])).digest();
          if (!sigOk(line.split(' ')[1], attachDigest)) {
            process.stdout.write('ERR attach: bad signature\n'); process.exit(1);
          }
          process.stdout.write('READY\n');
          greet();
          state = 'repl';
        } else {
          const cmd = line.trim();
          if (cmd === 'help') process.stdout.write('commands: help, echo <x>, quit\n');
          else if (cmd === 'quit') process.exit(0);
          else process.stdout.write('echo: ' + cmd + '\n');
        }
      }
    });
    process.stdin.on('end', () => process.exit(0));
  }
} else if (argv.includes('file')) {
  const verb = argv[argv.indexOf('file') + 1];
  const cesPath = [...argv].reverse().find((a) => a.startsWith('/'));
  const f = (fx.files && fx.files[cesPath]) || null;
  if (!f) fail('FILE_NOT_FOUND');

  if (verb === 'stat') {
    if (f.statError) fail(f.statError);
    process.stdout.end(JSON.stringify({ size: sizeOf(f), modifiedUs: f.modifiedUs || 0 }));
  } else if (verb === 'get') {
    if (f.getError) fail(f.getError);
    const buf = bytesOf(f);
    if (f.fill === 'stall') {
      if (f.stallBytes) process.stdout.write(buf.subarray(0, f.stallBytes));
      setInterval(() => {}, 1 << 30);        // hang until SIGKILL'd by the reaper
    } else if (f.fill === 'drip') {
      const step = f.dripBytes || 65536, ms = f.dripMs || 50;
      let off = 0;
      const tick = () => {
        const end = Math.min(off + step, buf.length);
        process.stdout.write(buf.subarray(off, end));
        off = end;
        if (off >= buf.length) { process.stdout.end(); return; }
        setTimeout(tick, ms);
      };
      tick();
    } else {
      process.stdout.end(buf);
    }
  } else {
    fail('BAD_NAME');
  }
} else {
  fail('BAD_NAME');
}
