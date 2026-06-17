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
  // handshake (BIND→TOKEN, ATTACH→READY) — sigs are not verified here; this is a
  // stand-in. The fixture's `dial` block can tweak the greeting or force a fail.
  const pid = [...argv].reverse().find((a) => /^\d+$/.test(a) && a !== '--pubkey') || '?';
  const d = fx.dial || {};
  if (d.fail) fail(d.fail === true ? 'COMPUTE_INSTANCE_NOT_FOUND' : d.fail);
  const extsign = argv.includes('--extsign');
  const greet = () => process.stdout.write((d.greeting || `fakecesh dial pid=${pid} ready`) + '\n');
  let state = extsign ? 'bind' : 'repl';
  if (!extsign) greet();
  let buf = '';
  process.stdin.on('data', (c) => {
    buf += c.toString();
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).replace(/\r$/, '');
      buf = buf.slice(nl + 1);
      if (state === 'bind') {
        if (!line.startsWith('BIND ')) { process.stdout.write('ERR expected BIND\n'); process.exit(1); }
        process.stdout.write('TOKEN 12345\n');
        state = 'attach';
      } else if (state === 'attach') {
        if (!line.startsWith('ATTACH ')) { process.stdout.write('ERR expected ATTACH\n'); process.exit(1); }
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
