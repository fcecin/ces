// The SSRF guard: the engine refuses to dial a host that resolves to a
// non-globally-routable address (loopback, RFC1918, link-local, CGNAT, …), so a
// crafted URL can't aim the gateway at localhost or the internal network.
// Run with: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isGloballyRoutable, hostOf, State } from '../src/engine.js';
import { tmpDir, writeFixture, makeEngine, waitState } from './util.mjs';

test('isGloballyRoutable rejects non-routable, accepts public', () => {
  const bad = ['127.0.0.1', '10.0.0.5', '192.168.1.1', '169.254.1.1',
    '172.16.0.1', '172.31.255.255', '100.64.0.1', '0.0.0.0', '224.0.0.1',
    '::1', '::', 'fe80::1', 'fc00::1', 'fd12::3456', 'ff02::1', '::ffff:127.0.0.1'];
  for (const ip of bad) assert.equal(isGloballyRoutable(ip), false, ip);
  const good = ['8.8.8.8', '1.1.1.1', '172.32.0.1',
    '2606:4700:4700::1111', '::ffff:8.8.8.8'];
  for (const ip of good) assert.equal(isGloballyRoutable(ip), true, ip);
});

test('hostOf strips the port', () => {
  assert.equal(hostOf('ces.pubcom.org:53830'), 'ces.pubcom.org');
  assert.equal(hostOf('1.2.3.4:53830'), '1.2.3.4');
  assert.equal(hostOf('[::1]:53830'), '::1');
  assert.equal(hostOf('host'), 'host');
});

test('engine refuses a non-routable host (allowPrivateHosts off)', async () => {
  const cache = tmpDir();
  const fx = writeFixture(cache, {
    ping: { rpcPort: 40000, serverKey: 'ab'.repeat(32) },
    files: { '/p/a.txt': { bytes: 'hi' } },
  });
  const engine = makeEngine(cache, fx, { allowPrivateHosts: false });
  try {
    const s = await waitState(engine, 'localhost', 53830, '/p/a.txt', State.FAILED);
    assert.equal(s.errKind, 'unreachable');   // never pinged; refused at resolve
  } finally { engine.stop(); }
});
