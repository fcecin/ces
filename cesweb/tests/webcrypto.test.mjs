// Pins the BROWSER signing path. The terminal page signs with native WebCrypto
// Ed25519 (PKCS#8 import → JWK pubkey → crypto.subtle.sign). This replicates
// those exact steps with Node's WebCrypto (same implementation surface as
// browsers) and asserts the output matches cessign — which the dice e2e proves a
// real CES server verifies. So: browser path == cessign == CES. The DOM glue
// itself isn't unit-tested (that needs a headless browser), but the crypto is.
// Run with: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pubkeyHex, signBind, signAttach } from '../src/cessign.js';

const PFX = Buffer.from('302e020100300506032b657004220420', 'hex');  // Ed25519 PKCS#8 prefix
const ED = '00' + 'cd'.repeat(32);
const be16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const be64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const sha256 = async (buf) => Buffer.from(await crypto.subtle.digest('SHA-256', buf));

async function importBrowserStyle(dec66) {
  const pk8 = Buffer.concat([PFX, Buffer.from(dec66.slice(2), 'hex')]);
  const ext = await crypto.subtle.importKey('pkcs8', pk8, { name: 'Ed25519' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', ext);
  const pub = Buffer.from(jwk.x.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('hex');
  const key = await crypto.subtle.importKey('pkcs8', pk8, { name: 'Ed25519' }, false, ['sign']); // non-extractable
  return { key, pub };
}
const wcSign = async (key, digest) =>
  Buffer.concat([Buffer.from([0x00]), Buffer.from(await crypto.subtle.sign({ name: 'Ed25519' }, key, digest))]).toString('hex');

test('WebCrypto path: pubkey matches cessign', async () => {
  const { pub } = await importBrowserStyle(ED);
  assert.equal(pub, pubkeyHex(ED));
});

test('WebCrypto path: bind signature matches cessign (== CES)', async () => {
  const { key, pub } = await importBrowserStyle(ED);
  const t = 1_700_000_000_000_000;
  const name = Buffer.from('/ces/lua/1', 'utf8');
  const digest = await sha256(Buffer.concat([be16(name.length), name, be64(t), Buffer.from(pub, 'hex')]));
  assert.equal(await wcSign(key, digest), signBind(ED, '/ces/lua/1', t));
});

test('WebCrypto path: ATTACH signature matches cessign', async () => {
  const { key } = await importBrowserStyle(ED);
  const digest = await sha256(Buffer.concat([Buffer.from([0x01]), be64(7), be64(99)]));
  assert.equal(await wcSign(key, digest), signAttach(ED, 7, 99));
});
