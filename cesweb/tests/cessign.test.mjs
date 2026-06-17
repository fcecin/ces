// cessign.js — validates the JS reproduction of CES signing (keys.h / wire.cpp).
// These prove cessign is internally correct: the sigs are valid ed25519/secp256k1
// over the exact bind/per-op digests (right tag, BE encoding, field order),
// 65-byte wire, deterministic. The authoritative CES-MATCH check is the live
// dicedemo e2e (scripts/diceweb.sh), where a real CES server verifies these
// sigs; if the digest format ever drifted from CES, that e2e would fail.
//
// Run with: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { pubkeyHex, signBind, signAttach } from '../src/cessign.js';

const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
const be16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const be64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };

const ED = '00' + 'cd'.repeat(32);   // ed25519 decorated private key
const SK = '01' + 'a1'.repeat(32);   // secp256k1 decorated private key

// Reference digests, re-derived independently from the documented CES format.
const bindDigest = (key, name, t) => {
  const pub = Buffer.from(pubkeyHex(key), 'hex');
  const nm = Buffer.from(name, 'utf8');
  return sha256(Buffer.concat([be16(nm.length), nm, be64(t), pub]));
};
const attachDigest = (instanceId, token) =>
  sha256(Buffer.concat([Buffer.from([0x01]), be64(instanceId), be64(token)]));

const splitSig = (hex) => { const b = Buffer.from(hex, 'hex'); return { tag: b[0], sig: b.subarray(1) }; };
function verifyOver(key, digest, sigHex) {
  const { tag, sig } = splitSig(sigHex);
  const x = Buffer.from(pubkeyHex(key), 'hex');
  if (tag === 0x00) return ed25519.verify(sig, digest, x);
  // secp256k1: rebuild the compressed pubkey from stored X + parity tag.
  const comp = Buffer.concat([Buffer.from([tag === 0x01 ? 0x02 : 0x03]), x]);
  return secp256k1.verify(sig, digest, comp);
}

test('pubkeyHex: 32-byte (64-hex) account keys; ed25519 matches noble', () => {
  assert.equal(pubkeyHex(ED).length, 64);
  assert.equal(pubkeyHex(SK).length, 64);
  assert.equal(pubkeyHex(ED),
    Buffer.from(ed25519.getPublicKey(Buffer.from(ED.slice(2), 'hex'))).toString('hex'));
});

test('rejects malformed private keys', () => {
  assert.throws(() => pubkeyHex('zz'));
  assert.throws(() => pubkeyHex('02' + 'cd'.repeat(32)));  // unknown algo byte
  assert.throws(() => pubkeyHex('00' + 'cd'.repeat(10)));  // wrong length
});

for (const [label, key] of [['ed25519', ED], ['secp256k1', SK]]) {
  test(`signBind ${label}: 65-byte sig, correct tag, verifies over the bind digest`, () => {
    const t = 1_700_000_000_000_000;
    const sigHex = signBind(key, '/ces/lua/1', t);
    assert.equal(Buffer.from(sigHex, 'hex').length, 65);
    const { tag } = splitSig(sigHex);
    if (label === 'ed25519') assert.equal(tag, 0x00);
    else assert.ok(tag === 0x01 || tag === 0x02, `secp tag ${tag}`);
    assert.ok(verifyOver(key, bindDigest(key, '/ces/lua/1', t), sigHex), 'bind sig must verify');
  });

  test(`signAttach ${label}: verifies over the per-op digest`, () => {
    const sigHex = signAttach(key, 7, 0xdeadbeef);
    assert.ok(verifyOver(key, attachDigest(7, 0xdeadbeef), sigHex), 'attach sig must verify');
  });

  test(`${label}: signatures are deterministic`, () => {
    assert.equal(signBind(key, '/ces/lua/1', 5), signBind(key, '/ces/lua/1', 5));
    assert.equal(signAttach(key, 1, 2), signAttach(key, 1, 2));
  });
}
