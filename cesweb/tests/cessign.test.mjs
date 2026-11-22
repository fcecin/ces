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
import { pubkeyHex, bindDigest, signBind, signAttach } from '../src/cessign.js';

const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
const be16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const be64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };

const ED = '00' + 'cd'.repeat(32);   // ed25519 decorated private key
const SK = '01' + 'a1'.repeat(32);   // secp256k1 decorated private key

// The server hello that the tests sign for: a key, and a challenge above 2^53.
const SERVER_KEY = '22'.repeat(32);
const CHALLENGE = '9223372036854775809';

// Reference digests, re-derived independently from the documented CES format.
const refBindDigest = (key, name, t) => {
  const pub = Buffer.from(pubkeyHex(key), 'hex');
  const nm = Buffer.from(name, 'utf8');
  return sha256(Buffer.concat([be16(nm.length), nm, be64(t), pub,
    Buffer.from(SERVER_KEY, 'hex'), be64(CHALLENGE)]));
};
const attachDigest = (instanceId, bindDig) =>
  sha256(Buffer.concat([Buffer.from([0x01]), be64(instanceId), bindDig]));
// The bind digest that the ATTACH tests sign for.
const BIND_DIGEST = Buffer.from(
  '04bcbf72a154ef9775748c52f2ee9a94a4d9234c32f509ea27db123cb36def65', 'hex');

const splitSig = (hex) => { const b = Buffer.from(hex, 'hex'); return { tag: b[0], sig: b.subarray(1) }; };
function verifyOver(key, digest, sigHex) {
  const { tag, sig } = splitSig(sigHex);
  const x = Buffer.from(pubkeyHex(key), 'hex');
  if (tag === 0x00) return ed25519.verify(sig, digest, x);
  // secp256k1: rebuild the compressed pubkey from stored X + parity tag.
  const comp = Buffer.concat([Buffer.from([tag === 0x01 ? 0x02 : 0x03]), x]);
  return secp256k1.verify(sig, digest, comp, { prehash: false });   // CES signs the digest
}

test('pubkeyHex: 32-byte (64-hex) account keys; ed25519 matches noble', () => {
  assert.equal(pubkeyHex(ED).length, 64);
  assert.equal(pubkeyHex(SK).length, 64);
  assert.equal(pubkeyHex(ED),
    Buffer.from(ed25519.getPublicKey(Buffer.from(ED.slice(2), 'hex'))).toString('hex'));
});

// The same vector as BindDigestKnownAnswer in tests/test_cesplex.cpp.
test('bindDigest: the known answer of the C++ suite', () => {
  const d = bindDigest('/ces/lua/1', 1_700_000_000_000_000, '11'.repeat(32),
    '22'.repeat(32), '9223372036854775809');
  assert.equal(d.toString('hex'),
    '04bcbf72a154ef9775748c52f2ee9a94a4d9234c32f509ea27db123cb36def65');
});

// The same keys, bind and signatures as SignaturesMatchCessign in
// tests/test_cesplex.cpp: CES (Crypto++ ed25519, libsecp256k1) and cessign
// sign the same digest to the same bytes, with no second hash.
test('signatures: the known answers of the C++ suite', () => {
  const t = 1_700_000_000_000_000;
  assert.equal(pubkeyHex(ED), 'fc947730f49eb01427a66e050733294d9e520e545c7a27125a780634e0860a27');
  assert.equal(pubkeyHex(SK), 'ab5d2e79cfd621b1b027ffb24e2453ed7fb571ba9a841ff0e2473466cabd168d');
  assert.equal(signBind(ED, '/ces/lua/1', t, SERVER_KEY, CHALLENGE),
    '00bcc1e29f99b9d73fa943adb28cadb5140f24815aa65adb50d2d53de1a811a0137821e069fed2a1096b56cb95c50736dcc39cbd84ab115f90601289300e811709');
  assert.equal(signBind(SK, '/ces/lua/1', t, SERVER_KEY, CHALLENGE),
    '02a2b26927b785d103744d29e93e720dd35ee5661bfe3e8aa211ae05a2bfa95f204bb7d15442c45bca1dd25f6dea60afcb694c9ce964a5dc8b04a41f8443aa5538');
});

test('a challenge as a Number is refused', () => {
  assert.throws(() => signBind(ED, '/ces/lua/1', 5, SERVER_KEY, 12345));
  assert.throws(() => signBind(ED, '/ces/lua/1', 5, 'zz', CHALLENGE));
});

test('signAttach refuses a bind digest that is not 32 bytes', () => {
  assert.throws(() => signAttach(ED, 1, 12345));
  assert.throws(() => signAttach(ED, 1, CHALLENGE));
  assert.throws(() => signAttach(ED, 1, BIND_DIGEST.subarray(1)));
});

// The same vector as PerOpDigestKnownAnswer in tests/test_cesplex.cpp.
test('signAttach: signs the known per-op digest of the C++ suite', () => {
  const kat = Buffer.from(
    'fcc76fdaffc05370107ae476fa3ac2cb80a156ac8486707468cef58d0bb2922b', 'hex');
  assert.deepEqual(attachDigest(7, BIND_DIGEST), kat);
  assert.ok(verifyOver(ED, kat, signAttach(ED, 7, BIND_DIGEST)));
  assert.ok(verifyOver(SK, kat, signAttach(SK, 7, BIND_DIGEST)));
});

test('rejects malformed private keys', () => {
  assert.throws(() => pubkeyHex('zz'));
  assert.throws(() => pubkeyHex('02' + 'cd'.repeat(32)));  // unknown algo byte
  assert.throws(() => pubkeyHex('00' + 'cd'.repeat(10)));  // wrong length
});

for (const [label, key] of [['ed25519', ED], ['secp256k1', SK]]) {
  test(`signBind ${label}: 65-byte sig, correct tag, verifies over the bind digest`, () => {
    const t = 1_700_000_000_000_000;
    const sigHex = signBind(key, '/ces/lua/1', t, SERVER_KEY, CHALLENGE);
    assert.equal(Buffer.from(sigHex, 'hex').length, 65);
    const { tag } = splitSig(sigHex);
    if (label === 'ed25519') assert.equal(tag, 0x00);
    else assert.ok(tag === 0x01 || tag === 0x02, `secp tag ${tag}`);
    assert.ok(verifyOver(key, refBindDigest(key, '/ces/lua/1', t), sigHex), 'bind sig must verify');
  });

  test(`signAttach ${label}: verifies over the per-op digest`, () => {
    const sigHex = signAttach(key, 7, BIND_DIGEST);
    assert.ok(verifyOver(key, attachDigest(7, BIND_DIGEST), sigHex), 'attach sig must verify');
  });

  test(`${label}: signatures are deterministic`, () => {
    assert.equal(signBind(key, '/ces/lua/1', 5, SERVER_KEY, CHALLENGE),
                 signBind(key, '/ces/lua/1', 5, SERVER_KEY, CHALLENGE));
    assert.equal(signAttach(key, 1, BIND_DIGEST), signAttach(key, 1, BIND_DIGEST));
  });
}
