// Pins the BROWSER signing path. The terminal page signs with native WebCrypto
// Ed25519 (PKCS#8 import → JWK pubkey → crypto.subtle.sign). This runs the
// page's own helpers (src/pagesign.js, the text that server.js inlines) with
// Node's WebCrypto (same implementation surface as browsers) and asserts the
// output matches cessign and the C++ known answer. So: browser path == cessign
// == CES. The DOM glue itself isn't unit-tested (that needs a headless
// browser), but the crypto is.
// Run with: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pubkeyHex, signBind, signAttach } from '../src/cessign.js';
import { PAGE_SIGN_JS } from '../src/pagesign.js';

const ED = '00' + 'cd'.repeat(32);

// The page's own helpers: the exact text that server.js puts in the page, run
// here with Node's WebCrypto (the same API as the browsers).
const page = new Function(PAGE_SIGN_JS +
  '\nreturn { h2b, b2h, bindDigest, attachDigest, importEd25519, signDigest };')();

// The same vector as BindDigestKnownAnswer in tests/test_cesplex.cpp.
test('page: the bind digest has the known answer of the C++ suite', async () => {
  const d = await page.bindDigest('/ces/lua/1', 1_700_000_000_000_000,
    page.h2b('11'.repeat(32)), '22'.repeat(32), '9223372036854775809');
  assert.equal(page.b2h(d),
    '04bcbf72a154ef9775748c52f2ee9a94a4d9234c32f509ea27db123cb36def65');
});

test('page: the pubkey matches cessign', async () => {
  const { pubHex } = await page.importEd25519(ED);
  assert.equal(pubHex, pubkeyHex(ED));
});

test('page: the bind signature matches cessign (== CES)', async () => {
  const { signKey, pubBytes } = await page.importEd25519(ED);
  const t = 1_700_000_000_000_000;
  const serverKey = '22'.repeat(32), challenge = '9223372036854775809';
  const sig = await page.signDigest(signKey,
    await page.bindDigest('/ces/lua/1', t, pubBytes, serverKey, challenge));
  assert.equal(sig, signBind(ED, '/ces/lua/1', t, serverKey, challenge));
});

test('page: the ATTACH signature matches cessign', async () => {
  const { signKey, pubBytes } = await page.importEd25519(ED);
  const t = 1_700_000_000_000_000;
  const bindDig = await page.bindDigest('/ces/lua/1', t, pubBytes, '22'.repeat(32),
    '9223372036854775809');
  const sig = await page.signDigest(signKey, await page.attachDigest('7', bindDig));
  assert.equal(sig, signAttach(ED, 7, Buffer.from(bindDig)));
});

// The same vector as PerOpDigestKnownAnswer in tests/test_cesplex.cpp.
test('page: the per-op digest of the C++ suite', async () => {
  const bindDig = page.h2b('04bcbf72a154ef9775748c52f2ee9a94a4d9234c32f509ea27db123cb36def65');
  assert.equal(page.b2h(await page.attachDigest('7', bindDig)),
    'fcc76fdaffc05370107ae476fa3ac2cb80a156ac8486707468cef58d0bb2922b');
  await assert.rejects(() => page.attachDigest('7', '99'));
});
