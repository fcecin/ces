// CES signing in JS — reproduces keys.h + cesplex/wire.h byte-for-byte so a
// tunneler (cesweb now; the browser later) can sign a CesPlex bind + ATTACH
// WITHOUT the private key ever reaching cesh.
//
// Decorated private key: "00"+64hex (ed25519) or "01"+64hex (secp256k1).
// Signature wire = 1 tag byte + 64-byte sig:
//   ed25519   → tag 0x00
//   secp256k1 → tag 0x01 (pubkey Y even) / 0x02 (odd). CES stores the pubkey as
//   the 32-byte X; the tag carries the parity so the verifier rebuilds the
//   compressed key. Sign is RFC6979-deterministic + low-S (libsecp default).
// Digests are sha256 with BIG-ENDIAN integers (matching ces::shaUpdate, which
// goes through logkv's native_to_big).

import crypto from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest();
const be16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n & 0xffff); return b; };
const be64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };

function parsePriv(hex) {
  const h = String(hex).trim();
  if (!/^[0-9a-fA-F]{66}$/.test(h)) throw new Error('private key must be 66 hex (00/01 + 64)');
  const priv = Buffer.from(h.slice(2), 'hex');
  const tag = h.slice(0, 2);
  if (tag === '00') return { algo: 'ed25519', priv };
  if (tag === '01') return { algo: 'secp256k1', priv };
  throw new Error('unknown key algorithm byte ' + tag);
}

// 32-byte (64-hex) account pubkey for a decorated private key.
export function pubkeyHex(privDecorated) {
  const k = parsePriv(privDecorated);
  if (k.algo === 'ed25519') return Buffer.from(ed25519.getPublicKey(k.priv)).toString('hex');
  return Buffer.from(secp256k1.getPublicKey(k.priv, true).slice(1)).toString('hex'); // X only
}

function signDigest(k, digest) {
  if (k.algo === 'ed25519') {
    return Buffer.concat([Buffer.from([0x00]), Buffer.from(ed25519.sign(digest, k.priv))]);
  }
  const sig = secp256k1.sign(digest, k.priv);                       // 64-byte compact
  const tag = secp256k1.getPublicKey(k.priv, true)[0] === 0x02 ? 0x01 : 0x02;
  return Buffer.concat([Buffer.from([tag]), Buffer.from(sig)]);
}

// Bind digest: sha256( u16(nameLen) ‖ name ‖ u64(timeUs) ‖ pubkey32 ).
export function signBind(privDecorated, name, timeUs) {
  const k = parsePriv(privDecorated);
  const pub = Buffer.from(pubkeyHex(privDecorated), 'hex');
  const nameBuf = Buffer.from(name, 'utf8');
  const digest = sha256(Buffer.concat([be16(nameBuf.length), nameBuf, be64(timeUs), pub]));
  return signDigest(k, digest).toString('hex');
}

// Per-op (ATTACH) digest: sha256( verb(0x01) ‖ u64(instanceId) ‖ u64(token) ).
export function signAttach(privDecorated, instanceId, sessionToken) {
  const k = parsePriv(privDecorated);
  const digest = sha256(Buffer.concat([Buffer.from([0x01]), be64(instanceId), be64(sessionToken)]));
  return signDigest(k, digest).toString('hex');
}
