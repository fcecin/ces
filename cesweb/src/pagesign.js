// The signing helpers of the web terminal page, as the browser runs them.
// server.js puts this text, as it is, in the page's script, and
// tests/webcrypto.test.mjs runs the same text with Node's WebCrypto. So the
// test checks the bytes that the page signs, not a copy of them.
//
// The text is plain browser JavaScript: no imports, no exports. The page's own
// script calls these functions.
//   bindDigest(name, timeUs, pubBytes, serverKeyHex, challenge)
//     sha256( u16 name_len ‖ name ‖ u64 timeUs ‖ client key ‖ server key
//             ‖ u64 challenge ), as cesplex/wire.h computes it.
//   attachDigest(pid, bindDig)     sha256( 0x01 ‖ u64 pid ‖ bindDig ), where
//                                  bindDig is the 32 bytes of bindDigest()
//   importEd25519(dec66)           { signKey (non-extractable), pubBytes, pubHex }
//   signDigest(signKey, digest)    65-byte CES signature, as hex (tag 0x00)
// The challenge is a decimal u64 string: be64 takes it as a BigInt, never as a
// Number, because it can be above 2^53.

export const PAGE_SIGN_JS = String.raw`
const PFX=Uint8Array.from([0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20]);
function h2b(h){const a=new Uint8Array(h.length/2);for(let i=0;i<a.length;i++)a[i]=parseInt(h.substr(i*2,2),16);return a;}
function b2h(b){let s='';for(const x of b)s+=x.toString(16).padStart(2,'0');return s;}
function b64u2b(s){s=s.replace(/-/g,'+').replace(/_/g,'/');const r=atob(s);const a=new Uint8Array(r.length);for(let i=0;i<r.length;i++)a[i]=r.charCodeAt(i);return a;}
function be16(n){const b=new Uint8Array(2);new DataView(b.buffer).setUint16(0,n,false);return b;}
function be64(n){const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,BigInt(n),false);return b;}
function cat(){let l=0;for(const x of arguments)l+=x.length;const o=new Uint8Array(l);let i=0;for(const x of arguments){o.set(x,i);i+=x.length;}return o;}
async function sha256(buf){return new Uint8Array(await crypto.subtle.digest('SHA-256',buf));}
async function bindDigest(name,timeUs,pubBytes,serverKeyHex,challenge){
  const n=new TextEncoder().encode(name);
  return sha256(cat(be16(n.length),n,be64(timeUs),pubBytes,h2b(serverKeyHex),be64(challenge)));
}
async function attachDigest(pid,bindDig){if(!(bindDig instanceof Uint8Array)||bindDig.length!==32)throw new Error('the bind digest must be 32 bytes');return sha256(cat(Uint8Array.of(0x01),be64(pid),bindDig));}
async function importEd25519(dec66){
  if(!/^00[0-9a-fA-F]{64}$/.test(dec66)) throw new Error('the web wallet needs an ed25519 key (00 + 64 hex)');
  const seed=h2b(dec66.slice(2)), pk8=cat(PFX,seed);
  let ext;
  try{ext=await crypto.subtle.importKey('pkcs8',pk8,{name:'Ed25519'},true,['sign']);}
  catch(e){throw new Error('this browser has no native Ed25519 (use a current Chrome/Firefox/Safari)');}
  const jwk=await crypto.subtle.exportKey('jwk',ext);
  const pubBytes=b64u2b(jwk.x);
  const signKey=await crypto.subtle.importKey('pkcs8',pk8,{name:'Ed25519'},false,['sign']); // non-extractable
  seed.fill(0); pk8.fill(0);
  return {signKey,pubBytes,pubHex:b2h(pubBytes)};
}
async function signDigest(signKey,digest){
  const sig=new Uint8Array(await crypto.subtle.sign({name:'Ed25519'},signKey,digest));
  const o=new Uint8Array(65); o[0]=0x00; o.set(sig,1); return b2h(o);
}
`;
