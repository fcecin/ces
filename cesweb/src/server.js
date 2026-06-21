#!/usr/bin/env node
// cesweb — HTTP gateway to a CES server's L2 file store.
//
// This file is the WEB RESPONDER and nothing else. It parses a request, asks
// the engine for the content's current state, and renders that state: a ready
// cache file (streamed, range-capable) → a sitrep page that auto-refreshes
// while the engine works → an error page. It NEVER fetches, validates, evicts,
// or blocks. All of that lives in engine.js, off the request path. A request
// always returns immediately with the content's current state (e.g. downloading
// 43%, queued).
//
// cesweb speaks no CES itself: the engine shells out to the `cesh` CLI in pipe
// mode. Node owns the web; cesh owns CES; the engine is the state machine in
// between.

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { WebSocketServer } from 'ws';
import { parseRequestPath, parseDialPath } from './url.js';
import { contentTypeFor } from './mime.js';
import { gatewayPubkey, queryBalance } from './cesh.js';
import { Engine, State, fmtBytes } from './engine.js';
import { TerminalManager } from './term.js';

const PORT = parseInt(process.env.CESWEB_PORT || '8088', 10);
const BIND = process.env.CESWEB_BIND || '127.0.0.1';
const CESH = process.env.CESWEB_CESH || 'cesh';
const DEFAULT_CES_PORT = parseInt(process.env.CESWEB_DEFAULT_CES_PORT || '53830', 10);
const DEFAULT_HOST = process.env.CESWEB_DEFAULT_HOST || '';
const ALLOW = (process.env.CESWEB_ALLOW_HOSTS || '')
  .split(',').map((s) => s.trim()).filter(Boolean);
const walletOpts = {
  walletInline: process.env.CESWEB_WALLET || undefined,
  walletFile: process.env.CESWEB_WALLET_FILE || undefined,
};
let GATEWAY_PUBKEY = process.env.CESWEB_PUBKEY || '';

// The gateway's own balance on the default server (raw credits), refreshed in
// the background and shown on the home page. null = not known yet / no default.
let GATEWAY_BALANCE = null;
async function refreshBalance() {
  if (!DEFAULT_HOST || !GATEWAY_PUBKEY) { GATEWAY_BALANCE = null; return; }
  const bal = await queryBalance(CESH, `${DEFAULT_HOST}:${DEFAULT_CES_PORT}`,
                                 GATEWAY_PUBKEY, walletOpts);
  if (bal != null) GATEWAY_BALANCE = bal;          // keep the last good value on a blip
}

const CACHE_DIR = process.env.CESWEB_CACHE_DIR || path.join(process.cwd(), 'cache');
const MB = 1024 * 1024;
const num = (v, d) => { const n = parseInt(v, 10); return Number.isFinite(n) ? n : d; };

const engine = new Engine({
  cesh: CESH,
  cacheDir: CACHE_DIR,
  walletOpts,
  maxFileBytes:  num(process.env.CESWEB_MAX_FILE_MB, 1024) * MB,
  maxCacheBytes: num(process.env.CESWEB_MAX_CACHE_MB, 4096) * MB,
  lowWaterPct:   num(process.env.CESWEB_CACHE_LOW_WATER_PCT, 90),
  maxInflight:   num(process.env.CESWEB_MAX_INFLIGHT, 8),
  validateTtlMs: num(process.env.CESWEB_VALIDATE_TTL_MS, 15000),
  resolveTtlMs:  num(process.env.CESWEB_RESOLVE_TTL_MS, 60000),
  maxResolveEntries: num(process.env.CESWEB_MAX_RESOLVE_ENTRIES, 4096),
  getTimeoutMs:  num(process.env.CESWEB_GET_TIMEOUT_MS, 900000),
  stallTimeoutMs:num(process.env.CESWEB_STALL_TIMEOUT_MS, 60000),
  failTtlMs:     num(process.env.CESWEB_FAIL_TTL_MS, 10000),
  allowPrivateHosts: process.env.CESWEB_ALLOW_PRIVATE_HOSTS === '1',
}).start();

const ZONES = ['/h/', '/f/', '/p/', '/s/'];

// Web terminal: bridges a browser WebSocket to `cesh dial <pid>` into a running
// Lua L2 program. Reuses the engine's resolve cache for the host's rpcPort/key.
const terminals = new TerminalManager({
  cesh: CESH,
  resolve: (target) => engine.resolve(target),
  allowHost: (h) => !ALLOW.length || ALLOW.includes(h),
  log: (...a) => console.error('[term]', ...a),
});
const wss = new WebSocketServer({ noServer: true });

// A bad request or dropped socket must never take the gateway down.
process.on('uncaughtException', (e) => console.error('uncaughtException:', e?.stack || e));
process.on('unhandledRejection', (e) => console.error('unhandledRejection:', e));
process.on('SIGTERM', () => { terminals.stop(); engine.stop(); process.exit(0); });
process.on('SIGINT', () => { terminals.stop(); engine.stop(); process.exit(0); });

const clientIp = (req) => {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
};

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

function page(title, body, { refresh, countdown } = {}) {
  const meta = (refresh && !countdown) ? `<meta http-equiv=refresh content="${refresh}">` : '';
  const cd = countdown ? `<script>(function(){var n=${countdown},e=document.getElementById('cesweb-cd');
var t=setInterval(function(){n--;if(e)e.textContent=n;if(n<=0){clearInterval(t);location.reload();}},1000);})();</script>` : '';
  return `<!doctype html><html lang=en><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">${meta}
<title>${esc(title)}</title>
<style>
:root{color-scheme:light dark}
body{font:16px/1.6 system-ui,-apple-system,sans-serif;max-width:44rem;
margin:3rem auto;padding:0 1.2rem;color:#1b1b1f}
h1{font-size:1.6rem;margin:.2em 0 .6em}h2{font-size:1.05rem;margin:1.6em 0 .4em;color:#555}
code,pre{background:#00000010;border-radius:5px;font-size:.92em}
code{padding:.12em .4em}pre{padding:.7em .9em;overflow:auto}
ul{padding-left:0;list-style:none}li{padding:.25em 0;border-bottom:1px solid #00000010}
a{color:#0a7d33;text-decoration:none}a:hover{text-decoration:underline}
.muted{color:#888;font-size:.9rem;margin-top:2rem}
.big{font-size:3rem;margin:0}
.bar{height:.7rem;background:#00000018;border-radius:6px;overflow:hidden;margin:.8em 0}
.bar>span{display:block;height:100%;background:#0a7d33;transition:width .4s}
.pct{font-size:1.3rem;font-weight:600}
</style>
${body}${cd}`;
}

function sendHtml(res, status, body, extra = {}) {
  const buf = Buffer.from(body, 'utf8');
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8',
                          'content-length': buf.length, ...extra });
  res.end(buf);
}

function sendJson(res, status, obj) {
  const buf = Buffer.from(JSON.stringify(obj, null, 2), 'utf8');
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': buf.length });
  res.end(buf);
}

function landing() {
  const acct = GATEWAY_PUBKEY || '(account not set — CESWEB_PUBKEY)';
  const def = DEFAULT_HOST;
  const port = DEFAULT_CES_PORT;
  // Other servers worth advertising: the allowlist, minus the default and minus
  // anything plainly private (localhost has no business on the public page; the
  // engine refuses non-routable hosts anyway).
  const others = ALLOW.filter((h) =>
    h && h !== def && h !== 'localhost' &&
    !/^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(h));
  const open = ALLOW.length === 0;

  const zones = `<ul>
<li><code>/s/&lt;path&gt;</code> &mdash; what the operator put up (browse it: <a href="/s/index.html">/s/index.html</a>)</li>
<li><code>/p/&lt;path&gt;</code> &mdash; public files</li>
<li><code>/h/&lt;pubkey&gt;/&lt;path&gt;</code> &mdash; someone's home directory</li>
<li><code>/f/&lt;name&gt;/&lt;path&gt;</code> &mdash; a named directory</li>
</ul>`;

  const CES = '<a href="https://github.com/fcecin/ces">CES</a>';
  let body;
  if (def) {
    body = `<p>Serves files out of the ${CES} server <b>${esc(def)}</b> to your browser.
CES only speaks UDP, so this is the way in from the web.</p>
<p>Files go by their path on the server. Leave the host off and it means
<code>${esc(def)}</code>:</p>
${zones}
<p>So <code><a href="/s/welcome/index.html">/s/welcome/index.html</a></code> pulls
the demo page every CES server ships. A path ending in <code>/</code> gets
<code>index.html</code>.</p>`;
    if (others.length)
      body += `<p>It can also reach ${others.map((h) => `<code>${esc(h)}</code>`).join(', ')} &mdash;
put the host first: <code>/&lt;host&gt;[-port]/&lt;path&gt;</code>.</p>`;
    else if (open)
      body += `<p>Point it at another server by naming it:
<code>/&lt;host&gt;[-port]/&lt;path&gt;</code>.</p>`;
  } else {
    body = `<p>Serves files out of ${CES} servers to your browser — CES only speaks
UDP, so this is the way in from the web. Name the server in every URL:</p>
<pre><code>/&lt;host&gt;[-&lt;port&gt;]/&lt;path&gt;</code></pre>
<p>Zones: <code>/s/</code> (operator's, browsable) &middot; <code>/p/</code>
(public) &middot; <code>/h/&lt;pubkey&gt;/</code> &middot; <code>/f/&lt;name&gt;/</code>.
A path ending in <code>/</code> gets <code>index.html</code>.</p>` +
      (open ? '' : `<p>Reachable: ${others.map((h) => `<code>${esc(h)}</code>`).join(', ') || '(none)'}.</p>`);
  }

  // What it costs — only meaningful when there's a default server to report on.
  let cost = '';
  if (def) {
    const bal = GATEWAY_BALANCE != null
      ? `holds <b>${Number(GATEWAY_BALANCE).toLocaleString('en-US')}</b> credits right now`
      : 'balance isn’t available right now';
    cost = `<h2>What it costs</h2>
<p>Reading a file costs the gateway a little on <code>${esc(def)}</code>. Its account there &mdash;</p>
<pre><code>${esc(acct)}</code></pre>
<p>&mdash; ${bal}. Anyone can chip in by sending it credits from their own wallet:</p>
<pre><code>cesh --server ${esc(def)}:${port} transfer ${esc(acct)} &lt;amount&gt;</code></pre>
<p>(Run <code>${esc(def)}</code> yourself? Just mint to it:
<code>ces credit &lt;amount&gt; ${esc(acct)}</code>.) When it runs dry, file pages
come back <b>402</b>.</p>`;
  }

  return page('cesweb', `<h1>cesweb</h1>
${body}
${cost}
<h2>Dev tools</h2>
<p>Interactive things &mdash; a terminal into a running program, like the
<code>/s/dice</code> game. See <a href="/dev">/dev</a>.</p>`);
}

// A live progress page. Returned immediately for any non-ready, non-failed
// state; it auto-refreshes so the browser lands on the real content (or an
// error page) the moment the engine finishes.
function sitrepPage(snap, target) {
  const file = esc(snap.cesPath || '');
  const on = esc(target);
  let head, detail, refresh = 2;
  switch (snap.state) {
    case State.RESOLVING:
      // No stale bytes while we resolve the server's identity: a clean page with
      // a client-side 10s countdown that reloads to land on the real content.
      return page('Resolving cache entry',
        `<h1>Resolving cache entry</h1>
         <p>Reaching <code>${on}</code> and matching <code>${file}</code> in the gateway cache&hellip;</p>
         <p class=muted>Re-checking in <b id=cesweb-cd>10</b>s&hellip;</p>`,
        { countdown: 10 });
    case State.STATTING:
      head = 'Checking the file'; detail = `Looking up <code>${file}</code> on <code>${on}</code>&hellip;`; refresh = 1; break;
    case State.QUEUED:
      head = 'Queued';
      detail = `<code>${file}</code> is waiting for a download slot` +
               (snap.queueAhead ? ` (${snap.queueAhead} ahead)` : '') + '&hellip;';
      refresh = 2; break;
    case State.DOWNLOADING: {
      const want = snap.wantSize || 0, got = snap.gotBytes || 0;
      const pct = want ? Math.min(100, Math.floor((got / want) * 100)) : 0;
      head = 'Downloading from CES';
      detail =
        `<p>Pulling <code>${file}</code> from <code>${on}</code> into the gateway cache.
         CES reads in chunks, so a large file takes a while &mdash; this page refreshes itself.</p>
         <div class=bar><span style="width:${pct}%"></span></div>
         <p class=pct>${pct}%</p>
         <p class=muted>${fmtBytes(got)} of ${want ? fmtBytes(want) : '?'}</p>`;
      refresh = 2;
      return page('Downloading…', `<h1>${head}</h1>${detail}`, { refresh });
    }
    default:
      head = 'Working'; detail = 'One moment&hellip;'; refresh = 2;
  }
  return page(head, `<h1>${head}</h1><p>${detail}</p>`, { refresh });
}

// errKind (from cesh/engine) -> HTTP status + page.
function errPage(res, kind, target, cesPath) {
  const t = esc(target), p = esc(cesPath || '');
  switch (kind) {
    case 'poor': {
      const acct = GATEWAY_PUBKEY || '(set CESWEB_PUBKEY)';
      return sendHtml(res, 402, page('402 Payment Required', `<p class=big>402</p>
<h1>This gateway is out of credits on <code>${t}</code></h1>
<p>Serving a file costs the gateway a small fee on that server, and its account
there is empty. Crediting it is free for the server's operator:</p>
<pre><code>ces credit &lt;amount&gt; ${esc(acct)}</code></pre>`));
    }
    case 'notfound':
      return sendHtml(res, 404, page('404 Not Found',
        `<h1>404</h1><p><code>${p}</code> not found on <code>${t}</code>.</p>`));
    case 'badname':
      return sendHtml(res, 400, page('400 Bad Request', '<h1>400</h1><p>Malformed path.</p>'));
    case 'toobig':
      return sendHtml(res, 413, page('413 Too Large',
        `<h1>413</h1><p><code>${p}</code> is larger than this gateway will cache.</p>`));
    case 'unreachable':
      return sendHtml(res, 502, page('502 Bad Gateway',
        `<h1>502</h1><p>Can't reach <code>${t}</code>.</p>`));
    case 'nofileservice':
      return sendHtml(res, 502, page('502 Bad Gateway',
        `<h1>502</h1><p><code>${t}</code> has no file service.</p>`));
    default:
      return sendHtml(res, 502, page('502 Bad Gateway',
        `<h1>502</h1><p>Upstream error from <code>${t}</code>.</p>`));
  }
}

// Stream a local cache file, honoring Range (so media streams + seeks). This is
// the only "heavy" thing the responder does — and it's just a local file read,
// the actual job of a web server.
function serveLocal(req, res, file, type, knownSize) {
  let total = knownSize;
  if (total == null) {
    try { total = fs.statSync(file).size; }
    catch { return sendHtml(res, 404, page('404 Not Found', '<h1>404</h1>')); }
  }
  const base = { 'content-type': type, 'accept-ranges': 'bytes', 'cache-control': 'no-cache' };
  const range = req.headers.range;
  let start = 0, end = total - 1, status = 200;
  if (range) {
    const m = /^bytes=(\d*)-(\d*)$/.exec(range.trim());
    if (m && (m[1] !== '' || m[2] !== '')) {
      if (m[1] === '') { start = Math.max(0, total - parseInt(m[2], 10)); end = total - 1; }
      else { start = parseInt(m[1], 10); end = m[2] === '' ? total - 1 : Math.min(parseInt(m[2], 10), total - 1); }
      if (!Number.isFinite(start) || start > end || start >= total) {
        res.writeHead(416, { 'content-range': `bytes */${total}` });
        return res.end();
      }
      status = 206;
      base['content-range'] = `bytes ${start}-${end}/${total}`;
    }
  }
  base['content-length'] = end - start + 1;
  res.writeHead(status, base);
  if (req.method === 'HEAD') return res.end();
  const rs = fs.createReadStream(file, { start, end });
  rs.on('error', () => { try { res.destroy(); } catch {} });
  res.on('close', () => rs.destroy());
  rs.pipe(res);
}

// The embedded web terminal — a dev tool. The key is imported and used to SIGN
// entirely in the browser via native WebCrypto Ed25519 (non-extractable) — it
// never leaves the page. cesweb only relays signatures. The TARGET (server +
// pid) is entered in the page, not the URL: the session runs on the user's own
// key, so it isn't tied to a server. The page sends {hello, pubkey, time,
// bindSig, host, cesPort, pid}, gets the session token, returns {attachSig},
// then it's a raw byte pipe. ed25519 keys only; no native Ed25519 → it errors.
// `pre` is the optional URL prefill (may be null).
function termPage(pre) {
  const host = esc(pre?.host || DEFAULT_HOST || '');
  const port = pre?.cesPort || DEFAULT_CES_PORT;
  const pid = esc(pre?.pid || '');
  return `<!doctype html><html lang=en><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>cesweb terminal</title>
<style>
:root{color-scheme:dark light}
body{font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
margin:0;background:#0d0f12;color:#cdd3da;height:100vh;display:flex;flex-direction:column}
header{padding:.5rem .8rem;background:#15181d;border-bottom:1px solid #ffffff14;
font-size:.85rem;color:#8b94a0}
header b{color:#cdd3da}
header a{color:#6fae57;text-decoration:none}
#out{flex:1;overflow:auto;padding:.6rem .8rem;white-space:pre-wrap;word-break:break-word;cursor:text}
#out:focus{outline:none}
#out .s{color:#8b94a0;font-style:italic}
.cur{display:inline-block;width:.55ch;height:1.05em;background:#cdd3da;vertical-align:text-bottom;animation:bl 1.06s steps(1) infinite}
@keyframes bl{50%{opacity:0}}
#out:not(:focus) .cur{animation:none;opacity:.35}
form{display:flex;flex-wrap:wrap;gap:.5rem;padding:.5rem .8rem;background:#15181d;border-top:1px solid #ffffff14}
input{flex:1;min-width:7rem;background:#0d0f12;color:#cdd3da;border:1px solid #ffffff22;border-radius:5px;
padding:.45rem .6rem;font:inherit}
#connkey{flex-basis:100%}
button{background:#1f6f3f;color:#fff;border:0;border-radius:5px;padding:.45rem .9rem;font:inherit;cursor:pointer}
button:disabled{opacity:.5;cursor:default}
</style>
<header><a href="/">cesweb</a> &middot; <a href="/dev">dev tools</a> &middot; <b id=tgt>dial a CES compute instance</b></header>
<div id=out tabindex=0><span id=inl style=display:none><span id=ed></span><span class=cur></span></span></div>
<form id=connform>
<input id=srv autocomplete=off placeholder="server host" value="${host}">
<input id=port type=number autocomplete=off placeholder="port" value="${port}">
<input id=pid type=number autocomplete=off placeholder="instance id (pid)" value="${pid}">
<input id=connkey type=text autocomplete=off spellcheck=false placeholder="paste your ed25519 private key (00 + 64 hex) — signs locally, never sent">
<button type=submit>Attach</button>
</form>
<script>
const out=document.getElementById('out');
const connform=document.getElementById('connform');
const srv=document.getElementById('srv'), portin=document.getElementById('port'), pidin=document.getElementById('pid'), keyin=document.getElementById('connkey');
const inl=document.getElementById('inl'), ed=document.getElementById('ed');
const tgt=document.getElementById('tgt');
const dec=new TextDecoder(), enc=new TextEncoder();
// Scrollback is everything before the live input line; #inl stays last.
function add(t,cls){const s=document.createElement('span');if(cls)s.className=cls;s.textContent=t;out.insertBefore(s,inl);out.scrollTop=out.scrollHeight;}
function status(t){if(t)add(t+'\\n','s');}

// ---- native WebCrypto Ed25519 signing (the key never leaves this page) ----
const PFX=Uint8Array.from([0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20]);
function h2b(h){const a=new Uint8Array(h.length/2);for(let i=0;i<a.length;i++)a[i]=parseInt(h.substr(i*2,2),16);return a;}
function b2h(b){let s='';for(const x of b)s+=x.toString(16).padStart(2,'0');return s;}
function b64u2b(s){s=s.replace(/-/g,'+').replace(/_/g,'/');const r=atob(s);const a=new Uint8Array(r.length);for(let i=0;i<r.length;i++)a[i]=r.charCodeAt(i);return a;}
function be16(n){const b=new Uint8Array(2);new DataView(b.buffer).setUint16(0,n,false);return b;}
function be64(n){const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,BigInt(n),false);return b;}
function cat(){let l=0;for(const x of arguments)l+=x.length;const o=new Uint8Array(l);let i=0;for(const x of arguments){o.set(x,i);i+=x.length;}return o;}
async function sha256(buf){return new Uint8Array(await crypto.subtle.digest('SHA-256',buf));}
let signKey=null,pubHex=null,pubBytes=null,target=null;
async function importKey(dec66){
  if(!/^00[0-9a-fA-F]{64}$/.test(dec66)) throw new Error('the web wallet needs an ed25519 key (00 + 64 hex)');
  const seed=h2b(dec66.slice(2)), pk8=cat(PFX,seed);
  let ext;
  try{ext=await crypto.subtle.importKey('pkcs8',pk8,{name:'Ed25519'},true,['sign']);}
  catch(e){throw new Error('this browser has no native Ed25519 (use a current Chrome/Firefox/Safari)');}
  const jwk=await crypto.subtle.exportKey('jwk',ext);
  pubBytes=b64u2b(jwk.x); pubHex=b2h(pubBytes);
  signKey=await crypto.subtle.importKey('pkcs8',pk8,{name:'Ed25519'},false,['sign']); // non-extractable
  seed.fill(0); pk8.fill(0);
}
async function signDigest(digest){
  const sig=new Uint8Array(await crypto.subtle.sign({name:'Ed25519'},signKey,digest));
  const o=new Uint8Array(65); o[0]=0x00; o.set(sig,1); return b2h(o);
}
async function signBind(timeUs){const n=enc.encode('/ces/lua/1');return signDigest(await sha256(cat(be16(n.length),n,be64(timeUs),pubBytes)));}
async function signAttach(token){return signDigest(await sha256(cat(Uint8Array.of(0x01),be64(target.pid),be64(token))));}

let ws, live=false, lineBuf='';
function renderInput(){ ed.textContent=lineBuf; out.scrollTop=out.scrollHeight; }
// Local echo is plain — exactly the bytes you typed, no injected prompt or color
// (the program's output is rendered verbatim; only the cursor is ours).
function commitLine(){ add(lineBuf+'\\n'); try{ws.send(enc.encode(lineBuf+'\\n'));}catch{} lineBuf=''; renderInput(); }
function setConnected(){ if(live)return; live=true; inl.style.display=''; connform.style.display='none'; renderInput(); out.focus(); }
function setDisconnected(){ live=false; lineBuf=''; inl.style.display='none'; connform.style.display='flex'; }
function connectWs(){
  for(let n=out.firstChild;n;){const nx=n.nextSibling;if(n!==inl)out.removeChild(n);n=nx;}  // fresh screen each attach
  status('key imported locally (never sent) — dialing '+target.host+':'+target.port+' pid '+target.pid+'…');
  const proto=location.protocol==='https:'?'wss:':'ws:';
  ws=new WebSocket(proto+'//'+location.host+'/dev/dial');
  ws.binaryType='arraybuffer';
  ws.onopen=async ()=>{ const time=Date.now()*1000; ws.send(JSON.stringify({t:'hello',pubkey:pubHex,time,bindSig:await signBind(time),host:target.host,cesPort:target.port,pid:target.pid})); };
  ws.onmessage=async (ev)=>{
    if(typeof ev.data==='string'){
      let m; try{m=JSON.parse(ev.data);}catch{return;}
      if(m.t==='token'){ ws.send(JSON.stringify({t:'attachSig',sig:await signAttach(m.token)})); return; }
      if(m.t==='ready'){ setConnected(); return; }
      if(m._cesweb) status(m._cesweb);
      if(m._end){ setDisconnected(); }
    } else { add(dec.decode(ev.data)); setConnected(); }
  };
  ws.onclose=()=>{ status('— disconnected —'); setDisconnected(); };
  ws.onerror=()=>status('— connection error —');
}
connform.addEventListener('submit',async (e)=>{
  e.preventDefault();
  const host=srv.value.trim(), port=parseInt(portin.value,10), pid=pidin.value.trim(), k=keyin.value.trim();
  if(!host){status('✗ enter a server host');return;}
  if(!Number.isInteger(port)||port<1||port>65535){status('✗ enter a valid port');return;}
  if(!/^\\d+$/.test(pid)){status('✗ enter a numeric instance id (pid) — find it with: cesh compute ps');return;}
  if(!k){status('✗ paste your ed25519 private key');return;}
  try{await importKey(k);}catch(err){status('✗ '+err.message);return;}
  target={host,port,pid};
  tgt.textContent=host+':'+port+' · pid '+pid;
  connectWs();
});
// Type directly in the pane (click it, then type) — no input box. Cooked mode:
// local echo + line editing; the whole line is sent on Enter (the programs are
// line REPLs).
out.addEventListener('click',()=>{ if(live) out.focus(); });
out.addEventListener('keydown',(e)=>{
  if(!live||!ws||ws.readyState!==1) return;
  if(e.ctrlKey||e.metaKey||e.altKey) return;          // leave copy/paste/devtools alone
  if(e.key==='Enter'){ e.preventDefault(); commitLine(); }
  else if(e.key==='Backspace'){ e.preventDefault(); lineBuf=lineBuf.slice(0,-1); renderInput(); }
  else if(e.key.length===1){ e.preventDefault(); lineBuf+=e.key; renderInput(); }
});
out.addEventListener('paste',(e)=>{
  if(!live) return;
  e.preventDefault();
  const t=((e.clipboardData||window.clipboardData).getData('text')||'').replace(/\\r\\n?/g,'\\n');
  for(const ch of t){ if(ch==='\\n'){ commitLine(); } else if(ch>=' '){ lineBuf+=ch; } }
  renderInput();
});
</script>`;
}

function devIndex() {
  return page('cesweb · dev tools', `<h1>dev tools</h1>
<p>Bits that run on <b>your</b> key, not the gateway's: you paste it, it signs in
your browser, and it never reaches this gateway.</p>
<h2>dial</h2>
<p>A terminal into a running CES program. Give it the server, the instance id
(the <code>pid</code>, from <code>cesh compute ps</code>), and your key, then type
at it like a shell &mdash; e.g. the <code>/s/dice</code> game.</p>
<p><a href="/dev/dial">&rarr; open the terminal</a></p>
<p class=muted><a href="/">&larr; home</a></p>`);
}

const httpd = http.createServer((req, res) => {
  try {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return sendHtml(res, 405, page('405', '<h1>405</h1>'), { allow: 'GET, HEAD' });
    }
    const u = new URL(req.url, 'http://gateway');
    if (u.pathname === '/__cesweb/status') return sendJson(res, 200, engine.stats());

    // Dev tools index.
    if (u.pathname === '/dev' || u.pathname === '/dev/') return sendHtml(res, 200, devIndex());

    // Web terminal page (a dev tool; its WebSocket upgrade is handled below). The
    // target server + pid live in the page — the session runs on the user's own
    // key, so it isn't namespaced to a server in the URL. The path MAY prefill
    // them: /dev/dial/<host>[-port]/<pid> or /dev/dial/<pid>.
    if (u.pathname === '/dev/dial' || u.pathname.startsWith('/dev/dial/')) {
      return sendHtml(res, 200, termPage(parseDialPath(u.pathname, DEFAULT_CES_PORT, DEFAULT_HOST)));
    }

    const parsed = parseRequestPath(u.pathname, DEFAULT_CES_PORT, DEFAULT_HOST);
    if (parsed.kind === 'favicon') { res.writeHead(204); return res.end(); }
    if (parsed.kind === 'root') return sendHtml(res, 200, landing());

    const { host, cesPort, cesPath } = parsed;
    const target = `${host}:${cesPort}`;
    if (ALLOW.length && !ALLOW.includes(host)) {
      return sendHtml(res, 403, page('403',
        `<h1>403</h1><p><code>${esc(host)}</code> is not allowed by this gateway.</p>`));
    }
    if (!ZONES.some((z) => cesPath.startsWith(z))) {
      return sendHtml(res, 400, page('400',
        `<h1>400</h1><p>Path must start with a CES zone: <code>/h/ /f/ /p/ /s/</code>.</p>`));
    }

    // The whole web path: read the engine's state and render it.
    const snap = engine.requestContent(host, cesPort, cesPath);
    if (snap.state === State.READY) {
      return serveLocal(req, res, snap.file, contentTypeFor(cesPath), snap.size || null);
    }
    if (snap.state === State.FAILED) {
      return errPage(res, snap.errKind, target, cesPath);
    }
    // resolving / statting / queued / downloading → live sitrep, auto-refresh.
    return sendHtml(res, 200, sitrepPage(snap, target));
  } catch (e) {
    try { sendHtml(res, 500, page('500', '<h1>500</h1>')); } catch {}
    console.error('handler error:', e?.stack || e);
  }
});

// WebSocket upgrade → web terminal. One fixed endpoint, /dev/dial: the target
// server + pid arrive in the hello frame (the terminal manager validates +
// allow-checks them), since the session runs on the user's own key.
httpd.on('upgrade', (req, socket, head) => {
  let u;
  try { u = new URL(req.url, 'http://gateway'); } catch { return socket.destroy(); }
  if (u.pathname !== '/dev/dial') return socket.destroy();
  wss.handleUpgrade(req, socket, head, (ws) => {
    terminals.handle(ws, { ip: clientIp(req) });
  });
});

httpd.listen(PORT, BIND, async () => {
  if (!GATEWAY_PUBKEY) {
    try { GATEWAY_PUBKEY = (await gatewayPubkey(CESH, walletOpts)) || ''; } catch {}
  }
  // Prime + keep the home page's "balance on the default server" fresh.
  refreshBalance().catch(() => {});
  const bt = setInterval(() => refreshBalance().catch(() => {}), 120000);
  if (bt.unref) bt.unref();
  const realPort = httpd.address().port;   // honors PORT=0 (OS-assigned) for tests
  const s = engine.stats();
  console.error(
    `cesweb on http://${BIND}:${realPort}  cesh=${CESH}  defaultHost=${DEFAULT_HOST || '(none)'}` +
    `  cache=${CACHE_DIR} (${fmtBytes(s.totalBytes)}/${fmtBytes(s.maxCacheBytes)}, ${s.entries} files)` +
    `  account=${GATEWAY_PUBKEY || '(none)'}`
  );
});
