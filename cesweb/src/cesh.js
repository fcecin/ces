// Thin wrapper around the cesh CLI in its silent/pipe mode (-q): stdout is
// data only (JSON for queries, raw bytes for file content), errors on stderr.
// The gateway speaks no CES itself — cesh is the bridge.

import { spawn } from 'node:child_process';
import fs from 'node:fs';

// Map cesh's stderr (which prints errorString(rc)) to a coarse kind the gateway
// turns into an HTTP status. Heuristic by design — cesh returns 1 for every
// failure, so we match on the error name it printed.
function classifyErr(stderr) {
  const s = stderr || '';
  if (/INSUFFICIENT_BALANCE/.test(s)) return 'poor';
  if (/FILE_NOT_FOUND/.test(s))       return 'notfound';
  if (/BAD_NAME/.test(s))             return 'badname';
  return 'error';
}

export class CeshResult {
  constructor(code, stdout, stderr) {
    this.code = code;
    this.stdout = stdout;   // Buffer
    this.stderr = stderr;   // string
  }
  get ok() { return this.code === 0; }
  get errKind() { return classifyErr(this.stderr); }
}

// globalArgs come before the subcommand (CLI11 parses globals first); --wallet
// is global so it is injected there too.
export function runCesh(ceshBin, globalArgs, subArgs, opts = {}) {
  const { walletInline, walletFile, timeoutMs = 15000 } = opts;
  return new Promise((resolve) => {
    const env = { ...process.env };
    if (walletInline) env.CESH_WALLET = walletInline;
    const args = [...globalArgs];
    if (walletFile) args.push('--wallet', walletFile);
    args.push(...subArgs);

    let child;
    try {
      child = spawn(ceshBin, args, { env });
    } catch (e) {
      return resolve(new CeshResult(-1, Buffer.alloc(0), String(e)));
    }
    const out = [];
    let err = '';
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, timeoutMs);
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => { err += d.toString(); });
    child.on('error', (e) => { clearTimeout(timer); resolve(new CeshResult(-1, Buffer.alloc(0), String(e))); });
    child.on('close', (code) => { clearTimeout(timer); resolve(new CeshResult(code ?? -1, Buffer.concat(out), err)); });
  });
}

// Free MINX GetInfo (no wallet needed): { status, serverPublicKey, rpcPort, ... }
export async function ping(ceshBin, server, opts) {
  const r = await runCesh(ceshBin, ['-q', '--server', server], ['ping'], opts);
  if (!r.ok) throw Object.assign(new Error('cesh ping failed'), { result: r });
  return JSON.parse(r.stdout.toString('utf8'));
}

// The gateway's own account balance on `server` (raw credits), via the free
// unsigned account query. Returns a Number, or null if it can't be read (no
// PoW engine / unreachable / parse fail) — the home page degrades to "unknown".
export async function queryBalance(ceshBin, server, pubkey, opts) {
  const r = await runCesh(ceshBin, ['-q', '--server', server], ['query', pubkey], opts);
  if (!r.ok) return null;
  try {
    const j = JSON.parse(r.stdout.toString('utf8'));
    const n = Number(j.balance);
    return Number.isFinite(n) ? n : null;
  } catch { return null; }
}

// Build the global args shared by the file verbs (-q, --server, --rpc-port,
// and --server-key so cesh skips its own key lookup — no paid query).
function fileGlobals(server, rpcPort, serverKey) {
  const g = ['-q', '--server', server, '--rpc-port', String(rpcPort)];
  if (serverKey) g.push('--server-key', serverKey);
  return g;
}

// L2 STAT -> { ok, errKind, size, modifiedUs }. Cheap (one round-trip, metadata
// only) — the gateway uses it to validate the cache before the expensive READ.
export async function stat(ceshBin, server, rpcPort, cesPath, serverKey, opts) {
  const r = await runCesh(ceshBin, fileGlobals(server, rpcPort, serverKey),
                          ['file', 'stat', cesPath], opts);
  if (!r.ok) return { ok: false, errKind: r.errKind };
  try {
    const j = JSON.parse(r.stdout.toString('utf8'));
    return { ok: true, size: Number(j.size), modifiedUs: Number(j.modifiedUs) };
  } catch {
    return { ok: false, errKind: 'error' };
  }
}

// Spawn `cesh file get <cesPath>` streaming raw bytes to `partPath`. Returns
// { child, done } where `done` resolves to { ok, errKind, stderr } when cesh
// exits. The CALLER owns partPath: it stats it for live progress and is
// responsible for renaming on success / removing on failure. This is the
// engine's download primitive — it keeps the process + part-file lifecycle in
// the engine (so it can monitor progress, kill a stalled fetch, and recover)
// rather than hiding it inside one all-or-nothing promise. The expensive op:
// ≈550 chunked READs for a big file, but ~nothing in RAM (raw bytes stream
// straight to disk). The caller runs it only on a cache miss/change.
export function spawnFileGet(ceshBin, server, rpcPort, cesPath, serverKey, partPath, opts = {}) {
  const { walletInline, walletFile } = opts;
  const env = { ...process.env };
  if (walletInline) env.CESH_WALLET = walletInline;
  const args = [...fileGlobals(server, rpcPort, serverKey)];
  if (walletFile) args.push('--wallet', walletFile);
  args.push('file', 'get', cesPath);   // no local path => raw bytes to stdout

  let child;
  try {
    child = spawn(ceshBin, args, { env });
  } catch (e) {
    return { child: null, done: Promise.resolve({ ok: false, errKind: 'error', stderr: String(e) }) };
  }
  const ws = fs.createWriteStream(partPath);
  let err = '';
  const done = new Promise((resolve) => {
    ws.on('error', (e) => { try { child.kill('SIGKILL'); } catch {} });
    child.stdout.pipe(ws);
    child.stderr.on('data', (d) => { err += d.toString(); });
    child.on('error', (e) => {
      try { ws.destroy(); } catch {}
      resolve({ ok: false, errKind: 'error', stderr: String(e) });
    });
    child.on('close', (code) => {
      ws.end(() => resolve(code === 0
        ? { ok: true }
        : { ok: false, errKind: classifyErr(err), stderr: err }));
    });
  });
  return { child, done };
}

// Best-effort: the gateway's own account pubkey, shown on the 402 page so users
// know exactly which account to ask the operator to credit. MUST use `keys list
// -p`: a bare `keys list` line prints the DECORATED PRIVATE key, and grepping a
// 64-hex run off it grabs the decorator byte + 31 bytes of the private key — a
// mangled value that is NOT the account (see CLAUDE.md key-format gotcha). The
// real pubkey is the 64-hex inside the parentheses that `-p` appends.
export async function gatewayPubkey(ceshBin, opts) {
  const r = await runCesh(ceshBin, [], ['keys', 'list', '-p'], opts);
  if (!r.ok) return null;
  const m = r.stdout.toString('utf8').match(/\(([0-9a-fA-F]{64})\)/);
  return m ? m[1] : null;
}
