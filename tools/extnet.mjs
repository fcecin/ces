#!/usr/bin/env node
// extnet: a real multi-node CES network harness for the extension stack.
//
// Distinct from cesnet.mjs (which boots bare ledger servers for traffic/conservation
// sims): extnet wires the full CesPlex/L2 stack (file/lua/compute/peer) plus the
// chosen /s/ extensions (coalition, peerclusterer, peerfunder, discovery) and stands
// up a real multi-process network with NO actual mining -- the PoW engine runs at
// min_difficulty=1 (cache-only) so main-port probes/tickets work, peer_target=0 so
// nothing mints, accounts are pre-funded offline, and peer PoW is seeded in
// peerdata.toml. It is for exercising the extension stack end to end across genuine
// OS processes (coalition formation, grief/ban, discovery, clustering) and monitoring
// it over the web dashboard.
//
// Usage:
//   tools/extnet.mjs init      # generate workspace (keys, configs, peerdata, /s/, fund)
//   tools/extnet.mjs up        # boot all nodes
//   tools/extnet.mjs mon       # one monitoring snapshot (state / members / grief / ban)
//   tools/extnet.mjs down      # stop all nodes (keep data)
//   tools/extnet.mjs destroy   # stop + delete workspace
//
// Env knobs:
//   CES_DIR    ces repo root (default: parent of this script's dir)
//   CES_BUILD  build flavor for the binaries: debug | release (default debug)
//   HOME_DIR   workspace dir (default ./extnet-ws); keep it SHORT -- the per-instance
//              compute UDS path is bounded by the OS (sun_path, 108 bytes)
//   N          node count (default 20)
//   TOPO       "7,7,6" disjoint cliques | "mesh" full mesh (default 7,7,6)
//   EXTS       comma list of extensions to deploy (default: coalition)
//   GROUP_MAX / GROUP_MIN  coalition max/min group size (default 7 / 4)
//   MAL        node index to run a divergent-params malicious (default none)
//   TICK_MS    coalition tick (default 2000)

import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT = process.env.CES_DIR || path.resolve(SCRIPT_DIR, '..');
const BUILD = process.env.CES_BUILD || 'debug';
const BIN = `${ROOT}/build/${BUILD}/ces`;
const LUAJITD = `${ROOT}/build/${BUILD}/cesluajitd`;
const EXTSRC = `${ROOT}/extensions`;

const HOME = path.resolve(process.env.HOME_DIR || './extnet-ws');
const N = parseInt(process.env.N || '20', 10);
const TOPO = process.env.TOPO || '7,7,6';
const EXTS = (process.env.EXTS || 'coalition').split(',').map(s => s.trim()).filter(Boolean);
const GROUP_MAX = parseInt(process.env.GROUP_MAX || '7', 10);
const GROUP_MIN = parseInt(process.env.GROUP_MIN || '4', 10);
const TICK_MS = parseInt(process.env.TICK_MS || '2000', 10);
const MAL = process.env.MAL !== undefined && process.env.MAL !== '' ? parseInt(process.env.MAL, 10) : -1;

const MAIN0 = 54000, RPC0 = 55000, WEB0 = 8080, CB0 = 56000, CSTEP = 20;
const POW_SEED = 500000000;            // seeded reciprocated PoW (>= group_pow_target)
const POW_TARGET = 500000000;          // econ gate kept at default; satisfied by the seed
const USER_CREDIT = 1000000000000n;    // 10000 cr to the user on each node

const manifestPath = path.join(HOME, 'manifest.json');
const pidsPath = path.join(HOME, 'pids.json');

function sh(args) { return execFileSync(BIN, args, { encoding: 'utf8' }); }
function genkey() {
  const out = sh(['--genkeypair']);
  const priv = out.match(/Private Key:\s*([0-9a-fA-F]+)/)[1];
  const pub = out.match(/Public Key:\s*([0-9a-fA-F]+)/)[1];
  return { priv, pub };
}
function nowSecs() { return Math.floor(Date.now() / 1000); }

// Parse TOPO into a clique assignment: cliqueOf[i] = clique index (-1 = mesh: all one).
function cliques() {
  if (TOPO === 'mesh') return { mode: 'mesh', of: Array(N).fill(0), sizes: [N] };
  const sizes = TOPO.split(',').map(s => parseInt(s, 10));
  const of = Array(N).fill(-1);
  let idx = 0;
  sizes.forEach((sz, c) => { for (let k = 0; k < sz && idx < N; k++) of[idx++] = c; });
  for (; idx < N; idx++) of[idx] = sizes.length; // leftovers -> own clique
  return { mode: 'cliques', of, sizes };
}

// Who node i links to: same-clique peers (cliques mode) or everyone (mesh).
function peersOf(i, cl) {
  const out = [];
  for (let j = 0; j < N; j++) {
    if (j === i) continue;
    if (cl.mode === 'mesh' || cl.of[j] === cl.of[i]) out.push(j);
  }
  return out;
}

function confFor(name, i, mal) {
  if (name === 'coalition') {
    const max = mal ? GROUP_MAX + 2 : GROUP_MAX; // malicious: divergent params
    return [
      `max_group_size = ${max}`,
      `min_group_size = ${GROUP_MIN}`,
      `group_pow_target = ${POW_TARGET}`,
      `tick_ms = ${TICK_MS}`,
      `stable_ticks = 3`,
      `attempt_timeout_ms = 10000`,
      `cooldown_ms = 3000`,
      `member_stale_ms = 20000`,
    ].join('\n') + '\n';
  }
  if (name === 'peerclusterer')
    return `group_size = ${GROUP_MAX}\ntick_ms = 3000\npeer_credit_target = ${POW_TARGET}\n`;
  if (name === 'peerfunder')
    return `require_inbound = 1\nemit_ms = 5000\n`;
  if (name === 'discovery')
    return `seeds = 127.0.0.1:${MAIN0}\ncrawl_ms = 3000\nmaint_ms = 5000\nactive_target = ${N}\n`;
  return '';
}

function buildConfig(node, i) {
  return [
    `log_level = "info"`,
    `data_dir = "${node.dataDir}"`,
    `port = ${node.main}`,
    `server_key = "${node.priv}"`,
    `server_name = "127.0.0.1:${node.main}"`,
    `min_difficulty = 1`,
    `pow_delay = 0`,
    `no_pow_engine = false`,   // engine ON (diff=1, cache-only) so main-port probes/tickets work;
    `cache_only_pow = true`,   // peer_target=0 + pre-funded => nothing actually mints
    `threads = 1`,
    `min_accounts = 1000`,
    `max_accounts = 200000`,
    `min_assets = 1000`,
    `max_assets = 200000`,
    `flush_value = 0`,
    `max_log_size_gb = 1`,
    `fee_account = 0`,
    `fee_asset = 0`,
    `fee_tx = 0`,
    `fee_query = 0`,
    `peer_target = 0`,
    `peer_miner_interval = 5`,
    `settlement_max_retries = 3`,
    `rpc_port = ${node.rpc}`,
    `file_store_max_bytes = 67108864`,
    `ext_local_budget = 100000000000`,
    `compute_max_instances = 8`,
    `compute_port_base = ${node.cbase}`,
    `compute_port_count = 16`,
    `web_port = ${node.web}`,
    `web_bind = "127.0.0.1"`,
    `fee_file_rent = 0`,
    `fee_file_write = 0`,
    `fee_file_read = 0`,
    ``,
    `[cesplex_mounts]`,
    `"/ces/file/1"    = "builtin:file"`,
    `"/ces/lua/1"     = "builtin:lua"`,
    `"/ces/compute/1" = "builtin:compute"`,
    `"/ces/peer/1"    = "builtin:peer"`,
    ``,
    `[extension]`,
    ...EXTS.map(e => `${e} = 1`),
    ``,
  ].join('\n');
}

function buildPeerData(node, i, cl, nodes) {
  const lst = peersOf(i, cl);
  const t = nowSecs();
  let s = '';
  for (const j of lst) {
    s += `[[peers]]\n`;
    s += `key = "${nodes[j].pub}"\n`;
    s += `address = "127.0.0.1:${nodes[j].main}"\n`;
    s += `reachable = true\n`;
    s += `verified = true\n`;
    s += `outbound = true\n`;
    s += `total_inbound_pow = ${POW_SEED}\n`;
    s += `total_outbound_pow = ${POW_SEED}\n`;
    s += `last_inbound_time = ${t}\n`;
    s += `last_check_time = ${t}\n\n`;
  }
  return s;
}

function init() {
  if (fs.existsSync(HOME)) { console.error(`refuse: ${HOME} exists; destroy first`); process.exit(1); }
  fs.mkdirSync(HOME, { recursive: true });
  const cl = cliques();
  console.log(`init N=${N} topo=${TOPO} exts=${EXTS.join('+')} mal=${MAL} groupMax=${GROUP_MAX}`);
  const user = genkey();
  const nodes = [];
  for (let i = 0; i < N; i++) {
    const k = genkey();
    nodes.push({
      i, priv: k.priv, pub: k.pub,
      main: MAIN0 + i, rpc: RPC0 + i, web: WEB0 + i, cbase: CB0 + i * CSTEP,
      dir: path.join(HOME, `n${i}`),
      dataDir: path.join(HOME, `n${i}`, 'data'),
    });
  }
  for (const node of nodes) {
    const store = path.join(node.dataDir, 'cesfilestore', 's');
    fs.mkdirSync(store, { recursive: true });
    fs.writeFileSync(path.join(node.dir, 'config.toml'), buildConfig(node, node.i));
    fs.writeFileSync(path.join(node.dataDir, 'peerdata.toml'), buildPeerData(node, node.i, cl, nodes));
    for (const e of EXTS) {
      fs.copyFileSync(path.join(EXTSRC, `${e}.lua`), path.join(store, `${e}.lua`));
      fs.writeFileSync(path.join(store, `${e}.conf`), confFor(e, node.i, node.i === MAL));
    }
  }
  // Pre-fund: user on every node (offline mint), so any signed op has funds.
  for (const node of nodes) {
    execFileSync(BIN, ['--config', path.join(node.dir, 'config.toml'),
      'credit', String(USER_CREDIT), user.pub], { stdio: 'ignore' });
  }
  fs.writeFileSync(manifestPath, JSON.stringify({ user, nodes, cl, EXTS, MAL, TOPO, GROUP_MAX, GROUP_MIN, TICK_MS }, null, 2));
  console.log(`workspace ready at ${HOME}`);
}

function up() {
  const m = JSON.parse(fs.readFileSync(manifestPath));
  const pids = {};
  for (const node of m.nodes) {
    const logf = fs.openSync(path.join(node.dir, 'ces.log'), 'a');
    const child = spawn(BIN, ['--config', path.join(node.dir, 'config.toml')],
      { detached: true, stdio: ['ignore', logf, logf], env: { ...process.env, PATH: `${ROOT}/build/debug:${process.env.PATH}` } });
    child.unref();
    pids[node.i] = child.pid;
  }
  fs.writeFileSync(pidsPath, JSON.stringify(pids, null, 2));
  console.log(`booted ${Object.keys(pids).length} nodes`);
}

function alive(pid) { try { process.kill(pid, 0); return true; } catch { return false; } }
function sleepSync(ms) { const end = Date.now() + ms; while (Date.now() < end) {} }
function down() {
  if (!fs.existsSync(pidsPath)) { console.log('no pids'); return; }
  const pids = JSON.parse(fs.readFileSync(pidsPath));
  const list = Object.values(pids);
  for (const p of list) { try { process.kill(p, 'SIGTERM'); } catch {} }
  // Wait up to 10s for graceful exit, then SIGKILL stragglers.
  for (let i = 0; i < 20; i++) { if (!list.some(alive)) break; sleepSync(500); }
  for (const p of list) { if (alive(p)) { try { process.kill(p, 'SIGKILL'); } catch {} } }
  sleepSync(1500); // let the OS release the bound UDP ports
  fs.rmSync(pidsPath);
  console.log('stopped');
}

function destroy() { down(); if (fs.existsSync(HOME)) fs.rmSync(HOME, { recursive: true, force: true }); console.log('destroyed'); }

function getJson(port, p) {
  return new Promise((resolve) => {
    const req = http.get({ host: '127.0.0.1', port, path: p, timeout: 2500 }, (res) => {
      let d = ''; res.on('data', c => d += c); res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
    });
    req.on('error', () => resolve(null)); req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}

async function mon() {
  const m = JSON.parse(fs.readFileSync(manifestPath));
  const rows = [];
  let formed = 0, idle = 0, settling = 0, down_ = 0;
  for (const node of m.nodes) {
    const [cs, pe] = await Promise.all([
      getJson(node.web, `/api/extension_status?name=coalition`),
      getJson(node.web, `/api/peers`),
    ]);
    let state = '-', members = '-', last = '-', faults = '-', commits = '-';
    if (cs && cs.ok && Array.isArray(cs.kv)) {
      const kv = {}; cs.kv.forEach(p => { kv[p[0]] = p[1]; });
      state = kv.state || '?'; members = kv.members || '?'; last = kv.last || '';
      faults = kv.faults || '0'; commits = kv.commits || '0';
      if (state === 'formed') formed++; else if ((last || '').startsWith('settling')) settling++; else idle++;
    } else { down_++; state = 'DOWN'; }
    let npeers = '-', banned = '-', grief = '-';
    if (pe && pe.peers) {
      npeers = pe.peers.length;
      banned = pe.peers.filter(p => p.banned).length;
      grief = pe.peers.reduce((a, p) => a + (p.grief || 0), 0);
    }
    rows.push(`n${String(node.i).padStart(2)} c${m.cl.of[node.i]} | ${String(state).padEnd(8)} m=${String(members).padEnd(3)} flt=${String(faults).padStart(3)} cmt=${String(commits).padStart(2)} pk=${String(npeers).padStart(2)} grf=${String(grief).padStart(3)} ban=${String(banned).padStart(2)} | ${(last || '').slice(0, 28)}`);
  }
  console.log(`=== mon @ ${new Date().toISOString()}  formed=${formed} settling=${settling} idle=${idle} down=${down_} ===`);
  console.log(rows.join('\n'));
}

const cmd = process.argv[2];
({ init, up, down, destroy, mon }[cmd] || (() => { console.error('cmd?'); process.exit(1); }))();
