#!/usr/bin/env node
//
// cesnet - CES server network orchestrator.
//
// Manages persistent network workspaces: directories containing server configs,
// keys, data, and runtime state. A workspace survives up/down cycles.

import { execSync, spawn, spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, openSync, closeSync } from "node:fs";
import { join, resolve } from "node:path";

const PROJECT_ROOT = resolve(import.meta.dirname, "..");
const MANIFEST = "cesnet.json";
const PIDFILE = "cesnet.pids";
const PEER_LIQUIDITY = 1_000_000_000_000;
const USER_CREDIT = 1_000_000_000_000;

let cesBinCached = null;
let ceshBinCached = null;
function cesBin() { return cesBinCached ??= findBinary("ces"); }
function ceshBin() { return ceshBinCached ??= findBinary("cesh"); }

// ---- Utilities ----

function findBinary(name) {
  for (const build of ["debug", "relwithdebinfo", "release"]) {
    const p = join(PROJECT_ROOT, "build", build, name);
    if (existsSync(p)) return p;
  }
  throw new Error(`Cannot find ${name} binary. Run build.sh first.`);
}

function genKeypair(cesBin) {
  const out = execSync(`${cesBin} --genkeypair`, { encoding: "utf8" });
  const priv = out.match(/Private Key:\s*(\w+)/)?.[1];
  const pub = out.match(/Public Key:\s*(\w+)/)?.[1];
  if (!priv || !pub) throw new Error("Failed to parse genkeypair output");
  return { priv, pub };
}

function sleep(ms) {
  spawnSync("sleep", [String(ms / 1000)]);
}

function isAlive(pid) {
  try { process.kill(pid, 0); return true; } catch { return false; }
}

function findStrayProcesses() {
  try {
    const out = execSync("pgrep -a '^ces$' 2>/dev/null || true", { encoding: "utf8" });
    return out.trim().split("\n").filter(Boolean).map((line) => {
      const pid = parseInt(line.split(/\s+/)[0]);
      return { pid, line: line.trim() };
    });
  } catch { return []; }
}

// ---- Workspace I/O ----

function loadManifest(dir) {
  const p = join(dir, MANIFEST);
  if (!existsSync(p)) {
    console.error(`Not a cesnet workspace: ${dir}`);
    process.exit(1);
  }
  return JSON.parse(readFileSync(p, "utf8"));
}

function saveManifest(dir, manifest) {
  writeFileSync(join(dir, MANIFEST), JSON.stringify(manifest, null, 2));
}

function loadPids(dir) {
  const p = join(dir, PIDFILE);
  if (!existsSync(p)) return null;
  return JSON.parse(readFileSync(p, "utf8"));
}

function savePids(dir, pids) {
  writeFileSync(join(dir, PIDFILE), JSON.stringify(pids));
}

function clearPids(dir) {
  const p = join(dir, PIDFILE);
  if (existsSync(p)) rmSync(p);
}

function isUp(dir) {
  const pids = loadPids(dir);
  return pids && pids.some((pid) => isAlive(pid));
}

// ---- Server config generation ----

function buildToml(server, allServers) {
  const peers = allServers
    .filter((s) => s.port !== server.port)
    .map(
      (s) => `[[peers]]\nkey = "${s.pub}"\naddress = "127.0.0.1:${s.port}"\n`
    )
    .join("\n");

  return `
log_level = "info"
data_dir = "${server.dataDir}"
port = ${server.port}
server_key = "${server.priv}"
server_name = "127.0.0.1:${server.port}"
min_difficulty = 1
pow_delay = 0
spend_slot_size = 3600
no_pow_engine = true
cache_only_pow = false
threads = 1
min_accounts = 100
max_accounts = 100000
min_assets = 100
max_assets = 100000
flush_value = 0
max_log_size_gb = 1
fee_account = 0
fee_asset = 0
fee_tx = 0
fee_query = 0
peer_target = 0
peer_miner_interval = 2
settlement_max_retries = 1

${peers}
`.trim();
}

function launchServer(cesBin, dir, idx) {
  const configFile = join(dir, `server${idx}.toml`);
  const logFile = join(dir, `server${idx}.log`);
  const logFd = openSync(logFile, "a");
  const child = spawn(cesBin, ["--config", configFile, "-x"], {
    stdio: ["ignore", logFd, logFd],
    detached: true,
  });
  child.unref();
  closeSync(logFd);
  return child.pid;
}

// ---- Commands ----

function cmdInit(args) {
  let n = null;
  let basePort = 54000;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--base-port") { basePort = parseInt(args[++i]); continue; }
    if (n === null) { n = parseInt(args[i]); continue; }
  }

  if (!n || n < 1 || n > 20) {
    console.error("Usage: cesnet init <N> [--base-port PORT]");
    process.exit(1);
  }

  const dir = homeDir;
  if (existsSync(join(dir, MANIFEST))) {
    console.error(`Workspace already exists: ${dir}`);
    process.exit(1);
  }

  mkdirSync(dir, { recursive: true });

  // Generate user key (@0)
  const user = genKeypair(cesBin());

  // Generate server keys (@1 through @N)
  const servers = [];
  for (let i = 0; i < n; i++) {
    const { priv, pub } = genKeypair(cesBin());
    const port = basePort + i;
    const dataDir = join(dir, `server${i}`, "data");
    mkdirSync(dataDir, { recursive: true });
    servers.push({ index: i, port, priv, pub, dataDir });
  }

  // Write server TOML configs
  for (const s of servers) {
    const toml = buildToml(s, servers);
    writeFileSync(join(dir, `server${s.index}.toml`), toml);
  }

  // Write peerdata.toml (pre-mark peers as reachable)
  if (n > 1) {
    for (const s of servers) {
      const pd = servers
        .filter((p) => p.port !== s.port)
        .map((p) => `[[peers]]\nkey = "${p.pub}"\naddress = "127.0.0.1:${p.port}"\nreachable = true\nverified = true\noutbound = true\n`)
        .join("\n");
      writeFileSync(join(s.dataDir, "peerdata.toml"), pd);
    }
  }

  if (n > 1) {
    console.log("  Minting peer liquidity...");
    for (const s of servers) {
      for (const peer of servers) {
        if (peer.port === s.port) continue;
        execSync(
          `${cesBin()} --config ${join(dir, `server${s.index}.toml`)} credit ${PEER_LIQUIDITY} ${peer.pub}`,
          { stdio: "ignore" }
        );
      }
    }
  }

  // Write wallet: @0 = user, @1..@N = server keys
  const walletLines = [user.priv, ...servers.map((s) => s.priv)];
  writeFileSync(join(dir, "wallet"), walletLines.join("\n") + "\n");

  console.log("  Crediting user on all servers...");
  for (const s of servers) {
    execSync(
      `${cesBin()} --config ${join(dir, `server${s.index}.toml`)} credit ${USER_CREDIT} ${user.pub}`,
      { stdio: "ignore" }
    );
  }

  // Save manifest
  const manifest = {
    user: { pub: user.pub, priv: user.priv },
    servers: servers.map((s) => ({
      index: s.index,
      port: s.port,
      pub: s.pub,
      priv: s.priv,
    })),
    basePort,
  };
  saveManifest(dir, manifest);

  console.log(`  @0 user: ${user.pub.slice(0, 16)}...`);
  for (const s of servers) {
    console.log(`  @${s.index + 1} server${s.index}: port=${s.port} pub=${s.pub.slice(0, 16)}...`);
  }
  console.log(`\nWorkspace created: ${dir}`);
  console.log(`${n} servers configured. Use 'cesnet up' to launch.`);
}

function cmdUp(args) {
  const dir = homeDir;
  const manifest = loadManifest(dir);

  if (isUp(dir)) {
    console.error("Network already running. Use 'down' first.");
    process.exit(1);
  }

  // Check for strays
  const knownPids = new Set((loadPids(dir) || []).filter(isAlive));
  const strays = findStrayProcesses().filter((s) => !knownPids.has(s.pid));
  if (strays.length > 0) {
    console.error("Stray ces processes detected:");
    for (const s of strays) console.error(`  ${s.line}`);
    console.error("Kill them manually or run: cesnet nuke");
    process.exit(1);
  }

  const pids = [];

  for (const s of manifest.servers) {
    const pid = launchServer(cesBin(), dir, s.index);
    pids.push(pid);
    console.log(`  server${s.index}: port=${s.port} pid=${pid}`);
  }

  savePids(dir, pids);

  // Probe: verify all servers are responding
  let allOk = false;
  for (let attempt = 1; attempt <= 5; attempt++) {
    sleep(1000);
    let ok = 0;
    for (let i = 0; i < manifest.servers.length; i++) {
      if (!isAlive(pids[i])) continue;
      try {
        execSync(
          `${ceshBin()} --server 127.0.0.1:${manifest.servers[i].port} query ${manifest.servers[i].pub}`,
          { stdio: "ignore", timeout: 3000 }
        );
        ok++;
      } catch {}
    }
    if (ok === manifest.servers.length) {
      allOk = true;
      break;
    }
    console.log(`  Waiting for servers... (${ok}/${manifest.servers.length} ready)`);
  }

  if (allOk)
    console.log("Network started. All servers responding.");
  else
    console.log("Network started. Warning: not all servers responded to probe.");
}

function cmdDown() {
  const dir = homeDir;
  loadManifest(dir); // validate workspace
  const pids = loadPids(dir);

  if (!pids) {
    console.log("Network not running.");
    return;
  }

  for (const pid of pids) {
    try {
      process.kill(pid, "SIGTERM");
      console.log(`  Stopped pid ${pid}`);
    } catch {
      console.log(`  pid ${pid} already dead`);
    }
  }

  sleep(1000);
  clearPids(dir);
  console.log("Network stopped. Workspace preserved.");
}

function cmdStatus() {
  const dir = homeDir;
  const manifest = loadManifest(dir);
  const pids = loadPids(dir) || [];

  for (let i = 0; i < manifest.servers.length; i++) {
    const s = manifest.servers[i];
    const pid = pids[i] || 0;
    const alive = pid && isAlive(pid);
    const mark = alive ? "\x1b[32mUP\x1b[0m" : "\x1b[31mDOWN\x1b[0m";
    console.log(`  server${s.index}: port=${s.port} ${mark}${pid ? ` pid=${pid}` : ""}`);
  }
}

function cmdInfo() {
  const dir = homeDir;
  const manifest = loadManifest(dir);
  const info = {
    user: { wallet_index: 0, pub: manifest.user.pub },
    servers: manifest.servers.map((s) => ({
      wallet_index: s.index + 1,
      index: s.index,
      address: `127.0.0.1:${s.port}`,
      pub: s.pub,
    })),
    wallet: join(dir, "wallet"),
  };
  console.log(JSON.stringify(info, null, 2));
}

function cmdCesh() {
  const dir = homeDir;
  loadManifest(dir); // validate
  const walletFile = join(dir, "wallet");
  let ceshArgs = [...rest]; // everything after "cesh"
  // Auto-append -w <wallet> for key mutation commands so saves go back to workspace
  const mutatingKeysCmds = ["gen", "add"];
  if (ceshArgs.includes("keys") &&
      ceshArgs.some((a) => mutatingKeysCmds.includes(a)) &&
      !ceshArgs.includes("-w") && !ceshArgs.includes("--save")) {
    ceshArgs.push("-w", walletFile);
  }
  const result = spawnSync(ceshBin(), ["-r", walletFile, ...ceshArgs], {
    stdio: "inherit",
    env: process.env,
  });
  process.exit(result.status || 0);
}

function cmdCredit(args) {
  const dir = homeDir;
  const manifest = loadManifest(dir);
  const pids = loadPids(dir) || [];

  const idx = parseInt(args[0]);
  const amount = args[1];
  const pubkey = args[2];

  if (isNaN(idx) || !amount || !pubkey) {
    console.error("Usage: cesnet credit <server-index> <amount> <pubkey>");
    process.exit(1);
  }
  if (idx < 0 || idx >= manifest.servers.length) {
    console.error(`Server index ${idx} out of range (0-${manifest.servers.length - 1})`);
    process.exit(1);
  }

  const configFile = join(dir, `server${idx}.toml`);
  const wasRunning = pids[idx] && isAlive(pids[idx]);

  if (wasRunning) {
    console.log(`  Stopping server${idx} (pid ${pids[idx]})...`);
    try { process.kill(pids[idx], "SIGTERM"); } catch {}
    sleep(500);
  }

  console.log(`  Crediting ${amount} to ${pubkey.slice(0, 16)}...`);
  execSync(`${cesBin()} --config ${configFile} credit ${amount} ${pubkey}`,
    { stdio: "ignore" });

  if (wasRunning) {
    const newPid = launchServer(cesBin(), dir, idx);
    pids[idx] = newPid;
    savePids(dir, pids);
    console.log(`  Restarted server${idx} (pid ${newPid})`);
  }

  console.log("Done.");
}

function cmdDestroy() {
  const dir = homeDir;
  if (!existsSync(join(dir, MANIFEST))) {
    console.error(`Not a cesnet workspace: ${dir}`);
    process.exit(1);
  }

  // Kill any running servers
  const pids = loadPids(dir) || [];
  for (const pid of pids) {
    try { process.kill(pid, "SIGTERM"); } catch {}
  }
  if (pids.length) sleep(1000);

  rmSync(dir, { recursive: true, force: true });
  console.log(`Destroyed workspace: ${dir}`);
}

function cmdNuke() {
  const strays = findStrayProcesses();
  if (strays.length === 0) {
    console.log("No ces processes found.");
    return;
  }
  for (const s of strays) {
    try {
      process.kill(s.pid, "SIGKILL");
      console.log(`  Killed ${s.pid}: ${s.line}`);
    } catch {
      console.log(`  ${s.pid} already dead`);
    }
  }
  console.log("Nuked.");
}

// ---- Main ----

// Parse --home globally, strip from args
const DEFAULT_HOME = resolve("mynet");
let homeDir = DEFAULT_HOME;
const rawArgs = process.argv.slice(2);
const filteredArgs = [];
for (let i = 0; i < rawArgs.length; i++) {
  if (rawArgs[i] === "--home" && i + 1 < rawArgs.length) {
    homeDir = resolve(rawArgs[++i]);
  } else if (rawArgs[i].startsWith("--home=")) {
    homeDir = resolve(rawArgs[i].slice("--home=".length));
  } else {
    filteredArgs.push(rawArgs[i]);
  }
}
const [cmd, ...rest] = filteredArgs;
switch (cmd) {
  case "init":    cmdInit(rest); break;
  case "up":      cmdUp(); break;
  case "down":    cmdDown(); break;
  case "status":  cmdStatus(); break;
  case "info":    cmdInfo(); break;
  case "credit":  cmdCredit(rest); break;
  case "cesh":    cmdCesh(); break;
  case "destroy": cmdDestroy(); break;
  case "nuke":    cmdNuke(); break;
  default:
    console.log(`cesnet - CES server network orchestrator

Usage: cesnet [--home <dir>] <command> [args]

All commands operate on a workspace directory (default: ./mynet).
Use --home to override.

Workspace commands:
  init <N> [--base-port PORT] Create a workspace with N peered CES servers.
                              Generates keys, configs, peer liquidity, a user
                              key (@0) credited on all servers, and a wallet
                              file with all keys. Does not launch anything.

  up                          Launch all servers in the workspace.
  down                        Stop all servers. Data is preserved.
  destroy                     Stop servers and delete workspace entirely.

  status                      Show which servers are running.
  info                        Print JSON with addresses, keys, and wallet path.

  credit <idx> <amt> <pub>    Credit an account on server <idx>. Stops and
                              restarts the server if it's running.

  cesh [cesh-args...]         Run cesh with the workspace wallet loaded.
                              This is a full cesh session — every cesh command
                              works (transfers, queries, mining, assets, etc.).
                              The workspace wallet is loaded via -r, so all
                              keys are available as @0, @1, @2, etc.

                              Wallet layout (set up by init):
                                @0          The user key (credited on all servers)
                                @1 .. @N    Server private keys (one per server)

                              Key mutations are auto-saved: "cesnet cesh keys gen"
                              and "cesnet cesh keys add <hex>" automatically write
                              back to the workspace wallet (no -w flag needed).
                              New keys appear as @N+1, @N+2, etc.

Global commands:
  nuke                        Kill ALL running ces processes.

Examples:
  # Set up and launch a 3-server network:
  cesnet init 3
  cesnet up

  # Check server status:
  cesnet status

  # Get server addresses and keys as JSON:
  cesnet info

  # Query user (@0) balance on server 0:
  cesnet cesh --server 127.0.0.1:54000 query @0

  # Local transfer on server 0 (user to user, same ledger):
  cesnet cesh --server 127.0.0.1:54000 -a @0 transfer @0 1000

  # Cross-transfer from server 0 to server 1:
  cesnet cesh --server 127.0.0.1:54000 -a @0 \\
    cross @0 100000000 "127.0.0.1:54001"

  # Check user balance on server 1 after cross-transfer:
  cesnet cesh --server 127.0.0.1:54001 query @0

  # Generate a new key (auto-saved to workspace wallet):
  cesnet cesh keys gen

  # List all wallet keys:
  cesnet cesh keys list

  # Credit an account on a specific server:
  cesnet credit 0 500000000 <pubkey>

  # Lifecycle:
  cesnet down                 Stop servers (data survives).
  cesnet up                   Relaunch from existing data.
  cesnet destroy              Delete everything.

  # Use a custom workspace:
  cesnet --home ./other init 5
  cesnet --home ./other up
`);
    process.exit(1);
}
