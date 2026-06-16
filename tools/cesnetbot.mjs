#!/usr/bin/env node
//
// cesnetbot - simulated user traffic on a cesnet workspace.
//
// Generates users, credits them, then fires parallel transfers
// (local and cross-server). Verifies balance conservation at the end.

import { execSync, spawn as nodeSpawn, spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync, openSync, closeSync } from "node:fs";
import { join, resolve } from "node:path";

const PROJECT_ROOT = resolve(import.meta.dirname, "..");
const MANIFEST = "cesnet.json";
const USER_CREDIT = 1_000_000_000;
const PEER_LIQUIDITY = 1_000_000_000_000;
const USER_CREDIT_INIT = 1_000_000_000_000;

// Cached binary paths (resolved on first use)
let ceshBinCached = null;
let cesBinCached = null;
function ceshBin() { return ceshBinCached ??= findBinary("cesh"); }
function cesBin() { return cesBinCached ??= findBinary("ces"); }

// ---- Utilities ----

function findBinary(name) {
  for (const build of ["debug", "relwithdebinfo", "release"]) {
    const p = join(PROJECT_ROOT, "build", build, name);
    if (existsSync(p)) return p;
  }
  throw new Error(`Cannot find ${name} binary. Run build.sh first.`);
}

function sleep(ms) {
  spawnSync("sleep", [String(ms / 1000)]);
}

function isAlive(pid) {
  try { process.kill(pid, 0); return true; } catch { return false; }
}

function loadManifest(dir) {
  const p = join(dir, MANIFEST);
  if (!existsSync(p)) {
    console.error(`Not a cesnet workspace: ${dir}`);
    console.error(`Run 'cesnet init <N>' first, or use --home <dir>.`);
    process.exit(1);
  }
  return JSON.parse(readFileSync(p, "utf8"));
}

// ---- Sync cesh (for setup/queries) ----

function ceshSync(dir, args) {
  const walletFile = join(dir, "wallet");
  const result = spawnSync(ceshBin(), ["-r", walletFile, ...args], {
    encoding: "utf8",
    timeout: 10000,
  });
  return { ok: result.status === 0, stdout: result.stdout || "", stderr: result.stderr || "" };
}

// ---- Async cesh (for parallel transfers) ----

function ceshAsync(dir, args) {
  return new Promise((resolve) => {
    const walletFile = join(dir, "wallet");
    const child = nodeSpawn(ceshBin(), ["-r", walletFile, ...args], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "", stderr = "";
    child.stdout.on("data", (d) => { stdout += d; });
    child.stderr.on("data", (d) => { stderr += d; });
    child.on("close", (code) => {
      const ok = code === 0 && stdout.includes("Success");
      const err = ok ? "" : (stderr.trim() || stdout.trim().split("\n").pop() || "unknown");
      resolve({ ok, err, stdout });
    });
  });
}

function queryBalance(dir, serverAddr, pubkey) {
  const r = ceshSync(dir, ["--server", serverAddr, "query", pubkey]);
  if (!r.ok) return null;
  const m = r.stdout.match(/Balance:\s*(-?\d+)/);
  return m ? parseInt(m[1]) : null;
}

// ---- Help & Args ----

function printHelp() {
  console.log(`cesnetbot - parallel simulated user traffic on a cesnet workspace

Usage: cesnetbot run [options]

Options:
  --home <dir>     Workspace directory (default: ./mynet)
  --users <N>      Number of simulated users (default: 3)
  --rounds <N>     Number of transfer rounds (default: 20)
  --amount <N>     Transfer amount per round (default: 1000)

The workspace must be initialized (cesnet init) and running (cesnet up).
Bot users are generated as new wallet keys and credited on random servers.
Each round, all users fire transfers in parallel (local or cross-server).
At the end, total balances are verified for conservation against total minted.

Exit code 0 if zero operation failures and balances conserved, 1 otherwise.`);
}

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = { home: resolve("mynet"), users: 3, rounds: 20, amount: 1000 };

  if (!args.length || args[0] !== "run") {
    printHelp();
    process.exit(args.some((a) => a === "--help" || a === "-h") ? 0 : 1);
  }

  for (let i = 1; i < args.length; i++) {
    if (args[i] === "--home" && args[i + 1]) opts.home = resolve(args[++i]);
    else if (args[i].startsWith("--home=")) opts.home = resolve(args[i].slice(7));
    else if (args[i] === "--users" && args[i + 1]) opts.users = parseInt(args[++i]);
    else if (args[i] === "--rounds" && args[i + 1]) opts.rounds = parseInt(args[++i]);
    else if (args[i] === "--amount" && args[i + 1]) opts.amount = parseInt(args[++i]);
  }
  return opts;
}

// ---- Main ----

async function main() {
  const opts = parseArgs();
  const dir = opts.home;
  const manifest = loadManifest(dir);
  const servers = manifest.servers;
  const n = servers.length;

  if (n < 2) {
    console.error("Need at least 2 servers for cross-transfer testing.");
    process.exit(1);
  }

  if (!existsSync(join(dir, "cesnet.pids"))) {
    console.error("Network not running. Run 'cesnet up' first.");
    process.exit(1);
  }

  console.log(`cesnetbot: ${opts.users} users, ${opts.rounds} rounds, ${n} servers`);

  // ---- Setup: generate keys (serial, writes wallet) ----

  const walletBefore = ceshSync(dir, ["keys", "list"]);
  const existingKeys = (walletBefore.stdout.match(/@\d+/g) || []).length;

  for (let i = 0; i < opts.users; i++) {
    ceshSync(dir, ["keys", "gen", "-w", join(dir, "wallet")]);
    if ((i + 1) % 10 === 0 || i + 1 === opts.users)
      process.stdout.write(`\r  Generating keys... ${i + 1}/${opts.users}`);
  }
  console.log("");

  const walletAfter = ceshSync(dir, ["keys", "list", "-p"]);
  const keyLines = walletAfter.stdout.trim().split("\n").filter((l) => l.includes("@"));
  const botUsers = [];
  for (let i = existingKeys; i < keyLines.length; i++) {
    const m = keyLines[i].match(/@(\d+).*\((\w+)\)/);
    if (m) {
      botUsers.push({ walletIdx: parseInt(m[1]), pub: m[2], homeServer: i % n });
    }
  }

  if (botUsers.length < opts.users) {
    console.error(`Only generated ${botUsers.length}/${opts.users} bot users.`);
    process.exit(1);
  }

  // ---- Setup: credit users (serial, stops/restarts servers) ----

  const pidFile = join(dir, "cesnet.pids");
  const pids = existsSync(pidFile) ? JSON.parse(readFileSync(pidFile, "utf8")) : [];

  // Group credits by server to minimize stop/restart cycles
  const creditsByServer = {};
  for (const u of botUsers) {
    const sIdx = u.homeServer;
    if (!creditsByServer[sIdx]) creditsByServer[sIdx] = [];
    creditsByServer[sIdx].push(u);
  }

  let creditsDone = 0;
  const serverKeys = Object.keys(creditsByServer);
  for (const sIdxStr of serverKeys) {
    const sIdx = parseInt(sIdxStr);
    const users = creditsByServer[sIdx];
    const configFile = join(dir, `server${sIdx}.toml`);
    const wasRunning = pids[sIdx] && isAlive(pids[sIdx]);

    if (wasRunning) {
      process.stdout.write(`\r  Crediting: stopping server${sIdx}...`);
      try { process.kill(pids[sIdx], "SIGTERM"); } catch {}
      sleep(500);
    }

    for (const u of users) {
      execSync(`${cesBin()} --config ${configFile} credit ${USER_CREDIT} ${u.pub}`,
        { stdio: "ignore" });
      creditsDone++;
      if (creditsDone % 5 === 0 || creditsDone === botUsers.length)
        process.stdout.write(`\r  Crediting... ${creditsDone}/${botUsers.length} (server${sIdx})   `);
    }

    if (wasRunning) {
      process.stdout.write(`\r  Crediting: restarting server${sIdx}...          `);
      const logFile = join(dir, `server${sIdx}.log`);
      const logFd = openSync(logFile, "a");
      const child = nodeSpawn(cesBin(), ["--config", configFile, "-x"], {
        stdio: ["ignore", logFd, logFd],
        detached: true,
      });
      child.unref();
      closeSync(logFd);
      pids[sIdx] = child.pid;
    }
  }

  if (pids.length) {
    writeFileSync(pidFile, JSON.stringify(pids));
    process.stdout.write(`\r  Waiting for servers to restart...               `);
    sleep(1000);
  }
  console.log(`\r  Credited ${botUsers.length} users across ${serverKeys.length} servers.       `);

  // ---- Run rounds (parallel within each round) ----

  let localOk = 0, localFail = 0, crossOk = 0, crossFail = 0;
  let totalMoved = 0;
  const failures = [];
  const rand = (max) => Math.floor(Math.random() * max);

  // A cross-transfer can transiently fail with UNKNOWN_PEER while the origin
  // server's peer miner hasn't probed the destination peer yet (reachability is
  // set asynchronously, and a missed probe is only retried every
  // peer_miner_interval). Retry such failures briefly so the test isn't flaky on
  // a startup / re-probe race — settlement still has to conserve credits to pass.
  const asleep = (ms) => new Promise((res) => setTimeout(res, ms));
  const execOp = async (op) => {
    let r = await op.run();
    let tries = 0;
    while (!r.ok && op.type === "cross" &&
           /unknown.?peer/i.test(r.err) && tries < 8) {
      await asleep(1500);
      r = await op.run();
      tries++;
    }
    return r;
  };

  for (let round = 1; round <= opts.rounds; round++) {
    // Build all transfers for this round
    const ops = [];

    for (const user of botUsers) {
      const srcServer = servers[user.homeServer];
      const srcAddr = `127.0.0.1:${srcServer.port}`;
      const destUser = botUsers[rand(botUsers.length)];
      const doCross = rand(2) === 0 && n > 1;

      if (doCross) {
        const otherServers = servers.filter((s) => s.port !== srcServer.port);
        const destServer = otherServers[rand(otherServers.length)];
        const destAddr = `127.0.0.1:${destServer.port}`;

        ops.push({
          type: "cross",
          run: () => ceshAsync(dir,
            ["--server", srcAddr, "-a", `@${user.walletIdx}`,
             "cross", destUser.pub, String(opts.amount), destAddr]),
          desc: `@${user.walletIdx}→@${destUser.walletIdx} ${srcAddr}→${destAddr}`,
        });
      } else {
        ops.push({
          type: "local",
          run: () => ceshAsync(dir,
            ["--server", srcAddr, "-a", `@${user.walletIdx}`,
             "transfer", destUser.pub, String(opts.amount), "--open"]),
          desc: `@${user.walletIdx}→@${destUser.walletIdx} on ${srcAddr}`,
        });
      }
    }

    // Fire all in parallel, wait for all to complete (cross ops retry briefly
    // on a transient UNKNOWN_PEER reachability race; see execOp above).
    const results = await Promise.all(ops.map((op) => execOp(op)));

    for (let i = 0; i < results.length; i++) {
      const r = results[i];
      const op = ops[i];
      if (r.ok) {
        if (op.type === "cross") { crossOk++; } else { localOk++; }
        totalMoved += opts.amount;
      } else {
        if (op.type === "cross") { crossFail++; } else { localFail++; }
        failures.push(`${op.type.toUpperCase()} FAIL round=${round} ${op.desc} amt=${opts.amount}: ${r.err}`);
      }
    }

    const total = localOk + localFail + crossOk + crossFail;
    process.stdout.write(
      `\r  round ${round}/${opts.rounds}` +
      ` | local: ${localOk} ok ${localFail} fail` +
      ` | cross: ${crossOk} ok ${crossFail} fail` +
      ` | total: ${total} | moved: ${totalMoved}   `
    );
  }

  console.log("\n");

  // Build complete set of all pubkeys in the system:
  // bot users + @0 user + all server keys
  const allPubs = new Set(botUsers.map((u) => u.pub));
  allPubs.add(manifest.user.pub);
  for (const s of servers) allPubs.add(s.pub);
  const pubList = [...allPubs];

  // Total minted = peer liquidity + @0 user + bot users
  const totalMintedAll =
    n * (n - 1) * PEER_LIQUIDITY +
    n * USER_CREDIT_INIT +
    botUsers.length * USER_CREDIT;

  // Wait for async settlement, then verify conservation.
  // Polls every 2s for up to 60s. Final poll result IS the verification.
  //
  // Each server's OWN account on ITSELF is excluded from the sum: it's
  // the operator's bottomless reserve (auto-topped near INT64_MAX
  // every boot), deliberately outside "credits in circulation." The
  // same server's pubkey on OTHER servers (peer-liquidity / vostro)
  // IS counted — that's real balance held by one server with another.
  function sumAllBalances() {
    let sum = 0;
    for (const pub of pubList) {
      for (const s of servers) {
        if (pub === s.pub) continue; // server's own reserve, uncounted
        const bal = queryBalance(dir, `127.0.0.1:${s.port}`, pub);
        if (bal !== null) sum += bal;
      }
    }
    return sum;
  }

  let totalBalance = 0;
  for (let attempt = 0; attempt < 30; attempt++) {
    sleep(2000);
    totalBalance = sumAllBalances();
    process.stdout.write(`\r  Verifying... ${attempt * 2}s (${totalBalance}/${totalMintedAll})`);
    if (totalBalance === totalMintedAll) break;
  }
  console.log(totalBalance === totalMintedAll ? " ok." : " timeout.");

  const conserved = totalBalance === totalMintedAll;

  // ---- Summary ----

  console.log("\n=== Summary ===");
  console.log(`Rounds:          ${opts.rounds}`);
  console.log(`Local transfers: ${localOk} ok, ${localFail} failed`);
  console.log(`Cross transfers: ${crossOk} ok, ${crossFail} failed`);
  console.log(`Total moved:     ${totalMoved}`);
  if (failures.length) {
    console.log("\nFailures:");
    for (const f of failures) console.log(`  ${f}`);
  }
  console.log(`\nConservation:    minted=${totalMintedAll} actual=${totalBalance} ${conserved ? "PASS" : "FAIL"}`);

  const totalFails = localFail + crossFail;
  const pass = conserved && totalFails === 0;
  console.log(pass ? "\nTEST PASS" : "\nTEST FAIL");
  process.exit(pass ? 0 : 1);
}

main();
