// Process helpers that cesnet and cesnetbot share. They wait for an event (a
// server ends, a server answers), not for a guessed time.

import { spawn, spawnSync } from "node:child_process";
import { readFileSync, openSync, closeSync } from "node:fs";
import { join } from "node:path";

// The longest wait for a server to stop or to answer. A debug build on a busy
// machine can need many seconds. This limit only ends a wait that cannot end.
export const SERVER_WAIT_LIMIT_MS = 60_000;

const sleepCell = new Int32Array(new SharedArrayBuffer(4));

export function sleep(ms) {
  Atomics.wait(sleepCell, 0, 0, ms);
}

// True while the process exists and is not a zombie. A zombie is a child that
// ended before its parent reaped it, and it still answers kill(pid, 0).
export function isAlive(pid) {
  try { process.kill(pid, 0); } catch { return false; }
  let stat;
  try { stat = readFileSync(`/proc/${pid}/stat`, "utf8"); } catch { return true; }
  const close = stat.lastIndexOf(")");   // the name in parentheses can hold ")"
  return stat[close + 2] !== "Z";
}

// Poll `cond` every `everyMs` until it is true or `limitMs` passes.
export function waitUntil(cond, limitMs = SERVER_WAIT_LIMIT_MS, everyMs = 50) {
  const end = Date.now() + limitMs;
  for (;;) {
    if (cond()) return true;
    if (Date.now() >= end) return false;
    sleep(everyMs);
  }
}

// Send SIGTERM to each server and wait until all of them end. A server saves
// its data when it stops, and only then frees its port and its data directory.
// Returns the pids that did not end inside the limit.
export function stopServers(pids) {
  const live = pids.filter((pid) => pid && isAlive(pid));
  for (const pid of live) {
    try { process.kill(pid, "SIGTERM"); } catch {}
  }
  waitUntil(() => live.every((pid) => !isAlive(pid)));
  return live.filter(isAlive);
}

export function launchServer(cesBin, dir, idx) {
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

// Wait until the server answers a query for its own key. Returns false when
// the process ends first (for example, when it cannot bind its port), or when
// the limit passes.
export function waitServerUp(ceshBin, pid, port, pub) {
  return waitUntil(() => {
    if (!isAlive(pid)) return true;
    const r = spawnSync(ceshBin, ["--server", `127.0.0.1:${port}`, "query", pub],
                        { stdio: "ignore", timeout: 10_000 });
    return r.status === 0;
  }, SERVER_WAIT_LIMIT_MS, 200) && isAlive(pid);
}
