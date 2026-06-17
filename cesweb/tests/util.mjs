// Shared helpers for the cesweb test harness.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Engine } from '../src/engine.js';

const here = path.dirname(fileURLToPath(import.meta.url));
export const FAKECESH = path.join(here, 'fakecesh.mjs');
export const SERVER = path.join(here, '..', 'src', 'server.js');

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function tmpDir(prefix = 'cesweb-test-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

export function writeFixture(dir, obj) {
  const p = path.join(dir, 'fixture.json');
  fs.writeFileSync(p, JSON.stringify(obj));
  return p;
}

// An Engine wired to the fake cesh + a fresh cache dir. Tighten the timers so
// state-machine tests run in well under a second.
export function makeEngine(cacheDir, fixturePath, opts = {}) {
  process.env.FAKECESH_FIXTURE = fixturePath;
  const e = new Engine({
    cesh: FAKECESH,
    cacheDir,
    progressIntervalMs: 25,
    evictIntervalMs: 100000,   // tests trigger eviction via fills, not the timer
    resolveTtlMs: 60000,
    allowPrivateHosts: true,   // the fake-cesh harness talks to localhost
    log: () => {},             // quiet
    ...opts,
  });
  return e.start();
}

// Poll fn() until it returns a truthy value, or throw on timeout.
export async function waitFor(fn, { timeout = 5000, interval = 15 } = {}) {
  const t0 = Date.now();
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() - t0 > timeout) throw new Error('waitFor: timed out');
    await sleep(interval);
  }
}

// Drive an entry by re-requesting it until it reaches `want` state.
export async function waitState(engine, host, port, cesPath, want, o) {
  return waitFor(() => {
    const s = engine.requestContent(host, port, cesPath);
    return s.state === want ? s : false;
  }, o);
}
