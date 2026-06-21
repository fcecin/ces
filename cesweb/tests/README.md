# cesweb tests

cesweb is a content state machine: the HTTP responder only reads state, while a
background **engine** resolves servers, downloads files (with live progress),
revalidates, refills, evicts, and recovers from faults. These tests pin that
machine.

```bash
npm test          # = node --test
node --test tests/engine.test.mjs    # just the state machine
node --test tests/server.test.mjs    # just the HTTP wiring
```

No real CES server is needed. `fakecesh.mjs` is a controllable stand-in for the
`cesh` CLI in pipe mode: it reads a JSON fixture (`$FAKECESH_FIXTURE`) fresh on
every invocation, so a test scripts the child's behavior — ping success/failure,
stat results, download speed (`drip`), stalls (`stall`), read failures, and
upstream changes (rewrite the fixture between calls) — with zero network.

- **`fakecesh.mjs`** — the fake `cesh`. Fixture shape is documented at its top.
- **`util.mjs`** — `makeEngine` (engine + fake cesh + temp cache, tight timers),
  `writeFixture`, `waitFor`/`waitState`.
- **`engine.test.mjs`** — drives the `Engine` directly: ready/notfound/poor/
  toobig/unreachable, live download progress, stall reaping, the inflight queue,
  LRU eviction under a cap, revalidation refill (stays READY while swapping),
  upstream-deletion eviction, and disk recovery on restart.
- **`server.test.mjs`** — spawns the real `src/server.js` (with `CESWEB_PORT=0`,
  reading the bound port back from its log) against the fake cesh and exercises
  the HTTP surface: cold sitrep → content, Range/206, `/status`, and the
  404 / 402 / 403 / 400 mappings.
