# cesweb

An HTTP gateway that serves CES content to ordinary browsers. CES servers speak
only UDP; cesweb is the door in from the web. It speaks no CES itself — it shells
out to the `cesh` CLI (silent/pipe mode, `-q`) and translates HTTP ↔ cesh. Pure
userspace, additive, deployable next to any web server. CES is sealed and
unchanged by this project.

It is an instrument (reach + visibility into live, sovereign CES servers), not a
website host or a CDN. Caching exists only to amortize the gateway's own
per-read cost, not as a feature.

## Two scopes

1. **Files (done).** READ a file from a server's L2 file store and serve it,
   Content-Type guessed from the URL extension. The gateway holds a wallet and
   **pays** the read fee on the target server; it caches to amortize. This is the
   `/<host>/<path>` URL space.

2. **Dev tools (done).** Interactive things under `/dev`. Currently `/dev/dial`:
   a browser terminal into a running CES compute instance (a Lua L2 program,
   e.g. `/s/dice`). These run on **the user's own key** — pasted in the page,
   signed in the browser, never sent to the gateway — and the **user** pays for
   the session. So they are NOT namespaced to a server in the URL; you pick the
   server in the page.

3. **Metadata / wallet (later).** Account/asset/server-info as a block explorer;
   a web wallet for signed ops. Design notes: `../local/web.md`.

The split is the whole economic model: **files are on the gateway's dime; `/dev`
is on yours.** cesweb never holds your key for either.

## Architecture: responder + engine

Split so a slow CES read can never block a web request.

- **`src/server.js` — the responder.** Per request: parse the URL, ask the
  engine for the content's current state, render it (a ready cache file, streamed
  + Range-capable → a sitrep page that auto-refreshes while work happens → an
  error page). It also serves the home page, the `/dev` index, the `/dev/dial`
  terminal page, and `/status` (engine state as JSON), and owns the
  WebSocket upgrade for the terminal. It never fetches, validates, evicts, or
  awaits anything but a local file stream.

- **`src/engine.js` — the content engine. The cache IS the filesystem.** Content
  lives at its natural path, `cache/<host>/<cesPath>`, and the file's own **size +
  mtime ARE its metadata** (mtime is set to the CES file's `modifiedUs`). No hash,
  no sidecar, no in-RAM index of cached files — the OS owns the index, so the
  gateway boots instantly and scales with the filesystem. The engine resolves
  hosts, STATs, downloads (watching the growing `.part` for live progress),
  revalidates ready files, refills changed ones (serving the old copy until the
  new one is renamed in), and sweeps. Nothing it does touches the request path.

Identity = **(host, cesPath)**. Serving needs no resolve: the responder maps a
request straight to its `cache/<host>/<cesPath>` and `stat`s it — a real FILE
there is a hit. Resolving (`ping` → rpc port + server key, bounded-LRU resolve
cache) is only needed to *fetch*. Per-request states:
`resolving → statting → queued → downloading → ready` (or `failed`). READY ⇒ the
responder serves; FAILED ⇒ error page; anything else ⇒ sitrep. There is no
recovery step — a restart serves the on-disk tree immediately.

**Revalidation** compares the CES STAT's `size`/`modifiedUs` against the cached
file's `size`/`mtime` (so even a *same-size* change is caught), on a TTL, in the
background; an upstream deletion drops the cache file.

**A file↔directory type change at a path is the invalidation signal**, not a
collision: the CES source store can't have both, and the server tells us which
via signed STAT, so the stale node (a file where a dir is now needed, or a dir
where a file is) is removed and replaced with what the server reports.

**Path traversal is contained** (security-critical): `cesPath` is caller-driven,
so `_fsPath` rejects `..`/`.`/control-chars and asserts the result stays under
`cache/<host>/`.

**Eviction is insertion-driven and disk-bounded — no sweep, no RAM index.** The
LRU signal is the filesystem's own `atime` (the OS bumps it when a file is
served), so a million cached files cost zero RAM. Before the worker caches a new
file it checks free disk (`statfs`, O(1)); only if free is below `minFreeBytes`
does it walk and **list** candidates (never deleting mid-walk), stopping when it
has listed enough files idle past `maxAgeMs` to cover the need (after a `minScan`
sample, so small caches get a full eval), or at `maxScan` (RAM guard), or at the
walk's end. Then it deletes oldest-first until the need is met — preferring idle
files, falling back to reaping the oldest recent ones. CPU is spent only under
disk pressure; latency under load is unbounded by design (requests wait).
`maxFileBytes` refuses any single file bigger than itself.

## Security: no key to the server, and no SSRF

- **The browser holds the key.** For `/dev/dial`, the page imports the pasted
  ed25519 key with native WebCrypto (non-extractable) and signs the CesPlex bind
  + ATTACH itself. cesweb only relays the signatures into `cesh dial --extsign`.
  The private key never reaches the gateway. ed25519 only — no native Ed25519 in
  the browser ⇒ the page errors (WebCrypto has no secp256k1).

  Why paste-a-key is safe: a Lua L2 program has **zero spending authority** over
  a connected user. `account_read` is read-only; its `TRANSFER` moves the
  *program's* money; CES has no pull/allowance. You only ever lose credits via a
  transfer **you** sign (dice's bet is an out-of-band `cesh transfer` it merely
  *verifies*). The bind key is identity + the channel meter's payer (infra,
  `feeNet*`, ≈0 idle), never an app-spend authorization.

- **No open proxy / SSRF.** Two layers: (1) `CESWEB_ALLOW_HOSTS` allowlist; and
  (2) the engine refuses any host that resolves to a non-globally-routable
  address — loopback, RFC1918, link-local, CGNAT, ULA, multicast, etc. — checking
  **every** A/AAAA record (`isGloballyRoutable` / `_assertRoutable` in
  `engine.js`). So `localhost` and internal IPs can't be dialed even if
  allow-listed. `CESWEB_ALLOW_PRIVATE_HOSTS=1` disables the routability check —
  used ONLY by the test harness and `live.sh`, never in production. A
  consequence: the gateway reaches even its own co-located CES server by its
  **public** name, not `localhost`.

- **Trust.** cesweb terminates TLS, so the browser trusts the gateway, not the
  origin (the Tor/IPFS-gateway deal). A later trust-minimized tier could
  re-verify CES signatures in-browser.

## URL grammar

**Files** — the server lives in the path:

```
/<host>[-<ces-port>]/<ces-zone-path>
```

Anchors on the server's **primary** (CES) port; the gateway resolves the rpc port
+ server key from it for free via `cesh ping` (MINX GetInfo). `-53830` is
omittable (defaults to `CESWEB_DEFAULT_CES_PORT`). Host may contain dashes; the
port is only a trailing `-<digits>`. **The host must be a DNS name — IP literals
(v4 and v6) are rejected** (`400`), so the cache dir is always the name verbatim
(filesystem-safe, no lossy rewrite, no collisions). The remainder is the **verbatim CES path** —
the CES zone namespace IS the URL namespace. Zones: `/h/ /f/ /p/ /s/` (only `/s/`
lists its contents). A trailing `/` ⇒ `index.html`.

With `CESWEB_DEFAULT_HOST` set, a host-less path (`/p/site/index.html`) resolves
to that host — the clean single-server form.

**Dev terminal** — `/dev` (index) and `/dev/dial` (the terminal). The terminal's
real inputs (server host:port + instance pid + key) are entered IN the page and
ride the WebSocket `hello` frame, not the URL — the session is on the user's key,
so it isn't tied to a server. `/dev/dial/<host>[-port]/<pid>` may *prefill* the
page's boxes (`parseDialPath`), but the WebSocket endpoint is the fixed
`/dev/dial`.

## The home page

`src/server.js` `landing()` is a short, plain manual that adapts to the config:

- Names the **default server** and shows that host-less paths resolve to it; lists
  other reachable servers (allowlist, minus the default and minus anything
  plainly private) or the open `/<host>/` form.
- Shows the gateway's **live balance on the default server** — `queryBalance`
  (free unsigned `cesh query`) refreshed in the background (~120 s), cached in
  `GATEWAY_BALANCE`, degrading to "unavailable" if it can't be read.
- The funding ask uses **`cesh transfer`** (anyone can send the gateway credits
  on that server) and notes the operator can `ces credit` it for free. `ces
  credit` is operator-only (offline, server-side); donors use `transfer`.

## Economics

Reads are paid: cesweb holds a wallet and pays `feeQuery`+`feeFileRead` on the
target server, from its account **on that server** (same key identity
everywhere). That's the feature, not a blocker:

- It caches to amortize: pay the read once, serve many.
- Idle ≈ 0 via the server's feemult.
- If the gateway operator IS the CES node operator, the wallet can be the node's
  **bottomless** account → serving your own content costs nothing (and its
  balance reads as the boot-reset `2^50`).
- Out of credit on a server ⇒ that server's file pages return **402** naming the
  account, so users can fund it. `/dev` sessions are unaffected (user-paid).

## cesh key format — CRITICAL, do not mangle (this cost a long debug)

- A wallet line / `cesh keys list` entry is the **decorated PRIVATE key**:
  leading `00`=ed25519 / `01`=secp256k1 (the algorithm — **part of the key**, not
  padding) + 64-hex = **66 hex chars**. `keys list` does NOT print the pubkey.
- The **public key** = the account identity to credit/query/transfer-to (64 hex,
  no decorator). Get it from `ces --genkeypair` (`Public Key:` line), the
  parenthesized value in `cesh keys gen`, or `cesh keys list -p`. **NEVER**
  `grep -oE '[0-9a-fA-F]{64}'` a keys-list line — that grabs decorator + 31 bytes
  of the privkey → a mangled key.
- Funding the wrong hex is silently self-consistent: `ces credit` and `cesh
  query` agree, but signed/L2 ops reject it as `CES_ERROR_ORIGIN_NOT_FOUND`.
  Symptom: an account that works for `query` but fails signed ops → wrong key.

## Config (env vars)

- `CESWEB_PORT` (8088) / `CESWEB_BIND` (127.0.0.1)
- `CESWEB_CESH` — path to the `cesh` binary (default `cesh` on PATH)
- `CESWEB_DEFAULT_CES_PORT` (53830) — assumed when a URL omits `-<port>`
- `CESWEB_DEFAULT_HOST` — serve host-less paths (`/p/...`) against this host
- `CESWEB_ALLOW_HOSTS` — comma list; empty = open. Use the **public** name(s);
  never `localhost`.
- `CESWEB_ALLOW_PRIVATE_HOSTS` — `1` disables the non-routable-host refusal.
  Tests + `live.sh` only. NEVER set in production.
- `CESWEB_WALLET_FILE` or `CESWEB_WALLET` (inline) — the gateway's wallet
- `CESWEB_PUBKEY` — gateway account (else derived at boot via `keys list -p`)
- `CESWEB_CACHE_DIR` (`<cwd>/cache`) — the cache tree (`cache/<host>/<cesPath>`)
- `CESWEB_MAX_FILE_MB` (1024) — refuse (413) any single file bigger than this
- `CESWEB_MIN_FREE_MB` (2048) — keep this much disk free; eviction triggers below it
- `CESWEB_MAX_AGE_HOURS` (24) — a file idle longer than this is freely evictable
- `CESWEB_MAX_INFLIGHT` (1) — fetch workers; misses queue and wait (cache hits aren't gated)
- `CESWEB_VALIDATE_TTL_MS` (15000) — trust a stat-validation this long
- `CESWEB_RESOLVE_TTL_MS` (60000) — reuse a host's resolved rpcPort/key this long
- `CESWEB_MAX_RESOLVE_ENTRIES` (4096) — hard cap on the resolve cache (host→identity); LRU-evicted, since the host-spelling key space is caller-controlled on the open `/<host>/` form
- `CESWEB_MAX_STATUS_ITEMS` (200) — cap on the `/status` items list (live entries only; the cache itself is never enumerated)
- `CESWEB_GET_TIMEOUT_MS` (900000) — hard cap on one fill
- `CESWEB_STALL_TIMEOUT_MS` (60000) — kill a fill that makes no progress
- `CESWEB_FAIL_TTL_MS` (10000) — cache a failure this long before retrying

Dev terminal (`/dev/dial`) bounds:
- `CESWEB_MAX_TERMINALS` (8) / `CESWEB_MAX_TERMINALS_PER_IP` (2)
- `CESWEB_TERM_IDLE_MS` (600000) / `CESWEB_TERM_MAX_MS` (1800000) — idle + lifetime
- `CESWEB_TERM_INPUT_BPS` (2048) / `CESWEB_TERM_MAX_MSG` (4096) — input rate + frame cap
- `CESWEB_TERM_MAX_BYTES` (4 MiB) / `CESWEB_TERM_OUT_BUF` (1 MiB) — ceiling + backpressure

## Layout

```
src/server.js   HTTP responder: routes, home/dev pages, the /dev/dial terminal
                page + its WebSocket upgrade, status endpoint, range serving.
                Holds the cached gateway balance.
src/engine.js   filesystem-backed cache (one worker, no RAM index): maps
                (host, cesPath) -> cache/<host>/<cesPath> (size+mtime are the
                metadata, atime is the LRU); resolve(+SSRF guard) / stat /
                download(+progress) / revalidate / refill / file<->dir
                invalidation / disk-bounded age-first eviction on insert.
                Owns the resolve cache. Exports isGloballyRoutable / hostOf /
                fmtBytes.
src/cesh.js     spawn-cesh: runCesh / ping / queryBalance / stat /
                spawnFileGet(engine primitive) / gatewayPubkey
src/term.js     dev terminal: WebSocket ↔ `cesh dial <pid> --extsign` bridge.
                Target (server+pid) + allow-check from the hello frame; bounded
                pool + live-traffic limits; pure signature relay (no key).
src/url.js      parseRequestPath: /<host>[-port]/<zone-path>;
                parseDialPath: /dev/dial/… (optional prefill)
src/mime.js     extension → Content-Type (octet-stream fallback)
src/cessign.js  CES signing in JS (@noble/curves) — the byte-exact reference the
                browser's WebCrypto path matches; used by tests + the dice e2e.
scripts/live.sh        long-running local CES box + sample site + gateway, for
                       browsing (`npm run live`); CES-free `npm test` is separate
scripts/diceweb.sh + diceweb-client.mjs   e2e: real CES + /s/dice played over a
                       WebSocket; the ONE test that runs JS signing vs real CES
tests/          node --test. fakecesh.mjs scripts the cesh child (file get + dial
                modes; no real CES server). engine/routable = state machine + SSRF
                guard; server = HTTP; term = WebSocket terminal; cessign/webcrypto
                = signing byte-equivalence.
```

## Run

```bash
npm install                   # once — deps: ws, @noble/curves
npm test                      # state machine + HTTP + terminal + signing (no CES box)
npm run e2e:dice              # real CES + /s/dice over a WebSocket (needs a built CES tree)
npm run live                  # long-running local CES box + sample site + gateway, for browsing

# point cesweb at an already-running CES server (cesh built in the parent tree):
CESWEB_CESH=../build/debug/cesh CESWEB_WALLET_FILE=wallet.txt \
CESWEB_DEFAULT_HOST=<host> CESWEB_DEFAULT_CES_PORT=53830 CESWEB_ALLOW_HOSTS=<host> \
node src/server.js
# For a LOCAL server use CESWEB_DEFAULT_HOST=localhost and add
# CESWEB_ALLOW_PRIVATE_HOSTS=1 — the SSRF guard refuses non-routable hosts otherwise.
```

The CES server cesweb fronts must have its **rpc port** and **file store** on
(`rpc_port != 0`, `file_store_max_bytes > 0`); otherwise file pages 502 with "no
file service". (`/dev/dial` additionally needs compute enabled on that server.)

## Deploy

`deploy/deploy.sh` ships cesh + libs + `src/` + `node_modules` + the nginx site +
the systemd unit to `/opt/cesweb`, restarts cesweb, reloads nginx, and
self-checks. It derives the CES tree + cesweb dir from its own location, so it
works wherever the repo lives. Set `HOST=user@server` and `DOMAIN=public.host`
(and `CESHOST` if cesweb fronts a different CES server). ADDITIVE + SAFE: it
never touches `/opt/ces` or the running CES server. `SKIP_BUILD=1` skips the
release rebuild (use it when only the JS/nginx changed).

- `deploy/cesweb.service` / `deploy/nginx-cesweb.conf` — TEMPLATES; deploy.sh
  renders `@@CESHOST@@` / `@@DOMAIN@@` from env at ship time, so they stay
  generic. TLS (`:443`, `:80`→301); `location /dev/dial` forwards the WebSocket
  upgrade and lets sessions stay open (cesweb's own caps bound them). Ubuntu
  24.04 nginx 1.24 rejects `http2 on;` — don't add it.
- `deploy/cache-clear.sh` — `HOST=user@server bash deploy/cache-clear.sh` wipes
  the gateway's `/opt/cesweb/cache` and restarts cesweb, forcing a full refresh.
  Rarely needed (STAT-revalidation catches ordinary changes); for an out-of-band
  same-size+mtime swap STAT can't see. ADDITIVE + SAFE: never touches `/opt/ces`.
- `deploy/README.md` — one-time box setup + the deploy env vars.
