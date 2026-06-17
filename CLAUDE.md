# CES

C++20 public token/credit ledger for resource accounting. Clients earn credits via RandomX PoW mining, spend on transfers/queries/assets. Each server is a sovereign ledger; servers peer via bilateral vostro/reserve settlement. No blockchain.

On top of the ledger sits **CesPlex**, the L1 connection multiplexer on `rpc_port`: it runs the signed bind handshake, routes each bound RUDP channel to a named handler, and meters the channel's raw byte/time usage for the host to price — CesPlex itself knows no credits. The handlers riding it are L2. Shipped in CES core: `builtin:file` (disk file storage), `builtin:compute` (instance lifecycle + Lua hosting), `builtin:lua` (channel attach into a running program). The protocol name `/ces/rpc/1` is reserved and CES ships the SYS_RPC *outbound* engine, but `builtin:rpc` is **not** registered by CES core — inbound RPC is L3 (downstream binaries link ceslib and register their own).

## Coding practices

- **Always use `build.sh`** to build and run tests. Don't invoke `cmake --build` directly; same for `cestests` — go through `./build.sh debug --test` (or `--teste2e`).
- **Always redirect `build.sh` output to a file**, then `tail`/`head`/`grep` it. Don't tail the live pipe — direct pipes lose buffered stdio output, and reading live output fights the test harness for ephemeral ports (phantom port-collision failures). Pattern:

  ```bash
  ./build.sh debug --test 2>&1 > /tmp/ces-build.log
  grep -E 'error:|FAILED|No errors|All Tests passed' /tmp/ces-build.log | tail -5
  ```

- **Never reinvent wire serialization.** The canonical wire-bytes types and API live in `<ces/buffer.h>`: `ces::Bytes` (a heap `vector<uint8_t>` that just *holds* bytes) and `ces::Buffer` (vector-owning, cursor-tracked, auto-growing, with BE/LE `put`/`get`/`peek`/`poke` plus static raw-pointer helpers); `ces/keys.h` adds a `PublicKey` serializer. **DO NOT** hand-roll byte-shift loops, and **DO NOT** type wire data as a bare `std::vector<uint8_t>` — use `ces::Bytes` so the type signals wire intent. (MINX has its own MTU-bounded `minx::Bytes`/`minx::Buffer` for borrowed spans; interop is byte-level. One exception: `cesluajitd`'s supervisor-IPC framing keeps its own minimal helpers, documented inline.)

- **xxx.h ↔ xxx.cpp is law.** Every header in `include/ces/.../<name>.h` has a matching `src/ceslib/<name>.cpp` (or wherever its translation unit lives) under the SAME name. No exceptions — renaming a header renames its cpp. Helps grep, helps mental model, removes naming drift.

- **No "Step N rollout" / "Phase A/B" comments.** Reference what code does today, not which iteration of a design plan it represents. Step numbers rot the moment the next step lands.

## Build

```bash
./build.sh debug                    # debug build
./build.sh release                  # optimized
./build.sh debug --test             # build + unit tests
./build.sh debug --test <filter>    # run matching tests only
./build.sh debug --teste2e          # build + E2E tests
./build.sh debug --asan             # AddressSanitizer
./build.sh rm                       # delete all build dirs
```

Requires: CMake 3.28+, C++20, Boost 1.83+, CryptoPP, LuaJIT, Qt6 (optional).
CMake fetches: MINX, logkv, secp256k1 v0.4.1, CLI11, tomlplusplus, libbacktrace.

## Project layout

```
include/ces/        CES core (L1) — types, account/asset, keys, protocol,
                    server/client, clientasync, cesvm, ramfilestore,
                    autoexec, cesco, cesproxy, feemult, buffer, persisted
include/ces/cesplex/  CesPlex — the L1 connection multiplexer (moved out
                    of l2/):
                      mux     — bus core: bind handshake, channel routing,
                                handler registry, CesPlexHost seam
                      wire    — bind contract + per-op envelope wire format
                      session — per-op serve loop + CesPlexClient (the L2
                                verb SDK file/compute ride; lua bypasses it)
                      meter   — ChannelMeter: per-channel byte/time meter
                                (measures + reports; never prices or closes)
include/ces/l2/     L2 protocols riding CesPlex. Two families:
                      file_*     — disk-backed file storage protocol
                      compute_*  — instance hosting (compute_handler) +
                                   channel-attach (compute_lua_handler) +
                                   client lib (compute_client)
include/ces/util/   shared helpers — ctrlc, fileperm, hash, hex, log,
                    metrics, resolver, vmprogram, wallet
                    Every include/ces/<group>/<x>.h has a matching
                    src/ceslib/<group>/<x>.cpp (the src tree mirrors it).
src/ceslib/         static lib mirroring the include tree — top-level
                    server.cpp (incl. SYS_RPC outbound engine), cesvm.cpp,
                    ramfilestore.cpp, accounts/assets/client/clientasync/
                    cesco; subdirs cesplex/, l2/, util/; builtin_apps/
                    holds operator-deployable app sources (dice.lua)
src/ces/main.cpp    server CLI: config, key gen, ces credit/debit/snapshot
src/cesh/           shell client (main.cpp + dial.cpp/h)
src/cesluajitd/     compute child runtime (LuaJIT-hosted, default)
src/cescompmockd/   no-Lua mock child (regression-test plumbing only)
src/cesproxy/       TCP↔UDP proxy with wire-level validation
src/cesbench/       in-process benchmark
src/cesqt/          Qt6 GUI: 11 tabs + JSON-RPC server (rpcserver.cpp)
tests/              Boost.Test suites compiled into one `cestests` binary
                    (filter by suite name). test_common.h = CesFixture
                    (in-process server+client, 10B prefunded).
tools/cesnet.mjs    network orchestrator (init/up/down/destroy)
tools/cesnetbot.mjs parallel traffic simulator + conservation check
cesweb/             L3 HTTP gateway (Node) serving CES files + a /dev terminal to
                    browsers via the cesh CLI; self-contained, own CLAUDE.md
```

## Data model — the two-type ledger

CES has exactly two ledger types: **Account** and **Asset**. Files, programs, schedules, namespaces, autoexec, the market — all compose out of those two. No separate file/program/namespace tables.

**Account** (map key = first 8 bytes of `sha256(pubkey)`; a key-tail disambiguates prefix collisions):
- `balance` — **sign-overloaded**: positive = ordinary account; negative = unsettled payment account
- `nonce` — replay counter (`reqNonce == nonce+1`), **overloaded** on payment accounts as days-until-expiry
- last-transfer receipt (dest/amount/time) — doubles as the signed single-query payment proof

No type field, no role flags — the sign of balance and the nonce value carry the only state distinction.

**Asset** (map key = full 32-byte hash):
- `owner` — the account or asset prefix that controls the cell
- `balance` — encodes days-remaining (rent) plus flag bits: immutable / asset-owned / private
- `price` — non-zero ⇒ any signer can `CES_BUY_ASSET` for that amount
- `content` — ~210 bytes of arbitrary user bytes

**The asset is the generative primitive.** Files are chains of assets; VM programs are assets (`CES_RUN_ASSET`); autoexec and scheduled runs are key-patterns on assets; `/f/<name>` namespaces are gated by who owns the asset at `sha256("/f/<name>")` (transferable via `CES_GIVE_ASSET`). The fixed ~210-byte cell makes the system extensible without protocol changes.

Asset day-counter is **rent**. Daily maintenance decrements every asset's balance by 1; assets at ≤ 1 die. Keep alive via `CES_FUND_ASSET`.

**PRICE_UNIT = 100,000,000** (8 decimal places). Wire prices are user-facing whole credits; multiply by PRICE_UNIT for internal units.

## Cryptography (`keys.h`)

Two algorithms behind a 1-byte decorator: ED25519 (CryptoPP) and secp256k1 (libsecp256k1, RFC 6979); a signature is the tag byte + 64 bytes. SHA256 over the input unless it's already 32 bytes. The secp256k1 context and CryptoPP PRNG are `thread_local`.

Wallet format: one key per line, `"00" + 64-hex` or `"01" + 64-hex`. Wallets validate keys at insertion.

**Private vs public key — read this before scripting cesh/ces (easy to get wrong):**
- A wallet line / `cesh keys list` entry is the **decorated PRIVATE key**: a leading byte (`00`=ed25519, `01`=secp256k1) **that is part of the key (the algorithm), not padding** — `"00"+64-hex` = **66 hex chars** total. `keys list` is **private-key-prioritized** and does **NOT** print the public key.
- The **public key** is the **account identity** — what you credit, query, and what the ledger keys accounts by (map key = first 8 bytes of the pubkey hash). It is **64 hex chars, no decorator**. `cesh keys gen` shows it in **parentheses** after the private key; `ces --genkeypair` labels `Private Key:` / `Public Key:` cleanly.
- **NEVER** `grep -oE '[0-9a-fA-F]{64}'` a `keys list` line to get an account key — that grabs the decorator byte + the first 31 bytes of the private key (a mangled 64-hex value). Use `ces --genkeypair`'s `Public Key:` line, or the parenthesized value from `cesh keys gen`.
- Funding the wrong hex is **silently self-consistent**: `ces credit <wrong>` and `cesh query <wrong>` agree (both key by the same wrong prefix, so the balance "shows up"), but every **signed/L2 op rejects it as `CES_ERROR_ORIGIN_NOT_FOUND`** because it binds the real key. If a funded account works for `query` but signed ops say ORIGIN_NOT_FOUND, you funded the wrong key.

## Wire protocol (`protocol.h`, `types.h`)

`CES_INJECT_SIGNED_METHODS` / `CES_INJECT_UNSIGNED_METHODS` macros generate `toBytes`/`fromBytes`/`verifySignature`.

**Opcodes** (`op_code_t`) ride the primary UDP port — transfers, account/asset queries, asset CRUD, VM run, and the unsigned peer-table read. The **APPLICATION lane** (`app_code_t`, 0x80+) carries client↔program messages (`CES_APP_COMPUTE_MSG`) over MINX's app path instead of the signed-op path. Result/error codes are `error_code_t`. (These enums move — read `types.h`, don't memorize numbers.)

**Nonce modes**: `0` skip (internal); `CES_NONCELESS (UINT32_MAX)` server assigns (settlement pipelining); `N` must equal `nonce + 1`. Auto-nonce: signed ops carry timestamp; server rejects stale, dedups by sig-hash prefix. **Retried ops must reuse the same signed payload** so dedup returns OK without re-executing.

## CesVM (`cesvm.h`, `cesvm.cpp`)

Harvard architecture; runs on `logicStrand_`; mutations atomic with undo log.

**io[]** (1024 cells × 8 bytes) is the data plane only — registers, program scratch, context, preloaded caller/self keys, and fixed input/output windows; bytecode lives in a separate `code_` buffer indexed by PC. `vmprogram.h`'s bump allocator (`pgm.allocContent()`) hands out typed scratch `Region`s so build code never types raw cell numbers.

**Syscalls** (`cesvm.h`) cover account/asset read + mutate, transfers (local + cross), hashing, sig-verify, code load, scheduling, deposit/withdraw, send-to-client, and outbound `SYS_RPC`. `SYS_SEND_UDP` is tombstoned (returns DISABLED).

**VmProgram** (`vmprogram.h`): C++ fluent API, one method per opcode, label support; emits an asset cell or a byte vector.

**Cron / SYS_SCHEDULE**: enqueues one-shot VM run at absolute wall time; missed deadlines fire ASAP. Recurrence = scheduled VM re-calls SYS_SCHEDULE. Schedule state persisted as ledger entries.

**Autoexec** (`autoexec.h`): boot-time hook. Asset key pattern `[8 zero][8 AUTOEXEC_KEY_MAGIC BE][8 account_prefix][8 random]`; content = signed `CesRunAsset`. Server scans on boot, runs each via `scheduleRun` at `now`.

## L1 RAM filestore — in-asset file chain (`ramfilestore.h`)

In-ledger files as linked asset chains. The head asset holds size + hash + metadata + the first chunk-key; each chunk holds its payload + the next chunk-key. Chunks are uploaded **in reverse order** so each already knows its successor.

API: `ramfilePut`/`ramfileGet`/`ramfileFund`/`ramfileScan` + random-access `ramfileRead`/`Write`/`Append`/`Resize`/`Rehash`. Header struct `RamfileHeader`. VM-reachable via `SYS_LOAD_CODE`/`SYS_READ_ASSET`. cesh verb: `cesh ramfile`. For host-scale disk files, see L2 file handler (`cesh file`).

## CesPlex — L1 protocol multiplexer (`cesplex/mux.h`, `cesplex/wire.h`)

Runs on `rpc_port`. Each inbound RUDP channel does a **signed bind contract**: client signs `(name + client_time + client_pubkey)`; server replies signed, committing server pubkey + per-channel `sessionToken`. The bind is **identity-only — no prices on the wire**. Handler receives `BoundChannelContext` (pubkey, payerPfx, sessionToken, bind time). CesPlex knows no credits: a `ChannelMeter` measures each channel's raw byte/time usage (`CesPlexUsage`) and reports it to the host (`CesPlexHost::cesplexReportUsage`); the host prices it, charges the payer, and closes the channel on non-payment.

Each per-op envelope is verb + preamble + a 65-byte sig over `sha256(verb || preamble || sessionToken)` — no per-op pubkey or timestamp (implicit on the bound channel). Body-bearing verbs append bytes hashed against a digest committed in the preamble. Dedup key = the first 8 sig bytes (per-channel-incarnation, so no cross-channel collisions).

Handlers register via `registerCesPlexBuiltin("<name>", &inst)`; CesServer maps `proto_name → "builtin:<name>"`, freezing the bind table at construction. Errors close the channel (clients reopen). Most handlers **loop** on the channel; exception: `builtin:lua` ATTACH is a one-shot verb that converts the channel into a raw byte stream into the target compute instance.

CES sets `rpcRudpMaxChannelsPerPeer = 2` so a long-lived `cesh dial` can coexist with side ops.

**Handlers shipped (registered in CES core):**
- `/ces/file/1`    → `builtin:file`    — disk-backed file storage. `l2/file_{handler,client}.{h,cpp}`
- `/ces/compute/1` → `builtin:compute` — instance lifecycle (LAUNCH/KILL/LIST/STAT/INSTANCES). `l2/compute_{handler,client}.{h,cpp}`
- `/ces/lua/1`     → `builtin:lua`     — one-shot ATTACH; converts the channel into a raw byte tunnel into a running compute instance. `l2/compute_lua_handler.{h,cpp}`. No client lib (use `cesh dial` for terminal use).

**Compute hierarchy.** The `compute_*` family covers two protocols on the same feature: `compute_handler` runs the management verbs and the per-instance supervisor (CPU/RSS sampling, slot/rent billing); `compute_lua_handler` runs the channel-attach protocol that pipes user bytes into a chosen instance. They are two CesPlexHandler subclasses, but co-engineered — each .cpp #includes both .h files because compute exposes APIs (`computeOpenConnection`, `computeSendConnDataIn`, …) the lua handler calls into, and lua exposes APIs (`luaHandlerHandleConnDataOut`, `luaHandlerOnInstanceDying`, …) compute calls into. They ship together because lua-routing only makes sense given a compute instance to route to.

**`/ces/rpc/1` — protocol name reserved; CES core ships only the outbound engine.** SYS_RPC's outbound side (`RpcSession` + `queueRpc`/`executeRpc`/`completeRpc`) lives in `src/ceslib/server.cpp`; it dials peers, runs the signed bind, exchanges, writes the response into a ramfile, fires a follow-up VM run. There is **no `builtin:rpc` handler in CES core**. The inbound side is L3: downstream binaries (content-servers in C++/Go/JS/whatever) link ceslib and register their own `builtin:rpc`. The in-tree `MockRpcServer` in `tests/test_sysrpc.cpp` is the test fixture for this shape, not a production handler. The asymmetry is the architectural deal: **outbound from CES is one funnel (SYS_RPC); inbound to CES core is zero — the door opens outward, not inward.** A future CES 2.x feature could add a `builtin:rpc` that routes inbound requests into Lua-program providers registered under the compute family.

## ChannelMeter (`cesplex/meter.h`)

Every bound channel tracked. 60s tick computes per-tick deltas across four measured dimensions (bytes sent, bytes received, memory-byte-seconds of RUDP buffer residency, channel age) and reports them as a `CesPlexUsage` to the host via `cesplexReportUsage`. The meter **measures and reports only** — it never prices, charges, or evicts. The host (CesServer) prices the usage at its live `feeNet*` rates, posts the debit on `logicStrand_`, and evicts via `Rudp::closeChannel` if the payer can't cover the tick. Host rates default to 0 = observability-only.

## L2 file storage — `builtin:file` (v2)

Disk-backed, priced per byte/day (rent) and per KB (I/O), namespaced. Ten verbs preamble-first (envelope sig over preamble before any body — verify+charge before touching body). Every response server-signed with `req_sig_hash`.

**Verbs:** CREATE (any) / WRITE (owner) / READ (any signer) / STAT (any signer; metadata only) / DEPOSIT (any) / WITHDRAW (owner) / SET_PRICE (owner) / DELETE (owner) / APPEND (owner) / RESIZE (owner). (There is **no unsigned path** in CesPlex — STAT, like every verb, rides the signed bind and pays `feeQuery`; "free" only ever meant ≈0 at idle via feemult.)

**Four-zone naming (mandatory):**
- `/h/<64-hex-pubkey>/...` — auto home dir; signer must match the hex
- `/f/<name>/...` — asset-gated; signer must own asset at `sha256("/f/<name>")`. Transferable via `CES_GIVE_ASSET`.
- `/p/...` — public; first-come-first-served on exact path
- `/s/...` — **server-deployed**, unmetered, outside the cap. Only the server's own private key may CREATE/WRITE; reads operator-donated. Used for curated programs (`/s/chat.lua` etc.). **Auto-indexed:** the handler keeps a generated `/s/index.html` catalog of the zone, regenerated on every `/s/` file-set change and at boot if missing (`regenerateServerIndex`, pure disk on the file strand — never `logicStrand_`). `/s/` is the **only** zone that's enumerable, and safely so: it's operator-write-only, so listing it leaks no untrusted content. Every other zone is deliberately non-enumerable (no LIST verb exists) — the path is the capability; knowing it is the access.

Anything else → `BAD_NAME`. Zone ownership checked **only at CREATE**; subsequent ops use sidecar's stamped `owner_pubkey`.

**Three-cost model:**
- `feeFileRent` — credits per byte×day; drains `file_balance`
- `feeFileWrite` — per KB; drains `file_balance` at WRITE/APPEND
- `feeFileRead` — per KB; drains reader's account (burned; even owner pays)

Plus `feeQuery` from bound signer on every signed op. READ also pays owner's `price_per_kb` → `file_balance` (waived for owner reads). CREATE has no per-byte cost (sparse). /s/ exempt and lives outside `cesFileStoreMaxBytes`.

**On-disk**: paths mirror filesystem under `cesFileStoreDir`. Each file: content at `<path>` + TOML sidecar at `<path>.sidecar.toml` (owner_pubkey, file_balance, price_per_kb, size, timestamps, last_rent_us; written atomically). Global `.store.toml` with `total_files`/`total_bytes`/`last_gc_us` guarded by one process-wide mutex.

**Lazy rent, JIT GC, upfront:**
- Every non-DEPOSIT op rolls rent forward (`size × feeFileRent × elapsed`). If `file_balance < owed`: file deleted mid-op, returns `FILE_NOT_FOUND`.
- CREATE/APPEND/RESIZE-grow require ≥ 15 minutes' upfront rent on the delta (anti-grief).
- CREATE that overflows `cesFileStoreMaxBytes` triggers `gcReclaim(bytesNeeded)` — walks store, deletes files whose balance can't cover up-to-now owed rent; debounced to ≤ 1 scan / 15 min.

**Cross-handler exec**: `fileHandlerExec(req, cb, executor)` is a parallel in-process verb path used by `builtin:compute`. Lua program acts under owner X's authority but **all credits billed to source file's `file_balance`** (not X's account). Refunds also land back in source's file_balance. Zone-ownership still applies.

**Master switch**: `cesFileStoreMaxBytes = 0` → feature off; `> 0` → feature on with that hard cap.

## L2 compute — `builtin:compute`

Hosts user programs. LAUNCH spawns a child process (default `cesluajitd`) with Unix-domain socket IPC. Supervisor tick (default 60s) samples /proc CPU+RSS and debits **source file's `file_balance`** for slot-seconds + cpu-seconds + rss-byte-days. Out of funds → SIGKILL; source file deleted → all instances SIGKILLed.

Five verbs, keyed three different ways: **LAUNCH** / **KILL** (owner-gated, they mutate); **LIST** (by *signer* — your own instances, incl. `file_balance`); **STAT** (by *instance id* — **public** to any signer; id/uptime/cpu/rss/**ports**/name); **INSTANCES** (by *source path* — **public**; one record per live instance incl. **ports**, for discovering AND dialing services like `/s/chat.lua`). STAT and INSTANCES expose each instance's leased ports (outbound CES-client + inbound `/ces/luarpc/1` host; 0 = no lease) so anyone can find a running service and reach it — relayed via the server's rpc port (`/ces/lua/1`) or direct to the instance's own port. LAUNCH mints fresh `instance_id` (multiple per source allowed up to `computeMaxInstances`) and requires 15 min upfront slot+rss rent in `file_balance` or fails `COMPUTE_FUND_TOO_LOW`.

Bind prereqs: `computeMaxInstances > 0`, `builtin:file` registered, `computeUser` resolvable.

**Per-instance ports.** Each launched instance gets a CES client on a statically-allocated UDP port from `[computePortBase, computePortBase + computePortCount - 1]` (TOML `compute_port_base` / `compute_port_count`; flags `--computeportbase` / `--computeportcount`), leased RAII and released on instance death. A fixed, known source port is what makes real P2P work behind a firewall — open the range, not ephemeral egress. `computePortBase == 0` → no range: instances launch **local-only** and their `ces.transfer` / remote verbs error **permanently** with `networking disabled`. Port allocation is **best-effort/soft** — an exhausted range is not a launch failure; the instance just gets port 0 (local-only) and stays reachable via the server's own rpc port (`/ces/lua/1` relay), so `compute_port_count = 0` is a valid config. Each instance is leased **two** ports this way — its outbound CES-client port and a second reserved for the instance's own inbound CesPlex host (`/ces/luarpc/1`) — independently and best-effort, so it may get both, one, or neither. The Lua program does **not** own the socket — the C++ host runs the packet processor; the program only receives its reserved port number in the bootstrap frame.

**cesluajitd**: one sandboxed LuaJIT VM per process — no `os`/`io`/`debug`/`require`/`loadstring`/`ffi`. The supervisor frames IPC over the UDS and hands the child a bootstrap frame with its identity (owner key + program keypair), its server-reserved ports (outbound CES client + the instance's own `/ces/luarpc/1` host; either may be 0), and the source. The Lua API surfaces client messaging, the file store (owner-authority, billed to the source's `file_balance`), `ces.transfer` / `account_read` / `random_bytes`, identity + time helpers, capacity-billed `bucket`s, and the unified `ces.conn` raw byte-stream API — **one** listener serving BOTH the server-relayed `/ces/lua/1` and this instance's own direct `/ces/luarpc/1`, plus outbound `ces.conn.connect` (see L2 lua / luarpc below). The program never owns the socket — the C++ host runs the packet processor and passes it the reserved port numbers.

**[builtin_app]** auto-launches named Lua programs from `/s/` at boot. For each enabled name, `launchBuiltinApps` calls `computeHandlerLaunchInternal("/s/<name>.lua")` (no auth/dedup/upfront fee). The source is **operator-deployed, NOT embedded in the binary**: the operator drops `<name>.lua` into `<storeDir>/s/` (startup reconcile stamps its sidecar before launch); a missing source just logs a WRN and is skipped. Shipped: `dice` (`[builtin_app] dice = 1` / `--builtin-app-dice`) — fair-coin double-or-nothing whose house bankroll is the file's dedicated program account (`ces.program_pubkey()`), auto-funded on /s/ by the boot zone reconcile.

## L2 lua — `builtin:lua` (channel routing)

User binds `/ces/lua/1`, sends one ATTACH naming an `instance_id` (a running pid — discover it via compute STAT/INSTANCES; **not** a source path). If that instance has its accept gate open (`ces.conn.set_listener` called), handler allocates `conn_id`, sends TAG_CONN_OPENED to child carrying the **ATTACHing user's** authenticated pubkey; RudpStream becomes raw byte pipe — user→program wraps as TAG_CONN_DATA_IN; `conn:write` from Lua routes back as TAG_CONN_DATA_OUT. Either side close tears down both directions; instance death tears down all routes. Gate closed → `NOT_LISTENING`; instance missing → `COMPUTE_INSTANCE_NOT_FOUND`.

`cesh dial <instance_id>` is the user-side primitive (stdin↔channel↔stdout, half-close on EOF).

## L2 luarpc — `/ces/luarpc/1` (per-instance byte stream)

**Not a CES-core builtin.** Each compute instance hosts its OWN CesPlex on its second leased port via `CesPlexEndpoint` (`cesplex/endpoint.h`), serving `/ces/luarpc/1`. Same semantics as `builtin:lua`: after the signed bind the channel collapses into a **raw, opaque byte pipe** — no host framing, batching, or buffering; any grammar lives in Lua. The difference from `/ces/lua/1` is **topology, not framing**: `/ces/lua/1` is server-relayed *into* the instance (always reachable, even a port-0 instance); `/ces/luarpc/1` is dialed **directly** at the instance's own firewall-punchable port — no host as relay, so it scales — but only if the instance actually got an rpc port. It is also the **program↔program** path.

**Unified Lua surface — ONE `ces.conn` API for BOTH transports.** A program does not distinguish relay (`/ces/lua/1`) from direct (`/ces/luarpc/1`): bytes are bytes, and any multiplexing it does is data-based, not door-based. **listen** via `ces.conn.set_listener{on_open,on_data,on_close}` — a single call arms the relay accept gate AND lazy-opens this instance's direct endpoint (no-op if it got no rpc port); nil closes both. **dial out** (direct only — the relay is inbound-only, not an egress proxy) via `ces.conn.connect(addr, server_pubkey)` → conn. **run** via `ces.conn.run()` (= `ces.run()`), the one loop that pumps both. A conn is `{id, source, pubkey, write(bytes), close()}`: `conn.id` is a single host-owned uid, **unique across both transports** (safe as a program key — cesluajitd owns it; the two native conn-id counters, the supervisor's `nextConnId` and the endpoint's `g_luarpc_next_id`, stay private as the routing id); `conn.source` is `0` (relay) / `1` (direct) for **origin info only**, never routing or identity. Tested in `tests/test_luarpc.cpp` (program-to-program echo + file/compute clients over it; needs real Lua) and `tests/test_lua_conn.cpp` (relay).

## Payment accounts

Created via `CES_CREATE_PAYMENT`. Cost = `(2 + days) * feeAccount`. New account: `balance = -amount`, `nonce = 1 + days` (expiry countdown). Daily maintenance decrements nonce; deleted at nonce ≤ 1. `settlePayment`: incoming transfer must match exact `|balance|`; on match, balance set to amount, nonce cleared.

## Daily maintenance

09:00 UTC daily:
- Payment accounts (balance < 0): decrement nonce; delete if nonce ≤ 1
- Regular accounts (balance ≥ 0): deduct `feeAccount`; delete if balance ≤ fee
- Assets: decrement balance by 1; delete if balance ≤ 1

Logs per-pass summary, triggers auto-snapshot. File-store has **no** periodic rent pass — lazy on every non-DEPOSIT touch; JIT GC fires on CREATE if cap exceeded. Compute instances billed on supervisor tick, not maintenance.

## Inter-server settlement

Each server is a sovereign ledger; no global state, no shared chain. Network = mesh of sovereign ledgers connected by **bilateral correspondent banking**: each peer-pair maintains two reciprocal accounts.

- **Vostro** = an account on our server, keyed by peer's pubkey — what we owe peer.
- **Reserve** = our account on peer's server — what peer owes us.

Cross-transfer flow: debit origin → credit vostro → return CES_OK immediately → async `openTransfer` to peer via `CesClientAsync` → peer debits reserve, credits dest. No round-trip required.

`CesClientAsync` runs multiple channels per peer (own MINX ticket chain each); per-channel state machine drives handshake→request→idle; sweep timer retries timeouts. Backpressure exposes `load()` percentage + hard cap. All settlement uses `CES_NONCELESS`. `cesnetbot` verifies the invariant: across all servers, sum of balances + vostro/reserve = total minted.

## SYS_RPC

Requires `rpc_port ≠ 0` (default 0 = disabled, returns `CES_ERROR_DISABLED`). Second MINX instance (`rpcMinx_`) wired to RUDP via `stdext` dispatcher.

Three-stage flow: **queueRpc** (logicStrand) reads request from ramfile, builds signed envelope, queues; **executeRpc** (rpcTaskIO) opens RUDP channel, sends, waits 30s — `rpcSessions_` lives only here; **completeRpc** (logicStrand) writes response into file chain, schedules followup VM.

The request is a signed envelope (body + timestamp + sender key + sig). The follow-up VM run receives the status and the response file-head key.

Backpressure: `rpcMaxPending` / `rpcMaxRequestBytes` / `rpcMaxResponseBytes` / `rpcResponseTimeoutMs`. RUDP-level pacing via `rpcRudpBytesPerSecond` / `rpcRudpBurstBytes`.

## Persistence (logkv)

Two stores: `accountStore_`, `assetStore_` (`Store<unordered_flat_map, K, V>`). Both accessed only on `logicStrand_` — no internal locking.

**Serialization modes** are thread-local, set before each `store.update()`: a `Full` mode (creation/snapshot) plus narrower modes for hot paths (balance+nonce, transfer, content, meta, balance-only) and `None` for deletion. `updateAssetFast` skips the WAL — content survives via snapshot only.

**Snapshots**: log grows until `max_log_size_gb`, then `forkSave` — `fork(2)`, child writes `.snapshot` while parent serves. Graceful shutdown / cesco snapshot / daily maintenance also fire one. Recovery: load newest `.snapshot`, replay WAL suffix. 30s debounce.

## Concurrency model

Five thread groups:
1. **netIO** (1): UDP send/receive
2. **taskIO** (N, configurable): MINX dispatch + `logicStrand_` for all ledger mutations
3. **verifyPoW** (1): RandomX verification
4. **settlementIO** (1): CesClientAsync async I/O
5. **rpcTaskIO** (1): rpc-port Minx + CesPlex sessions + handler `serve` + ChannelMeter tick + compute supervisor tick

`logicStrand_` IS the lock. No ledger mutexes. Cross-handler primitives (e.g. `fileHandlerExec`) hop onto `logicStrand_` internally as needed. Replies retransmitted on a timer to paper over UDP loss.

## Configuration

CLI flags > TOML > compiled defaults. `ces --config` dumps default template. `ces --genkeypair` prints a new keypair.

All numeric fees are raw uint64 credit values (no decimals; PRICE_UNIT is display-only; `-1` means "use the compiled default"). Compiled defaults cover account/asset rent, per-tx, per-query, and a VM-gas multiplier.

**Load-based fee discount (feemult).** Every named per-op fee (`feeTx`, `feeQuery`, VM gas, account/asset rent, compute slot/cpu/rss, bucket, net metering) is scaled by a per-FeeKind basis-points multiplier (0..10000) before it is charged. `feeDiscountEnabled` (compiled default `true`) drives each multiplier from a live load gauge measured against a lifetime throughput watermark: an idle server discounts toward 0 (an op can cost **literally 0** when its gauge genuinely reads idle), ramping to full fee as sustained load approaches the busiest the host has ever been. It is congestion pricing, not a fixed schedule. A gauge that is *undefined* (a required cap is 0, e.g. `maxAcc`/`maxAsset`/`netPeakBps`) snaps to full price, never 0, so a missing metric can never silently zero a fee. Disabled → all multipliers pinned at 10000 (full price). The anti-spam barrier is separate (MINX PoW tickets), so 0-fee at idle is not a spam hole.

The **feature master-switches** (full template via `ces --config`): `rpc_port` (0 ⇒ CesPlex + SYS_RPC off), `web_port` (0 ⇒ dashboard off; loopback-only, no auth), `file_store_max_bytes` (0 ⇒ file feature off), `compute_max_instances` (0 ⇒ compute off, needs file), `compute_port_base`/`_count` (per-instance UDP range), `admin_socket` (cesco UDS), `min_difficulty`/`no_pow_engine`/`cache_only_pow` (PoW), plus the `[[peers]]`, `[cesplex_mounts]`, and `[builtin_app]` tables.

## Cesco admin console

Embedded in server; enabled via `admin_socket`. UDS REPL: `rlwrap socat - UNIX-CONNECT:./admin.sock`.

Commands: `snapshot`, `credit <amt> <pubkey>`, `debit <amt> <pubkey>` (clamped), `netbill` (per-channel snapshot), `help`/`h`, `quit`/`q`/`exit`/Ctrl-C. Same machinery as offline `ces credit`/`ces debit` but no shutdown required.

## Web dashboard (`cesweb.h`/`cesweb.cpp`)

Localhost HTTP admin UI embedded in the server, enabled via `web_port` (0 = disabled). **No authentication by design** — binds loopback only (`web_bind`, default `127.0.0.1`); reach it over an SSH tunnel. A 0-or-1-client Boost.Asio HTTP/1.1 server on its own io_context/thread (modeled on Cesco): one acceptor + per-connection session, serving the whole single-page UI as one embedded string. The operator's "experience center" — the things you'd otherwise open cesh/cesqt for while running a node:

- **Overview** — identity, live stat cards + load gauges, feature flags.
- **Peers** — add/remove/list peers + runtime peer target (the marquee). Shows both directions: outbound (us→them) and inbound (their PoW to us).
- **Inspect** — server-info a remote by address: free handshake → pubkey/min-difficulty/reachability, optional paid KV info; **Mine** to bootstrap a reserve; **Add as outbound peer**.
- **Wallet** (transfer from server, credit/burn, snapshot), **Lookup** (account/asset/file), **Billing** (ChannelMeter), **Fees** (base-fee editors + live multipliers), **File** / **Compute** (L2 monitoring + fee/cap editors), **Logs** (live tail), **Config** (knobs, live fee multipliers, hello-banner editor).

GET endpoints emit hand-rolled JSON; POST actions take form-urlencoded bodies. Ledger reads hop onto `logicStrand_` via a `std::future`; remote inspect/mine run on worker threads joined at `stop()` (never the io thread). The live log tail is a bounded in-memory `LogRing` fed by a Boost.Log sink CesWeb installs on the logging core. cesco stays for now; slated for deletion once the dashboard is proven. Tests: `tests/test_cesweb.cpp` (suite `CesWebTests`) drives every endpoint over raw TCP against an in-process server.

**Hello banner.** `<data_dir>/hello.txt` → a UTF-8 string capped at 160 bytes (trimmed on a codepoint boundary, never mid-sequence), seeded at boot and served in `CES_QUERY_SERVER_INFO` as the `hello` field. The dashboard's Config tab is the only other writer (it rewrites the file and the served value).

## `ces credit` / `ces debit` / `ces snapshot`

Offline ledger ops (no networking). Load stores, mutate, `_save()`, exit. Used by `cesnet` to pre-fund accounts. `ces snapshot` compacts event log into a fresh `.snapshot`.

## Client tools

**cesh** — CLI client. Subcommands: `keys`, `query`/`squery`, `transfer`/`payment`/`cross`, `server-info`/`ping`, `peer-info <id> <server>` (unsigned peer-table slot read), `mine [-t N]` (clamped to `hardware_concurrency`), `asset` (create/update/meta/fast/fund/buy/give/query/squery/**run**), `ramfile` (L1; put/touch/get/info/scan/read/write/append/resize/rehash/fund; `--in text:|hex:|file:`), `file` (L2 disk; put/get/stat/rm/deposit/withdraw/set-price; needs `--rpc-port`), `compute` (L2; launch/kill/ps/stat/instances; needs `--rpc-port`), `dial <instance_id>` (bidirectional bytes over /ces/lua/1; stdin EOF half-closes; SIGINT/SIGTERM → 130/143; `-v` prints ATTACH-ok), `autoexec install`.

**Two output modes.** Default is human (headers + aligned fields). Global `-q`/`--quiet` is **silent/pipe mode: stdout is data only** — raw bytes for content (`file get` with no/`-` local path streams the file to stdout) and JSON for structured results (`query`, `ping`, `server-info`, `asset query`, `file stat`, `compute ps`/`stat`/`instances`, `compute launch`/`kill`); all human chrome is suppressed and errors still go to stderr with a nonzero exit. This makes cesh a clean data pipe for callers (e.g. a web gateway that shells out to it). The server's rpc port is discoverable without `--rpc-port`: free `ces ping` (and the paid `server-info`) advertise `rpcPort` (from the MINX `GetInfo` rdata, mirrored into the paid KV).

`cesh --help-all` for full verb list. Server: `--server host:port` or `$CESH_SERVER`. Wallet priority: `--wallet PATH` > `$CESH_WALLET` (**inline**, colon-separated keys — same format `cesh keys export` emits, NOT a path) > `~/.cesh/CESH_WALLET`. `@N` selects 0-based key index within wallet.

**cesqt** — Qt6 GUI wrapping cesh verbs. 11 tabs (Wallet/Account/Transfer/Mining/Create/Assets/Market/Keys/Servers/Console/About). Localhost JSON-RPC (`rpcserver.cpp`, port 21008) for browser apps with per-origin sandboxed keys (MetaMask UX). Built when `CESQT` CMake option is enabled.

**cesproxy** — TCP↔UDP proxy for non-UDP clients. `CesProxy` = `MinxProxy` subclass + wire-level validation.

**cesbench** — in-process benchmark. Server + client in one binary. Tunes `threads`, `flush_value`.

**cesluajitd** / **cescompmockd** — compute children; spawned by supervisor. Default `cesluajitd` (LuaJIT); `cescompmockd` is no-Lua plumbing-test stub.

## Logging (`blog.h` from MINX)

```cpp
LOG_MODULE("csv")
LOGINFO  << "started" << VAR(port);
LOGDEBUG << "failed"  << VAR(rc) << SVAR(addr);
LOGTRACE << "packet"  << BVAR(payload);
```

Macros: `LOGTRACE`/`DEBUG`/`INFO`/`WARNING`/`ERROR`/`FATAL`. `VAR(x)` native, `SVAR(x)` string-convertible, `BVAR(x)` bytes-as-hex. `blog::fast_min_level` is plain int — zero overhead for disabled levels. `blog::enable("module")`, `blog::set_level("module", blog::trace)`. `ces::setupLogger("debug")` is the shared CLI parser (`util/log.h`).

**Module names**: `csv` server, `ccl` client, `acc` accounts, `ast` assets, `cesvm` VM, `cesco` admin, `ceslib` wallet, `plex` CesPlex+file/compute handlers, `lua` builtin:lua, `netbill` ChannelMeter, `cfc` CesFileClient, `ccc` CesComputeClient.

**Production policy**: INFO = lifecycle only. DEBUG = failure conditions. TRACE = per-op firehose (NOT for production).

## Testing

**CesFixture** (`tests/test_common.h`): in-process server + CesClient + temp dir; client pre-funded 10B; auto-cleaned. All tests compile into one `cestests` "Megazord" binary; filter by suite name.

```bash
./build.sh debug --test AccountTests
./build.sh debug --teste2e            # E2E (shells out to cesh + cesnet/cesnetbot)
```

**Network simulator**:
- `tools/cesnet.mjs` — local multi-server topology. `init N` creates N workspaces; `up`/`down`/`destroy`. Workspaces persist across up/down with manifest + PID file.
- `tools/cesnetbot.mjs` — traffic on top of cesnet. K simulated users, parallel local + cross-server transfers, then verifies **credit conservation**: sum of all accounts + vostro/reserve = total minted. Drift = bug.

```bash
./cesnet init 3 && ./cesnet up
./cesnetbot run --users 10 --rounds 5
./cesnet destroy
```

## Key invariants

- All ledger mutations on `logicStrand_` — never touch stores from other threads
- Thread-local `SerMode` set before every `store.update()`/`persist()`
- `updateAssetFast` skips WAL — only when durability optional
- Auto-nonce retries must reuse the **same signed payload** (dedup matches sig hash)
- Cross-transfers fire-and-forget — CES_OK to user before async delivery to peer
- Payment account `nonce` is days-until-expiry, NOT replay counter
- `isConnected()=true` bypasses spam filter AND tickets — only for authenticated peers
- `rpc_port=0` disables SYS_RPC AND CesPlex entirely (VM gets `CES_ERROR_DISABLED`; no L2 binds; no ChannelMeter)
- `cesFileStoreMaxBytes=0` disables file handler entirely; compute requires file
- `computeMaxInstances=0` disables compute entirely
- **CesPlex per-op verifies use sessionToken**, not per-op timestamp. Bound pubkey implicit. Dedup hash = first 8 sig bytes.
- **CesPlex carries no prices.** The bus measures each channel's raw byte/time usage (`CesPlexUsage`) and reports it to the host, which prices at its live `feeNet*` rates and closes on non-payment. The bind contract is identity-only — no rate disclosure on the wire (a client wanting the schedule asks via `CES_QUERY_SERVER_INFO`).
- **Most CesPlex handlers loop on their channel.** Exception: `builtin:lua` ATTACH is one-shot, converts channel into raw byte stream into instance.
- File-store bytes need ≥ 15 min upfront rent at CREATE/APPEND/RESIZE-grow (`initial_deposit ≥ upfront(size)` or `INSUFFICIENT_BALANCE`). /s/ exempt.
- File paths must start with `/h/<64-hex>/`, `/f/<name>/`, `/p/`, or `/s/` — anything else → `BAD_NAME`.
- **/s/ requires server's own private key as signer.** Only operator deploys; reads unmetered. `fileHandlerDebitBalance`/`CreditBalance` no-op on /s/ — file_balance is decorative there, never consulted by supervisor billing.
- **Compute fees come out of source file's `file_balance`**, not launcher's account. Refunds also land back there. Bounds per-program credit exposure to operator funding.
- **Server's own account is uncounted + bottomless.** Force-reset to exactly `2^50` every boot (far below `INT64_MAX`, so incoming transfers can't overflow; resets even a value corrupted or overgrown by an older build, not just topped up); excluded from `totalCredits_` and from cesnetbot's conservation sum (server-self cells skipped, vostro/reserve cells on peers still count). Anchors the "credits are not money" thesis structurally.

## RandomX (via MINX)

CPU-hard PoW for Sybil-resistance on minting (credits from PoW only; no premine). Default keeps full dataset in RAM for fast verify; `cache_only_pow=true` trades speed for memory. Solutions arrive on main UDP port as unsigned packets; verification on its own thread. `min_difficulty` = per-solution hash floor; higher-difficulty solutions mint more credit. `no_pow_engine=true` for dev/test (no minting).

**The engine also verifies main-port anti-spam tickets** — so with `no_pow_engine=true`, **signed ops on the main port** (transfer, squery, `CES_QUERY_SERVER_INFO`, mint) silently drop and the client **times out**. But the **free MINX `GetInfo`** (cesh `ping`) and **all rpc-port CesPlex/L2 traffic** (file/compute binds + verbs) are **ticketless** and work fine without the engine. So a **pure file/compute-serving box can run `no_pow_engine=true`** (instant boot, no RandomX RAM) — only nodes that accept mints or serve signed main-port ops need the engine. (The cesweb file gateway exploits this: it uses `ping` + `--server-key` + rpc-port READ, never a signed main-port op.)

## Dependencies

```
CES
├── MINX (UDP, anti-spam PoW, ticket system, RUDP, MinxProxy)
│   └── RandomX (CPU PoW, large in-RAM dataset)
├── logkv (event-sourced K,V persistence)
├── CryptoPP (ED25519)
├── secp256k1/Bitcoin Core (ECDSA)
├── Boost (asio, log, filesystem, unordered_flat_map)
├── LuaJIT (cesluajitd)
└── Qt6 (GUI only)
```
