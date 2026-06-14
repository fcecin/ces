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

- **Never reinvent wire serialization.** The canonical CES wire-bytes types and serialization API live in `<ces/buffer.h>`:
  - **`ces::Bytes`** = `std::vector<uint8_t>` — heap-backed dynamic-size raw byte storage. Use when you just need to *hold* bytes (a Bytes member, a `shared_ptr<Bytes>` across an async I/O lifetime, a function return value).
  - **`ces::Buffer`** — concrete vector-owning object. Wraps a `ces::Bytes` member; tracks read+write cursors; auto-grows on put. All the methods are on this object: `put<T>`, `get<T>`, `peek<T>`, `poke<T>`, `putLE<T>`, `peekLE<T>`, `pokeLE<T>`, `shaUpdate(h, T)`, `putBytes`, `asioConstBuffer`. BE serialization delegates to `logkv::serializer<T>`; LE delegates to `boost::endian`. Plus static helpers (`Buffer::put<T>(vec, val)`, `Buffer::peek<T>(ptr)`, `Buffer::poke<T>(ptr, val)`, etc.) for sites that operate on raw pointers or external vectors instead of owning a `Buffer`.

  Family lineage in the dependency stack:
  ```
  logkv::Bytes  = std::vector<char>           heap, char (generic, C-ish)
  logkv::serializer<T>                        BE primitive (template)
  minx::Bytes   = static_vector<char, 1280>   stack-bounded, IPv6 MTU
  minx::Buffer  = AutoBuffer<uint8_t>         span-wrapper (borrowed, fixed)
  ces::Bytes    = std::vector<uint8_t>        heap, uint8_t (CES wire)
  ces::Buffer                                 vector-owning, growing
  ```
  Each Bytes type calibrated to its layer's bound (heap vs MTU-static) and ergonomics (char vs uint8_t). minx::Buffer and ces::Buffer are sovereign peers — interop is byte-level (anything byte-aware consumes a Bytes from any of them).

  `ces/keys.h` specializes `logkv::serializer<ces::PublicKey>` so `buf.put<PublicKey>(pk)` / `buf.get<PublicKey>()` work alongside the standard integer / array-of-uint8_t serializations.

  **DO NOT** write hand-rolled `appU64BE` / `write_u32_be` / `for (i=0..7) v=(v<<8)|p[i]` / similar shift loops. Use ces::Buffer (preferred for new code), minx::Buffer (for borrowed-span scenarios), or ces::Buffer's static helpers. **DO NOT** declare `std::vector<uint8_t>` for wire-shaped data members or function signatures — use `ces::Bytes` (or `minx::Bytes` if you specifically want the MTU-bounded shape) so the type system signals the wire-bytes intent.

  **One exception**: `src/cesluajitd/main.cpp`, the LuaJIT-hosted compute child runtime. It links `ceslib` (for `ces::CesClient` — its outbound networking), but its supervisor-IPC framing deliberately uses its own minimal `put_u16`/`put_u64`/`get_u32`/etc. helpers rather than `ces::Buffer`, keeping that framing layer self-contained. Documented inline at their definition site.

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
```

## Data model — the two-type ledger

CES has exactly two ledger types: **Account** and **Asset**. Files, programs, schedules, namespaces, autoexec, the market — all compose out of those two. No separate file/program/namespace tables.

**Account** (64B cache-aligned, map key = `HashPrefix` = first 8 bytes of `sha256(pubkey)`):
- `keyTail` (24B) — lower 24 bytes of the pubkey-hash
- `balance` (int64) — credit balance. **Sign overloaded**: positive = ordinary; negative = unsettled payment account
- `nonce` (uint32) — replay counter; `reqNonce` must equal `nonce+1`. **Also overloaded**: on payment accounts it's days-until-expiry
- `lastXferDest`/`lastXferAmount`/`lastXferTime` — receipt of most recent outgoing transfer (signed payload = single-query payment proof)

No type field, no role flags — sign of balance + nonce value carry the only state distinction.

**Asset** (256B, map key = full 32-byte hash):
- `owner` (HashPrefix, 8B) — account or asset prefix that controls this cell
- `balance` (uint16) — bits 0..12 = days remaining (max 8191); bit 13 = immutable; bit 14 = asset-owned (owner is asset prefix); bit 15 = private. `CES_QUERY_ASSET` and `SYS_READ_ASSET` return the raw u16 — clients/programs mask via `assetDays()` and check the flag bits as needed
- `price` (uint32) — sale price in PRICE_UNIT units. Non-zero ⇒ any signer can `CES_BUY_ASSET` for that amount
- `content` (AssetData, 210B) — arbitrary user bytes

**The asset is the generative primitive.** Files = chains of assets. VM programs = assets (`CES_RUN_ASSET`). Autoexec = a key-pattern on assets. `/f/<name>` namespace gated by who owns the asset at `sha256("/f/<name>")` — transferable via `CES_GIVE_ASSET`. Scheduled VM runs = assets. The 210-byte cell makes the system extensible without protocol changes.

Asset day-counter is **rent**. Daily maintenance decrements every asset's balance by 1; assets at ≤ 1 die. Keep alive via `CES_FUND_ASSET`.

**PRICE_UNIT = 100,000,000** (8 decimal places). Wire prices are user-facing whole credits; multiply by PRICE_UNIT for internal units.

## Cryptography (`keys.h`)

Two algorithms, 1-byte decorator: `0x00` ED25519 (CryptoPP, 64-byte deterministic), `0x01`/`0x02` secp256k1 even-y/odd-y (libsecp256k1, 64-byte compact, RFC 6979). Signature = 1B decorator + 64B = 65B total. SHA256 input unless already 32B. secp256k1 context + CryptoPP PRNG are `thread_local`.

Wallet format: one key per line, `"00" + 64-hex` or `"01" + 64-hex`. Wallets validate keys at insertion.

## Wire protocol (`protocol.h`, `types.h`)

`CES_INJECT_SIGNED_METHODS` / `CES_INJECT_UNSIGNED_METHODS` macros generate `toBytes`/`fromBytes`/`verifySignature`.

**Opcodes (op_code_t)** — primary UDP port:
- Transfers: `CES_TRANSFER` (0x00), `CES_OPEN_TRANSFER` (0x10, auto-create dest), `CES_BULK_TRANSFER` (0x01, ≤20), `CES_CREATE_PAYMENT` (0x11), `CES_CROSS_TRANSFER` (0x12)
- Queries: `CES_QUERY_ACCOUNT` (0x02), `CES_UNSIGNED_QUERY_ACCOUNT` (0x03), `CES_QUERY_ASSET` (0x0c), `CES_UNSIGNED_QUERY_ASSET` (0x0d), `CES_QUERY_SERVER_INFO` (0x0f), `CES_UNSIGNED_QUERY_SOLUTION` (0x04)
- Assets: `CES_CREATE_ASSET` (0x05), `CES_UPDATE_ASSET` (0x06), `CES_UPDATE_ASSET_META` (0x07), `CES_UPDATE_ASSET_FAST` (0x08), `CES_FUND_ASSET` (0x09), `CES_BUY_ASSET` (0x0a), `CES_GIVE_ASSET` (0x0b)
- VM: `CES_RUN_ASSET` (0x13)

**APPLICATION lane (app_code_t)** — pushed over MINX's APPLICATION path (not signed-op path). Values 0x80+.
- `CES_APP_COMPUTE_MSG` (0x81): client↔program message. Target/source = file_key prefix + payload (≤ 1 KB). Discarded silently if no instance matches.

**Error codes**: `CES_OK`=0, `ORIGIN_NOT_FOUND`=1, `WRONG_NONCE`=2, `INSUFFICIENT_BALANCE`=3, `INSUFFICIENT_BALANCE_WITH_CREATE`=4, `INVALID_TARGET_ACCOUNT`=5, `WRONG_TARGET_ACCOUNT`=6, `WRONG_PAYMENT_AMOUNT`=7, `ASSET_EXISTS`=8, `ASSET_NOT_FOUND`=9, `NOT_OWNER`=0xa, `NOT_FOR_SALE`=0xb, `INSUFFICIENT_PAYMENT`=0xc, `TIMEOUT`=0xd, `INTERNAL`=0xe, `TARGET_NOT_FOUND`=0xf, `UNKNOWN_PEER`=0x10, `QUEUE_FULL`=0x11, `VM_FAILED`=0x12, `DISABLED`=0x13, `ALLOWANCE_EXCEEDED`=0x14, `PROTO_REJECTED`=0x15 (CesPlex NACK), `FILE_NOT_FOUND`=0x16, `FILE_EXISTS`=0x17, `BAD_NAME`=0x18, `PATH_CONFLICT`=0x19, `STORE_FULL`=0x1a, `COMPUTE_DISABLED`=0x1b, `COMPUTE_NO_FILE_HANDLER`=0x1c, `COMPUTE_FUND_TOO_LOW`=0x1d, `COMPUTE_INSTANCE_NOT_FOUND`=0x1e, `COMPUTE_MAX_INSTANCES`=0x1f, `NOT_LISTENING`=0x20, `IMMUTABLE`=0x21, `BAD_INPUT`=0x22.

**Nonce modes**: `0` skip (internal); `CES_NONCELESS (UINT32_MAX)` server assigns (settlement pipelining); `N` must equal `nonce + 1`. Auto-nonce: signed ops carry timestamp; server rejects stale, dedups by sig-hash prefix. **Retried ops must reuse the same signed payload** so dedup returns OK without re-executing.

## CesVM (`cesvm.h`, `cesvm.cpp`)

Harvard architecture; runs on `logicStrand_`; mutations atomic with undo log.

**io[] (1024 cells × 8 bytes)** — data plane only; bytecode lives in a separate `code_` buffer indexed by PC, NOT in io:
```
io[0..15]    registers: PC, R, S, SYSCALL, ARG0-3, GPR0-7
io[16..751]  program-private scratch (736 cells = 5888 bytes)
io[752..755] context: input_len, output_len, budget, start_time
io[756..763] preloaded caller_key (4 cells), self_key (4 cells)
io[764..891] output (128 cells = 1024 bytes)
io[892..1019] input (128 cells = 1024 bytes)
io[1020]     allowance
io[1021]     budget_remaining
```

`vmprogram.h` ships a bump allocator over the io[16..751] scratch range — `auto buf = pgm.allocContent()` returns a typed `Region` so program-build code never types raw cell numbers (escape hatch: `allocAt(cell, count)` for protocol-fixed addresses).

**Syscalls** (dense range 0..22; SYS_SEND_UDP is tombstoned at 9 — returns CES_ERROR_DISABLED):
```
0  SYS_NOP                 12 SYS_CROSS_TRANSFER
1  SYS_READ_ACCOUNT        13 SYS_LOAD_CODE
2  SYS_TRANSFER            14 SYS_CREATE_ASSET
3  SYS_READ_ASSET          15 SYS_SEND_CLIENT
4  SYS_CREATE_ASSET_RANDOM 16 SYS_SCHEDULE
5  SYS_UPDATE_ASSET        17 SYS_CREATE_ASSET_MANAGED
6  SYS_FUND_ASSET          18 SYS_RPC
7  SYS_BUY_ASSET           19 SYS_OWNER_TRANSFER
8  SYS_GIVE_ASSET          20 SYS_DEPOSIT
9  SYS_SEND_UDP (disabled) 21 SYS_WITHDRAW
10 SYS_HASH                22 SYS_UPDATE_ASSET_META
11 SYS_VERIFY_SIG
```

**VmProgram** (`vmprogram.h`): C++ fluent API; one method per opcode; label support; outputs `toAssetData()` (210B) or byte vector.

**Cron / SYS_SCHEDULE**: enqueues one-shot VM run at absolute wall time; missed deadlines fire ASAP. Recurrence = scheduled VM re-calls SYS_SCHEDULE. Schedule state persisted as ledger entries.

**Autoexec** (`autoexec.h`): boot-time hook. Asset key pattern `[8 zero][8 AUTOEXEC_KEY_MAGIC BE][8 account_prefix][8 random]`; content = signed `CesRunAsset`. Server scans on boot, runs each via `scheduleRun` at `now`.

## L1 RAM filestore — in-asset file chain (`ramfilestore.h`)

In-ledger files as linked asset chains. Head asset (magic 'F'): 1B magic + 8B size + 32B SHA256 + 8B created + 8B modified + 121B metadata + 32B first-chunk-key = 210B. Chunk: 178B payload + 32B next-key = 210B. Chunks uploaded **in reverse order** (each already knows successor).

API: `ramfilePut`/`ramfileGet`/`ramfileFund`/`ramfileScan` + random-access `ramfileRead`/`Write`/`Append`/`Resize`/`Rehash`. Header struct `RamfileHeader`. VM-reachable via `SYS_LOAD_CODE`/`SYS_READ_ASSET`. cesh verb: `cesh ramfile`. For host-scale disk files, see L2 file handler (`cesh file`).

## CesPlex — L1 protocol multiplexer (`cesplex/mux.h`, `cesplex/wire.h`)

Runs on `rpc_port`. Each inbound RUDP channel does a **signed bind contract**: client signs `(name + client_time + client_pubkey)`; server replies signed, committing server pubkey + per-channel `sessionToken`. The bind is **identity-only — no prices on the wire**. Handler receives `BoundChannelContext` (pubkey, payerPfx, sessionToken, bind time). CesPlex knows no credits: a `ChannelMeter` measures each channel's raw byte/time usage (`CesPlexUsage`) and reports it to the host (`CesPlexHost::cesplexReportUsage`); the host prices it, charges the payer, and closes the channel on non-payment.

Per-op envelope: `[u8 verb][u32 BE preamble_len][preamble][65 sig over sha256(verb||preamble||sessionToken)]`. No per-op pubkey or timestamp — implicit on bound channel. Body-bearing verbs append bytes after sig, hashed against digest committed in preamble. Dedup key = first 8 sig bytes (per-channel-incarnation, no cross-channel collisions).

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

**Verbs (codes 0x01..0x0a):** CREATE (any) / WRITE (owner, ≤1MB body) / READ (any signer, reply body) / STAT (unsigned, free) / DEPOSIT (any signer) / WITHDRAW (owner) / SET_PRICE (owner) / DELETE (owner) / APPEND (owner, ≤1MB) / RESIZE (owner).

**Four-zone naming (mandatory):**
- `/h/<64-hex-pubkey>/...` — auto home dir; signer must match the hex
- `/f/<name>/...` — asset-gated; signer must own asset at `sha256("/f/<name>")`. Transferable via `CES_GIVE_ASSET`.
- `/p/...` — public; first-come-first-served on exact path
- `/s/...` — **server-deployed**, unmetered, outside the cap. Only the server's own private key may CREATE/WRITE; reads operator-donated. Used for curated programs (`/s/chat.lua` etc.).

Anything else → `BAD_NAME`. Zone ownership checked **only at CREATE**; subsequent ops use sidecar's stamped `owner_pubkey`.

**Three-cost model:**
- `feeFileRent` — credits per byte×day; drains `file_balance`
- `feeFileWrite` — per KB; drains `file_balance` at WRITE/APPEND
- `feeFileRead` — per KB; drains reader's account (burned; even owner pays)

Plus `feeQuery` from bound signer on every signed op. READ also pays owner's `price_per_kb` → `file_balance` (waived for owner reads). CREATE has no per-byte cost (sparse). /s/ exempt and lives outside `cesFileStoreMaxBytes`.

**On-disk**: paths mirror filesystem under `cesFileStoreDir`. Each file: content at `<path>` + TOML sidecar at `<path>.sidecar.toml` (owner_pubkey, file_balance, price_per_kb, size, content_type, timestamps, last_rent_us; written atomically). Global `.store.toml` with `total_files`/`total_bytes`/`last_gc_us` guarded by one process-wide mutex.

**Lazy rent, JIT GC, upfront:**
- Every non-DEPOSIT op rolls rent forward (`size × feeFileRent × elapsed`). If `file_balance < owed`: file deleted mid-op, returns `FILE_NOT_FOUND`.
- CREATE/APPEND/RESIZE-grow require ≥ 15 minutes' upfront rent on the delta (anti-grief).
- CREATE that overflows `cesFileStoreMaxBytes` triggers `gcReclaim(bytesNeeded)` — walks store, deletes files whose balance can't cover up-to-now owed rent; debounced to ≤ 1 scan / 15 min.

**Cross-handler exec**: `fileHandlerExec(req, cb, executor)` is a parallel in-process verb path used by `builtin:compute`. Lua program acts under owner X's authority but **all credits billed to source file's `file_balance`** (not X's account). Refunds also land back in source's file_balance. Zone-ownership still applies.

**Master switch**: `cesFileStoreMaxBytes = 0` → feature off; `> 0` → feature on with that hard cap.

## L2 compute — `builtin:compute`

Hosts user programs. LAUNCH spawns a child process (default `cesluajitd`) with Unix-domain socket IPC. Supervisor tick (default 60s) samples /proc CPU+RSS and debits **source file's `file_balance`** for slot-seconds + cpu-seconds + rss-byte-days. Out of funds → SIGKILL; source file deleted → all instances SIGKILLed.

Five verbs: LAUNCH / KILL / LIST (per-signer) / STAT / INSTANCES (public — used to discover services like `/s/chat.lua`). LAUNCH mints fresh `instance_id` (multiple per source allowed up to `computeMaxInstances`) and requires 15 min upfront slot+rss rent in `file_balance` or fails `COMPUTE_FUND_TOO_LOW`.

Bind prereqs: `computeMaxInstances > 0`, `builtin:file` registered, `computeUser` resolvable.

**Per-instance ports.** Each launched instance gets a CES client on a statically-allocated UDP port from `[computePortBase, computePortBase + computePortCount - 1]` (TOML `compute_port_base` / `compute_port_count`; flags `--computeportbase` / `--computeportcount`), leased RAII and released on instance death. A fixed, known source port is what makes real P2P work behind a firewall — open the range, not ephemeral egress. `computePortBase == 0` → no range: instances launch **local-only** and their `ces.transfer` / remote verbs error **permanently** with `networking disabled`. Port allocation is **best-effort/soft** — an exhausted range is not a launch failure; the instance just gets port 0 (local-only) and stays reachable via the server's own rpc port (`/ces/lua/1` relay), so `compute_port_count = 0` is a valid config. Each instance is leased **two** ports this way — its outbound CES-client port and a second reserved for the instance's own inbound CesPlex host (`/ces/luarpc/1`) — independently and best-effort, so it may get both, one, or neither. The Lua program does **not** own the socket — the C++ host runs the packet processor; the program only receives its reserved port number in the bootstrap frame.

**cesluajitd**: one sandboxed LuaJIT VM per process — no `os`/`io`/`debug`/`package`/`require`/`loadfile`/`dofile`/`loadstring`/`ffi`. IPC framed `[u32 BE length][u8 tag][u16 BE corr_id][body]`. Bootstrap frame carries `[8B prog_pfx][32B owner_pubkey][32B program_pubkey][32B program_privkey][2B client_port BE][2B rpc_port BE][8B start_time_us BE][u32 BE src_len][src]` (program_privkey lets the program sign its own remote ops; client_port = server-reserved outbound UDP port; rpc_port = server-reserved port for the instance's own inbound CesPlex host (`/ces/luarpc/1`); each is 0 when the range couldn't supply it). Lua API: `ces.client_send`/`ces.client_recv` (CES_APP_COMPUTE_MSG), `ces.conn.set_listener`/`ces.conn.run` (accept gate for /ces/lua/1), `conn:write`/`conn:close`, `ces.file.*` (owner-authority, billed to source's file_balance), `ces.transfer(target, amount)` / `ces.account_read(pubkey)` / `ces.random_bytes(n)`, `ces.owner_pubkey()` (owner's wallet key) / `ces.program_pubkey()` (the file's dedicated program account, what `ces.transfer` spends from) / `ces.start_time()` / `ces.now()`, `ces.bucket_new(ttl_secs, max_entries, max_entry_bytes)` → `:put`/`:get` (capacity-billed via `feeBucketByteSec` summed into the supervisor tick).

**[builtin_app]** auto-launches named Lua programs from `/s/` at boot. For each enabled name, `launchBuiltinApps` calls `computeHandlerLaunchInternal("/s/<name>.lua")` (no auth/dedup/upfront fee). The source is **operator-deployed, NOT embedded in the binary**: the operator drops `<name>.lua` into `<storeDir>/s/` (startup reconcile stamps its sidecar before launch); a missing source just logs a WRN and is skipped. Shipped: `dice` (`[builtin_app] dice = 1` / `--builtin-app-dice`) — fair-coin double-or-nothing whose house bankroll is the file's dedicated program account (`ces.program_pubkey()`), auto-funded on /s/ by the boot zone reconcile.

## L2 lua — `builtin:lua` (channel routing)

User binds `/ces/lua/1`, sends one ATTACH naming a source-file path. If an instance has its accept gate open (`ces.conn.set_listener` called), handler allocates `conn_id`, sends TAG_CONN_OPENED to child; RudpStream becomes raw byte pipe — user→program wraps as TAG_CONN_DATA_IN; `conn:write` from Lua routes back as TAG_CONN_DATA_OUT. Either side close tears down both directions; instance death tears down all routes. Gate closed → `NOT_LISTENING`; instance missing → `COMPUTE_INSTANCE_NOT_FOUND`.

`cesh dial <instance_id>` is the user-side primitive (stdin↔channel↔stdout, half-close on EOF).

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

Signed envelope: `[u32 body_len][body][u64 time_us][32 sender_key][32 sha256(body||time||key)][65 sig]`. Followup VM gets `(tag, status, wire_body_len, bytes_written, file_head_key)`.

Backpressure: `rpcMaxPending` / `rpcMaxRequestBytes` / `rpcMaxResponseBytes` / `rpcResponseTimeoutMs`. RUDP-level pacing via `rpcRudpBytesPerSecond` / `rpcRudpBurstBytes`.

## Persistence (logkv)

Two stores: `accountStore_`, `assetStore_` (`Store<unordered_flat_map, K, V>`). Both accessed only on `logicStrand_` — no internal locking.

**Serialization modes** (thread-local, set before each `store.update()`):
- Account SerMode: `Full`=53B (creation/snapshot), `BalanceNonce`=13B (PoW/fees), `Transfer`=33B, `None`=1B (deletion)
- Asset SerMode: `Full`=236B, `Content`=210B, `Meta`=14B (owner+price), `Balance`=2B, `None`=1B. `updateAssetFast` skips WAL — content survives via snapshot only.

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

All numeric fees are raw uint64 credit values. No decimals. PRICE_UNIT exists for display only. `-1` means "use built-in default".

```
BASE_FEE_ACCOUNT     = 6'400'000      // per-day account rent
BASE_FEE_ASSET       = 25'600'000     // per-day asset rent (4× account)
BASE_FEE_TRANSACTION = 320'000        // per signed transfer/asset op
BASE_FEE_QUERY       = 20'000         // per signed query / nonce-bearing op
BASE_FEE_VM_MULT     = 50             // VM gas multiplier
```

**Load-based fee discount (feemult).** Every named per-op fee (`feeTx`, `feeQuery`, VM gas, account/asset rent, compute slot/cpu/rss, bucket, net metering) is scaled by a per-FeeKind basis-points multiplier (0..10000) before it is charged. `feeDiscountEnabled` (compiled default `true`) drives each multiplier from a live load gauge measured against a lifetime throughput watermark: an idle server discounts toward 0 (an op can cost **literally 0** when its gauge genuinely reads idle), ramping to full fee as sustained load approaches the busiest the host has ever been. It is congestion pricing, not a fixed schedule. A gauge that is *undefined* (a required cap is 0, e.g. `maxAcc`/`maxAsset`/`netPeakBps`) snaps to full price, never 0, so a missing metric can never silently zero a fee. Disabled → all multipliers pinned at 10000 (full price). The anti-spam barrier is separate (MINX PoW tickets), so 0-fee at idle is not a spam hole.

Key TOML:
```toml
min_difficulty  = 10         # PoW floor (compiled default)
no_pow_engine   = false      # true = mints no credits (dev/test)
cache_only_pow  = false      # true = lighter RAM, slower verify
threads         = 4          # task-processing threads
flush_value     = 10000
max_log_size_gb = 100
rpc_port        = 0          # CesPlex port (0 = disabled)
admin_socket    = ""         # cesco UDS (empty = disabled)

# fee_net_*           = 0    # ChannelMeter rates — 0 = observability-only
file_store_max_bytes  = 0    # 0 = file feature off
compute_max_instances = 0    # 0 = compute feature off
# compute_port_base   = 0    # 0 = instances local-only (no UDP egress)
# compute_port_count  = 0    # size of the per-instance UDP port range
# compute_process_mem_max  = 268435456    # 256 MB rlimit per child
# compute_process_cpu_max  = 50           # cgroup cpu.max %
# ces_compute_user         = "cesluad"
# ces_compute_child_binary = "cesluajitd"

# [cesplex_mounts]
# "/ces/file/1"    = "builtin:file"
# "/ces/compute/1" = "builtin:compute"
# "/ces/lua/1"     = "builtin:lua"

[[peers]]
key     = "..."
address = "host:port"
```

## Cesco admin console

Embedded in server; enabled via `admin_socket`. UDS REPL: `rlwrap socat - UNIX-CONNECT:./admin.sock`.

Commands: `snapshot`, `credit <amt> <pubkey>`, `debit <amt> <pubkey>` (clamped), `netbill` (per-channel snapshot), `help`/`h`, `quit`/`q`/`exit`/Ctrl-C. Same machinery as offline `ces credit`/`ces debit` but no shutdown required.

## `ces credit` / `ces debit` / `ces snapshot`

Offline ledger ops (no networking). Load stores, mutate, `_save()`, exit. Used by `cesnet` to pre-fund accounts. `ces snapshot` compacts event log into a fresh `.snapshot`.

## Client tools

**cesh** — CLI client. Subcommands: `keys`, `query`/`squery`, `transfer`/`payment`/`cross`, `server-info`/`ping`, `mine [-t N]` (clamped to `hardware_concurrency`), `asset` (create/update/meta/fast/fund/buy/give/query/squery/**run**), `ramfile` (L1; put/touch/get/info/scan/read/write/append/resize/rehash/fund; `--in text:|hex:|file:`), `file` (L2 disk; put/get/stat/rm/deposit/withdraw/set-price; needs `--rpc-port`), `compute` (L2; launch/kill/ps/stat/instances; needs `--rpc-port`), `dial <instance_id>` (bidirectional bytes over /ces/lua/1; stdin EOF half-closes; SIGINT/SIGTERM → 130/143; `-v` prints ATTACH-ok), `autoexec install`.

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
