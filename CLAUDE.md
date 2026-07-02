# CES

C++20 public token/credit ledger for resource accounting. Clients earn credits via RandomX PoW mining and spend them on transfers, queries, and assets. Each server is a sovereign ledger; servers peer via bilateral vostro/reserve settlement. No blockchain.

CesPlex is the L1 connection multiplexer on `rpc_port`: it runs the signed bind handshake, routes each bound RUDP channel to a named handler, and meters the channel's raw byte/time usage for the host to price. CesPlex knows no credits. The handlers riding it are L2. Shipped in CES core: `builtin:file` (disk file storage), `builtin:compute` (instance lifecycle plus Lua hosting), `builtin:lua` (channel attach into a running program). The protocol name `/ces/rpc/1` is reserved and CES ships the SYS_RPC outbound engine, but CES core mounts no inbound `/ces/rpc/1` handler; inbound RPC is L3 (downstream binaries link ceslib and host their own).

## Coding practices

- Always use `build.sh` to build and run tests. Do not invoke `cmake --build` or `cestests` directly; go through `./build.sh debug --test` (or `--teste2e`).
- Always redirect `build.sh` output to a file, then grep/tail it. Do not tail the live pipe: direct pipes lose buffered stdio output, and reading live output races the test harness for ephemeral ports.

  ```bash
  ./build.sh debug --test 2>&1 > /tmp/ces-build.log
  grep -E 'error:|FAILED|No errors|All Tests passed' /tmp/ces-build.log | tail -5
  ```

- Never reinvent wire serialization. The canonical types and API live in `<ces/buffer.h>`: `ces::Bytes` (a heap `vector<uint8_t>` that holds bytes) and `ces::Buffer` (vector-owning, cursor-tracked, auto-growing, with BE/LE `put`/`get`/`peek`/`poke` plus static raw-pointer helpers); `ces/keys.h` adds a `PublicKey` serializer. Do not hand-roll byte-shift loops, and do not type wire data as a bare `std::vector<uint8_t>`; use `ces::Bytes`. MINX has its own MTU-bounded `minx::Bytes`/`minx::Buffer` for borrowed spans; interop is byte-level. `cesluajitd`'s supervisor-IPC framing keeps its own minimal helpers, documented inline.
- `xxx.h` maps to `xxx.cpp`. Every header `include/ces/.../<name>.h` has a matching `src/ceslib/<name>.cpp` (or wherever its translation unit lives) under the same name. Renaming a header renames its cpp.
- No "Step N" or "Phase A/B" comments. Reference what the code does today, not which iteration of a plan it came from.
- Comments and authored text, including this file, commit messages, and CLI output: terse, factual, no narration or design history, plain ASCII, no em-dashes.

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
include/ces/        CES core (L1): types, account/asset, keys, protocol,
                    server/client, clientasync, cesvm, ramfilestore,
                    autoexec, cesco, cesproxy, feemult, buffer, persisted
include/ces/cesplex/  CesPlex, the L1 connection multiplexer:
                      mux     bus core: bind handshake, channel routing,
                              object mount(), CesPlexHost seam
                      wire    bind contract + per-op envelope wire format
                      session per-op serve loop + CesPlexClient (the L2
                              verb SDK file/compute ride; lua bypasses it)
                      meter   ChannelMeter: per-channel byte/time meter
                              (measures and reports; never prices or closes)
include/ces/l2/     L2 protocols riding CesPlex. Two families:
                      file_*     disk-backed file storage protocol
                      compute_*  instance hosting (compute_handler) +
                                 channel-attach (compute_lua_handler) +
                                 client lib (compute_client)
include/ces/util/   shared helpers: ctrlc, fileperm, hash, hex, log,
                    metrics, resolver, vmprogram, wallet.
                    Each include/ces/<group>/<x>.h has a matching
                    src/ceslib/<group>/<x>.cpp.
src/ceslib/         static lib mirroring the include tree: top-level
                    server.cpp (incl. SYS_RPC outbound engine), cesvm.cpp,
                    ramfilestore.cpp, accounts/assets/client/clientasync/
                    cesco; subdirs cesplex/, l2/, util/
src/ces/main.cpp    server CLI: config, key gen, ces credit/debit/snapshot
src/cesh/           shell client (main.cpp + dial.cpp/h)
src/cesluajitd/     compute child runtime (LuaJIT-hosted, default)
src/cescompmockd/   no-Lua mock child (regression-test plumbing only)
src/cesproxy/       TCP/UDP proxy with wire-level validation
src/cesbench/       in-process benchmark
src/cesqt/          Qt6 GUI: 11 tabs + JSON-RPC server (rpcserver.cpp)
extensions/         committed catalog of operator-deployable /s/ Lua
                    extensions (dice.lua + dice.md, discovery.lua +
                    discovery.md); the default extensions_dir. Install
                    copies one into a server's /s/. discovery.lua is a
                    built cesdk bundle (source: cesdk apps/discovery).
tests/              Boost.Test suites compiled into one cestests binary
                    (filter by suite name). test_common.h = CesFixture
                    (in-process server+client, 10B prefunded).
tools/cesnet.mjs    network orchestrator (init/up/down/destroy)
tools/cesnetbot.mjs parallel traffic simulator + conservation check
cesweb/             L3 HTTP gateway (Node) serving CES files plus a /dev
                    terminal via the cesh CLI; self-contained, own CLAUDE.md
```

## Data model: the two-type ledger

CES has exactly two ledger types: Account and Asset. Files, programs, schedules, namespaces, autoexec, and the market all compose out of those two. No separate file/program/namespace tables.

Account (map key = first 8 bytes of the raw pubkey, not a hash of it; a key-tail disambiguates prefix collisions):
- `balance` is sign-overloaded: positive = ordinary account, negative = unsettled payment account.
- `nonce` is the replay counter (`reqNonce == nonce+1`), overloaded on payment accounts as days-until-expiry.
- last-transfer receipt (dest/amount/time) doubles as the signed single-query payment proof.

No type field, no role flags: the sign of balance and the nonce value carry the only state distinction.

Asset (map key = full 32-byte hash):
- `owner` is the account or asset prefix that controls the cell.
- `balance` encodes days-remaining (rent) plus flag bits: immutable, asset-owned, private.
- `price` non-zero means any signer can `CES_BUY_ASSET` for that amount.
- `content` is ~210 bytes of arbitrary user bytes.

The asset is the generative primitive. Files are chains of assets; VM programs are assets (`CES_RUN_ASSET`); autoexec and scheduled runs are key-patterns on assets; `/f/<name>` namespaces are gated by who owns the asset at `sha256("/f/<name>")` (transferable via `CES_GIVE_ASSET`).

Asset day-counter is rent. Daily maintenance decrements every asset's balance by 1; assets at <= 1 die. Keep alive via `CES_FUND_ASSET`.

PRICE_UNIT = 100,000,000 (8 decimal places). Wire prices are user-facing whole credits; multiply by PRICE_UNIT for internal units.

## Cryptography (`keys.h`)

Two algorithms behind a 1-byte decorator: ED25519 (CryptoPP) and secp256k1 (libsecp256k1, RFC 6979); a signature is the tag byte plus 64 bytes. SHA256 over the input unless it is already 32 bytes. The secp256k1 context and CryptoPP PRNG are `thread_local`.

Wallet format: one key per line, `"00" + 64-hex` or `"01" + 64-hex`. Wallets validate keys at insertion.

Private vs public key (easy to get wrong when scripting cesh/ces):
- A wallet line or `cesh keys list` entry is the decorated PRIVATE key: a leading byte (`00`=ed25519, `01`=secp256k1) that is part of the key, not padding, so `"00"+64-hex` is 66 hex chars total. `keys list` is private-key-prioritized and does NOT print the public key.
- The public key is the account identity: what you credit, query, and what the ledger keys accounts by (map key = first 8 bytes of the raw pubkey). It is 64 hex chars, no decorator. `cesh keys gen` shows it in parentheses after the private key; `ces --genkeypair` labels `Private Key:` / `Public Key:`.
- Do NOT `grep -oE '[0-9a-fA-F]{64}'` a `keys list` line to get an account key: that grabs the decorator byte plus the first 31 bytes of the private key (a mangled value). Use `ces --genkeypair`'s `Public Key:` line, or the parenthesized value from `cesh keys gen`.
- Funding the wrong hex is silently self-consistent: `ces credit <wrong>` and `cesh query <wrong>` agree (both key by the same wrong prefix), but every signed/L2 op rejects it as `CES_ERROR_ORIGIN_NOT_FOUND`. If a funded account works for `query` but signed ops say ORIGIN_NOT_FOUND, you funded the wrong key.

## Wire protocol (`protocol.h`, `types.h`)

`CES_INJECT_SIGNED_METHODS` / `CES_INJECT_UNSIGNED_METHODS` macros generate `toBytes`/`fromBytes`/`verifySignature`.

Opcodes (`op_code_t`) ride the primary UDP port: transfers, account/asset queries, asset CRUD, VM run, and the unsigned peer-table read. The application lane (`app_code_t`, 0x80+) carries client/program messages (`CES_APP_COMPUTE_MSG`) over MINX's app path instead of the signed-op path. Result/error codes are `error_code_t`. These enums move; read `types.h`, do not memorize numbers.

Nonce modes: `0` skip (internal); `CES_NONCELESS` (UINT32_MAX) server assigns (settlement pipelining); `N` must equal `nonce + 1`. Auto-nonce: signed ops carry a timestamp; the server rejects stale ops and dedups by sig-hash prefix. Retried ops must reuse the same signed payload so dedup returns OK without re-executing.

## CesVM (`cesvm.h`, `cesvm.cpp`)

Harvard architecture; runs on `logicStrand_`; mutations atomic with an undo log.

`io[]` (1024 cells x 8 bytes) is the data plane only: registers, program scratch, context, preloaded caller/self keys, and fixed input/output windows. Bytecode lives in a separate `code_` buffer indexed by PC. `vmprogram.h`'s bump allocator (`pgm.allocContent()`) hands out typed scratch `Region`s so build code never types raw cell numbers.

Syscalls (`cesvm.h`) cover account/asset read and mutate, transfers (local and cross), hashing, sig-verify, code load, scheduling, deposit/withdraw, send-to-client, and outbound `SYS_RPC`. `SYS_SEND_UDP` is tombstoned (returns DISABLED).

VmProgram (`vmprogram.h`): C++ fluent API, one method per opcode, label support; emits an asset cell or a byte vector.

Cron / `SYS_SCHEDULE`: enqueues a one-shot VM run at absolute wall time; missed deadlines fire ASAP. Recurrence is a scheduled VM re-calling `SYS_SCHEDULE`. Schedule state persisted as ledger entries.

Autoexec (`autoexec.h`): boot-time hook. Asset key pattern `[8 zero][8 AUTOEXEC_KEY_MAGIC BE][8 account_prefix][8 random]`; content is a signed `CesRunAsset`. Server scans on boot and runs each via `scheduleRun` at `now`.

## L1 RAM filestore: in-asset file chain (`ramfilestore.h`)

In-ledger files as linked asset chains. The head asset holds size, hash, metadata, and the first chunk-key; each chunk holds its payload and the next chunk-key. Chunks are uploaded in reverse order so each already knows its successor.

API: `ramfilePut`/`ramfileGet`/`ramfileFund`/`ramfileScan` plus random-access `ramfileRead`/`Write`/`Append`/`Resize`/`Rehash`. Header struct `RamfileHeader`. VM-reachable via `SYS_LOAD_CODE`/`SYS_READ_ASSET`. cesh verb: `cesh ramfile`. For host-scale disk files, see the L2 file handler (`cesh file`).

## CesPlex: L1 protocol multiplexer (`cesplex/mux.h`, `cesplex/wire.h`)

Runs on `rpc_port`. Each inbound RUDP channel does a signed bind contract: the client signs `(name + client_time + client_pubkey)`; the server replies signed, committing the server pubkey and a per-channel `sessionToken`. The bind is identity-only, no prices on the wire. The handler receives `BoundChannelContext` (pubkey, payerPfx, sessionToken, bind time). A `ChannelMeter` measures each channel's raw byte/time usage (`CesPlexUsage`) and reports it to the host (`CesPlexHost::cesplexReportUsage`); the host prices it, charges the payer, and closes the channel on non-payment.

Each per-op envelope is verb + preamble + a 65-byte sig over `sha256(verb || preamble || sessionToken)`, with no per-op pubkey or timestamp (implicit on the bound channel). Body-bearing verbs append bytes hashed against a digest committed in the preamble. Dedup key is the first 8 sig bytes (per-channel-incarnation, so no cross-channel collisions).

CesServer mounts each `[cesplex_mounts]` entry as a per-server handler object: `resolveBuiltin` (server.cpp) maps `builtin:<name>` to a concrete class, constructs it once, and calls `CesPlex::mount(proto, obj)`. There is no global registry; an unknown `builtin:<name>` is logged and skipped. Errors close the channel (clients reopen). Most handlers loop on the channel; the exception is `builtin:lua` ATTACH, a one-shot verb that converts the channel into a raw byte stream into the target compute instance.

CES sets `rpcRudpMaxChannelsPerPeer = 2` so a long-lived `cesh dial` can coexist with side ops.

Handlers shipped (registered in CES core):
- `/ces/file/1` to `builtin:file`: disk-backed file storage. `l2/file_{handler,client}.{h,cpp}`
- `/ces/compute/1` to `builtin:compute`: instance lifecycle (LAUNCH/KILL/LIST/STAT/INSTANCES). `l2/compute_{handler,client}.{h,cpp}`
- `/ces/lua/1` to `builtin:lua`: one-shot ATTACH; converts the channel into a raw byte tunnel into a running compute instance. `l2/compute_lua_handler.{h,cpp}`. No client lib (use `cesh dial`).
- `/ces/peer/1` to `builtin:peer`: the server-to-server mesh. `l2/peer_handler.{h,cpp}`. Mounted only when wired in `[cesplex_mounts]` (like every builtin; nothing auto-mounts). A persistent, unmetered, bidirectional channel between two servers that are mutual peer-table entries. Peer-gated at bind (`cesplexBindAllowed`); never metered (`cesplexChannelMetered`). Self-maintains on a reconcile pass riding the rpcTaskIO tick: dial a peer we should link to but do not, drop a link whose peer left the table, keepalive the rest (a sub-60s keepalive holds the link past RUDP's idle GC and surfaces a dead peer via send failure). Lower-pubkey side dials, higher accepts (one channel per pair). The dialer rides the server's own `rpcRudp_`; the reconcile decision (`computePeerLinkActions`) is pure and separately tested.

Compute handler pair: `compute_handler` runs the management verbs and the per-instance supervisor (CPU/RSS sampling, slot/rent billing); `compute_lua_handler` runs the channel-attach protocol that pipes user bytes into a chosen instance. They are two CesPlexHandler subclasses; each .cpp includes both .h files because compute exposes APIs the lua handler calls (`computeOpenConnection`, `computeSendConnDataIn`) and lua exposes APIs compute calls (`luaHandlerHandleConnDataOut`, `luaHandlerOnInstanceDying`).

`/ces/rpc/1` protocol name is reserved; CES core ships only the outbound engine. SYS_RPC's outbound side (`RpcSession` plus `queueRpc`/`executeRpc`/`completeRpc`) lives in `src/ceslib/server.cpp`. There is no `builtin:rpc` handler in CES core; the inbound side is L3 (downstream binaries link ceslib and host their own). `MockRpcServer` in `tests/test_sysrpc.cpp` is the test fixture for this shape, not a production handler.

## ChannelMeter (`cesplex/meter.h`)

Every bound channel is tracked. A 60s tick computes per-tick deltas across four measured dimensions (bytes sent, bytes received, memory-byte-seconds of RUDP buffer residency, channel age) and reports them as a `CesPlexUsage` to the host via `cesplexReportUsage`. The meter measures and reports only; it never prices, charges, or evicts. The host (CesServer) prices the usage at its live `feeNet*` rates, posts the debit on `logicStrand_`, and evicts via `Rudp::closeChannel` if the payer cannot cover the tick. Throughput is metered per KiB (`feeNetKiBSent`/`feeNetKiBReceived`), not per byte. A `feeNet*` of 0 is a sentinel, not "free": the CesServer ctor resolves any 0 to a non-zero rate derived from the ledger fee anchors (floored to >= 1), so a live server always meters and evicts. An explicit non-zero is honored as-is.

## L2 file storage: `builtin:file`

Disk-backed, priced per byte/day (rent) and per KB (I/O), namespaced. Ten verbs, preamble-first (envelope sig over the preamble before any body, so verify and charge happen before touching the body). Every response is server-signed with `req_sig_hash`.

Verbs: CREATE (any) / WRITE (owner) / READ (any signer) / STAT (any signer; metadata only) / DEPOSIT (any) / WITHDRAW (owner) / SET_PRICE (owner) / DELETE (owner) / APPEND (owner) / RESIZE (owner). There is no unsigned path in CesPlex: STAT, like every verb, rides the signed bind and pays `feeQuery`.

Four-zone naming (mandatory):
- `/h/<64-hex-pubkey>/...` auto home dir; signer must match the hex.
- `/f/<name>/...` asset-gated; signer must own the asset at `sha256("/f/<name>")`. Transferable via `CES_GIVE_ASSET`.
- `/p/...` public; first-come-first-served on the exact path.
- `/s/...` server-deployed, unmetered, outside the cap. Only the server's own private key may CREATE/WRITE; reads are operator-donated. The handler keeps a generated `/s/index.html` catalog (`regenerateServerIndex`, on the file strand, never `logicStrand_`). `/s/` is the only enumerable zone, and safely so since it is operator-write-only. Every other zone is non-enumerable (no LIST verb exists): the path is the capability.

Anything else returns `BAD_NAME`. Zone ownership is checked only at CREATE; subsequent ops use the sidecar's stamped `owner_pubkey`.

Three-cost model:
- `feeFileRent`: credits per byte-day; drains `file_balance`.
- `feeFileWrite`: per KB; drains `file_balance` at WRITE/APPEND.
- `feeFileRead`: per KB; drains the reader's account (burned; even the owner pays).

Plus `feeQuery` from the bound signer on every signed op. READ also pays the owner's `price_per_kb` into `file_balance` (waived for owner reads). CREATE has no per-byte cost (sparse). `/s/` is exempt and lives outside `cesFileStoreMaxBytes`.

On-disk: paths mirror the filesystem under `cesFileStoreDir`. Each file is content at `<path>` plus a TOML sidecar at `<path>.sidecar.toml` (owner_pubkey, file_balance, price_per_kb, size, timestamps, last_rent_us; written atomically). A global `.store.toml` holds `total_files`/`total_bytes`/`last_gc_us`, guarded by one process-wide mutex.

Rent is lazy: every non-DEPOSIT op rolls rent forward (`size x feeFileRent x elapsed`); if `file_balance < owed` the file is deleted mid-op and returns `FILE_NOT_FOUND`. CREATE/APPEND/RESIZE-grow require >= 15 minutes upfront rent on the delta. A CREATE that overflows `cesFileStoreMaxBytes` triggers `gcReclaim(bytesNeeded)`, which deletes files whose balance cannot cover owed rent, debounced to at most one scan per 15 min.

Cross-handler exec: `fileHandlerExec(req, cb, executor)` is an in-process verb path used by `builtin:compute`. The Lua program acts under owner X's authority but all credits are billed to the source file's `file_balance`, not X's account; refunds land back there. Zone-ownership still applies.

Master switch: `cesFileStoreMaxBytes = 0` disables the feature; `> 0` enables it with that hard cap.

## L2 compute: `builtin:compute`

Hosts user programs. LAUNCH spawns a child process (default `cesluajitd`) with Unix-domain-socket IPC. The supervisor tick (default 60s) samples /proc CPU+RSS and debits the source file's `file_balance` for slot-seconds, cpu-seconds, and rss-byte-days. Out of funds means SIGKILL; a deleted source file SIGKILLs all its instances.

Five verbs, keyed three ways: LAUNCH and KILL (owner-gated, they mutate); LIST (by signer; your own instances, incl. `file_balance`); STAT (by pid; public to any signer; pid/uptime/cpu/rss/ports/name); INSTANCES (by source path; public; one record per live instance incl. ports). STAT and INSTANCES expose each instance's leased ports (outbound CES-client and inbound `/ces/luarpc/1` host; 0 = no lease) so anyone can find a running service and reach it, relayed via the server's rpc port (`/ces/lua/1`) or direct to the instance's own port. LAUNCH mints a fresh `pid` (multiple per source up to `computeMaxInstances`) and requires 15 min upfront slot+rss rent in `file_balance` or fails `COMPUTE_FUND_TOO_LOW`.

Bind prereqs: `computeMaxInstances > 0`, `builtin:file` registered, `computeUser` resolvable.

Per-instance ports: each instance gets a CES client on a statically-allocated UDP port from `[computePortBase, computePortBase + computePortCount - 1]` (TOML `compute_port_base` / `compute_port_count`; flags `--computeportbase` / `--computeportcount`), leased RAII and released on instance death. A fixed source port is what makes P2P work behind a firewall. `computePortBase == 0` means no range: instances launch local-only and their `ces.transfer` / remote verbs error permanently with `networking disabled`. Allocation is best-effort: an exhausted range is not a launch failure; the instance gets port 0 (local-only) and stays reachable via the `/ces/lua/1` relay, so `compute_port_count = 0` is valid. Each instance is leased two ports independently and best-effort (outbound CES-client port, and the instance's own inbound `/ces/luarpc/1` host), so it may get both, one, or neither. The Lua program does not own the socket; the C++ host runs the packet processor and passes the program its reserved port numbers in the bootstrap frame.

cesluajitd: one sandboxed LuaJIT VM per process, with no `os`/`io`/`debug`/`require`/`loadstring`/`ffi`. The supervisor frames IPC over the UDS and hands the child a bootstrap frame with its identity (owner key + program keypair), its reserved ports, and the source. The Lua API surfaces client messaging, the file store (owner-authority, billed to the source's `file_balance`), `ces.transfer` / `account_read` / `random_bytes`, identity and time helpers, capacity-billed `bucket`s, and the unified `ces.conn` raw byte-stream API.

`[extension]` auto-launches named Lua programs from `/s/` at boot. For each enabled name, `launchExtensions` calls `computeHandlerLaunchInternal("/s/<name>.lua")` (no auth/dedup/upfront fee). The source is operator-deployed, not embedded in the binary: the operator drops `<name>.lua` into `<storeDir>/s/` (startup reconcile stamps its sidecar before launch); a missing source logs a WRN and is skipped. The repeatable flag is the generic `--extension <name>`. Shipped: `dice` (fair-coin double-or-nothing whose house bankroll is the file's program account, `ces.program_pubkey()`); and `discovery` (a built cesdk bundle that keeps the host's peer table populated and gossips known servers via paid sample exchange).

## L2 lua: `builtin:lua` (channel routing)

A user binds `/ces/lua/1` and sends one ATTACH naming a `pid` (a running instance, discovered via compute STAT/INSTANCES, not a source path). If that instance has its accept gate open (`ces.conn.set_listener` called), the handler allocates a `conn_id`, sends TAG_CONN_OPENED to the child carrying the ATTACHing user's authenticated pubkey, and the RudpStream becomes a raw byte pipe: user-to-program wraps as TAG_CONN_DATA_IN; `conn:write` from Lua routes back as TAG_CONN_DATA_OUT. Either side closing tears down both directions; instance death tears down all routes. Gate closed returns `NOT_LISTENING`; instance missing returns `COMPUTE_INSTANCE_NOT_FOUND`.

`cesh dial <pid>` is the user-side primitive (stdin/channel/stdout, half-close on EOF).

## L2 luarpc: `/ces/luarpc/1` (per-instance byte stream)

Not a CES-core builtin. Each compute instance hosts its own CesPlex on its second leased port via `CesPlexEndpoint` (`cesplex/endpoint.h`), serving `/ces/luarpc/1`. Same semantics as `builtin:lua`: after the signed bind the channel collapses into a raw, opaque byte pipe (no host framing or buffering; any grammar lives in Lua). The difference from `/ces/lua/1` is topology, not framing: `/ces/lua/1` is server-relayed into the instance (always reachable, even a port-0 instance); `/ces/luarpc/1` is dialed directly at the instance's own firewall-punchable port (no relay), but only if the instance got an rpc port. It is also the program-to-program path.

One `ces.conn` API serves both transports. A program does not distinguish relay from direct. listen via `ces.conn.set_listener{on_open,on_data,on_close}` (one call arms the relay accept gate and lazy-opens the direct endpoint; nil closes both). dial out (direct only) via `ces.conn.connect(addr, server_pubkey)`. run via `ces.conn.run()` (= `ces.run()`), the one loop that pumps both. A conn is `{id, source, pubkey, write(bytes), close()}`: `conn.id` is a host-owned uid unique across both transports (safe as a program key); `conn.source` is `0` (relay) or `1` (direct) for origin info only, never routing or identity. Tested in `tests/test_luarpc.cpp` (program-to-program echo plus file/compute clients; needs real Lua) and `tests/test_lua_conn.cpp` (relay).

## L2 async: cesluajitd concurrency model

One Lua thread, cooperative coroutine scheduler in the C++ host (`src/cesluajitd/main.cpp`); no preemption, no parallelism. Blocking-looking host calls (`ces.ping`, `ces.transfer`, `account_read`, file/compute client verbs, `ces.conn.connect`) yield the coroutine when called from one and block inline when called from the host thread, with the same value-return signature either way (`local x = ces.ping(...)`; the next line runs only once `x` is ready). No callbacks, no function coloring.

Coroutine contexts (calls yield; the VM keeps serving others): `ces.spawn(fn)`; conn handlers `on_open`/`on_data`/`on_close` (one live coroutine per conn, later frames queue while it is parked); `ces.every(ms, fn)` ticks (dispatched per fire as a coroutine, skip-if-busy). Host-thread contexts (calls block inline, cannot yield): the program main chunk and `ces.extension_admin` callbacks.

`ces.sleep(ms)` (coroutine only) parks for `ms`; `ces.sleep(0)` is the voluntary yield (return to the run loop, service pending inbound, resume).

`ces.chan()` is a CSP message channel. `ch:send(v)` enqueues any Lua value, never blocks, returns `false` on a closed channel; `ch:recv([timeout_ms])` returns the next value or `nil,"timeout"` / `nil,"closed"` (default 10000 ms); `ch:close()` wakes parked receivers and drops later sends. It carries whole values, not bytes. Tests: `ChanTests` / `AsyncTests` / `AsyncConnTests` in `tests/test_async.cpp`.

Invariant: every wait has an external backstop (a network `timeout_ms`, the host reply, or process death). No primitive waits on a program-internal event that may never arrive; `recv`'s default timeout keeps channels inside that rule.

## Payment accounts

Created via `CES_CREATE_PAYMENT`. Cost = `(2 + days) * feeAccount`. New account: `balance = -amount`, `nonce = 1 + days` (expiry countdown). Daily maintenance decrements the nonce; the account is deleted at nonce <= 1. `settlePayment`: an incoming transfer must match the exact `|balance|`; on match, balance is set to amount and nonce cleared.

## Daily maintenance

09:00 UTC daily:
- Payment accounts (balance < 0): decrement nonce; delete if nonce <= 1.
- Regular accounts (balance >= 0): deduct `feeAccount`; delete if balance <= fee.
- Assets: decrement balance by 1; delete if balance <= 1.

Logs a per-pass summary and triggers an auto-snapshot. Flat files have no periodic rent pass: rent is lazy (every non-DEPOSIT op rolls it forward; JIT GC fires on CREATE if the cap is exceeded). KV-file cells, by contrast, ARE swept on this daily pass: `sweepKvRent` charges each cell its per-byte rent and erases zero-balance keys (the daily tick is the only place kv-cell rent is charged; kv ops do not roll rent per-touch like flat files do). Compute instances are billed on the supervisor tick, not maintenance.

## Inter-server settlement

Each server is a sovereign ledger; no global state, no shared chain. The network is a mesh of sovereign ledgers connected by bilateral correspondent banking: each peer-pair maintains two reciprocal accounts.

- Vostro: an account on our server, keyed by the peer's pubkey; what we owe the peer.
- Reserve: our account on the peer's server; what the peer owes us.

Cross-transfer flow: debit origin, credit vostro, return CES_OK immediately, then async `openTransfer` to the peer via `CesClientAsync`; the peer debits reserve and credits dest. No round-trip required.

`CesClientAsync` runs multiple channels per peer (each with its own MINX ticket chain); a per-channel state machine drives handshake to request to idle; a sweep timer retries timeouts and gives an op up at its deadline (settlement after the nonceless dedup window, gossip after a short window). Backpressure exposes a `load()` percentage and a hard cap. All settlement uses `CES_NONCELESS`. `cesnetbot` verifies the invariant: across all servers, sum of balances plus vostro/reserve equals total minted.

## CES_GOSSIP (`protocol.h`, `server.cpp`)

A conserved, capped multicast value-disperser on the main UDP port (`CES_GOSSIP` opcode); gossip is one rider, the message is just a payload. Each hop forwards to a random `gossipFanoutDegree` subset (default 6; `0` = every funded peer) of its funded corridors, so the budget divides by a constant degree per hop. Re-signed each hop: `originId` is the immediate sender, `authorId`/`msgId` carry unchanged for provenance and dedup, `dest` all-zero means broadcast else a targeted route. `budget` is the value that flows (whole credits). Cycles die via a bounded `BucketCache<HashPrefix, GossipCharge> gossipSeen_`. `handleGossip` runs on `logicStrand_`.

Per-hop economics: a receiver Y of a gossip from sender X with budget b collects `min(b, X-on-Y)` (the budget capped by the sender's reserve held here), skims `feeTx`, fans the remainder across the chosen subset (each peer capped by our cached reserve there and by `maxPeerReserveDisturbance`), and charges only `skim + fanned` from X-on-Y, acking the amount so X mirrors it into Y-on-X. Each leg is a conserved pair, so total credit is conserved. A failed hop fires `paid = 0` (no credit mirrored), so it burns rather than mints. `splitCapped` is a pure, separately-tested function (conservation, caps, maximality).

Sink: when a server hosts the `dest` pubkey it uniquely hosts (a running compute program/extension registered at LAUNCH via `registerSinkTarget`, or itself), it is the sink and ends the flood. It does leg 2 only: drain `min(budget, sender-reserve-here)`, skim `feeTx`, credit the remainder into `dest`'s account here, and reply `paid = skim` so the sender mirrors only the skim. The delivered remainder reaches `dest` with no leg 1 (a leg-1 credit on it would mint). Terminal, no fan-out. Deduped by msgId, so a retransmit re-acks without re-charging. `dest == self` burns the delivered amount into the bottomless self-account.

Producer: `CesClient::gossip(msg, budget, dest)` and `cesh gossip <msg> <budget> [dest]` (no dest = broadcast). `handleGossip` is sender-agnostic, so a client-originated gossip collects from the client's account on its home server.

Consumer (L2 Lua): L1 never interprets the message. On a gossip (received or self-originated) the server calls `deliverGossipLocal`, hops onto `rpcTaskIO_`, and fans a `TAG_GOSSIP_IN` frame to every local compute instance. The child calls the program's global `on_gossip(msg, {author, sender, msgid, dest})` as a coroutine if defined. Outbound from a program: `ces.gossip.send(msg, budget [, dest])` (msg <= 1024 B). The program's source `file_balance` is debited the full budget up front, then refunded `budget - fanned`. Tests: `test_gossip.cpp` (economics and conservation), `test_luarpc.cpp` (real-Lua delivery and sink credit).

## SYS_RPC

Requires `rpc_port != 0` (default 0 = disabled, returns `CES_ERROR_DISABLED`). A second MINX instance (`rpcMinx_`) is wired to RUDP via the `stdext` dispatcher.

Three-stage flow: `queueRpc` (logicStrand) reads the request from a ramfile, builds a signed envelope, queues it; `executeRpc` (rpcTaskIO) opens an RUDP channel, sends, waits 30s (`rpcSessions_` lives only here); `completeRpc` (logicStrand) writes the response into a file chain and schedules a follow-up VM run.

The request is a signed envelope (body + timestamp + sender key + sig). The follow-up VM run receives the status and the response file-head key.

Backpressure: `rpcMaxPending` / `rpcMaxRequestBytes` / `rpcMaxResponseBytes` / `rpcResponseTimeoutMs`. RUDP-level pacing via `rpcRudpBytesPerSecond` / `rpcRudpBurstBytes`.

## Persistence (logkv)

Two stores: `accountStore_`, `assetStore_` (`Store<unordered_flat_map, K, V>`). Both accessed only on `logicStrand_`; no internal locking.

Serialization modes are thread-local, set before each `store.update()`: a `Full` mode (creation/snapshot) plus narrower modes for hot paths (balance+nonce, transfer, content, meta, balance-only) and `None` for deletion. `updateAssetFast` skips the WAL; content survives via snapshot only.

Snapshots: the log grows until `max_log_size_gb`, then `forkSave` (`fork(2)`, child writes `.snapshot` while the parent serves). Graceful shutdown, cesco snapshot, and daily maintenance also fire one. Recovery loads the newest `.snapshot` and replays the WAL suffix. 30s debounce.

## Concurrency model

Five thread groups:
1. netIO (1): UDP send/receive.
2. taskIO (N, configurable): MINX dispatch plus `logicStrand_` for all ledger mutations.
3. verifyPoW (1): RandomX verification.
4. settlementIO (1): CesClientAsync async I/O.
5. rpcTaskIO (1): rpc-port Minx + CesPlex sessions + handler `serve` + ChannelMeter tick + compute supervisor tick.

`logicStrand_` is the lock. No ledger mutexes. Cross-handler primitives (e.g. `fileHandlerExec`) hop onto `logicStrand_` internally as needed. Replies are retransmitted on a timer to paper over UDP loss.

## Configuration

CLI flags override TOML, which overrides compiled defaults. `ces --config` dumps the default template. `ces --genkeypair` prints a new keypair.

All numeric fees are raw uint64 credit values (no decimals; PRICE_UNIT is display-only; `-1` means use the compiled default). Compiled defaults cover account/asset rent, per-tx, per-query, and a VM-gas multiplier.

Load-based fee discount (feemult): every named per-op fee (`feeTx`, `feeQuery`, VM gas, account/asset rent, compute slot/cpu/rss, bucket, net metering) is scaled by a per-FeeKind basis-points multiplier (0..10000) before it is charged. `feeDiscountEnabled` (compiled default true) drives each multiplier from a live load gauge measured against a lifetime throughput watermark: an idle server discounts toward 0 (an op can cost 0 when its gauge reads idle), ramping to full fee as sustained load approaches the busiest the host has seen. A gauge that is undefined (a required cap is 0, e.g. `maxAcc`/`maxAsset`/`netPeakBps`) snaps to full price, never 0. Disabled means all multipliers pinned at 10000 (full price). The anti-spam barrier is separate (MINX PoW tickets), so 0-fee at idle is not a spam hole.

Feature master-switches (full template via `ces --config`): `rpc_port` (0 disables CesPlex and SYS_RPC), `web_port` (0 disables the dashboard; loopback-only, no auth), `file_store_max_bytes` (0 disables the file feature), `compute_max_instances` (0 disables compute, needs file), `compute_port_base`/`_count` (per-instance UDP range), `admin_socket` (cesco UDS), `min_difficulty`/`no_pow_engine`/`cache_only_pow` (PoW), plus the `[[peers]]`, `[cesplex_mounts]`, and `[extension]` tables.

## Cesco admin console

Embedded in the server; enabled via `admin_socket`. UDS REPL: `rlwrap socat - UNIX-CONNECT:./admin.sock`.

Commands: `snapshot`, `credit <amt> <pubkey>`, `debit <amt> <pubkey>` (clamped), `netbill` (per-channel snapshot), `help`/`h`, `quit`/`q`/`exit`/Ctrl-C. Same machinery as offline `ces credit`/`ces debit` but with no shutdown required.

## Web admin dashboard (`webadmin.h`/`webadmin.cpp`)

The in-server operator dashboard (class `WebAdmin`), distinct from `cesweb` (the separate Node L2-file gateway). Localhost HTTP admin UI, enabled via `web_port` (0 = disabled). No authentication: binds loopback only (`web_bind`, default `127.0.0.1`); reach it over an SSH tunnel. A 0-or-1-client Boost.Asio HTTP/1.1 server on its own io_context/thread, serving the single-page UI as one embedded string.

- Overview: identity, live stat cards, load gauges, feature flags.
- Peers: add/remove/list peers plus runtime peer target. Shows both directions (outbound us-to-them, inbound their PoW to us).
- Inspect: server-info a remote by address (free handshake to pubkey/min-difficulty/reachability, optional paid KV info); Mine to bootstrap a reserve; Add as outbound peer.
- Wallet (transfer, credit/burn, snapshot), Lookup (account/asset/file), Billing (ChannelMeter), Fees (base-fee editors plus live multipliers), File / Compute (L2 monitoring plus fee/cap editors), Logs (live tail), Config (knobs, live fee multipliers, hello-banner editor).

GET endpoints emit hand-rolled JSON; POST actions take form-urlencoded bodies. Ledger reads hop onto `logicStrand_` via a `std::future`; remote inspect/mine run on worker threads joined at `stop()`, never the io thread. The live log tail is a bounded in-memory `LogRing` fed by a Boost.Log sink. Tests: `tests/test_webadmin.cpp` (suite `WebAdminTests`) drives every endpoint over raw TCP against an in-process server.

Hello banner: `<data_dir>/hello.txt` is a UTF-8 string capped at 160 bytes (trimmed on a codepoint boundary), seeded at boot and served in `CES_QUERY_SERVER_INFO` as the `hello` field. The dashboard's Config tab is the only other writer.

## `ces credit` / `ces debit` / `ces snapshot`

Offline ledger ops (no networking). Load stores, mutate, `_save()`, exit. Used by `cesnet` to pre-fund accounts. `ces snapshot` compacts the event log into a fresh `.snapshot`.

## Client tools

cesh: CLI client. Subcommands: `keys`, `query`/`squery`, `transfer`/`payment`/`cross`, `server-info`/`ping`, `peer-info <id> <server>` (unsigned peer-table slot read), `mine [-t N]` (clamped to `hardware_concurrency`), `asset` (create/update/meta/fast/fund/buy/give/query/squery/run), `ramfile` (L1; put/touch/get/info/scan/read/write/append/resize/rehash/fund; `--in text:|hex:|file:`), `file` (L2 disk; put/get/stat/rm/deposit/withdraw/set-price; needs `--rpc-port`), `compute` (L2; launch/kill/ps/stat/instances; needs `--rpc-port`), `dial <pid>` (bidirectional bytes over /ces/lua/1; stdin EOF half-closes; SIGINT/SIGTERM to 130/143; `-v` prints ATTACH-ok), `gossip`, `autoexec install`.

Two output modes: default is human (headers plus aligned fields). Global `-q`/`--quiet` is silent/pipe mode: stdout is data only (raw bytes for content; JSON for structured results), all human chrome suppressed, errors to stderr with a nonzero exit. The server's rpc port is discoverable without `--rpc-port`: free `ces ping` and the paid `server-info` advertise `rpcPort`.

`cesh --help-all` for the full verb list. Server: `--server host:port` or `$CESH_SERVER`. Wallet priority: `--wallet PATH` over `$CESH_WALLET` (inline, colon-separated keys, the format `cesh keys export` emits, NOT a path) over `~/.cesh/CESH_WALLET`. `@N` selects a 0-based key index within the wallet.

cesqt: Qt6 GUI wrapping cesh verbs. 11 tabs (Wallet/Account/Transfer/Mining/Create/Assets/Market/Keys/Servers/Console/About). Localhost JSON-RPC (`rpcserver.cpp`, port 21008) for browser apps with per-origin sandboxed keys. Built when the `CESQT` CMake option is enabled.

cesproxy: TCP/UDP proxy for non-UDP clients. `CesProxy` is a `MinxProxy` subclass plus wire-level validation.

cesbench: in-process benchmark. Server and client in one binary. Tunes `threads`, `flush_value`.

cesweb: HTTP gateway (Node) serving a server's L2 files to browsers, plus a `/dev` terminal into L2 programs; shells out to `cesh`. Lives in `cesweb/` with its own CLAUDE.md. Distinct from the in-server `webadmin` dashboard: cesweb is an external Node proxy to the L2 file store; webadmin is the embedded loopback operator UI.

cesluajitd / cescompmockd: compute children spawned by the supervisor. Default `cesluajitd` (LuaJIT); `cescompmockd` is a no-Lua plumbing-test stub.

## Logging (`blog.h` from MINX)

```cpp
LOG_MODULE("csv")
LOGINFO  << "started" << VAR(port);
LOGDEBUG << "failed"  << VAR(rc) << SVAR(addr);
LOGTRACE << "packet"  << BVAR(payload);
```

Macros: `LOGTRACE`/`DEBUG`/`INFO`/`WARNING`/`ERROR`/`FATAL`. `VAR(x)` native, `SVAR(x)` string-convertible, `BVAR(x)` bytes-as-hex. `blog::fast_min_level` is a plain int (zero overhead for disabled levels). `blog::enable("module")`, `blog::set_level("module", blog::trace)`. `ces::setupLogger("debug")` is the shared CLI parser (`util/log.h`).

Module names: `csv` server, `ccl` client, `acc` accounts, `ast` assets, `cesvm` VM, `cesco` admin, `ceslib` wallet, `plex` CesPlex core (mux/session/endpoint/meter), `file` builtin:file, `compute` builtin:compute (incl. program `ces.log` output), `lua` builtin:lua, `cfc` CesFileClient, `ccc` CesComputeClient.

Production policy: INFO = lifecycle only. DEBUG = failure conditions. TRACE = per-op firehose (not for production).

## Testing

CesFixture (`tests/test_common.h`): in-process server plus CesClient plus temp dir; client pre-funded 10B; auto-cleaned. All tests compile into one `cestests` binary; filter by suite name.

```bash
./build.sh debug --test AccountTests
./build.sh debug --teste2e            # E2E (shells out to cesh + cesnet/cesnetbot)
```

Network simulator:
- `tools/cesnet.mjs`: local multi-server topology. `init N` creates N workspaces; `up`/`down`/`destroy`. Workspaces persist across up/down with a manifest plus PID file.
- `tools/cesnetbot.mjs`: traffic on top of cesnet. K simulated users, parallel local and cross-server transfers, then verifies credit conservation: sum of all accounts plus vostro/reserve equals total minted. Drift is a bug.

```bash
./cesnet init 3 && ./cesnet up
./cesnetbot run --users 10 --rounds 5
./cesnet destroy
```

## Key invariants

- All ledger mutations on `logicStrand_`; never touch stores from other threads.
- Thread-local `SerMode` set before every `store.update()`/`persist()`.
- `updateAssetFast` skips the WAL; only when durability is optional.
- Auto-nonce retries must reuse the same signed payload (dedup matches the sig hash).
- Cross-transfers are fire-and-forget: CES_OK to the user before async delivery to the peer.
- Payment account `nonce` is days-until-expiry, not a replay counter.
- `isConnected() == true` bypasses the spam filter and tickets; only for authenticated peers.
- `rpc_port = 0` disables SYS_RPC and CesPlex entirely (VM gets `CES_ERROR_DISABLED`; no L2 binds; no ChannelMeter; no peer mesh). With the plex port up, CesPlex is always constructed (even with zero handlers mounted), so inbound channels are accepted at the channel level and rejected at the per-protocol bind gate, not at channel accept.
- `builtin:peer` (`/ces/peer/1`): mounted only when wired in `[cesplex_mounts]` (no auto-mount); admits only peer-table members and is never metered (server-to-server, both ends bottomless). One channel per pair (lower pubkey dials), held open by keepalives, reconciled against the peer table on the rpcTaskIO tick. No new thread.
- `cesFileStoreMaxBytes = 0` disables the file handler entirely; compute requires file.
- `computeMaxInstances = 0` disables compute entirely.
- CesPlex per-op verifies use the sessionToken, not a per-op timestamp. Bound pubkey is implicit. Dedup hash is the first 8 sig bytes.
- CesPlex carries no prices. The bus measures raw byte/time usage and reports it to the host, which prices at its live `feeNet*` rates and closes on non-payment. A client wanting the schedule asks via `CES_QUERY_SERVER_INFO`.
- Most CesPlex handlers loop on their channel. Exception: `builtin:lua` ATTACH is one-shot.
- File-store bytes need >= 15 min upfront rent at CREATE/APPEND/RESIZE-grow (`initial_deposit >= upfront(size)` or `INSUFFICIENT_BALANCE`). `/s/` exempt.
- File paths must start with `/h/<64-hex>/`, `/f/<name>/`, `/p/`, or `/s/`; anything else returns `BAD_NAME`.
- `/s/` requires the server's own private key as signer. Only the operator deploys; reads are unmetered. `fileHandlerDebitBalance`/`CreditBalance` no-op on `/s/`.
- Compute fees come out of the source file's `file_balance`, not the launcher's account. Refunds land back there.
- The server's own account is uncounted and bottomless. Force-reset to exactly `2^50` every boot (below `INT64_MAX`, so incoming transfers cannot overflow); excluded from `totalCredits_` and from cesnetbot's conservation sum (server-self cells skipped, vostro/reserve cells on peers still count).

## RandomX (via MINX)

CPU-hard PoW for Sybil-resistance on minting (credits from PoW only; no premine). The default keeps the full dataset in RAM for fast verify; `cache_only_pow = true` trades speed for memory. Solutions arrive on the main UDP port as unsigned packets; verification runs on its own thread. `min_difficulty` is the per-solution hash floor; higher-difficulty solutions mint more credit. `no_pow_engine = true` for dev/test (no minting).

The engine also verifies main-port anti-spam tickets, so with `no_pow_engine = true` signed ops on the main port (transfer, squery, `CES_QUERY_SERVER_INFO`, mint) silently drop and the client times out. The free MINX `GetInfo` (cesh `ping`) and all rpc-port CesPlex/L2 traffic (file/compute binds and verbs) are ticketless and work without the engine. So a pure file/compute-serving box can run `no_pow_engine = true` (instant boot, no RandomX RAM); only nodes that accept mints or serve signed main-port ops need the engine. The cesweb file gateway uses `ping` plus `--server-key` plus rpc-port READ, never a signed main-port op.

## Dependencies

```
CES
- MINX (UDP, anti-spam PoW, ticket system, RUDP, MinxProxy)
  - RandomX (CPU PoW, large in-RAM dataset)
- logkv (event-sourced K,V persistence)
- CryptoPP (ED25519)
- secp256k1/Bitcoin Core (ECDSA)
- Boost (asio, log, filesystem, unordered_flat_map)
- LuaJIT (cesluajitd)
- Qt6 (GUI only)
```
