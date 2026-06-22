# dicedemo

A self-contained walkthrough of CES's **Lua compute feature**, using
`/s/dice.lua` (the bundled fair-coin double-or-nothing program) as
the demo program. Each numbered script does one step; the workspace
lives in `./workspace/` and is fully self-contained.

## What this demonstrates

- **Lua compute (`builtin:compute` + `cesluajitd`)** — a sandboxed
  LuaJIT VM running as a child process under the server's
  supervision, with CPU + RSS billed per supervisor tick.
- **`/s/` server-zone files** — a curated namespace owned by the
  server's pubkey, unmetered, used to ship operator-deployed
  programs like `dice.lua`.
- **CesPlex `/ces/lua/1` dial** — the user-side primitive that turns
  a bound RUDP channel into a raw byte stream into a running compute
  instance. `cesh dial <id>` is the front-end; the program-side
  speaks via `ces.conn.set_listener` + `conn:write`.
- **The Lua API** — `ces.account_read`, `ces.transfer`,
  `ces.random_bytes`, `ces.owner_pubkey`, `ces.bucket_new` (the
  capacity-billed replay-protection cache).
- **The "server as bottomless house" pattern** — `/s/` programs run
  with the server's account as their source of funds. The server's
  account is auto-topped to `2^62` (half of `INT64_MAX`, so incoming
  transfers can't overflow signed addition) every boot and excluded
  from totalCredits; structurally, the operator can never run out
  of "money" to pay out winners. Credits are a fairness-meter.

## Prerequisites

```bash
# from the repo root:
./build.sh debug
```

You need `ces`, `cesh`, and `cesluajitd` at `build/debug/`.

## Run order

Run each script from inside `dicedemo/`. They print the next
command at the end.

| Step | Script | What it does |
|------|--------|--------------|
| 1 | `./01-setup.sh` | Wipe & recreate `./workspace`, generate the server keypair, copy `dice.lua` into the file store at `data/cesfilestore/s/dice.lua`. |
| 2 | `./02-start-server.sh` | Launch `ces` in the background with all knobs as CLI flags (no TOML). Logs to `./workspace/server.log`. Verify `extension launched dice` is in the tail. |
| 3 | `./03-wallet.sh` | Build the demo wallet — slot `@0` is a fresh client key (the dice player), slot `@1` is the server's privkey (so cesh can act as the bottomless donor). |
| 4 | `./04-fund.sh` | Transfer 1B raw credits (~10 user-credits) from `@1` (server) to `@0` (client) with `--open`. No special "operator credit" command needed — the server is just another account in the wallet. |
| 5 | `./05-play.sh` | Find the dice instance id, transfer 100 raw credits from `@0` to the house (= server pubkey), dial dice, send `play` then `quit`. Re-run to bet again. |
| 99 | `./99-stop-server.sh` | Kill the server. Workspace is left in place for inspection. |

## Expected output

`05-play.sh` prints the dice greeting (house pubkey, command list)
and one of:

```
heads. you won 200 (+100)
```

or

```
tails. house keeps 100
```

50/50, 0 house edge — the program flips via `ces.random_bytes(1)`.

## Files

- `common.sh` — shared paths/ports, sourced by every script. Binary
  paths are hardcoded relative to the repo root (`../build/debug/`).
- `0N-*.sh` — numbered demo steps.
- `99-stop-server.sh` — cleanup.
- `workspace/` — created by `01-setup.sh`, contains the server's
  data dir, log, pid, generated keys, and wallet. Wiped on rerun.

## Inspecting after the fact

The workspace is left intact when you run `99-stop-server.sh`, so:

```bash
tail -100 workspace/server.log              # what the server did
cat workspace/data/cesfilestore/s/dice.lua  # the deployed program
ls workspace/data/cescompute/               # per-instance scratch + IPC sockets
```
