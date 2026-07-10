# /s/hylesolo.lua

A single-node hyle blockchain hosted inside a CES server, shipped as an
extension.

`hylesolo` boots a SINGLE-NODE (transportless) `hyle-services` chain in
the extension's own `cesluajitd` process, over the `ces.hyle.solo`
binding. The extension's own program key is the sole validator and
proposer, so it reaches its own 1-of-1 quorum and commits one block
every `block_pace_ms` with no peers and no network. The extension config
IS the hyle genesis/economy config.

Enabling the extension does NOT start a chain: it loads and lets you set
the config. Two admin buttons drive it:

- **Start** boots a node from the current config and begins the block
  heartbeat.
- **Stop** tears the node down (the chain is in-RAM only, so it is
  dropped).

Disabling or uninstalling the extension kills the `cesluajitd` process,
which destroys the in-process node too, so that also stops the chain.

The `hyle` name and namespace are reserved for a future
transport-enabled multi-node chain; `hylesolo` runs side-by-side with
it, in its own `/s/` file and its own instance.

The full design lives in the cesdk source tree (`apps/hylesolo/`); this
file is the built single-file bundle the operator deploys.

---

## Prerequisite: a `--hyle` node

`ces.hyle.solo` only exists when `cesluajitd` was built with the hyle
consensus engine linked in:

```
./build.sh release --hyle
```

That fetches `hyle` (core + services) from GitHub and statically links
it into `cesluajitd`; the first such build is slow (it also pulls
Rust / malachite-cpp). A normal build omits it, and then this extension
still installs and enables cleanly but **Start** reports:

```
ces.hyle.solo absent -- build the node with --hyle
```

so a non-hyle node degrades gracefully rather than failing.

---

## Operator: enabling hylesolo on a server

`hylesolo` is a local, transportless program: it needs the L2 stack
(file + compute + lua) but no outbound networking and no compute port
range. In your server config:

```toml
rpc_port              = 53831       # > 0: the L2 stack is up
file_store_max_bytes  = 104857600   # any value > 0 (compute needs file)
compute_max_instances = 8           # any value > 0
# no compute_port_base needed -- hylesolo is single-node and transportless

[cesplex_mounts]
"/ces/file/1"    = "builtin:file"
"/ces/compute/1" = "builtin:compute"
"/ces/lua/1"     = "builtin:lua"

[extension]
hylesolo = 1
```

Equivalent CLI flag: `--extension hylesolo` (repeatable).

The `--hyle` `cesluajitd` must be on the server's `PATH`, or set
`compute_child_binary = "/abs/path/to/cesluajitd"`.

No PoW and no peers are required: the extension is a pure local L2
compute program, so a box that only runs hylesolo can set
`no_pow_engine = true`.

**Deploy hylesolo.lua to /s/.** `/s/` is operator-controlled at the disk
level. Copy the file directly into `<storeDir>/s/`:

```
cp extensions/hylesolo.lua <data_dir>/cesfilestore/s/hylesolo.lua
```

`<storeDir>` is `file_store_dir` if set, otherwise
`<data_dir>/cesfilestore`. At boot the file handler walks `s/`, sees an
`/s/hylesolo.lua` content file with no sidecar, and auto-generates one
(owner = server pubkey). Then the autolaunch path picks it up. Look for
these lines in the log:

```
builtin:file /s/ sidecar generated   /s/hylesolo.lua  size=...
builtin:compute launched             id=1 ...
extension launched                 hylesolo  /s/hylesolo.lua
```

If `/s/hylesolo.lua` is missing you will see
`WRN extension: launch failed hylesolo /s/hylesolo.lua` and the server
keeps running.

Enabling only loads the program. Press **Start** on the Extensions tab
(or run the `start` command) to boot the chain.

---

## Configuration

Optional. Drop `/s/hylesolo.conf` (a `key = value` file) to override
defaults; absent keys keep the built-in defaults shown here. The config
is read on Start, so re-Start after a change. The config IS the hyle
genesis/economy config.

```
chain_id = hylesolo           # chain identity
block_pace_ms = 1000          # one committed block per this interval
alloc = 1000000000            # genesis allocation to the program's own account
fee_transfer = 1              # economy fees (whole credits)
fee_entry = 1
fee_mint = 1
reward_base = 2               # floor-difficulty mint reward per block, to the proposer
```

All values are whole credits. `alloc` funds the program's own account at
genesis; `reward_base` is minted to the sole validator (also the program
itself) each block, so its balance climbs as the chain advances.

---

## Observability

The Extensions tab of the web dashboard renders hylesolo's mene panel: a state
badge, live metric tiles (height with a per-block sparkline, validator balance,
txs, queries), the chain detail rows, a copyable validator pubkey, the
Start/Stop chain buttons (Stop asks for confirmation), and a genesis/economy
config form that persists /s/hylesolo.conf (takes effect on the next Start). The flat status map
below stays registered for API consumers:

- `state` -- `stopped` (loaded, no chain) or `running`.
- `chain` -- the running chain id.
- `height` -- committed block height (climbs at `block_pace_ms`).
- `balance` -- the sole validator's own minted balance (climbs by
  `reward_base` per block; the visible payoff of the economy).
- `accounts` -- account (a) cell count in the RAM state.
- `entries` -- entry (e) cell count in the RAM state.
- `txs` -- ops committed into blocks, lifetime of the running node.
- `queries` -- chain-read calls routed through the extension, lifetime.
- `last_block` -- wall-time (unix seconds) of the last committed block.
- `validators` -- `1 (self)`.
- `self` -- the validator pubkey (this program's own key).

Watch `height`, `balance`, and `last_block` climb together to confirm
the chain is producing and the economy is minting.

The state is in-RAM and not persisted; all counters reset on the next
Start. `accounts` starts at 1 (the genesis-funded validator) and
`entries`/`txs` at 0: a solo chain that only ticks produces empty
blocks, so these move once an op-submission path (transfer / entry /
mint) is added. `queries` climbs as the dashboard polls the status.

---

## Files

- `hylesolo.lua` -- the program (operator deploys this to `/s/`); the
  built single-file bundle, generated from the cesdk `apps/hylesolo`
  source. Do not hand-edit; rebuild it in cesdk and re-ship.
- `hylesolo.md` -- this manual.
