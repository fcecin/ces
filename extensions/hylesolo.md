# /s/hylesolo.lua

A hyle blockchain hosted inside a CES server, shipped as an extension.

`hylesolo` boots a hyle chain in the extension's own `cesluajitd` process,
over the `ces.hyle` binding. The extension's own program key is the sole
validator and proposer, so it reaches its own quorum and commits a block
every `block_pace_ms` with no peers and no network. The extension config
IS the hyle genesis and economy.

It implements the WHOLE hyle interface -- ops, entries, governance, sudo --
against a real `hyle::services::Runtime`. A one-validator set only means that a
supermajority is one signature, so a proposal executes in the block that opens
it. Programs and clients written against it move to a real multi-node chain
unchanged. It is the development net.

The full design lives in the cesdk source tree (`apps/hylesolo/`); this
file is the built single-file bundle the operator deploys.

---

## The service

A hyle `entry` is a K,V mapping with an owner and a rent balance, so the
chain already IS the service:

| verb | hyle op |
|---|---|
| signer S publishes K,V | entry put on a name nobody owns |
| signer S updates K,V to V2 | entry put by the owner |
| signer S gives K,V to S2 | entry give |
| signer S deletes K,V | entry del (the balance is refunded) |
| signer S funds K,V | transfer whose destination is the entry |

Plus rent (an entry pays for its own footprint per second) and the cull:
anyone at all may reap an entry whose balance ran out and collect
`rip_bounty` for it.

**The client signs its own ops.** It encodes a hyle op offline and hands
the bytes over; the program relays them without reading them and never
holds a user's key. CES is the carrier, the chain is the authority.

---

## Prerequisite: a `--hyle` node

`ces.hyle` only exists when `cesluajitd` was built with the hyle consensus
engine linked in:

```
./build.sh release --hyle
```

That fetches `hyle` (core + services) from GitHub and statically links it
into `cesluajitd`; the first such build is slow (it also pulls Rust /
malachite-cpp). To build against a local hyle checkout instead, use
`--hyle-src <path>`.

A normal build omits it, and then this extension still installs and enables
cleanly but reports:

```
ces.hyle absent -- build the node with --hyle
```

so a non-hyle node degrades gracefully rather than failing.

---

## Operator: enabling hylesolo on a server

`hylesolo` is a local, transportless program: it needs the L2 stack (file +
compute + lua) but no outbound networking and no compute port range. In your
server config:

```toml
rpc_port              = 53831       # > 0: the L2 stack is up
file_store_max_bytes  = 104857600   # any value > 0 (compute needs file)
compute_max_instances = 8           # any value > 0

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

No PoW and no peers are required, so a box that only runs hylesolo can set
`no_pow_engine = true`.

**Deploy hylesolo.lua to /s/.** `/s/` is operator-controlled at the disk
level. Copy the file directly into `<storeDir>/s/`:

```
cp extensions/hylesolo.lua <data_dir>/cesfilestore/s/hylesolo.lua
```

At boot the file handler walks `s/`, generates a sidecar, and the autolaunch
path picks it up:

```
builtin:file /s/ sidecar generated   /s/hylesolo.lua  size=...
extension launched                 hylesolo  /s/hylesolo.lua
hylesolo: started 'hylesolo', one block every 1000ms
```

The chain starts on its own (`autostart = 1`). Stop and Start are on the
Extensions tab.

---

## Talking to it

`cesh dial <pid>` (find the pid with `cesh compute instances /s/hylesolo.lua`),
or any program over `ces.conn`. One command per line, one line back, always
starting `ok` or `err`.

```
info                      chain, height, cells, quorum, gov_seq, supply
config                    the genesis economy
self                      the validator/program pubkey
height
mintkey                   the proof-of-work epoch key
account <hex32>           balance, sequence
entry <name>              owner, balance, timestamps, payload
txr <hex32>               did this tx apply, and at what height
submit <hex>              admit signed ops; the bytes are opaque
faucet <amount>           mint to YOUR key (the one that bound this channel)
```

`submit` is the service. `faucet` is the devnet's credit on-ramp: it
sudo-mints to `conn.pubkey`, the key CES already authenticated at bind,
which is *also* that caller's hyle account (see Identity). Per-caller cap,
held in RAM, reset on restart -- a devnet faucet, not an economy.

---

## Identity: one key, two ledgers

The chain's sole validator is derived from the program's own 32-byte secret,
and CES and hyle derive ed25519 the same way. So `ces.hyle.self()` is byte
for byte `ces.program_pubkey()`: the program's CES account and its chain
account are the same key.

This generalizes. **Any CES ed25519 identity is already a hyle account at the
same 32 bytes.** That is what lets a payment on one ledger authorize a mint on
the other with no mapping table, and the reason `faucet` needs no argument.

The corollary is a constraint: **signers must be ed25519.** A secp256k1 CES key
(decorator `01`) has no hyle identity. `HyleSoloTests/ACesIdentityIsAHyleIdentity`
pins this, so if CES ever changes how it mints keys, that fails loudly instead of
silently addressing a different account.

---

## Sudo

Governance can run any act with the act's own guards waived -- no signature,
no sequence, no fee, no ownership check. Approval is collected on chain, the
way EOSIO's `eosio.msig` collects it. `ces.hyle.sudo.propose(inner)` opens a
proposal carrying the program's own vote; `ces.hyle.sudo.approve(proposer,
inner)` adds another member's; the vote that reaches quorum executes the act.
`ces.hyle.sudo.pending(proposer)` shows an open proposal (the act, approvals
so far, quorum needed).

On a one-validator chain the program's own vote IS the quorum, so
`propose(inner)` executes on the next block. `ces.hyle.sudo.submit` is an alias
for `propose`, the name the faucet uses. Raise the validator count and a
proposal simply waits, collecting `approve`s from the other members until it
reaches quorum.

The proposal lives in a `g` cell keyed by its proposer, so a member holds at
most one at a time -- that bounds the space to the validator set, which is why
these cells pay no rent. An abandoned proposal is overwritten by the proposer's
next one, or expires after `sudo_ttl_secs`.

Only one source creates credit: the **mint sentinel**, the all-zero key. A
sudo transfer from it mints (that is what the faucet does, and it is counted
in `sudo_minted`). Every other sudo still has to find the money it moves, so
governance can seize but not create credit.

---

## Configuration

Optional. Drop `/s/hylesolo.conf` (a `key = value` file) to override defaults.
The config is read on Start, so re-Start after a change; the panel's config
form does both.

```
chain_id = hylesolo           # chain identity
block_pace_ms = 1000          # one committed block per this interval
autostart = 1                 # boot the chain when the extension loads
alloc = 1000000000            # genesis allocation to the program's own account
fee_transfer = 10
fee_entry = 10
fee_mint = 1
fee_sudo = 1                  # per-op fee for a sudo propose/approve
reward_base = 2               # proof-of-work mint reward at floor difficulty
rent_rate = 1                 # per byte-second of entry footprint
rip_bounty = 10               # paid to whoever reaps a starved entry
sudo_ttl_secs = 0             # a pending proposal past this age is dead; 0 = never
faucet_max = 1000000          # most one caller may mint, per instance
```

Two economic invariants the chain enforces at genesis, and refuses to boot
without:

- `reward_base > fee_mint` -- a floor-difficulty mint must net positive.
- with `rent_rate > 0`, `rip_bounty <= min(fee_transfer, fee_entry)` -- a
  bounty worth more than the fee to create a rippable entry is a pump that
  mints money out of the cull.

A refused genesis is reported on the panel and by every protocol command
(`err no_chain <reason>`).

`rent_rate = 0` is legal but hollows the model out: entries become immortal,
funding buys nothing, and nothing can ever be culled.

---

## Observability

The Extensions tab renders hylesolo's mene panel: a state badge, live tiles
(height with a sparkline, entries, accounts, ops-in-blocks), the chain detail
rows, the validator pubkey, Start/Stop, and the genesis form.

- `height` -- committed blocks; climbs at `block_pace_ms`.
- `entries` / `accounts` -- cells in the RAM state.
- `txs` -- ops carried in blocks (applied or not; a rejected op is still in
  the block).
- `sudo acts` -- `gov_seq`, the number of sudo acts that have applied.
- `minted by sudo` -- credit created out of the sentinel.
- `validator balance` -- the program's own account. It is the genesis `alloc`
  and it does NOT climb per block: the services economy has no proposer block
  reward, and `reward_base` is the proof-of-work mint reward, not a block
  subsidy.
- `mempool` -- admitted ops not yet in a block.
- `app hash` -- the composite state hash.

All state is in RAM and is not persisted: stopping the extension, or the
process dying, drops the chain. A later Start boots a fresh one from the
current config.

---

## Files

- `hylesolo.lua` -- the program (operator deploys this to `/s/`); the built
  single-file bundle, generated from the cesdk `apps/hylesolo` source. Do not
  hand-edit; rebuild it in cesdk and re-ship.
- `hylesolo.md` -- this manual.

Tests: `HyleSoloTests` in `tests/test_hyle.cpp` (a real server, a real
cesluajitd, a real chain, and a client that signs its own ops), and `SudoTests`
in the hyle repo.
