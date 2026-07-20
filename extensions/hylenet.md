# /s/hylenet.lua

A multi-node hyle blockchain over the CES server peer mesh, shipped as an extension.

`hylenet` runs one hyle chain across several CES servers. Its validator identity
is the CES SERVER's key, and consensus rides the CES server peer mesh
(`ces.peer.*`), so the validators are simply the CES servers that are mutual
peers and carry the same genesis. It has no transport of its own: lose CES
peership with a validator and BFT rides on at 2f+1.

It implements the WHOLE hyle interface -- ops, entries, governance, sudo --
against a real `hyle::services::Runtime`, driven by a fine pump tick. The same
`ces.hyle.*` interface as the solo dev net (`hylesolo`), so programs and clients
move between them unchanged; only the lifecycle differs.

The full design lives in the cesdk source tree (`apps/hylenet/`); this file is
the built single-file bundle the operator deploys.

---

## The service

Identical to `hylesolo`: a hyle `entry` is a K,V mapping with an owner and a
rent balance, so the chain already IS the service.

| verb | hyle op |
|---|---|
| signer S publishes K,V | entry put on a name nobody owns |
| signer S updates K,V to V2 | entry put by the owner |
| signer S gives K,V to S2 | entry give |
| signer S deletes K,V | entry del (the balance is refunded) |
| signer S funds K,V | transfer whose destination is the entry |

Plus rent and the permissionless cull (`rip_bounty`). **The client signs its own
ops** and hands the bytes over; the program relays them without reading them.
CES is the carrier, the chain is the authority.

---

## Prerequisite: a `--hyle` node on an ed25519 server key

`ces.hyle` only exists when `cesluajitd` was built with the hyle consensus engine
linked in:

```
./build.sh release --hyle
```

To build against a local hyle checkout, use `--hyle-src <path>`. Without hyle the
extension still installs and enables cleanly but reports `ces.hyle.net absent --
build the node with --hyle`.

The validator identity is the server key, which must be **ed25519**. A secp256k1
server key has no hyle identity, and `net.start` refuses it. See Identity.

---

## Operator: running a hylenet chain

A hylenet chain is a set of CES servers that:

1. run a `--hyle` `cesluajitd` (ed25519 server key),
2. mount `builtin:peer` and are MUTUAL peers of each other (the transport), and
3. deploy `/s/hylenet.lua` with an IDENTICAL config -- the same `chain_id`, the
   same `validators` list, and the same economy.

Server config on every validator:

```toml
rpc_port              = 53831       # > 0: the L2 stack + the peer mesh are up
file_store_max_bytes  = 104857600   # any value > 0 (compute needs file)
compute_max_instances = 8           # any value > 0

[cesplex_mounts]
"/ces/file/1"    = "builtin:file"
"/ces/compute/1" = "builtin:compute"
"/ces/lua/1"     = "builtin:lua"
"/ces/peer/1"    = "builtin:peer"    # REQUIRED: hyle consensus rides this mesh

# the other validators as peers (each server lists all the others)
[[peers]]
# ... peer-table entries for the other validators' rpc endpoints ...

[extension]
hylenet = 1
```

The peer mesh links form when the servers are mutual peer-table entries;
`hylenet` sends and receives consensus over those links, addressed by server
pubkey. A validator that is not currently a CES peer simply does not receive
votes; the chain commits as long as 2f+1 of the validators are linked.

**Deploy hylenet.lua to /s/** and drop a `/s/hylenet.conf` carrying the shared
genesis:

```
cp extensions/hylenet.lua <data_dir>/cesfilestore/s/hylenet.lua
```

The chain starts on its own (`autostart = 1`) once the config lands. Stop and
Start are on the Extensions tab.

---

## Talking to it

`cesh dial <pid>` (find the pid with `cesh compute instances /s/hylenet.lua`),
or any program over `ces.conn`. One command per line, one line back, always
starting `ok` or `err`.

```
info                      chain, height, cells, quorum, validators, supply, app_hash
config                    the genesis economy
self                      this node's validator (server) pubkey
height
account <hex32>           balance, sequence
entry <name>              owner, balance, timestamps, payload
txr <hex32>               did this tx apply, and at what height
submit <hex>              admit signed ops; the bytes are opaque
nodekey                   (owner only) the validator private key, to load into cesh
```

`submit` is the service. There is no `faucet`: on a real chain credit is not a
per-caller devnet handout. Funding is per-block validator autofill (see
Configuration) plus governance sudo out of the mint sentinel.

---

## Identity: one key, two ledgers

A node's validator identity is its OWN CES ed25519 identity. On `hylenet` that is
the SERVER key -- the same key that identifies the server on the peer mesh -- so
there is no second key to manage. CES and hyle derive ed25519 the same way, so
`ces.hyle.self()` is the server's account on both ledgers, byte for byte.

This generalizes: **any CES ed25519 identity is already a hyle account at the same
32 bytes**, which lets a payment on one ledger authorize a mint on the other with
no mapping table. The constraint: **signers must be ed25519.** The server key
included -- `net.start` refuses a secp256k1 server key.

`net.start` uses the server secret IN-PROCESS to build the validator key (host-gated
to a `/s/`-owned-by-server instance); the raw key is never surfaced to the Lua
sandbox, so a program cannot exfiltrate the permanent server identity.

---

## Funding: per-block autofill

There is no alloc and no faucet. `credit_autofill_ceiling` tops every validator's
balance toward the ceiling once per block, through consensus itself -- so a node
that runs the chain is self-funding, with no quorum dance. A funded validator can
then transfer to any account. Governance sudo out of the mint sentinel remains
for anything autofill does not cover.

```
credit_autofill_ceiling = 0   # 0 = off; set > 0 to fund validators per block
refill_rate             = 0   # extra per-block top-up beyond the lift to the ceiling
```

---

## Sudo

Identical to `hylesolo`: governance runs an act with its guards waived, approval
collected on chain EOSIO-`eosio.msig`-style. `ces.hyle.sudo.propose(inner)` opens
a proposal with this node's own vote; `approve(proposer, inner)` adds another
member's; the vote that reaches quorum executes the act. On a real N-validator
set a proposal WAITS, collecting `approve`s from the other validators until it
reaches 2f+1 -- so governance actually requires the other operators to agree,
unlike the one-validator dev net where a proposal is its own quorum.

Only the **mint sentinel** (the all-zero key) creates credit; every other sudo
must find the money it moves.

---

## Configuration

Drop `/s/hylenet.conf` (a `key = value` file). Every validator must ship the SAME
`chain_id`, `validators`, and economy -- a mismatch is a different genesis and the
node forks off. The config is read on Start; the panel's config form re-Starts.

```
chain_id = hylenet
# the validator set: space-separated 64-hex CES server pubkeys, INCLUDING this node's own.
validators = <hex> <hex> <hex> <hex>
block_pace_ms = 1000          # throttles EMPTY-block production; consensus itself is not paced
consensus_timeout_ms = 1000   # a round with NO message activity this long moves on; keep it above
                              # a few inter-validator round-trips or rounds change prematurely
autostart = 1
credit_autofill_ceiling = 0   # per-block validator funding (0 = off)
refill_rate = 0
fee_transfer = 10
fee_entry = 10
fee_sudo = 1
rent_rate = 1
rip_bounty = 10
member_cap = 21               # consensus rule: max validators (all nodes must agree)
member_floor = 1              # consensus rule: min validators
sudo_ttl_secs = 0
snapshot_interval = 0
block_retention = 1024
```

Genesis invariants the chain enforces (and refuses to boot without): with
`rent_rate > 0`, `rip_bounty <= min(fee_transfer, fee_entry)`. A refused genesis
is reported on the panel and by every protocol command (`err no_chain <reason>`).

---

## Observability

The Extensions tab renders the mene panel: state badge, live tiles (height with a
sparkline, entries, accounts, ops-in-blocks), chain detail rows, this node's
validator pubkey, Start/Stop, and the genesis form. `validators` / `quorum` on the
`info` line show the set size and the 2f+1 threshold; `app_hash` is the composite
state hash, identical across honest validators at a given height.

All state is in RAM and is not persisted: stopping the extension, or the process
dying, drops this node's copy; it rejoins by restarting against the same genesis.
Catch-up is automatic: a restarted or lagging node pulls the blocks it lacks from
its peers (certificate-verified), and a node behind every peer's retained window
adopts a snapshot on an attestation quorum, then replays the tail. A follower not
in the genesis set syncs the same way once voted in.

---

## Files

- `hylenet.lua` -- the program (operator deploys this to `/s/`); the built
  single-file bundle from the cesdk `apps/hylenet` source. Do not hand-edit;
  rebuild it in cesdk and re-ship.
- `hylenet.md` -- this manual.

Tests: `HyleNetTests` in `tests/test_hylenet.cpp` -- four real CES servers, mutual
peers, each running a hylenet validator, committing blocks over the peer mesh and
agreeing on AppHash (both an inline program and the shipped extension).
