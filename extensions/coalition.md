# coalition

A `/s/` extension that forms a fixed membership set from a clique of mutually peered
servers by unanimous atomic commitment, and installs it as a named object for a
downstream consensus engine.

## Mechanism

The coalition size is a single protocol constant N (`group_size`, default 7 = 3f+1 at
f=2): the coalition is exactly N nodes or nothing, not a range. (A range is illusory --
nodes peer up slowly, so the first closed clique to settle locks in near the low end and
never climbs, and the size is in the fingerprint, so every member must agree on it
regardless.) Each member independently derives the candidate set: the eligible, mutually
connected canonical clique of the lowest N public keys it belongs to. A fingerprint is
taken over the member list and the formation parameters, so members that agree on both
compute the same fingerprint.

Commitment is a two-round all-to-all exchange over the `/ces/peer/1` mesh:

1. VOUCH: each member attests that every other member satisfies all criteria from
   its own view.
2. CONFIRM: each member attests it has collected a VOUCH from every member.

A member commits when it holds a VOUCH and a CONFIRM from every member over one
fingerprint. Any failed criterion, fingerprint mismatch, missing message, or
timeout aborts the attempt; the member discards attempt state and retries after a
cooldown. There is no proposer: any member may start an attempt, and concurrent
attempts over the same candidate share a fingerprint. Commitment requires all
members to agree, so a single failing member prevents commitment until it leaves the
candidate set. The timers are deliberately relaxed (a coalition forms on a human and
operator timescale -- hours and days), so formation is unhurried and never thrashes.

## Criteria

A member admits another only if all hold:

1. linked: a live `/ces/peer/1` channel
2. speaking: heard on the coalition mesh within `member_stale_ms`
3. staked: lifetime inbound PoW at least `group_pow_target`
4. roster: same member list
5. params: same parameters, protocol version, and criteria
6. completeness: vouches the whole set and confirms it saw every vouch

Criteria 1 to 3 are checked locally; 4 to 6 reduce to a fingerprint match.

## Accountable formation

Each VOUCH and CONFIRM is server-signed by its origin (`ces.serverSign`) and relayed:
a vote that reaches any honest member reaches all, so a member cannot withhold a vote
from some members and not others (relay reunites it). A relayed vote stays attributable
to its origin, not the relayer, because it carries the origin's own server-key signature.

## Provisional commit, retraction, maturity

A commit is provisional. A member installs the coalition as soon as it holds a VOUCH and
a CONFIRM from every member ("formed"), but that is provisional, not final. A transferable
proof against any member later retracts it: the member is banned and the coalition is
discarded, then the honest set reforms without it. This is safe because nothing is built
on the set yet and because relay floods the proof to everyone,
so every member that committed with the offender eventually retracts and the set converges.

A coalition is mature only after it has stood `maturity_ms` (default one week) with no
retraction. Only a mature coalition is safe for a downstream consumer to build on; the
consumer is itself time-dilated and does not latch onto a fresh, still-provisional
coalition. A coalition that survives the maturity window is one that no proof
contradicted; that, not a quorum, is what the consumer relies on.

## Shedding a defective member

A member that keeps a clique from committing, or that a proof condemns, is removed from
the candidate. By confidence in the evidence:

1. Conclusive, transferable (equivocation): two signature-verified CONFIRMs from one
   member for the same fingerprint with different vhash. vhash is a deterministic
   function of the fingerprint, so an honest member emits exactly one; two is a portable
   proof anyone re-verifies. The member is banned via `ces.ban_peer` and any coalition
   it is in is retracted.
2. Conclusive (params divergence): a divergent params hash is something an honest member
   cannot emit, so it is reported via `ces.ban_peer` for an immediate ban.
3. Withholding (an individual timeout, no vote): a member that vouches the fingerprint, so
   it owed a confirm, but almost never produces it while the clique does is withholding
   rather than losing packets (per-tick retransmit masks loss). Each node drops it from its
   own candidate on its own first-hand record -- collateral-free and reversible. Because
   every vote is relayed, the withholder's silence is absolute: if it confirmed, the relay
   would carry it to everyone, so its absence is witnessed by every honest node, including a
   spare outside the clique (which sees the others' relayed confirms but never the
   withholder's). So every node sheds it and the honest set reforms without it -- no quorum
   vote, since excluding an unprovable fault stays a per-node timeout, made to converge by
   universal relayed witnessing.
4. Fallback (grief): the host peer table accrues a small grief on a withheld confirm and
   decays it slowly, banning only a sustained pattern. A backstop under the per-node detector.

## Output

The committed set installs to `/s/coalition.kv` under key `coalition` and survives restart.
A consumer extension reads the published record -- `fingerprint`, the ordered `members`,
`formed_at`, and `maturity_ms` -- so it judges maturity (`now >= formed_at + maturity_ms`)
and slices a deterministic subset without knowing this extension's config. A consumer reads
it via `ces.store("/s/coalition.kv")` (the cesdk `coalition_read` library wraps
read / has / both_members / subset).

## Config (`/s/coalition.conf`)

```
group_size = 7                 # the coalition size N (a protocol constant; all members must match)
group_pow_target = 500000000   # lifetime inbound PoW (raw units) to admit a peer; 0 disables the check
tick_ms = 60000                # heartbeat (gossip + eval): 1 min
gossip_cap = 512               # max peers advertised per gossip; real bound is the RUDP message size
stable_ticks = 3               # ticks a candidate must hold before an attempt
attempt_timeout_ms = 3600000   # give up on a stuck attempt: 1 hour
cooldown_ms = 600000           # delay after an abort before the next attempt: 10 min
member_stale_ms = 7200000      # a member unheard this long is gone: 2 hours
maturity_ms = 604800000        # provisional -> mature (safe for a consumer): 1 week
```

Timers are relaxed to the operator timescale on purpose; fast timers only thrash.

## Enabling

Requires the L2 stack and the peer mesh:

```toml
rpc_port              = 53831
file_store_max_bytes  = 104857600
compute_max_instances = 8

[cesplex_mounts]
"/ces/file/1"    = "builtin:file"
"/ces/compute/1" = "builtin:compute"
"/ces/lua/1"     = "builtin:lua"
"/ces/peer/1"    = "builtin:peer"

[extension]
coalition = 1
```

Equivalent flag: `--extension coalition`. `cesluajitd` must be on `PATH`, or set
`compute_child_binary`. Deploy the bundle into `<storeDir>/s/`:

```
cp extensions/coalition.lua <data_dir>/cesfilestore/s/coalition.lua
```

`coalition` uses only the peer mesh, so it needs no compute port range. It runs
without the PoW engine, but a nonzero `group_pow_target` requires peers to have
reciprocated PoW, so a network using a nonzero target runs the engine.

## Observability

The Extensions tab of the web dashboard reports state, fingerprint, member count,
and attempt counters. The instance can also be dialed directly:

```bash
cesh --server $SRV --rpc-port $RPC compute instances /s/coalition.lua   # -> pid
printf 'status\n'  | cesh -r <wallet> --server $SRV --rpc-port $RPC dial <pid>
printf 'members\n' | cesh -r ... dial <pid>
```

## Files

- `coalition.lua`: the bundle, built from the cesdk `apps/coalition` source. Do not
  edit it directly; rebuild in cesdk and re-ship.
- `coalition.md`: this file.
