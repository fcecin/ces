# /s/discovery.lua

The network registry crawler, shipped as a CES extension.

`discovery` walks the network as an ordinary CES client and keeps the
host's peer table populated, hands-off. It pages every known server's
public peer table (`ces.peer_info`), validates each rumor with
`ces.ping`, and keeps an in-RAM registry of what it finds (persisted
periodically to `/s/discovery.reg`). For breadth past the peer table it
publishes a bounded random sample of its registry at
`/s/discovery.sample` and pulls peers' samples over a paid file read,
so address books spread server-to-server. Validated servers are
promoted into the host's outbound peer set up to a target; hosts that
go unreachable are retried, given up after a few failures, and dropped.

No mesh, no persistent connections: it is a periodic crawler built out
of the same client primitives any program has.

The full design lives in the cesdk source tree
(`apps/discovery/`, `local/PEERING_AGENT_DESIGN.md`); this file is the
built single-file bundle the operator deploys.

---

## Operator: enabling discovery on a server

`discovery` requires the full L2 stack AND outbound networking (it dials
other servers), so unlike a local-only program it needs a compute port
range. In your server config:

```toml
rpc_port              = 53831
file_store_max_bytes  = 104857600   # any value > 0
compute_max_instances = 8           # any value > 0
compute_port_base     = 53900       # > 0: instances get real UDP ports to
compute_port_count    = 16          #      dial peers (0 => local-only, breaks it)

[cesplex_mounts]
"/ces/file/1"    = "builtin:file"
"/ces/compute/1" = "builtin:compute"
"/ces/lua/1"     = "builtin:lua"

[extension]
discovery = 1
```

Equivalent CLI flag: `--extension discovery` (repeatable).

`cesluajitd` must be on the server's `PATH`, or set
`compute_child_binary = "/abs/path/to/cesluajitd"`.

**Reserves and PoW.** Crawling and promotion are free (peer-table reads
and pings are ticketless). The *gossip pull* — reading a peer's
published sample — is a paid file read, funded from a small reserve the
host mines at each peer. So a node that should learn via gossip needs
the PoW engine enabled (the default; not `--nopowengine`) to mine those
reserves, or the operator can seed reserves manually. Without any
reserve a node still crawls and promotes from peer tables; it just does
not pull samples.

**Deploy discovery.lua to /s/.** /s/ is operator-controlled at the disk
level — copy the file directly into `<storeDir>/s/`:

```
cp extensions/discovery.lua <data_dir>/cesfilestore/s/discovery.lua
```

`<storeDir>` is `file_store_dir` if set, otherwise
`<data_dir>/cesfilestore`. At boot the file handler walks `s/`, sees an
/s/discovery.lua content file with no sidecar, and auto-generates one
(owner = server pubkey). Then the autolaunch path picks it up.
Look for these lines in the log:

```
builtin:file /s/ sidecar generated   /s/discovery.lua  size=...
builtin:compute launched             id=1 ...
extension launched                 discovery  /s/discovery.lua
```

Then, from the program's own log line:

```
compute /s/discovery.lua pid 1: discovery: up, registry=1
```

If `/s/discovery.lua` is missing, you'll see
`WRN extension: launch failed discovery /s/discovery.lua` and the server
keeps running.

---

## Configuration

Optional. Drop `/s/discovery.conf` (a `key = value` file) to override
defaults; absent keys keep the built-in defaults shown here. Re-enable
the extension to apply a change (config is read at launch).

```
seeds = ces.pubcom.org:53830   # comma-separated rendezvous; "seeds =" disables
active_target = 20             # max peers discovery auto-promotes (leaves the
                               #   rest of the ~100 peer table for the operator)
crawl_ms = 3000                # one peer-table slot / one ping per tick
maint_ms = 10000               # promote / curate / publish cadence
save_ms = 300000               # full registry flush to /s/ (~5 min)
pull_floor_ms = 60000          # min gap between paid sample pulls (learning)
pull_ceil_ms = 1800000         # max gap between pulls (converged, backs off)
sample_k = 16                  # addresses per published / pulled sample
probe_ms = 3000                # per-ping reply wait; lower to give up on dead
                               #   hosts faster (the ces.ping default is 3s)
dead_after = 10                # failed re-validations before a host is dropped
peer_min_credit = 100000000    # reserve floor (1.0 credit) to keep at each peer
```

`ces.pubcom.org:53830` is the built-in default seed (the `:53830`
default-port suffix is required — addresses are validated as
`host:port`). A node with no seed and no peers stays empty until
someone adds it a peer.

---

## Observability

The Extensions tab of the web dashboard shows discovery's live status
(registry size, alive/verified/heard/dark counts, current pull gap).

You can also dial the instance directly for a console:

```bash
# find the pid
cesh --server $SRV --rpc-port $RPC compute instances /s/discovery.lua
# → 1
# one-line status, or a full registry dump
printf 'status\n' | cesh -r $(... server wallet ...) --server $SRV --rpc-port $RPC dial 1
printf 'dump\n'   | cesh -r ... dial 1
```

`status` reports `registry=/alive=/verified=/dark=/sample=/outbound=`;
`dump` lists every known address and its state.

---

## How it gives up on dead hosts

A host that fails `ces.ping`/`ces.peer_info` is retried each crawl pass.
A live sighting resets its failure count; merely hearing it gossiped
does not (you cannot un-fail a host by rumor). After `dead_after`
consecutive failures it is marked DEAD, the crawl stops probing it, and
the next save drops it from the persisted registry — after which it is
re-learnable from any fresh sighting. The registry is bounded (10k
records); at save time it prunes to the healthiest if over.

---

## Files

- `discovery.lua` — the program (operator deploys this to /s/); the
  built single-file bundle, generated from the cesdk `apps/discovery`
  source. Do not hand-edit; rebuild it in cesdk and re-ship.
- `discovery.md` — this manual

Adding a new extension is just two steps: drop `<name>.lua` into this
directory (canonical source-tree home, ships in the repo), and arrange
for the operator to copy it to `<storeDir>/s/<name>.lua` at deploy time.
There's no per-app C++ knob — `[extension] <name> = 1` in the config
triggers `computeHandlerLaunchInternal("/s/<name>.lua")` at boot, the
file handler auto-sidecars the file, and you're live.
