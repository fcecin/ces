# /s/monitor.lua

A public, read-only web dashboard for a CES server, served to a plain browser
through cesweb.

It shows the server's own stats (accounts, assets, aliases, credits in
circulation, transaction count, tps, min difficulty, fees, version) and its
peering: every peer this server holds, with the full 64-hex peer public key,
address, direction, reachability, and the reserve/PoW on each side. Everything
shown is already publicly queryable -- a CES server is a public entity, and only
its private key is secret. The page is a snapshot: refresh (F5) re-queries. No
WebSocket, no streaming, no persistent sockets.

The program reads the server's stats in-process via `ces.server_info()` and the
peer table via `ces.peers()`, then serves one self-contained HTML page.

---

## Operator: enabling monitor on a server

Same requirements as any web extension: the full L2 stack plus a cesweb gateway
fronting the server.

```toml
rpc_port              = 53831
file_store_max_bytes  = 104857600   # any value > 0
compute_max_instances = 8           # any value > 0

[cesplex_mounts]
"/ces/file/1"    = "builtin:file"
"/ces/compute/1" = "builtin:compute"
"/ces/lua/1"     = "builtin:lua"

[extension]
monitor = 1
```

CLI equivalent: `--extension monitor` (repeatable).

Deploy the bundle to `/s/`:

```
cp extensions/monitor.lua <data_dir>/cesfilestore/s/monitor.lua
```

Run cesweb fronting the server (see `cesweb/`). cesweb reaches the instance on
the gateway's own wallet, so browsing is free to the visitor.

---

## Viewing

Find the instance pid (public, any signer):

```
cesh --server $SRV --rpc-port $RPC compute instances /s/monitor.lua
# -> 1
```

Open the gateway URL:

```
http://<gateway>/i/<host>/<pid>/
```

Each GET renders a fresh snapshot; the `refresh` button (or F5) re-queries. The
page holds no state.

---

## What it shows

- server: full pubkey, version, accounts, assets, aliases, circulating, tx
  count, tps, min difficulty, fee_tx, fee_query, rpc port
- peers: full 64-hex pubkey, address, direction (out / in / both), reachable,
  verified, rpc port, reserve in / out

`ces.server_info()` (CES core, `builtin:compute`) returns the server stats as a
named table; the peer list comes from `ces.peers()`. Both are public reads.

---

## Files

- `monitor.lua` - the built program (operator deploys this to /s/)
- `monitor.md` - this manual

Source: cesdk `apps/monitor`, composing `lib/web` (HTTP over `ces.conn`) and
`lib/json`. Rebuild with `cesdk build` in that project.
