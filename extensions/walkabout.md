# /s/walkabout.lua

A tiny real-time multiplayer world, served to a plain browser through cesweb.

Each connected browser is an avatar (a random name, a random spawn) that walks a
shared box; everyone sees everyone move, live. No client install: the program
serves its own HTML5/JS page over HTTP and runs the game over a WebSocket, both
on the same compute instance, relayed by cesweb's `/i/` scope. It is the
reference demo of the web-serving path -- a Lua compute program speaking HTTP/1.1
and WebSocket over `ces.conn`, reached by ordinary browsers via the gateway.

---

## Operator: enabling walkabout on a server

walkabout needs the full L2 stack AND a cesweb gateway fronting the server (the
browser speaks HTTP to cesweb; cesweb speaks CesPlex to the instance on its own
wallet, so the browser never holds a key).

```toml
rpc_port              = 53831
file_store_max_bytes  = 104857600   # any value > 0
compute_max_instances = 8           # any value > 0

[cesplex_mounts]
"/ces/file/1"    = "builtin:file"
"/ces/compute/1" = "builtin:compute"
"/ces/lua/1"     = "builtin:lua"

[extension]
walkabout = 1
```

CLI equivalent: `--extension walkabout` (repeatable).

Deploy the bundle to `/s/`:

```
cp extensions/walkabout.lua <data_dir>/cesfilestore/s/walkabout.lua
```

At boot the file handler auto-sidecars the file (owner = server pubkey) and the
autolaunch path starts it. Run cesweb fronting the server (see `cesweb/`).

---

## Playing

Find the instance pid (public, any signer):

```
cesh --server $SRV --rpc-port $RPC compute instances /s/walkabout.lua
# -> 1
```

Open the gateway URL in two or more browser windows:

```
http://<gateway>/i/<host>/<pid>/
```

Move with `WASD` or the arrow keys; other windows' avatars move in real time.
Any number of windows join the same world.

---

## Wire protocol

The page's JS opens a WebSocket to `<url>/ws`. Space-delimited text messages:

```
server -> client :  welcome <id> <w> <h> <name> <x> <y>
                    join <id> <name> <x> <y>
                    pos <id> <x> <y>
                    leave <id>
client -> server :  move <x> <y>
```

`ids` are per-connection; there is no persistent identity (a reconnect is a new
avatar).

---

## Files

- `walkabout.lua` - the built program (operator deploys this to /s/)
- `walkabout.md` - this manual

Source: cesdk `apps/walkabout`, composing `lib/web` (HTTP/1.1 + WebSocket over
`ces.conn`). Rebuild with `cesdk build` in that project.
