# /s/dice.lua

Fair-coin double-or-nothing, shipped as a CES builtin app.

The server's own pubkey is the **house**. Bets are placed by
transferring credits to the house, then typing `play` over a dial
session — the bet amount is whatever you just transferred. The
program flips a fair coin via `ces.random_bytes`; on heads it
transfers `2N` back to the player from the server's account, on
tails it keeps the deposit. 50/50, 0 house edge.

The server's account is auto-topped to near `INT64_MAX` every boot,
so the house is structurally bottomless — the dice game is a free
amusement, not an income source.

---

## Operator: enabling dice on a server

`dice` requires the full L2 stack. In your server config:

```toml
rpc_port              = 53831
file_store_max_bytes  = 104857600   # any value > 0
compute_max_instances = 8           # any value > 0

[cesplex_mounts]
"/ces/file/1"    = "builtin:file"
"/ces/compute/1" = "builtin:compute"
"/ces/lua/1"     = "builtin:lua"

[builtin_app]
dice = 1
```

Equivalent CLI flag: `--builtin-app dice` (repeatable).

`cesluajitd` must be on the server's `PATH`, or set
`compute_child_binary = "/abs/path/to/cesluajitd"`.

**Deploy dice.lua to /s/.** /s/ is operator-controlled at the disk
level — copy or unpack the file directly into `<storeDir>/s/`:

```
cp src/ceslib/builtin_apps/dice.lua <data_dir>/cesfilestore/s/dice.lua
```

`<storeDir>` is `file_store_dir` if set, otherwise
`<data_dir>/cesfilestore`. At boot the file handler walks `s/`,
sees an /s/dice.lua content file with no sidecar, and auto-generates
one (owner = server pubkey, file_balance = 0). Then the autolaunch
path picks it up.
Look for these lines in the log:

```
builtin:file /s/ sidecar generated   /s/dice.lua  size=...
builtin:compute launched             id=1 ...
builtin_app launched                 dice  /s/dice.lua
```

If `/s/dice.lua` is missing, you'll see
`WRN builtin_app: launch failed dice /s/dice.lua` and the server
keeps running.

---

## Player: betting from cesh

Assume `$SRV` = `host:port`, `$RPC` = the rpc port, `$WALLET` = a
local file path.

```bash
# 1. Wallet
cesh -r $WALLET keys gen -w $WALLET 1
# → "[@0] [ED] <priv-hex> (<pub-hex>)"

# 2. Get credits
cesh -r $WALLET --server $SRV mine                   # PoW, or
ces --config server.toml credit <amount> <user-pub>  # operator-side

# 3. Find the dice pid
cesh -r $WALLET --server $SRV --rpc-port $RPC \
  compute instances /s/dice.lua
# → 1

# 4. House pubkey is the server's own pubkey. cesh dial's greeting
#    prints it; you can also fetch it via:
cesh -r $WALLET --server $SRV server-info | grep serverPubKey

# 5. Bet N: transfer N to house, then dial and play
cesh -r $WALLET --server $SRV transfer <house-pub> 100 --open
echo "play" | cesh -r $WALLET --server $SRV --rpc-port $RPC dial 1
# → "heads. you won 200 (+100)"   or   "tails. house keeps 100"
```

Inside the dial, `help`, `balance`, `quit` work as expected.

---

## Bet rules

- **One transfer = one bet.** Each deposit can be played exactly
  once. Replay attempts get `that deposit was already played`.
- **Bet amount = your last transfer.** No need to type the amount
  with `play` — the program reads `lastXferAmount` directly. There
  is no upper cap; the transfer layer already enforces "you can't
  bet more than you have." Only zero-amount transfers (`< 1`) are
  rejected — those would have been just-the-fee donations.
- **Deposit must postdate the dice instance.** Server restart
  resets the freshness floor; pre-restart deposits get
  `your last payment predates this dice instance`.
- **Deposit must be recent.** The replay-protection bucket cache
  guarantees ~2 hours of memory; older deposits get
  `your deposit is too old to verify`.

---

## Wallet flags

- `-r FILE` — load wallet from FILE
- `-w FILE` — save wallet to FILE (only `keys gen` / `keys add`
  honor this — without `-w` they print but don't persist)
- `cesh -r FILE keys export` — print `export CESH_WALLET="..."` to
  inline the keys into your env, no file needed

---

## Files

- `dice.lua` — the program source (operator deploys this to /s/)
- `dice.md` — this manual

Adding a new builtin app is just two steps: drop `<name>.lua` into
this directory (canonical source-tree home, ships in the repo), and
arrange for the operator to copy it to `<storeDir>/s/<name>.lua` at
deploy time. There's no per-app C++ knob — `[builtin_app] <name> = 1`
in the config triggers `computeHandlerLaunchInternal("/s/<name>.lua")`
at boot, the file handler auto-sidecars the file, and you're live.
