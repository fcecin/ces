# dice2 - double-or-nothing paid via SYS_L2_CALL

The SYS_L2_CALL flavor of `dice`. Same game (fair-coin double-or-nothing, 0 house
edge), but the bet is carried by a paid VM->L2 call instead of an out-of-band
transfer plus a `play` command. The house bankroll is this file's program account
(`ces.program_pubkey()`).

## How a bet is placed

A caller runs a CesVM program that issues `SYS_L2_CALL` at the running instance:

- discriminator = `sha256("builtin:compute")[:8]`
- blob = `[u64 pid BE]` (the target instance's pid, from compute STAT/INSTANCES)
- value = the bet

On delivery the instance's `on_l2call(payload, ctx)` fires:

- `ctx.payer` = the caller's account (full key), delivered by the call.
- `ctx.value` = the bet.
- heads -> `ces.transfer(ctx.payer, 2*bet)`; tails -> the house keeps the bet.

Settlement is reply-time: the burned `value` is minted into the house account
only after `on_l2call` returns (or the call times out), so during the handler
the house balance does not yet include the bet.

Bets are serialized: `on_l2call` enqueues onto an internal channel and one
worker coroutine plays them in arrival order, so the bankroll check and the
payout are atomic per bet.

If the house cannot cover `2*bet` from standing funds, the call is ignored (no
payout, no refund), so the operator must keep the program account funded above
twice the largest accepted bet. On `/s/` the server auto-tops it at boot;
elsewhere fund it with `cesh file deposit`.

## Enable

```
[extension]
dice2 = 1
```

or `--extension dice2`. The house pubkey is `ces.program_pubkey()` for the
deployed `dice2.lua`; a live instance exposes it via compute `STAT`/`INSTANCES`.

## Admin

The webadmin Extensions tab shows a panel with the house balance, play counts,
amount wagered/paid, and the heads/tails fairness split.
