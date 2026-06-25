# peerfunder

A `/s/` extension. Each tick it transfers a bounded amount of credit from its
program account to each peer, crediting the peer's balance with us.

Peers funded: reachable, inbound (have sent us PoW), not blacklisted, not self;
with `require_inbound = 0`, any reachable peer. A peer at or above `per_peer_cap`
is skipped, and a tick stops when the budget would fall below `min_reserve`. All
reads are the local ledger (the program-account balance, a peer's balance with us).

The budget is the program account, which the server tops up to `ext_local_budget`
on boot and daily.

## Config (`/s/peerfunder.conf`)

```
emit_ms = 600000          # tick interval (ms)
emit_per_peer = 10000000  # raw units paid to each peer per tick (0.1 credit)
per_peer_cap = 0          # skip a peer holding >= this with us (0 = no cap)
min_reserve = 0           # keep at least this in the program account
require_inbound = 1       # only fund peers that have sent us PoW; 0 = any reachable
blacklist =               # comma-separated 64-hex peer pubkeys to never fund
```

Amounts are raw units (PRICE_UNIT = 1e8 per credit).

## Relay commands (`cesh dial`)

- `status` - budget, candidate count, totals, program pubkey
- `peers` - candidates and their balance with us
- `emit` - run one tick now
- `blacklist <64-hex>` / `unblacklist <64-hex>`
- `selftest`
