---
title: Credits
summary: The unit of money, raw units (1 credit = 100000000 raw), and how to write amounts
order: 1
---

The money of CES is the credit. Each server keeps the balances of its own
accounts.

## Raw units

The commands take amounts in raw units, not in credits.

| Credits | Raw units |
| --- | --- |
| 1 | 100000000 |
| 0.5 | 50000000 |
| 10 | 1000000000 |
| 1000 | 100000000000 |

To convert credits to raw units, multiply by 100000000 (eight zeros). Thus
"send 5 credits" is `cesh transfer <dest> 500000000`.

The output of the commands also shows raw units, for example
`Rem. Bal: 60368744132848` is 603687.44 credits.

## Where credits come from

- A transfer from another account.
- Mining (`cesh mine`), on servers that accept proof of work.
- The operator of a server can credit an account.

A credit on one server is not a credit on another server. To move credits to
a key on a peer server, see [Cross-server transfers](../money/cross.md).
