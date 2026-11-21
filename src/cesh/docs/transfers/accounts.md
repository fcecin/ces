---
title: Accounts
summary: What an account is, the daily account fee, and how to read a balance (query, squery)
order: 1
---

An account is a balance on one server, keyed by a public key. The same key
can have an account on many servers, each with its own balance.

## Life of an account

- An account starts when someone sends credits to its key with
  `cesh transfer <key> <amount> --open`.
- Each day at 09:00 UTC the server takes the account fee from each account.
  An account with a balance at or under the fee is deleted.
- Thus an account must keep a balance to stay.

## Read a balance

| Command | Cost | Gives |
| --- | --- | --- |
| `cesh query <key>` | Free | Balance and nonce, unsigned |
| `cesh squery <key>` | Paid | The same, signed by the server |

`<key>` is a public key in hex, `@N` for a wallet key, or a key name.

Example: `cesh query @0` shows the balance of the first wallet key on the
current server.
