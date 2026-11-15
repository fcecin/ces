---
title: Cross-server transfers
summary: How to send credits from this server to a key on a peer server (cesh cross)
order: 3
---

Each server is a separate ledger. Peer servers keep accounts for each other,
so a transfer can start on one server and end on another.

```
cesh cross <dest> <amount> <server>
```

- `<dest>`: the public key that gets the credits on the other server.
- `<amount>`: in raw units.
- `<server>`: the address `host:port` of the destination server.
- `--server` is the server that you pay from. It must be a peer of the
  destination server, else the transfer fails with `CES_ERROR_UNKNOWN_PEER`.

The origin server takes the credits at once and returns. The other server
credits the destination soon after. To check, run `cesh query <dest>` with
`--server` set to the destination server.
