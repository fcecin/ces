---
title: Send credits
summary: How to send credits to a key on the same server (cesh transfer), with --open for a new account
order: 2
---

```
cesh transfer <dest> <amount> [--open]
```

- `<dest>`: the public key in hex, `@N` for a wallet key, or a key name that
  this server knows (see [Key names](../names/keynames.md)).
- `<amount>`: in raw units. 1 credit = 100000000. See [Credits](../basics/credits.md).
- `--open`: make the destination account if it does not exist. Without it,
  a transfer to a new key fails with `CES_ERROR_TARGET_NOT_FOUND`.
- The signer pays: the default is `@0`; use `-a` for another key.

The transfer also pays a fee, so the balance must cover the amount and the
fee.

## Examples

Send 5 credits from `@0` to a key, and open its account if necessary:

```
cesh transfer a1d948985b95b286ad167505a6c224e0a7eace3d61d503a499478a4d93e79525 500000000 --open
```

Send 1 credit from the second wallet key to the first:

```
cesh -a @1 transfer @0 100000000
```

On success cesh prints the remaining balance (`Rem. Bal`) and `Success.`

To send to a key on another server, see [Cross-server transfers](cross.md).
