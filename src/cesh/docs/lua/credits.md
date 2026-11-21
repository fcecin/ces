---
title: Credits
summary: The program's balance, payments in calls, ces.transfer, ces.account_read, and credit to keys on other servers
order: 8
---

## The program's balance

Each source file has a program key, `ces.program_pubkey()`. The balance of
the file is the account of that key on this server. It gets:

- the deposit of the owner, and `cesh file deposit`;
- the payments of [paid calls](calls.md);
- any credit that anyone sends to the program key.

It pays for each second that the program runs, for its file calls, and for
its transfers. When it is gone, the program stops. No call can spend the
credit of another account.

| Call | Returns |
| --- | --- |
| `ces.transfer(key, raw)` | `true, balance_left`. Pays a key on this server, and opens its account if it has none |
| `ces.account_read(key)` | A table: `balance`, `nonce`, `last_xfer_dest`, `last_xfer_amount`, `last_xfer_time`. A key with no account gives zeros |
| `ces.cross_transfer(key, raw, server)` | `true, balance_left`. Pays a key on a peer server (`host:port`) |

## A shared fund

```lua
local function unhex(h)
  return (h:gsub("..", function(x) return string.char(tonumber(x, 16)) end))
end

function on_l2call(memo, info)
  if memo == "balance" then
    local acct = ces.account_read(ces.program_pubkey())
    return acct.balance .. " raw in the fund"
  end
  local key, amount = memo:match("^pay (%x+) (%d+)$")
  if key and #key == 64 then
    if info.payer ~= ces.owner_pubkey() then return "only the owner pays" end
    local ok, err = ces.transfer(unhex(key), tonumber(amount))
    if not ok then return "error " .. err end
    return "paid; " .. err .. " raw left"     -- on success, the 2nd value is the balance
  end
  return "commands: balance, pay <64-hex key> <raw>; pay with any call to give"
end

ces.run()
```

A call that pays gives to the fund. Only the owner can take from it,
because the program checks `info.payer`.

## Credit to another server

Each server is a separate ledger. `ces.cross_transfer` sends from the
program's balance here to a key on a peer server, as `cesh cross` does (see
[Cross-server transfers](../transfers/cross.md)). This server takes the
credit at once, and the other server adds it a moment later.

```lua
local function unhex(h)
  return (h:gsub("..", function(x) return string.char(tonumber(x, 16)) end))
end

-- "send <64-hex key> <raw> <host:port>" pays a key on a peer server.
function on_l2call(memo, info)
  if info.payer ~= ces.owner_pubkey() then return "only the owner sends" end
  local key, amount, server = memo:match("^send (%x+) (%d+) (%S+)$")
  if not key or #key ~= 64 then return "send <64-hex key> <raw> <host:port>" end
  local ok, err = ces.cross_transfer(unhex(key), tonumber(amount), server)
  if not ok then
    if err == ces.err.UNKNOWN_PEER then return server .. " is not a peer of this server" end
    return "error " .. err
  end
  return "sent; " .. err .. " raw left here"
end

ces.run()
```

The program key can get credit on another server the same way:
`ces.cross_transfer(ces.program_pubkey(), raw, server)`. Then the program
can spend it there, as its own key (see [Other servers](servers.md)).
