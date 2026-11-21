---
title: Other servers
summary: Files, programs and accounts on other CES servers, as the program's own key, with ces.file_client, ces.compute_client and the remote_* calls
order: 9
---

A program can use other CES servers, and its own server over the network
too. There it acts as its own key, `ces.program_pubkey()`, and its account
on that server pays. That account is not the program's balance here: send
it credit first (see [Credits](credits.md)).

## Find a server

`ces.ping(addr)` asks a server at `host:port` for its facts, free, and
returns `{pubkey, rpc_port, min_difficulty}`, or `nil, error`. The clients
below dial the rpc port, `host:<rpc_port>`, not the main port.

## Accounts

| Call | Returns |
| --- | --- |
| `ces.remote_account_read(addr, key)` | `balance, nonce, last_dest, last_amount, last_time` of a key on the server at `addr`. Free |
| `ces.remote_transfer(addr, key, raw)` | `true, balance_left`. Pays from the program key's account on that server |
| `ces.remote_cross_transfer(addr, key, raw, server)` | `true, balance_left`. From the program key's account at `addr` to a key on `server`, a peer of `addr` |

## Clients

| Call | Returns |
| --- | --- |
| `ces.file_client(rpc_addr [, server_key])` | A handle on the server's file store |
| `ces.compute_client(rpc_addr [, server_key])` | A handle on the server's programs |
| `ces.think_client(rpc_addr [, server_key])` | A handle on the server's model (see [Language model](think.md)) |

Each returns `nil, error` when it cannot open the service. Give the
`server_key` (from `ces.ping`) so that the program checks that it talks to
that server. A handle does one call at a time: a second call while one
waits fails. End it with `h:close()`, which tells the server.

The file handle has the verbs of `cesh file`, and it returns its values
with no `true` first:

| Call | Returns |
| --- | --- |
| `fc:create(path, size, price_per_kb, deposit)` | `file_balance, cost` |
| `fc:write(path, offset, data)` | `file_balance` |
| `fc:append(path, data)` | `file_balance, new_size` |
| `fc:read(path, offset, length)` | `data, range_hash` |
| `fc:stat(path)` | A table, as `ces.file_stat` |
| `fc:resize(path, size)`, `fc:deposit(path, raw)`, `fc:withdraw(path, raw)`, `fc:set_price(path, price)`, `fc:delete(path)` | The new size, balance, price or refund |

The files that a program makes this way belong to the program key, so it
writes in `/h/<program key hex>/`.

The compute handle:

| Call | Returns |
| --- | --- |
| `cc:launch(path)` | `pid, started_us`. Starts a program from a file of the program key |
| `cc:kill(pid)` | `true` |
| `cc:stat(pid)` | A table: `pid`, `source_name`, `started_at_us`, `file_balance`, `cpu_basis_points`, `rss_bytes`, `client_port`, `rpc_port`, `program_pubkey` |
| `cc:list()` | An array of the program key's instances, as `stat` |
| `cc:instances(path)` | An array of the instances of a source file |

## Example: a file on another server

```lua
local function hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end
local me = ces.program_pubkey()

-- Credit for the program's own key on another server: memo is its host:port.
local function fund(server, amount)
  local before = ces.remote_account_read(server, me) or 0
  local ok, err = ces.cross_transfer(me, amount, server)
  if not ok then return nil, "cross: error " .. err end
  for _ = 1, 50 do                         -- the other server credits soon after
    local bal = ces.remote_account_read(server, me)
    if bal and bal >= before + amount then return bal end
    ces.sleep(200)
  end
  return nil, "the credit did not arrive in 10 s"
end

function on_l2call(memo)
  local bal, err = fund(memo, 200000000)   -- 2 credits
  if not bal then return err end
  local info = ces.ping(memo)
  local host = memo:match("^(.*):%d+$")
  local fc = ces.file_client(host .. ":" .. info.rpc_port, info.pubkey)
  local path = "/h/" .. hex(me) .. "/hello.txt"
  fc:delete(path)
  local fb, e = fc:create(path, 5, 0, 100000000)   -- the program key pays there
  if not fb then fc:close() return "create: error " .. e end
  fc:write(path, 0, "hello")
  fc:close()
  return "the program key has " .. bal .. " raw there, and " .. path .. " exists"
end

ces.run()
```

The server at `memo` must be a peer of this server, for the cross
transfer.
