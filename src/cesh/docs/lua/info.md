---
title: Keys and server facts
summary: The program's keys, key names, and facts about this server and other servers
order: 12
---

| Call | Returns |
| --- | --- |
| `ces.program_pubkey()` | The program's own key (32 raw bytes). Its account is the program's balance |
| `ces.owner_pubkey()` | The key of the owner of the source file |
| `ces.keyname(key)` | The key name of `key` on this server (see [Key names](../names/keynames.md)), or `nil` |
| `ces.server_info()` | A table of this server's facts: `server_name`, `rpc_port`, `version`, the fees (`fee_tx`, ...), `min_difficulty` and its counts |
| `ces.peers()` | An array of this server's peers: `pubkey`, `address`, `reachable`, `verified`, `outbound`, `inbound` |
| `ces.ping(addr)` | `{pubkey, rpc_port, min_difficulty}` of the server at `host:port`, or `nil, error`. Free |
| `ces.peer_info(addr, i)` | Entry `i` of the peer table of the server at `addr`: `{count, found, pubkey, address}` |
| `ces.rpc_port()` | This program's own rpc port, where other programs dial it (see [Connections](connections.md)) |

## Who is it

A call gives the caller's key in `info.payer`, and a connection gives it in
`conn.pubkey`. Compare a key with `ces.owner_pubkey()` to give the owner
more rights:

```lua
function on_l2call(memo, info)
  if memo == "stop" then
    if info.payer ~= ces.owner_pubkey() then return "only the owner stops me" end
    ces.spawn(function() ces.sleep(100); ces.exit() end)   -- reply first, then end
    return "stopping"
  end
  local name = ces.keyname(info.payer)
  return "hello " .. (name or "stranger")
end

ces.run()
```

## Where am I

```lua
local function hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

function on_l2call(memo)
  local s = ces.server_info()
  return s.server_name .. " runs this program, and its key is "
    .. hex(ces.program_pubkey()):sub(1, 16) .. "..."
end

ces.run()
```

A program that serves people should tell its key and its server, so that
people can pay it and find it again.
