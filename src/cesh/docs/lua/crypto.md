---
title: Signatures and randomness
summary: ces.sign and ces.verify with the program's key, ces.sha256, and ces.random_bytes for fair games
order: 11
---

| Call | Returns |
| --- | --- |
| `ces.sign(data)` | A signature of 65 bytes, with the program's key. The private key stays out of the program |
| `ces.verify(key, data, sig)` | `true` when `sig` is a signature of `data` by `key` |
| `ces.sha256(data)` | The SHA-256 of `data`, 32 raw bytes |
| `ces.random_bytes(n)` | `n` random bytes (1 to 256) for keys, dice and draws |

Anyone can check what a program signs with `ces.program_pubkey()`, also
other programs and people who are not on the server.

## Receipts and dice

```lua
local function hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end
local function unhex(h)
  return (h:gsub("..", function(x) return string.char(tonumber(x, 16)) end))
end

function on_l2call(memo, info)
  local text = memo:match("^sign (.+)$")
  if text then
    return hex(ces.sign(text))                      -- 65 bytes, as 130 hex
  end
  local sig, msg = memo:match("^check (%x+) (.+)$")
  if sig then
    local ok = ces.verify(ces.program_pubkey(), msg, unhex(sig))
    return ok and "this program signed it" or "not signed by this program"
  end
  if memo == "roll" then
    return tostring(ces.random_bytes(1):byte() % 6 + 1)  -- a fair die
  end
  if memo == "hash" then return hex(ces.sha256("abc")) end
  return "commands: sign <text>, check <sig hex> <text>, roll, hash"
end

ces.run()
```

- `ces.random_bytes(1):byte() % 6` is not quite even (256 is not a
  multiple of 6). For a game that pays credits, draw again when the byte is 252 or
  more.
- Do not use `math.random` for anything that is worth credit: a person can
  guess it.
