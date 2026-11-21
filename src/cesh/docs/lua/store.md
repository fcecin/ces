---
title: Key-value store
summary: ces.store(path): keys and values that stay after the program stops, where each key pays its own rent
order: 6
---

`ces.store(path)` gives a key-value store in a file of this server. The
program acts as its owner, as with [Files](files.md), so `path` is a full
path where the owner can make files. The values stay after the program
stops.

| Call | Returns |
| --- | --- |
| `local db = ces.store(path)` | A handle. It keeps no state: a new handle on the same path sees the same data |
| `db:create()` | `true, 0`. Makes the store. When a file is at that path, it fails with `PATH_CONFLICT` |
| `db:put(key, value [, deposit])` | `true, key_balance, store_size`. `deposit` raw goes into the key's balance |
| `db:get(key)` | The value, or a single `nil` for a key that is not there. `nil, code` is an error |
| `db:erase(key)` | `true`, also for a key that is not there |
| `db:deposit(key, raw)` | The key's new balance. Anyone can pay for any key |
| `db:keys()` | An array of all the keys |
| `db:range(lo, hi [, max_bytes])` | `entries, next`. The keys from `lo` up to `hi`, in order, as `{key=, value=}`. `""` is the start or the end |

- A key has at most 256 bytes, and a value at most 1 MB.
- Each key has a balance of its own that pays its rent. A key with a
  balance of 0 goes at the next daily rent sweep. Give each key that must
  stay a deposit, with `put` or `deposit`.
- Each `put` pays a small write fee from the program's balance.
- `range` gives a part when the range is big: then `next` is the first key
  that it did not give. Call `range(next, hi)` again until `next` is `hi`.

## High scores

```lua
local function hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end
local path = "/h/" .. hex(ces.owner_pubkey()) .. "/scores.kv"
local db = ces.store(path)
if not ces.file_stat(path) then db:create() end   -- make it the first time

function on_l2call(memo)
  local name, score = memo:match("^set (%w+) (%d+)$")
  if name then
    -- Each key pays its own rent: 0.01 credit here keeps it.
    local ok, err = db:put(name, score, 1000000)
    if not ok then return "error " .. err end
    return name .. " has " .. score
  end
  name = memo:match("^get (%w+)$")
  if name then
    local v, err = db:get(name)
    if err then return "error " .. err end
    return v or (name .. " has no score")
  end
  if memo == "all" then
    local out, lo = {}, ""
    repeat                         -- range gives a part; go on from where it ends
      local entries, hi = db:range(lo, "")
      if not entries then return "error " .. hi end
      for _, e in ipairs(entries) do out[#out + 1] = e.key .. "=" .. e.value end
      lo = hi
    until hi == ""
    return table.concat(out, " ")
  end
  return "commands: set <name> <score>, get <name>, all"
end

ces.run()
```

```
cesh compute call <pid> 0 --in "text:set ana 30"   # ana has 30
cesh compute call <pid> 0 --in "text:all"          # ana=30
```
