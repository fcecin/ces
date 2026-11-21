---
title: Buckets
summary: ces.bucket_new, a cache in memory that keeps each entry for at least its time and then forgets it
order: 7
---

A bucket is a cache in the program's memory. It keeps an entry for at
least `ttl` seconds and at most two times `ttl`, and then forgets it. Use
it to remember something for a time, such as "this key already played this
hour", with no table that grows forever.

| Call | Returns |
| --- | --- |
| `ces.bucket_new(ttl_secs, max_entries, max_entry_bytes)` | A bucket, or `nil, error` |
| `b:put(key, value)` | `true`, or `false` when the bucket is full |
| `b:get(key)` | The value, or `nil` |

- `ttl_secs` is from 1 s to 30 days, `max_entries` up to 1000000, and
  `max_entry_bytes` up to 64 KB. The key and the value together must fit
  in `max_entry_bytes`.
- The program pays for `max_entries` × `max_entry_bytes` of memory while
  the bucket lives, also when it is empty. Ask only for what you need.
- A full bucket refuses new entries. It does not drop old ones.
- The buckets end with the program.

## One gift per hour

```lua
-- One small gift per key per hour.
local given = ces.bucket_new(3600, 10000, 64)  -- 1 h, 10000 keys, 64 bytes each

function on_l2call(memo, info)
  if given:get(info.payer) then return "one gift an hour: come back later" end
  if not given:put(info.payer, "1") then return "too many keys this hour" end
  local ok, err = ces.transfer(info.payer, 1000000)   -- 0.01 credit
  if not ok then return "no gift: error " .. err end
  return "a gift of 0.01 credit"
end

ces.run()
```
