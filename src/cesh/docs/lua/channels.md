---
title: Channels
summary: ces.chan, a queue of Lua values between the tasks of a program
order: 3
---

A channel passes Lua values from task to task, in order.

| Call | What it does |
| --- | --- |
| `ces.chan()` | A new channel |
| `ch:send(v)` | Put `v` (any Lua value) in the queue. It does not wait. Returns `false` when the channel is closed |
| `ch:recv([ms])` | The next value. It waits at most `ms` (10000 if not given), then returns `nil, "timeout"`. On a closed channel it returns `nil, "closed"` |
| `ch:close()` | Close the channel: the tasks that wait get `nil, "closed"`, and later values are dropped |

`recv` waits, so it runs in a task.

## Example

```lua
-- One task keeps the lines in order. A call only puts its line in the queue.
local queue = ces.chan()
local lines = {}

ces.spawn(function()
  while true do
    local line = queue:recv(60000)    -- nil, "timeout" after 60 s with no line
    if line then lines[#lines + 1] = line end
  end
end)

function on_l2call(memo)
  if memo == "show" then return table.concat(lines, ", ") end
  queue:send(memo)
  return "queued"
end

ces.run()
```

A channel also gets the replies of a [dial to another program](connections.md):
`on_data` sends them to the channel, and the task that dialed reads them.
