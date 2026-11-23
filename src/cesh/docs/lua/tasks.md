---
title: Tasks and time
summary: ces.spawn, ces.sleep, ces.every, ces.cancel, ces.now, ces.start_time and ces.exit
order: 2
---

A program runs many tasks at once in one Lua state. A task is a coroutine.
`on_l2call`, each connection callback and each `ces.spawn` run as tasks.
When a task waits, the other tasks run.

| Call | What it does |
| --- | --- |
| `ces.spawn(fn)` | Start `fn` as a new task, at the next turn of the loop |
| `ces.sleep(ms)` | Wait `ms` milliseconds in this task. Only a task can wait: the main chunk cannot |
| `ces.every(ms, fn)` | Call `fn()` every `ms` milliseconds. Returns an id |
| `ces.cancel(id)` | Stop a timer of `ces.every` |
| `ces.now()` | The time, in microseconds since 1970 |
| `ces.start_time()` | When this program started, in microseconds |
| `ces.exit()` | End the program now. A paid call that runs then gets an empty reply, and its payment stays |

## Example

```lua
local seconds = 0
ces.every(1000, function() seconds = seconds + 1 end)

function on_l2call(memo)
  if memo == "uptime" then
    return seconds .. " s"
  elseif memo == "reset" then
    ces.spawn(function()
      ces.sleep(2000)
      seconds = 0                 -- 2 s after the call
    end)
    return "the count goes to 0 in 2 s"
  elseif memo == "wait" then
    local t0 = ces.now()
    ces.sleep(500)                -- a call can wait, and the program goes on
    return math.floor((ces.now() - t0) / 1000) .. " ms later"
  end
  return "commands: uptime, reset, wait"
end

ces.run()
```

- A game or a clock moves with `ces.every`.
- Work that must not hold up the reply goes in `ces.spawn`.
- To pass values between tasks, use a [channel](channels.md).
- An error in a task goes to the error handler, if the program has one
  (see [Errors](errors.md)). With no handler, it ends the program.
