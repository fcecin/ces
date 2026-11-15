---
title: Lua programs
summary: How to write a CES program in Lua: on_l2call, ces.run(), the main ces calls, and the sandbox
order: 4
---

A program is a Lua file that a server runs (see [Compute](compute.md)). It
is LuaJIT with `base`, `string`, `table`, `math` and `bit`. There is no
`os`, `io`, `require`, `load`, `debug` or `print`.
The API is the global table `ces`.

## The smallest service

```lua
function on_l2call(memo, info)
  return "hello " .. memo
end
ces.run()
```

- `ces.run()` must be the last line. It is the event loop: without it, the
  program ends after its first lines and does nothing more.
- `on_l2call(memo, info)` answers a paid call (`cesh compute call <pid>
  --in <memo> --value <raw>`). `memo` is the caller's text. `info.payer` is
  the caller's key (32 raw bytes), `info.value` the credits paid (raw), and
  `info.callid` the call's number. The string you return is the reply.
- The paid credits arrive in the program's balance after `on_l2call`
  returns. A program with no `on_l2call` refunds every call.

## Main calls

| Call | What it does |
| --- | --- |
| `ces.program_pubkey()` | The program's own key (32 raw bytes); credits sent to it go to its balance |
| `ces.owner_pubkey()` | The key of the file's owner (32 raw bytes) |
| `ces.transfer(key32, raw)` | Send credits from the program's balance |
| `ces.think(prompt)` | Ask the server's model; returns the reply and the cost |
| `ces.spawn(fn)` | Run `fn` as a coroutine |
| `ces.sleep(ms)` | Wait, in a coroutine |
| `ces.every(ms, fn)` | Run `fn` again and again |
| `ces.now()` | Time in microseconds |
| `ces.exit()` | End the program now |

A call that waits (`think`, `transfer`, `sleep`) runs inside `on_l2call` or
`ces.spawn(function() ... end)`, where the program goes on serving while it
waits.

## Money

The program's balance is the balance of its source file. It pays for each
second the program runs, for its file operations, and for each `ces.think`.
When the balance is gone, the program stops.
