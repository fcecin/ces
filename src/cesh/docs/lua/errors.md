---
title: Errors
summary: What a failed call returns, the ces.err names, ces.on_error, and what ends a program
order: 13
---

## A call that fails

A call of `ces` that fails returns `nil` and a code. The code is a number,
and `ces.err` gives it a name:

```lua
local ok, err = ces.file_create(path, 10, 0, 100000000)
if not ok then
  if err == ces.err.FILE_EXISTS then
    -- the file is there already: use it
  elseif err == ces.err.INSUFFICIENT_BALANCE then
    return "the program has too few credits"
  else
    return "error " .. tostring(err)
  end
end
```

- A bad argument, such as a key that is not 32 bytes, gives `nil` and a
  text in place of a code.
- [Errors](../basics/errors.md) says what each `CES_ERROR_*` code means.
  In Lua the names drop `CES_ERROR_`: `ces.err.NOT_OWNER` is
  `CES_ERROR_NOT_OWNER`.
- To show a name from a code:

  ```lua
  local names = {}
  for k, v in pairs(ces.err) do names[v] = k end
  -- names[err] is "FILE_NOT_FOUND", "BAD_NAME", ...
  ```

These come up most:

| Name | Meaning |
| --- | --- |
| `FILE_NOT_FOUND` | No file at that path |
| `FILE_EXISTS` | A file is already at that path |
| `BAD_NAME` | The path is in no zone, or it is a bare name |
| `NOT_OWNER` | The key cannot do that to this file or zone |
| `INSUFFICIENT_BALANCE` | Too few credits in the account that pays |
| `UNKNOWN_PEER` | The other server is not a peer of this server |
| `DISABLED` | This server does not run that service |
| `PROTO_REJECTED` | The other server does not run that service |
| `UNREACHABLE` | No server answered at that address |
| `CONNECTION_LOST` | The connection to the server closed during the call |
| `TIMEOUT` | No reply in time |

## An error in the program

An error in Lua (`error(...)`, or a bad index) ends the task that has it.

- `ces.on_error(fn)` sets a handler: `fn(message)` runs in a task of its
  own, and the program goes on. `ces.on_error(nil)` removes it.
- With no handler, an error ends the program.
- In `on_l2call`, the caller pays in every case, and gets an empty reply.
- An error in the handler, a compile error, and a program that uses all its
  memory end the program.

```lua
local last = "none"
ces.on_error(function(msg) last = msg end)   -- such as "program:7: bad input"

function on_l2call(memo)
  if memo == "last" then return last end
  if memo == "" then error("bad input") end
  return "ok"
end

ces.run()
```

The owner cannot read a log of the program. Keep the last errors, as above,
and give them in a command such as `state`.
