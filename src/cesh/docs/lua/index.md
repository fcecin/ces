---
title: Lua programs
summary: How to write a CES program in Lua, the sandbox, how to run it, and the pages about each part of the ces API
order: 4
---

A program is a Lua file that a server runs (see [Compute](../compute.md)).
It is LuaJIT with `base`, `string`, `table`, `math` and `bit`. There is no
`os`, `io`, `require`, `load`, `debug` or `print`. LuaJIT is Lua 5.1: there
is no `//` and no `&`, `|`, `~`, `<<` or `>>`. Use `math.floor(a / b)` and
`bit.band`, `bit.bor`, `bit.bxor`, `bit.lshift` and `bit.rshift`. The API is
the global table `ces`.

## The smallest program

```lua
function on_l2call(memo, info)
  return "hello " .. memo
end

ces.run()
```

`on_l2call` answers each paid call, and `ces.run()` is the event loop. It
must be the last line: without it the program ends after its first lines.

## Run it

```
cesh file put hello.lua hello.lua --deposit 5000000000
cesh compute launch hello.lua                 # prints the pid
cesh compute call <pid> 0 --in "text:world"   # prints "hello world"
cesh compute kill <pid>
```

The deposit (50 credits here) is the program's balance. It pays for each
second that the program runs, and for what the program does.

## Facts for every page

- A key is 32 raw bytes, such as `ces.program_pubkey()`. To show a key or
  to read one from text, change it to hex and back:

  ```lua
  local function hex(s)
    return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
  end
  local function unhex(h)
    return (h:gsub("..", function(x) return string.char(tonumber(x, 16)) end))
  end
  ```

- Amounts are raw units: 1 credit is 100000000 raw.
- A call that fails returns `nil` and a code. Compare the code with
  `ces.err`, for example `err == ces.err.FILE_NOT_FOUND`. See [Errors](errors.md).
- A call that waits, such as a file call or `ces.sleep`, runs in a task:
  `on_l2call`, a connection callback or `ces.spawn`. While it waits, the
  program goes on with its other tasks.
- `tostring` of a big number gives `1.795e+15`. Use
  `string.format("%.0f", n)` for times in microseconds.

## Pages

- [Paid calls](calls.md): `on_l2call`, its memo and payment, and the reply.
- [Tasks and time](tasks.md): `ces.spawn`, `ces.sleep`, `ces.every`, `ces.now` and `ces.exit`.
- [Channels](channels.md): `ces.chan`, to pass values between tasks.
- [Connections](connections.md): people and programs that dial the program, and dials to other programs.
- [Files](files.md): `ces.file_*`, files on this server as the owner.
- [Key-value store](store.md): `ces.store`, keys that pay their own rent.
- [Buckets](buckets.md): `ces.bucket_new`, a cache that forgets after a time.
- [Credits](credits.md): the program's balance, `ces.transfer`, and credit to other servers.
- [Other servers](servers.md): files, programs and accounts on other servers, as the program's key.
- [Language model](think.md): `ces.think` and `ces.think_client`.
- [Signatures and randomness](crypto.md): `ces.sign`, `ces.verify`, `ces.sha256` and `ces.random_bytes`.
- [Keys and server facts](info.md): the program's keys, key names and facts about the server.
- [Errors](errors.md): failed calls, `ces.err` and `ces.on_error`.
- [Loadables](loadables.md): `ces.load` and VS1, screens for programs that people dial.
