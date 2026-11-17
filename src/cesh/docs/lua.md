---
title: Lua programs
summary: How to write a CES program in Lua: on_l2call, ces.run(), the main ces calls, connections that people dial (ces.conn), and the sandbox
order: 4
---

A program is a Lua file that a server runs (see [Compute](compute.md)). It
is LuaJIT with `base`, `string`, `table`, `math` and `bit`. There is no
`os`, `io`, `require`, `load`, `debug` or `print`. LuaJIT is Lua 5.1: there
is no `//` and no `&`, `|`, `~`, `<<` or `>>`. Use `math.floor(a / b)` and
`bit.band`, `bit.bor`, `bit.bxor`, `bit.lshift` and `bit.rshift`.
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
| `ces.on_error(fn)` | Get each error of the program, with `fn(message)` in a task of its own |
| `ces.exit()` | End the program now |

A call that waits (`think`, `transfer`, `sleep`) runs inside `on_l2call` or
`ces.spawn(function() ... end)`, where the program goes on serving while it
waits.

## Connections

A person can dial a program and use it as a terminal: `cesh dial <pid>`,
or a window of a site. Each dial is a connection to the program.

```lua
ces.conn.set_listener({
  hello = "\27[2J\27[Hhello\r\n",
  on_open = function(conn) conn:write("you are " .. conn.id .. "\r\n") end,
  on_data = function(conn, data) conn:write(data) end,
  on_close = function(conn) end,
})
ces.run()
```

- `ces.conn.set_listener(t)` lets people dial the program.
  `ces.conn.set_listener(nil)` stops new dials. The connections that are
  open stay.
- `t.hello` is the first text that each connection gets. Keep it small
  (less than 1 KB), and write a bigger first screen in `on_open`.
- `on_open(conn)` runs for a new connection. `on_data(conn, data)` gets the
  bytes that the person sends. `on_close(conn)` runs when the connection
  ends.
- `conn:write(s)` sends bytes to the person. It returns true, or nil and an
  error. `conn:close()` ends the connection.
- `conn.id` is a number that no other connection of the program has.
  `conn.pubkey` is the key of the person (32 raw bytes).

The program and the side that dials agree on what the bytes mean. On a
terminal (`cesh dial`), they are text and the escape codes of a terminal
(ECMA-48, as xterm reads them): `ESC[<row>;<col>H` moves the cursor,
`ESC[2J` clears the screen, and `ESC[1;33m` sets bold yellow. In Lua, ESC
is `"\27"`. A key comes as the bytes that the terminal sends: a letter as
itself, Enter as `"\r"`, and the arrow keys as `ESC[A`, `ESC[B`, `ESC[C`
and `ESC[D` (up, down, right, left). A site can read the bytes in its own
way. One `on_data` can carry several keys, or a part of one. A program
that moves things on its own clock, such as a game, uses
`ces.every(ms, fn)`.

## Errors

`ces.on_error(fn)` sets a handler for the errors of the program, in a task or
in the first run. `fn(message)` runs in a task of its own, and the program
goes on. With no handler an error ends the program, and a program of the
server logs it. An error in the handler, a compile error and running out of
memory end the program.

## Money

The program's balance is the balance of its source file. It pays for each
second the program runs, for its file operations, and for each `ces.think`.
When the balance is gone, the program stops.
