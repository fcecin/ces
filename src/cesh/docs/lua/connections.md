---
title: Connections
summary: ces.conn: people and programs that dial the program, terminal bytes, and dials from one program to another
order: 4
---

A person dials a program with `cesh dial <pid>`, or with a window of a
site, and uses it as a terminal. Another program can dial it too. Each dial
is a connection.

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
  bytes that the other side sends. `on_close(conn)` runs when the
  connection ends. Each callback runs as a task, and the callbacks of one
  connection run in order.
- `conn:write(s)` sends bytes. It returns true, or nil and an error.
  `conn:close()` ends the connection.
- `conn.id` is a number that no other connection of the program has.
  `conn.pubkey` is the key of the side that dialed (32 raw bytes), so the
  program knows who it talks to.

## Greet by name

```lua
local function hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

ces.conn.set_listener({
  on_open = function(conn)
    local name = ces.keyname(conn.pubkey)
    conn:write("hello " .. (name or hex(conn.pubkey):sub(1, 8)) .. "\r\n")
  end,
  on_data = function(conn, data) conn:write("you said " .. data) end,
})

ces.run()
```

`ces.keyname(key)` is the key name of that key on this server, or nil (see
[Keys and server facts](info.md)).

## Terminal codes

The program and the side that dials agree on what the bytes mean. On a
terminal (`cesh dial`), they are text and the escape codes of a terminal
(ECMA-48, as xterm reads them): `ESC[<row>;<col>H` moves the cursor,
`ESC[2J` clears the screen, and `ESC[1;33m` sets bold yellow. In Lua, ESC
is `"\27"`.

- With `cesh dial`, the terminal sends a line at Enter, and the program
  gets it with `"\n"` at its end.
- With `cesh dial --raw`, each key comes at once as the bytes that the
  terminal sends: a letter as itself, Enter as `"\r"`, and the arrow keys
  as `ESC[A`, `ESC[B`, `ESC[C` and `ESC[D` (up, down, right, left).
- One `on_data` can carry several keys, or a part of one.
- A program that moves things on its own clock, such as a game, uses
  `ces.every(ms, fn)`.
- A window of character cells, with colors and the mouse, is VS1 (see
  [Loadables](loadables.md)).

## Dial another program

`ces.conn.connect(addr, key [, timeout_ms])` dials another program, on
this server or on another one. `addr` is `host:port` of that program's own
rpc port, and `key` is that program's key (`ces.program_pubkey()` there).
`compute_client:stat(pid)` gives both (see [Other servers](servers.md)).
It returns a connection, or nil and an error. The replies come to the
program's own `on_data`, so the program needs a listener.

```lua
-- Dials another program of this server and sends it a line: memo is its pid.
local replies = ces.chan()
ces.conn.set_listener({
  on_data = function(conn, data) replies:send(data) end,  -- dials out land here too
})

function on_l2call(memo)
  local pid = tonumber(memo)
  if not pid then return "give the pid of a program" end
  local info = ces.server_info()
  local host = info.server_name:match("^(.*):%d+$")
  local cc, err = ces.compute_client(host .. ":" .. info.rpc_port)
  if not cc then return "no compute: " .. tostring(err) end
  local st, e = cc:stat(pid)
  cc:close()
  if not st then return "no program " .. memo .. ": error " .. tostring(e) end
  local conn, why = ces.conn.connect(host .. ":" .. st.rpc_port, st.program_pubkey)
  if not conn then return "cannot dial: " .. why end
  conn:write("hi\n")
  local reply = replies:recv(3000)
  conn:close()
  return reply or "no reply in 3 s"
end

ces.run()
```
