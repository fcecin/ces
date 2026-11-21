---
title: Language model
summary: ces.think, the server's language model for a program, with streaming, conversation files, and ces.think_client for the model of another server
order: 10
---

`ces.think(prompt [, on_piece [, file]])` asks the language model of the
server that runs the program. The program's balance pays. It works only on a
server that runs the model (`/ces/think/1`); elsewhere it fails with
`ces.err.DISABLED`.

| Result | Values |
| --- | --- |
| A reply | `reply, charged, append_error`. `charged` is the cost in raw, and `append_error` is `ces.err.OK`, or the code of a failed write to `file` |
| A failure | `nil, code, partial`. `partial` is the part of the reply that came before the failure |

- Before the call, the server takes the most that the call can cost, and
  after it, it gives back the rest. So the program's balance must have that
  much, else the call fails with `ces.err.INSUFFICIENT_BALANCE` (see
  [Think](../think.md)). The most is the largest reply plus the prompt, so a
  server with a large reply limit needs a large balance. `cesh think -v`
  shows the server's limits and the cost of a call.
- `on_piece(piece)` gets the reply in pieces as the model writes it. It
  cannot wait, so it cannot call `ces.sleep` or a file call.
- The call waits until the reply is complete, so it runs in a task.

## Ask a question

```lua
-- Answers a question with the server's model. The program's balance pays.
function on_l2call(memo)
  local reply, a, b = ces.think("Answer in one short sentence: " .. memo)
  if not reply then
    return "no answer: error " .. a       -- a is the code, b the part that came
  end
  return reply .. " (" .. a .. " raw)"    -- a is the charge
end

ces.run()
```

## Send the reply as it comes

```lua
-- Each line that a person types goes to the model, and the reply comes
-- back piece by piece as the model writes it.
ces.conn.set_listener({
  on_data = function(conn, data)
    local reply, err = ces.think(data, function(piece) conn:write(piece) end)
    if not reply then conn:write("[error " .. err .. "]") end
    conn:write("\r\n")
  end,
})

ces.run()
```

## A conversation file

With `file`, the server puts the content of that file before the prompt,
and after a complete reply it adds the prompt and the reply to the end of
the file. So the model sees the talk so far. The program acts as its owner
for the file, as with [Files](files.md), and the program's balance pays
for the bytes that the file gets. The server adds the prompt and the reply
with nothing between them, so put the marks of the talk in the prompt.

```lua
local function hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end
local talk = "/h/" .. hex(ces.owner_pubkey()) .. "/talk.txt"

-- The file is the memory of the talk. The server reads it before each
-- prompt, and adds the prompt and the reply to it.
if not ces.file_stat(talk) then
  local intro = "A talk between a person and a helpful assistant.\n"
  ces.file_create(talk, #intro, 0, 100000000)
  ces.file_write(talk, 0, intro)
end

function on_l2call(memo)
  local reply, a, b = ces.think("\nPerson: " .. memo .. "\nAssistant: ", nil, talk)
  if not reply then return "no answer: error " .. a end
  if b ~= ces.err.OK then return reply .. " (not kept: error " .. b .. ")" end
  return reply
end

ces.run()
```

The file grows with each turn, and each turn sends all of it. A prompt with
its file must fit the server's input limit.

## Ask another server's model

`ces.think_client(rpc_addr [, server_key])` opens the model of another
server, as the program's own key (see [Other servers](servers.md)).
`tc:think(prompt [, file])` returns the same values as `ces.think`, with no
pieces. The program key's account on that server pays, so send it credit
there first.

```lua
-- Asks the model of another server (memo: its host:port). The program key's
-- account on that server pays, so it needs credit there.
function on_l2call(memo)
  local info, err = ces.ping(memo)
  if not info then return "no answer from " .. memo end
  local host = memo:match("^(.*):%d+$")
  local tc, why = ces.think_client(host .. ":" .. info.rpc_port, info.pubkey)
  if not tc then return "no model there: " .. tostring(why) end
  local reply, a = tc:think("Say hello in one word.")
  tc:close()
  if not reply then return "no answer: error " .. a end
  return reply
end

ces.run()
```

A server with no model refuses the client with `ces.err.PROTO_REJECTED`.
