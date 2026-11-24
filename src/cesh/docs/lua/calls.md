---
title: Paid calls
summary: on_l2call(memo, info), what the caller pays, the reply, and a tip jar example
order: 1
---

A paid call sends a memo to the program and gets a reply. It comes from
`cesh compute call <pid> <raw> --in "text:<memo>"`, from a site, or from
another program (`cc:call`, see [Other servers](servers.md)). The caller
pays `<raw>` credits with the call, and 0 is a valid amount.

```lua
function on_l2call(memo, info)
  return "you sent " .. memo
end
ces.run()
```

- `memo` is the bytes that the caller sent.
- `info.payer` is the caller's key (32 raw bytes).
- `info.value` is what the caller paid, in raw.
- `info.callid` is the number of the call.
- The value that `on_l2call` returns is the reply: a string, or a number as
  text. `nil` gives an empty reply.
- The payment goes into the program's balance after `on_l2call` returns.
- The caller pays also when `on_l2call` fails with an error, and gets an
  empty reply. With no error handler (see [Errors](errors.md)), the error
  also ends the program.
- A call has no time limit. It ends when the program answers, when the program
  ends, or when the caller's connection ends. The caller can hang up.
- A caller that hangs up before the program starts the call gets the payment
  back, and the program never runs the call. A call that the program has started
  goes on, and the program gets the payment at the hang-up.
- A program with no `on_l2call` gives every payment back.
- `on_l2call` runs as a task, so it can wait (`ces.sleep`, file calls) and
  other calls run meanwhile.

## Give a program commands

Give each program a few text commands, such as `help` and `state`, so that
you and other programs can check it with a call that pays 0.

```lua
-- A tip jar. "state" reads the count, and a call that pays adds a tip.
local tips, total = 0, 0

function on_l2call(memo, info)
  if memo == "help" then
    return "commands: help, state, tip (pay with the call)"
  elseif memo == "state" then
    return tips .. " tips, " .. total .. " raw in all"
  elseif memo == "tip" then
    if info.value == 0 then return "a tip needs credits: pay with the call" end
    tips, total = tips + 1, total + info.value
    return "thank you for " .. info.value .. " raw"
  end
  return "unknown command: " .. memo
end

ces.run()
```

```
cesh compute call <pid> 0 --in "text:state"       # 0 tips, 0 raw in all
cesh compute call <pid> 5000 --in "text:tip"      # thank you for 5000 raw
```

## Arguments in the memo

Split the memo with Lua patterns:

```lua
function on_l2call(memo)
  local name, score = memo:match("^set (%w+) (%d+)$")
  if name then return name .. " has " .. score end
  return "usage: set <name> <score>"
end
```

A variable in Lua keeps its value only while the program runs. To keep
data after the program stops, use [Files](files.md) or
[the key-value store](store.md).
