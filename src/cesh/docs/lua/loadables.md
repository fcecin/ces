---
title: Loadables
summary: ces.load, the Lua files that a server gives to every program, and VS1 for screens of character cells
order: 14
---

A loadable is a Lua file under `/s/loadables/` on the server.
`ces.load(path)` runs it and returns its value, and later calls return the
same value.

```lua
local vs1 = ces.load("vs1/vs1.lua")
```

- The path is relative to `/s/loadables/`.
- The call waits for the server, so load at the top of the program.
- A path that is not there gives an error. Catch it with `pcall` to go on
  without it:

  ```lua
  local ok, vs1 = pcall(ces.load, "vs1/vs1.lua")
  if not ok then vs1 = nil end   -- this server has no VS1
  ```

## VS1

`vs1/vs1.lua` is VS1, screens of character cells for programs that people
dial: text in 24-bit color, with keys and the mouse. Each viewer can have
a screen of its own. Its docs are at the top of the file:

```
cesh file get /s/loadables/vs1/vs1.lua -
```
