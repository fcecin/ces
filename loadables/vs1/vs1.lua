-- VS1 (Visual System 1). Screens of character cells that a program ships to
-- the people who dial it, and their input.
--
--   local vs1 = ces.load("vs1/vs1.lua")
--   local s = vs1.new(40, 25)                -- columns, rows
--   s:color(0xffcc00, 0x000000)              -- fg and bg of the next writes
--   s:write(3, 2, "hello")                   -- the cursor goes after the text
--   s:write("!")                             -- at the cursor
--   s:at(1, 25)                              -- move the cursor
--   s:put(10, 5, 0x2588)                     -- a character by its code
--   s:fill(1, 20, 40, 6, "#")
--   s:blit(5, 8, {"/\\", "\\/"})              -- one string per row
--   s:clear()
--   s:title("my game")
--   s:ship(conn)                             -- the changed cells, as one frame
--   s:forget(conn)                           -- in on_close
--   for e in vs1.events(conn, data) do end   -- in on_data
--
-- Positions start at 1, writes stop at the right edge, and colors are
-- 0xRRGGBB. Events are {type = "key", action = "down"|"up"|"repeat", key,
-- time, shift, ctrl, alt, meta}, {type = "pointer", action =
-- "down"|"up"|"move", button, x, y, time}, {type = "focus", on, time} and
-- {type = "text", text}. key is the browser's key name, and time is the
-- viewer's clock in ms. A text event is a line or a paste.
--
--   local keys = vs1.keys(170, 50, function(conn, key) end)
--   keys:feed(conn, e)                       -- each event
--   keys:forget(conn)                        -- in on_close
--
-- vs1.keys calls the function once at a key down, then every 50 ms after
-- 170 ms until the key up, counted on the viewer's clock. Repeats are ignored.
--
-- VS1 sets vs1.fault as ces.on_error when it loads. On an error it writes the
-- message over the screens from the top left, sends each viewer the screen it
-- saw last, and takes the listener, so later viewers get the first screen and
-- the program gets no more events.
--
-- Each message to or from a viewer is [u8 kind][u32 size][body], little-endian.
--   1 mode     [u8 1][u16 cols][u16 rows], all cells a space, 0xaaaaaa on 0
--   2 frame    runs of [u16 x][u16 y][u16 n] and n x [u32 code][u24 fg][u24 bg]
--   3 title    UTF-8
--   128 keepalive  no body, skipped
--   129 key    [u8 action 1 down 2 up 3 repeat][u8 mods 1 shift 2 ctrl 4 alt
--              8 meta][u32 time][name]
--   130 pointer [u8 action 1 down 2 up 3 move][u8 button][u16 x][u16 y][u32 time]
--   131 focus  [u8 on][u32 time]
--   132 text   UTF-8, a line or a paste, with "\n" for Enter
-- Positions in messages start at 0. A viewer message over 4096 bytes drops
-- what VS1 holds from that viewer.
local vs1 = {}
vs1.__index = vs1
local char, byte, band, rshift = string.char, string.byte, bit.band, bit.rshift
local function u16(n) return char(band(n, 255), band(rshift(n, 8), 255)) end
local function u24(n) return u16(n) .. char(band(rshift(n, 16), 255)) end
local function u32(n) return u24(n) .. char(band(rshift(n, 24), 255)) end
local function msg(kind, body) return char(kind) .. u32(#body) .. body end
local function at32(s, i) return byte(s, i) + byte(s, i + 1) * 256 + byte(s, i + 2) * 65536 + byte(s, i + 3) * 16777216 end
local BLANK = u32(32) .. u24(0xaaaaaa) .. u24(0)

local function codes(s)
  local out, i, n = {}, 1, #s
  while i <= n do
    local c, k = byte(s, i), 0
    if c >= 0xF0 then k, c = 3, c - 0xF0 elseif c >= 0xE0 then k, c = 2, c - 0xE0
    elseif c >= 0xC0 then k, c = 1, c - 0xC0 elseif c >= 0x80 then c = 0xFFFD end
    for j = i + 1, i + k do
      local d = byte(s, j)
      if not d or d < 0x80 or d >= 0xC0 then c, k = 0xFFFD, j - i - 1; break end
      c = c * 64 + d - 0x80
    end
    out[#out + 1] = c <= 0x10FFFF and c or 0xFFFD
    i = i + k + 1
  end
  return out
end

-- Screen -> the order it was made in. Weak, so dropped screens are collected.
local screens, made = setmetatable({}, {__mode = 'k'}), 0

function vs1.new(cols, rows)
  local s = setmetatable({cols = cols, rows = rows, ver = {}, seen = {}}, vs1)
  s:color(0xaaaaaa, 0)
  s:clear()
  made = made + 1
  screens[s] = made
  return s
end

function vs1:color(fg, bg)
  self.fg, self.bg = fg or self.fg, bg or self.bg
  self.pen = u24(self.fg) .. u24(self.bg)
end

function vs1:at(x, y) self.x, self.y = x, y end

local function place(self, x, y, cs)
  if self.frozen then return end
  local row = self.cells[y]
  if row then
    for i = 1, #cs do
      local cx = x + i - 1
      if cx >= 1 and cx <= self.cols then row[cx] = u32(cs[i]) .. self.pen end
    end
    self.ver[y] = self.ver[y] + 1
  end
  self.x, self.y = x + #cs, y
end

function vs1:write(x, y, text)
  if y == nil then text, x, y = x, self.x, self.y end
  place(self, x, y, codes(tostring(text)))
end

function vs1:put(x, y, code) place(self, x, y, {code}) end

function vs1:fill(x, y, w, h, ch)
  local c, cs = type(ch) == "number" and ch or codes(ch or " ")[1] or 32, {}
  for i = 1, w do cs[i] = c end
  for j = 0, h - 1 do place(self, x, y + j, cs) end
end

function vs1:blit(x, y, rows)
  for j = 1, #rows do self:write(x, y + j - 1, rows[j]) end
end

function vs1:clear()
  if self.frozen then return end
  local blank, cells = u32(32) .. self.pen, {}
  for y = 1, self.rows do
    local row = {}
    for x = 1, self.cols do row[x] = blank end
    cells[y], self.ver[y] = row, (self.ver[y] or 0) + 1
  end
  self.cells, self.x, self.y = cells, 1, 1
end

function vs1:title(text)
  if self.frozen then return end
  self.name = tostring(text)
end

function vs1:ship(conn)
  local seen, out, runs = self.seen[conn.id], {}, {}
  if not seen or conn.vs1 ~= self then
    seen = {ver = {}, cells = {}, conn = conn}
    self.seen[conn.id], conn.vs1 = seen, self
    out[1] = msg(1, char(1) .. u16(self.cols) .. u16(self.rows))
  end
  if seen.name ~= self.name then
    out[#out + 1] = msg(3, self.name or "")
    seen.name = self.name
  end
  for y = 1, self.rows do
    if seen.ver[y] ~= self.ver[y] then
      local row, old, x = self.cells[y], seen.cells[y] or {}, 1
      while x <= self.cols do
        if row[x] ~= (old[x] or BLANK) then
          local e = x
          while e < self.cols and row[e + 1] ~= (old[e + 1] or BLANK) do e = e + 1 end
          runs[#runs + 1] = u16(x - 1) .. u16(y - 1) .. u16(e - x + 1) .. table.concat(row, "", x, e)
          for i = x, e do old[i] = row[i] end
          x = e + 1
        else
          x = x + 1
        end
      end
      seen.cells[y], seen.ver[y] = old, self.ver[y]
    end
  end
  if #runs > 0 then out[#out + 1] = msg(2, table.concat(runs)) end
  if #out > 0 then return conn:write(table.concat(out)) end
  return true
end

function vs1:forget(conn) self.seen[conn.id] = nil end

local KEYS, POINTS = {"down", "up", "repeat"}, {"down", "up", "move"}

function vs1.events(conn, data)
  local buf, list, i = (conn.vs1_in or "") .. data, {}, 1
  while #buf - i >= 4 do
    local kind, n = byte(buf, i), at32(buf, i + 1)
    if n > 4096 then i = #buf + 1; break end
    if #buf - i + 1 < 5 + n then break end
    local b = buf:sub(i + 5, i + 4 + n)
    if kind == 129 and n >= 6 then
      local m = byte(b, 2)
      list[#list + 1] = {type = "key", action = KEYS[byte(b, 1)] or "down", time = at32(b, 3), key = b:sub(7),
        shift = band(m, 1) ~= 0, ctrl = band(m, 2) ~= 0, alt = band(m, 4) ~= 0, meta = band(m, 8) ~= 0}
    elseif kind == 130 and n >= 10 then
      list[#list + 1] = {type = "pointer", action = POINTS[byte(b, 1)] or "move", button = byte(b, 2),
        x = byte(b, 3) + byte(b, 4) * 256 + 1, y = byte(b, 5) + byte(b, 6) * 256 + 1, time = at32(b, 7)}
    elseif kind == 131 and n >= 5 then
      list[#list + 1] = {type = "focus", on = byte(b, 1) == 1, time = at32(b, 2)}
    elseif kind == 132 then
      list[#list + 1] = {type = "text", text = b}
    end
    i = i + 5 + n
  end
  conn.vs1_in = buf:sub(i)
  local k = 0
  return function() k = k + 1; return list[k] end
end

local STEPS = {}
STEPS.__index = STEPS

function vs1.keys(delay, rate, step)
  return setmetatable({delay = delay, rate = rate, step = step, down = {}}, STEPS)
end

local function release(self, conn, mine, key, time)
  local h = mine[key]
  mine[key] = nil
  local held = math.max(0, time - h.t0)
  local due = 1 + (held > self.delay and math.ceil((held - self.delay) / self.rate) or 0)
  for _ = h.given + 1, due do self.step(conn, key) end
end

function STEPS:feed(conn, e)
  local mine = self.down[conn.id] or {}
  self.down[conn.id] = mine
  if e.type == "focus" and not e.on then
    for key in pairs(mine) do release(self, conn, mine, key, e.time) end
  elseif e.type == "key" and e.action == "down" and not mine[e.key] then
    local h = {t0 = e.time, given = 1}
    mine[e.key] = h
    self.step(conn, e.key)
    ces.spawn(function()
      ces.sleep(self.delay)
      while mine[e.key] == h do
        h.given = h.given + 1
        self.step(conn, e.key)
        ces.sleep(self.rate)
      end
    end)
  elseif e.type == "key" and e.action == "up" and mine[e.key] then
    release(self, conn, mine, e.key, e.time)
  end
end

function STEPS:forget(conn)
  local mine = self.down[conn.id]
  if mine then for key in pairs(mine) do mine[key] = nil end end
  self.down[conn.id] = nil
end

function vs1.fault(err)
  if vs1.crashed then return end
  vs1.crashed = tostring(err)
  local list = {}
  for s in pairs(screens) do list[#list + 1] = s end
  table.sort(list, function(p, q) return screens[p] < screens[q] end)
  if #list == 0 then list[1] = vs1.new(80, 25) end
  local text = codes(vs1.crashed)
  for _, s in ipairs(list) do
    s:color(0xaaaaaa, 0)
    local x, y = 1, 1
    for _, c in ipairs(text) do
      if c == 10 then
        x, y = 1, y + 1
      else
        if x > s.cols then x, y = 1, y + 1 end
        if y > s.rows then break end
        place(s, x, y, {c < 32 and 32 or c})
        x = x + 1
      end
    end
    s.frozen = true
  end
  for _, s in ipairs(list) do
    for _, v in pairs(s.seen) do v.conn.vs1:ship(v.conn) end
  end
  ces.conn.set_listener({
    on_open = function(conn) list[1]:ship(conn) end,
    on_close = function(conn) for _, s in ipairs(list) do s:forget(conn) end end,
  })
end

if ces and ces.on_error then ces.on_error(vs1.fault) end

return vs1
