// Tests of VS1 (loadables/vs1/vs1.lua).

#define BOOST_TEST_DYN_LINK
#include "test_loadable_common.h"

#include <ces/buffer.h>

#include <algorithm>
#include <string>
#include <vector>

using namespace ces;

namespace {

// Reads VS1 messages into a screen. Positions start at 1, as in VS1.
struct Monitor {
  struct Cell {
    uint32_t code = 32, fg = 0xaaaaaa, bg = 0;
    bool operator==(const Cell&) const = default;
  };
  int cols = 0, rows = 0;
  std::vector<Cell> cells;
  std::string title;
  std::vector<int> kinds;   // the kind of each message, in order
  size_t frameCells = 0;    // the cells in the last frame
  std::string error;        // what the monitor could not read

  explicit Monitor(const std::string& bytes) {
    const auto* p = reinterpret_cast<const uint8_t*>(bytes.data());
    size_t at = 0;
    while (error.empty() && at + 5 <= bytes.size()) {
      const uint32_t size = ces::Buffer::peekLE<uint32_t>(p + at + 1);
      if (at + 5 + size > bytes.size()) { error = "a message is cut"; break; }
      read(p[at], p + at + 5, size);
      at += 5 + size;
    }
    if (error.empty() && at != bytes.size()) error = "bytes after the last message";
  }

  static uint32_t u24(const uint8_t* p) {
    return ces::Buffer::peekLE<uint16_t>(p) | (uint32_t(p[2]) << 16);
  }

  void read(int kind, const uint8_t* b, size_t size) {
    kinds.push_back(kind);
    if (kind == 1) {
      if (size != 5 || b[0] != 1) { error = "a bad mode"; return; }
      cols = ces::Buffer::peekLE<uint16_t>(b + 1);
      rows = ces::Buffer::peekLE<uint16_t>(b + 3);
      cells.assign(size_t(cols) * rows, Cell{});
    } else if (kind == 2) {
      frameCells = 0;
      for (size_t at = 0; at < size;) {
        if (at + 6 > size) { error = "a run is cut"; return; }
        const int x = ces::Buffer::peekLE<uint16_t>(b + at);
        const int y = ces::Buffer::peekLE<uint16_t>(b + at + 2);
        const int n = ces::Buffer::peekLE<uint16_t>(b + at + 4);
        at += 6;
        if (at + size_t(n) * 10 > size || y >= rows || x + n > cols) { error = "a bad run"; return; }
        for (int i = 0; i < n; ++i, at += 10)
          cells[size_t(y) * cols + x + i] = {ces::Buffer::peekLE<uint32_t>(b + at), u24(b + at + 4),
                                             u24(b + at + 7)};
        frameCells += size_t(n);
      }
    } else if (kind == 3) {
      title.assign(reinterpret_cast<const char*>(b), size);
    } else {
      error = "a message of kind " + std::to_string(kind);
    }
  }

  const Cell& cell(int x, int y) const { return cells.at(size_t(y - 1) * cols + (x - 1)); }

  // Row `y` in UTF-8, without trailing spaces.
  std::string row(int y) const {
    std::string s;
    for (int x = 1; x <= cols; ++x) {
      const uint32_t c = cell(x, y).code;
      if (c < 0x80) {
        s += char(c);
      } else if (c < 0x800) {
        s += char(0xc0 | (c >> 6));
        s += char(0x80 | (c & 0x3f));
      } else if (c < 0x10000) {
        s += char(0xe0 | (c >> 12));
        s += char(0x80 | ((c >> 6) & 0x3f));
        s += char(0x80 | (c & 0x3f));
      } else {
        s += char(0xf0 | (c >> 18));
        s += char(0x80 | ((c >> 12) & 0x3f));
        s += char(0x80 | ((c >> 6) & 0x3f));
        s += char(0x80 | (c & 0x3f));
      }
    }
    s.erase(s.find_last_not_of(' ') + 1);
    return s;
  }
};

std::string message(uint8_t kind, const ces::Bytes& body) {
  ces::Bytes m{kind};
  ces::Buffer::putLE<uint32_t>(m, static_cast<uint32_t>(body.size()));
  m.insert(m.end(), body.begin(), body.end());
  return std::string(m.begin(), m.end());
}

std::string key(uint8_t action, uint8_t mods, uint32_t time, const std::string& name) {
  ces::Bytes b{action, mods};
  ces::Buffer::putLE<uint32_t>(b, time);
  b.insert(b.end(), name.begin(), name.end());
  return message(129, b);
}

std::string pointer(uint8_t action, uint8_t button, uint16_t x, uint16_t y, uint32_t time) {
  ces::Bytes b{action, button};
  ces::Buffer::putLE<uint16_t>(b, x);
  ces::Buffer::putLE<uint16_t>(b, y);
  ces::Buffer::putLE<uint32_t>(b, time);
  return message(130, b);
}

std::string text(const std::string& t) {
  return message(132, ces::Bytes(t.begin(), t.end()));
}

std::string focus(bool on, uint32_t time) {
  ces::Bytes b{uint8_t(on ? 1 : 0)};
  ces::Buffer::putLE<uint32_t>(b, time);
  return message(131, b);
}

size_t lineOf(const std::string& src, const std::string& what) {
  const size_t at = src.find(what);
  BOOST_REQUIRE(at != std::string::npos);
  return 1 + std::count(src.begin(), src.begin() + at, '\n');
}

}  // namespace

BOOST_FIXTURE_TEST_SUITE(Vs1E2E, loadtest::LoadableFixture)

// The checks run in the sandbox, with fake viewers and a fake clock.
BOOST_AUTO_TEST_CASE(ChecksInTheSandbox) {
  deployFromRepo("vs1/vs1.lua");
  uint64_t pid = launch("checks.lua", R"LUA(
local vs1 = ces.load('vs1/vs1.lua')
local real = ces
local function checks()
  local function conn(id)
    return {id = id, writes = 0, write = function(self, s)
      self.writes, self.last = self.writes + 1, s
      return true
    end}
  end
  local function eq(a, b, what)
    if a ~= b then error(what .. ': ' .. tostring(a) .. ' ~= ' .. tostring(b), 2) end
  end
  local c1, c2 = conn(1), conn(2)
  local a = vs1.new(6, 3)

  a:write(2, 1, 'ab')
  eq(a.x, 4, 'the cursor after a write')
  a:ship(c1)
  eq(c1.writes, 1, 'one write for a frame')
  eq(c1.last:byte(1), 1, 'a mode first')
  a:ship(c1)
  eq(c1.writes, 1, 'no write with no change')

  a:write(5, 2, 'xyz')
  eq(a.x, 8, 'the cursor after a clipped write')
  eq(a.cells[2][7], nil, 'no cell past the right edge')
  a:write('!')

  a:title('box')
  a:ship(c1)
  a:ship(c1)
  eq(c1.writes, 2, 'the title goes once')

  local b = vs1.new(3, 1)
  b:write(1, 1, 'B')
  b:ship(c1)
  eq(c1.last:byte(1), 1, 'a mode for the other screen')
  a:ship(c1)
  eq(c1.last:byte(1), 1, 'a mode when the viewer comes back')

  a:ship(c2)
  eq(c2.writes, 1, 'one write for a new viewer')
  a:forget(c2)
  eq(a.seen[2], nil, 'forget')

  local function le32(n)
    return string.char(n % 256, math.floor(n / 256) % 256, math.floor(n / 65536) % 256,
                       math.floor(n / 16777216) % 256)
  end
  local function key(action, mods, time, name)
    local body = string.char(action, mods) .. le32(time) .. name
    return string.char(129) .. le32(#body) .. body
  end
  local all = key(1, 1, 1000, 'ArrowLeft')
    .. string.char(130) .. le32(10) .. string.char(3, 0, 3, 0, 4, 0) .. le32(1001)
    .. string.char(131) .. le32(5) .. string.char(0) .. le32(1002)
    .. key(2, 0, 4294967295, ' ')
  local got = {}
  for e in vs1.events(c1, all:sub(1, 9)) do got[#got + 1] = e end
  eq(#got, 0, 'half an event waits')
  for e in vs1.events(c1, all:sub(10)) do got[#got + 1] = e end
  eq(#got, 4, 'the events')
  eq(got[1].type .. ' ' .. got[1].action .. ' ' .. got[1].key .. ' ' .. got[1].time,
     'key down ArrowLeft 1000', 'a key')
  eq(got[1].shift, true, 'shift')
  eq(got[1].ctrl, false, 'ctrl')
  eq(got[2].type .. ' ' .. got[2].action .. ' ' .. got[2].x .. ' ' .. got[2].y .. ' ' .. got[2].time,
     'pointer move 4 5 1001', 'the pointer, from 1')
  eq(got[3].type .. ' ' .. tostring(got[3].on) .. ' ' .. got[3].time, 'focus false 1002', 'focus')
  eq(got[4].action .. ' [' .. got[4].key .. '] ' .. got[4].time, 'up [ ] 4294967295',
     'the space key, at the last ms of the clock')
  for _ in vs1.events(c1, string.char(129, 255, 255, 0, 0, 1)) do error('a giant event') end
  eq(c1.vs1_in, '', 'a giant event drops the bytes')

  -- A fake clock for ces.spawn and ces.sleep.
  local now, sleepers = 0, {}
  local function wake(co, ...)
    local ok, at = coroutine.resume(co, ...)
    if not ok then error(at, 0) end
    if coroutine.status(co) ~= 'dead' then sleepers[#sleepers + 1] = {co = co, at = at} end
  end
  ces = {
    spawn = function(fn) wake(coroutine.create(fn)) end,
    sleep = function(ms) return coroutine.yield(now + ms) end,
  }
  local function advance(ms)
    local target = now + ms
    while true do
      table.sort(sleepers, function(p, q) return p.at < q.at end)
      local s = sleepers[1]
      if not s or s.at > target then break end
      table.remove(sleepers, 1)
      now = s.at
      wake(s.co)
    end
    now = target
  end
  local steps = {}
  local keys = vs1.keys(170, 50, function(c, k) steps[#steps + 1] = c.id .. k end)
  local function ev(action, k, time) return {type = 'key', action = action, key = k, time = time} end
  local c3 = {id = 3}

  keys:feed(c3, ev('down', 'a', 1000))
  keys:feed(c3, ev('up', 'a', 1040))
  eq(#steps, 1, 'a tap is one step')
  eq(steps[1], '3a', 'the step of the key of the viewer')
  advance(1000)
  eq(#steps, 1, 'nothing after a tap')
  eq(#sleepers, 0, 'nothing runs while no key is down')

  steps = {}
  keys:feed(c3, ev('down', 'b', 5000))
  eq(#steps, 1, 'a step at the key down')
  advance(169)
  eq(#steps, 1, 'no step before the delay')
  advance(1)
  eq(#steps, 2, 'a step at the delay')
  advance(100)
  eq(#steps, 4, 'a step each 50 ms')
  keys:feed(c3, ev('up', 'b', 5280))
  eq(#steps, 4, 'a hold of 280 ms earns 1 + ceil(110 / 50) = 4 steps')
  advance(500)
  eq(#steps, 4, 'the key up stops the steps')

  steps = {}
  keys:feed(c3, ev('down', 'c', 9000))
  keys:feed(c3, ev('up', 'c', 9300))
  eq(#steps, 4, 'a hold of 300 ms is 1 + ceil(130 / 50) = 4 steps')
  advance(1000)
  eq(#steps, 4, 'and no more')

  steps = {}
  keys:feed(c3, ev('down', 'd', 20000))
  keys:feed(c3, {type = 'focus', on = false, time = 20230})
  eq(#steps, 3, 'a hold of 230 ms is 1 + ceil(60 / 50) = 3 steps')
  advance(1000)
  eq(#steps, 3, 'and it stops')

  steps = {}
  keys:feed(c3, ev('down', 'e', 30000))
  keys:forget(c3)
  advance(1000)
  eq(#steps, 1, 'forget stops the steps')

  steps = {}
  keys:feed(c3, ev('down', 'f', 40000))
  keys:feed(c3, ev('repeat', 'f', 40050))
  keys:feed(c3, ev('down', 'f', 40060))
  keys:feed(c3, ev('up', 'f', 40100))
  eq(#steps, 1, 'only the first down steps')
  advance(1000)
  eq(#steps, 1, 'and nothing after it')

  keys:feed(c3, ev('repeat', 'g', 50000))
  keys:feed(c3, ev('up', 'g', 50400))
  advance(1000)
  eq(#steps, 1, 'a repeat with no down makes no step')
  eq(#sleepers, 0, 'nothing runs at the end')
  ces = real

  -- The sandbox has no collectgarbage, so many screens make the collector run.
  local probe = setmetatable({}, {__mode = 'v'})
  probe[1] = vs1.new(1, 1)
  for _ = 1, 20000 do vs1.new(1, 1) end
  eq(probe[1], nil, 'a screen that nobody holds goes')

  local before = c1.writes
  vs1.fault('boom')
  eq(vs1.crashed, 'boom', 'the error')
  eq(c1.writes, before + 1, 'one write for the viewer')
  eq(c1.last:byte(1), 2, 'a frame, with no mode')
  local cell, title = a.cells[1][1], a.name
  a:write(1, 1, 'zz')
  a:clear()
  a:title('new')
  eq(a.cells[1][1], cell, 'no change after a failure')
  eq(a.name, title, 'and no new title')
  vs1.fault('again')
  eq(vs1.crashed, 'boom', 'the first error stays')
end
local ok, err = pcall(checks)
ces = real
ces.conn.set_listener({ on_open = function(c)
  c:write(ok and 'vs1 checks ok\n' or ('vs1 checks failed: ' .. tostring(err) .. '\n'))
end })
ces.run()
)LUA");
  BOOST_REQUIRE(waitInstanceListening(*server, pid));
  const std::string out = dial(pid);
  BOOST_CHECK_MESSAGE(out == "vs1 checks ok\n", out);
  kill(pid);
}

BOOST_AUTO_TEST_CASE(AViewerSeesTheScreen) {
  deployFromRepo("vs1/vs1.lua");
  uint64_t pid = launch("screen.lua", R"LUA(
local vs1 = ces.load('vs1/vs1.lua')
local s = vs1.new(12, 4)
s:title('demo')
s:write(2, 1, 'hello')
s:color(0xffcc00, 0x101020)
s:write(1, 2, '\195\169\226\150\136')
s:color(0xaaaaaa, 0)
s:put(12, 4, 0x2588)
s:write(10, 3, 'wxyz')
s:fill(1, 4, 2, 1, '#')
s:blit(5, 3, {'ab', 'cd'})
ces.conn.set_listener({ on_open = function(c) s:ship(c) end })
ces.run()
)LUA");
  BOOST_REQUIRE(waitInstanceListening(*server, pid));
  const Monitor m(dial(pid));
  BOOST_REQUIRE_MESSAGE(m.error.empty(), m.error);
  BOOST_CHECK((m.kinds == std::vector<int>{1, 3, 2}));
  BOOST_CHECK_EQUAL(m.cols, 12);
  BOOST_CHECK_EQUAL(m.rows, 4);
  BOOST_CHECK_EQUAL(m.title, "demo");
  BOOST_CHECK_EQUAL(m.row(1), " hello");
  BOOST_CHECK_EQUAL(m.row(2), "\xc3\xa9\xe2\x96\x88");
  BOOST_CHECK_EQUAL(m.row(3), "    ab   wxy");
  BOOST_CHECK_EQUAL(m.row(4), "##  cd     \xe2\x96\x88");
  BOOST_CHECK((m.cell(1, 2) == Monitor::Cell{0xe9, 0xffcc00, 0x101020}));
  BOOST_CHECK((m.cell(2, 2) == Monitor::Cell{0x2588, 0xffcc00, 0x101020}));
  BOOST_CHECK((m.cell(12, 4) == Monitor::Cell{0x2588, 0xaaaaaa, 0}));
  BOOST_CHECK_EQUAL(m.frameCells, 17u);
  kill(pid);
}

BOOST_AUTO_TEST_CASE(EventsFromTheWire) {
  deployFromRepo("vs1/vs1.lua");
  uint64_t pid = launch("events.lua", R"LUA(
local vs1 = ces.load('vs1/vs1.lua')
ces.conn.set_listener({ on_data = function(c, d)
  for e in vs1.events(c, d) do
    local mods = (e.shift and 'S' or '') .. (e.ctrl and 'C' or '') .. (e.alt and 'A' or '') .. (e.meta and 'M' or '')
    if e.type == 'key' then
      c:write('key ' .. e.action .. ' [' .. e.key .. '] ' .. mods .. ' ' .. e.time .. '\n')
    elseif e.type == 'pointer' then
      c:write('pointer ' .. e.action .. ' ' .. e.button .. ' ' .. e.x .. ' ' .. e.y .. ' ' .. e.time .. '\n')
    elseif e.type == 'text' then
      c:write('text [' .. e.text .. ']\n')
    else
      c:write('focus ' .. tostring(e.on) .. ' ' .. e.time .. '\n')
    end
  end
end })
ces.run()
)LUA");
  BOOST_REQUIRE(waitInstanceListening(*server, pid));
  const std::string out = dial(pid, key(1, 1, 1000, "ArrowLeft") + key(3, 0, 1001, "a") +
                                    key(2, 2 | 8, 4294967295u, " ") + key(1, 4, 7, "\xc3\xa7") +
                                    pointer(1, 2, 0, 0, 8) + pointer(3, 0, 79, 24, 9) +
                                    pointer(2, 1, 1, 2, 12) + text("ls -l\n\xc3\xa7") + focus(false, 10) +
                                    focus(true, 11));
  BOOST_CHECK_EQUAL(out,
                    "key down [ArrowLeft] S 1000\n"
                    "key repeat [a]  1001\n"
                    "key up [ ] CM 4294967295\n"
                    "key down [\xc3\xa7] A 7\n"
                    "pointer down 2 1 1 8\n"
                    "pointer move 0 80 25 9\n"
                    "pointer up 1 2 3 12\n"
                    "text [ls -l\n\xc3\xa7]\n"
                    "focus false 10\n"
                    "focus true 11\n");
  kill(pid);
}

BOOST_AUTO_TEST_CASE(KeysMakeSteps) {
  deployFromRepo("vs1/vs1.lua");
  uint64_t pid = launch("keys.lua", R"LUA(
local vs1 = ces.load('vs1/vs1.lua')
local s = vs1.new(20, 1)
local n = {a = 0, b = 0, c = 0}
local function show(c)
  s:write(1, 1, 'a' .. n.a .. ' b' .. n.b .. ' c' .. n.c)
  s:ship(c)
end
local keys = vs1.keys(170, 50, function(c, k)
  n[k] = n[k] + 1
  show(c)
end)
ces.conn.set_listener({
  on_open = show,
  on_data = function(c, d) for e in vs1.events(c, d) do keys:feed(c, e) end end,
  on_close = function(c) s:forget(c); keys:forget(c) end,
})
ces.run()
)LUA");
  BOOST_REQUIRE(waitInstanceListening(*server, pid));
  const Monitor m(dial(pid, key(1, 0, 1000, "a") + key(2, 0, 1040, "a") + key(1, 0, 5000, "b") +
                                key(2, 0, 5280, "b") + key(3, 0, 6000, "c") + key(2, 0, 6400, "c")));
  BOOST_REQUIRE_MESSAGE(m.error.empty(), m.error);
  BOOST_CHECK_EQUAL(m.row(1), "a1 b4 c0");
  kill(pid);
}

BOOST_AUTO_TEST_CASE(ACrashShowsTheErrorOverTheLastFrame) {
  deployFromRepo("vs1/vs1.lua");
  const std::string src = R"LUA(
local vs1 = ces.load('vs1/vs1.lua')
local s = vs1.new(30, 6)
s:title('crash')
s:write(1, 4, 'HELLO')
local ticks = 0
ces.every(50, function() ticks = ticks + 1; s:write(1, 6, 'tick ' .. ticks) end)
ces.conn.set_listener({
  on_open = function(c) s:ship(c) end,
  on_data = function(c, d)
    for e in vs1.events(c, d) do
      if e.type == 'key' then error('bad key ' .. e.key) end
    end
  end,
  on_close = function(c) s:forget(c) end,
})
ces.run()
)LUA";
  const std::string err =
    "program:" + std::to_string(lineOf(src, "error('bad key")) + ": bad key q";
  uint64_t pid = launch("crash.lua", src);
  BOOST_REQUIRE(waitInstanceListening(*server, pid));

  const Monitor first(dial(pid, key(1, 0, 1, "q")));
  BOOST_REQUIRE_MESSAGE(first.error.empty(), first.error);
  BOOST_CHECK((first.kinds == std::vector<int>{1, 3, 2, 2}));
  BOOST_CHECK_EQUAL(first.row(1), err);
  BOOST_CHECK_EQUAL(first.row(4), "HELLO");
  BOOST_CHECK_EQUAL(first.title, "crash");

  const Monitor later(dial(pid));
  BOOST_REQUIRE_MESSAGE(later.error.empty(), later.error);
  BOOST_CHECK((later.kinds == std::vector<int>{1, 3, 2}));
  BOOST_CHECK_EQUAL(later.row(1), err);
  BOOST_CHECK_EQUAL(later.row(4), "HELLO");
  BOOST_CHECK(later.row(6).rfind("tick ", 0) == 0);

  const Monitor last(dial(pid, key(1, 0, 2, "z")));
  BOOST_REQUIRE_MESSAGE(last.error.empty(), last.error);
  BOOST_CHECK((last.kinds == std::vector<int>{1, 3, 2}));
  BOOST_CHECK(last.cells == later.cells);
  BOOST_CHECK(waitInstanceListening(*server, pid));
  kill(pid);
}

BOOST_AUTO_TEST_CASE(ACrashBeforeAScreen) {
  deployFromRepo("vs1/vs1.lua");
  uint64_t pid = launch("early.lua", "local vs1 = ces.load('vs1/vs1.lua')\nlocal t = nil\nt.x = 1\n");
  BOOST_REQUIRE(waitInstanceListening(*server, pid));
  const Monitor m(dial(pid));
  BOOST_REQUIRE_MESSAGE(m.error.empty(), m.error);
  BOOST_CHECK_EQUAL(m.cols, 80);
  BOOST_CHECK_EQUAL(m.rows, 25);
  BOOST_CHECK_MESSAGE(m.row(1).rfind("program:3: attempt to index", 0) == 0, m.row(1));
  kill(pid);
}

// The viewer saw the first-made screen last, so a fault that ships screens in
// the order they were made ends on the wrong one.
BOOST_AUTO_TEST_CASE(AViewerKeepsTheScreenThatItSawLast) {
  deployFromRepo("vs1/vs1.lua");
  uint64_t pid = launch("two.lua", R"LUA(
local vs1 = ces.load('vs1/vs1.lua')
local a = vs1.new(10, 2)
a:write(1, 2, 'screen a')
local b = vs1.new(20, 3)
b:write(1, 3, 'screen b')
ces.conn.set_listener({
  on_open = function(c) b:ship(c); a:ship(c) end,
  on_data = function(c, d) error('x', 0) end,
})
ces.run()
)LUA");
  BOOST_REQUIRE(waitInstanceListening(*server, pid));
  const Monitor m(dial(pid, "k"));
  BOOST_REQUIRE_MESSAGE(m.error.empty(), m.error);
  BOOST_CHECK_EQUAL(m.cols, 10);
  BOOST_CHECK_EQUAL(m.row(1), "x");
  BOOST_CHECK_EQUAL(m.row(2), "screen a");
  const Monitor later(dial(pid));
  BOOST_REQUIRE_MESSAGE(later.error.empty(), later.error);
  BOOST_CHECK_EQUAL(later.cols, 10);
  BOOST_CHECK_EQUAL(later.row(2), "screen a");
  kill(pid);
}

BOOST_AUTO_TEST_CASE(AHandlerOfTheProgramReplacesTheOneOfVs1) {
  deployFromRepo("vs1/vs1.lua");
  uint64_t pid = launch("handler.lua", R"LUA(
local vs1 = ces.load('vs1/vs1.lua')
local s = vs1.new(10, 4)
s:write(1, 4, 'four')
ces.on_error(function(e) vs1.fault('ab\tcdefghijk\nxy') end)
ces.conn.set_listener({
  on_open = function(c) s:ship(c) end,
  on_data = function(c, d) error('x') end,
})
ces.run()
)LUA");
  BOOST_REQUIRE(waitInstanceListening(*server, pid));
  const Monitor m(dial(pid, "k"));
  BOOST_REQUIRE_MESSAGE(m.error.empty(), m.error);
  BOOST_CHECK_EQUAL(m.row(1), "ab cdefghi");
  BOOST_CHECK_EQUAL(m.row(2), "jk");
  BOOST_CHECK_EQUAL(m.row(3), "xy");
  BOOST_CHECK_EQUAL(m.row(4), "four");
  kill(pid);
}

BOOST_AUTO_TEST_SUITE_END()
