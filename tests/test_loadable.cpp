// Tests of ces.load.

#define BOOST_TEST_DYN_LINK
#include "test_loadable_common.h"

#include <ces/l2/loadable.h>

#include <algorithm>
#include <string>
#include <vector>

using namespace ces;

namespace {

void has(const std::string& out, const std::string& what) {
  BOOST_CHECK_MESSAGE(out.find(what) != std::string::npos, "no [" << what << "] in [" << out << "]");
}

}  // namespace

BOOST_AUTO_TEST_SUITE(LoadableTests)

BOOST_AUTO_TEST_CASE(PathRule) {
  for (const char* p : {"vs1/vs1.lua", "a.lua", "a", "A-b_c.9/d.e.lua", "x/y/z/w.lua", "a./b"})
    BOOST_CHECK_MESSAGE(isLoadablePath(p), "refused [" << p << "]");
  for (const char* p : {"", "/vs1.lua", "./vs1.lua", "../vs1.lua", "a/../b.lua", "a/./b.lua",
                        "a//b.lua", "a/", ".", "..", "vs1/.vs1.lua", ".a", "a b.lua", "a\\b.lua",
                        "a:b", "a*", "\xc3\xa9.lua", "~/a.lua"})
    BOOST_CHECK_MESSAGE(!isLoadablePath(p), "took [" << p << "]");
  BOOST_CHECK(!isLoadablePath(std::string_view("a\0b", 3)));
  BOOST_CHECK(isLoadablePath(std::string(kLoadablePathMax, 'a')));
  BOOST_CHECK(!isLoadablePath(std::string(kLoadablePathMax + 1, 'a')));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(LoadableE2E, loadtest::LoadableFixture)

BOOST_AUTO_TEST_CASE(WhatALoadGivesAProgram) {
  deploy("t/count.lua", "runs = (runs or 0) + 1\nreturn {n = runs}\n");
  deploy("t/inner.lua", "return {count = ces.load('t/count.lua')}\n");
  deploy("t/none.lua", "local x = 1\n");
  deploy("t/false.lua", "return false\n");
  deploy("t/globals.lua", "shared = 'from the loadable'\nreturn program_global\n");
  deploy("t/syntax.lua", "local = 1\n");
  deploy("t/fails.lua", "tries = (tries or 0) + 1\nerror('no ' .. tries)\n");
  // No tail calls, which drop the chunk's position from errors.
  deploy("t/self.lua", "local m = ces.load('t/self.lua')\nreturn m\n");
  deploy("t/a.lua", "local m = ces.load('t/b.lua')\nreturn m\n");
  deploy("t/b.lua", "local m = ces.load('t/a.lua')\nreturn m\n");
  deploy("t/bytecode.lua", std::string("\x1bLJ\x02junk", 8));
  deploy("t/.hidden.lua", "return 'hidden'\n");
  deploy("t/task.lua", "return 'in a task'\n");
  const std::string head = "return 'max'\n--";
  deploy("t/max.lua", head + std::string(kLoadableMaxBytes - head.size(), 'x'));
  deploy("t/big.lua", head + std::string(kLoadableMaxBytes + 1 - head.size(), 'x'));
  fs::create_directories(treeFile("t/dir.lua"));
  loadtest::writeBytes(storeDir() / "s" / "outside.lua", "return 'outside'\n");

  const std::string src = R"LUA(
local lines = {}
local function say(s) lines[#lines + 1] = s end
local function try(path)
  local ok, v = pcall(ces.load, path)
  return (ok and '= ' or '! ') .. tostring(v)
end
local a, b = ces.load('t/count.lua'), ces.load('t/count.lua')
say('once ' .. tostring(a == b) .. ' ' .. a.n .. ' ' .. runs)
say('inner ' .. tostring(ces.load('t/inner.lua').count == a))
say('none ' .. try('t/none.lua'))
say('false ' .. try('t/false.lua') .. ' ' .. try('t/false.lua'))
program_global = 'from the program'
say('globals ' .. try('t/globals.lua') .. ' ' .. tostring(shared))
say('missing ' .. try('t/missing.lua'))
say('dir ' .. try('t/dir.lua'))
say('syntax ' .. try('t/syntax.lua'))
say('fails ' .. try('t/fails.lua') .. ' ' .. try('t/fails.lua'))
say('self ' .. try('t/self.lua'))
say('cycle ' .. try('t/a.lua'))
say('bytecode ' .. try('t/bytecode.lua'))
say('max ' .. try('t/max.lua'))
say('big ' .. try('t/big.lua'))
for _, p in ipairs({'/t/count.lua', './t/count.lua', '../outside.lua', 't/../t/count.lua',
                    't//count.lua', 't/.hidden.lua', ''}) do
  say('path [' .. p .. '] ' .. try(p))
end
say('number ' .. try(42))
local _, e = pcall(function() ces.load('t/missing.lua') end)
say('where ' .. e)
ces.spawn(function()
  local info
  ces.spawn(function() info = ces.server_info() or 'none' end)
  ces.sleep(0)
  say('task ' .. try('t/task.lua'))
  while not info do ces.sleep(10) end
  say('info ' .. type(info))
  local report = table.concat(lines, '\n') .. '\nend\n'
  ces.conn.set_listener({ on_open = function(c) c:write(report) end })
end)
ces.run()
)LUA";
  const std::string where = "pcall(function() ces.load('t/missing.lua') end)";
  const size_t line = 1 + std::count(src.begin(), src.begin() + src.find(where), '\n');
  uint64_t pid = launch("load.lua", src);
  BOOST_REQUIRE(waitInstanceListening(*server, pid));
  const std::string out = dial(pid);
  has(out, "once true 1 1\n");
  has(out, "inner true\n");
  has(out, "none = true\n");
  has(out, "false = false = false\n");
  has(out, "globals = from the program from the loadable\n");
  has(out, "missing ! ces.load: no loadable t/missing.lua\n");
  has(out, "dir ! ces.load: no loadable t/dir.lua\n");
  has(out, "syntax ! ces.load: t/syntax.lua:1: ");
  has(out, "fails ! t/fails.lua:2: no 1 ! t/fails.lua:2: no 2\n");
  has(out, "self ! t/self.lua:1: ces.load: t/self.lua is loading");
  has(out, "cycle ! t/b.lua:1: ces.load: t/a.lua is loading");
  has(out, "bytecode ! ces.load: t/bytecode.lua is bytecode, not Lua text\n");
  has(out, "max = max\n");
  has(out, "big ! ces.load: t/big.lua is bigger than 1048576 bytes\n");
  for (const char* p : {"/t/count.lua", "./t/count.lua", "../outside.lua", "t/../t/count.lua",
                        "t//count.lua", "t/.hidden.lua", ""})
    has(out, std::string("path [") + p + "] ! ces.load: not a path of a loadable: " + p + "\n");
  has(out, "number ! ces.load: the path is not a string\n");
  has(out, "where program:" + std::to_string(line) + ": ces.load: no loadable t/missing.lua\n");
  has(out, "task = in a task\n");
  has(out, "info table\n");
  has(out, "end\n");
  kill(pid);
}

BOOST_AUTO_TEST_CASE(AnErrorOfALoadIsAnErrorOfTheProgram) {
  deploy("t/fails.lua", "error('broken')\n");
  BOOST_CHECK(waitInstanceGone(*server, launch("plain.lua", "ces.load('t/fails.lua')\nces.run()\n")));
  BOOST_CHECK(waitInstanceGone(*server, launch("gone.lua", "ces.load('t/gone.lua')\nces.run()\n")));
  uint64_t pid = launch("caught.lua",
    "ces.on_error(function(e)\n"
    "  ces.conn.set_listener({ on_open = function(c) c:write('caught ' .. e .. '\\n') end })\n"
    "end)\n"
    "ces.load('t/fails.lua')\n");
  BOOST_REQUIRE(waitInstanceListening(*server, pid));
  has(dial(pid), "caught t/fails.lua:1: broken\n");
  kill(pid);
}

BOOST_AUTO_TEST_CASE(ALoadableIsAFileOfS) {
  deploy("t/copied.lua", "return 'copied'\n");
  auto sc = fileClient(serverKey);
  const std::string text = "return 'put'\n";
  uint64_t bal = 0, cost = 0;
  CES_REQUIRE_OK(sc->create("/s/loadables/t/put.lua", text.size(), 0, 0, bal, cost));
  ces::Bytes bytes(text.begin(), text.end());
  CES_REQUIRE_OK(sc->write("/s/loadables/t/put.lua", 0, bytes, bal));

  auto oc = fileClient(ownerKey);
  CesFileClient::StatInfo si;
  CES_REQUIRE_OK(oc->stat("/s/loadables/t/copied.lua", si));
  ces::Bytes data;
  minx::Hash hash;
  CES_REQUIRE_OK(oc->read("/s/loadables/t/copied.lua", 0, si.size, data, hash));
  BOOST_CHECK_EQUAL(std::string(data.begin(), data.end()), "return 'copied'\n");

  uint64_t pid = launch("m.lua",
    "local a, b = ces.load('t/copied.lua'), ces.load('t/put.lua')\n"
    "ces.conn.set_listener({ on_open = function(c) c:write(a .. ' ' .. b .. '\\n') end })\n"
    "ces.run()\n");
  BOOST_REQUIRE(waitInstanceListening(*server, pid));
  has(dial(pid), "copied put\n");
  kill(pid);
}

BOOST_AUTO_TEST_SUITE_END()
