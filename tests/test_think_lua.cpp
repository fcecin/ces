// builtin:think from real Lua programs (cesluajitd), with a scripted backend
// (no network). ces.think is the host call: it bills the file's program
// account and streams pieces into on_piece. ces.think_client is the CesPlex
// client: the program dials a server as its own account. Each program reports
// through transfers to a beacon account that the test polls. The program
// account is also the file's balance, and slot rent drains it while the
// instance runs, so the tests prove who pays by refusal (a rich owner does
// not help a poor program) and by the owner's balance not moving.

#include "test_common.h"
#include "test_compute_wait.h"
#include "test_e2e_common.h"   // ces::e2e::findBinary

#include <ces/account.h>
#include <ces/client.h>
#include <ces/keys.h>
#include <ces/server.h>
#include <ces/l2/compute_client.h>
#include <ces/l2/file_client.h>
#include <ces/l2/file_handler.h>
#include <ces/l2/think_backend.h>
#include <ces/l2/think_handler.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace ces;

namespace {

std::string luaBytes(const uint8_t* p, size_t n) {
  std::string s;
  char buf[8];
  for (size_t i = 0; i < n; i++) {
    std::snprintf(buf, sizeof(buf), "\\%03u", static_cast<unsigned>(p[i]));
    s += buf;
  }
  return s;
}

// Replies "Hello, world." in three pieces with fixed usage, or fails after
// the pieces with `status`. With `block` it waits for `release` (or stop)
// before the first piece.
struct LuaScriptBackend : ThinkBackend {
  uint8_t status = CES_OK;
  std::atomic<int> calls{0};
  std::atomic<bool> block{false};
  std::atomic<bool> release{false};
  std::atomic<bool> entered{false};
  ThinkOutcome run(const std::string&, uint32_t,
                   const std::atomic<bool>& stop,
                   const std::function<bool(std::string_view)>& onText)
      override {
    ++calls;
    entered = true;
    while (block.load() && !release.load() && !stop.load())
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    ThinkOutcome o;
    for (const char* p : {"Hel", "lo, ", "world."}) {
      if (!onText(p)) {
        o.status = CES_ERROR_INTERNAL;
        o.billing = ThinkOutcome::kEstimate;
        return o;
      }
    }
    o.status = status;
    o.billing = status == CES_OK ? ThinkOutcome::kUsage : ThinkOutcome::kNone;
    o.usage = ThinkUsage{100, 40, 3};
    return o;
  }
};

constexpr uint64_t kFeeIn = 1'000'000;        // 1 per input token
constexpr uint64_t kFeeCachedIn = 100'000;    // 0.1 per cached input token
constexpr uint64_t kFeeOut = 2'000'000;       // 2 per output token
constexpr uint32_t kMaxOut = 1000;
const ThinkFees kFees{kFeeIn, kFeeCachedIn, kFeeOut};
const uint64_t kCost = thinkCost(kFees, ThinkUsage{100, 40, 3});   // 70

struct ThinkLuaFixture {
  fs::path dir;
  std::unique_ptr<CesServer> server;
  std::unique_ptr<CesClient> client;
  uint16_t rpcPort = 0;
  KeyPair ownerKey;
  KeyPair beacon;
  std::shared_ptr<LuaScriptBackend> backend =
      std::make_shared<LuaScriptBackend>();

  explicit ThinkLuaFixture(bool mountThink = true,
                           uint32_t maxOut = kMaxOut) {
    blog::init();
    blog::set_level(blog::fatal);
    dir = makeUniqueTempDir("thinklua");
    minx::Hash priv;
    priv.fill(0xD7);
    CesConfig cfg =
      makeTestConfig(dir, priv, std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = {
      {"/ces/file/1",    "builtin:file"},
      {"/ces/compute/1", "builtin:compute"},
    };
    if (mountThink) cfg.cesplexMounts["/ces/think/1"] = "builtin:think";
    cfg.cesFileStoreMaxBytes = 16ull * 1024 * 1024;
    cfg.feeFileRent = 1;
    cfg.computeMaxInstances = 8;
    cfg.computePortBase = findFreeUdpPortRange(16);
    cfg.computePortCount = 16;
    cfg.feeComputeSlotSec = 1;
    cfg.cesComputeChildBinary = ces::e2e::findBinary("cesluajitd");
    cfg.cesComputeWorkDir = (dir / "cescompute").string();
    cfg.thinkFeeIn = kFeeIn;
    cfg.thinkFeeCachedIn = kFeeCachedIn;
    cfg.thinkFeeOut = kFeeOut;
    cfg.thinkMaxOutTokens = maxOut;

    server = std::make_unique<CesServer>(cfg);
    uint16_t mainPort = server->start(0);
    rpcPort = server->_rpcBoundPort();
    if (mountThink) {
      BOOST_REQUIRE(server->thinkHandler() != nullptr);
      server->thinkHandler()->_testSetBackend(backend);
    }
    server->_brr(ownerKey.getPublicKeyAsHash(), 100'000'000'000);
    server->_brr(beacon.getPublicKeyAsHash(), 1);

    boost::asio::ip::udp::endpoint ep(
      boost::asio::ip::address_v6::loopback(), mainPort);
    client = std::make_unique<CesClient>(ep, false);
    client->start(0);
    client->setKey(ownerKey);
    client->connect();
    // _brr lands on the logic strand; wait for the funds.
    BOOST_REQUIRE(waitUntil([&] {
      return balanceOf(ownerKey.getPublicKeyAsHash()) > 0 &&
             balanceOf(beacon.getPublicKeyAsHash()) == 1;
    }));
  }

  ~ThinkLuaFixture() {
    backend->release = true;
    if (client) client->stop();
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    boost::system::error_code ec;
    fs::remove_all(dir, ec);
  }

  minx::Hash deploy(const std::string& path, const std::string& src,
                    uint64_t deposit = 10'000'000'000) {
    CesFileClient fc;
    fc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(fc.connect("localhost", rpcPort, ownerKey));
    uint64_t fb = 0, cost = 0;
    CES_REQUIRE_OK(fc.create(path, src.size(), 0, deposit, fb, cost));
    ces::Bytes content(src.begin(), src.end());
    CES_REQUIRE_OK(fc.write(path, 0, content, fb));
    fc.disconnect();
    std::array<uint8_t, 32> pk{};
    BOOST_REQUIRE(server->fileHandler()->readProgramPubkey(path, pk));
    minx::Hash h;
    std::memcpy(h.data(), pk.data(), 32);
    return h;
  }

  void launch(const std::string& path) {
    CesComputeClient cc;
    cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));
    uint64_t id = 0, st = 0;
    CES_REQUIRE_OK(cc.launch(path, id, st));
    cc.disconnect();
  }

  int64_t balanceOf(const minx::Hash& pk) {
    int64_t bal = 0;
    uint32_t nonce = 0;
    client->queryAccount(Account::getMapKey(pk), bal, nonce);
    return bal;
  }

  // Wait for the beacon to leave 1; return the code the program sent (0 =
  // none within the limit).
  int64_t beaconCode(const KeyPair& b,
                     std::chrono::steady_clock::duration limit = kTestWaitLimit) {
    const auto pk = b.getPublicKeyAsHash();
    int64_t bal = 1;
    waitUntil([&] { bal = balanceOf(pk); return bal != 1; }, limit);
    return bal - 1;
  }
  int64_t beaconCode() { return beaconCode(beacon); }
  bool waitEntered() {
    return waitUntil([&] { return backend->entered.load(); });
  }
  bool fileExists(const std::string& p) {
    std::array<uint8_t, 32> pk{};
    return server->fileHandler()->readProgramPubkey(p, pk);
  }

  std::string getFile(const std::string& p) {
    CesFileClient fc;
    fc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    if (fc.connect("localhost", rpcPort, ownerKey) != CES_OK) return "<err>";
    CesFileClient::StatInfo st{};
    if (fc.stat(p, st) != CES_OK) return "<err>";
    ces::Bytes out;
    minx::Hash h;
    if (st.size > 0 &&
        fc.read(p, 0, static_cast<uint32_t>(st.size), out, h) != CES_OK)
      return "<err>";
    return std::string(out.begin(), out.end());
  }

  std::string path(const char* name) {
    return "/h/" + ownerKey.getPublicKeyHexStr() + "/" + name;
  }
  std::string B() {
    return "local B = '" + luaBytes(beacon.getPublicKeyAsHash().data(), 32) +
           "'\n";
  }
  std::string B2(const KeyPair& b) {
    return "local B2 = '" + luaBytes(b.getPublicKeyAsHash().data(), 32) +
           "'\n";
  }
};

struct ThinkLuaNoMountFixture : ThinkLuaFixture {
  ThinkLuaNoMountFixture() : ThinkLuaFixture(false) {}
};
// A hold of about 8e9 raw units: more than a 1e9 deposit covers.
struct ThinkLuaBigHoldFixture : ThinkLuaFixture {
  ThinkLuaBigHoldFixture() : ThinkLuaFixture(true, 4'000'000'000u) {}
};

}  // namespace

BOOST_AUTO_TEST_SUITE(ThinkLuaTests)

// ces.think in a coroutine: the pieces reach on_piece in order, the reply
// and the charge come back, and the PROGRAM account pays exactly the usage
// cost. 77 = all checks passed.
BOOST_FIXTURE_TEST_CASE(HostThink_CoroutineStreamsAndBillsProgram,
                        ThinkLuaFixture) {
  const std::string src = B() +
    "ces.spawn(function()\n"
    "  local got = {}\n"
    "  local r, c = ces.think('hi there', function(p) got[#got + 1] = p end)\n"
    "  if r ~= 'Hello, world.' then ces.transfer(B, 2); return end\n"
    "  if #got ~= 3 or got[1] ~= 'Hel' or got[3] ~= 'world.' then\n"
    "    ces.transfer(B, 3); return end\n"
    "  if c ~= " + std::to_string(kCost) + " then ces.transfer(B, 4); return end\n"
    "  ces.transfer(B, 77)\n"
    "end)\n"
    "ces.run()\n";
  deploy(path("t1.lua"), src);
  launch(path("t1.lua"));
  const int64_t ownerAfterLaunch = balanceOf(ownerKey.getPublicKeyAsHash());
  BOOST_CHECK_EQUAL(beaconCode(), 77);
  BOOST_CHECK_EQUAL(backend->calls.load(), 1);
  // The owner launched it but does not pay for the thinking.
  BOOST_CHECK_EQUAL(balanceOf(ownerKey.getPublicKeyAsHash()), ownerAfterLaunch);
}

// ces.think in the main chunk blocks, and on_piece still runs per piece.
BOOST_FIXTURE_TEST_CASE(HostThink_MainChunkBlocks, ThinkLuaFixture) {
  const std::string src = B() +
    "local n = 0\n"
    "local r, c = ces.think('hi', function(p) n = n + 1 end)\n"
    "if r ~= 'Hello, world.' then ces.transfer(B, 2); return end\n"
    "if n ~= 3 then ces.transfer(B, 3); return end\n"
    "ces.transfer(B, 77)\n";
  deploy(path("t2.lua"), src);
  launch(path("t2.lua"));
  BOOST_CHECK_EQUAL(beaconCode(), 77);
}

// A program whose own account cannot cover the hold is refused, even though
// its owner is rich: the program can only spend its own account.
BOOST_FIXTURE_TEST_CASE(HostThink_OnlyProgramAccountPays,
                        ThinkLuaBigHoldFixture) {
  const std::string src = B() +
    "local r, rc = ces.think('hi')\n"
    "if r == nil and rc == ces.err.INSUFFICIENT_BALANCE then\n"
    "  ces.transfer(B, 77) else ces.transfer(B, 2) end\n";
  deploy(path("t3.lua"), src, 1'000'000'000);
  launch(path("t3.lua"));
  const int64_t ownerAfterLaunch = balanceOf(ownerKey.getPublicKeyAsHash());
  BOOST_REQUIRE_GT(ownerAfterLaunch, 8'000'000'000);   // owner could pay
  BOOST_CHECK_EQUAL(beaconCode(), 77);
  BOOST_CHECK_EQUAL(backend->calls.load(), 0);
  BOOST_CHECK_EQUAL(balanceOf(ownerKey.getPublicKeyAsHash()), ownerAfterLaunch);
}

// A backend failure returns nil, rc and the partial reply, and a call with
// no billable work costs nothing.
BOOST_FIXTURE_TEST_CASE(HostThink_FailureGivesPartial, ThinkLuaFixture) {
  backend->status = CES_ERROR_TIMEOUT;
  const std::string src = B() +
    "ces.spawn(function()\n"
    "  local r, rc, part = ces.think('hi')\n"
    "  if r == nil and rc == ces.err.TIMEOUT and part == 'Hello, world.' then\n"
    "    ces.transfer(B, 77) else ces.transfer(B, 2) end\n"
    "end)\n"
    "ces.run()\n";
  deploy(path("t4.lua"), src);
  launch(path("t4.lua"));
  BOOST_CHECK_EQUAL(beaconCode(), 77);
}

// Bad arguments are refused in the child, before any IPC.
BOOST_FIXTURE_TEST_CASE(HostThink_EmptyPromptRefused, ThinkLuaFixture) {
  const std::string src = B() +
    "local r, err = ces.think('')\n"
    "if r == nil and type(err) == 'string' then ces.transfer(B, 77)\n"
    "else ces.transfer(B, 2) end\n";
  deploy(path("t5.lua"), src);
  launch(path("t5.lua"));
  BOOST_CHECK_EQUAL(beaconCode(), 77);
  BOOST_CHECK_EQUAL(backend->calls.load(), 0);
}

// ces.think with a conversation file: the program acts as its owner, so the
// owner's file is context and grows by the prompt and the reply.
BOOST_FIXTURE_TEST_CASE(HostThink_ConversationFile, ThinkLuaFixture) {
  const std::string chat = path("chat.txt");
  deploy(chat, "og|");
  const std::string src = B() +
    "ces.spawn(function()\n"
    "  local r, c, append_error = ces.think('hi!', nil, '" + chat + "')\n"
    "  if r == 'Hello, world.' and append_error == ces.err.OK then ces.transfer(B, 77)\n"
    "  else ces.transfer(B, 2) end\n"
    "end)\n"
    "ces.run()\n";
  deploy(path("t8.lua"), src);
  launch(path("t8.lua"));
  BOOST_CHECK_EQUAL(beaconCode(), 77);
  BOOST_CHECK_EQUAL(getFile(chat), "og|hi!Hello, world.");
}

// ces.think_client: the program dials its own server's /ces/think/1 as its
// program account, and that account pays.
BOOST_FIXTURE_TEST_CASE(ThinkClient_FromCoroutine, ThinkLuaFixture) {
  const auto serverPk = server->_serverKeyPair().getPublicKeyAsHash();
  const std::string src = B() +
    "ces.spawn(function()\n"
    "  local tc = ces.think_client('127.0.0.1:" + std::to_string(rpcPort) +
      "', '" + luaBytes(serverPk.data(), 32) + "')\n"
    "  if not tc then ces.transfer(B, 2); return end\n"
    "  local r, c = tc:think('hi')\n"
    "  tc:close()\n"
    "  if r ~= 'Hello, world.' then ces.transfer(B, 3); return end\n"
    "  if c ~= " + std::to_string(kCost) + " then ces.transfer(B, 4); return end\n"
    "  ces.transfer(B, 77)\n"
    "end)\n"
    "ces.run()\n";
  deploy(path("t6.lua"), src);
  launch(path("t6.lua"));
  const int64_t ownerAfterLaunch = balanceOf(ownerKey.getPublicKeyAsHash());
  const int64_t code = beaconCode();
  // This test failed on CI with code 0 (the program sent nothing in 60 s).
  // The backend's call count tells which half stalled: 0 means the THINK
  // never reached the server, 1 means its reply never reached the program.
  BOOST_CHECK_MESSAGE(code == 77, "beacon code " << code << ", backend calls "
                                  << backend->calls.load() << ", backend entered "
                                  << backend->entered.load());
  BOOST_CHECK_EQUAL(balanceOf(ownerKey.getPublicKeyAsHash()), ownerAfterLaunch);
}

// A charge that falls due during a ces.think call, and that the account can
// pay only with the credits on hold, does not delete the file. The hold is
// about 8e9 of a 9e9 deposit, so the free balance is about 1e9.
BOOST_FIXTURE_TEST_CASE(HostThink_HoldDoesNotExhaustTheFile,
                        ThinkLuaBigHoldFixture) {
  backend->block = true;
  const std::string p = path("t9.lua");
  const std::string src = B() +
    "ces.spawn(function()\n"
    "  local r = ces.think('hi')\n"
    "  if r == 'Hello, world.' then ces.transfer(B, 77)\n"
    "  else ces.transfer(B, 2) end\n"
    "end)\n"
    "ces.run()\n";
  deploy(p, src, 9'000'000'000);
  launch(p);
  BOOST_REQUIRE(waitEntered());
  BOOST_CHECK(!server->fileHandler()->debitBalance(p, 2'000'000'000));
  BOOST_CHECK(fileExists(p));
  backend->release = true;
  BOOST_CHECK_EQUAL(beaconCode(), 77);
  BOOST_CHECK(fileExists(p));
}

// When the owner deletes the source file during a ces.think call, the
// refund of the hold goes to the owner, as the file's balance did.
BOOST_FIXTURE_TEST_CASE(HostThink_RefundGoesToOwnerWhenSourceIsGone,
                        ThinkLuaBigHoldFixture) {
  backend->block = true;
  const std::string p = path("t10.lua");
  const std::string src = B() +
    "ces.spawn(function() ces.think('hi') end)\n"
    "ces.run()\n";
  deploy(p, src, 9'000'000'000);
  launch(p);
  BOOST_REQUIRE(waitEntered());
  const auto ownerPk = ownerKey.getPublicKeyAsHash();
  uint64_t refunded = 0;
  {
    CesFileClient fc;
    fc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(fc.connect("localhost", rpcPort, ownerKey));
    CES_REQUIRE_OK(fc.deleteFile(p, refunded));
  }
  const int64_t afterDelete = balanceOf(ownerPk);
  backend->release = true;
  // The hold (about 8e9) less the small charge comes back to the owner.
  int64_t now = afterDelete;
  waitUntil([&] {
    now = balanceOf(ownerPk);
    return now >= afterDelete + 7'000'000'000;
  });
  BOOST_CHECK_GE(now, afterDelete + 7'000'000'000);
}

// More than 65535 host calls while one ces.think call waits: the call id
// counter wraps, but it never takes the id of a call in flight.
BOOST_FIXTURE_TEST_CASE(HostThink_CorrIdWrapKeepsTheCall, ThinkLuaFixture) {
  backend->block = true;
  KeyPair loopBeacon;
  server->_brr(loopBeacon.getPublicKeyAsHash(), 1);
  BOOST_REQUIRE(waitUntil(
      [&] { return balanceOf(loopBeacon.getPublicKeyAsHash()) == 1; }));
  const std::string src = B() + B2(loopBeacon) +
    "ces.spawn(function()\n"
    "  local r = ces.think('hi')\n"
    "  if r == 'Hello, world.' then ces.transfer(B, 77)\n"
    "  else ces.transfer(B, 2) end\n"
    "end)\n"
    "ces.spawn(function()\n"
    "  for i = 1, 66000 do ces.random_bytes(1) end\n"
    "  ces.transfer(B2, 5)\n"
    "end)\n"
    "ces.run()\n";
  const std::string p = path("t11.lua");
  deploy(p, src);
  launch(p);
  BOOST_REQUIRE(waitEntered());
  // 66000 host calls: allow a slow machine plenty of time.
  BOOST_REQUIRE_EQUAL(beaconCode(loopBeacon, std::chrono::minutes(5)), 5);
  backend->release = true;
  BOOST_CHECK_EQUAL(beaconCode(), 77);
}

// A prompt too large for one IPC frame is refused in the child, and the
// program keeps running.
BOOST_FIXTURE_TEST_CASE(HostThink_PromptOverFrameCapRefused,
                        ThinkLuaFixture) {
  const std::string src = B() +
    "local r, err = ces.think(string.rep('x', 3 * 1024 * 1024))\n"
    "if r == nil and type(err) == 'string' then ces.transfer(B, 77)\n"
    "else ces.transfer(B, 2) end\n";
  const std::string p = path("t12.lua");
  deploy(p, src);
  launch(p);
  BOOST_CHECK_EQUAL(beaconCode(), 77);
  BOOST_CHECK_EQUAL(backend->calls.load(), 0);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(ThinkLuaNoMountTests)

// With builtin:think not mounted, ces.think answers DISABLED.
BOOST_FIXTURE_TEST_CASE(HostThink_NotMountedIsDisabled,
                        ThinkLuaNoMountFixture) {
  const std::string src = B() +
    "local r, rc = ces.think('hi')\n"
    "if r == nil and rc == ces.err.DISABLED then ces.transfer(B, 77)\n"
    "else ces.transfer(B, 2) end\n";
  deploy(path("t7.lua"), src);
  launch(path("t7.lua"));
  BOOST_CHECK_EQUAL(beaconCode(), 77);
}

BOOST_AUTO_TEST_SUITE_END()
