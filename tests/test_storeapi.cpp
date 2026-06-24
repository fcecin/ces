// ===========================================================================
// ces.store — the L2 Lua persistent key-value store binding.
// ===========================================================================
//
// ces.store(path) hands a Lua program a handle onto a logkv-backed kv-file
// managed by builtin:file. The handle's methods (:create/:put/:get/:erase/
// :keys) ride the in-process file path with kv verbs, billed and evicted like
// any file. These tests drive the WHOLE stack on the real runtime: a spawned
// cesluajitd child runs Lua that calls ces.store; the kv verbs cross the
// supervisor IPC into compute_handler, which dispatches fileHandlerExec's kv
// cores; the reply round-trips back to Lua. Needs the real cesluajitd binary.
//
//   StoreRoundTrip               — create/put/get/erase/keys + binary values
//   StorePersistsAcrossRestart   — data outlives the program: a fresh instance
//                                  of the same source reads what a now-killed
//                                  instance wrote (the store is server-side,
//                                  owned by builtin:file, not the child).

#define BOOST_TEST_DYN_LINK
#include "test_common.h"
#include "test_e2e_common.h"

#include <ces/account.h>
#include <ces/buffer.h>
#include <ces/keys.h>
#include <ces/l2/compute_client.h>
#include <ces/l2/file_client.h>
#include <ces/ramfilestore.h>   // ces::sha256
#include <ces/server.h>
#include <ces/types.h>

#include <minx/minx.h>

#include <array>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>

using namespace ces;

namespace {

// Captures the program's ces.client_send replies addressed to our Minx.
struct StoreCapture : public minx::MinxListener {
  std::mutex m;
  std::condition_variable cv;
  std::vector<std::string> payloads;  // program payloads, in arrival order

  void incomingApplication(const minx::SockAddr&, const uint8_t,
                           const minx::Bytes& data) override {
    // Wire body: [1B flags][8B prog_pfx][u16 BE len][payload]
    if (data.size() < 11) return;
    uint16_t len = ces::Buffer::peek<uint16_t>(
      reinterpret_cast<const uint8_t*>(data.data()) + 9);
    if (data.size() < size_t(11) + len) return;
    std::string p(reinterpret_cast<const char*>(data.data() + 11), len);
    {
      std::lock_guard lk(m);
      payloads.push_back(std::move(p));
    }
    cv.notify_all();
  }

  bool wait_for(size_t minCount, std::chrono::milliseconds timeout) {
    std::unique_lock lk(m);
    return cv.wait_for(lk, timeout, [&] { return payloads.size() >= minCount; });
  }
  std::string at(size_t i) {
    std::lock_guard lk(m);
    return i < payloads.size() ? payloads[i] : std::string();
  }
};

struct StoreFixture {
  std::unique_ptr<CesServer> server;
  fs::path tempDir;
  uint16_t serverPort = 0;
  uint16_t rpcPort = 0;
  std::string luajitBin;

  KeyPair ownerKey;
  KeyPair clientKey;

  std::unique_ptr<StoreCapture> listener;
  std::unique_ptr<minx::Minx> clientMinx;
  boost::asio::io_context clientNetIO, clientTaskIO;
  using WG = boost::asio::executor_work_guard<
    boost::asio::io_context::executor_type>;
  std::unique_ptr<WG> clientNetGuard, clientTaskGuard;
  std::thread clientNetThread, clientTaskThread;
  uint16_t clientPort = 0;

  StoreFixture() {
    blog::init();
    blog::set_level(blog::fatal);
    blog::set_level("plex", blog::fatal);

    tempDir = makeUniqueTempDir("ces_store");
    minx::Hash serverPriv;
    serverPriv.fill(0x5B);

    CesConfig cfg = makeTestConfig(
      tempDir, serverPriv, std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = {
      {"/ces/file/1",    "builtin:file"},
      {"/ces/compute/1", "builtin:compute"},
    };
    cfg.cesFileStoreMaxBytes = 16ull * 1024 * 1024;
    cfg.feeFileRent = 1;
    cfg.computeMaxInstances = 8;
    cfg.feeComputeSlotSec = 1;
    luajitBin = ces::e2e::findBinary("cesluajitd");
    cfg.cesComputeChildBinary = luajitBin;
    cfg.cesComputeUser = "";
    cfg.cesComputeWorkDir = (tempDir / "cescompute").string();

    server = std::make_unique<CesServer>(cfg);
    serverPort = server->start(0);
    BOOST_REQUIRE_MESSAGE(serverPort > 0, "server port bind failed");
    rpcPort = server->_rpcBoundPort();
    BOOST_REQUIRE_MESSAGE(rpcPort > 0, "rpc port bind failed");

    server->_brr(ownerKey.getPublicKeyAsHash(),  100'000'000'000ULL);
    server->_brr(clientKey.getPublicKeyAsHash(),  10'000'000'000ULL);

    listener = std::make_unique<StoreCapture>();
    minx::MinxConfig mc{};
    mc.instanceName = "tst";
    mc.randomXVMsToKeep = 0;
    mc.randomXInitThreads = 0;
    mc.trustLoopback = true;
    clientMinx = std::make_unique<minx::Minx>(listener.get(), mc);
    clientNetGuard = std::make_unique<WG>(clientNetIO.get_executor());
    clientTaskGuard = std::make_unique<WG>(clientTaskIO.get_executor());
    clientNetThread = std::thread([this]() { clientNetIO.run(); });
    clientTaskThread = std::thread([this]() { clientTaskIO.run(); });
    clientPort = clientMinx->openSocket(
      boost::asio::ip::address_v6::any(), 0, clientNetIO, clientTaskIO);
    BOOST_REQUIRE_MESSAGE(clientPort > 0, "test client minx socket failed");

    minx::SockAddr clientLoop(boost::asio::ip::make_address("::1"), clientPort);
    HashPrefix clientPfx = Account::getMapKey(clientKey.getPublicKeyAsHash());
    server->_primePresence(clientPfx, clientLoop);

    wait_net();
  }

  ~StoreFixture() {
    if (clientMinx) clientMinx->closeSocket(false);
    if (clientNetGuard) clientNetGuard->reset();
    if (clientTaskGuard) clientTaskGuard->reset();
    clientNetIO.stop();
    clientTaskIO.stop();
    if (clientNetThread.joinable()) clientNetThread.join();
    if (clientTaskThread.joinable()) clientTaskThread.join();
    clientMinx.reset();
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }

  std::string ownerHex() const { return ownerKey.getPublicKeyHexStr(); }

  // Bake the owner hex into a program template wherever "OWNER" appears.
  std::string withOwner(const std::string& src) const {
    std::string out = src;
    const std::string ph = "OWNER";
    for (size_t pos; (pos = out.find(ph)) != std::string::npos;)
      out.replace(pos, ph.size(), ownerHex());
    return out;
  }

  void uploadScript(const std::string& path, const std::string& source,
                    uint64_t initialDeposit = 5'000'000'000ULL) {
    CesFileClient fc;
    fc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(fc.connect("localhost", rpcPort, ownerKey));
    uint64_t bal = 0, cost = 0;
    CES_REQUIRE_OK(fc.create(path, source.size(), 0, initialDeposit, bal, cost));
    ces::Bytes content(source.begin(), source.end());
    CES_REQUIRE_OK(fc.write(path, 0, content, bal));
    fc.disconnect();
  }

  uint64_t launchScript(const std::string& path) {
    CesComputeClient cc;
    cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));
    uint64_t instId = 0, startedAt = 0;
    CES_REQUIRE_OK(cc.launch(path, instId, startedAt));
    cc.disconnect();
    return instId;
  }

  void killInstance(uint64_t pid) {
    CesComputeClient cc;
    cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));
    CES_REQUIRE_OK(cc.kill(pid));
    cc.disconnect();
  }

  std::array<uint8_t, 8> progPrefixOf(const std::string& path) {
    minx::Hash h = ces::sha256(
      reinterpret_cast<const uint8_t*>(path.data()), path.size());
    std::array<uint8_t, 8> pf{};
    std::memcpy(pf.data(), h.data(), 8);
    return pf;
  }

  void sendAppToProgram(const std::array<uint8_t, 8>& prog_pfx,
                        const std::string& payload) {
    minx::Bytes pkt;
    ces::Buffer::put<uint8_t>(pkt, 0);
    pkt.insert(pkt.end(), prog_pfx.begin(), prog_pfx.end());
    ces::Buffer::put<uint16_t>(pkt, static_cast<uint16_t>(payload.size()));
    pkt.insert(pkt.end(), payload.begin(), payload.end());
    minx::SockAddr srv(boost::asio::ip::make_address("::1"), serverPort);
    clientMinx->sendApplication(srv, pkt, CES_APP_COMPUTE_MSG);
  }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(StoreApiTests, StoreFixture)

// Full lifecycle through the real binding: create an empty store, put/get,
// confirm a missing key reads back nil, overwrite a key with a NUL-bearing
// binary value (the wire path is length-prefixed, so it must survive), erase,
// and watch :keys() track the live key set. One program, one poke, one verdict.
BOOST_AUTO_TEST_CASE(StoreRoundTrip) {
  const std::string src = withOwner(R"LUA(
    local pfx = ces.client_recv()
    local e = {}
    local db = ces.store("/h/OWNER/rt.kv")
    if not db:create(2000000000) then e[#e+1] = "create" end
    local k0 = db:keys()
    if type(k0) ~= "table" or #k0 ~= 0 then e[#e+1] = "keys0" end
    if not db:put("k1", "v1")  then e[#e+1] = "put1" end
    if not db:put("k2", "vv2") then e[#e+1] = "put2" end
    local v1 = db:get("k1")
    if v1 ~= "v1" then e[#e+1] = "get1:" .. tostring(v1) end
    if db:get("nope") ~= nil then e[#e+1] = "getmiss" end
    local k2 = db:keys()
    if #k2 ~= 2 then e[#e+1] = "keys2:" .. tostring(#k2) end
    if not db:put("k1", "A\0B") then e[#e+1] = "putbin" end
    if db:get("k1") ~= "A\0B" then e[#e+1] = "getbin" end
    if not db:erase("k1") then e[#e+1] = "erase1" end
    if db:get("k1") ~= nil then e[#e+1] = "geterased" end
    local k3 = db:keys()
    if #k3 ~= 1 then e[#e+1] = "keys3:" .. tostring(#k3) end
    if #e == 0 then ces.client_send(pfx, "ok")
    else ces.client_send(pfx, "bad:" .. table.concat(e, ",")) end
    ces.run()
  )LUA");
  const std::string path = "/h/" + ownerHex() + "/rt_store.lua";
  uploadScript(path, src);
  BOOST_REQUIRE(launchScript(path) > 0);
  auto pfx = progPrefixOf(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(250));
  sendAppToProgram(pfx, "go");
  BOOST_REQUIRE_MESSAGE(listener->wait_for(1, std::chrono::seconds(5)),
                        "no reply from round-trip program");
  BOOST_CHECK_EQUAL(listener->at(0), "ok");
}

// One program, two launches of the SAME source. The first writes a value and
// is then KILLED; a fresh instance reads it back. The kv-file lives in the
// server (builtin:file owns it), so a value survives the program that wrote it.
BOOST_AUTO_TEST_CASE(StorePersistsAcrossRestart) {
  const std::string src = withOwner(R"LUA(
    local pfx, cmd = ces.client_recv()
    local db = ces.store("/h/OWNER/persist.kv")
    if cmd == "put" then
      db:create(2000000000)            -- first launch creates it
      local ok = db:put("alpha", "hello-kv")
      ces.client_send(pfx, ok and "put_ok" or "put_fail")
    elseif cmd == "get" then
      local v = db:get("alpha")
      ces.client_send(pfx, "got:" .. tostring(v))
    else
      ces.client_send(pfx, "unknown")
    end
    ces.run()
  )LUA");
  const std::string path = "/h/" + ownerHex() + "/persist_store.lua";
  uploadScript(path, src);
  auto pfx = progPrefixOf(path);

  // Launch #1: write the value, then kill it.
  uint64_t inst1 = launchScript(path);
  BOOST_REQUIRE(inst1 > 0);
  std::this_thread::sleep_for(std::chrono::milliseconds(250));
  sendAppToProgram(pfx, "put");
  BOOST_REQUIRE_MESSAGE(listener->wait_for(1, std::chrono::seconds(5)),
                        "no reply from writer instance");
  BOOST_CHECK_EQUAL(listener->at(0), "put_ok");
  killInstance(inst1);
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  // Launch #2 (fresh child, same source): read the value back.
  uint64_t inst2 = launchScript(path);
  BOOST_REQUIRE(inst2 > 0);
  std::this_thread::sleep_for(std::chrono::milliseconds(250));
  sendAppToProgram(pfx, "get");
  BOOST_REQUIRE_MESSAGE(listener->wait_for(2, std::chrono::seconds(5)),
                        "no reply from reader instance");
  BOOST_CHECK_EQUAL(listener->at(1), "got:hello-kv");
}

// The :get contract a consumer (the DHT) leans on: an ABSENT key returns a bare
// nil with NO second value, while a real FAILURE (here: get before the store is
// even created) returns nil + a numeric error code. The program verifies both,
// plus a present-key read, and reports one verdict.
BOOST_AUTO_TEST_CASE(GetDistinguishesAbsentFromError) {
  const std::string src = withOwner(R"LUA(
    local pfx = ces.client_recv()
    local e = {}
    local db = ces.store("/h/OWNER/err.kv")
    -- before create: a genuine error -> (nil, number)
    local v0, err0 = db:get("x")
    if v0 ~= nil then e[#e+1] = "v0" end
    if type(err0) ~= "number" then e[#e+1] = "noerrcode" end
    db:create(2000000000)
    -- existing store, missing key -> (nil) with NO error
    local v1, err1 = db:get("missing")
    if v1 ~= nil then e[#e+1] = "v1" end
    if err1 ~= nil then e[#e+1] = "spurious:" .. tostring(err1) end
    -- present key -> value, no error
    db:put("k", "v")
    local v2, err2 = db:get("k")
    if v2 ~= "v" then e[#e+1] = "v2:" .. tostring(v2) end
    if err2 ~= nil then e[#e+1] = "err2" end
    if #e == 0 then ces.client_send(pfx, "errprop_ok")
    else ces.client_send(pfx, "bad:" .. table.concat(e, ",")) end
    ces.run()
  )LUA");
  const std::string path = "/h/" + ownerHex() + "/err_store.lua";
  uploadScript(path, src);
  BOOST_REQUIRE(launchScript(path) > 0);
  auto pfx = progPrefixOf(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(250));
  sendAppToProgram(pfx, "go");
  BOOST_REQUIRE_MESSAGE(listener->wait_for(1, std::chrono::seconds(5)),
                        "no reply from errprop program");
  BOOST_CHECK_EQUAL(listener->at(0), "errprop_ok");
}

// The funding path from Lua: :put(key, value, deposit) seeds a cell's rent
// balance and returns it; :deposit(key, amount) tops it up. End-to-end through
// the supervisor IPC and the per-cell billing in the file service.
BOOST_AUTO_TEST_CASE(PutDepositBalances) {
  const std::string src = withOwner(R"LUA(
    local pfx = ces.client_recv()
    local e = {}
    local db = ces.store("/h/OWNER/fund.kv")
    db:create(0)
    local ok, bal = db:put("k", "v", 5000)        -- seed cell balance 5000
    if not ok then e[#e+1] = "put" end
    if bal ~= 5000 then e[#e+1] = "bal:" .. tostring(bal) end
    local nb = db:deposit("k", 3000)              -- top up -> 8000
    if nb ~= 8000 then e[#e+1] = "dep:" .. tostring(nb) end
    -- the record itself is unchanged by funding
    if db:get("k") ~= "v" then e[#e+1] = "get" end
    -- funding a missing key is an error (nil, code)
    local mv, merr = db:deposit("ghost", 1)
    if mv ~= nil or type(merr) ~= "number" then e[#e+1] = "ghost" end
    if #e == 0 then ces.client_send(pfx, "fund_ok")
    else ces.client_send(pfx, "bad:" .. table.concat(e, ",")) end
    ces.run()
  )LUA");
  const std::string path = "/h/" + ownerHex() + "/fund_store.lua";
  uploadScript(path, src);
  BOOST_REQUIRE(launchScript(path) > 0);
  auto pfx = progPrefixOf(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(250));
  sendAppToProgram(pfx, "go");
  BOOST_REQUIRE_MESSAGE(listener->wait_for(1, std::chrono::seconds(5)),
                        "no reply from fund program");
  BOOST_CHECK_EQUAL(listener->at(0), "fund_ok");
}

// db:range from Lua: sorted [key,value] entries, half-open sub-range, and the
// effective_hi resume signal.
BOOST_AUTO_TEST_CASE(RangeFromLua) {
  const std::string src = withOwner(R"LUA(
    local pfx = ces.client_recv()
    local e = {}
    local db = ces.store("/h/OWNER/lr.kv")
    db:create(0)
    db:put("b", "2", 1000000000)        -- inserted out of order
    db:put("a", "1", 1000000000)
    db:put("c", "3", 1000000000)
    local ent, nexthi = db:range("", "", 1000000)
    if #ent ~= 3 then e[#e+1] = "n:" .. tostring(#ent) end
    if ent[1].key ~= "a" or ent[2].key ~= "b" or ent[3].key ~= "c" then e[#e+1] = "order" end
    if ent[1].value ~= "1" then e[#e+1] = "val:" .. tostring(ent[1].value) end
    if nexthi ~= "" then e[#e+1] = "nexthi:" .. tostring(nexthi) end
    local sub = db:range("a", "c", 1000000)     -- [a,c) -> a,b
    if #sub ~= 2 or sub[1].key ~= "a" or sub[2].key ~= "b" then e[#e+1] = "sub" end
    if #e == 0 then ces.client_send(pfx, "range_ok")
    else ces.client_send(pfx, "bad:" .. table.concat(e, ",")) end
    ces.run()
  )LUA");
  const std::string path = "/h/" + ownerHex() + "/range_store.lua";
  uploadScript(path, src);
  BOOST_REQUIRE(launchScript(path) > 0);
  auto pfx = progPrefixOf(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(250));
  sendAppToProgram(pfx, "go");
  BOOST_REQUIRE_MESSAGE(listener->wait_for(1, std::chrono::seconds(5)),
                        "no reply from range program");
  BOOST_CHECK_EQUAL(listener->at(0), "range_ok");
}

BOOST_AUTO_TEST_SUITE_END()
