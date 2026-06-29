// ===========================================================================
// cesluajitd cooperative async — transparent-yield I/O.
// ===========================================================================
//
// The runtime turns every host round-trip (ces.file_*, ces.transfer,
// ces.account_read, ces.random_bytes, ces.bucket_*, ...) into a coroutine
// yield: a call made from inside a ces.spawn coroutine suspends THAT behavior
// while the run loop services everyone else, then resumes it when the host
// reply lands. No async naming, no await -- the only program-visible delta is
// that calls look blocking but interleave. From the main chunk (no coroutine
// to suspend) the same call blocks, which is the correct degenerate case.
//
// These tests pin the model's load-bearing assumptions on the REAL runtime
// (a spawned cesluajitd child):
//   * a host call from a coroutine YIELDS -- proven by interleave order
//   * the yield path returns the SAME values as the blocking path
//   * many concurrent in-flight calls all complete (corr_id -> coroutine map)
//   * a host call from the main chunk still blocks and returns correctly

#define BOOST_TEST_DYN_LINK
#include "test_common.h"
#include "test_e2e_common.h"
#include "test_lua_conn_common.h"  // PlexLuaPeer + LuaConnFixture (relay conn harness)

#include <ces/account.h>
#include <ces/buffer.h>
#include <ces/keys.h>
#include <ces/l2/compute_client.h>
#include <ces/l2/file_client.h>
#include <ces/ramfilestore.h> // ces::sha256
#include <ces/server.h>
#include <ces/types.h>

#include <minx/minx.h>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>

using namespace ces;

namespace {

// Captures inbound APPLICATION messages (the program's ces.client_send
// replies) addressed to the test client's Minx.
struct AsyncCapture : public minx::MinxListener {
  std::mutex m;
  std::condition_variable cv;
  std::vector<std::string> payloads;  // decoded program payloads, in arrival order

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
  std::string first() {
    std::lock_guard lk(m);
    return payloads.empty() ? std::string() : payloads.front();
  }
};

struct AsyncFixture {
  std::unique_ptr<CesServer> server;
  fs::path tempDir;
  uint16_t serverPort = 0;
  uint16_t rpcPort = 0;
  std::string luajitBin;

  KeyPair ownerKey;
  KeyPair clientKey;

  std::unique_ptr<AsyncCapture> listener;
  std::unique_ptr<minx::Minx> clientMinx;
  boost::asio::io_context clientNetIO, clientTaskIO;
  using WG = boost::asio::executor_work_guard<
    boost::asio::io_context::executor_type>;
  std::unique_ptr<WG> clientNetGuard, clientTaskGuard;
  std::thread clientNetThread, clientTaskThread;
  uint16_t clientPort = 0;

  AsyncFixture() {
    blog::init();
    blog::set_level(blog::fatal);
    blog::set_level("plex", blog::fatal);

    tempDir = makeUniqueTempDir("ces_async");
    minx::Hash serverPriv;
    serverPriv.fill(0x5A);

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

    listener = std::make_unique<AsyncCapture>();
    minx::MinxConfig mc{};
    mc.instanceName = "tas";
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

  ~AsyncFixture() {
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

  // Deploy + launch `source` under a unique path, poke it once (so its main
  // chunk's ces.client_recv() returns the test client's prefix), and return
  // the single reply payload the program sends back via ces.client_send.
  std::string runAndCollect(const std::string& tag, const std::string& source,
                            std::chrono::milliseconds timeout =
                              std::chrono::seconds(5)) {
    std::string path = "/h/" + ownerHex() + "/" + tag + ".lua";
    uploadScript(path, source);
    BOOST_REQUIRE(launchScript(path) > 0);
    auto pfx = progPrefixOf(path);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    sendAppToProgram(pfx, "go");
    BOOST_REQUIRE_MESSAGE(listener->wait_for(1, timeout),
                          "timed out waiting for program reply (" + tag + ")");
    return listener->first();
  }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(AsyncTests, AsyncFixture)

// Two spawned behaviors each log a marker, hit one host call (the yield point),
// then log a second marker; the second to finish ships the log. If the host
// call YIELDS, the run loop interleaves them: A1;B1;A2;B2. If it BLOCKED, the
// first behavior would run to completion before the second starts: A1;A2;B1;B2.
// The interleaved order is the proof of transparent yielding.
BOOST_AUTO_TEST_CASE(SpawnedHostCallYields) {
  const std::string src = R"LUA(
    local pfx = ces.client_recv()
    local log, done = "", 0
    local function finish()
      done = done + 1
      if done == 2 then ces.client_send(pfx, log) end
    end
    ces.spawn(function()
      log = log .. "A1;"
      ces.account_read(string.rep("\0", 32))
      log = log .. "A2;"
      finish()
    end)
    ces.spawn(function()
      log = log .. "B1;"
      ces.account_read(string.rep("\0", 32))
      log = log .. "B2;"
      finish()
    end)
    ces.run()
  )LUA";
  BOOST_CHECK_EQUAL(runAndCollect("interleave", src), "A1;B1;A2;B2;");
}

// The yield path must reconstruct the SAME Lua return values as the blocking
// path: the decoder runs at resume and pushes the call's results. Exercise a
// handful of distinct decoder shapes (string, table, file round-trip) from
// inside a coroutine and report a single ok/bad verdict.
BOOST_AUTO_TEST_CASE(YieldPathReturnsCorrectValues) {
  const std::string src = R"LUA(
    local pfx = ces.client_recv()
    ces.spawn(function()
      local errs = {}
      -- string decoder: ces.random_bytes(n) -> n bytes
      local rb = ces.random_bytes(8)
      if type(rb) ~= "string" or #rb ~= 8 then errs[#errs+1] = "rb" end
      -- table decoder: ces.account_read -> {balance=..,nonce=..,..}
      local a = ces.account_read(string.rep("\0", 32))
      if type(a) ~= "table" or a.balance ~= 0 or a.nonce ~= 0 then
        errs[#errs+1] = "acct"
      end
      -- multi-value decoder + file round-trip through the yield path
      local fp = "/h/OWNER/rt.txt"
      local ok, bal = ces.file_create(fp, 64, 0, 1000000)
      if not ok then errs[#errs+1] = "create" end
      local wok = ces.file_write(fp, 0, "hello-async")
      if not wok then errs[#errs+1] = "write" end
      local rd = ces.file_read(fp, 0, 11)
      if rd ~= "hello-async" then errs[#errs+1] = "read:" .. tostring(rd) end
      if #errs == 0 then ces.client_send(pfx, "values_ok")
      else ces.client_send(pfx, "values_bad:" .. table.concat(errs, ",")) end
    end)
    ces.run()
  )LUA";
  std::string fixed = src;
  // Bake the owner hex into the file path the program uses.
  const std::string ph = "OWNER";
  for (size_t pos; (pos = fixed.find(ph)) != std::string::npos;)
    fixed.replace(pos, ph.size(), ownerHex());
  BOOST_CHECK_EQUAL(runAndCollect("values", fixed), "values_ok");
}

// Many coroutines each with several in-flight host calls must all complete:
// the corr_id -> coroutine map keeps every parked behavior distinct, and the
// run loop resumes each on its own reply. A deadlock or a mixed-up corr_id
// would hang (caught by the wait timeout) or drop the count.
BOOST_AUTO_TEST_CASE(ManyConcurrentInFlight) {
  const std::string src = R"LUA(
    local pfx = ces.client_recv()
    local N, done, sum = 16, 0, 0
    for i = 1, N do
      ces.spawn(function()
        for _ = 1, 4 do ces.account_read(string.rep("\0", 32)) end
        sum = sum + 1
        done = done + 1
        if done == N then ces.client_send(pfx, "done:" .. sum) end
      end)
    end
    ces.run()
  )LUA";
  BOOST_CHECK_EQUAL(runAndCollect("concurrent", src), "done:16");
}

// The same verb called from the MAIN chunk (no coroutine to suspend) must
// block and return correctly -- the degenerate case that keeps boot-time setup
// code working unchanged.
BOOST_AUTO_TEST_CASE(MainChunkBlocksAndReturns) {
  const std::string src = R"LUA(
    local pfx = ces.client_recv()
    local rb = ces.random_bytes(5)
    local a = ces.account_read(string.rep("\0", 32))
    if type(rb) == "string" and #rb == 5 and a and a.balance == 0 then
      ces.client_send(pfx, "main_ok")
    else
      ces.client_send(pfx, "main_bad")
    end
    ces.run()
  )LUA";
  BOOST_CHECK_EQUAL(runAndCollect("mainchunk", src), "main_ok");
}

BOOST_AUTO_TEST_SUITE_END()

// ===========================================================================
// Conn handlers as coroutines: on_open/on_data/on_close run in their own
// coroutine, so a handler can make blocking-looking calls that yield -- and
// frames for one conn stay strictly ordered behind a parked handler.
// ===========================================================================

BOOST_FIXTURE_TEST_SUITE(AsyncConnTests, LuaConnFixture)

// on_data calls ces.sleep AND a host I/O verb, then replies. ces.sleep yields
// and is only legal inside a coroutine -- if on_data were dispatched on the
// main thread (as it was before handlers became coroutines) this would error
// "only inside spawn" and no reply would come back. A correct "ok:0" reply is
// the proof that the handler itself is a transparently-yielding coroutine.
BOOST_AUTO_TEST_CASE(OnDataIsAYieldingCoroutine) {
  const std::string scriptPath = "/h/" + ownerKey.getPublicKeyHexStr() + "/h_yield.lua";
  const std::string src =
    "ces.conn.set_listener({\n"
    "  on_data = function(conn, data)\n"
    "    ces.sleep(5)\n"
    "    local a = ces.account_read(string.rep('\\0', 32))\n"
    "    conn:write('ok:' .. tostring(a.balance))\n"
    "  end,\n"
    "})\n"
    "ces.conn.run()\n";
  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  uint64_t sessionToken = 0;
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, sessionToken));
  auto r = peer.attach(userKey, sessionToken, instId);
  CES_REQUIRE_RC_EQ(r.status, CES_OK);

  ces::Bytes ping{'x'};
  BOOST_REQUIRE(peerWrite(peer, ping));
  ces::Bytes got;
  BOOST_REQUIRE(peerReadExact(peer, got, 4, std::chrono::seconds(5)));
  BOOST_CHECK_EQUAL(std::string(got.begin(), got.end()), "ok:0");
  peer.closeStream();
}

// A ces.every timer whose body calls ces.sleep proves three things at once:
//   * the timer body runs in a COROUTINE -- ces.sleep is "only inside spawn",
//     so on the old host-thread dispatch it would error every tick and the body
//     would never get past it;
//   * an inbound on_data answering WHILE the tick is parked proves the timer no
//     longer freezes the VM (the whole point of Item 1);
//   * `entered` staying at 1 across the many re-fires that come due during one
//     long park proves skip-if-busy (a long tick never laps itself).
// The program replies [entered][exited] as two ascii digits to each conn write.
// The park is deliberately long (seconds) so probe 1 lands inside the first park
// regardless of how long the attach handshake takes under load; the property under
// test is order-of-events, not wall-clock, so a generous margin removes the race.
BOOST_AUTO_TEST_CASE(TimerBodyIsCoroutineYieldsAndSkipsIfBusy) {
  const std::string scriptPath =
    "/h/" + ownerKey.getPublicKeyHexStr() + "/h_timer.lua";
  const std::string src =
    "local entered, exited = 0, 0\n"
    "ces.every(20, function()\n"
    "  entered = entered + 1\n"
    "  ces.sleep(3000)\n"           // long park; the 20ms re-fires must be skipped
    "  exited = exited + 1\n"
    "end)\n"
    "ces.conn.set_listener({\n"
    "  on_data = function(conn, data)\n"
    "    local e = entered > 9 and 9 or entered\n"
    "    local x = exited  > 9 and 9 or exited\n"
    "    conn:write(tostring(e) .. tostring(x))\n"
    "  end,\n"
    "})\n"
    "ces.conn.run()\n";
  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  uint64_t sessionToken = 0;
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, sessionToken));
  auto r = peer.attach(userKey, sessionToken, instId);
  CES_REQUIRE_RC_EQ(r.status, CES_OK);

  // Probe 1, during the first tick's 800ms park: on_data answers (VM not
  // frozen), exactly one tick has started (skip-if-busy), none has finished.
  ces::Bytes p1{'a'};
  BOOST_REQUIRE(peerWrite(peer, p1));
  ces::Bytes g1;
  BOOST_REQUIRE(peerReadExact(peer, g1, 2, std::chrono::seconds(5)));
  BOOST_CHECK_EQUAL(std::string(g1.begin(), g1.end()), "10");

  // Wait past the full 3000ms park (the tick was already in flight at probe 1,
  // so 3300ms guarantees it resumed past ces.sleep and a later tick has begun).
  std::this_thread::sleep_for(std::chrono::milliseconds(3300));

  // Probe 2: exited incremented -> the body resumed past ces.sleep (a real
  // coroutine); entered advanced -> the timer kept ticking after the long one.
  ces::Bytes p2{'b'};
  BOOST_REQUIRE(peerWrite(peer, p2));
  ces::Bytes g2;
  BOOST_REQUIRE(peerReadExact(peer, g2, 2, std::chrono::seconds(5)));
  BOOST_CHECK_MESSAGE(g2.size() == 2 && g2[0] >= '2' && g2[1] >= '1',
                      "probe2 expected entered>=2,exited>=1 got '"
                        + std::string(g2.begin(), g2.end()) + "'");
  peer.closeStream();
}

BOOST_AUTO_TEST_SUITE_END()

// ===========================================================================
// ces.chan — CSP channels (Hoare). spawn = sequential processes, chan = the
// message passing between them. recv is timeout-bounded so a channel can never
// add an unbounded wait. These pin send/recv, the timeout backstop, close, the
// buffered/drain/drop-on-closed lifecycle, value-type fidelity (messages, not
// bytes), and the fan-out-collect pattern a DHT lookup is built on.
// ===========================================================================

BOOST_FIXTURE_TEST_SUITE(ChanTests, AsyncFixture)

// The headline pattern: N workers each compute (via a yielding host call) then
// send; one coordinator recvs exactly N. This is the Kademlia α-fan-out shape.
BOOST_AUTO_TEST_CASE(FanOutCollect) {
  const std::string src = R"LUA(
    local pfx = ces.client_recv()
    local ch, N = ces.chan(), 5
    for i = 1, N do
      ces.spawn(function()
        ces.account_read(string.rep("\0", 32))   -- yield first, then send
        ch:send(i * 10)
      end)
    end
    ces.spawn(function()
      local sum = 0
      for _ = 1, N do local v = ch:recv(3000); sum = sum + (v or -1000) end
      ces.client_send(pfx, "sum:" .. sum)
    end)
    ces.run()
  )LUA";
  BOOST_CHECK_EQUAL(runAndCollect("fanout", src), "sum:150");
}

// recv on an empty channel returns nil,"timeout" after the bound -- the property
// that makes a channel unable to introduce an unbounded wait.
BOOST_AUTO_TEST_CASE(RecvTimesOut) {
  const std::string src = R"LUA(
    local pfx = ces.client_recv()
    ces.spawn(function()
      local ch = ces.chan()
      local v, err = ch:recv(30)
      ces.client_send(pfx, "to:" .. tostring(v) .. "," .. tostring(err))
    end)
    ces.run()
  )LUA";
  BOOST_CHECK_EQUAL(runAndCollect("recvto", src), "to:nil,timeout");
}

// close() wakes a parked recv-er with nil,"closed" -- the prompt-shutdown path.
BOOST_AUTO_TEST_CASE(CloseWakesRecver) {
  const std::string src = R"LUA(
    local pfx = ces.client_recv()
    local ch = ces.chan()
    ces.spawn(function()
      local v, err = ch:recv(5000)
      ces.client_send(pfx, "cl:" .. tostring(v) .. "," .. tostring(err))
    end)
    ces.spawn(function() ces.sleep(20); ch:close() end)
    ces.run()
  )LUA";
  BOOST_CHECK_EQUAL(runAndCollect("close", src), "cl:nil,closed");
}

// Buffered sends queue; recv drains them in order EVEN after close; a send to a
// closed channel drops (false); a drained+closed recv returns nil,"closed".
BOOST_AUTO_TEST_CASE(BufferedDrainAndClosedDrop) {
  const std::string src = R"LUA(
    local pfx = ces.client_recv()
    ces.spawn(function()
      local ch = ces.chan()
      ch:send("a"); ch:send("b")
      ch:close()
      local dropped = ch:send("c")    -- closed -> false
      local x = ch:recv(100)          -- "a"
      local y = ch:recv(100)          -- "b"
      local z, e = ch:recv(100)       -- nil,"closed"
      ces.client_send(pfx, x .. y .. "," .. tostring(dropped) ..
                           "," .. tostring(z) .. ":" .. tostring(e))
    end)
    ces.run()
  )LUA";
  BOOST_CHECK_EQUAL(runAndCollect("buffered", src), "ab,false,nil:closed");
}

// A channel carries whole Lua VALUES, not bytes: a table sent is the table
// received, intact and typed. (Why it's send/recv, not read/write.)
BOOST_AUTO_TEST_CASE(CarriesLuaValues) {
  const std::string src = R"LUA(
    local pfx = ces.client_recv()
    local ch = ces.chan()
    ces.spawn(function() ch:send({ n = 7, s = "hi" }) end)
    ces.spawn(function()
      local v = ch:recv(3000)
      ces.client_send(pfx, "tbl:" .. tostring(v.n) .. v.s)
    end)
    ces.run()
  )LUA";
  BOOST_CHECK_EQUAL(runAndCollect("values", src), "tbl:7hi");
}

// The leak we designed against: recv-ing MORE than was sent must TIME OUT, not
// hang forever. Under-recv is free (the unsent value just GCs); over-recv is
// bounded by the timeout.
BOOST_AUTO_TEST_CASE(OverRecvTimesOutNotHangs) {
  const std::string src = R"LUA(
    local pfx = ces.client_recv()
    ces.spawn(function()
      local ch = ces.chan()
      ch:send(1)
      local a = ch:recv(100)          -- 1
      local b, e = ch:recv(100)       -- nothing left -> nil,"timeout"
      ces.client_send(pfx, "ovr:" .. tostring(a) .. "," ..
                           tostring(b) .. "," .. tostring(e))
    end)
    ces.run()
  )LUA";
  BOOST_CHECK_EQUAL(runAndCollect("overrecv", src), "ovr:1,nil,timeout");
}

BOOST_AUTO_TEST_SUITE_END()
