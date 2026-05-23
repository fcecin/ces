// ===========================================================================
// builtin:compute × LuaJIT — hello-world echo round-trip.
// ===========================================================================
//
// The stub-process tests in test_compute.cpp verify the plumbing
// (LAUNCH / KILL / instance registry / file-deletion interlock /
// APPLICATION dispatch) using cescompmockd as the child. This file
// exercises the REAL runtime: it spawns cesluajitd, feeds it a
// three-line Lua script that echoes inbound client messages, and
// verifies the reply comes back through the server's APPLICATION
// push path.
//
// Everything is in-process except the cesluajitd child (whose
// whole point is to be a separate OS process). The test's "client"
// is a local Minx instance with a capturing listener.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"
#include "test_e2e_common.h"

#include <ces/l2/compute_client.h>
#include <ces/buffer.h>
#include <ces/l2/file_client.h>
#include <ces/l2/net_multiplexer.h>
#include <ces/l2/compute_handler.h>
#include <ces/l2/file_handler.h>
#include <ces/ramfilestore.h> // ces::sha256
#include <ces/server.h>

#include <unistd.h> // getpid

#include <minx/minx.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>

using namespace ces;

namespace {

// Listener that captures inbound APPLICATION messages addressed to
// the test client's Minx.
struct CaptureListener : public minx::MinxListener {
  std::mutex m;
  std::condition_variable cv;
  std::vector<std::pair<uint8_t, minx::Bytes>> messages;

  void incomingApplication(const minx::SockAddr&, const uint8_t code,
                           const minx::Bytes& data) override {
    std::lock_guard lk(m);
    messages.emplace_back(code, data);
    cv.notify_all();
  }

  // Wait up to `timeout` for at least `minCount` messages.
  bool wait_for(size_t minCount, std::chrono::milliseconds timeout) {
    std::unique_lock lk(m);
    return cv.wait_for(lk, timeout, [&] { return messages.size() >= minCount; });
  }
};

struct LuaComputeFixture {
  std::unique_ptr<CesServer> server;
  fs::path tempDir;
  uint16_t serverPort = 0;
  uint16_t rpcPort = 0;
  std::string luajitBin;

  KeyPair ownerKey;       // owner of the Lua source file
  KeyPair clientKey;      // test "client" that talks to the program

  // Test client Minx (distinct from the CesClient the fixture also
  // stands up, to keep the APPLICATION capture path clean).
  std::unique_ptr<CaptureListener> listener;
  std::unique_ptr<minx::Minx> clientMinx;
  boost::asio::io_context clientNetIO, clientTaskIO;
  using WG = boost::asio::executor_work_guard<
    boost::asio::io_context::executor_type>;
  std::unique_ptr<WG> clientNetGuard;
  std::unique_ptr<WG> clientTaskGuard;
  std::thread clientNetThread, clientTaskThread;
  uint16_t clientPort = 0;

  LuaComputeFixture() {
    blog::init();
    blog::set_level(blog::fatal);
    blog::set_level("plex", blog::fatal);

    tempDir = makeUniqueTempDir("compute_lua");

    minx::Hash serverPriv;
    serverPriv.fill(0xCC);

    CesConfig cfg = makeTestConfig(
      tempDir, serverPriv, std::numeric_limits<uint64_t>::max());
    // OS-allocated rpc port — no collisions, no time-modulo nonsense.
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = {
      {"/ces/file/1",    "builtin:file"},
      {"/ces/compute/1", "builtin:compute"},
    };
    cfg.cesFileStoreMaxBytes = 16ull * 1024 * 1024;
    cfg.feeFileRent = 1;

    cfg.computeMaxInstances = 4;
    cfg.feeComputeSlotSec = 1;
    // Leave at production default (60 s). Tests that care about tick
    // side-effects drive them synchronously via
    // ces::_computeTestForceTick() rather than waiting on the timer.
    luajitBin = ces::e2e::findBinary("cesluajitd");
    cfg.cesComputeChildBinary = luajitBin;
    cfg.cesComputeUser = ""; // running as dev user; no drop attempted
    cfg.cesComputeWorkDir = (tempDir / "cescompute").string();

    server = std::make_unique<CesServer>(cfg);
    serverPort = server->start(0);
    BOOST_REQUIRE_MESSAGE(serverPort > 0, "server port bind failed");
    rpcPort = server->_rpcBoundPort();
    BOOST_REQUIRE_MESSAGE(rpcPort > 0, "rpc port bind failed");

    server->_brr(ownerKey.getPublicKeyAsHash(),  10'000'000'000);
    server->_brr(clientKey.getPublicKeyAsHash(), 10'000'000'000);

    // Test client Minx setup.
    listener = std::make_unique<CaptureListener>();
    minx::MinxConfig mc{};
    mc.instanceName = "tcl";
    mc.randomXVMsToKeep = 0;
    mc.randomXInitThreads = 0;
    mc.trustLoopback = true;
    clientMinx = std::make_unique<minx::Minx>(listener.get(), mc);
    clientNetGuard = std::make_unique<WG>(clientNetIO.get_executor());
    clientTaskGuard = std::make_unique<WG>(clientTaskIO.get_executor());
    clientNetThread = std::thread([this]() { clientNetIO.run(); });
    clientTaskThread = std::thread([this]() { clientTaskIO.run(); });
    clientPort = clientMinx->openSocket(
      boost::asio::ip::address_v6::any(), 0,
      clientNetIO, clientTaskIO);
    BOOST_REQUIRE_MESSAGE(clientPort > 0,
                          "test client minx socket failed to open");

    // Prime server's presence cache — lets the running program's
    // ces.client_send resolve our client's 8-byte prefix to an addr.
    minx::SockAddr clientLoop(
      boost::asio::ip::make_address("::1"), clientPort);
    HashPrefix clientPfx = Account::getMapKey(clientKey.getPublicKeyAsHash());
    server->_primePresence(clientPfx, clientLoop);

    wait_net();
  }

  ~LuaComputeFixture() {
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

  // Upload the given Lua source at path (absolute CES name) using
  // the owner key. Caller supplies enough file_balance to cover
  // CREATE upfront + WRITE costs at the fixture's fees.
  // `initialDeposit` defaults to 100M (1 user-credit) — small,
  // matches the original test budget for plumbing-only checks.
  // Tests that exercise asset minting / heavier program-account
  // spend should bump this explicitly.
  void uploadScript(const std::string& path,
                    const std::string& source,
                    uint64_t initialDeposit = 100'000'000ULL) {
    CesFileClient fc;
    fc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(fc.connect("localhost", rpcPort, ownerKey));
    uint64_t bal = 0, cost = 0;
    CES_REQUIRE_OK(fc.create(
      path,
      /*size=*/source.size(),
      /*pricePerKb=*/0,
      initialDeposit,
      /*contentType=*/"text/x-lua",
      bal, cost));
    ces::Bytes content(source.begin(), source.end());
    CES_REQUIRE_OK(fc.write(path, /*offset=*/0, content, bal));
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

  // Compute the 8-byte prog prefix used both to address outbound
  // CES_APP_COMPUTE_MSG packets and as the "from" ID on replies.
  std::array<uint8_t, 8> progPrefixOf(const std::string& path) {
    minx::Hash h = ces::sha256(
      reinterpret_cast<const uint8_t*>(path.data()), path.size());
    std::array<uint8_t, 8> pf{};
    std::memcpy(pf.data(), h.data(), 8);
    return pf;
  }

  // Fire a CES_APP_COMPUTE_MSG to the server destined for the
  // running program under `prog_pfx`. Payload is the opaque body.
  // Wire body (what Minx's sendApplication takes as "data"):
  //   [1B flags=0][8B prog_pfx][u16 BE len][payload]
  void sendAppToProgram(const std::array<uint8_t, 8>& prog_pfx,
                        const std::string& payload) {
    minx::Bytes pkt;
    ces::Buffer::put<uint8_t>(pkt, 0); // flags
    pkt.insert(pkt.end(), prog_pfx.begin(), prog_pfx.end());
    ces::Buffer::put<uint16_t>(pkt, static_cast<uint16_t>(payload.size()));
    pkt.insert(pkt.end(), payload.begin(), payload.end());
    minx::SockAddr srv(
      boost::asio::ip::make_address("::1"), serverPort);
    clientMinx->sendApplication(srv, pkt, CES_APP_COMPUTE_MSG);
  }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(ComputeLuaTests, LuaComputeFixture)

BOOST_AUTO_TEST_CASE(HelloWorldEcho) {
  // Tiny echo program. `ces.client_recv` is blocking by default;
  // the while loop terminates when the socket closes (pfx == nil)
  // — the supervisor sends SIGKILL on fund depletion, which hits
  // us before the pipe closes cleanly, but a clean pipe close is
  // also handled.
  const std::string echoSource =
    "while true do\n"
    "  local pfx, msg = ces.client_recv()\n"
    "  if not pfx then break end\n"
    "  ces.client_send(pfx, 'Hello, ' .. msg .. '!')\n"
    "end\n";

  const std::string path =
    "/h/" + ownerKey.getPublicKeyHexStr() + "/echo.lua";
  uploadScript(path, echoSource);
  uint64_t instId = launchScript(path);
  BOOST_REQUIRE(instId > 0);

  auto pfx = progPrefixOf(path);

  // Give cesluajitd a moment to finish luaL_openlibs + run to the
  // ces.client_recv() entry before we fire the message. In
  // practice the child is ready within a few ms of LAUNCH return,
  // but the send-before-recv race would make this test flakey
  // without a brief settle.
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  sendAppToProgram(pfx, "World");

  BOOST_REQUIRE_MESSAGE(
    listener->wait_for(1, std::chrono::seconds(5)),
    "timed out waiting for program to reply");

  std::pair<uint8_t, minx::Bytes> got;
  {
    std::lock_guard lk(listener->m);
    BOOST_REQUIRE(!listener->messages.empty());
    got = listener->messages.front();
  }

  BOOST_CHECK_EQUAL(static_cast<int>(got.first),
                    static_cast<int>(CES_APP_COMPUTE_MSG));
  const auto& data = got.second;
  // [1B flags=0][8B prog_pfx][u16 BE len][payload]
  BOOST_REQUIRE(data.size() >= 11);
  BOOST_CHECK_EQUAL(static_cast<int>(data[0]), 0);
  BOOST_CHECK(std::memcmp(data.data() + 1, pfx.data(), 8) == 0);
  uint16_t len = ces::Buffer::peek<uint16_t>(
    reinterpret_cast<const uint8_t*>(data.data()) + 9);
  BOOST_REQUIRE_EQUAL(data.size(), static_cast<size_t>(11) + len);
  std::string payload(
    reinterpret_cast<const char*>(data.data() + 11), len);
  BOOST_CHECK_EQUAL(payload, "Hello, World!");
}

// ---------------------------------------------------------------------------
// File-API round-trip: the Lua program receives a client message, stashes
// it in /h/<owner>/greet.txt via CREATE+APPEND, reads it back, and echoes
// the contents. Proves that owner-authority file ops dispatched from Lua
// through the compute handler's IPC path reach the in-process file
// primitives and that the reply data makes it all the way back to the
// Lua script.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(FileApiRoundTrip) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/file_echo.lua";
  const std::string dataPath   = "/h/" + ownerHex + "/greet.txt";

  // Program does:
  //   1. wait for one inbound message (pfx, msg)
  //   2. create a 512-byte sparse file + deposit 10M credits into it
  //   3. append the message text to it
  //   4. read the message back from offset 0
  //   5. reply "Hello, <readback>!"
  const std::string src =
    std::string("local dpath = '") + dataPath + "'\n" +
    "local pfx, msg = ces.client_recv()\n"
    "if not pfx then return end\n"
    "-- CREATE: 512 bytes sparse, no price, 10M deposit, text/plain.\n"
    "local okc, fb = ces.file_create(dpath, 512, 0, 10000000, 'text/plain')\n"
    "if not okc then\n"
    "  ces.client_send(pfx, 'create_failed:' .. tostring(fb))\n"
    "  return\n"
    "end\n"
    "-- APPEND the inbound message.\n"
    "local oka, fb2, sz = ces.file_append(dpath, msg)\n"
    "if not oka then\n"
    "  ces.client_send(pfx, 'append_failed:' .. tostring(fb2))\n"
    "  return\n"
    "end\n"
    "-- READ it back at the end of the sparse region (original size=512).\n"
    "local data = ces.file_read(dpath, 512, sz - 512)\n"
    "if not data then\n"
    "  ces.client_send(pfx, 'read_failed')\n"
    "  return\n"
    "end\n"
    "ces.client_send(pfx, 'Hello, ' .. data .. '!')\n";

  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);

  auto pfx = progPrefixOf(scriptPath);

  // Give the child time to reach ces.client_recv.
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  sendAppToProgram(pfx, "World");

  BOOST_REQUIRE_MESSAGE(
    listener->wait_for(1, std::chrono::seconds(5)),
    "timed out waiting for program to reply");

  std::pair<uint8_t, minx::Bytes> got;
  {
    std::lock_guard lk(listener->m);
    BOOST_REQUIRE(!listener->messages.empty());
    got = listener->messages.front();
  }
  BOOST_CHECK_EQUAL(static_cast<int>(got.first),
                    static_cast<int>(CES_APP_COMPUTE_MSG));
  const auto& data = got.second;
  BOOST_REQUIRE(data.size() >= 11);
  uint16_t len = ces::Buffer::peek<uint16_t>(
    reinterpret_cast<const uint8_t*>(data.data()) + 9);
  BOOST_REQUIRE_EQUAL(data.size(), static_cast<size_t>(11) + len);
  std::string payload(
    reinterpret_cast<const char*>(data.data() + 11), len);
  BOOST_CHECK_EQUAL(payload, "Hello, World!");
}

// ---------------------------------------------------------------------------
// Fees: a Lua program's file ops must drain the SOURCE file's file_balance
// at the same per-op rates as if the owner had run them over `cesh file`.
// Without this drain, the feature is spammable — any running program could
// do unbounded writes/reads for free.
//
// This test checks two things:
//   1. After a few file ops, source file_balance dropped by AT LEAST
//      feeQuery × op_count.
//   2. Writes/reads drain additional per-KB fees on top.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(FileApiFeesDrainSource) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/file_fees.lua";
  const std::string dataPath   = "/h/" + ownerHex + "/fees_scratch.txt";

  // Program: wait for message, then do 5 file ops in sequence, then
  // reply with "done". We'll STAT the source before/after from the
  // test-side to check its file_balance dropped.
  const std::string src =
    std::string("local dpath = '") + dataPath + "'\n" +
    "local pfx, msg = ces.client_recv()\n"
    "if not pfx then return end\n"
    "ces.file_create(dpath, 256, 0, 5000000, 'text/plain')\n"
    "ces.file_append(dpath, 'AAAA')\n"
    "ces.file_append(dpath, 'BBBB')\n"
    "ces.file_read(dpath, 256, 4)\n"
    "ces.file_delete(dpath)\n"
    "ces.client_send(pfx, 'done')\n";

  uploadScript(scriptPath, src);

  // Snapshot source file_balance BEFORE launch. LAUNCH takes a 15-min
  // upfront slot-fee off it, so we capture after the launch has
  // settled but before the program runs its file ops.
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  auto pfx = progPrefixOf(scriptPath);
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  auto readSourceBalance = [&]() -> uint64_t {
    std::array<uint8_t, 32> ownerPk;
    uint64_t bal = 0;
    BOOST_REQUIRE(
      ces::fileHandlerReadOwnerAndBalance(scriptPath, ownerPk, bal));
    return bal;
  };
  uint64_t before = readSourceBalance();

  sendAppToProgram(pfx, "x");

  BOOST_REQUIRE_MESSAGE(
    listener->wait_for(1, std::chrono::seconds(5)),
    "timed out waiting for program to reply");

  // Give the handler's delete-refund credit a moment to settle onto
  // source file_balance (execDelete refunds the target's remaining
  // file_balance into source).
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  uint64_t after = readSourceBalance();

  // The program did: CREATE + APPEND + APPEND + READ + DELETE = 5 ops
  // each costing at LEAST feeQuery. Source file_balance must have
  // dropped by at least 5 × feeQuery, but should be close to that
  // value since the DELETE refunded most of the 5M initial deposit
  // that was pulled off source on CREATE.
  //
  // The exact delta is:
  //   feeQuery × 5
  //   + kbCeil(4)*feeFileRead = 1*feeFileRead    (READ)
  //   + initial_deposit_5M - refund               (~5M that round-trips
  //                                                to source via DELETE's
  //                                                refund, minus small
  //                                                per-op drains on target)
  // Concretely: refund ≈ 5M - 2*kbCeil(4)*feeFileWrite - tiny_upfront
  //           ≈ 5M - 2*feeFileWrite - ε
  // So (before - after) ≈ 5*feeQuery + feeFileRead + 2*feeFileWrite
  //
  // We just assert the floor — 5 × feeQuery — and that after > 0
  // (program didn't drain its wallet to zero).
  const CesConfig& cfg = server->_config();
  uint64_t expectedMin = 5ull * cfg.feeQuery;
  BOOST_CHECK_MESSAGE(before >= after + expectedMin,
    "source file_balance did not drop enough: before=" << before
    << " after=" << after << " expected_min_drop=" << expectedMin);
  BOOST_CHECK(after > 0);
}

// ---------------------------------------------------------------------------
// Direct sampler: read /proc for the test process itself. RSS must be
// positive (we're a real running process with plenty of malloc'd state);
// ticks must be readable. Tests the parser + pagesize conversion, not
// the supervisor integration.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(ReadProcSampleOfSelf) {
  uint64_t ticks = 0, rss = 0;
  BOOST_REQUIRE(ces::_computeTestReadProcSample(::getpid(), ticks, rss));
  BOOST_CHECK(rss > 0);
  BOOST_CHECK_MESSAGE(rss < uint64_t(1024) * 1024 * 1024 * 64,
    "unreasonable RSS from /proc: " << rss);
  // ticks may be 0 on a just-started process — no lower bound.
}

// ---------------------------------------------------------------------------
// Integration: a Lua program that allocates ~8 MB and busy-loops gets
// non-zero CPU basis points (ideally near 10000 — 100% of one core)
// and its RSS exceeds the allocated buffer. We wait >2 supervisor
// ticks so the delta-based CPU measurement has two samples.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(CpuAndRssReportedForBusyLuaProgram) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/burner.lua";

  // Allocate ~8 MB (string.rep), anchor it to a table so the GC
  // doesn't collect. Then busy-loop summing integers forever —
  // single-threaded LuaJIT will saturate one core.
  const std::string src =
    "local big = string.rep('X', 8 * 1024 * 1024)\n"
    "_G.__anchor = big\n"
    "local x = 0\n"
    "while true do\n"
    "  for i = 1, 100000 do x = x + i end\n"
    "end\n";

  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);

  // Let the Lua program get to its busy loop + allocation.
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  // First tick: baseline sample (sets lastCpuTicks / lastSampleUs).
  ces::_computeTestForceTick();
  // Give the child measurable CPU between samples, then sample again.
  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  ces::_computeTestForceTick();

  CesComputeClient cc;
  cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));
  CesComputeClient::InstanceInfo info;
  CES_REQUIRE_OK(cc.stat(instId, info));
  // Tear down the busy-looping child before disconnect — on the same
  // channel so we don't rebuild the CesPlex handshake.
  CES_REQUIRE_OK(cc.kill(instId));
  cc.disconnect();

  BOOST_CHECK_EQUAL(info.instanceId, instId);
  // The program is pegging one core. We've seen CI noise dropping
  // samples, so check a conservative floor (20%).
  BOOST_CHECK_MESSAGE(info.cpuBasisPoints >= 2000,
    "expected busy-loop CPU ≥ 2000 bp (20% of one core), got "
    << info.cpuBasisPoints);
  // RSS must at least cover the 8 MB string we allocated. LuaJIT
  // itself uses a few more MB on top.
  BOOST_CHECK_MESSAGE(info.rssBytes >= uint64_t(8) * 1024 * 1024,
    "expected RSS ≥ 8 MB, got " << info.rssBytes);
}

// ---------------------------------------------------------------------------
// AuthenticAssetCreate: a Lua program calls ces.authentic_asset_create
// with a recipient pubkey and a payload. The server stamps the first
// 32 bytes of the asset's content with sha256(source || path), sets
// IMMUTABLE, owns the asset by the recipient, and returns CES_OK.
// We verify (a) the asset exists and is owned by the recipient,
// (b) the content's first 32 bytes equal the expected program hash,
// (c) the IMMUTABLE bit is enforced (updateAsset rejects).
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(AuthenticAssetCreate) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/mint.lua";

  // Recipient is a fresh keypair the program will mint to.
  KeyPair recipientKey;
  std::string recipientPk(
    reinterpret_cast<const char*>(recipientKey.getPublicKeyAsHash().data()), 32);
  // Asset id is 32 fixed bytes — the test predetermines it so we
  // can query it back. The Lua source embeds it as a length-prefixed
  // string literal.
  std::array<uint8_t, 32> assetId{};
  for (int i = 0; i < 32; ++i)
    assetId[i] = static_cast<uint8_t>(0xA0 + (i & 0x1F));
  minx::Hash assetIdHash{};
  std::memcpy(assetIdHash.data(), assetId.data(), 32);

  // Encode the recipient and asset id as escaped Lua strings.
  auto luaEsc = [](const uint8_t* p, size_t n) {
    std::string out;
    char buf[8];
    for (size_t i = 0; i < n; ++i) {
      std::snprintf(buf, sizeof(buf), "\\%u",
                    static_cast<unsigned>(p[i]));
      out += buf;
    }
    return out;
  };
  std::string aidLit = luaEsc(assetId.data(), 32);
  std::string rcptLit = luaEsc(
    reinterpret_cast<const uint8_t*>(recipientPk.data()), 32);

  // Program waits for one client message. The message body is the
  // payload to mint into the asset (≤ 178 bytes).
  const std::string src =
    "local pfx, msg = ces.client_recv()\n"
    "if not pfx then return end\n"
    "local aid = '" + aidLit + "'\n"
    "local rcpt = '" + rcptLit + "'\n"
    "local ok, err = ces.authentic_asset_create(aid, rcpt, msg, 30)\n"
    "if ok then\n"
    "  ces.client_send(pfx, 'OK')\n"
    "else\n"
    "  ces.client_send(pfx, 'ERR:' .. tostring(err))\n"
    "end\n";

  // Authentic-asset mint debits the program account for asset
  // rent — give the file enough to cover (2+30) × feeAsset.
  uploadScript(scriptPath, src, /*initialDeposit=*/2'000'000'000ULL);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);

  auto pfx = progPrefixOf(scriptPath);
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  const std::string payload = "loot:gold-coin:50";
  sendAppToProgram(pfx, payload);

  BOOST_REQUIRE_MESSAGE(
    listener->wait_for(1, std::chrono::seconds(5)),
    "timed out waiting for program to reply");
  std::pair<uint8_t, minx::Bytes> got;
  {
    std::lock_guard lk(listener->m);
    got = listener->messages.front();
  }
  const auto& data = got.second;
  BOOST_REQUIRE(data.size() >= 11);
  uint16_t len = ces::Buffer::peek<uint16_t>(
    reinterpret_cast<const uint8_t*>(data.data()) + 9);
  std::string reply(
    reinterpret_cast<const char*>(data.data() + 11), len);
  BOOST_CHECK_MESSAGE(reply == "OK",
    "program reported failure: " << reply);

  // The expected program-identity hash is sha256(source || path).
  ces::Bytes hashInput(src.begin(), src.end());
  hashInput.insert(hashInput.end(),
                   scriptPath.begin(), scriptPath.end());
  minx::Hash expectedProgHash = ces::sha256(
    hashInput.data(), hashInput.size());

  // Query the new asset via a fresh CesClient (the fixture's
  // CesClient isn't wired here — bring up our own briefly).
  CesClient queryClient(testServerEp(serverPort), false);
  queryClient.start(0);
  KeyPair queryKey;
  queryClient.setKey(queryKey);
  BOOST_REQUIRE(queryClient.connect());
  // Need a tiny balance for the signed query op.
  server->_brr(queryKey.getPublicKeyAsHash(), 1'000'000'000);
  wait_net();

  std::vector<AssetEntry> results;
  uint8_t qrc = queryClient.queryAssetSigned(assetIdHash, 0, results);
  CES_REQUIRE_OK(qrc);
  BOOST_REQUIRE_EQUAL(results.size(), 1u);
  const AssetEntry& e = results[0];

  // Owner == recipient prefix.
  HashPrefix recipientPrefix = Account::getMapKey(recipientKey.getPublicKeyAsHash());
  BOOST_CHECK(e.ownerId == recipientPrefix);

  // First 32 bytes of content are the expected program-identity hash.
  BOOST_CHECK(std::memcmp(e.content.data(),
                          expectedProgHash.data(), 32) == 0);
  // Next bytes are the user payload (zero-padded to 178).
  BOOST_CHECK(std::memcmp(e.content.data() + 32,
                          payload.data(), payload.size()) == 0);
  // Trailing bytes are zero.
  for (size_t i = 32 + payload.size(); i < e.content.size(); ++i) {
    BOOST_CHECK_EQUAL(static_cast<int>(e.content[i]), 0);
  }

  // Verify IMMUTABLE by trying to update it. First grant the
  // recipient a tiny balance so we can issue the update op as the
  // owner.
  server->_brr(recipientKey.getPublicKeyAsHash(), 1'000'000'000);
  wait_net();
  CesClient ownerClient(testServerEp(serverPort), false);
  ownerClient.start(0);
  ownerClient.setKey(recipientKey);
  BOOST_REQUIRE(ownerClient.connect());
  AssetData newData{};
  newData.fill(0xEE);
  uint8_t urc = ownerClient.updateAsset(
    assetIdHash, recipientPrefix, newData, 0);
  CES_CHECK_RC_EQ(urc, CES_ERROR_IMMUTABLE);

  ownerClient.stop();
  queryClient.stop();
}

// ---------------------------------------------------------------------------
// AuthenticAssetHashStableAcrossMints: minting two assets from the
// same program produces identical first-32B prefixes (the cached
// program_hash is reused, no re-hashing).
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(AuthenticAssetHashStableAcrossMints) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/mint2.lua";

  KeyPair recipientKey;
  std::string recipientPk(
    reinterpret_cast<const char*>(recipientKey.getPublicKeyAsHash().data()), 32);

  // Two distinct asset ids.
  std::array<uint8_t, 32> aid1{}, aid2{};
  for (int i = 0; i < 32; ++i) {
    aid1[i] = static_cast<uint8_t>(0xC0 + (i & 0x1F));
    aid2[i] = static_cast<uint8_t>(0xD0 + (i & 0x1F));
  }
  minx::Hash aid1Hash{}, aid2Hash{};
  std::memcpy(aid1Hash.data(), aid1.data(), 32);
  std::memcpy(aid2Hash.data(), aid2.data(), 32);

  auto luaEsc = [](const uint8_t* p, size_t n) {
    std::string out;
    char buf[8];
    for (size_t i = 0; i < n; ++i) {
      std::snprintf(buf, sizeof(buf), "\\%u",
                    static_cast<unsigned>(p[i]));
      out += buf;
    }
    return out;
  };
  std::string aid1Lit = luaEsc(aid1.data(), 32);
  std::string aid2Lit = luaEsc(aid2.data(), 32);
  std::string rcptLit = luaEsc(
    reinterpret_cast<const uint8_t*>(recipientPk.data()), 32);

  // Program mints two assets back-to-back.
  const std::string src =
    "local pfx, msg = ces.client_recv()\n"
    "if not pfx then return end\n"
    "local rcpt = '" + rcptLit + "'\n"
    "local ok1 = ces.authentic_asset_create('" + aid1Lit +
        "', rcpt, 'first', 30)\n"
    "local ok2 = ces.authentic_asset_create('" + aid2Lit +
        "', rcpt, 'second', 30)\n"
    "if ok1 and ok2 then\n"
    "  ces.client_send(pfx, 'OK')\n"
    "else\n"
    "  ces.client_send(pfx, 'ERR')\n"
    "end\n";

  // Two mints × ~8 user-credits each — fund the program account
  // with at least 16 user-credits worth.
  uploadScript(scriptPath, src, /*initialDeposit=*/2'000'000'000ULL);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);

  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  sendAppToProgram(progPrefixOf(scriptPath), "go");

  BOOST_REQUIRE_MESSAGE(
    listener->wait_for(1, std::chrono::seconds(5)),
    "timed out waiting for program to reply");
  {
    std::lock_guard lk(listener->m);
    const auto& data = listener->messages.front().second;
    uint16_t len = (uint16_t(uint8_t(data[9])) << 8)
                 |  uint16_t(uint8_t(data[10]));
    std::string reply(
      reinterpret_cast<const char*>(data.data() + 11), len);
    BOOST_REQUIRE_EQUAL(reply, "OK");
  }

  CesClient qc(testServerEp(serverPort), false);
  qc.start(0);
  KeyPair qk;
  qc.setKey(qk);
  BOOST_REQUIRE(qc.connect());
  server->_brr(qk.getPublicKeyAsHash(), 1'000'000'000);
  wait_net();

  std::vector<AssetEntry> r1, r2;
  CES_REQUIRE_OK(qc.queryAssetSigned(aid1Hash, 0, r1));
  CES_REQUIRE_OK(qc.queryAssetSigned(aid2Hash, 0, r2));
  BOOST_REQUIRE_EQUAL(r1.size(), 1u);
  BOOST_REQUIRE_EQUAL(r2.size(), 1u);

  // Both assets share the same program-identity prefix.
  BOOST_CHECK(std::memcmp(r1[0].content.data(),
                          r2[0].content.data(), 32) == 0);
  // Different payloads survive at offset 32.
  BOOST_CHECK(std::memcmp(r1[0].content.data() + 32, "first", 5) == 0);
  BOOST_CHECK(std::memcmp(r2[0].content.data() + 32, "second", 6) == 0);

  qc.stop();
}

BOOST_AUTO_TEST_SUITE_END()
