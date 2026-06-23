// ===========================================================================
// Compute-program remote ledger verbs — two-server integration.
// ===========================================================================
//
// A Lua compute program holds its own account (program_pubkey) and packs a
// CesClient, so it can reach ledgers on its home server and on remote servers.
// Server A hosts a command-driven program (spawned in a real cesluajitd child);
// server B is a plain ledger the program reaches over the network. Exercises
// the cross-server quadrants end to end — ces.remote_account_read,
// ces.remote_transfer, ces.cross_transfer and ces.remote_cross_transfer —
// across success and the failure paths (account/dest not found, insufficient
// balance, bad address, unknown peer).
//
// The test "client" is a local Minx with a capturing listener; it drives the
// program with CES_APP_COMPUTE_MSG commands and reads the program's replies.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"
#include "test_e2e_common.h"

#include <ces/l2/compute_client.h>
#include <ces/l2/file_client.h>
#include <ces/buffer.h>
#include <ces/account.h>
#include <ces/ramfilestore.h> // ces::sha256
#include <ces/server.h>

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

  bool wait_for(size_t minCount, std::chrono::milliseconds timeout) {
    std::unique_lock lk(m);
    return cv.wait_for(lk, timeout,
                       [&] { return messages.size() >= minCount; });
  }
};

struct ComputeRemoteFixture {
  // Server A — hosts the program.
  std::unique_ptr<CesServer> serverA;
  fs::path dirA;
  uint16_t portA = 0;
  uint16_t rpcA = 0;
  std::string luajitBin;

  // Server B — remote ledger target.
  std::unique_ptr<CesServer> serverB;
  fs::path dirB;
  uint16_t portB = 0;

  KeyPair ownerKey;   // owner of the source file on A
  KeyPair clientKey;  // test client that drives the program

  std::unique_ptr<CaptureListener> listener;
  std::unique_ptr<minx::Minx> clientMinx;
  boost::asio::io_context clientNetIO, clientTaskIO;
  using WG = boost::asio::executor_work_guard<
    boost::asio::io_context::executor_type>;
  std::unique_ptr<WG> clientNetGuard, clientTaskGuard;
  std::thread clientNetThread, clientTaskThread;
  uint16_t clientPort = 0;

  ComputeRemoteFixture() {
    blog::init();
    blog::set_level(blog::fatal);
    blog::set_level("plex", blog::fatal);

    luajitBin = ces::e2e::findBinary("cesluajitd");

    // --- Server A (compute + file) ---
    dirA = makeUniqueTempDir("compute_remote_a");
    minx::Hash privA; privA.fill(0xA1);
    CesConfig cfgA = makeTestConfig(
      dirA, privA, std::numeric_limits<uint64_t>::max());
    cfgA.rpcPort = 0;
    cfgA.rpcAutoPort = true;
    cfgA.cesplexMounts = {
      {"/ces/file/1",    "builtin:file"},
      {"/ces/compute/1", "builtin:compute"},
    };
    cfgA.cesFileStoreMaxBytes = 16ull * 1024 * 1024;
    cfgA.feeFileRent = 1;
    cfgA.computeMaxInstances = 4;
    // Static client-port range so the program's outbound CES client has a
    // bound port (range 0 = networking disabled). Base below the OS
    // ephemeral floor to avoid collisions; tests run sequentially so the
    // small fixed range is safe.
    cfgA.computePortBase = 28000;
    cfgA.computePortCount = 8;
    cfgA.feeComputeSlotSec = 1;
    cfgA.cesComputeChildBinary = luajitBin;
    cfgA.cesComputeUser = "";
    cfgA.cesComputeWorkDir = (dirA / "cescompute").string();
    serverA = std::make_unique<CesServer>(cfgA);
    portA = serverA->start(0);
    BOOST_REQUIRE(portA > 0);
    rpcA = serverA->_rpcBoundPort();
    BOOST_REQUIRE(rpcA > 0);
    serverA->_brr(ownerKey.getPublicKeyAsHash(),  10'000'000'000);
    serverA->_brr(clientKey.getPublicKeyAsHash(), 10'000'000'000);

    // --- Server B (plain ledger target) ---
    dirB = makeUniqueTempDir("compute_remote_b");
    minx::Hash privB; privB.fill(0xB2);
    CesConfig cfgB = makeTestConfig(
      dirB, privB, std::numeric_limits<uint64_t>::max());
    serverB = std::make_unique<CesServer>(cfgB);
    portB = serverB->start(0);
    BOOST_REQUIRE(portB > 0);

    // --- Test client Minx on A ---
    listener = std::make_unique<CaptureListener>();
    minx::MinxConfig mc{};
    mc.instanceName = "trm";
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
    BOOST_REQUIRE(clientPort > 0);

    minx::SockAddr clientLoop(boost::asio::ip::make_address("::1"), clientPort);
    HashPrefix clientPfx = Account::getMapKey(clientKey.getPublicKeyAsHash());
    serverA->_primePresence(clientPfx, clientLoop);
    wait_net();
  }

  ~ComputeRemoteFixture() {
    if (clientMinx) clientMinx->closeSocket(false);
    if (clientNetGuard) clientNetGuard->reset();
    if (clientTaskGuard) clientTaskGuard->reset();
    clientNetIO.stop();
    clientTaskIO.stop();
    if (clientNetThread.joinable()) clientNetThread.join();
    if (clientTaskThread.joinable()) clientTaskThread.join();
    clientMinx.reset();
    if (serverA) serverA->stop();
    if (serverB) serverB->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    boost::system::error_code ec;
    fs::remove_all(dirA, ec);
    fs::remove_all(dirB, ec);
  }

  std::string bAddr() const { return "::1:" + std::to_string(portB); }

  void uploadScript(const std::string& path, const std::string& source) {
    CesFileClient fc;
    fc.setServerPubkey(serverA->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(fc.connect("localhost", rpcA, ownerKey));
    uint64_t bal = 0, cost = 0;
    CES_REQUIRE_OK(fc.create(path, source.size(), 0, 100'000'000ULL,
                             bal, cost));
    ces::Bytes content(source.begin(), source.end());
    CES_REQUIRE_OK(fc.write(path, 0, content, bal));
    fc.disconnect();
  }

  uint64_t launchScript(const std::string& path) {
    CesComputeClient cc;
    cc.setServerPubkey(serverA->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(cc.connect("localhost", rpcA, ownerKey));
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

  void sendApp(const std::array<uint8_t, 8>& pfx, const ces::Bytes& payload) {
    minx::Bytes pkt;
    ces::Buffer::put<uint8_t>(pkt, 0);
    pkt.insert(pkt.end(), pfx.begin(), pfx.end());
    ces::Buffer::put<uint16_t>(pkt, static_cast<uint16_t>(payload.size()));
    pkt.insert(pkt.end(), payload.begin(), payload.end());
    minx::SockAddr srv(boost::asio::ip::make_address("::1"), portA);
    clientMinx->sendApplication(srv, pkt, CES_APP_COMPUTE_MSG);
  }

  // Send one command to the program, wait for the next reply, return its
  // payload as a string. `prog` is the program's prog_pfx.
  std::string cmd(const std::array<uint8_t, 8>& prog, const ces::Bytes& body) {
    size_t before;
    { std::lock_guard lk(listener->m); before = listener->messages.size(); }
    sendApp(prog, body);
    BOOST_REQUIRE_MESSAGE(listener->wait_for(before + 1, std::chrono::seconds(8)),
                          "timed out waiting for program reply");
    std::pair<uint8_t, minx::Bytes> got;
    { std::lock_guard lk(listener->m); got = listener->messages.back(); }
    const auto& data = got.second;
    BOOST_REQUIRE(data.size() >= 11);
    uint16_t len = ces::Buffer::peek<uint16_t>(
      reinterpret_cast<const uint8_t*>(data.data()) + 9);
    BOOST_REQUIRE_EQUAL(data.size(), static_cast<size_t>(11) + len);
    return std::string(reinterpret_cast<const char*>(data.data() + 11), len);
  }

  static ces::Bytes u64be(uint64_t v) {
    ces::Bytes b; ces::Buffer::put<uint64_t>(b, v); return b;
  }

  // Establish a mutual reachable A<->B peering with seeded reserves, so
  // cross-transfers settle without the peer-miner loop.
  void setupPeering() {
    auto akey = serverA->_serverKeyPair().getPublicKeyAsHash();
    auto bkey = serverB->_serverKeyPair().getPublicKeyAsHash();
    serverA->_markPeerReachable(bkey, "localhost:" + std::to_string(portB));
    serverB->_markPeerReachable(akey, "localhost:" + std::to_string(portA));
    serverB->_brr(akey, 1'000'000'000); // A's reserve on B
    serverA->_brr(bkey, 1'000'000'000); // B's reserve on A
  }

  // Poll an account on `srv` until its balance reaches `want` (cross-transfer
  // settlement is async) or a timeout; returns the last-read balance.
  int64_t pollBalance(CesServer* srv, const minx::Hash& pk, int64_t want) {
    int64_t bal = 0;
    for (int i = 0; i < 120; ++i) {
      uint32_t n = 0; HashPrefix d{}; uint64_t a = 0; uint32_t t = 0;
      srv->unsignedQueryAccount(Account::getMapKey(pk), bal, n, d, a, t);
      if (bal >= want) return bal;
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return bal;
  }
};

// Command-driven driver. ops: 0 = report program pubkey; 1 = remote_account_read;
// 2 = remote_transfer; 3 = cross_transfer; 4 = remote_cross_transfer;
// 5 = peer_info(addr, index).
const char* kDriver =
  "local function be64(s, off)\n"
  "  local v = 0\n"
  "  for i = 0, 7 do v = v * 256 + string.byte(s, off + i) end\n"
  "  return v\n"
  "end\n"
  "while true do\n"
  "  local pfx, msg = ces.client_recv()\n"
  "  if not pfx then break end\n"
  "  local op = string.byte(msg, 1)\n"
  "  if op == 0 then\n"
  "    ces.client_send(pfx, ces.program_pubkey())\n"
  "  elseif op == 1 then\n"
  "    local pubkey = string.sub(msg, 2, 33)\n"
  "    local addr = string.sub(msg, 34)\n"
  "    local bal, nonce = ces.remote_account_read(addr, pubkey)\n"
  "    if bal then\n"
  "      ces.client_send(pfx, 'OK ' .. string.format('%.0f', bal))\n"
  "    else\n"
  "      ces.client_send(pfx, 'ERR ' .. tostring(nonce))\n"
  "    end\n"
  "  elseif op == 2 then\n"
  "    local dest = string.sub(msg, 2, 33)\n"
  "    local amount = be64(msg, 34)\n"
  "    local addr = string.sub(msg, 42)\n"
  "    local ok, second = ces.remote_transfer(addr, dest, amount)\n"
  "    if ok then\n"
  "      ces.client_send(pfx, 'OK ' .. string.format('%.0f', second))\n"
  "    else\n"
  "      ces.client_send(pfx, 'ERR ' .. tostring(second))\n"
  "    end\n"
  "  elseif op == 3 then\n"
  "    local dest = string.sub(msg, 2, 33)\n"
  "    local amount = be64(msg, 34)\n"
  "    local dsrv = string.sub(msg, 42)\n"
  "    local ok, second = ces.cross_transfer(dest, amount, dsrv)\n"
  "    if ok then\n"
  "      ces.client_send(pfx, 'OK ' .. string.format('%.0f', second))\n"
  "    else\n"
  "      ces.client_send(pfx, 'ERR ' .. tostring(second))\n"
  "    end\n"
  "  elseif op == 4 then\n"
  "    local dest = string.sub(msg, 2, 33)\n"
  "    local amount = be64(msg, 34)\n"
  "    local dlen = string.byte(msg, 42)\n"
  "    local dial = string.sub(msg, 43, 42 + dlen)\n"
  "    local dsrv = string.sub(msg, 43 + dlen)\n"
  "    local ok, second = ces.remote_cross_transfer(dial, dest, amount, dsrv)\n"
  "    if ok then\n"
  "      ces.client_send(pfx, 'OK ' .. string.format('%.0f', second))\n"
  "    else\n"
  "      ces.client_send(pfx, 'ERR ' .. tostring(second))\n"
  "    end\n"
  "  elseif op == 5 then\n"
  "    local index = string.byte(msg, 2)\n"
  "    local addr = string.sub(msg, 3)\n"
  "    local r, err = ces.peer_info(addr, index)\n"
  "    if r then\n"
  "      ces.client_send(pfx, 'OK ' .. tostring(r.count) .. ' ' ..\n"
  "                       tostring(r.found) .. ' ' .. (r.address or ''))\n"
  "    else\n"
  "      ces.client_send(pfx, 'ERR ' .. tostring(err))\n"
  "    end\n"
  "  end\n"
  "end\n";

} // namespace

BOOST_FIXTURE_TEST_SUITE(ComputeRemoteTests, ComputeRemoteFixture)

// Launch the driver, return its prog_pfx and program pubkey (32B).
static std::array<uint8_t, 8> g_unused;

BOOST_AUTO_TEST_CASE(RemoteAccountReadSuccess) {
  const std::string path = "/h/" + ownerKey.getPublicKeyHexStr() + "/drv.lua";
  uploadScript(path, kDriver);
  BOOST_REQUIRE(launchScript(path) > 0);
  auto prog = progPrefixOf(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(250));

  // Fund a known account X on server B.
  KeyPair x;
  serverB->_brr(x.getPublicKeyAsHash(), 5000);
  wait_net();

  // op 1: read X on B.
  ces::Bytes c; c.push_back(1);
  auto xpk = x.getPublicKeyAsHash();
  c.insert(c.end(), xpk.data(), xpk.data() + 32);
  std::string addr = bAddr();
  c.insert(c.end(), addr.begin(), addr.end());

  std::string r = cmd(prog, c);
  BOOST_CHECK_MESSAGE(r == "OK 5000", "expected 'OK 5000', got '" << r << "'");
}

BOOST_AUTO_TEST_CASE(RemoteAccountReadUnknownIsZero) {
  const std::string path = "/h/" + ownerKey.getPublicKeyHexStr() + "/drv.lua";
  uploadScript(path, kDriver);
  BOOST_REQUIRE(launchScript(path) > 0);
  auto prog = progPrefixOf(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(250));

  KeyPair ghost; // never funded on B
  ces::Bytes c; c.push_back(1);
  auto gpk = ghost.getPublicKeyAsHash();
  c.insert(c.end(), gpk.data(), gpk.data() + 32);
  std::string addr = bAddr();
  c.insert(c.end(), addr.begin(), addr.end());

  std::string r = cmd(prog, c);
  BOOST_CHECK_MESSAGE(r == "OK 0",
                      "expected 'OK 0' for unfunded account, got '" << r << "'");
}

BOOST_AUTO_TEST_CASE(RemoteAccountReadBadAddress) {
  const std::string path = "/h/" + ownerKey.getPublicKeyHexStr() + "/drv.lua";
  uploadScript(path, kDriver);
  BOOST_REQUIRE(launchScript(path) > 0);
  auto prog = progPrefixOf(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(250));

  KeyPair x;
  ces::Bytes c; c.push_back(1);
  auto xpk = x.getPublicKeyAsHash();
  c.insert(c.end(), xpk.data(), xpk.data() + 32);
  std::string addr = "no.such.host.invalid:53999";
  c.insert(c.end(), addr.begin(), addr.end());

  std::string r = cmd(prog, c);
  BOOST_CHECK_MESSAGE(r.rfind("ERR", 0) == 0,
                      "expected ERR for bad address, got '" << r << "'");
}

BOOST_AUTO_TEST_CASE(RemoteTransferSuccess) {
  const std::string path = "/h/" + ownerKey.getPublicKeyHexStr() + "/drv.lua";
  uploadScript(path, kDriver);
  BOOST_REQUIRE(launchScript(path) > 0);
  auto prog = progPrefixOf(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(250));

  // op 0: learn the program's pubkey, fund that account on B.
  ces::Bytes probe; probe.push_back(0);
  std::string ppkStr = cmd(prog, probe);
  BOOST_REQUIRE_EQUAL(ppkStr.size(), 32u);
  minx::Hash progPk{};
  std::memcpy(progPk.data(), ppkStr.data(), 32);
  serverB->_brr(progPk, 10'000'000);

  // A destination that already exists on B. (ces.remote_transfer is an OPEN
  // transfer and would create a missing dest — see RemoteTransferCreatesDest —
  // but here Y pre-exists, so this checks the credit-existing path.)
  KeyPair y;
  serverB->_brr(y.getPublicKeyAsHash(), 1);
  wait_net();

  // op 2: transfer 3000 from program account to Y on B.
  ces::Bytes c; c.push_back(2);
  auto ypk = y.getPublicKeyAsHash();
  c.insert(c.end(), ypk.data(), ypk.data() + 32);
  auto amt = u64be(3000);
  c.insert(c.end(), amt.begin(), amt.end());
  std::string addr = bAddr();
  c.insert(c.end(), addr.begin(), addr.end());

  std::string r = cmd(prog, c);
  BOOST_CHECK_MESSAGE(r.rfind("OK", 0) == 0,
                      "expected OK for transfer, got '" << r << "'");

  // Verify Y received the credit on B.
  int64_t ybal = 0; uint32_t yn = 0; HashPrefix yld{};
  uint64_t yla = 0; uint32_t ylt = 0;
  serverB->unsignedQueryAccount(Account::getMapKey(y.getPublicKeyAsHash()),
                                ybal, yn, yld, yla, ylt);
  BOOST_CHECK_EQUAL(ybal, 1 + 3000);
}

// ces.remote_transfer is an OPEN transfer: a destination that does not yet
// exist on the remote is created, not rejected. (The human-facing cesh transfer
// stays "safe" — see test_cesh_e2e — but a program paying out wants the account
// made, like the funding worker and the local ces.transfer.)
BOOST_AUTO_TEST_CASE(RemoteTransferCreatesDest) {
  const std::string path = "/h/" + ownerKey.getPublicKeyHexStr() + "/drv.lua";
  uploadScript(path, kDriver);
  BOOST_REQUIRE(launchScript(path) > 0);
  auto prog = progPrefixOf(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(250));

  // Fund the program account on B generously: an open transfer that CREATES the
  // dest also pays the account-creation cost (a few days of feeAccount), so the
  // tight 10M used by the credit-existing case isn't enough here.
  ces::Bytes probe; probe.push_back(0);
  std::string ppkStr = cmd(prog, probe);
  BOOST_REQUIRE_EQUAL(ppkStr.size(), 32u);
  minx::Hash progPk{};
  std::memcpy(progPk.data(), ppkStr.data(), 32);
  serverB->_brr(progPk, 1'000'000'000);

  // Y is NOT created on B; the open transfer must create it.
  KeyPair y;
  wait_net();

  ces::Bytes c; c.push_back(2);
  auto ypk = y.getPublicKeyAsHash();
  c.insert(c.end(), ypk.data(), ypk.data() + 32);
  auto amt = u64be(3000);
  c.insert(c.end(), amt.begin(), amt.end());
  std::string addr = bAddr();
  c.insert(c.end(), addr.begin(), addr.end());

  std::string r = cmd(prog, c);
  BOOST_CHECK_MESSAGE(r.rfind("OK", 0) == 0,
                      "expected OK creating dest, got '" << r << "'");

  // Y now exists on B with exactly the transferred amount.
  int64_t ybal = 0; uint32_t yn = 0; HashPrefix yld{};
  uint64_t yla = 0; uint32_t ylt = 0;
  serverB->unsignedQueryAccount(Account::getMapKey(y.getPublicKeyAsHash()),
                                ybal, yn, yld, yla, ylt);
  BOOST_CHECK_EQUAL(ybal, 3000);
}

BOOST_AUTO_TEST_CASE(RemoteTransferInsufficient) {
  const std::string path = "/h/" + ownerKey.getPublicKeyHexStr() + "/drv.lua";
  uploadScript(path, kDriver);
  BOOST_REQUIRE(launchScript(path) > 0);
  auto prog = progPrefixOf(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(250));

  ces::Bytes probe; probe.push_back(0);
  std::string ppkStr = cmd(prog, probe);
  BOOST_REQUIRE_EQUAL(ppkStr.size(), 32u);
  minx::Hash progPk{};
  std::memcpy(progPk.data(), ppkStr.data(), 32);
  serverB->_brr(progPk, 100); // tiny balance

  KeyPair y;
  serverB->_brr(y.getPublicKeyAsHash(), 1);
  wait_net();

  ces::Bytes c; c.push_back(2);
  auto ypk = y.getPublicKeyAsHash();
  c.insert(c.end(), ypk.data(), ypk.data() + 32);
  auto amt = u64be(1'000'000); // far more than 100
  c.insert(c.end(), amt.begin(), amt.end());
  std::string addr = bAddr();
  c.insert(c.end(), addr.begin(), addr.end());

  std::string r = cmd(prog, c);
  BOOST_CHECK_MESSAGE(r.rfind("ERR", 0) == 0,
                      "expected ERR for insufficient balance, got '" << r << "'");
}

BOOST_AUTO_TEST_CASE(CrossTransferUnknownPeer) {
  const std::string path = "/h/" + ownerKey.getPublicKeyHexStr() + "/drv.lua";
  uploadScript(path, kDriver);
  BOOST_REQUIRE(launchScript(path) > 0);
  auto prog = progPrefixOf(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(250));

  // op 3: cross_transfer to a server A has no peering with → UNKNOWN_PEER.
  ces::Bytes c; c.push_back(3);
  KeyPair dest;
  auto dpk = dest.getPublicKeyAsHash();
  c.insert(c.end(), dpk.data(), dpk.data() + 32);
  auto amt = u64be(100);
  c.insert(c.end(), amt.begin(), amt.end());
  std::string dsrv = bAddr(); // B is not a configured peer of A
  c.insert(c.end(), dsrv.begin(), dsrv.end());

  std::string r = cmd(prog, c);
  BOOST_CHECK_MESSAGE(r.rfind("ERR", 0) == 0,
                      "expected ERR for unknown peer, got '" << r << "'");
}

BOOST_AUTO_TEST_CASE(CrossTransferSuccess) {
  setupPeering();
  const std::string path = "/h/" + ownerKey.getPublicKeyHexStr() + "/drv.lua";
  uploadScript(path, kDriver);
  BOOST_REQUIRE(launchScript(path) > 0);
  auto prog = progPrefixOf(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(250));

  // Fund the program's home account on A — cross_transfer spends from it.
  ces::Bytes probe; probe.push_back(0);
  std::string ppkStr = cmd(prog, probe);
  BOOST_REQUIRE_EQUAL(ppkStr.size(), 32u);
  minx::Hash progPk{};
  std::memcpy(progPk.data(), ppkStr.data(), 32);
  serverA->_brr(progPk, 10'000'000);

  // op 3: home cross_transfer of the program's A-funds to a dest on peer B.
  KeyPair dest;
  ces::Bytes c; c.push_back(3);
  auto dpk = dest.getPublicKeyAsHash();
  c.insert(c.end(), dpk.data(), dpk.data() + 32);
  auto amt = u64be(3000);
  c.insert(c.end(), amt.begin(), amt.end());
  std::string dsrv = "localhost:" + std::to_string(portB);
  c.insert(c.end(), dsrv.begin(), dsrv.end());

  std::string r = cmd(prog, c);
  BOOST_CHECK_MESSAGE(r.rfind("OK", 0) == 0,
                      "expected OK for cross_transfer, got '" << r << "'");
  // Async settlement — poll the dest account on B for the credit.
  int64_t db = pollBalance(serverB.get(), dest.getPublicKeyAsHash(), 3000);
  BOOST_CHECK_EQUAL(db, 3000);
}

BOOST_AUTO_TEST_CASE(RemoteCrossTransferSuccess) {
  setupPeering();
  const std::string path = "/h/" + ownerKey.getPublicKeyHexStr() + "/drv.lua";
  uploadScript(path, kDriver);
  BOOST_REQUIRE(launchScript(path) > 0);
  auto prog = progPrefixOf(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(250));

  // Fund the program's account on B — it signs the cross op there.
  ces::Bytes probe; probe.push_back(0);
  std::string ppkStr = cmd(prog, probe);
  BOOST_REQUIRE_EQUAL(ppkStr.size(), 32u);
  minx::Hash progPk{};
  std::memcpy(progPk.data(), ppkStr.data(), 32);
  serverB->_brr(progPk, 10'000'000);

  // op 4: dial B, have B cross-transfer the program's B-funds to a dest on A.
  KeyPair dest;
  ces::Bytes c; c.push_back(4);
  auto dpk = dest.getPublicKeyAsHash();
  c.insert(c.end(), dpk.data(), dpk.data() + 32);
  auto amt = u64be(3000);
  c.insert(c.end(), amt.begin(), amt.end());
  std::string dial = bAddr(); // "::1:<portB>"
  c.push_back(static_cast<uint8_t>(dial.size()));
  c.insert(c.end(), dial.begin(), dial.end());
  std::string dsrv = "localhost:" + std::to_string(portA);
  c.insert(c.end(), dsrv.begin(), dsrv.end());

  std::string r = cmd(prog, c);
  BOOST_CHECK_MESSAGE(r.rfind("OK", 0) == 0,
                      "expected OK for remote_cross_transfer, got '" << r << "'");
  int64_t da = pollBalance(serverA.get(), dest.getPublicKeyAsHash(), 3000);
  BOOST_CHECK_EQUAL(da, 3000);
}

BOOST_AUTO_TEST_CASE(PeerInfoReadsRemotePeerTable) {
  setupPeering();   // serverB's peer table now holds A at localhost:<portA>
  const std::string path = "/h/" + ownerKey.getPublicKeyHexStr() + "/drv.lua";
  uploadScript(path, kDriver);
  BOOST_REQUIRE(launchScript(path) > 0);
  auto prog = progPrefixOf(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(250));

  std::string addr = bAddr();

  // op 5: read serverB's peer-table slot 0 (B peers A at localhost:<portA>).
  ces::Bytes c; c.push_back(5); c.push_back(0);
  c.insert(c.end(), addr.begin(), addr.end());
  std::string r = cmd(prog, c);
  std::string want = "OK 1 true localhost:" + std::to_string(portA);
  BOOST_CHECK_MESSAGE(r == want, "expected '" << want << "', got '" << r << "'");

  // op 5 past the end: count still reported, found=false, no address.
  ces::Bytes c2; c2.push_back(5); c2.push_back(99);
  c2.insert(c2.end(), addr.begin(), addr.end());
  std::string r2 = cmd(prog, c2);
  BOOST_CHECK_MESSAGE(r2 == "OK 1 false ", "expected 'OK 1 false ', got '" << r2 << "'");
}

BOOST_AUTO_TEST_SUITE_END()
