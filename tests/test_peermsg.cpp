// test_peermsg.cpp -- the mesh message primitive (ces.peer.send / ces.peer.listen)
// across TWO real rpc-enabled CesServers in ONE process.
//
// This is the first runtime test of ces.peer. The primitive was built but
// never exercised in isolation: the full server-to-server path needs two
// rpc-enabled servers, and the old gServer singleton clobbered the second one.
// The per-server-object refactor removed that singleton, so two (or N) full L2
// servers now coexist in one process and the mesh path can be driven directly.
//
// Topology: node A and node B, mutual peer-table entries, linked over
// /ces/peer/1 (lower-pubkey dials; reconcileNow drives it without the tick).
// Each runs a real cesluajitd instance:
//   B (echo): ces.peer.listen('mesh', f); f replies 'PONG' to the sender.
//   A (probe): retries ces.peer.send(B, 'mesh', 'PING') and, on the FIRST
//              'PONG' back, transfers 7 to a beacon on A.
// Observing the beacon on A reach 1+7 proves the whole round trip: A->B send,
// B receives with a usable `from` pubkey, B->A reply send, A receives. The
// reply is addressed to `from`, so correct from-routing is asserted implicitly.

#include "test_common.h"
#include "test_e2e_common.h"   // ces::e2e::findBinary

#include <ces/account.h>
#include <ces/client.h>
#include <ces/keys.h>
#include <ces/server.h>
#include <ces/l2/compute_client.h>
#include <ces/l2/compute_handler.h>
#include <ces/l2/file_client.h>
#include <ces/l2/file_handler.h>      // FileHandler::readProgramPubkey
#include <ces/l2/peer_handler.h>

#include <boost/asio/ip/address.hpp>
#include <boost/test/unit_test.hpp>

#include <array>
#include <chrono>
#include <cstdio>
#include <memory>
#include <string>
#include <thread>

using namespace ces;

namespace {

// Bake raw bytes as a Lua string literal using 3-digit \ddd escapes
// (zero-padded so there's never any digit-run ambiguity).
std::string luaBytes(const uint8_t* p, size_t n) {
  std::string s;
  char buf[8];
  for (size_t i = 0; i < n; i++) {
    std::snprintf(buf, sizeof(buf), "\\%03u", static_cast<unsigned>(p[i]));
    s += buf;
  }
  return s;
}

// One in-process node: a full L2 server backed by the REAL cesluajitd child,
// plus a CesClient on the main port for balance queries.
struct Node {
  fs::path dir;
  std::unique_ptr<CesServer> server;
  std::unique_ptr<CesClient> client;
  uint16_t mainPort = 0;
  uint16_t rpcPort = 0;
  minx::Hash serverPub;
  KeyPair owner;

  void start(const std::string& childBin, uint8_t privByte) {
    dir = makeUniqueTempDir("peermsg");
    minx::Hash priv;
    priv.fill(privByte);
    CesConfig cfg =
      makeTestConfig(dir, priv, std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = {
      {"/ces/file/1",    "builtin:file"},
      {"/ces/compute/1", "builtin:compute"},
      {"/ces/lua/1",     "builtin:lua"},
      {"/ces/peer/1",    "builtin:peer"},
    };
    cfg.cesFileStoreMaxBytes = 16ull * 1024 * 1024;
    cfg.feeFileRent = 1;
    cfg.computeMaxInstances = 4;
    cfg.computePortBase = 0;          // ces.peer rides the server link, no port
    cfg.computePortCount = 0;
    cfg.feeComputeSlotSec = 0;
    cfg.cesComputeChildBinary = childBin;
    cfg.cesComputeWorkDir = (dir / "cescompute").string();

    server = std::make_unique<CesServer>(cfg);
    mainPort = server->start(0);
    rpcPort = server->_rpcBoundPort();
    serverPub = server->_serverKeyPair().getPublicKeyAsHash();
    server->_brr(owner.getPublicKeyAsHash(), 100'000'000'000ll);

    boost::asio::ip::udp::endpoint ep(
      boost::asio::ip::address_v6::loopback(), mainPort);
    client = std::make_unique<CesClient>(ep, false);
    client->start(0);
    client->setKey(owner);
    client->connect();
  }

  ~Node() {
    if (client) client->stop();
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(120));
    boost::system::error_code ec;
    fs::remove_all(dir, ec);
  }

  // Deploy `src` as a privileged /s/ program; return its program-account
  // pubkey. ces.peer is operator-only (registered only for /s/ programs), so
  // the deploy + launch are signed with the server's own key (the /s/ owner).
  std::array<uint8_t, 32> deploy(const std::string& path,
                                 const std::string& src) {
    CesFileClient fc;
    fc.setServerPubkey(serverPub);
    CES_REQUIRE_OK(fc.connect("localhost", rpcPort, server->_serverKeyPair()));
    uint64_t fb = 0, cost = 0;
    CES_REQUIRE_OK(fc.create(path, src.size(), 0, 0, fb, cost));
    ces::Bytes content(src.begin(), src.end());
    CES_REQUIRE_OK(fc.write(path, 0, content, fb));
    fc.disconnect();
    std::array<uint8_t, 32> pk{};
    BOOST_REQUIRE(server->fileHandler()->readProgramPubkey(path, pk));
    return pk;
  }

  uint64_t launch(const std::string& path) {
    CesComputeClient cc;
    cc.setServerPubkey(serverPub);
    CES_REQUIRE_OK(cc.connect("localhost", rpcPort, server->_serverKeyPair()));
    uint64_t id = 0, st = 0;
    CES_REQUIRE_OK(cc.launch(path, id, st));
    cc.disconnect();
    return id;
  }

  int64_t balanceOf(const minx::Hash& pubkey) {
    HashPrefix mapKey = Account::getMapKey(pubkey);
    int64_t bal = 0;
    uint32_t nonce = 0;
    client->queryAccount(mapKey, bal, nonce);
    return bal;
  }
};

bool pollLinked(CesServer* s, const minx::Hash& k) {
  for (int i = 0; i < 200; ++i) {
    if (s->peerHandler() && s->peerHandler()->isLinked(k)) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  return s->peerHandler() && s->peerHandler()->isLinked(k);
}

}  // namespace

BOOST_AUTO_TEST_SUITE(PeerMsgTests)

BOOST_AUTO_TEST_CASE(PeerSendListenRoundTrip) {
  blog::init();
  blog::set_level(blog::fatal);
  const std::string childBin = ces::e2e::findBinary("cesluajitd");

  Node a, b;
  a.start(childBin, 0x21);
  b.start(childBin, 0x22);
  BOOST_REQUIRE(a.rpcPort > 0 && b.rpcPort > 0);
  wait_net();

  // Mutual peer entries with pre-resolved plex endpoints, then link over
  // /ces/peer/1 (dial v6 loopback; rpc binds dual-stack). reconcileNow drives
  // the dial immediately; pollLinked waits for the channel to establish.
  const auto v6lo =
    boost::asio::ip::address(boost::asio::ip::address_v6::loopback());
  a.server->_testAddPeerWithRpc(
    b.serverPub, "[::1]:" + std::to_string(b.rpcPort), v6lo, b.rpcPort);
  b.server->_testAddPeerWithRpc(
    a.serverPub, "[::1]:" + std::to_string(a.rpcPort), v6lo, a.rpcPort);
  a.server->peerHandler()->reconcileNow();
  b.server->peerHandler()->reconcileNow();
  BOOST_REQUIRE_MESSAGE(pollLinked(a.server.get(), b.serverPub),
                        "A did not link to B over /ces/peer/1");
  BOOST_REQUIRE_MESSAGE(pollLinked(b.server.get(), a.serverPub),
                        "B did not link to A over /ces/peer/1");

  // Beacon on A: the observable. Pre-funded 1 so the expected total is 1+7=8.
  KeyPair beacon;
  const auto beaconPk = beacon.getPublicKeyAsHash();
  a.server->_brr(beaconPk, 1);

  // B: echo program. Reply 'PONG' to whoever sent 'PING'.
  const std::string echoSrc =
    "ces.peer.listen('mesh', function(from, msg)\n"
    "  if msg == 'PING' then ces.peer.send(from, 'mesh', 'PONG') end\n"
    "end)\n"
    "ces.run()\n";
  const std::string echoPath = "/s/echo.lua";
  b.deploy(echoPath, echoSrc);
  b.launch(echoPath);

  // A: probe program. Retry PING every 300ms (fire-and-forget; covers link or
  // listener not yet ready), pay the beacon once on the first PONG back.
  const std::string probeSrc =
    "local done = false\n"
    "ces.peer.listen('mesh', function(from, msg)\n"
    "  if not done and msg == 'PONG' then\n"
    "    done = true\n"
    "    ces.transfer('" + luaBytes(beaconPk.data(), 32) + "', 7)\n"
    "  end\n"
    "end)\n"
    "ces.every(300, function()\n"
    "  ces.peer.send('" + luaBytes(b.serverPub.data(), 32) + "', 'mesh', 'PING')\n"
    "end)\n"
    "ces.run()\n";
  const std::string probePath = "/s/probe.lua";
  const auto probePk = a.deploy(probePath, probeSrc);
  a.server->_brr(probePk, 1'000'000'000);   // fund the probe's beacon transfer
  a.launch(probePath);

  // Observe the round trip land on the beacon.
  int64_t bal = 0;
  for (int i = 0; i < 300 && bal < 8; i++) {
    bal = a.balanceOf(beaconPk);
    if (bal < 8) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_CHECK_EQUAL(bal, 8);
}

BOOST_AUTO_TEST_SUITE_END()
