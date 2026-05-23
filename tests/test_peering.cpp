/**
 * Peering tests — automated peer miner builds bilateral reserves.
 *
 * Two CES servers configured as outbound peers of each other.
 * Cache-only RandomX, minDiff=1, zero fees, 2-second miner interval.
 * Tests that the peer miner loop automatically creates bilateral
 * credit reserves without manual intervention.
 */

#include "test_common.h"

#include <ces/buffer.h>
#include <ces/util/wallet.h>
#include <toml++/toml.hpp>
#include <filesystem>

// ces/wallet.h declares ces::fs = std::filesystem, which collides with
// the boost::filesystem `fs` from test_common.h (via `using namespace ces`).
// Use `bfs` for boost::filesystem in this file to disambiguate.
namespace bfs = boost::filesystem;

// Shared config for peering tests: minDiff=1, zero fees, in-memory flush,
// 2 task threads. Tests that need extra knobs (e.g. feeAsset, minAsset,
// peer miner interval) layer them on after this returns.
static CesConfig makePeeringConfig(const bfs::path& dataDir,
                                   const minx::Hash& privKey) {
  CesConfig cfg;
  cfg.dataDir = dataDir;
  cfg.serverPrivKey = privKey;
  cfg.minAcc = 100;
  cfg.maxAcc = 10000;
  cfg.minDiff = 1;
  cfg.spendSlotSize = 10;
  cfg.taskThreads = 2;
  cfg.flushValue = std::numeric_limits<uint64_t>::max();
  cfg.feeAccount = 0;
  cfg.feeTx = 0;
  cfg.feeQuery = 0;
  return cfg;
}

BOOST_AUTO_TEST_SUITE(PeeringTests)

BOOST_AUTO_TEST_CASE(AutomatedBilateralPeering) {
  blog::init();
  blog::set_level(blog::info);


  bfs::path dirA = makeUniqueTempDir("ces_peer_a");
  bfs::path dirB = makeUniqueTempDir("ces_peer_b");

  minx::Hash privA; privA.fill(0xAA);
  minx::Hash privB; privB.fill(0xBB);
  ces::KeyPair kpA(privA);
  ces::KeyPair kpB(privB);

  CesConfig cfgA = makePeeringConfig(dirA, privA);
  cfgA.peerMiningFullDataset = false;
  cfgA.peerMinerIntervalSecs = 2;

  CesConfig cfgB = cfgA;
  cfgB.dataDir = dirB;
  cfgB.serverPrivKey = privB;

  // -- Start Server A --
  auto serverA = std::make_unique<CesServer>(cfgA);
  uint16_t portA = serverA->start(0);
  BOOST_REQUIRE(portA > 0);
  serverA->createPoWEngine(false); // cache-only

  // -- Start Server B --
  auto serverB = std::make_unique<CesServer>(cfgB);
  uint16_t portB = serverB->start(0);
  BOOST_REQUIRE(portB > 0);
  serverB->createPoWEngine(false);

  // Wait for both PoW engines to be ready
  for (int i = 0; i < 300; ++i) {
    if (serverA->isPoWEngineReady() && serverB->isPoWEngineReady()) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  BOOST_REQUIRE_MESSAGE(serverA->isPoWEngineReady(), "A PoW engine not ready");
  BOOST_REQUIRE_MESSAGE(serverB->isPoWEngineReady(), "B PoW engine not ready");

  // Now that we know the ports, rebuild both servers with peer configs.
  // (cfg_.peerTarget is const post-construction, so we need fresh CesServers.)
  serverA->stop();
  serverB->stop();
  serverA.reset();
  serverB.reset();

  cfgA.peerTarget = 100000; // target 100k credits on each peer
  cfgA.peers.push_back({minx::hashToString(kpB.getPublicKeyAsHash()),
                         "localhost:" + std::to_string(portB)});

  cfgB.peerTarget = 100000;
  cfgB.peers.push_back({minx::hashToString(kpA.getPublicKeyAsHash()),
                         "localhost:" + std::to_string(portA)});

  serverA = std::make_unique<CesServer>(cfgA);
  uint16_t portA2 = serverA->start(portA); // reuse same port
  BOOST_REQUIRE_EQUAL(portA2, portA);
  serverA->createPoWEngine(false);

  serverB = std::make_unique<CesServer>(cfgB);
  uint16_t portB2 = serverB->start(portB);
  BOOST_REQUIRE_EQUAL(portB2, portB);
  serverB->createPoWEngine(false);

  // Wait for PoW engines again
  for (int i = 0; i < 300; ++i) {
    if (serverA->isPoWEngineReady() && serverB->isPoWEngineReady()) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  BOOST_REQUIRE(serverA->isPoWEngineReady());
  BOOST_REQUIRE(serverB->isPoWEngineReady());

  // Start peer miners
  serverA->startPeerMiner();
  serverB->startPeerMiner();

  LOGINFO << "Both peer miners started. Waiting for bilateral reserves...";

  // Poll for bilateral balances — timeout after 3 minutes
  auto serverMapKeyA = Account::getMapKey(kpA.getPublicKeyAsHash());
  auto serverMapKeyB = Account::getMapKey(kpB.getPublicKeyAsHash());
  bool aHasBalOnB = false;
  bool bHasBalOnA = false;

  for (int attempt = 0; attempt < 90 && !(aHasBalOnB && bHasBalOnA); ++attempt) {
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Check A's balance on B (query B directly via server API)
    if (!aHasBalOnB) {
      int64_t bal = 0;
      uint32_t nonce = 0;
      HashPrefix xd{};
      uint64_t xa = 0;
      uint32_t xt = 0;
      serverB->unsignedQueryAccount(serverMapKeyA, bal, nonce, xd, xa, xt);
      if (bal > 0) {
        aHasBalOnB = true;
        LOGINFO << "A's balance on B: " << bal;
      }
    }

    // Check B's balance on A
    if (!bHasBalOnA) {
      int64_t bal = 0;
      uint32_t nonce = 0;
      HashPrefix xd{};
      uint64_t xa = 0;
      uint32_t xt = 0;
      serverA->unsignedQueryAccount(serverMapKeyB, bal, nonce, xd, xa, xt);
      if (bal > 0) {
        bHasBalOnA = true;
        LOGINFO << "B's balance on A: " << bal;
      }
    }
  }

  BOOST_CHECK_MESSAGE(aHasBalOnB, "A never got credits on B");
  BOOST_CHECK_MESSAGE(bHasBalOnA, "B never got credits on A");

  // Stop servers (triggers savePeerData on shutdown)
  serverA->stop();
  serverB->stop();
  serverA.reset();
  serverB.reset();
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  // Assert peer data files were written
  auto peerFileA = (dirA / "peerdata.toml").string();
  auto peerFileB = (dirB / "peerdata.toml").string();
  BOOST_CHECK_MESSAGE(std::filesystem::exists(peerFileA),
                      "Server A peerdata.toml not written");
  BOOST_CHECK_MESSAGE(std::filesystem::exists(peerFileB),
                      "Server B peerdata.toml not written");

  // Reload servers and verify peer tables were restored
  auto serverA2 = std::make_unique<CesServer>(cfgA);
  auto serverB2 = std::make_unique<CesServer>(cfgB);

  // Check A's peer table has B with outbound + credits.
  // peerTable_ is private; we verify via the persisted peerdata.toml.
  {
    bool foundB = false;
    auto tbl = toml::parse_file(peerFileA);
    auto peers = tbl["peers"].as_array();
    BOOST_REQUIRE(peers);
    for (auto& p : *peers) {
      auto t = p.as_table();
      BOOST_REQUIRE(t);
      auto key = (*t)["key"].value_or(std::string(""));
      if (key == minx::hashToString(kpB.getPublicKeyAsHash())) {
        foundB = true;
        auto inbound = (*t)["total_inbound_pow"].value_or(int64_t(0));
        auto outbound = (*t)["total_outbound_pow"].value_or(int64_t(0));
        auto balance = (*t)["our_balance"].value_or(int64_t(-1));
        auto isOutbound = (*t)["outbound"].value_or(false);
        BOOST_CHECK(isOutbound);
        BOOST_CHECK_GT(outbound, 0);
        BOOST_CHECK_GE(balance, 0);
        LOGINFO << "A's persisted peer B: outbound_pow=" << outbound
                << " balance=" << balance << " outbound=" << isOutbound;
      }
    }
    BOOST_CHECK_MESSAGE(foundB, "B not found in A's persisted peer table");
  }

  // Check B's peer table has A with outbound + credits
  {
    bool foundA = false;
    auto tbl = toml::parse_file(peerFileB);
    auto peers = tbl["peers"].as_array();
    BOOST_REQUIRE(peers);
    for (auto& p : *peers) {
      auto t = p.as_table();
      BOOST_REQUIRE(t);
      auto key = (*t)["key"].value_or(std::string(""));
      if (key == minx::hashToString(kpA.getPublicKeyAsHash())) {
        foundA = true;
        auto inbound = (*t)["total_inbound_pow"].value_or(int64_t(0));
        auto outbound = (*t)["total_outbound_pow"].value_or(int64_t(0));
        auto balance = (*t)["our_balance"].value_or(int64_t(-1));
        auto isOutbound = (*t)["outbound"].value_or(false);
        BOOST_CHECK(isOutbound);
        BOOST_CHECK_GT(outbound, 0);
        BOOST_CHECK_GE(balance, 0);
        LOGINFO << "B's persisted peer A: outbound_pow=" << outbound
                << " balance=" << balance << " outbound=" << isOutbound;
      }
    }
    BOOST_CHECK_MESSAGE(foundA, "A not found in B's persisted peer table");
  }

  serverA2.reset();
  serverB2.reset();

  // Cleanup
  boost::system::error_code ec;
  bfs::remove_all(dirA, ec);
  bfs::remove_all(dirB, ec);
}

BOOST_AUTO_TEST_CASE(CrossServerTransfer) {
  blog::init();
  blog::set_level(blog::info);


  bfs::path dirA = makeUniqueTempDir("ces_cross_a");
  bfs::path dirB = makeUniqueTempDir("ces_cross_b");

  minx::Hash privA; privA.fill(0xAA);
  minx::Hash privB; privB.fill(0xBB);
  ces::KeyPair kpA(privA);
  ces::KeyPair kpB(privB);
  ces::KeyPair alice; // user on A
  ces::KeyPair bob;   // recipient on B

  CesConfig cfgA = makePeeringConfig(dirA, privA);
  CesConfig cfgB = cfgA;
  cfgB.dataDir = dirB;
  cfgB.serverPrivKey = privB;

  // Start both servers
  auto serverA = std::make_unique<CesServer>(cfgA);
  uint16_t portA = serverA->start(0);
  BOOST_REQUIRE(portA > 0);

  auto serverB = std::make_unique<CesServer>(cfgB);
  uint16_t portB = serverB->start(0);
  BOOST_REQUIRE(portB > 0);

  std::string addrB = "localhost:" + std::to_string(portB);

  // Fund Alice on Server A
  serverA->_brr(alice.getPublicKeyAsHash(), 10000);
  wait_net();

  // Fund Server A's account on Server B (the bilateral reserve)
  serverB->_brr(kpA.getPublicKeyAsHash(), 50000);
  wait_net();

  // Register B as a reachable peer on A
  serverA->_markPeerReachable(kpB.getPublicKeyAsHash(), addrB);

  // Alice sends 5000 credits to Bob on Server B via cross-transfer
  {
    auto ep = boost::asio::ip::udp::endpoint(
      boost::asio::ip::address_v6::loopback(), portA);
    CesClient client(ep, false);
    client.setKey(alice);
    client.start(0);
    BOOST_REQUIRE(client.connect());

    int64_t newBal = 0;
    uint8_t rc = client.crossTransfer(
      bob.getPublicKeyAsHash(), 5000, addrB, newBal);

    CES_CHECK_OK(rc);
    BOOST_CHECK_EQUAL(newBal, 5000); // 10000 - 5000
    LOGINFO << "Cross-transfer result: rc=" << (int)rc << " newBal=" << newBal;

    client.disconnect();
    client.stop();
  }

  wait_net();

  // Verify: Alice's balance on A decreased
  {
    auto mapKey = Account::getMapKey(alice.getPublicKeyAsHash());
    int64_t bal = 0;
    uint32_t nonce = 0;
    HashPrefix xd{};
    uint64_t xa = 0;
    uint32_t xt = 0;
    serverA->unsignedQueryAccount(mapKey, bal, nonce, xd, xa, xt);
    BOOST_CHECK_EQUAL(bal, 5000);
    LOGINFO << "Alice's balance on A: " << bal;
  }

  // Verify: B's vostro on A increased
  {
    auto mapKey = Account::getMapKey(kpB.getPublicKeyAsHash());
    int64_t bal = 0;
    uint32_t nonce = 0;
    HashPrefix xd{};
    uint64_t xa = 0;
    uint32_t xt = 0;
    serverA->unsignedQueryAccount(mapKey, bal, nonce, xd, xa, xt);
    BOOST_CHECK_EQUAL(bal, 5000);
    LOGINFO << "B's vostro on A: " << bal;
  }

  // Wait for async remote delivery
  std::this_thread::sleep_for(std::chrono::seconds(10));

  // Verify: A's reserve on B decreased
  {
    auto mapKey = Account::getMapKey(kpA.getPublicKeyAsHash());
    int64_t bal = 0;
    uint32_t nonce = 0;
    HashPrefix xd{};
    uint64_t xa = 0;
    uint32_t xt = 0;
    serverB->unsignedQueryAccount(mapKey, bal, nonce, xd, xa, xt);
    BOOST_CHECK_EQUAL(bal, 45000); // 50000 - 5000
    LOGINFO << "A's reserve on B: " << bal;
  }

  // Verify: Bob got credits on B
  {
    auto mapKey = Account::getMapKey(bob.getPublicKeyAsHash());
    int64_t bal = 0;
    uint32_t nonce = 0;
    HashPrefix xd{};
    uint64_t xa = 0;
    uint32_t xt = 0;
    serverB->unsignedQueryAccount(mapKey, bal, nonce, xd, xa, xt);
    BOOST_CHECK_EQUAL(bal, 5000);
    LOGINFO << "Bob's balance on B: " << bal;
  }

  // Cleanup
  serverA->stop();
  serverB->stop();
  serverA.reset();
  serverB.reset();
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  boost::system::error_code ec;
  bfs::remove_all(dirA, ec);
  bfs::remove_all(dirB, ec);
}

BOOST_AUTO_TEST_CASE(CrossServerPaymentSettlement) {
  blog::init();
  blog::set_level(blog::info);


  bfs::path dirA = makeUniqueTempDir("ces_pay_a");
  bfs::path dirB = makeUniqueTempDir("ces_pay_b");

  minx::Hash privA; privA.fill(0xAA);
  minx::Hash privB; privB.fill(0xBB);
  ces::KeyPair kpA(privA);
  ces::KeyPair kpB(privB);
  ces::KeyPair alice; // sender on A
  ces::KeyPair bob;   // receiver on B — will create a payment account

  CesConfig cfgA = makePeeringConfig(dirA, privA);
  CesConfig cfgB = cfgA;
  cfgB.dataDir = dirB;
  cfgB.serverPrivKey = privB;

  auto serverA = std::make_unique<CesServer>(cfgA);
  uint16_t portA = serverA->start(0);
  BOOST_REQUIRE(portA > 0);

  auto serverB = std::make_unique<CesServer>(cfgB);
  uint16_t portB = serverB->start(0);
  BOOST_REQUIRE(portB > 0);

  std::string addrB = "localhost:" + std::to_string(portB);

  // Fund Alice on A
  serverA->_brr(alice.getPublicKeyAsHash(), 100000);
  wait_net();

  // Fund A's reserve on B (bilateral liquidity)
  serverB->_brr(kpA.getPublicKeyAsHash(), 500000);
  wait_net();

  // Register B as reachable peer on A
  serverA->_markPeerReachable(kpB.getPublicKeyAsHash(), addrB);

  // Bob creates a payment account on B: "I expect exactly 7000"
  {
    auto ep = boost::asio::ip::udp::endpoint(
      boost::asio::ip::address_v6::loopback(), portB);
    CesClient client(ep, false);
    client.setKey(bob);
    // Bob needs funds to create the payment — fund him first
    serverB->_brr(bob.getPublicKeyAsHash(), 50000);
    wait_net();

    client.start(0);
    BOOST_REQUIRE(client.connect());

    int64_t newBal = 0;
    uint8_t rc = client.createPayment(alice.getPublicKeyAsHash(), 7000, 1, newBal);
    CES_CHECK_OK(rc);
    LOGINFO << "Bob created payment account for Alice on B: rc=" << (int)rc
            << " bobNewBal=" << newBal;

    client.disconnect();
    client.stop();
  }

  wait_net();

  // Verify: Alice's payment account on B has negative balance
  {
    auto mapKey = Account::getMapKey(alice.getPublicKeyAsHash());
    int64_t bal = 0;
    uint32_t nonce = 0;
    HashPrefix xd{};
    uint64_t xa = 0;
    uint32_t xt = 0;
    serverB->unsignedQueryAccount(mapKey, bal, nonce, xd, xa, xt);
    BOOST_CHECK_EQUAL(bal, -7000);
    LOGINFO << "Alice's payment account on B (before): " << bal;
  }

  // Alice cross-transfers exactly 7000 to her payment account on B
  {
    auto ep = boost::asio::ip::udp::endpoint(
      boost::asio::ip::address_v6::loopback(), portA);
    CesClient client(ep, false);
    client.setKey(alice);
    client.start(0);
    BOOST_REQUIRE(client.connect());

    int64_t newBal = 0;
    uint8_t rc = client.crossTransfer(
      alice.getPublicKeyAsHash(), 7000, addrB, newBal);
    CES_CHECK_OK(rc);
    BOOST_CHECK_EQUAL(newBal, 93000); // 100000 - 7000
    LOGINFO << "Alice cross-transfer to payment: rc=" << (int)rc
            << " newBal=" << newBal;

    client.disconnect();
    client.stop();
  }

  wait_net();

  // Wait for async remote delivery
  std::this_thread::sleep_for(std::chrono::seconds(10));

  // Verify: Alice's payment account on B is now settled (balance = 7000)
  {
    auto mapKey = Account::getMapKey(alice.getPublicKeyAsHash());
    int64_t bal = 0;
    uint32_t nonce = 0;
    HashPrefix xd{};
    uint64_t xa = 0;
    uint32_t xt = 0;
    serverB->unsignedQueryAccount(mapKey, bal, nonce, xd, xa, xt);
    BOOST_CHECK_EQUAL(bal, 7000);
    LOGINFO << "Alice's payment account on B (after settlement): " << bal;
  }

  // Verify: Alice's balance on A decreased
  {
    auto mapKey = Account::getMapKey(alice.getPublicKeyAsHash());
    int64_t bal = 0;
    uint32_t nonce = 0;
    HashPrefix xd{};
    uint64_t xa = 0;
    uint32_t xt = 0;
    serverA->unsignedQueryAccount(mapKey, bal, nonce, xd, xa, xt);
    BOOST_CHECK_EQUAL(bal, 93000);
    LOGINFO << "Alice's balance on A: " << bal;
  }

  serverA->stop();
  serverB->stop();
  serverA.reset();
  serverB.reset();
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  boost::system::error_code ec;
  bfs::remove_all(dirA, ec);
  bfs::remove_all(dirB, ec);
}

// ============================================================================
// Auto-nonce dedup — end-to-end via wire replay
// ============================================================================

namespace {

// Minimal MINX client that captures INFO handshake + open-transfer replies.
// Built for dedup replay testing: we need to send the same signed payload
// bytes twice, which CesClient can't do (it resigns each call). So we use
// MinxClientTransport directly and drive the MINX envelope by hand.
class RawMinxListener : public minx::MinxListener {
public:
  std::mutex m;
  std::condition_variable cv;
  bool gotInfo = false;
  uint64_t serverTicket = 0;
  minx::Hash serverKey{};
  std::vector<CesOpenTransferResult> replies;

  void incomingInfo(const minx::SockAddr&, const minx::MinxInfo& msg) override {
    std::lock_guard lk(m);
    gotInfo = true;
    serverTicket = msg.gpassword;
    serverKey = msg.skey;
    cv.notify_all();
  }

  void incomingMessage(const minx::SockAddr&,
                       const minx::MinxMessage& msg) override {
    if (msg.data.empty() || msg.data[0] != CES_OPEN_TRANSFER_RESULT) return;
    CesOpenTransferResult r;
    try { r.fromBytes(msg.data); } catch (...) { return; }
    std::lock_guard lk(m);
    replies.push_back(r);
    serverTicket = msg.gpassword; // accept refreshed ticket
    cv.notify_all();
  }
};

} // anonymous namespace

// Replay the exact same signed CES_OPEN_TRANSFER bytes twice and verify
// that the ledger moves once, not twice — the auto-nonce sig-hash dedup
// must catch the second packet. This covers the dispatch path end-to-end:
// MINX envelope → signature check → CES_NONCELESS timestamp window →
// checkAndInsertDedup → transfer execution.
BOOST_AUTO_TEST_CASE(DedupReplayViaWire) {
  blog::init();
  blog::set_level(blog::info);

  bfs::path dir = makeUniqueTempDir("ces_dedup_e2e");

  minx::Hash priv; priv.fill(0xCD);
  CesConfig cfg;
  cfg.dataDir = dir;
  cfg.serverPrivKey = priv;
  cfg.minAcc = 100;
  cfg.maxAcc = 10000;
  cfg.minDiff = 1;
  cfg.spendSlotSize = 10;
  cfg.minProveWorkTimestamp = 0;
  cfg.taskThreads = 2;
  cfg.flushValue = std::numeric_limits<uint64_t>::max();
  cfg.feeAccount = 0;
  cfg.feeTx = 0;
  cfg.feeQuery = 0;

  auto server = std::make_unique<CesServer>(cfg);
  uint16_t port = server->start(0);
  BOOST_REQUIRE(port > 0);

  ces::KeyPair alice;
  ces::KeyPair bob;
  const int64_t aliceFunding = 1'000'000;
  const uint64_t xferAmount = 1000;
  server->_brr(alice.getPublicKeyAsHash(), aliceFunding);
  wait_net();

  // Stand up a raw MINX client — bypasses CesClient so we can replay bytes.
  RawMinxListener listener;
  boost::asio::ip::udp::endpoint ep(
    boost::asio::ip::address_v6::loopback(), port);
  auto transport = std::make_unique<minx::MinxClientTransport>(&listener, ep);
  transport->setUseDataset(false);
  BOOST_REQUIRE(transport->start(0));

  // Handshake: GET_INFO → INFO gives us a ticket + the server's pubkey
  minx::MinxGetInfo gi{0, transport->generatePassword(), {}};
  transport->sendGetInfo(gi);
  {
    std::unique_lock lk(listener.m);
    BOOST_REQUIRE(listener.cv.wait_for(
      lk, std::chrono::seconds(5), [&] { return listener.gotInfo; }));
  }

  // Build + sign ONE auto-nonce open-transfer envelope — bytes are frozen.
  CesOpenTransfer req;
  req.originId = alice.getPublicKeyAsHash();
  req.serverId = Account::getMapKey(listener.serverKey);
  req.reqNonce = CES_NONCELESS;
  req.destKey = bob.getPublicKeyAsHash();
  req.amount = xferAmount;
  req.time = getMicrosSinceEpoch();
  minx::Bytes signedBytes = req.toBytes(alice);

  // First send — should execute the transfer.
  {
    uint64_t stick;
    { std::lock_guard lk(listener.m); stick = listener.serverTicket; }
    minx::MinxMessage m1{0, transport->generatePassword(), stick, signedBytes};
    transport->sendMessage(m1);
  }
  {
    std::unique_lock lk(listener.m);
    BOOST_REQUIRE(listener.cv.wait_for(
      lk, std::chrono::seconds(5), [&] { return !listener.replies.empty(); }));
    BOOST_CHECK_EQUAL((int)listener.replies[0].rcode, (int)CES_OK);
  }

  // Wait for the ledger mutation to land on logicStrand_.
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  // Sanity: transfer did execute the first time.
  {
    int64_t bal = 0; uint32_t n = 0;
    HashPrefix xd{}; uint64_t xa = 0; uint32_t xt = 0;
    server->unsignedQueryAccount(
      Account::getMapKey(alice.getPublicKeyAsHash()), bal, n, xd, xa, xt);
    BOOST_REQUIRE_EQUAL(bal, aliceFunding - (int64_t)xferAmount);
  }

  // Second send — exact same signed bytes. Dedup must reject it.
  {
    uint64_t stick;
    { std::lock_guard lk(listener.m); stick = listener.serverTicket; }
    minx::MinxMessage m2{0, transport->generatePassword(), stick, signedBytes};
    transport->sendMessage(m2);
  }

  // Give the server plenty of time to process (or fail to process) the replay.
  std::this_thread::sleep_for(std::chrono::seconds(2));

  // Sanity: the replay actually reached the server. Dedup replies with CES_OK
  // (line ~1630 in server.cpp) — so we must see a second reply, distinct from
  // the first. If listener.replies is still size 1 (modulo retransmits), it
  // would mean MINX silently dropped M2 and we'd be passing vacuously.
  {
    std::lock_guard lk(listener.m);
    BOOST_CHECK_GE(listener.replies.size(), 2u);
    for (const auto& r : listener.replies) {
      BOOST_CHECK_EQUAL((int)r.rcode, (int)CES_OK);
    }
  }

  // THE test: Alice debited once, Bob credited once — not twice.
  {
    int64_t aliceBal = 0; uint32_t aliceNonce = 0;
    HashPrefix xd{}; uint64_t xa = 0; uint32_t xt = 0;
    server->unsignedQueryAccount(
      Account::getMapKey(alice.getPublicKeyAsHash()),
      aliceBal, aliceNonce, xd, xa, xt);
    BOOST_CHECK_EQUAL(aliceBal, aliceFunding - (int64_t)xferAmount);

    int64_t bobBal = 0; uint32_t bobNonce = 0;
    server->unsignedQueryAccount(
      Account::getMapKey(bob.getPublicKeyAsHash()),
      bobBal, bobNonce, xd, xa, xt);
    BOOST_CHECK_EQUAL(bobBal, (int64_t)xferAmount);
  }

  transport->stop();
  transport.reset();
  server->stop();
  server.reset();
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  boost::system::error_code ec;
  bfs::remove_all(dir, ec);
}

BOOST_AUTO_TEST_CASE(DedupTimeRejection) {
  // Test that the auto-nonce handler rejects stale/future timestamps.
  // This tests the server-level logic, not just the dedup table.
  bfs::path dirA = makeUniqueTempDir("ces_dtr_a");
  bfs::path dirB = makeUniqueTempDir("ces_dtr_b");

  minx::Hash privA; privA.fill(0xAA);
  minx::Hash privB; privB.fill(0xBB);
  ces::KeyPair kpA(privA);
  ces::KeyPair kpB(privB);
  ces::KeyPair alice;

  CesConfig cfgA = makePeeringConfig(dirA, privA);
  CesConfig cfgB = cfgA;
  cfgB.dataDir = dirB;
  cfgB.serverPrivKey = privB;

  auto serverA = std::make_unique<CesServer>(cfgA);
  uint16_t portA = serverA->start(0);
  BOOST_REQUIRE(portA > 0);

  auto serverB = std::make_unique<CesServer>(cfgB);
  uint16_t portB = serverB->start(0);
  BOOST_REQUIRE(portB > 0);

  std::string addrB = "localhost:" + std::to_string(portB);

  // Fund Alice on A and the reserve on B
  serverA->_brr(alice.getPublicKeyAsHash(), 100000);
  serverB->_brr(kpA.getPublicKeyAsHash(), 500000);
  wait_net();

  // Register B as reachable peer on A
  serverA->_markPeerReachable(kpB.getPublicKeyAsHash(), addrB);

  // Normal auto-nonce transfer should work
  {
    auto ep = boost::asio::ip::udp::endpoint(
      boost::asio::ip::address_v6::loopback(), portA);
    CesClient client(ep, false);
    client.setKey(alice);
    client.start(0);
    BOOST_REQUIRE(client.connect());

    int64_t newBal = 0;
    uint8_t rc = client.crossTransfer(
      alice.getPublicKeyAsHash(), 1000, addrB, newBal);
    CES_CHECK_OK(rc);

    client.disconnect();
    client.stop();
  }

  wait_net();
  std::this_thread::sleep_for(std::chrono::seconds(10));

  // Verify money arrived on B
  {
    auto mapKey = Account::getMapKey(alice.getPublicKeyAsHash());
    int64_t bal = 0;
    uint32_t nonce = 0;
    HashPrefix xd{};
    uint64_t xa = 0;
    uint32_t xt = 0;
    serverB->unsignedQueryAccount(mapKey, bal, nonce, xd, xa, xt);
    BOOST_CHECK_EQUAL(bal, 1000);
    LOGINFO << "DedupTimeRejection: Alice on B = " << bal;
  }

  serverA->stop();
  serverB->stop();
  serverA.reset();
  serverB.reset();
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  boost::system::error_code ec;
  bfs::remove_all(dirA, ec);
  bfs::remove_all(dirB, ec);
}

// ============================================================================
// SYS_CROSS_TRANSFER end-to-end (VM syscall path)
// ============================================================================
//
// A VM program running on server A issues SYS_CROSS_TRANSFER to Bob on
// server B. Verify that the ledger mutations on A happen synchronously
// in the VM host lambda (caller debit + peer vostro credit), and that
// the commit-phase async dispatch actually delivers the money to Bob.
//
// Regression guard: the commit-phase dispatch was a TODO until this
// session. The old code buffered the deferred list and then silently
// dropped it, so a VM program's cross-transfer syscall would report
// CES_OK to the program but the destination would never receive a
// single credit. The unit test `CesVMTests/SyscallCrossTransfer` only
// asserted "VM didn't crash" and would happily pass the broken build.
BOOST_AUTO_TEST_CASE(VmCrossTransfer) {
  blog::init();
  blog::set_level(blog::info);

  bfs::path dirA = makeUniqueTempDir("ces_vmx_a");
  bfs::path dirB = makeUniqueTempDir("ces_vmx_b");

  minx::Hash privA; privA.fill(0xAA);
  minx::Hash privB; privB.fill(0xBB);
  ces::KeyPair kpA(privA);
  ces::KeyPair kpB(privB);
  ces::KeyPair alice; // runs the VM program on A
  ces::KeyPair bob;   // recipient on B

  CesConfig cfgA = makePeeringConfig(dirA, privA);
  cfgA.minAsset = 100;
  cfgA.maxAsset = 10000;
  cfgA.feeAsset = 0;
  cfgA.feeVmMult = 1; // 1x gas multiplier — predictable billing

  CesConfig cfgB = cfgA;
  cfgB.dataDir = dirB;
  cfgB.serverPrivKey = privB;

  auto serverA = std::make_unique<CesServer>(cfgA);
  uint16_t portA = serverA->start(0);
  BOOST_REQUIRE(portA > 0);

  auto serverB = std::make_unique<CesServer>(cfgB);
  uint16_t portB = serverB->start(0);
  BOOST_REQUIRE(portB > 0);

  std::string addrB = "localhost:" + std::to_string(portB);

  // Alice: enough for runAsset gas budget + cross-transfer amount.
  serverA->_brr(alice.getPublicKeyAsHash(), 50000);
  wait_net();

  // Bilateral liquidity — A's reserve on B.
  serverB->_brr(kpA.getPublicKeyAsHash(), 50000);
  wait_net();

  // Register B as a reachable peer on A.
  serverA->_markPeerReachable(kpB.getPublicKeyAsHash(), addrB);

  // Program bytecode. Copies dest key and server string from the input
  // region (io[892..]) into addressable cells (io[16..] and io[24..])
  // and then issues SYS_CROSS_TRANSFER.
  //
  // cesvm.cpp's opcode table is file-private; redeclare the handful of
  // opcodes we actually use here to keep this test self-contained.
  constexpr uint8_t OP_SET  = 2;
  constexpr uint8_t OP_MOV  = 37;
  constexpr uint8_t OP_HOST = 20;
  constexpr uint8_t OP_TERM = 1;
  constexpr uint8_t SHORT_VAL = 0x40;
  auto sv = [](uint8_t v) -> uint8_t { return SHORT_VAL | (v & 0x3F); };
  auto rp = [](uint8_t v) -> uint8_t { return 0x80 | SHORT_VAL | (v & 0x3F); };

  AssetData pgm{};
  size_t pc = 0;
  // io[9] = 892 (start of input region, where dest key lives)
  pgm[pc++] = OP_SET; pgm[pc++] = sv(9);
  pgm[pc++] = 2;      ces::Buffer::pokeLE<uint16_t>(pgm.data() + pc, 892); pc += 2;
  // MOV io[16..19] <- 4 cells from io[io[9]] = io[892..895] (dest key)
  pgm[pc++] = OP_MOV; pgm[pc++] = sv(16); pgm[pc++] = rp(9); pgm[pc++] = sv(4);
  // io[9] = 896 (next input cell, where server string lives)
  pgm[pc++] = OP_SET; pgm[pc++] = sv(9);
  pgm[pc++] = 2;      ces::Buffer::pokeLE<uint16_t>(pgm.data() + pc, 896); pc += 2;
  // MOV io[24..31] <- 8 cells from io[io[9]] = io[896..903] (server string)
  pgm[pc++] = OP_MOV; pgm[pc++] = sv(24); pgm[pc++] = rp(9); pgm[pc++] = sv(8);
  // Arm SYS_CROSS_TRANSFER:
  pgm[pc++] = OP_SET; pgm[pc++] = sv(3); pgm[pc++] = sv(SYS_CROSS_TRANSFER);
  pgm[pc++] = OP_SET; pgm[pc++] = sv(4); pgm[pc++] = sv(16); // dest ptr cell
  pgm[pc++] = OP_SET; pgm[pc++] = sv(5); pgm[pc++] = sv(50); // amount = 50
  pgm[pc++] = OP_SET; pgm[pc++] = sv(6); pgm[pc++] = sv(24); // server ptr cell
  pgm[pc++] = OP_HOST;
  pgm[pc++] = OP_TERM;

  // Upload program asset on A.
  minx::Hash programKey;
  programKey.fill(0);
  programKey[0] = 'X';
  programKey[1] = 'F';

  uint64_t aliceInitialBalance = 0;
  uint64_t vmBudgetUsed = 0;
  {
    auto ep = boost::asio::ip::udp::endpoint(
      boost::asio::ip::address_v6::loopback(), portA);
    CesClient client(ep, false);
    client.setKey(alice);
    client.start(0);
    BOOST_REQUIRE(client.connect());

    uint8_t rc = client.createAsset(programKey, pgm, 30);
    CES_REQUIRE_OK(rc);

    // Input = 32-byte dest key + 64 bytes of server string (null-padded).
    ces::Bytes input;
    input.reserve(32 + 64);
    for (auto b : bob.getPublicKeyAsHash()) input.push_back(b);
    for (size_t i = 0; i < 64; ++i) {
      input.push_back(i < addrB.size()
        ? static_cast<uint8_t>(addrB[i])
        : uint8_t{0});
    }

    // Snapshot Alice's balance pre-runAsset so we can assert the VM
    // cross-transfer debit happened synchronously.
    {
      int64_t bal = 0; uint32_t nonce = 0;
      HashPrefix xd{}; uint64_t xa = 0; uint32_t xt = 0;
      serverA->unsignedQueryAccount(
        Account::getMapKey(alice.getPublicKeyAsHash()),
        bal, nonce, xd, xa, xt);
      aliceInitialBalance = static_cast<uint64_t>(bal);
    }

    uint64_t vmError = 0;
    ces::Bytes output;
    const uint64_t budget = 10000;
    rc = client.runAsset(programKey, budget, input,
                         vmError, vmBudgetUsed, output);
    CES_CHECK_OK(rc);
    BOOST_CHECK_EQUAL(vmError, CESVM_OK);
    LOGINFO << "VM cross-transfer: rc=" << (int)rc
            << " vmError=" << vmError
            << " budgetUsed=" << vmBudgetUsed;

    client.disconnect();
    client.stop();
  }

  wait_net();

  // --- Synchronous assertions on server A ---
  //
  // Alice paid budgetUsed (gas, since feeTx=0 in this test config)
  // plus the cross-transfer amount. Unused budget was refunded.
  // B's vostro on A grew by exactly the cross-transfer amount.
  {
    auto aliceKey = Account::getMapKey(alice.getPublicKeyAsHash());
    int64_t bal = 0;
    uint32_t nonce = 0;
    HashPrefix xd{};
    uint64_t xa = 0;
    uint32_t xt = 0;
    serverA->unsignedQueryAccount(aliceKey, bal, nonce, xd, xa, xt);
    BOOST_CHECK_EQUAL(bal,
      static_cast<int64_t>(aliceInitialBalance)
        - static_cast<int64_t>(vmBudgetUsed) - 50);
    LOGINFO << "Alice on A after VM cross-transfer: " << bal
            << " (started " << aliceInitialBalance << ")";
  }
  {
    auto bKey = Account::getMapKey(kpB.getPublicKeyAsHash());
    int64_t bal = 0;
    uint32_t nonce = 0;
    HashPrefix xd{};
    uint64_t xa = 0;
    uint32_t xt = 0;
    serverA->unsignedQueryAccount(bKey, bal, nonce, xd, xa, xt);
    BOOST_CHECK_EQUAL(bal, 50);
    LOGINFO << "B vostro on A: " << bal;
  }

  // --- Async settlement: wait for delivery to land on B ---
  std::this_thread::sleep_for(std::chrono::seconds(10));

  // Bob should have received the credits.
  {
    auto bobKey = Account::getMapKey(bob.getPublicKeyAsHash());
    int64_t bal = 0;
    uint32_t nonce = 0;
    HashPrefix xd{};
    uint64_t xa = 0;
    uint32_t xt = 0;
    serverB->unsignedQueryAccount(bobKey, bal, nonce, xd, xa, xt);
    BOOST_CHECK_EQUAL(bal, 50);
    LOGINFO << "Bob on B after settlement: " << bal;
  }

  // A's reserve on B should have been drawn down.
  {
    auto aKey = Account::getMapKey(kpA.getPublicKeyAsHash());
    int64_t bal = 0;
    uint32_t nonce = 0;
    HashPrefix xd{};
    uint64_t xa = 0;
    uint32_t xt = 0;
    serverB->unsignedQueryAccount(aKey, bal, nonce, xd, xa, xt);
    BOOST_CHECK_EQUAL(bal, 49950); // 50000 - 50
    LOGINFO << "A reserve on B after settlement: " << bal;
  }

  // Cleanup
  serverA->stop();
  serverB->stop();
  serverA.reset();
  serverB.reset();
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  boost::system::error_code ec;
  bfs::remove_all(dirA, ec);
  bfs::remove_all(dirB, ec);
}

// Focused test for the peer miner's reachability detection. Every
// cross-transfer test in this file bypasses this path by writing
// `reachable = true` directly into A's peer table — so if the real
// detection path in peerMinerLoop regresses, the cross-transfer tests
// still pass while production cross-transfers fail with "unknown /
// unreachable peer". This test is the one that would fail instead.
//
// peerMinerLoop only writes `reachable` back into peerTable_ inside the
// `bestIdx >= 0` branch — i.e. after it has decided to mine on this
// peer. So we let the miner actually mine one round at minDiff=1 with
// cache-only RandomX and assert the flag after it writes back.
BOOST_AUTO_TEST_CASE(PeerReachabilityDetection) {
  blog::init();
  blog::set_level(blog::info);

  bfs::path dirA = makeUniqueTempDir("ces_reach_a");
  bfs::path dirB = makeUniqueTempDir("ces_reach_b");

  minx::Hash privA; privA.fill(0xA1);
  minx::Hash privB; privB.fill(0xB2);
  ces::KeyPair kpA(privA);
  ces::KeyPair kpB(privB);

  CesConfig cfgB;
  cfgB.dataDir = dirB;
  cfgB.serverPrivKey = privB;
  cfgB.minAcc = 100;
  cfgB.maxAcc = 10000;
  cfgB.minDiff = 1;
  cfgB.spendSlotSize = 10;
  cfgB.taskThreads = 2;
  cfgB.flushValue = std::numeric_limits<uint64_t>::max();
  cfgB.feeAccount = 0;
  cfgB.feeTx = 0;
  cfgB.feeQuery = 0;

  auto serverB = std::make_unique<CesServer>(cfgB);
  uint16_t portB = serverB->start(0);
  BOOST_REQUIRE(portB > 0);
  serverB->createPoWEngine(false);

  CesConfig cfgA = cfgB;
  cfgA.dataDir = dirA;
  cfgA.serverPrivKey = privA;
  cfgA.peerTarget = 100'000;
  cfgA.peerMinerIntervalSecs = 1;
  cfgA.peerMiningFullDataset = false;
  cfgA.peers.push_back({minx::hashToString(kpB.getPublicKeyAsHash()),
                        "localhost:" + std::to_string(portB)});

  auto serverA = std::make_unique<CesServer>(cfgA);
  uint16_t portA = serverA->start(0);
  BOOST_REQUIRE(portA > 0);
  serverA->createPoWEngine(false);

  for (int i = 0; i < 300; ++i) {
    if (serverA->isPoWEngineReady() && serverB->isPoWEngineReady()) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  BOOST_REQUIRE(serverA->isPoWEngineReady());
  BOOST_REQUIRE(serverB->isPoWEngineReady());

  // Sanity: seeded peer is not yet reachable before the miner runs.
  BOOST_REQUIRE(!serverA->_isPeerReachable(kpB.getPublicKeyAsHash()));

  serverA->startPeerMiner();

  bool reachable = false;
  for (int attempt = 0; attempt < 120 && !reachable; ++attempt) {
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    reachable = serverA->_isPeerReachable(kpB.getPublicKeyAsHash());
  }

  BOOST_CHECK_MESSAGE(reachable,
    "peer miner never marked B reachable — cross-transfers would silently "
    "fail with CES_ERROR_UNKNOWN_PEER in production");

  serverA->stop();
  serverB->stop();
  serverA.reset();
  serverB.reset();
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  boost::system::error_code ec;
  bfs::remove_all(dirA, ec);
  bfs::remove_all(dirB, ec);
}

BOOST_AUTO_TEST_SUITE_END()
