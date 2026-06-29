/**
 * Gossip tests: CES_GOSSIP spreads across the server mesh, deduped once.
 *
 * N cache-only servers, all mutually peered (minDiff=1, zero fees, 2s miner).
 * One server originates a broadcast gossip; the test asserts it reaches every
 * other server exactly once (reach plus bucketcache dedup kills the cycles)
 * and never the originator. Mirrors the peering-test harness: start on port 0
 * to learn ports, then rebuild with peer configs (peers/peerTarget are const
 * post-construction), restart on the same ports, run the peer miners.
 */

#include "test_common.h"

#include <ces/buffer.h>
#include <ces/keys.h>

#include <cstring>
#include <limits>
#include <random>
#include <vector>

namespace bfs = boost::filesystem;

static CesConfig makeGossipConfig(const bfs::path& dataDir,
                                  const minx::Hash& privKey,
                                  uint64_t feeTx = 0) {
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
  cfg.feeTx = feeTx;
  cfg.feeQuery = 0;
  // Pin fees to full price so a gossip hop charge equals feeTx exactly.
  cfg.feeDiscountEnabled = false;
  cfg.peerMinerIntervalSecs = 2;
  // Effectively uncap per-peer reserve disturbance so the flood/conservation
  // tests fan out their full budget regardless of the production default.
  cfg.maxPeerReserveDisturbance = std::numeric_limits<uint64_t>::max();
  // Flood every peer (degree 0 = no gossip subset) so the conservation tests
  // exercise the full mesh deterministically, independent of the production
  // gossip degree default.
  cfg.gossipFanoutDegree = 0;
  return cfg;
}

BOOST_AUTO_TEST_SUITE(GossipTests)

BOOST_AUTO_TEST_CASE(GossipFloodReachesAllPeersOnce) {
  blog::init();
  blog::set_level(blog::info);

  const int N = 3;
  const uint64_t kReserve = 10'000'000;
  std::vector<bfs::path> dirs;
  std::vector<minx::Hash> privs;
  std::vector<minx::Hash> pubkeys;
  for (int i = 0; i < N; ++i) {
    dirs.push_back(makeUniqueTempDir("ces_gossip_" + std::to_string(i)));
    minx::Hash p;
    p.fill(static_cast<uint8_t>(0xA0 + i));
    privs.push_back(p);
    ces::KeyPair kp(p);
    pubkeys.push_back(kp.getPublicKeyAsHash());
  }

  std::vector<std::unique_ptr<CesServer>> servers(N);
  std::vector<uint16_t> ports(N);
  for (int i = 0; i < N; ++i) {
    servers[i] =
      std::make_unique<CesServer>(makeGossipConfig(dirs[i], privs[i]));
    ports[i] = servers[i]->start(0);
    BOOST_REQUIRE(ports[i] > 0);
  }

  // Seed a fully-reciprocated, funded all-to-all mesh directly (reachable +
  // verified peer, reserve held, inbound PoW proved) as a completed mining
  // cycle would, so the flood runs without RandomX or the peer miner. Sender
  // i's reserve at receiver j lives on j's ledger keyed by i.
  for (int i = 0; i < N; ++i)
    for (int j = 0; j < N; ++j) {
      if (i == j) continue;
      servers[i]->_markPeerReachable(pubkeys[j],
                                     "localhost:" + std::to_string(ports[j]));
      servers[i]->_testCompletePeering(pubkeys[j],
                                       static_cast<int64_t>(kReserve), 1);
      servers[j]->_brr(pubkeys[i], static_cast<int64_t>(kReserve));
    }

  // Server 0 originates a broadcast gossip (dest all-zero = everyone).
  ces::Bytes payload;
  const char* text = "hello gossip mesh";
  payload.insert(payload.end(), text, text + std::strlen(text));
  Hash broadcast{};
  servers[0]->originateGossip(payload, 500'000, broadcast);

  // Poll: every other server should receive it.
  bool reachedAll = false;
  for (int t = 0; t < 600 && !reachedAll; ++t) {  // up to ~30s
    reachedAll = true;
    for (int i = 1; i < N; ++i)
      if (servers[i]->gossipReceivedCount() < 1) reachedAll = false;
    if (!reachedAll) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_CHECK_MESSAGE(reachedAll, "gossip did not reach all peers");

  // Let any duplicate (cycle) copies arrive, then assert dedup held: once each.
  std::this_thread::sleep_for(std::chrono::milliseconds(750));
  for (int i = 1; i < N; ++i)
    BOOST_CHECK_EQUAL(servers[i]->gossipReceivedCount(), 1u);
  BOOST_CHECK_EQUAL(servers[0]->gossipReceivedCount(), 0u);

  for (int i = 0; i < N; ++i) servers[i]->stop();
}

// Both settlement legs. Seed server 0 a reserve on server 1, fire one gossip
// 0->1: server 0's reserve on 1 drops by feeTx (leg 2) and server 1's reserve on
// 0 rises by feeTx (leg 1). The fee moves between ledgers, conserved.
BOOST_AUTO_TEST_CASE(GossipChargeDrainsSenderReserve) {
  blog::init();
  blog::set_level(blog::info);

  const uint64_t kFeeTx = 1000;
  const uint64_t kReserve = 1'000'000;

  std::vector<bfs::path> dirs;
  std::vector<minx::Hash> privs, pubkeys;
  for (int i = 0; i < 2; ++i) {
    dirs.push_back(makeUniqueTempDir("ces_gossip_charge_" + std::to_string(i)));
    minx::Hash p;
    p.fill(static_cast<uint8_t>(0xB0 + i));
    privs.push_back(p);
    pubkeys.push_back(ces::KeyPair(p).getPublicKeyAsHash());
  }

  std::vector<std::unique_ptr<CesServer>> servers(2);
  std::vector<uint16_t> ports(2);
  for (int i = 0; i < 2; ++i) {
    servers[i] = std::make_unique<CesServer>(
      makeGossipConfig(dirs[i], privs[i], kFeeTx));
    ports[i] = servers[i]->start(0);
    BOOST_REQUIRE(ports[i] > 0);
    servers[i]->createPoWEngine(false);  // cache-only: verifies main-port tickets
  }
  for (int t = 0; t < 300; ++t) {
    if (servers[0]->isPoWEngineReady() && servers[1]->isPoWEngineReady()) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  BOOST_REQUIRE(servers[0]->isPoWEngineReady());
  BOOST_REQUIRE(servers[1]->isPoWEngineReady());

  // Wire reachability directly (no miner) and seed server 0's reserve on 1.
  servers[0]->_markPeerReachable(pubkeys[1],
                                 "localhost:" + std::to_string(ports[1]));
  servers[1]->_markPeerReachable(pubkeys[0],
                                 "localhost:" + std::to_string(ports[0]));
  servers[1]->_brr(pubkeys[0], static_cast<int64_t>(kReserve));
  BOOST_REQUIRE_EQUAL(servers[1]->_adminQueryAccount(pubkeys[0]).balance,
                      static_cast<int64_t>(kReserve));

  // Server 0 originates; it forwards the one reachable peer (1), which charges
  // 0's reserve held on it before relaying onward (1 has no other peer to relay
  // to, so this is the single charged hop).
  ces::Bytes payload;
  const char* text = "charge me";
  payload.insert(payload.end(), text, text + std::strlen(text));
  servers[0]->originateGossip(payload, 1'000'000, Hash{});

  bool got = false;
  for (int t = 0; t < 200 && !got; ++t) {
    if (servers[1]->gossipReceivedCount() >= 1) got = true;
    else std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_REQUIRE_MESSAGE(got, "gossip did not reach the paid peer");

  // Leg 2: server 0's reserve on server 1 drained by exactly feeTx.
  BOOST_CHECK_EQUAL(servers[1]->_adminQueryAccount(pubkeys[0]).balance,
                    static_cast<int64_t>(kReserve - kFeeTx));

  // Leg 1: server 1's reserve on server 0 rose by exactly feeTx, created when
  // server 0 processed the ack. Async (settlement ack -> strand), so poll.
  int64_t legOne = 0;
  for (int t = 0; t < 200; ++t) {
    legOne = servers[0]->_adminQueryAccount(pubkeys[1]).balance;
    if (legOne == static_cast<int64_t>(kFeeTx)) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_CHECK_EQUAL(legOne, static_cast<int64_t>(kFeeTx));

  for (int i = 0; i < 2; ++i) servers[i]->stop();
}

// splitCapped over thousands of random (budget, caps): conservation
// (sum(alloc) + pocket == budget), cap-respect (alloc[i] <= caps[i]), and
// maximality (a non-zero pocket means no entry has spendable headroom left).
BOOST_AUTO_TEST_CASE(SplitCappedInvariants) {
  const uint64_t M = std::numeric_limits<uint64_t>::max();
  uint64_t pocket = 0;

  { auto a = CesServer::splitCapped(100, {}, pocket);
    BOOST_CHECK(a.empty()); BOOST_CHECK_EQUAL(pocket, 100u); }          // no peers

  { auto a = CesServer::splitCapped(0, {10, 10}, pocket);
    BOOST_CHECK_EQUAL(a[0] + a[1], 0u); BOOST_CHECK_EQUAL(pocket, 0u); } // no budget

  { auto a = CesServer::splitCapped(100, {M, M, M, M}, pocket);
    BOOST_CHECK_EQUAL(a[0], 25u); BOOST_CHECK_EQUAL(a[3], 25u);
    BOOST_CHECK_EQUAL(pocket, 0u); }                                    // even split

  { auto a = CesServer::splitCapped(100, {M, M, M, 4}, pocket);      // redistribute
    BOOST_CHECK_EQUAL(a[3], 4u);
    BOOST_CHECK_EQUAL(a[0] + a[1] + a[2], 96u);  // excess redistributed
    BOOST_CHECK_EQUAL(pocket, 0u); }

  { auto a = CesServer::splitCapped(100, {10, 10, 10}, pocket);      // over caps
    BOOST_CHECK_EQUAL(a[0] + a[1] + a[2], 30u);
    BOOST_CHECK_EQUAL(pocket, 70u); }

  std::mt19937_64 rng(0xC0FFEEULL);
  for (int iter = 0; iter < 5000; ++iter) {
    size_t n = rng() % 8;
    uint64_t budget = rng() % 100000;
    std::vector<uint64_t> caps(n);
    for (auto& c : caps) {
      uint64_t r = rng() % 4;
      c = (r == 0) ? 0 : (r == 1) ? M : (rng() % 30000);
    }
    uint64_t p = 0;
    auto a = CesServer::splitCapped(budget, caps, p);
    uint64_t sum = 0, headroom = 0;
    for (size_t i = 0; i < n; ++i) {
      BOOST_REQUIRE(a[i] <= caps[i]);                 // cap-respect
      sum += a[i];
      if (a[i] < caps[i]) ++headroom;
    }
    BOOST_REQUIRE_EQUAL(sum + p, budget);             // conservation
    if (p > 0) BOOST_REQUIRE(headroom == 0 || p < headroom);  // maximality
  }
}

// End-to-end conservation: a real flood across a 3-node mesh MOVES value
// (per-hop skims, the reserve settlement, the surplus refund) but never mints
// or burns it. Seed every directed reserve, originate one gossip, and prove the
// total circulating credit across all three ledgers returns to EXACTLY its
// pre-flood value once the asynchronous legs settle.
BOOST_AUTO_TEST_CASE(GossipFloodConserved) {
  blog::init();
  blog::set_level(blog::info);

  const int N = 3;
  const uint64_t kFeeTx = 1000;
  const uint64_t kReserve = 10'000'000;  // ample per directed pair
  const uint64_t kBudget = 500'000;

  std::vector<bfs::path> dirs;
  std::vector<minx::Hash> privs, pubkeys;
  for (int i = 0; i < N; ++i) {
    dirs.push_back(makeUniqueTempDir("ces_gossip_cons_" + std::to_string(i)));
    minx::Hash p;
    p.fill(static_cast<uint8_t>(0xC0 + i));
    privs.push_back(p);
    pubkeys.push_back(ces::KeyPair(p).getPublicKeyAsHash());
  }
  std::vector<std::unique_ptr<CesServer>> servers(N);
  std::vector<uint16_t> ports(N);
  for (int i = 0; i < N; ++i) {
    servers[i] = std::make_unique<CesServer>(
      makeGossipConfig(dirs[i], privs[i], kFeeTx));
    ports[i] = servers[i]->start(0);
    BOOST_REQUIRE(ports[i] > 0);
    servers[i]->createPoWEngine(false);
  }
  for (int t = 0; t < 300; ++t) {
    bool all = true;
    for (int i = 0; i < N; ++i)
      if (!servers[i]->isPoWEngineReady()) all = false;
    if (all) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  // All-to-all reachability + seed every directed reserve (sender i's reserve
  // at receiver j lives on j's ledger, keyed by i) so leg 1 credits an existing
  // account rather than creating one.
  for (int i = 0; i < N; ++i)
    for (int j = 0; j < N; ++j) {
      if (i == j) continue;
      servers[i]->_markPeerReachable(pubkeys[j],
                                     "localhost:" + std::to_string(ports[j]));
      servers[j]->_brr(pubkeys[i], static_cast<int64_t>(kReserve));
    }

  auto totalCirculating = [&]() -> int64_t {
    int64_t s = 0;
    for (int i = 0; i < N; ++i) s += servers[i]->_adminStats().circulating;
    return s;
  };
  const int64_t before = totalCirculating();
  BOOST_REQUIRE_EQUAL(before,
                      static_cast<int64_t>(N) * (N - 1) * kReserve);

  ces::Bytes payload{'h', 'i'};
  servers[0]->originateGossip(payload, kBudget, Hash{});

  bool reached = false;
  for (int t = 0; t < 400 && !reached; ++t) {
    reached = servers[1]->gossipReceivedCount() >= 1 &&
              servers[2]->gossipReceivedCount() >= 1;
    if (!reached) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_REQUIRE_MESSAGE(reached, "flood did not reach all peers");

  // Once every async leg settles, total credit is EXACTLY conserved. Poll for
  // convergence (a drain lands before its matching credit, so mid-flight the
  // sum dips, then returns). A mint/burn bug would converge to the wrong value.
  int64_t after = before - 1;
  for (int t = 0; t < 400 && after != before; ++t) {
    after = totalCirculating();
    if (after != before) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_CHECK_EQUAL(after, before);

  // And the flood actually moved value (not a trivial no-op): server 0's
  // reserve AT server 1 (which lives on server 1's ledger and is drained by
  // leg 2 as the flood propagates) dropped below its seed.
  BOOST_CHECK_LT(servers[1]->_adminQueryAccount(pubkeys[0]).balance,
                 static_cast<int64_t>(kReserve));

  for (int i = 0; i < N; ++i) servers[i]->stop();
}

// Sink conservation: register key D as a sink on server 1, originate dest=D over
// a 3-node mesh. Server 1 flushes the collected budget into D instead of
// forwarding. Total credit stays conserved, D is funded, server 1 sank (no
// normal receive).
BOOST_AUTO_TEST_CASE(GossipSinkConserved) {
  blog::init();
  blog::set_level(blog::info);

  const int N = 3;
  const uint64_t kFeeTx = 1000;
  const uint64_t kReserve = 10'000'000;
  const uint64_t kBudget = 500'000;

  std::vector<bfs::path> dirs;
  std::vector<minx::Hash> privs, pubkeys;
  for (int i = 0; i < N; ++i) {
    dirs.push_back(makeUniqueTempDir("ces_gossip_sink_" + std::to_string(i)));
    minx::Hash p;
    p.fill(static_cast<uint8_t>(0xD0 + i));
    privs.push_back(p);
    pubkeys.push_back(ces::KeyPair(p).getPublicKeyAsHash());
  }
  // A distinct destination key, hosted by NO server until we register it.
  minx::Hash dPriv;
  dPriv.fill(0xDD);
  const minx::Hash D = ces::KeyPair(dPriv).getPublicKeyAsHash();

  std::vector<std::unique_ptr<CesServer>> servers(N);
  std::vector<uint16_t> ports(N);
  for (int i = 0; i < N; ++i) {
    servers[i] = std::make_unique<CesServer>(
      makeGossipConfig(dirs[i], privs[i], kFeeTx));
    ports[i] = servers[i]->start(0);
    BOOST_REQUIRE(ports[i] > 0);
    servers[i]->createPoWEngine(false);
  }
  for (int t = 0; t < 300; ++t) {
    bool all = true;
    for (int i = 0; i < N; ++i)
      if (!servers[i]->isPoWEngineReady()) all = false;
    if (all) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  for (int i = 0; i < N; ++i)
    for (int j = 0; j < N; ++j) {
      if (i == j) continue;
      servers[i]->_markPeerReachable(pubkeys[j],
                                     "localhost:" + std::to_string(ports[j]));
      servers[j]->_brr(pubkeys[i], static_cast<int64_t>(kReserve));
    }
  // Register D as a sink target on server 1 only.
  servers[1]->registerSinkTarget(D);
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  auto totalCirculating = [&]() -> int64_t {
    int64_t s = 0;
    for (int i = 0; i < N; ++i) s += servers[i]->_adminStats().circulating;
    return s;
  };
  const int64_t before = totalCirculating();
  BOOST_REQUIRE_EQUAL(before, static_cast<int64_t>(N) * (N - 1) * kReserve);

  ces::Bytes payload{'p', 'a', 'y'};
  servers[0]->originateGossip(payload, kBudget, D);

  // Wait until server 1 has sunk at least once and D is funded.
  bool sank = false;
  for (int t = 0; t < 400 && !sank; ++t) {
    sank = servers[1]->gossipSinkCount() >= 1 &&
           servers[1]->_adminQueryAccount(D).balance > 0;
    if (!sank) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_REQUIRE_MESSAGE(sank, "server 1 did not sink the gossip into D");

  // Total credit is EXACTLY conserved once the async legs settle.
  int64_t after = before - 1;
  for (int t = 0; t < 400 && after != before; ++t) {
    after = totalCirculating();
    if (after != before)
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_CHECK_EQUAL(after, before);

  // D was funded (the multicast payment landed); server 1 sank (never relayed).
  BOOST_CHECK_GT(servers[1]->_adminQueryAccount(D).balance, 0);
  BOOST_CHECK_EQUAL(servers[1]->gossipReceivedCount(), 0u);
  BOOST_CHECK_GE(servers[1]->gossipSinkCount(), 1u);
  // Server 2 is a plain relay: it received and forwarded normally.
  BOOST_CHECK_GE(servers[2]->gossipReceivedCount(), 1u);

  for (int i = 0; i < N; ++i) servers[i]->stop();
}

// Sink to the server's own identity: the delivered remainder burns, only the
// skim is mirrored back. Server 0 floods dest=server-1; circulating drops by
// exactly budget minus feeTx.
BOOST_AUTO_TEST_CASE(GossipSinkSelfBurns) {
  blog::init();
  blog::set_level(blog::info);

  const uint64_t kFeeTx = 1000;
  const uint64_t kReserve = 1'000'000;
  const uint64_t kBudget = 500'000;

  std::vector<bfs::path> dirs;
  std::vector<minx::Hash> privs, pubkeys;
  for (int i = 0; i < 2; ++i) {
    dirs.push_back(makeUniqueTempDir("ces_gossip_self_" + std::to_string(i)));
    minx::Hash p;
    p.fill(static_cast<uint8_t>(0xE0 + i));
    privs.push_back(p);
    pubkeys.push_back(ces::KeyPair(p).getPublicKeyAsHash());
  }
  std::vector<std::unique_ptr<CesServer>> servers(2);
  std::vector<uint16_t> ports(2);
  for (int i = 0; i < 2; ++i) {
    servers[i] = std::make_unique<CesServer>(
      makeGossipConfig(dirs[i], privs[i], kFeeTx));
    ports[i] = servers[i]->start(0);
    BOOST_REQUIRE(ports[i] > 0);
    servers[i]->createPoWEngine(false);
  }
  for (int t = 0; t < 300; ++t) {
    if (servers[0]->isPoWEngineReady() && servers[1]->isPoWEngineReady()) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  servers[0]->_markPeerReachable(pubkeys[1],
                                 "localhost:" + std::to_string(ports[1]));
  servers[1]->_markPeerReachable(pubkeys[0],
                                 "localhost:" + std::to_string(ports[0]));
  servers[1]->_brr(pubkeys[0], static_cast<int64_t>(kReserve));

  auto totalCirculating = [&]() -> int64_t {
    return servers[0]->_adminStats().circulating +
           servers[1]->_adminStats().circulating;
  };
  const int64_t before = totalCirculating();
  BOOST_REQUIRE_EQUAL(before, static_cast<int64_t>(kReserve));

  // dest = server 1's own identity -> sinks into server 1's bottomless self.
  ces::Bytes payload{'b', 'u', 'r', 'n'};
  servers[0]->originateGossip(payload, kBudget, pubkeys[1]);

  bool sank = false;
  for (int t = 0; t < 400 && !sank; ++t) {
    sank = servers[1]->gossipSinkCount() >= 1;
    if (!sank) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_REQUIRE_MESSAGE(sank, "server 1 did not sink the self-addressed gossip");

  // Circulating drops by exactly delivered = budget - skim (the burn); the skim
  // returns to server 0 as leg 1. Converges as the async ack lands.
  const int64_t expected = before - static_cast<int64_t>(kBudget - kFeeTx);
  int64_t after = before;
  for (int t = 0; t < 400 && after != expected; ++t) {
    after = totalCirculating();
    if (after != expected)
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_CHECK_EQUAL(after, expected);
  BOOST_CHECK_EQUAL(servers[1]->gossipReceivedCount(), 0u);
  BOOST_CHECK_EQUAL(servers[1]->gossipSinkCount(), 1u);

  for (int i = 0; i < 2; ++i) servers[i]->stop();
}

// A sink is terminal: it does not fan out. Line topology 0 -> 1 -> 2 (server 2
// only reachable via server 1). Register D on server 1, originate dest=D at
// server 0. Server 1 sinks and does not relay, so server 2 never sees it.
BOOST_AUTO_TEST_CASE(GossipSinkNoFanout) {
  blog::init();
  blog::set_level(blog::info);

  const int N = 3;
  const uint64_t kFeeTx = 1000;
  const uint64_t kReserve = 10'000'000;
  const uint64_t kBudget = 500'000;

  std::vector<bfs::path> dirs;
  std::vector<minx::Hash> privs, pubkeys;
  for (int i = 0; i < N; ++i) {
    dirs.push_back(makeUniqueTempDir("ces_gossip_term_" + std::to_string(i)));
    minx::Hash p;
    p.fill(static_cast<uint8_t>(0xF0 + i));
    privs.push_back(p);
    pubkeys.push_back(ces::KeyPair(p).getPublicKeyAsHash());
  }
  minx::Hash dPriv;
  dPriv.fill(0xFD);
  const minx::Hash D = ces::KeyPair(dPriv).getPublicKeyAsHash();

  std::vector<std::unique_ptr<CesServer>> servers(N);
  std::vector<uint16_t> ports(N);
  for (int i = 0; i < N; ++i) {
    servers[i] = std::make_unique<CesServer>(
      makeGossipConfig(dirs[i], privs[i], kFeeTx));
    ports[i] = servers[i]->start(0);
    BOOST_REQUIRE(ports[i] > 0);
    servers[i]->createPoWEngine(false);
  }
  for (int t = 0; t < 300; ++t) {
    bool all = true;
    for (int i = 0; i < N; ++i)
      if (!servers[i]->isPoWEngineReady()) all = false;
    if (all) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  // Line: 0 reaches 1; 1 reaches 0 and 2; 2 reaches 1. Seed the reserves each
  // sender would spend (0's at 1, 1's at 2) so a relay COULD forward if it tried.
  servers[0]->_markPeerReachable(pubkeys[1],
                                 "localhost:" + std::to_string(ports[1]));
  servers[1]->_markPeerReachable(pubkeys[0],
                                 "localhost:" + std::to_string(ports[0]));
  servers[1]->_markPeerReachable(pubkeys[2],
                                 "localhost:" + std::to_string(ports[2]));
  servers[2]->_markPeerReachable(pubkeys[1],
                                 "localhost:" + std::to_string(ports[1]));
  servers[1]->_brr(pubkeys[0], static_cast<int64_t>(kReserve));  // 0's reserve @1
  servers[2]->_brr(pubkeys[1], static_cast<int64_t>(kReserve));  // 1's reserve @2
  servers[1]->registerSinkTarget(D);
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  ces::Bytes payload{'x'};
  servers[0]->originateGossip(payload, kBudget, D);

  bool sank = false;
  for (int t = 0; t < 400 && !sank; ++t) {
    sank = servers[1]->gossipSinkCount() >= 1;
    if (!sank) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_REQUIRE_MESSAGE(sank, "server 1 did not sink");

  // Give any (erroneous) onward relay ample time to arrive, then assert silence.
  std::this_thread::sleep_for(std::chrono::milliseconds(750));
  BOOST_CHECK_EQUAL(servers[2]->gossipReceivedCount(), 0u);
  BOOST_CHECK_EQUAL(servers[2]->gossipSinkCount(), 0u);
  BOOST_CHECK_GT(servers[1]->_adminQueryAccount(D).balance, 0);

  for (int i = 0; i < N; ++i) servers[i]->stop();
}

// maxPeerReserveDisturbance caps each leg, so a large budget over two reachable
// peers fans out only nPeers*cap; the rest reverts to the originator.
// originateGossip returns the fanned total. The plan is synchronous, no PoW.
BOOST_AUTO_TEST_CASE(GossipReserveDisturbanceCapRefunds) {
  blog::init();
  blog::set_level(blog::info);

  auto dir = makeUniqueTempDir("ces_gossip_cap");
  minx::Hash priv;
  priv.fill(0x7A);
  CesConfig cfg = makeGossipConfig(dir, priv);
  const uint64_t kCap = 1000;
  cfg.maxPeerReserveDisturbance = kCap;        // tiny per-peer-op cap
  auto srv = std::make_unique<CesServer>(cfg);
  uint16_t port = srv->start(0);
  BOOST_REQUIRE(port > 0);

  // Two reachable peers (ourBalanceThere stays -1 = unknown -> uncapped by
  // reserve, so the disturbance cap is the binding constraint).
  minx::Hash a, b;
  a.fill(0x01);
  b.fill(0x02);
  srv->_markPeerReachable(ces::KeyPair(a).getPublicKeyAsHash(), "localhost:1");
  srv->_markPeerReachable(ces::KeyPair(b).getPublicKeyAsHash(), "localhost:2");

  // Budget far above 2 * cap: only 2*cap fans out, the rest refunds.
  ces::Bytes payload{'c', 'a', 'p'};
  uint64_t fanned = srv->originateGossip(payload, 1'000'000, Hash{});
  BOOST_CHECK_EQUAL(fanned, 2 * kCap);          // clipped to nPeers * cap

  // With the cap removed, the same budget fans out in full (no refund).
  CesConfig cfg2 = makeGossipConfig(dir, priv);
  cfg2.maxPeerReserveDisturbance = 0;           // uncapped
  // (reuse a fresh server so the peer table is rebuilt)
  srv->stop();
  auto dir2 = makeUniqueTempDir("ces_gossip_cap2");
  cfg2.dataDir = dir2;
  auto srv2 = std::make_unique<CesServer>(cfg2);
  BOOST_REQUIRE(srv2->start(0) > 0);
  srv2->_markPeerReachable(ces::KeyPair(a).getPublicKeyAsHash(), "localhost:1");
  srv2->_markPeerReachable(ces::KeyPair(b).getPublicKeyAsHash(), "localhost:2");
  uint64_t fanned2 = srv2->originateGossip(payload, 1'000'000, Hash{});
  BOOST_CHECK_EQUAL(fanned2, 1'000'000u);       // uncapped -> full budget
  srv2->stop();
}

// A hop forwards to at most gossipFanoutDegree peers. With 12 reachable peers
// and a per-peer cap C, the plan fans out degree legs (one C each), so the
// fanned total is degree*C; degree 0 forwards to all 12.
BOOST_AUTO_TEST_CASE(GossipFanoutDegreeLimit) {
  blog::init();
  blog::set_level(blog::info);

  const uint64_t kCap = 1000;
  const int kPeers = 12;

  auto mk = [&](const char* tag, uint32_t degree) -> uint64_t {
    auto dir = makeUniqueTempDir(std::string("ces_gossip_deg_") + tag);
    minx::Hash priv;
    priv.fill(0x8C);
    CesConfig cfg = makeGossipConfig(dir, priv);
    cfg.maxPeerReserveDisturbance = kCap;   // each leg clips to C
    cfg.gossipFanoutDegree = degree;
    auto srv = std::make_unique<CesServer>(cfg);
    BOOST_REQUIRE(srv->start(0) > 0);
    for (int i = 0; i < kPeers; ++i) {
      minx::Hash p;
      p.fill(static_cast<uint8_t>(0x10 + i));
      srv->_markPeerReachable(ces::KeyPair(p).getPublicKeyAsHash(),
                              "localhost:" + std::to_string(10000 + i));
    }
    ces::Bytes payload{'d', 'e', 'g'};
    uint64_t fanned = srv->originateGossip(payload, 1'000'000'000, Hash{});
    srv->stop();
    return fanned;
  };

  BOOST_CHECK_EQUAL(mk("d6", 6), 6 * kCap);       // degree 6: 6 legs
  BOOST_CHECK_EQUAL(mk("d0", 0), kPeers * kCap);  // degree 0: every peer
}

BOOST_AUTO_TEST_SUITE_END()
