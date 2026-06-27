// ===========================================================================
// In-process multi-server network fuzz.
// ===========================================================================
//
// Stands up kNumServers CesServers in ONE process, each with the full L2
// stack (file/compute/lua/peer) mounted, then fires randomized file,
// compute, ledger, and peer ops at random servers and asserts each server's
// observable state matches a per-server oracle (send fuzz at one server,
// read it back and check it never leaked into another).
//
// This is the regression for the per-server-object refactor. The old design
// kept compute state (gInstances, gByPrefix, gNextPid, gUsedComputePorts)
// and the active-server pointer (gServer) in process globals, so a second
// CesServer in the same process clobbered the first: launches routed through
// whichever server set gServer last, instances from every server piled into
// one shared map, and pids were minted from one global counter. A shared
// singleton handler cross-contaminates instances/ledgers/files here and
// fails the isolation asserts below.
//
// The existing in-process multi-server tests (gossip, peering) pass without
// catching this because they exercise only the per-server ledger and the
// main-port gossip path, never the rpc-port L2 handlers.
//
// Deterministic: a fixed RNG seed makes every run identical, so a failure
// reproduces. cescompmockd is the child binary (a no-Lua plumbing stub),
// local-only instances (no per-instance port range needed).

#define BOOST_TEST_DYN_LINK
#include "test_common.h"
#include "test_e2e_common.h"

#include <ces/server.h>
#include <ces/account.h>
#include <ces/l2/file_client.h>
#include <ces/l2/compute_client.h>
#include <ces/l2/file_handler.h>
#include <ces/l2/compute_handler.h>
#include <ces/l2/compute_lua_handler.h>
#include <ces/l2/peer_handler.h>

#include <boost/asio/ip/address.hpp>

#include <chrono>
#include <map>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <vector>

using namespace ces;

namespace {

constexpr int kNumServers   = 20;
constexpr int kFuzzOps      = 700;
constexpr int kFilesPerNode = 6;   // distinct /p file slots fuzzed per node
constexpr int kNumProbes    = 4;   // shared account identities per node
constexpr int kMaxInstances = 4;   // computeMaxInstances per node

// One in-process node: a server plus the owner key that signs every L2 verb
// against it. Clients are held persistent (one bound channel each) and reused
// across the whole fuzz so the loop doesn't churn bind handshakes per op.
struct Node {
  std::unique_ptr<CesServer> server;
  fs::path dir;
  KeyPair owner;
  std::string sourcePath;             // owner's compute source under /h
  uint16_t rpcPort = 0;
  minx::Hash serverPub;
  std::unique_ptr<CesFileClient> fc;
  std::unique_ptr<CesComputeClient> cc;
};

// Quiet this test (20 servers + 72 child launches are noisy) without leaking
// the level into later suites: blog level is process-global and Boost runs
// every case in one process. Restores on scope exit, including a REQUIRE throw.
struct LogLevelGuard {
  blog::severity_level prev;
  LogLevelGuard()
    : prev(static_cast<blog::severity_level>(blog::fast_min_level)) {
    blog::set_level(blog::fatal);
  }
  ~LogLevelGuard() { blog::set_level(prev); }
};

bool pollLinked(CesServer* s, const minx::Hash& k, bool want) {
  for (int i = 0; i < 150; ++i) {
    if (s->peerHandler() && s->peerHandler()->isLinked(k) == want) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  return s->peerHandler() && s->peerHandler()->isLinked(k) == want;
}

} // namespace

BOOST_AUTO_TEST_SUITE(MultiServerNetworkTests)

BOOST_AUTO_TEST_CASE(TwentyServerNetworkFuzz) {
  blog::init();
  LogLevelGuard logGuard;

  const std::string childBin = ces::e2e::findBinary("cescompmockd");

  // -----------------------------------------------------------------------
  // Stand up the network: kNumServers, full L2 stack, distinct keys/dirs,
  // ephemeral main + rpc ports.
  // -----------------------------------------------------------------------
  std::vector<Node> nodes(kNumServers);
  for (int i = 0; i < kNumServers; ++i) {
    Node& n = nodes[i];
    n.dir = makeUniqueTempDir("multisrv_" + std::to_string(i));

    minx::Hash priv;
    priv.fill(static_cast<uint8_t>(0x11 + i));   // distinct, nonzero

    CesConfig cfg =
      makeTestConfig(n.dir, priv, std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;          // unique rpc port per server
    cfg.cesplexMounts = {
      {"/ces/file/1",    "builtin:file"},
      {"/ces/compute/1", "builtin:compute"},
      {"/ces/lua/1",     "builtin:lua"},
      {"/ces/peer/1",    "builtin:peer"},
    };
    cfg.cesFileStoreMaxBytes = 64ull * 1024 * 1024;
    cfg.feeFileRent  = 1;            // real rent; huge deposits keep files alive
    cfg.feeFileWrite = 0;
    cfg.feeFileRead  = 0;
    cfg.feeQuery     = 0;
    cfg.feeDiscountEnabled = false;
    cfg.computeMaxInstances = kMaxInstances;
    cfg.feeComputeSlotSec = 0;
    cfg.computePortBase = 0;         // local-only instances; no port range
    cfg.computePortCount = 0;
    cfg.cesComputeChildBinary = childBin;
    cfg.cesComputeWorkDir = (n.dir / "cescompute").string();

    n.server = std::make_unique<CesServer>(cfg);
    uint16_t mainPort = n.server->start(0);
    BOOST_REQUIRE_MESSAGE(mainPort > 0, "node " << i << " main bind failed");
    n.rpcPort = n.server->_rpcBoundPort();
    BOOST_REQUIRE_MESSAGE(n.rpcPort > 0, "node " << i << " rpc bind failed");
    n.serverPub = n.server->_serverKeyPair().getPublicKeyAsHash();

    // Fund the owner so signed verbs never starve, then a generously funded
    // compute source file under /h.
    n.server->_brr(n.owner.getPublicKeyAsHash(), 100'000'000'000ll);
    n.sourcePath = "/h/" + n.owner.getPublicKeyHexStr() + "/prog.bin";
  }
  wait_net();

  // -----------------------------------------------------------------------
  // Structural anti-singleton: every server owns its OWN handler objects.
  // Under the gServer design there were no per-server handler instances at
  // all (state was process-global, shared across servers). Require
  // kNumServers distinct, non-null handler pointers per role.
  // -----------------------------------------------------------------------
  std::set<const void*> fileH, compH, luaH, peerH;
  for (int i = 0; i < kNumServers; ++i) {
    Node& n = nodes[i];
    BOOST_REQUIRE_MESSAGE(n.server->fileHandler(),    "node " << i << " file");
    BOOST_REQUIRE_MESSAGE(n.server->computeHandler(), "node " << i << " compute");
    BOOST_REQUIRE_MESSAGE(n.server->luaHandler(),     "node " << i << " lua");
    BOOST_REQUIRE_MESSAGE(n.server->peerHandler(),    "node " << i << " peer");
    fileH.insert(n.server->fileHandler());
    compH.insert(n.server->computeHandler());
    luaH.insert(n.server->luaHandler());
    peerH.insert(n.server->peerHandler());
  }
  BOOST_REQUIRE_EQUAL(fileH.size(), size_t(kNumServers));
  BOOST_REQUIRE_EQUAL(compH.size(), size_t(kNumServers));
  BOOST_REQUIRE_EQUAL(luaH.size(),  size_t(kNumServers));
  BOOST_REQUIRE_EQUAL(peerH.size(), size_t(kNumServers));

  // Connect persistent owner-signed clients + create each compute source.
  for (int i = 0; i < kNumServers; ++i) {
    Node& n = nodes[i];
    n.fc = std::make_unique<CesFileClient>();
    n.fc->setServerPubkey(n.serverPub);
    BOOST_REQUIRE_MESSAGE(
      n.fc->connect("localhost", n.rpcPort, n.owner) == CES_OK,
      "node " << i << " file client connect failed");

    n.cc = std::make_unique<CesComputeClient>();
    n.cc->setServerPubkey(n.serverPub);
    BOOST_REQUIRE_MESSAGE(
      n.cc->connect("localhost", n.rpcPort, n.owner) == CES_OK,
      "node " << i << " compute client connect failed");

    uint64_t outBal = 0, outCost = 0;
    BOOST_REQUIRE_MESSAGE(
      n.fc->create(n.sourcePath, /*size=*/1, /*pricePerKb=*/0,
                   /*deposit=*/10'000'000'000ull, outBal, outCost) == CES_OK,
      "node " << i << " source create failed");
  }

  // Probe accounts: the SAME kNumProbes identities exist on every node, each
  // with an independent balance. A shared ledger would merge them.
  std::vector<KeyPair> probes(kNumProbes);

  // -----------------------------------------------------------------------
  // Oracle state.
  // -----------------------------------------------------------------------
  std::map<std::pair<int, std::string>, ces::Bytes> fileOracle;
  std::set<std::pair<int, std::string>> fileCreated;
  std::vector<std::pair<int, std::string>> createdList;
  std::vector<std::set<uint64_t>> pidsByNode(kNumServers);
  std::vector<std::pair<int, uint64_t>> allPids;   // (node, pid) sampling pool
  std::map<std::pair<int, int>, int64_t> ledgerOracle;

  std::mt19937 rng(0xCE5C0FFEu);   // fixed seed: reproducible fuzz
  auto pick = [&](int hi) { return static_cast<int>(rng() % static_cast<uint32_t>(hi)); };
  auto randBytes = [&](size_t len) {
    ces::Bytes b(len);
    for (size_t k = 0; k < len; ++k) b[k] = static_cast<uint8_t>(rng() & 0xFF);
    return b;
  };
  auto filePath = [](int k) { return "/p/f" + std::to_string(k) + ".bin"; };

  // Counters so the test reports what it actually exercised.
  int nPut = 0, nGet = 0, nLaunch = 0, nList = 0, nStat = 0, nKill = 0,
      nCredit = 0, nVerify = 0;

  // -----------------------------------------------------------------------
  // Fuzz loop. Every read op checks the other side against the oracle.
  // -----------------------------------------------------------------------
  for (int op = 0; op < kFuzzOps; ++op) {
    const int roll = pick(100);
    const int ni = pick(kNumServers);
    Node& n = nodes[ni];

    if (roll < 25) {
      // FILE_PUT: write random bytes; create the slot on first touch.
      const int k = pick(kFilesPerNode);
      const std::string path = filePath(k);
      const auto key = std::make_pair(ni, path);
      const ces::Bytes content = randBytes(static_cast<size_t>(1 + pick(2048)));
      uint64_t outBal = 0, outCost = 0;
      if (!fileCreated.count(key)) {
        uint8_t rc = n.fc->create(path, /*size=*/4096, /*pricePerKb=*/0,
                                  /*deposit=*/10'000'000ull, outBal, outCost);
        BOOST_REQUIRE_MESSAGE(rc == CES_OK,
          "node " << ni << " create " << path << " rc=" << int(rc));
        fileCreated.insert(key);
        createdList.push_back(key);
      }
      uint8_t rc = n.fc->write(path, /*offset=*/0, content, outBal);
      BOOST_REQUIRE_MESSAGE(rc == CES_OK,
        "node " << ni << " write " << path << " rc=" << int(rc));
      fileOracle[key] = content;
      ++nPut;
    } else if (roll < 43) {
      // FILE_GET: read a previously-written slot back, assert byte-equality.
      if (createdList.empty()) continue;
      const auto key = createdList[pick(static_cast<int>(createdList.size()))];
      auto it = fileOracle.find(key);
      if (it == fileOracle.end()) continue;
      const ces::Bytes& want = it->second;
      ces::Bytes got;
      minx::Hash rangeHash;
      uint8_t rc = nodes[key.first].fc->read(
        key.second, /*offset=*/0,
        static_cast<uint32_t>(want.size()), got, rangeHash);
      BOOST_REQUIRE_MESSAGE(rc == CES_OK,
        "node " << key.first << " read " << key.second << " rc=" << int(rc));
      BOOST_REQUIRE_MESSAGE(got == want,
        "node " << key.first << " read " << key.second
                << " content mismatch (" << got.size() << " vs "
                << want.size() << " bytes)");
      ++nGet;
    } else if (roll < 56) {
      // COMPUTE_LAUNCH: spawn one instance of this node's source.
      if (static_cast<int>(pidsByNode[ni].size()) >= kMaxInstances - 1) continue;
      uint64_t pid = 0, started = 0;
      uint8_t rc = n.cc->launch(n.sourcePath, pid, started);
      BOOST_REQUIRE_MESSAGE(rc == CES_OK,
        "node " << ni << " launch rc=" << int(rc));
      BOOST_REQUIRE_MESSAGE(pid > 0, "node " << ni << " launch pid==0");
      pidsByNode[ni].insert(pid);
      allPids.emplace_back(ni, pid);
      ++nLaunch;
    } else if (roll < 65) {
      // COMPUTE_LIST: owner's list on its node == exactly that node's pids.
      std::vector<CesComputeClient::InstanceInfo> list;
      uint8_t rc = n.cc->list(list);
      BOOST_REQUIRE_MESSAGE(rc == CES_OK, "node " << ni << " list rc=" << int(rc));
      std::set<uint64_t> seen;
      for (const auto& info : list) {
        BOOST_REQUIRE_MESSAGE(info.sourceName == n.sourcePath,
          "node " << ni << " list foreign source " << info.sourceName);
        seen.insert(info.pid);
      }
      BOOST_REQUIRE_MESSAGE(seen == pidsByNode[ni],
        "node " << ni << " list set mismatch (" << seen.size()
                << " vs " << pidsByNode[ni].size() << ")");
      ++nList;
    } else if (roll < 81) {
      // COMPUTE_STAT (cross-node isolation): sample a pid VALUE minted on any
      // node, query an arbitrary node. Found iff THIS node minted it; if so it
      // must be this node's own instance. Under gServer the shared map (and
      // globally-unique pids) would surface a foreign instance here.
      if (allPids.empty()) continue;
      const uint64_t pid = allPids[pick(static_cast<int>(allPids.size()))].second;
      const bool expectOk = pidsByNode[ni].count(pid) > 0;
      CesComputeClient::InstanceInfo info;
      uint8_t rc = n.cc->stat(pid, info);
      if (expectOk) {
        BOOST_REQUIRE_MESSAGE(rc == CES_OK,
          "node " << ni << " stat own pid " << pid << " rc=" << int(rc));
        BOOST_REQUIRE_MESSAGE(info.pid == pid && info.sourceName == n.sourcePath,
          "node " << ni << " stat pid " << pid << " wrong instance");
      } else {
        BOOST_REQUIRE_MESSAGE(rc == CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND,
          "node " << ni << " stat foreign pid " << pid
                  << " leaked (rc=" << int(rc) << ")");
      }
      ++nStat;
    } else if (roll < 88) {
      // COMPUTE_KILL: tear down one of this node's instances.
      if (pidsByNode[ni].empty()) continue;
      auto it = pidsByNode[ni].begin();
      std::advance(it, pick(static_cast<int>(pidsByNode[ni].size())));
      const uint64_t pid = *it;
      uint8_t rc = n.cc->kill(pid);
      BOOST_REQUIRE_MESSAGE(rc == CES_OK,
        "node " << ni << " kill pid " << pid << " rc=" << int(rc));
      pidsByNode[ni].erase(it);
      ++nKill;
    } else if (roll < 94) {
      // LEDGER_CREDIT: credit a shared probe identity on this node only.
      const int p = pick(kNumProbes);
      const int64_t amt = 1 + pick(1'000'000);
      n.server->_brr(probes[p].getPublicKeyAsHash(), amt);
      ledgerOracle[{ni, p}] += amt;
      ++nCredit;
    } else {
      // LEDGER_VERIFY: the probe's balance on this node matches the oracle,
      // independent of the same identity's balance on every other node.
      const int p = pick(kNumProbes);
      int64_t bal = 0; uint32_t nonce = 0; uint64_t lastAmt = 0; uint32_t lastTime = 0;
      HashPrefix dest{};
      n.server->unsignedQueryAccount(
        Account::getMapKey(probes[p].getPublicKeyAsHash()),
        bal, nonce, dest, lastAmt, lastTime);
      const int64_t want = ledgerOracle.count({ni, p}) ? ledgerOracle[{ni, p}] : 0;
      BOOST_REQUIRE_MESSAGE(bal == want,
        "node " << ni << " probe " << p << " balance " << bal
                << " != oracle " << want);
      ++nVerify;
    }
  }

  // -----------------------------------------------------------------------
  // Final consistency sweep: re-check every node's instance set and every
  // probe balance against the oracle.
  // -----------------------------------------------------------------------
  for (int i = 0; i < kNumServers; ++i) {
    Node& n = nodes[i];
    std::vector<CesComputeClient::InstanceInfo> list;
    BOOST_REQUIRE_EQUAL(n.cc->list(list), CES_OK);
    std::set<uint64_t> seen;
    for (const auto& info : list) {
      BOOST_CHECK_EQUAL(info.sourceName, n.sourcePath);
      seen.insert(info.pid);
    }
    BOOST_CHECK_MESSAGE(seen == pidsByNode[i],
      "final: node " << i << " instance set drift");

    for (int p = 0; p < kNumProbes; ++p) {
      int64_t bal = 0; uint32_t nonce = 0; uint64_t lastAmt = 0; uint32_t lastTime = 0;
      HashPrefix dest{};
      n.server->unsignedQueryAccount(
        Account::getMapKey(probes[p].getPublicKeyAsHash()),
        bal, nonce, dest, lastAmt, lastTime);
      const int64_t want = ledgerOracle.count({i, p}) ? ledgerOracle[{i, p}] : 0;
      BOOST_CHECK_MESSAGE(bal == want,
        "final: node " << i << " probe " << p << " " << bal << " != " << want);
    }
  }

  BOOST_TEST_MESSAGE("fuzz ops: put=" << nPut << " get=" << nGet
    << " launch=" << nLaunch << " list=" << nList << " stat=" << nStat
    << " kill=" << nKill << " credit=" << nCredit << " verify=" << nVerify);

  // -----------------------------------------------------------------------
  // Peer mesh: establish REAL server-to-server /ces/peer/1 links between
  // in-process servers (disjoint pairs), dialed at each peer's own rpc port.
  // Lower-pubkey side dials; reconcileNow() drives it without waiting for the
  // tick. Dial over ::1 (rpc binds v6 dual-stack).
  // -----------------------------------------------------------------------
  const auto v6lo = boost::asio::ip::address(boost::asio::ip::address_v6::loopback());
  const int pairs = kNumServers / 2;
  for (int j = 0; j < pairs; ++j) {
    Node& a = nodes[2 * j];
    Node& b = nodes[2 * j + 1];
    a.server->_testAddPeerWithRpc(
      b.serverPub, "[::1]:" + std::to_string(b.rpcPort), v6lo, b.rpcPort);
    b.server->_testAddPeerWithRpc(
      a.serverPub, "[::1]:" + std::to_string(a.rpcPort), v6lo, a.rpcPort);
  }
  for (int j = 0; j < pairs; ++j) {
    nodes[2 * j].server->peerHandler()->reconcileNow();
    nodes[2 * j + 1].server->peerHandler()->reconcileNow();
  }
  for (int j = 0; j < pairs; ++j) {
    Node& a = nodes[2 * j];
    Node& b = nodes[2 * j + 1];
    BOOST_CHECK_MESSAGE(pollLinked(a.server.get(), b.serverPub, true),
      "pair " << j << ": node " << (2 * j) << " did not link to "
              << (2 * j + 1));
    BOOST_CHECK_MESSAGE(pollLinked(b.server.get(), a.serverPub, true),
      "pair " << j << ": node " << (2 * j + 1) << " did not link to "
              << (2 * j));
  }

  // -----------------------------------------------------------------------
  // Teardown: drop clients, stop servers, remove temp dirs.
  // -----------------------------------------------------------------------
  for (auto& n : nodes) {
    if (n.fc) n.fc->disconnect();
    if (n.cc) n.cc->disconnect();
  }
  for (auto& n : nodes) {
    if (n.server) n.server->stop();
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  for (auto& n : nodes) {
    boost::system::error_code ec;
    fs::remove_all(n.dir, ec);
  }
}

BOOST_AUTO_TEST_SUITE_END()
