// test_peerclusterer.cpp -- the peerclusterer /s/ extension driving a real,
// in-process network of CesServers into closed peer cliques.
//
// This is the convergence test the per-server-object refactor unlocked: N real
// rpc-enabled CesServers in ONE process, each auto-launching the shipped
// extensions/peerclusterer.lua via the production extension loader (cfg.extensions
// + a /s/ drop), gossiping peer lists over /ces/peer/1, and add-only nudging
// their peer tables toward cliques of `group_size`. The assertion is on the
// ground-truth peer table (CesServer::_peerSnapshot), not the program's view.
//
// Seeding stands in for discovery: a sparse but connected "fuel" graph with live
// /ces/peer/1 links (so the pheromone flows), from which the clusterer closes
// the cliques. The clusterer is stigmergic (no consensus, no votes); convergence
// is emergent and measurable, which is exactly what these cases assert:
//   ClosesOneClique     - a star closes into a single clique
//   MultipleClusters    - two disjoint stars close into two disjoint cliques
//   VaryingClusterSize  - the same logic closes a clique of a different size
//   SparseIdles         - no triadic opportunity -> zero speculative adds

#include "test_common.h"
#include "test_e2e_common.h"   // ces::e2e::findBinary

#include <ces/account.h>
#include <ces/keys.h>
#include <ces/server.h>
#include <ces/l2/peer_handler.h>

#include <boost/asio/ip/address.hpp>
#include <boost/test/unit_test.hpp>

#include <chrono>
#include <fstream>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace ces;

namespace {

struct Node {
  fs::path dir;
  std::unique_ptr<CesServer> server;
  uint16_t mainPort = 0;
  uint16_t rpcPort = 0;
  minx::Hash pub;
};

std::string readSource() {
  const std::string path =
    std::string(CES_SOURCE_DIR) + "/extensions/peerclusterer.lua";
  std::ifstream f(path, std::ios::binary);
  BOOST_REQUIRE_MESSAGE(f.good(), "cannot open peerclusterer.lua at " + path);
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

void writeFile(const fs::path& p, const std::string& content) {
  fs::create_directories(p.parent_path());
  std::ofstream f(p, std::ios::binary | std::ios::trunc);
  f << content;
}

// Bring up a peerclusterer-enabled node: full L2 stack, real cesluajitd, the
// shipped extension dropped into /s/ and enabled via cfg.extensions, with the
// given operator config.
void startNode(Node& n, int idx, const std::string& childBin,
               const std::string& extSrc, const std::string& conf,
               bool clusterer = true) {
  n.dir = makeUniqueTempDir("pclust_" + std::to_string(idx));
  minx::Hash priv;
  priv.fill(static_cast<uint8_t>(0x31 + idx));

  CesConfig cfg =
    makeTestConfig(n.dir, priv, std::numeric_limits<uint64_t>::max());
  cfg.rpcPort = 0;
  cfg.rpcAutoPort = true;
  cfg.cesplexMounts = {
    {"/ces/file/1",    "builtin:file"},
    {"/ces/compute/1", "builtin:compute"},
    {"/ces/lua/1",     "builtin:lua"},
    {"/ces/peer/1",    "builtin:peer"},
  };
  cfg.cesFileStoreDir = (n.dir / "cesfilestore").string();
  cfg.cesFileStoreMaxBytes = 64ull * 1024 * 1024;
  cfg.feeFileRent = 0;
  cfg.feeFileWrite = 0;
  cfg.feeFileRead = 0;
  cfg.feeQuery = 0;
  cfg.feeDiscountEnabled = false;
  cfg.computeMaxInstances = 4;
  cfg.feeComputeSlotSec = 0;
  cfg.computePortBase = 0;
  cfg.computePortCount = 0;
  cfg.cesComputeChildBinary = childBin;
  cfg.cesComputeWorkDir = (n.dir / "cescompute").string();

  // A non-clusterer node is a full L2 server (so /ces/peer/1 links still form)
  // that simply does NOT run peerclusterer -- used to prove such a peer is never
  // recruited into a cluster.
  if (clusterer) {
    cfg.extensions = { "peerclusterer" };
    // Production extension deploy: drop the source + config under /s/; the file
    // handler stamps the sidecar at startup reconcile, then launchExtensions runs it.
    writeFile(fs::path(cfg.cesFileStoreDir) / "s" / "peerclusterer.lua", extSrc);
    writeFile(fs::path(cfg.cesFileStoreDir) / "s" / "peerclusterer.conf", conf);
  }

  n.server = std::make_unique<CesServer>(cfg);
  n.mainPort = n.server->start(0);
  BOOST_REQUIRE_MESSAGE(n.mainPort > 0, "node " << idx << " main bind failed");
  n.rpcPort = n.server->_rpcBoundPort();
  BOOST_REQUIRE_MESSAGE(n.rpcPort > 0, "node " << idx << " rpc bind failed");
  n.pub = n.server->_serverKeyPair().getPublicKeyAsHash();
}

const boost::asio::ip::address kV6Lo =
  boost::asio::ip::address(boost::asio::ip::address_v6::loopback());

// Establish a bidirectional /ces/peer/1 seed link (the discovery "fuel").
void seedEdge(Node& a, Node& b) {
  a.server->_testAddPeerWithRpc(
    b.pub, "[::1]:" + std::to_string(b.mainPort), kV6Lo, b.rpcPort);
  b.server->_testAddPeerWithRpc(
    a.pub, "[::1]:" + std::to_string(a.mainPort), kV6Lo, a.rpcPort);
}

bool pollLinked(CesServer* s, const minx::Hash& k) {
  for (int i = 0; i < 200; ++i) {
    if (s->peerHandler() && s->peerHandler()->isLinked(k)) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  return s->peerHandler() && s->peerHandler()->isLinked(k);
}

std::set<minx::Hash> peerSet(CesServer* s) {
  std::set<minx::Hash> out;
  for (const auto& p : s->_peerSnapshot()) out.insert(p.ckey);
  return out;
}

bool hasPeer(Node& a, Node& b) { return peerSet(a.server.get()).count(b.pub) > 0; }

// Seed the given undirected edges as live /ces/peer/1 links, then drive the
// reconcile and wait for every seed link to establish (so gossip can flow).
void linkSeed(std::vector<Node>& nodes,
              const std::vector<std::pair<int, int>>& edges) {
  for (auto& e : edges) seedEdge(nodes[e.first], nodes[e.second]);
  for (auto& n : nodes) n.server->peerHandler()->reconcileNow();
  for (auto& e : edges) {
    BOOST_REQUIRE_MESSAGE(pollLinked(nodes[e.first].server.get(),
                                     nodes[e.second].pub),
      "seed link " << e.first << "-" << e.second << " did not come up");
    BOOST_REQUIRE_MESSAGE(pollLinked(nodes[e.second].server.get(),
                                     nodes[e.first].pub),
      "seed link " << e.second << "-" << e.first << " did not come up");
  }
}

void stopAll(std::vector<Node>& nodes) {
  for (auto& n : nodes) if (n.server) n.server->stop();
  std::this_thread::sleep_for(std::chrono::milliseconds(150));
  for (auto& n : nodes) {
    boost::system::error_code ec;
    fs::remove_all(n.dir, ec);
  }
}

// Wait (up to ~timeoutMs) until every (i,j) in `members` x `members`, i != j,
// is a mutual peer -- i.e. the members form a closed clique.
bool waitClique(std::vector<Node>& nodes, const std::vector<int>& members,
                int timeoutMs) {
  auto closed = [&]() {
    for (int i : members)
      for (int j : members)
        if (i != j && !hasPeer(nodes[i], nodes[j])) return false;
    return true;
  };
  for (int t = 0; t * 250 < timeoutMs && !closed(); ++t)
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
  return closed();
}

std::string confFor(int groupSize) {
  // peer_credit_target = 0: no PoW is exchanged in-process, so econ-fitness is
  // disabled for tests (a peer counts on reciprocation alone). The 24h dud
  // window is never reached in a seconds-long test, so no peers are reclaimed.
  return "group_size = " + std::to_string(groupSize) +
         "\nmax_peers = 50\ntick_ms = 400\ngossip_cap = 64"
         "\npeer_credit_target = 0\n";
}

}  // namespace

BOOST_AUTO_TEST_SUITE(PeerClustererTests)

// A star (node 0 the only hub) with group_size = 4: every node closes the K4 in
// its peer table -- the leaves learn each other from the hub's gossip and add the
// triadic edges. Add-only, so the assertion is "every node peered with all others".
BOOST_AUTO_TEST_CASE(ClosesOneClique) {
  blog::init();
  blog::set_level(blog::fatal);
  const std::string childBin = ces::e2e::findBinary("cesluajitd");
  const std::string extSrc = readSource();

  const int N = 4;
  std::vector<Node> nodes(N);
  for (int i = 0; i < N; ++i) startNode(nodes[i], i, childBin, extSrc, confFor(4));
  wait_net();
  linkSeed(nodes, {{0, 1}, {0, 2}, {0, 3}});

  std::vector<int> all = {0, 1, 2, 3};
  BOOST_CHECK_MESSAGE(waitClique(nodes, all, 60000), "K4 did not close");
  for (int i = 0; i < N; ++i)
    for (int j = 0; j < N; ++j)
      if (i != j)
        BOOST_CHECK_MESSAGE(hasPeer(nodes[i], nodes[j]),
          "node " << i << " never peered node " << j);
  stopAll(nodes);
}

// Two disjoint stars (0 hubs 1,2,3; 4 hubs 5,6,7), no cross edges, group_size = 4.
// Each star must close its own K4, and -- because the two halves share no gossip
// -- NO cross-cluster edge may form. Tests "multiple clusters" + "distinct
// clusters stay distinct".
BOOST_AUTO_TEST_CASE(MultipleClusters) {
  blog::init();
  blog::set_level(blog::fatal);
  const std::string childBin = ces::e2e::findBinary("cesluajitd");
  const std::string extSrc = readSource();

  const int N = 8;
  std::vector<Node> nodes(N);
  for (int i = 0; i < N; ++i) startNode(nodes[i], i, childBin, extSrc, confFor(4));
  wait_net();
  linkSeed(nodes, {{0, 1}, {0, 2}, {0, 3}, {4, 5}, {4, 6}, {4, 7}});

  std::vector<int> a = {0, 1, 2, 3}, b = {4, 5, 6, 7};
  BOOST_CHECK_MESSAGE(waitClique(nodes, a, 60000), "cluster A K4 did not close");
  BOOST_CHECK_MESSAGE(waitClique(nodes, b, 60000), "cluster B K4 did not close");

  // No cross-cluster edges: a node in A is never peered with a node in B.
  for (int i : a)
    for (int j : b)
      BOOST_CHECK_MESSAGE(!hasPeer(nodes[i], nodes[j]),
        "cross-cluster edge formed: " << i << "-" << j);
  stopAll(nodes);
}

// The same logic closes a clique of a different target size (K5 from a 5-star).
BOOST_AUTO_TEST_CASE(VaryingClusterSize) {
  blog::init();
  blog::set_level(blog::fatal);
  const std::string childBin = ces::e2e::findBinary("cesluajitd");
  const std::string extSrc = readSource();

  const int N = 5;
  std::vector<Node> nodes(N);
  for (int i = 0; i < N; ++i) startNode(nodes[i], i, childBin, extSrc, confFor(5));
  wait_net();
  linkSeed(nodes, {{0, 1}, {0, 2}, {0, 3}, {0, 4}});

  std::vector<int> all = {0, 1, 2, 3, 4};
  BOOST_CHECK_MESSAGE(waitClique(nodes, all, 70000), "K5 did not close");
  stopAll(nodes);
}

// Two nodes, a single seed edge, group_size = 4: there is no triadic opportunity
// (each side's 2-hop view is just itself), so a correct clusterer makes ZERO
// speculative adds and idles. Asserts it never strands or invents peers.
BOOST_AUTO_TEST_CASE(SparseIdles) {
  blog::init();
  blog::set_level(blog::fatal);
  const std::string childBin = ces::e2e::findBinary("cesluajitd");
  const std::string extSrc = readSource();

  const int N = 2;
  std::vector<Node> nodes(N);
  for (int i = 0; i < N; ++i) startNode(nodes[i], i, childBin, extSrc, confFor(4));
  wait_net();
  linkSeed(nodes, {{0, 1}});

  // Give the clusterer ample ticks to (mis)behave, then assert no growth.
  std::this_thread::sleep_for(std::chrono::seconds(6));
  BOOST_CHECK_EQUAL(peerSet(nodes[0].server.get()).size(), size_t(1));
  BOOST_CHECK_EQUAL(peerSet(nodes[1].server.get()).size(), size_t(1));
  BOOST_CHECK_MESSAGE(hasPeer(nodes[0], nodes[1]) && hasPeer(nodes[1], nodes[0]),
    "the single seed edge should remain");
  stopAll(nodes);
}

// Nodes 0..3 run peerclusterer; node 4 is a full server (peer/1 enabled) that
// does NOT run it, seeded as a peer of hub node 0. The clusterers must close the
// K4 among themselves and must NEVER recruit node 4 -- it is connected to a
// cluster member but never speaks the mesh, so node 0 never hears it, never
// flags it a speaker, and 1/2/3 never vouch or add it. (A peer/1-DISABLED node
// is strictly more excluded: it cannot even link, so it is never heard either.)
BOOST_AUTO_TEST_CASE(NonSpeakerNotRecruited) {
  blog::init();
  blog::set_level(blog::fatal);
  const std::string childBin = ces::e2e::findBinary("cesluajitd");
  const std::string extSrc = readSource();

  const int N = 5;   // 0..3 clusterer, 4 non-clusterer
  std::vector<Node> nodes(N);
  for (int i = 0; i < 4; ++i) startNode(nodes[i], i, childBin, extSrc, confFor(4));
  startNode(nodes[4], 4, childBin, extSrc, confFor(4), /*clusterer=*/false);
  wait_net();
  // Star around 0 for the clusterers, plus 0-4 (node 4 is a peer of the hub).
  linkSeed(nodes, {{0, 1}, {0, 2}, {0, 3}, {0, 4}});

  std::vector<int> clique = {0, 1, 2, 3};
  BOOST_CHECK_MESSAGE(waitClique(nodes, clique, 60000), "K4 did not close");

  // The non-speaker is never pulled into the cluster: 1/2/3 never peer node 4.
  for (int i = 1; i <= 3; ++i)
    BOOST_CHECK_MESSAGE(!hasPeer(nodes[i], nodes[4]),
      "node " << i << " wrongly recruited the non-clusterer node 4");
  // Node 4 itself never clusters; it keeps only its seed peer (the hub).
  BOOST_CHECK_EQUAL(peerSet(nodes[4].server.get()).size(), size_t(1));
  stopAll(nodes);
}

// The dud-reclamation path, driven by a SHORT dud_timeout so the real 24h logic
// fires in seconds (no mocks, no clock manipulation -- dud_timeout_ms is a
// config). Topology is a path A--B--C (not a triangle): B has heard C (B--C is
// linked), so B vouches C to A, and A (wanting group_size=3) adds C. But A--C
// never links in-process, so A never hears C; after the window A reclaims C as a
// dud and, because a culled dud is never re-recruited, leaves it out.
BOOST_AUTO_TEST_CASE(ReclaimsOwnDud) {
  blog::init();
  blog::set_level(blog::fatal);
  const std::string childBin = ces::e2e::findBinary("cesluajitd");
  const std::string extSrc = readSource();
  const std::string conf =
    "group_size = 3\nmax_peers = 50\ntick_ms = 300\ngossip_cap = 64"
    "\npeer_credit_target = 0\ndud_timeout_ms = 3000\n";

  const int N = 3;   // 0=A, 1=B, 2=C
  std::vector<Node> nodes(N);
  for (int i = 0; i < N; ++i) startNode(nodes[i], i, childBin, extSrc, conf);
  wait_net();
  linkSeed(nodes, {{0, 1}, {1, 2}});   // path A--B--C; A and C are NOT linked

  // A must first ADD C (learned + vouched via B), then RECLAIM it once the dud
  // window passes without C ever reciprocating to A.
  bool sawAdded = false;
  bool reclaimed = false;
  for (int t = 0; t < 120; ++t) {       // ~12s, well past the 3s window
    bool hasC = peerSet(nodes[0].server.get()).count(nodes[2].pub) > 0;
    if (hasC) sawAdded = true;
    if (sawAdded && !hasC) { reclaimed = true; break; }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  BOOST_CHECK_MESSAGE(sawAdded, "A never added the vouched peer C");
  BOOST_CHECK_MESSAGE(reclaimed, "A did not reclaim the dud C after the window");
  // And it stays reclaimed (a culled dud is not re-recruited).
  std::this_thread::sleep_for(std::chrono::seconds(2));
  BOOST_CHECK_MESSAGE(!peerSet(nodes[0].server.get()).count(nodes[2].pub),
    "A re-added a reclaimed dud");
  // B keeps C (for B, C is a live, reciprocating member).
  BOOST_CHECK_MESSAGE(peerSet(nodes[1].server.get()).count(nodes[2].pub),
    "B wrongly dropped its live peer C");
  stopAll(nodes);
}

BOOST_AUTO_TEST_SUITE_END()
