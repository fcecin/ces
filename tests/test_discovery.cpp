// test_discovery.cpp -- smoke test for the shipped discovery /s/ extension.
// discovery crawls the network as a CES client: it validates servers with
// ces.ping (free MINX GetInfo, so it works without the PoW engine) and projects
// the reachable, identified ones into its host's peer table via ces.add_peer.
// The smoke: given a seed pointing at a live server, discovery learns that
// server's identity and adds it as a peer. Catches fundamental breakage (the
// extension launching, pinging, and promoting).

#include "test_ext_common.h"

using namespace ces;
using namespace ces::exttest;

BOOST_AUTO_TEST_SUITE(DiscoverySmokeTests)

BOOST_AUTO_TEST_CASE(PromotesSeedIntoPeerTable) {
  blog::init();
  blog::set_level(blog::fatal);
  const std::string childBin = ces::e2e::findBinary("cesluajitd");

  // B: a plain live server, the discovery seed target.
  ExtNode b;
  startExtNode(b, 1, childBin, "", "");

  // A: runs discovery, seeded with B's main address. min_peer_target=0 so it
  // does not raise the host peer target (no RandomX miner in the test);
  // peer_min_credit=0 so it does not try to fund. Fast crawl/maint.
  const std::string conf =
    "seeds = localhost:" + std::to_string(b.mainPort) +
    "\ncrawl_ms = 400\nmaint_ms = 700\nprobe_ms = 1000\nactive_target = 20"
    "\nmin_peer_target = 0\npeer_min_credit = 0\nsave_ms = 600000\n";

  // discovery does outbound client networking (ces.ping the seed), so its
  // instance needs a leased UDP port range -- without it ces.ping is disabled.
  ExtNode a;
  startExtNode(a, 0, childBin, "discovery", conf, /*computePorts=*/16);
  wait_net();

  // discovery should ping B, learn its pubkey, and promote it into A's table.
  bool found = false;
  for (int t = 0; t < 150 && !found; ++t) {   // up to ~15s
    found = peerSet(a.server.get()).count(b.pub) > 0;
    if (!found) std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  BOOST_CHECK_MESSAGE(found, "discovery never promoted the seed server B");

  stopExt(a);
  stopExt(b);
}

// Real 3-node gossip transport: A self-announces its address over CES_GOSSIP on
// the discovery typed-broadcast dest; an intermediary hub relays the flood; C's
// discovery hears the announce, pings A and promotes it. The gossip corridors are
// funded with printed money (_brr), not mining, so the test stays fast. Exercises
// the 128-zero-prefix typed-broadcast routing in handleGossip end to end, plus
// discovery's announce-send and on_gossip-receive.
BOOST_AUTO_TEST_CASE(AnnounceReachesPeerOverGossipHub) {
  blog::init();
  blog::set_level(blog::fatal);
  const std::string childBin = ces::e2e::findBinary("cesluajitd");

  // A announces its OWN address, so it needs a known main port up front.
  const uint16_t aPort = findFreeUdpPortRange(1);

  // A: discovery self-announcing every 500ms (and once on boot). No seeds, no
  // crawl pressure -- it only announces.
  const std::string aConf =
    "seeds =\nmin_peer_target = 0\npeer_min_credit = 0\ncrawl_ms = 60000"
    "\nannounce = localhost:" + std::to_string(aPort) +
    "\nannounce_ms = 500\nannounce_budget = 100000000\n";
  ExtNode a;
  startExtNode(a, 0, childBin, "discovery", aConf, /*computePorts=*/0,
              /*mainPort=*/aPort);

  // hub: a plain server that just relays the gossip flood.
  ExtNode hub;
  startExtNode(hub, 1, childBin, "", "");

  // C: discovery that must LEARN A from the relayed announce, then ping+promote
  // (needs a compute port for ces.ping).
  const std::string cConf =
    "seeds =\nmin_peer_target = 0\npeer_min_credit = 0\ncrawl_ms = 400"
    "\nmaint_ms = 700\nprobe_ms = 1000\nactive_target = 20\nsave_ms = 600000\n";
  ExtNode c;
  startExtNode(c, 2, childBin, "discovery", cConf, /*computePorts=*/16);
  wait_net();

  // Print money to fund the gossip path A -> hub -> C (no mining).
  fundGossipCorridor(a, hub, 10'000'000'000ll);   // hub collects A's announce
  fundGossipCorridor(hub, c, 10'000'000'000ll);   // C collects hub's relay

  // A re-announces every 500ms; once a flood carries it through hub, C learns A.
  bool found = false;
  for (int t = 0; t < 300 && !found; ++t) {   // up to ~30s
    found = peerSet(c.server.get()).count(a.pub) > 0;
    if (!found) std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  BOOST_CHECK_MESSAGE(found,
    "C did not learn A from the announce gossip relayed via hub");

  stopExt(c);
  stopExt(hub);
  stopExt(a);
}

BOOST_AUTO_TEST_SUITE_END()
