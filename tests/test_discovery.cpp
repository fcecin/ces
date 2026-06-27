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

BOOST_AUTO_TEST_SUITE_END()
