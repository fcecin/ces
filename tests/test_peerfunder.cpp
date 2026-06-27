// test_peerfunder.cpp -- smoke test for the shipped peerfunder /s/ extension.
// peerfunder transfers a bounded amount from its program account to each
// reachable peer every tick (seeding channel liquidity). The smoke: a real
// server running the real extension funds a reachable peer, so that peer's
// account on the funder's ledger grows. Catches fundamental breakage (the
// extension launching, reading peers, and emitting transfers).

#include "test_ext_common.h"

using namespace ces;
using namespace ces::exttest;

BOOST_AUTO_TEST_SUITE(PeerfunderSmokeTests)

BOOST_AUTO_TEST_CASE(FundsReachablePeer) {
  blog::init();
  blog::set_level(blog::fatal);
  const std::string childBin = ces::e2e::findBinary("cesluajitd");

  // require_inbound=0: no PoW is exchanged in-process, so fund any reachable
  // peer. Fast tick, a small per-peer amount well under the program budget.
  const std::string conf =
    "emit_ms = 400\nemit_per_peer = 1000000\nper_peer_cap = 0"
    "\nmin_reserve = 0\nrequire_inbound = 0\n";

  ExtNode a;
  startExtNode(a, 0, childBin, "peerfunder", conf);
  wait_net();

  // A reachable peer to fund. peerfunder only does local ledger transfers, so
  // the peer need not be a live server -- a reachable table entry is enough.
  KeyPair peer;
  const minx::Hash peerPub = peer.getPublicKeyAsHash();
  a.server->_testAddPeerWithRpc(
    peerPub, "127.0.0.1:1", boost::asio::ip::make_address("127.0.0.1"), 1);

  // Observe the peer's balance on A's ledger climb as peerfunder emits.
  int64_t bal = 0;
  for (int t = 0; t < 100 && bal <= 0; ++t) {
    bal = balanceOnLedger(a.server.get(), peerPub);
    if (bal <= 0) std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  BOOST_CHECK_MESSAGE(bal > 0,
    "peerfunder never funded the reachable peer (balance " << bal << ")");

  stopExt(a);
}

BOOST_AUTO_TEST_SUITE_END()
