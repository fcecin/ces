// ===========================================================================
// builtin:peer / /ces/peer/1 server-to-server mesh tests
// ===========================================================================
//
// Two layers:
//   PeerLinkLogic  - the pure reconcile decision (computePeerLinkActions):
//                    dial only higher-key dialable peers, drop links whose
//                    peer left the table. No I/O.
//   PeerLinkServer - the inbound path against a live rpc-enabled server via
//                    CesPlexClient: the bind gate (peers only) and the
//                    metering opt-out (peer channels are never metered).
//
// The full outbound mesh (one server dialing another) needs two
// rpc-enabled servers in one process, which the handler-singleton model
// does not support; that path is covered by the multi-process E2E harness.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"

#include <ces/l2/peer_handler.h>
#include <ces/cesplex/session.h>
#include <ces/cesplex/meter.h>
#include <ces/server.h>

#include <boost/asio/ip/address.hpp>

#include <chrono>
#include <set>
#include <thread>
#include <vector>

using namespace ces;

namespace {

// A hash whose ordering is controlled by its first byte (operator< on
// std::array is lexicographic).
minx::Hash hkey(uint8_t b) {
  minx::Hash h;
  h.fill(0);
  h[0] = b;
  return h;
}

PeerLinkTarget tgt(const minx::Hash& k, bool dialable) {
  PeerLinkTarget t;
  t.ckey = k;
  t.dialable = dialable;
  if (dialable) {
    t.endpoint = minx::SockAddr(
      boost::asio::ip::make_address("127.0.0.1"), 9999);
  }
  return t;
}

bool pollLinked(CesServer* server, const minx::Hash& k, bool want) {
  for (int i = 0; i < 100; ++i) {
    if (server->peerHandler() && server->peerHandler()->isLinked(k) == want)
      return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  return server->peerHandler() && server->peerHandler()->isLinked(k) == want;
}

} // namespace

// ---------------------------------------------------------------------------
// Pure reconcile decision
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_SUITE(PeerLinkLogic)

BOOST_AUTO_TEST_CASE(EmptyNoActions) {
  auto a = computePeerLinkActions({}, hkey(0x10), {});
  BOOST_CHECK(a.toDial.empty());
  BOOST_CHECK(a.toDrop.empty());
}

BOOST_AUTO_TEST_CASE(DialsHigherKeyDialablePeer) {
  minx::Hash me = hkey(0x10), high = hkey(0x20);
  auto a = computePeerLinkActions({tgt(high, true)}, me, {});
  BOOST_REQUIRE_EQUAL(a.toDial.size(), 1u);
  BOOST_CHECK(a.toDial[0] == high);
  BOOST_CHECK(a.toDrop.empty());
}

BOOST_AUTO_TEST_CASE(DoesNotDialLowerKeyPeer) {
  // We are the higher-pubkey side; the lower side dials us. We wait.
  minx::Hash me = hkey(0x10), low = hkey(0x05);
  auto a = computePeerLinkActions({tgt(low, true)}, me, {});
  BOOST_CHECK(a.toDial.empty());
  BOOST_CHECK(a.toDrop.empty());
}

BOOST_AUTO_TEST_CASE(DoesNotDialNonDialablePeer) {
  minx::Hash me = hkey(0x10), high = hkey(0x20);
  auto a = computePeerLinkActions({tgt(high, false)}, me, {});
  BOOST_CHECK(a.toDial.empty());
  BOOST_CHECK(a.toDrop.empty());
}

BOOST_AUTO_TEST_CASE(DoesNotRedialLinkedPeer) {
  minx::Hash me = hkey(0x10), high = hkey(0x20);
  std::set<minx::Hash> links{high};
  auto a = computePeerLinkActions({tgt(high, true)}, me, links);
  BOOST_CHECK(a.toDial.empty());
  BOOST_CHECK(a.toDrop.empty());
}

BOOST_AUTO_TEST_CASE(DropsLinkToDepartedPeer) {
  minx::Hash me = hkey(0x10), gone = hkey(0x07);
  std::set<minx::Hash> links{gone};
  auto a = computePeerLinkActions({}, me, links);
  BOOST_REQUIRE_EQUAL(a.toDrop.size(), 1u);
  BOOST_CHECK(a.toDrop[0] == gone);
  BOOST_CHECK(a.toDial.empty());
}

BOOST_AUTO_TEST_CASE(MixedDialDropKeep) {
  minx::Hash me = hkey(0x10);
  minx::Hash high = hkey(0x20);        // dial (higher, dialable, unlinked)
  minx::Hash low = hkey(0x05);         // skip (lower side waits)
  minx::Hash linkedHigh = hkey(0x30);  // keep (already linked, still a peer)
  minx::Hash gone = hkey(0x40);        // drop (linked but not a peer)
  std::vector<PeerLinkTarget> peers{
    tgt(high, true), tgt(low, true), tgt(linkedHigh, true)};
  std::set<minx::Hash> links{linkedHigh, gone};
  auto a = computePeerLinkActions(peers, me, links);
  BOOST_REQUIRE_EQUAL(a.toDial.size(), 1u);
  BOOST_CHECK(a.toDial[0] == high);
  BOOST_REQUIRE_EQUAL(a.toDrop.size(), 1u);
  BOOST_CHECK(a.toDrop[0] == gone);
}

BOOST_AUTO_TEST_SUITE_END()

// ---------------------------------------------------------------------------
// Inbound bind: gate + metering opt-out against a live server
// ---------------------------------------------------------------------------

namespace {

struct PeerServerFixture {
  fs::path tempDir;
  std::unique_ptr<CesServer> server;
  uint16_t rpcPort = 0;

  PeerServerFixture() {
    blog::init();
    blog::set_level(blog::fatal);
    blog::set_level("plex", blog::fatal);
    tempDir = makeUniqueTempDir("peerlink_test");
    minx::Hash priv;
    priv.fill(0x5A);
    CesConfig cfg = makeTestConfig(
      tempDir, priv, std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts["/ces/peer/1"] = "builtin:peer";  // wire the mesh
    server = std::make_unique<CesServer>(cfg);
    server->start();
    rpcPort = server->_rpcBoundPort();
    BOOST_REQUIRE(rpcPort != 0);
  }

  ~PeerServerFixture() {
    if (server) server->stop(false);
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(PeerLinkServer, PeerServerFixture)

// A non-peer's bind SUCCEEDS (every server speaks /ces/peer/1), but the
// handler refuses it: no link forms, the channel is closed. The peer-only
// gate lives in PeerHandler::serve, not in the bind handshake.
BOOST_AUTO_TEST_CASE(GateRejectsNonPeer) {
  KeyPair stranger;  // fresh key, not in the peer table
  minx::Hash strangerHash = stranger.getPublicKeyAsHash();
  CesPlexClient c;
  c.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  uint8_t rc = c.connect("localhost", rpcPort, ces::CES_PEER_PROTO, stranger);
  CES_CHECK_OK(rc);  // bind accepted; refusal is in the handler
  wait_net();        // let serve() run + close
  // No link is established for a non-peer.
  BOOST_CHECK(server->peerHandler() &&
              !server->peerHandler()->isLinked(strangerHash));
  c.disconnect();
}

// A peer pubkey binds OK, the link registers, and the channel is never
// metered. Added with rpcPort 0 (member but non-dialable) so the server's
// own reconcile cannot race an outbound dial against this inbound bind.
BOOST_AUTO_TEST_CASE(GateAcceptsPeerUnmeteredAndLinks) {
  KeyPair peerKey;
  minx::Hash peerHash = peerKey.getPublicKeyAsHash();
  server->_testAddPeerWithRpc(
    peerHash, "127.0.0.1:0",
    boost::asio::ip::make_address("127.0.0.1"), 0);

  CesPlexClient c;
  c.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  uint8_t rc = c.connect("localhost", rpcPort, ces::CES_PEER_PROTO, peerKey);
  CES_REQUIRE_OK(rc);

  BOOST_CHECK(pollLinked(server.get(), peerHash, true));

  // The /ces/peer/1 channel must not appear in the ChannelMeter.
  auto snaps = server->_channelMeter()->snapshot();
  for (const auto& s : snaps) {
    BOOST_CHECK(s.tag.find("/ces/peer/1") == std::string::npos);
  }

  // Reconcile tears the live link down once the peer leaves the table.
  server->_removePeer(peerHash);
  server->peerHandler()->reconcileNow();
  BOOST_CHECK(pollLinked(server.get(), peerHash, false));

  c.disconnect();
}

// Regression: peer is no longer auto-mounted. With /ces/peer/1 absent from
// [cesplex_mounts] the mesh handler is not created, even with the plex port up.
// (The fixture above wires it, so its cases cover the mounted case.)
BOOST_AUTO_TEST_CASE(PeerNotMountedWhenNotWired) {
  fs::path d = makeUniqueTempDir("peerlink_unwired");
  minx::Hash priv; priv.fill(0x5B);
  CesConfig cfg = makeTestConfig(d, priv, std::numeric_limits<uint64_t>::max());
  cfg.rpcPort = 0;
  cfg.rpcAutoPort = true;
  cfg.cesplexMounts["/ces/file/1"] = "builtin:file";  // rpc up, but peer absent
  cfg.cesFileStoreMaxBytes = 1024;
  auto s = std::make_unique<CesServer>(cfg);
  s->start(0);  // ephemeral main port (the fixture server already holds 53830)
  BOOST_REQUIRE(s->_rpcBoundPort() != 0);
  BOOST_CHECK(s->fileHandler() != nullptr);   // file wired -> mounted
  BOOST_CHECK(s->peerHandler() == nullptr);   // peer not wired -> not mounted
  s->stop(false);
  boost::system::error_code ec; fs::remove_all(d, ec);
}

BOOST_AUTO_TEST_SUITE_END()
