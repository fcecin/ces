/**
 * GET_INFO reply tests — verify the MINX INFO packet's CES-custom data
 * tail (min_secs_pow, pending_pows, tps, rpc_port) round-trips correctly
 * from the server's config to the client's accessors. Also covers
 * setRemoteEndpoint: moving a client to a new server and the inbound
 * address fence that drops a previous server's stragglers.
 */

#include "test_common.h"

#include <chrono>
#include <limits>

// MinxInfo carrying a server key, with >= 7 bytes of data so incomingInfo
// reaches the serverKey_ assignment.
static minx::MinxInfo makeInfo(const minx::Hash& skey) {
  minx::Bytes data;
  for (int i = 0; i < 7; ++i)
    data.push_back(0);
  return minx::MinxInfo{0, 0, 0, 1, skey, data};
}

BOOST_AUTO_TEST_SUITE(GetInfoTests)

BOOST_AUTO_TEST_CASE(RpcPortRoundtrip) {
  blog::init();
  blog::set_level(blog::info);

  fs::path dir = makeUniqueTempDir("ces_getinfo");
  minx::Hash priv; priv.fill(0xAB);

  CesConfig cfg = makeTestConfig(
    dir, priv, std::numeric_limits<uint64_t>::max());
  // OS-allocated rpc port; the test reads it back via _rpcBoundPort() below.
  cfg.rpcPort = 0;
  cfg.rpcAutoPort = true;

  auto server = std::make_unique<CesServer>(cfg);
  uint16_t serverPort = server->start(0);
  BOOST_REQUIRE(serverPort != 0);
  uint16_t boundRpc = server->_rpcBoundPort();
  BOOST_REQUIRE_MESSAGE(boundRpc != 0,
    "server failed to bind rpc port — cannot test non-zero rpc_port");

  KeyPair kp;
  CesClient client(testServerEp(serverPort), false);
  client.setKey(kp);
  BOOST_REQUIRE(client.start(0));
  BOOST_REQUIRE(client.connect());

  BOOST_CHECK_EQUAL(client.getServerRpcPort(), boundRpc);

  client.disconnect();
  client.stop();
  server->stop();
  server.reset();
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  boost::system::error_code ec;
  fs::remove_all(dir, ec);
}

BOOST_AUTO_TEST_CASE(RpcPortZeroWhenDisabled) {
  blog::init();
  blog::set_level(blog::info);

  fs::path dir = makeUniqueTempDir("ces_getinfo_zero");
  minx::Hash priv; priv.fill(0xCD);

  CesConfig cfg = makeTestConfig(
    dir, priv, std::numeric_limits<uint64_t>::max());
  // cfg.rpcPort left at its 0 default

  auto server = std::make_unique<CesServer>(cfg);
  uint16_t serverPort = server->start(0);
  BOOST_REQUIRE(serverPort != 0);
  BOOST_REQUIRE_EQUAL(server->_rpcBoundPort(), 0);

  KeyPair kp;
  CesClient client(testServerEp(serverPort), false);
  client.setKey(kp);
  BOOST_REQUIRE(client.start(0));
  BOOST_REQUIRE(client.connect());

  BOOST_CHECK_EQUAL(client.getServerRpcPort(), 0);

  client.disconnect();
  client.stop();
  server->stop();
  server.reset();
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  boost::system::error_code ec;
  fs::remove_all(dir, ec);
}

// The inbound fence accepts the current remote and drops any other, and the
// accepted address moves when the client is re-pointed. Drives incomingInfo
// directly to stand in for replies arriving from each address; no socket.
BOOST_AUTO_TEST_CASE(SetRemoteEndpointFenceFollowsRemote) {
  auto epA = testServerEp(9501);
  auto epB = testServerEp(9502);
  minx::Hash keyA = makeHash("repoint-server-A");
  minx::Hash keyB = makeHash("repoint-server-B");

  CesClient client(epB, false);

  client.incomingInfo(epB, makeInfo(keyB));
  BOOST_TEST((client.getServerKey() == keyB));

  client.incomingInfo(epA, makeInfo(keyA));
  BOOST_TEST((client.getServerKey() == keyB));

  BOOST_TEST(client.setRemoteEndpoint(epA));

  client.incomingInfo(epA, makeInfo(keyA));
  BOOST_TEST((client.getServerKey() == keyA));

  client.incomingInfo(epB, makeInfo(keyB));
  BOOST_TEST((client.getServerKey() == keyA));
}

// A wrong-mode call reports failure rather than silently doing nothing.
BOOST_AUTO_TEST_CASE(SetRemoteEndpointWrongModeReturnsFalse) {
  CesClient udpClient(testServerEp(9503), false);
  boost::asio::ip::tcp::endpoint tcpEp(boost::asio::ip::address_v6::loopback(),
                                       9504);
  BOOST_TEST(udpClient.setRemoteEndpoint(testServerEp(9505)));
  BOOST_TEST(!udpClient.setRemoteEndpoint(tcpEp));

  CesClient tcpClient(tcpEp, false);
  BOOST_TEST(!tcpClient.setRemoteEndpoint(testServerEp(9505)));
}

// Re-point a live client between two servers and confirm the second handshake
// reaches the second server (distinct keys), exercising disconnect + reconnect.
BOOST_AUTO_TEST_CASE(SetRemoteEndpointRedirectBetweenLiveServers) {
  blog::init();
  fs::path dirA = makeUniqueTempDir("ces_repoint_a");
  fs::path dirB = makeUniqueTempDir("ces_repoint_b");
  minx::Hash privA;
  privA.fill(0xA1);
  minx::Hash privB;
  privB.fill(0xB2);

  CesServer serverA(
    makeTestConfig(dirA, privA, std::numeric_limits<uint64_t>::max()));
  CesServer serverB(
    makeTestConfig(dirB, privB, std::numeric_limits<uint64_t>::max()));
  uint16_t portA = serverA.start(0);
  uint16_t portB = serverB.start(0);
  BOOST_REQUIRE(portA > 0);
  BOOST_REQUIRE(portB > 0);

  KeyPair clientKey;
  CesClient client(testServerEp(portA), false);
  client.start(0);
  client.setKey(clientKey);
  BOOST_REQUIRE(client.connect());
  minx::Hash keyA = client.getServerKey();

  BOOST_TEST(client.setRemoteEndpoint(testServerEp(portB)));
  BOOST_REQUIRE(client.connect());
  minx::Hash keyB = client.getServerKey();

  BOOST_TEST((keyA != keyB));

  client.stop();
  serverA.stop();
  serverB.stop();
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  boost::system::error_code ec;
  fs::remove_all(dirA, ec);
  fs::remove_all(dirB, ec);
}

BOOST_AUTO_TEST_SUITE_END()
