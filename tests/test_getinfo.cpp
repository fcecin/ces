/**
 * GET_INFO reply tests — verify the MINX INFO packet's CES-custom data
 * tail (min_secs_pow, pending_pows, tps, rpc_port) round-trips correctly
 * from the server's config to the client's accessors.
 */

#include "test_common.h"

#include <chrono>
#include <limits>

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

BOOST_AUTO_TEST_SUITE_END()
