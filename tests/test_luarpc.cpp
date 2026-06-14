// test_luarpc.cpp — end-to-end /ces/luarpc/1.
//
// Spins up real cesluajitd instances (the existing compute tests use the
// no-Lua cescompmockd, so they never exercise luarpc). One instance runs an
// echo SERVER program (ces.luarpc.set_listener + run); another runs a CLIENT
// program that ces.luarpc.connect()s to it, writes a payload, and — on
// receiving its echo back via on_data — transfers to a beacon account. The
// test observes the beacon balance, which proves the whole symmetric path:
// connect (dial out) + serve (accept) + conn:write + on_data, both ways.

#include "test_common.h"
#include "test_e2e_common.h"   // ces::e2e::findBinary

#include <ces/account.h>
#include <ces/client.h>
#include <ces/keys.h>
#include <ces/server.h>
#include <ces/l2/compute_client.h>
#include <ces/l2/compute_handler.h>   // _computeTestInstanceRpcPort
#include <ces/l2/file_client.h>
#include <ces/l2/file_handler.h>      // fileHandlerReadProgramPubkey

#include <boost/test/unit_test.hpp>

#include <array>
#include <chrono>
#include <cstdio>
#include <memory>
#include <string>
#include <thread>

using namespace ces;

namespace {

// Bake 32 raw bytes as a Lua string literal using 3-digit \ddd escapes
// (zero-padded so there's never any digit-run ambiguity).
std::string luaBytes(const uint8_t* p, size_t n) {
  std::string s;
  char buf[8];
  for (size_t i = 0; i < n; i++) {
    std::snprintf(buf, sizeof(buf), "\\%03u", static_cast<unsigned>(p[i]));
    s += buf;
  }
  return s;
}

// A compute-enabled server backed by the REAL cesluajitd child, with a port
// range big enough for two instances (each leases a CES + an rpc port), plus
// a CesClient on the main port for balance queries.
struct LuaRpcFixture {
  fs::path dir;
  std::unique_ptr<CesServer> server;
  std::unique_ptr<CesClient> client;
  uint16_t mainPort = 0;
  uint16_t rpcPort = 0;
  KeyPair ownerKey;

  LuaRpcFixture() {
    blog::init();
    blog::set_level(blog::fatal);
    dir = makeUniqueTempDir("luarpc");
    minx::Hash priv;
    priv.fill(0xD3);
    CesConfig cfg =
      makeTestConfig(dir, priv, std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = {
      {"/ces/file/1",    "builtin:file"},
      {"/ces/compute/1", "builtin:compute"},
    };
    cfg.cesFileStoreMaxBytes = 16ull * 1024 * 1024;
    cfg.feeFileRent = 1;
    cfg.computeMaxInstances = 8;
    cfg.computePortBase = 39200;
    cfg.computePortCount = 16;
    cfg.feeComputeSlotSec = 1;
    cfg.cesComputeChildBinary = ces::e2e::findBinary("cesluajitd");
    cfg.cesComputeWorkDir = (dir / "cescompute").string();

    server = std::make_unique<CesServer>(cfg);
    mainPort = server->start(0);
    rpcPort = server->_rpcBoundPort();
    server->_brr(ownerKey.getPublicKeyAsHash(), 100'000'000'000);

    boost::asio::ip::udp::endpoint ep(
      boost::asio::ip::address_v6::loopback(), mainPort);
    client = std::make_unique<CesClient>(ep, false);
    client->start(0);
    client->setKey(ownerKey);
    client->connect();
    wait_net();
  }

  ~LuaRpcFixture() {
    if (client) client->stop();
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    boost::system::error_code ec;
    fs::remove_all(dir, ec);
  }

  // Deploy `src` as a file at `path`; return its program-account pubkey.
  std::array<uint8_t, 32> deploy(const std::string& path,
                                 const std::string& src) {
    CesFileClient fc;
    fc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(fc.connect("localhost", rpcPort, ownerKey));
    uint64_t fb = 0, cost = 0;
    CES_REQUIRE_OK(fc.create(path, src.size(), 0, 10'000'000'000,
                             "text/x-lua", fb, cost));
    ces::Bytes content(src.begin(), src.end());
    CES_REQUIRE_OK(fc.write(path, 0, content, fb));
    fc.disconnect();
    std::array<uint8_t, 32> pk{};
    BOOST_REQUIRE(fileHandlerReadProgramPubkey(path, pk));
    return pk;
  }

  uint64_t launch(const std::string& path) {
    CesComputeClient cc;
    cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));
    uint64_t id = 0, st = 0;
    CES_REQUIRE_OK(cc.launch(path, id, st));
    cc.disconnect();
    return id;
  }

  int64_t balanceOf(const minx::Hash& pubkey) {
    HashPrefix mapKey = Account::getMapKey(pubkey);
    int64_t bal = 0;
    uint32_t nonce = 0;
    client->queryAccount(mapKey, bal, nonce);
    return bal;
  }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(LuaRpcTests)

BOOST_FIXTURE_TEST_CASE(ProgramToProgramEcho, LuaRpcFixture) {
  KeyPair beacon;
  const auto beaconPk = beacon.getPublicKeyAsHash();
  server->_brr(beaconPk, 1);   // create the beacon (1 credit) so we expect 1+7
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();

  // 1. Echo server program.
  const std::string serverPath = "/h/" + ownerHex + "/echo.bin";
  const std::string serverSrc =
    "ces.luarpc.set_listener({ on_data = function(c, b) c:write(b) end })\n"
    "ces.luarpc.run()\n";
  const auto serverPk = deploy(serverPath, serverSrc);
  const uint64_t serverId = launch(serverPath);

  // 2. The server's rpc port (server-side allocation is immediate); then a
  //    grace period for the child to actually bind its endpoint.
  uint16_t serverRpc = 0;
  for (int i = 0; i < 100 && serverRpc == 0; i++) {
    serverRpc = _computeTestInstanceRpcPort(serverId);
    if (serverRpc == 0)
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_REQUIRE_MESSAGE(serverRpc != 0, "echo server got no rpc port");
  std::this_thread::sleep_for(std::chrono::seconds(2));  // endpoint bind

  // 3. Client program: dial the server, write PINGPONG, and on receiving the
  //    echo back transfer 7 to the beacon.
  const std::string clientSrc =
    "ces.luarpc.set_listener({ on_data = function(c, b)\n"
    "  if b == 'PINGPONG' then ces.transfer('"
      + luaBytes(beaconPk.data(), 32) + "', 7) end\n"
    "end })\n"
    "local conn = ces.luarpc.connect('127.0.0.1:" + std::to_string(serverRpc)
      + "', '" + luaBytes(serverPk.data(), 32) + "')\n"
    "if conn then conn:write('PINGPONG') end\n"
    "ces.luarpc.run()\n";
  const std::string clientPath = "/h/" + ownerHex + "/client.bin";
  const auto clientPk = deploy(clientPath, clientSrc);
  server->_brr(clientPk, 1'000'000'000);   // fund the client's transfer
  launch(clientPath);

  // 4. Observe: the beacon reaches 1 + 7 = 8.
  int64_t bal = 0;
  for (int i = 0; i < 200 && bal < 8; i++) {
    bal = balanceOf(beaconPk);
    if (bal < 8) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_CHECK_EQUAL(bal, 8);
}

BOOST_AUTO_TEST_SUITE_END()
