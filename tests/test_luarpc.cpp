// test_luarpc.cpp — end-to-end outbound from a lua program: /ces/luarpc/1
// (peer) plus ces.file_client / ces.compute_client (verb clients).
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

  explicit LuaRpcFixture(uint16_t portCount = 16) {
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
    cfg.computePortCount = portCount;
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

// Same fixture, but with NO compute port range — instances get no rpc port, so
// outbound clients must fail permanently.
struct LuaNoPortFixture : LuaRpcFixture {
  LuaNoPortFixture() : LuaRpcFixture(0) {}
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

// ===========================================================================
// ces.file_client / ces.compute_client — outbound L2 verb clients driven from
// a lua program, riding the instance's own CesPlex endpoint (the firewall-
// correct socket) and reusing the same CesFileClient / CesComputeClient codec
// cesh uses. Each test launches a program that dials ITS OWN server and, on a
// successful round-trip, transfers a sentinel to a beacon the test polls.
// ===========================================================================

BOOST_AUTO_TEST_SUITE(LuaClientTests)

// file_client: every verb over a PINNED channel. Staged codes localize a
// failure; 77 = all verbs round-tripped.
BOOST_FIXTURE_TEST_CASE(ProgramFileClient, LuaRpcFixture) {
  KeyPair beacon;
  const auto beaconPk = beacon.getPublicKeyAsHash();
  server->_brr(beaconPk, 1);   // expect 1 + 77
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string rpc = std::to_string(rpcPort);
  const auto serverPk = server->_serverKeyPair().getPublicKeyAsHash();

  const std::string path = "/h/" + ownerHex + "/fcprog.bin";
  const std::string src =
    "local B = '" + luaBytes(beaconPk.data(), 32) + "'\n"
    "local fc = ces.file_client('127.0.0.1:" + rpc + "', '"
      + luaBytes(serverPk.data(), 32) + "')\n"
    "if not fc then ces.transfer(B, 2); return end\n"
    "if not fc:create('/p/cov', 5, 0, 100000000, 'text/plain') then ces.transfer(B, 3); return end\n"
    "if not fc:write('/p/cov', 0, 'hello') then ces.transfer(B, 4); return end\n"
    "if fc:read('/p/cov', 0, 5) ~= 'hello' then ces.transfer(B, 5); return end\n"
    "local st = fc:stat('/p/cov')\n"
    "if not (st and st.size == 5 and st.content_type == 'text/plain') then ces.transfer(B, 6); return end\n"
    "local ab, ns = fc:append('/p/cov', 'XYZ')\n"
    "if not (ab and ns == 8) then ces.transfer(B, 7); return end\n"
    "if fc:read('/p/cov', 0, 8) ~= 'helloXYZ' then ces.transfer(B, 8); return end\n"
    "if fc:resize('/p/cov', 4) ~= 4 then ces.transfer(B, 9); return end\n"
    "if not fc:deposit('/p/cov', 1000) then ces.transfer(B, 10); return end\n"
    "if not fc:withdraw('/p/cov', 500) then ces.transfer(B, 11); return end\n"
    "if fc:set_price('/p/cov', 42) ~= 42 then ces.transfer(B, 12); return end\n"
    "if not fc:delete('/p/cov') then ces.transfer(B, 13); return end\n"
    "fc:close()\n"
    "ces.transfer(B, 77)\n";
  const auto progPk = deploy(path, src);
  server->_brr(progPk, 100'000'000'000ull);   // fund the program's own ops
  launch(path);

  int64_t bal = 0;
  for (int i = 0; i < 200 && bal < 78; i++) {
    bal = balanceOf(beaconPk);
    if (bal < 78) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_CHECK_EQUAL(bal, 78);
}

// compute_client: the program file_client-creates + funds a noop source it
// owns, then exercises the full lifecycle on it — launch, stat, instances,
// kill — and transfers the sentinel only if every step succeeded.
BOOST_FIXTURE_TEST_CASE(ProgramComputeClient, LuaRpcFixture) {
  KeyPair beacon;
  const auto beaconPk = beacon.getPublicKeyAsHash();
  server->_brr(beaconPk, 1);   // expect 1 + 9
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string rpc = std::to_string(rpcPort);

  const std::string path = "/h/" + ownerHex + "/ccprog.bin";
  // Staged beacon codes localize a failure: 2 no fc, 3 create, 4 no cc,
  // 200+errcode launch, 300+errcode stat, 400+nins mismatch; 9 = full success.
  const std::string src =
    "local NOOP = 'ces.run()\\n'\n"
    "local B = '" + luaBytes(beaconPk.data(), 32) + "'\n"
    "local fc = ces.file_client('127.0.0.1:" + rpc + "')\n"
    "if not fc then ces.transfer(B, 2); return end\n"
    "local cb = fc:create('/p/cl_noop', #NOOP, 0, 10000000000, 'text/x-lua')\n"
    "if not cb then ces.transfer(B, 3); return end\n"
    "fc:write('/p/cl_noop', 0, NOOP)\n"
    "fc:close()\n"
    "local cc = ces.compute_client('127.0.0.1:" + rpc + "')\n"
    "if not cc then ces.transfer(B, 4); return end\n"
    "local id, lerr = cc:launch('/p/cl_noop')\n"
    "if not id then ces.transfer(B, 200 + (lerr or 0)); return end\n"
    "local info, serr = cc:stat(id)\n"
    "if not info then cc:kill(id); ces.transfer(B, 300 + (serr or 0)); return end\n"
    "local ids = cc:instances('/p/cl_noop')\n"
    "local mine = cc:list()\n"
    "local ok = 0\n"
    "if info.instance_id ~= id then ok = 410\n"
    "elseif not (ids and #ids >= 1) then ok = 411\n"
    "elseif not (mine and #mine >= 1) then ok = 412 end\n"
    "cc:kill(id)\n"
    "cc:close()\n"
    "if ok == 0 then ces.transfer(B, 9) else ces.transfer(B, ok) end\n";
  const auto progPk = deploy(path, src);
  server->_brr(progPk, 100'000'000'000ull);
  launch(path);

  int64_t bal = 0;
  for (int i = 0; i < 300 && bal < 10; i++) {
    bal = balanceOf(beaconPk);
    if (bal < 10) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_CHECK_EQUAL(bal, 10);
}

// file_client error model: a wrong-pubkey pin must be rejected; a missing file
// must yield ces.err.FILE_NOT_FOUND. 44 = both behaved.
BOOST_FIXTURE_TEST_CASE(FileClientErrors, LuaRpcFixture) {
  KeyPair beacon;
  const auto beaconPk = beacon.getPublicKeyAsHash();
  server->_brr(beaconPk, 1);   // expect 1 + 44
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string rpc = std::to_string(rpcPort);
  KeyPair wrong;   // a pubkey that is NOT the server's
  const auto wrongPk = wrong.getPublicKeyAsHash();

  const std::string path = "/h/" + ownerHex + "/errprog.bin";
  const std::string src =
    "local B = '" + luaBytes(beaconPk.data(), 32) + "'\n"
    "local bad = ces.file_client('127.0.0.1:" + rpc + "', '"
      + luaBytes(wrongPk.data(), 32) + "')\n"
    "if bad ~= nil then ces.transfer(B, 91); return end\n"
    "local fc = ces.file_client('127.0.0.1:" + rpc + "')\n"
    "if not fc then ces.transfer(B, 2); return end\n"
    "local d, err = fc:read('/p/nope', 0, 5)\n"
    "fc:close()\n"
    "if d ~= nil then ces.transfer(B, 92); return end\n"
    "if err ~= ces.err.FILE_NOT_FOUND then ces.transfer(B, 93); return end\n"
    "ces.transfer(B, 44)\n";
  const auto progPk = deploy(path, src);
  server->_brr(progPk, 100'000'000'000ull);
  launch(path);

  int64_t bal = 0;
  for (int i = 0; i < 200 && bal < 45; i++) {
    bal = balanceOf(beaconPk);
    if (bal < 45) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_CHECK_EQUAL(bal, 45);
}

// Permanent-disable contract: no compute port range → no rpc endpoint → the
// outbound file_client must fail (nil + string err), not hang or retry.
BOOST_FIXTURE_TEST_CASE(FileClientNoRpcPort, LuaNoPortFixture) {
  KeyPair beacon;
  const auto beaconPk = beacon.getPublicKeyAsHash();
  server->_brr(beaconPk, 1);   // expect 1 + 66
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string rpc = std::to_string(rpcPort);

  const std::string path = "/h/" + ownerHex + "/noport.bin";
  const std::string src =
    "local B = '" + luaBytes(beaconPk.data(), 32) + "'\n"
    "local fc, err = ces.file_client('127.0.0.1:" + rpc + "')\n"
    "if fc ~= nil then ces.transfer(B, 91); return end\n"
    "if type(err) ~= 'string' then ces.transfer(B, 92); return end\n"
    "ces.transfer(B, 66)\n";
  const auto progPk = deploy(path, src);
  server->_brr(progPk, 100'000'000'000ull);
  launch(path);

  int64_t bal = 0;
  for (int i = 0; i < 200 && bal < 67; i++) {
    bal = balanceOf(beaconPk);
    if (bal < 67) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_CHECK_EQUAL(bal, 67);
}

BOOST_AUTO_TEST_SUITE_END()
