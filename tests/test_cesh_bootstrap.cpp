// `cesh bootstrap` (src/cesh/bootstrap_command.cpp) against a local server,
// and the rpc port that cesh takes from the server's handshake when there is
// no --rpc-port. With no terminal, bootstrap prints the export line instead
// of starting a shell; --solutions bounds the mining loop.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"
#include "test_e2e_common.h"

#include <ces/account.h>
#include <ces/client.h>

#include <boost/test/unit_test.hpp>

using namespace ces;
using namespace ces::e2e;

namespace {

bool has(const std::string& s, const std::string& t) { return s.find(t) != std::string::npos; }

struct BootstrapFixture : E2EServerFixture {
  BootstrapFixture() : E2EServerFixture("cesh_boot") {}

  // cesh with no $CESH_WALLET and no $CESH_SERVER of the test runner, and
  // HOME in the temp dir, so a default wallet lands there.
  // `input` is what cesh reads on stdin (empty: /dev/null).
  std::string cesh(const std::string& env, const std::string& args,
                   const std::string& input = "") const {
    std::string in = input.empty() ? "" : "printf '" + input + "' | ";
    return inTempDir(in + "env -u CESH_WALLET -u CESH_SERVER HOME=" + tempDir.string() +
                     "/home " + env + " timeout -k 3 120 " + ceshBin +
                     " -l fatal -c --server localhost:" + std::to_string(serverPort) + " " +
                     args + (input.empty() ? " < /dev/null" : ""));
  }

  int64_t balanceOf(const KeyPair& k) {
    server->_drainLogic();
    boost::asio::ip::udp::endpoint ep(boost::asio::ip::address_v6::loopback(), serverPort);
    CesClient c(ep, false);
    c.start(0);
    c.setKey(k);
    int64_t bal = -1;
    uint32_t nonce = 0;
    if (c.connect()) c.queryAccount(Account::getMapKey(k.getPublicKeyAsHash()), bal, nonce);
    c.stop();
    return bal;
  }
};

}  // namespace

BOOST_FIXTURE_TEST_SUITE(CeshBootstrapTests, BootstrapFixture)

BOOST_AUTO_TEST_CASE(ExistingAccount_MinesOneAndPrintsExport) {
  ensurePoWEngine();
  const int64_t before = balanceOf(fundedKey);
  auto r = runShell(cesh("CESH_WALLET=" + fundedWalletHex, "bootstrap --solutions 1 -t 1"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  BOOST_CHECK_MESSAGE(has(r.out, "$CESH_WALLET · 1 key"), r.out);
  BOOST_CHECK_MESSAGE(has(r.out, fundedKey.getPublicKeyHexStr()), r.out);
  BOOST_CHECK_MESSAGE(has(r.out, "100 credits"), r.out);
  BOOST_CHECK_MESSAGE(has(r.out, "solution 1  +"), r.out);
  BOOST_CHECK_MESSAGE(has(r.out, "1 solution · +"), r.out);
  BOOST_CHECK_MESSAGE(has(r.out, "export CESH_SERVER=localhost:" + std::to_string(serverPort)), r.out);
  BOOST_CHECK_GT(balanceOf(fundedKey), before);
}

BOOST_AUTO_TEST_CASE(NoWallet_MakesOne) {
  auto r = runShell(cesh("", "bootstrap --solutions 0", "y\\n"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  BOOST_CHECK_MESSAGE(has(r.out, "No wallet yet"), r.out);
  BOOST_CHECK_MESSAGE(has(r.out, "1 key (new)"), r.out);
  BOOST_CHECK_MESSAGE(has(r.out, "none yet"), r.out);
  BOOST_CHECK(fs::exists(tempDir / "home" / ".cesh" / "CESH_WALLET"));
  // A second run keeps the wallet.
  auto again = runShell(cesh("", "bootstrap --solutions 0"));
  BOOST_CHECK_EQUAL(again.exitCode, 0);
  BOOST_CHECK(!has(again.out, "No wallet yet"));
  BOOST_CHECK(!has(again.out, "(new)"));
}

BOOST_AUTO_TEST_CASE(NoWallet_DeclinedStops) {
  auto r = runShell(cesh("", "bootstrap --solutions 0", "n\\n"));
  BOOST_CHECK_EQUAL(r.exitCode, 1);
  BOOST_CHECK(!fs::exists(tempDir / "home" / ".cesh" / "CESH_WALLET"));
}

BOOST_AUTO_TEST_CASE(DeadServer_Says_So) {
  auto r = runShell(inTempDir("env -u CESH_SERVER CESH_WALLET=" + fundedWalletHex +
                              " timeout -k 3 60 " + ceshBin +
                              " -l fatal --tries 1 --server localhost:1 bootstrap --solutions 0 < /dev/null"));
  BOOST_CHECK_EQUAL(r.exitCode, 1);
  BOOST_CHECK_MESSAGE(has(r.out, "localhost:1 does not answer"), r.out);
}

BOOST_AUTO_TEST_SUITE_END()

// ---------------------------------------------------------------------------
// The L2 commands take the rpc port from the server's handshake.
// ---------------------------------------------------------------------------

namespace {

struct AnnouncedRpcFixture {
  fs::path dir;
  std::unique_ptr<CesServer> server;
  uint16_t mainPort = 0;
  KeyPair key;

  AnnouncedRpcFixture() {
    blog::init();
    blog::set_level(blog::fatal);
    dir = makeUniqueTempDir("cesh_rpcport");
    minx::Hash priv;
    priv.fill(0xB3);
    CesConfig cfg = makeTestConfig(dir, priv, std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = {{"/ces/file/1", "builtin:file"}};
    cfg.cesFileStoreMaxBytes = 16ull * 1024 * 1024;
    server = std::make_unique<CesServer>(cfg);
    mainPort = server->start(0);
    BOOST_REQUIRE(server->_rpcBoundPort() > 0);
    server->_brr(key.getPublicKeyAsHash(), 10'000'000'000);
    server->_drainLogic();
  }
  ~AnnouncedRpcFixture() {
    if (server) server->stop();
    boost::system::error_code ec;
    fs::remove_all(dir, ec);
  }
};

}  // namespace

BOOST_FIXTURE_TEST_SUITE(CeshAnnouncedRpcPortTests, AnnouncedRpcFixture)

BOOST_AUTO_TEST_CASE(FileStat_WithoutRpcPortFlag_ReachesTheServer) {
  std::string path = "/h/" + key.getPublicKeyHexStr() + "/missing.txt";
  auto r = runShell("env -u CESH_SERVER CESH_WALLET=00" + key.getPrivateKeyHexStr() +
                    " timeout -k 3 60 " + findCeshBinary() + " -l fatal --server localhost:" +
                    std::to_string(mainPort) + " file stat " + path);
  BOOST_CHECK_MESSAGE(!has(r.out, "rpc port") && !has(r.out, "--rpc-port"), r.out);
  BOOST_CHECK_MESSAGE(has(r.out, "NOT_FOUND"), r.out);
}

// /h/@N/... in a remote path is the home of wallet key @N.
BOOST_AUTO_TEST_CASE(RemotePath_AtLabelIsTheKeysHome) {
  auto r = runShell("env -u CESH_SERVER CESH_WALLET=00" + key.getPrivateKeyHexStr() +
                    " timeout -k 3 60 " + findCeshBinary() + " -l fatal --server localhost:" +
                    std::to_string(mainPort) + " file stat /h/@0/missing.txt");
  BOOST_CHECK_MESSAGE(has(r.out, "NOT_FOUND") && !has(r.out, "BAD_NAME"), r.out);
}

// A key name works where a key goes: one name, one key on the server.
BOOST_AUTO_TEST_CASE(KeyName_AsDestination) {
  const std::string pre = "env -u CESH_SERVER CESH_WALLET=00" + key.getPrivateKeyHexStr() +
                          " timeout -k 3 60 " + findCeshBinary() + " -l fatal --server localhost:" +
                          std::to_string(mainPort) + " ";
  auto reg = runShell(pre + "keyname register boot_fixture_name");
  BOOST_REQUIRE_MESSAGE(reg.exitCode == 0, reg.out);
  auto q = runShell(pre + "query boot_fixture_name");
  BOOST_CHECK_EQUAL(q.exitCode, 0);
  BOOST_CHECK_MESSAGE(has(q.out, key.getPublicKeyHexStr()), q.out);
  auto t = runShell(pre + "transfer boot_fixture_name 1000");   // to itself, by name
  BOOST_CHECK_MESSAGE(has(t.out, "Success") || has(t.out, "Transfer"), t.out);
  BOOST_CHECK_MESSAGE(!has(t.out, "is not a key"), t.out);
  auto bad = runShell(pre + "query no_such_name_here");
  BOOST_CHECK(bad.exitCode != 0);
  BOOST_CHECK_MESSAGE(has(bad.out, "\"no_such_name_here\" is not a key"), bad.out);
}

// A key with no account reads as zeros; cesh query says so.
BOOST_AUTO_TEST_CASE(Query_KeyWithNoAccount_SaysSo) {
  KeyPair stranger;
  auto r = runShell("env -u CESH_SERVER CESH_WALLET=00" + key.getPrivateKeyHexStr() +
                    " timeout -k 3 60 " + findCeshBinary() + " -l fatal --server localhost:" +
                    std::to_string(mainPort) + " query " + stranger.getPublicKeyHexStr());
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  BOOST_CHECK_MESSAGE(has(r.out, "none (this key has no account on this server)"), r.out);
  auto send = runShell("env -u CESH_SERVER CESH_WALLET=00" + key.getPrivateKeyHexStr() +
                       " timeout -k 3 60 " + findCeshBinary() + " -l fatal --server localhost:" +
                       std::to_string(mainPort) + " transfer " + stranger.getPublicKeyHexStr() +
                       " 100000000");
  BOOST_CHECK_EQUAL(send.exitCode, 1);
  BOOST_CHECK_MESSAGE(has(send.out, "Hint: the destination key has no account on this server. Add --open"),
                      send.out);
  auto mine = runShell("env -u CESH_SERVER CESH_WALLET=00" + key.getPrivateKeyHexStr() +
                       " timeout -k 3 60 " + findCeshBinary() + " -l fatal --server localhost:" +
                       std::to_string(mainPort) + " query @0");
  BOOST_CHECK_MESSAGE(!has(mine.out, "no account"), mine.out);
}

BOOST_AUTO_TEST_SUITE_END()
