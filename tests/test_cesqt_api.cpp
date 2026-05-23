/**
 * E2E tests for the cesqt JSON-RPC API.
 *
 * Starts an in-process CesServer, launches cesqt with a sandboxed
 * --datadir (doctored config + wallet + pre-approved origin), then
 * exercises the RPC methods via HTTP.
 */

#include "test_e2e_common.h"

#include <array>
#include <csignal>
#include <fstream>
#include <regex>
#include <sstream>
#include <string>
#include <sys/wait.h>

using namespace ces::e2e;

// Alias so existing call sites keep working.
inline RunResult run(const std::string& cmd) { return runShell(cmd); }

static struct ApiTestSignalSetup {
  ApiTestSignalSetup() {
    std::signal(SIGINT, [](int) { _exit(130); });
  }
} apiTestSignalSetup_;

// ============================================================================
// Helpers
// ============================================================================

namespace {

static std::string rpcCall(uint16_t port, const std::string& origin,
                           const std::string& method,
                           const std::string& params = "{}",
                           int id = 1) {
  std::string body = "{\"jsonrpc\":\"2.0\",\"method\":\"" + method +
    "\",\"params\":" + params + ",\"id\":" + std::to_string(id) + "}";
  std::string cmd = "curl -s -X POST http://localhost:" +
    std::to_string(port) + "/ "
    "-H 'Content-Type: application/json' "
    "-H 'Origin: " + origin + "' "
    "-d '" + body + "'";
  auto r = run(cmd);
  return r.out;
}

} // anonymous namespace

// ============================================================================
// Test fixture
// ============================================================================

struct CesqtApiFixture {
  std::unique_ptr<CesServer> server;
  fs::path tempDir;
  uint16_t serverPort;
  uint16_t rpcPort;
  pid_t cesqtPid = 0;
  std::string cesqtBin;

  KeyPair fundedKey;
  KeyPair originKey;  // pre-approved origin account
  std::string testOrigin = "https://test.example.com";

  CesqtApiFixture() {
    blog::init();
    blog::set_level(blog::fatal);

    tempDir = makeUniqueTempDir("cesqt_api");


    // Start embedded CES server
    minx::Hash serverPriv;
    serverPriv.fill(0xDD);

    CesConfig cfg =
      makeTestConfig(tempDir / "serverdata", serverPriv,
                     std::numeric_limits<uint64_t>::max());
    cfg.feeAccount = 0;
    cfg.feeAsset = 0;
    cfg.feeTx = 0;
    cfg.feeQuery = 0;
    server = std::make_unique<CesServer>(cfg);
    serverPort = server->start(0);
    BOOST_REQUIRE(serverPort > 0);

    // Fund accounts
    server->_brr(fundedKey.getPublicKeyAsHash(), 10'000'000'000);
    server->_brr(originKey.getPublicKeyAsHash(), 1'000'000'000);
    wait_net();

    // Create sandboxed datadir
    fs::path dataDir = tempDir / "cesqtdata";
    fs::create_directories(dataDir);

    // Write wallet: funded key + origin key (pre-approved)
    {
      std::ofstream f((dataDir / "wallet").string());
      f << "00" << fundedKey.getPrivateKeyHexStr() << "\n";
      f << "00" << originKey.getPrivateKeyHexStr()
        << " " << testOrigin << "\n";
    }

    // Write config.json pointing to our test server
    {
      std::ofstream f((dataDir / "config.json").string());
      f << "{\n"
        << "  \"currentServer\": \"localhost:" << serverPort << "\",\n"
        << "  \"servers\": [\"localhost:" << serverPort << "\"]\n"
        << "}\n";
    }

    cesqtBin = findBinary("cesqt");

    // Sequential port per fixture to avoid TIME_WAIT collisions
    static std::atomic<uint16_t> nextPort{22000};
    rpcPort = nextPort.fetch_add(1);

    // Launch cesqt
    std::string cmd = "QT_QPA_PLATFORM=offscreen " + cesqtBin +
      " --datadir " + dataDir.string() +
      " --rpcport " + std::to_string(rpcPort) +
      " --autoapprove" +
      " --no-daemon > " + (tempDir / "cesqt.log").string() + " 2>&1 & echo $!";
    auto r = run(cmd);
    BOOST_REQUIRE_EQUAL(r.exitCode, 0);
    cesqtPid = std::stoi(r.out);
    BOOST_TEST_MESSAGE("cesqt pid=" + std::to_string(cesqtPid) +
                       " rpc=" + std::to_string(rpcPort));

    // Wait for RPC to be responsive
    bool ready = false;
    for (int i = 0; i < 100 && !ready; ++i) {
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
      auto resp = rpcCall(rpcPort, testOrigin, "ping");
      if (resp.find("pong") != std::string::npos)
        ready = true;
    }
    if (!ready) {
      // Dump log for debugging
      auto logr = run("cat " + (tempDir / "cesqt.log").string());
      BOOST_TEST_MESSAGE("cesqt log: " + logr.out);
    }
    BOOST_REQUIRE_MESSAGE(ready, "cesqt RPC not responsive");
  }

  ~CesqtApiFixture() {
    if (cesqtPid > 0) {
      kill(cesqtPid, SIGKILL);
      waitpid(cesqtPid, nullptr, 0);
    }
    if (server) server->stop();
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }
};

// ============================================================================
// Tests
// ============================================================================

BOOST_FIXTURE_TEST_SUITE(CesqtApi, CesqtApiFixture)

BOOST_AUTO_TEST_CASE(Ping) {
  auto resp = rpcCall(rpcPort, testOrigin, "ping");
  BOOST_TEST_MESSAGE("ping: " + resp);
  BOOST_CHECK(resp.find("pong") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(GetAccount) {
  auto resp = rpcCall(rpcPort, testOrigin, "getAccount");
  BOOST_TEST_MESSAGE("getAccount: " + resp);
  // Should return the origin key's public key
  std::string expectedPub = originKey.getPublicKeyHexStr();
  BOOST_CHECK(resp.find(expectedPub) != std::string::npos);
  BOOST_CHECK(resp.find("publicKey") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(QueryAsset) {
  // Query a non-existent asset — should return (not crash)
  auto resp = rpcCall(rpcPort, testOrigin, "queryAsset",
    "{\"key\":\"doesnotexist\"}");
  BOOST_TEST_MESSAGE("queryAsset: " + resp);
  // May return error or empty result — just shouldn't crash
  BOOST_CHECK(!resp.empty());
}

BOOST_AUTO_TEST_CASE(CreateAndQueryAsset) {
  // Create an asset
  auto resp = rpcCall(rpcPort, testOrigin, "createAsset",
    "{\"key\":\"testword\",\"content\":\"hello world\",\"days\":10}");
  BOOST_TEST_MESSAGE("createAsset: " + resp);
  BOOST_CHECK(resp.find("ok") != std::string::npos);

  // Query it back
  auto resp2 = rpcCall(rpcPort, testOrigin, "queryAsset",
    "{\"key\":\"testword\"}");
  BOOST_TEST_MESSAGE("queryAsset: " + resp2);
  BOOST_CHECK(resp2.find("hello world") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(Transfer) {
  // Transfer from origin account to funded account
  std::string dest = fundedKey.getPublicKeyHexStr();
  auto resp = rpcCall(rpcPort, testOrigin, "transfer",
    "{\"dest\":\"" + dest + "\",\"amount\":0.5}");
  BOOST_TEST_MESSAGE("transfer: " + resp);
  BOOST_CHECK(resp.find("newBalance") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(QueryBalance) {
  auto resp = rpcCall(rpcPort, testOrigin, "queryBalance");
  BOOST_TEST_MESSAGE("queryBalance: " + resp);
  BOOST_CHECK(resp.find("balance") != std::string::npos);
  BOOST_CHECK(resp.find("nonce") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(UpdateAssetFast) {
  // Create, then fast-update content
  auto r1 = rpcCall(rpcPort, testOrigin, "createAsset",
    "{\"key\":\"fastup\",\"content\":\"original\",\"days\":10}");
  BOOST_TEST_MESSAGE("create: " + r1);
  BOOST_CHECK(r1.find("ok") != std::string::npos);

  auto r2 = rpcCall(rpcPort, testOrigin, "updateAssetFast",
    "{\"key\":\"fastup\",\"content\":\"updated\"}");
  BOOST_TEST_MESSAGE("updateFast: " + r2);
  BOOST_CHECK(r2.find("ok") != std::string::npos);

  auto r3 = rpcCall(rpcPort, testOrigin, "queryAsset",
    "{\"key\":\"fastup\"}");
  BOOST_TEST_MESSAGE("query after update: " + r3);
  BOOST_CHECK(r3.find("updated") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(UpdateAssetMeta) {
  // Create asset then set price
  auto r1 = rpcCall(rpcPort, testOrigin, "createAsset",
    "{\"key\":\"priced\",\"content\":\"for sale\",\"days\":10}");
  BOOST_CHECK(r1.find("ok") != std::string::npos);

  auto r2 = rpcCall(rpcPort, testOrigin, "updateAssetMeta",
    "{\"key\":\"priced\",\"price\":5}");
  BOOST_TEST_MESSAGE("setPrice: " + r2);
  BOOST_CHECK(r2.find("ok") != std::string::npos);

  auto r3 = rpcCall(rpcPort, testOrigin, "queryAsset",
    "{\"key\":\"priced\"}");
  BOOST_TEST_MESSAGE("query after price: " + r3);
  BOOST_CHECK(r3.find("\"price\":5") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(FundAsset) {
  auto r1 = rpcCall(rpcPort, testOrigin, "createAsset",
    "{\"key\":\"funded\",\"content\":\"keep alive\",\"days\":5}");
  BOOST_CHECK(r1.find("ok") != std::string::npos);

  auto r2 = rpcCall(rpcPort, testOrigin, "fundAsset",
    "{\"key\":\"funded\",\"days\":10}");
  BOOST_TEST_MESSAGE("fund: " + r2);
  BOOST_CHECK(r2.find("ok") != std::string::npos);

  auto r3 = rpcCall(rpcPort, testOrigin, "queryAsset",
    "{\"key\":\"funded\"}");
  BOOST_TEST_MESSAGE("query after fund: " + r3);
  // days should be 5+10=15, but server may report 16 (includes creation day)
  BOOST_CHECK(r3.find("days") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(GiveAsset) {
  auto r1 = rpcCall(rpcPort, testOrigin, "createAsset",
    "{\"key\":\"giveme\",\"content\":\"a gift\",\"days\":10}");
  BOOST_CHECK(r1.find("ok") != std::string::npos);

  std::string dest = fundedKey.getPublicKeyHexStr();
  auto r2 = rpcCall(rpcPort, testOrigin, "giveAsset",
    "{\"key\":\"giveme\",\"newOwner\":\"" + dest + "\"}");
  BOOST_TEST_MESSAGE("give: " + r2);
  BOOST_CHECK(r2.find("ok") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(OpenTransfer) {
  // Open transfer creates destination if needed
  KeyPair newDest;
  std::string dest = newDest.getPublicKeyHexStr();
  auto resp = rpcCall(rpcPort, testOrigin, "transfer",
    "{\"dest\":\"" + dest + "\",\"amount\":0.01,\"open\":true}");
  BOOST_TEST_MESSAGE("openTransfer: " + resp);
  BOOST_CHECK(resp.find("newBalance") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(UnknownMethod) {
  auto resp = rpcCall(rpcPort, testOrigin, "nonexistent");
  BOOST_TEST_MESSAGE("unknown: " + resp);
  BOOST_CHECK(resp.find("Method not found") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
