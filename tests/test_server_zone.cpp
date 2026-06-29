// ===========================================================================
// /s/ (server zone) tests — unmetered, outside-the-cap, server-only CREATE.
// ===========================================================================
//
// /s/ paths live in the file store on disk but:
//   - CREATE/WRITE/APPEND/RESIZE/DELETE/DEPOSIT/WITHDRAW/SET_PRICE require
//     the signer to be the server's own pubkey (the server key in
//     server.toml);
//   - bytes don't count toward cesFileStoreMaxBytes;
//   - rent doesn't accrue (chargeRentOrDelete is a no-op on /s/);
//   - per-byte feeFileWrite / feeFileRead are waived;
//   - price_per_kb in the sidecar is ignored on READ (readers pay only
//     feeQuery + no per-byte + no per-kb).
//
// Drives CesFileClient directly against an in-process server.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"

#include <ces/l2/file_client.h>
#include <ces/cesplex/mux.h>
#include <ces/server.h>

#include <chrono>
#include <cstring>
#include <fstream>
#include <thread>

using namespace ces;

namespace {

// Fixture — identical to FileE2EFixture in test_cesh_file_e2e.cpp but
// trimmed to what in-process CesFileClient tests need, and with the
// server private key deterministically chosen so tests can sign as
// the server.
struct ServerZoneFixture {
  std::unique_ptr<CesServer> server;
  fs::path tempDir;
  uint16_t serverPort = 0;
  uint16_t rpcPort = 0;

  // Server key pair reconstructed from the fixed private hash we use
  // to start the server. Lets tests sign as the server for /s/ ops.
  minx::Hash serverPriv;
  KeyPair serverKey;

  // A distinct key for "non-server" callers (writes on /s/ must be
  // rejected for this key).
  KeyPair otherKey;

  ServerZoneFixture()
      : serverPriv([](){ minx::Hash h; h.fill(0xEE); return h; }()),
        serverKey(serverPriv) {
    blog::init();
    blog::set_level(blog::fatal);

    tempDir = makeUniqueTempDir("server_zone");

    CesConfig cfg = makeTestConfig(
      tempDir, serverPriv, std::numeric_limits<uint64_t>::max());

    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = { {"/ces/file/1", "builtin:file"} };
    // Tiny cap so we can prove /s/ bypasses it.
    cfg.cesFileStoreMaxBytes = 1024;
    cfg.feeFileRent = 1;

    server = std::make_unique<CesServer>(cfg);
    serverPort = server->start(0);
    BOOST_REQUIRE_MESSAGE(serverPort > 0, "server port bind failed");
    rpcPort = server->_rpcBoundPort();
    BOOST_REQUIRE_MESSAGE(rpcPort > 0, "rpc port bind failed");

    // Fund both keys so feeQuery debits don't starve mid-test.
    server->_brr(serverKey.getPublicKeyAsHash(), 10'000'000'000);
    server->_brr(otherKey.getPublicKeyAsHash(),  10'000'000'000);

    server->_drainLogic();
  }

  ~ServerZoneFixture() {
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }

  std::unique_ptr<CesFileClient> connectClient(const KeyPair& signer) {
    auto fc = std::make_unique<CesFileClient>();
    fc->setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    uint8_t rc = fc->connect("localhost", rpcPort, signer);
    BOOST_REQUIRE_EQUAL(static_cast<int>(rc), static_cast<int>(CES_OK));
    return fc;
  }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(ServerZoneTests, ServerZoneFixture)

BOOST_AUTO_TEST_CASE(NonServerKeyCannotCreateInS) {
  auto fc = connectClient(otherKey);
  uint64_t bal = 0, cost = 0;
  uint8_t rc = fc->create("/s/oops.bin",
                          /*size=*/1024, /*price=*/0,
                          /*deposit=*/0,
                          bal, cost);
  CES_CHECK_RC_EQ(rc, CES_ERROR_NOT_OWNER);
}

BOOST_AUTO_TEST_CASE(ServerKeyCanCreateInSWithZeroDeposit) {
  auto fc = connectClient(serverKey);
  uint64_t bal = 0, cost = 0;
  uint8_t rc = fc->create("/s/hello.bin",
                          /*size=*/64, /*price=*/0,
                          /*deposit=*/0,
                          bal, cost);
  CES_REQUIRE_OK(rc);
  // deposit forced to 0 by the server for /s/.
  BOOST_CHECK_EQUAL(bal, 0u);
}

BOOST_AUTO_TEST_CASE(ServerZoneBypassesCap) {
  // Cap is 1024 (see fixture). A 2 KB file in /s/ must succeed;
  // the same file in /p/ must fail STORE_FULL. Two clients because
  // each channel is bound to one signer (the bind contract).
  auto fcServer = connectClient(serverKey);
  auto fcOther  = connectClient(otherKey);
  uint64_t bal = 0, cost = 0;

  uint8_t rc = fcServer->create("/s/big.bin",
                                /*size=*/2048, /*price=*/0, /*deposit=*/0,
                                bal, cost);
  CES_REQUIRE_OK(rc);

  uint8_t rc2 = fcOther->create("/p/should_fail.bin",
                                /*size=*/2048, /*price=*/0, /*deposit=*/0,
                                bal, cost);
  CES_CHECK_RC_EQ(rc2, CES_ERROR_STORE_FULL);
}

BOOST_AUTO_TEST_CASE(ServerZoneWriteReadRoundTrip) {
  // A /s/ file fully populated via CREATE + WRITE (server-bound channel)
  // + READ from a non-server reader on a separate channel. Verifies:
  // write is unmetered, read is free of per-byte and per-kb charges
  // (reader pays only feeQuery).
  auto fcServer = connectClient(serverKey);
  uint64_t bal = 0, cost = 0;
  uint8_t rc = fcServer->create("/s/data.bin",
                                /*size=*/8, /*price=*/999,   // ignored on /s/
                                /*deposit=*/0,
                                bal, cost);
  CES_REQUIRE_OK(rc);

  ces::Bytes content{'s','s','s','s','s','s','s','s'};
  rc = fcServer->write("/s/data.bin", /*offset=*/0, content, bal);
  CES_REQUIRE_OK(rc);
  // Balance should still be 0 — /s/ WRITE is unmetered.
  BOOST_CHECK_EQUAL(bal, 0u);

  // Non-server reader: distinct bound channel.
  auto fcReader = connectClient(otherKey);
  ces::Bytes readBack;
  minx::Hash rangeHash;
  rc = fcReader->read("/s/data.bin", /*offset=*/0, 8,
                      readBack, rangeHash);
  CES_REQUIRE_OK(rc);
  BOOST_REQUIRE_EQUAL(readBack.size(), content.size());
  BOOST_CHECK(std::memcmp(readBack.data(), content.data(), 8) == 0);
}

BOOST_AUTO_TEST_CASE(ServerZoneNameValidationRejectsJustSlashS) {
  // "/s/" with no second component must fail BAD_NAME like every
  // other zone.
  auto fc = connectClient(serverKey);
  uint64_t bal = 0, cost = 0;
  uint8_t rc = fc->create("/s/",
                          /*size=*/1, /*price=*/0, /*deposit=*/0,
                          bal, cost);
  CES_CHECK_RC_EQ(rc, CES_ERROR_BAD_NAME);
}

// /s/ is the one zone safe to enumerate (operator-only write), so the server
// keeps an auto-generated /s/index.html catalog in sync on every /s/ change.
BOOST_AUTO_TEST_CASE(ServerZoneAutoIndex) {
  auto fc = connectClient(serverKey);
  uint64_t bal = 0, cost = 0;

  // Each /s/ CREATE regenerates the catalog (synchronously, before the
  // response returns).
  CES_REQUIRE_OK(fc->create("/s/alpha.txt", 16, 0, 0, bal, cost));
  CES_REQUIRE_OK(fc->create("/s/beta.lua",  16, 0, 0, bal, cost));

  auto readWhole = [&](const std::string& name, std::string& out) -> uint8_t {
    CesFileClient::StatInfo si;
    uint8_t src = fc->stat(name, si);
    if (src != CES_OK) return src;
    ces::Bytes data; minx::Hash h;
    uint8_t rrc = fc->read(name, 0, si.size, data, h);
    if (rrc != CES_OK) return rrc;
    out.assign(data.begin(), data.end());
    return CES_OK;
  };

  std::string idx;
  CES_REQUIRE_OK(readWhole("/s/index.html", idx));
  BOOST_CHECK(idx.find("/s/alpha.txt") != std::string::npos);
  BOOST_CHECK(idx.find("/s/beta.lua")  != std::string::npos);
  BOOST_CHECK(idx.find("server catalog") != std::string::npos);
  // The catalog never lists itself.
  BOOST_CHECK_MESSAGE(idx.find("/s/index.html") == std::string::npos,
                      "index must not list itself");

  // Delete one — the catalog updates on the next read.
  uint64_t refund = 0;
  CES_REQUIRE_OK(fc->deleteFile("/s/alpha.txt", refund));
  std::string idx2;
  CES_REQUIRE_OK(readWhole("/s/index.html", idx2));
  BOOST_CHECK_MESSAGE(idx2.find("/s/alpha.txt") == std::string::npos,
                      "deleted file must drop out of the catalog");
  BOOST_CHECK(idx2.find("/s/beta.lua") != std::string::npos);
}

// The bundled /s/welcome demo site ships inside the binary and is published into
// the file store at boot whenever the file feature is on (forced, no switch).
// It's readable by any signer and appears in the /s/ catalog.
BOOST_AUTO_TEST_CASE(BundledWelcomeSiteIsSeeded) {
  auto fc = connectClient(otherKey);   // any signer can READ /s/

  auto readWhole = [&](const std::string& name, std::string& out) -> uint8_t {
    CesFileClient::StatInfo si;
    uint8_t src = fc->stat(name, si);
    if (src != CES_OK) return src;
    ces::Bytes data; minx::Hash h;
    uint8_t rrc = fc->read(name, 0, si.size, data, h);
    if (rrc != CES_OK) return rrc;
    out.assign(data.begin(), data.end());
    return CES_OK;
  };

  std::string html, css, svg;
  CES_REQUIRE_OK(readWhole("/s/welcome/index.html", html));
  BOOST_CHECK(html.find("Hello from CES") != std::string::npos);
  BOOST_CHECK(html.find("style.css") != std::string::npos);   // relative asset link
  CES_REQUIRE_OK(readWhole("/s/welcome/style.css", css));
  BOOST_CHECK(css.find("body") != std::string::npos);
  CES_REQUIRE_OK(readWhole("/s/welcome/logo.svg", svg));
  BOOST_CHECK(svg.find("<svg") != std::string::npos);

  // The boot-regenerated catalog lists the seeded site.
  std::string cat;
  CES_REQUIRE_OK(readWhole("/s/index.html", cat));
  BOOST_CHECK(cat.find("/s/welcome/index.html") != std::string::npos);
}

// An operator can drop a program straight onto disk under <storeDir>/s/ with no
// signed CREATE and no sidecar; the first fetch from the /s/ zone mints the
// sidecar on the fly (server-owned, fresh program account) — the same per-file
// reconcile the boot scan runs — so "cp into /s/ and use it" works without a
// restart.
BOOST_AUTO_TEST_CASE(ServerZoneLazyMintsSidecarForDroppedFile) {
  const std::string& storeDir = server->_config().cesFileStoreDir;
  fs::path sDir = fs::path(storeDir) / "s";
  fs::create_directories(sDir);
  fs::path content = sDir / "dropped.lua";
  fs::path sidecar(content.string() + ".sidecar.toml");

  const std::string body = "return 42\n";
  {
    std::ofstream f(content, std::ios::binary);
    f << body;
  }
  BOOST_REQUIRE(fs::exists(content));
  BOOST_REQUIRE(!fs::exists(sidecar));   // no signed CREATE happened

  // First fetch (STAT by any signer) materializes the sidecar on the spot.
  auto fc = connectClient(otherKey);
  CesFileClient::StatInfo si;
  CES_REQUIRE_OK(fc->stat("/s/dropped.lua", si));
  BOOST_CHECK_EQUAL(si.size, body.size());

  // The minted sidecar is server-owned, and now exists on disk.
  const auto& srvPk = server->_serverKeyPair().getPublicKeyAsHash();
  BOOST_CHECK(std::memcmp(si.ownerPubkey.data(), srvPk.data(), 32) == 0);
  BOOST_CHECK(fs::exists(sidecar));

  // And the dropped bytes read back unchanged.
  ces::Bytes data; minx::Hash h;
  CES_REQUIRE_OK(fc->read("/s/dropped.lua", 0, si.size, data, h));
  std::string got(data.begin(), data.end());
  BOOST_CHECK_EQUAL(got, body);
}

BOOST_AUTO_TEST_SUITE_END()
