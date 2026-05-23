// ===========================================================================
// builtin:compute end-to-end tests (scaffolding pass, no Lua).
// ===========================================================================
//
// Each test stands up a CesServer with /ces/file/1 + /ces/compute/1
// mounted and points cesComputeChildBinary at the build's
// cescompmockd stub. Drives the handler through CesComputeClient
// (verb RPC) and CesFileClient (source-file creation / deposit /
// delete). No shell-out; everything is in-process.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"
#include "test_e2e_common.h"

#include <ces/l2/compute_client.h>
#include <ces/l2/file_client.h>
#include <ces/l2/net_multiplexer.h>
#include <ces/l2/file_handler.h>
#include <ces/server.h>

#include <chrono>
#include <set>
#include <thread>

using namespace ces;

namespace {

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct ComputeE2EFixture {
  std::unique_ptr<CesServer> server;
  fs::path tempDir;
  uint16_t serverPort = 0;
  uint16_t rpcPort = 0;
  std::string childBin;

  KeyPair ownerKey;
  KeyPair otherKey;

  // Canonical source-file path under the owner's /h zone. Pre-computed
  // so every test can reference the same file without recomputing.
  std::string ownerPath;

  ComputeE2EFixture() {
    blog::init();
    blog::set_level(blog::fatal);

    tempDir = makeUniqueTempDir("compute_e2e");

    minx::Hash serverPriv;
    serverPriv.fill(0xEE);

    CesConfig cfg = makeTestConfig(
      tempDir, serverPriv, std::numeric_limits<uint64_t>::max());
    // Avoid ephemeral-port collisions with parallel test binaries.
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = {
      {"/ces/file/1",    "builtin:file"},
      {"/ces/compute/1", "builtin:compute"},
    };
    cfg.cesFileStoreMaxBytes = 128ull * 1024 * 1024;
    cfg.feeFileRent = 1;

    cfg.computeMaxInstances = 8;
    cfg.feeComputeSlotSec = 1;            // tiny; predictable math
    childBin = ces::e2e::findBinary("cescompmockd");
    cfg.cesComputeChildBinary = childBin;
    cfg.cesComputeWorkDir = (tempDir / "cescompute").string();

    server = std::make_unique<CesServer>(cfg);
    serverPort = server->start(0);
    BOOST_REQUIRE_MESSAGE(serverPort > 0, "server port bind failed");
    rpcPort = server->_rpcBoundPort();
    BOOST_REQUIRE_MESSAGE(rpcPort > 0, "rpc port bind failed");

    // Fund both keys so feeQuery debits don't starve mid-test.
    server->_brr(ownerKey.getPublicKeyAsHash(), 10'000'000'000);
    server->_brr(otherKey.getPublicKeyAsHash(), 10'000'000'000);

    ownerPath = "/h/" + ownerKey.getPublicKeyHexStr() + "/prog.bin";

    wait_net();
  }

  ~ComputeE2EFixture() {
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }

  // Helpers.

  // Create a source file owned by `signer` with `deposit` credits in
  // file_balance. Size = 1 so rent is negligible. Returns rc.
  uint8_t createSource(const KeyPair& signer, const std::string& name,
                       uint64_t deposit) {
    CesFileClient fc;
    fc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    uint8_t rc = fc.connect("localhost", rpcPort, signer);
    if (rc != CES_OK) return rc;
    uint64_t outBal = 0, outCost = 0;
    rc = fc.create(name, /*size=*/1, /*pricePerKb=*/0,
                   deposit, /*contentType=*/"application/octet-stream",
                   outBal, outCost);
    fc.disconnect();
    return rc;
  }

  // Delete a source file owned by `signer`. Returns rc.
  uint8_t deleteSource(const KeyPair& signer, const std::string& name) {
    CesFileClient fc;
    fc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    uint8_t rc = fc.connect("localhost", rpcPort, signer);
    if (rc != CES_OK) return rc;
    uint64_t refund = 0;
    rc = fc.deleteFile(name, refund);
    fc.disconnect();
    return rc;
  }
};

} // namespace

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

BOOST_FIXTURE_TEST_SUITE(ComputeTests, ComputeE2EFixture)

BOOST_AUTO_TEST_CASE(LaunchKillRoundTrip) {
  CES_REQUIRE_OK(createSource(ownerKey, ownerPath, 1'000'000));

  CesComputeClient cc;
  cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));

  uint64_t instId = 0, startedAt = 0;
  CES_REQUIRE_OK(cc.launch(ownerPath, instId, startedAt));
  BOOST_CHECK(instId > 0);
  BOOST_CHECK(startedAt > 0);

  std::vector<CesComputeClient::InstanceInfo> list;
  CES_REQUIRE_OK(cc.list(list));
  BOOST_REQUIRE_EQUAL(list.size(), 1u);
  BOOST_CHECK_EQUAL(list[0].instanceId, instId);
  BOOST_CHECK_EQUAL(list[0].sourceName, ownerPath);

  CesComputeClient::InstanceInfo info;
  CES_REQUIRE_OK(cc.stat(instId, info));
  BOOST_CHECK_EQUAL(info.instanceId, instId);
  BOOST_CHECK_EQUAL(info.sourceName, ownerPath);

  CES_REQUIRE_OK(cc.kill(instId));

  list.clear();
  CES_REQUIRE_OK(cc.list(list));
  BOOST_CHECK_EQUAL(list.size(), 0u);

  cc.disconnect();
}

BOOST_AUTO_TEST_CASE(LaunchNotOwner) {
  CES_REQUIRE_OK(createSource(ownerKey, ownerPath, 1'000'000));

  // Connect as otherKey (not the file's owner) and try to launch.
  CesComputeClient cc;
  cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(cc.connect("localhost", rpcPort, otherKey));

  uint64_t instId = 0, startedAt = 0;
  uint8_t rc = cc.launch(ownerPath, instId, startedAt);
  CES_CHECK_RC_EQ(rc, CES_ERROR_NOT_OWNER);

  cc.disconnect();
}

BOOST_AUTO_TEST_CASE(LaunchFundTooLow) {
  // 1 credit covers neither a 15-min upfront nor the rent.
  CES_REQUIRE_OK(createSource(ownerKey, ownerPath, 1));

  CesComputeClient cc;
  cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));

  uint64_t instId = 0, startedAt = 0;
  uint8_t rc = cc.launch(ownerPath, instId, startedAt);
  CES_CHECK_RC_EQ(rc, CES_ERROR_COMPUTE_FUND_TOO_LOW);

  cc.disconnect();
}

BOOST_AUTO_TEST_CASE(LaunchMintsFreshIdEachTime) {
  // Per-source idempotency was dropped: every launch returns a new
  // instance_id. Multiple instances of the same source coexist up to
  // the configured cap.
  CES_REQUIRE_OK(createSource(ownerKey, ownerPath, 10'000'000));

  CesComputeClient cc;
  cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));

  uint64_t a = 0, as = 0, b = 0, bs = 0;
  CES_REQUIRE_OK(cc.launch(ownerPath, a, as));
  CES_REQUIRE_OK(cc.launch(ownerPath, b, bs));
  BOOST_CHECK(a != 0 && b != 0);
  BOOST_CHECK(a != b);

  std::vector<CesComputeClient::InstanceInfo> list;
  CES_REQUIRE_OK(cc.list(list));
  BOOST_REQUIRE_EQUAL(list.size(), 2u);

  CES_REQUIRE_OK(cc.kill(a));
  CES_REQUIRE_OK(cc.kill(b));
  cc.disconnect();
}

BOOST_AUTO_TEST_CASE(KillInstanceNotFound) {
  CesComputeClient cc;
  cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));

  uint8_t rc = cc.kill(/*bogus*/ 99999);
  CES_CHECK_RC_EQ(rc, CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND);

  cc.disconnect();
}

BOOST_AUTO_TEST_CASE(StatUnknownIdNotFound) {
  // STAT is ID-keyed now. There is no path-based "is anyone running this?"
  // query — that would need a new LIST-by-path verb if we ever want it.
  CesComputeClient cc;
  cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));

  CesComputeClient::InstanceInfo info;
  uint8_t rc = cc.stat(/*bogus*/ 99999, info);
  CES_CHECK_RC_EQ(rc, CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND);

  cc.disconnect();
}

BOOST_AUTO_TEST_CASE(ListFiltersByOwner) {
  CES_REQUIRE_OK(createSource(ownerKey, ownerPath, 1'000'000));

  std::string otherPath = "/h/" + otherKey.getPublicKeyHexStr() + "/p.bin";
  CES_REQUIRE_OK(createSource(otherKey, otherPath, 1'000'000));

  // Two clients — the bind contract binds one signer per channel.
  CesComputeClient ccOwner, ccOther;
  ccOwner.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  ccOther.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(ccOwner.connect("localhost", rpcPort, ownerKey));
  CES_REQUIRE_OK(ccOther.connect("localhost", rpcPort, otherKey));

  uint64_t a = 0, as = 0, b = 0, bs = 0;
  CES_REQUIRE_OK(ccOwner.launch(ownerPath, a, as));
  CES_REQUIRE_OK(ccOther.launch(otherPath, b, bs));

  std::vector<CesComputeClient::InstanceInfo> list;
  CES_REQUIRE_OK(ccOwner.list(list));
  BOOST_REQUIRE_EQUAL(list.size(), 1u);
  BOOST_CHECK_EQUAL(list[0].instanceId, a);

  list.clear();
  CES_REQUIRE_OK(ccOther.list(list));
  BOOST_REQUIRE_EQUAL(list.size(), 1u);
  BOOST_CHECK_EQUAL(list[0].instanceId, b);

  CES_REQUIRE_OK(ccOwner.kill(a));
  CES_REQUIRE_OK(ccOther.kill(b));
  ccOwner.disconnect();
  ccOther.disconnect();
}

BOOST_AUTO_TEST_CASE(InstancesIsPublicAndEnumeratesIds) {
  // Owner launches two instances of the same source; a different
  // signer (no ownership) calls instances(path) and gets both ids.
  // Verifies (1) public access — no owner check — and (2) that
  // multi-instance is correctly reported.
  CES_REQUIRE_OK(createSource(ownerKey, ownerPath, 10'000'000));

  CesComputeClient ccOwner;
  ccOwner.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(ccOwner.connect("localhost", rpcPort, ownerKey));

  uint64_t a = 0, as = 0, b = 0, bs = 0;
  CES_REQUIRE_OK(ccOwner.launch(ownerPath, a, as));
  CES_REQUIRE_OK(ccOwner.launch(ownerPath, b, bs));
  BOOST_REQUIRE(a != 0 && b != 0 && a != b);

  // Stranger queries — must succeed without owning the source.
  CesComputeClient ccStranger;
  ccStranger.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(ccStranger.connect("localhost", rpcPort, otherKey));

  std::vector<uint64_t> ids;
  CES_REQUIRE_OK(ccStranger.instances(ownerPath, ids));
  BOOST_REQUIRE_EQUAL(ids.size(), 2u);
  std::set<uint64_t> got(ids.begin(), ids.end());
  BOOST_CHECK_EQUAL(got.count(a), 1u);
  BOOST_CHECK_EQUAL(got.count(b), 1u);

  // Empty path → empty list (no error).
  std::vector<uint64_t> empty;
  CES_REQUIRE_OK(ccStranger.instances(
    "/h/0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef/nope.lua",
    empty));
  BOOST_CHECK_EQUAL(empty.size(), 0u);

  // After kill, count drops.
  CES_REQUIRE_OK(ccOwner.kill(a));
  ids.clear();
  CES_REQUIRE_OK(ccStranger.instances(ownerPath, ids));
  BOOST_REQUIRE_EQUAL(ids.size(), 1u);
  BOOST_CHECK_EQUAL(ids[0], b);

  CES_REQUIRE_OK(ccOwner.kill(b));
  ccOwner.disconnect();
  ccStranger.disconnect();
}

BOOST_AUTO_TEST_CASE(FileDeletionKillsInstance) {
  CES_REQUIRE_OK(createSource(ownerKey, ownerPath, 1'000'000));

  CesComputeClient cc;
  cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));

  uint64_t instId = 0, startedAt = 0;
  CES_REQUIRE_OK(cc.launch(ownerPath, instId, startedAt));

  // Explicitly delete the source file via the file handler.
  CES_REQUIRE_OK(deleteSource(ownerKey, ownerPath));

  // Deletion callback runs on rpcTaskIO_ — give it time to land.
  std::this_thread::sleep_for(std::chrono::milliseconds(250));

  // The file is gone; STAT on the path now returns FILE_NOT_FOUND.
  // LIST on the owner key must show no instances referencing the
  // deleted source.
  std::vector<CesComputeClient::InstanceInfo> list;
  CES_REQUIRE_OK(cc.list(list));
  for (auto& e : list) {
    BOOST_CHECK(e.sourceName != ownerPath);
  }

  cc.disconnect();
}

BOOST_AUTO_TEST_SUITE_END()

// ---------------------------------------------------------------------------
// Standalone: bind-prereq refusal.
// ---------------------------------------------------------------------------
//
// A server configured with compute mount but NOT file mount should
// leave the compute handler unbound. An inbound select for
// "/ces/compute/1" passes CesPlex (binding exists) but the handler's
// serve() sees no bound server and drops — client reads zero bytes.

BOOST_AUTO_TEST_CASE(ComputeBindRequiresFileHandler) {
  fs::path tmp = makeUniqueTempDir("compute_e2e_no_file");

  minx::Hash priv; priv.fill(0xDD);
  CesConfig cfg = makeTestConfig(
    tmp, priv, std::numeric_limits<uint64_t>::max());

  cfg.rpcPort = 0;
  cfg.rpcAutoPort = true;
  cfg.cesplexMounts = {
    // compute mount present, file mount ABSENT
    {"/ces/compute/1", "builtin:compute"},
  };
  cfg.computeMaxInstances = 4;
  cfg.cesComputeChildBinary = ces::e2e::findBinary("cescompmockd");
  cfg.cesComputeWorkDir = (tmp / "cescompute").string();

  auto server = std::make_unique<CesServer>(cfg);
  server->start(0);

  // A compute-select against this server should succeed at the
  // CesPlex layer (binding present) but the handler will drop the
  // channel because its bind failed. A LAUNCH verb from the client
  // will hit read EOF and return INTERNAL.
  CesComputeClient cc;
  cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  KeyPair someKey;
  uint8_t rc = cc.connect("localhost", server->_rpcBoundPort(), someKey);
  // Select itself succeeds (handler is registered even when unbound).
  CES_REQUIRE_OK(rc);

  uint64_t instId = 0, startedAt = 0;
  rc = cc.launch("/p/nope.bin", instId, startedAt);
  BOOST_CHECK_MESSAGE(rc != CES_OK,
                      "LAUNCH must fail without a bound server");

  cc.disconnect();
  server->stop();
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  boost::system::error_code ec;
  fs::remove_all(tmp, ec);
}

