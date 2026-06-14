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
#include <ces/l2/compute_handler.h>
#include <ces/l2/file_client.h>
#include <ces/cesplex/mux.h>
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

// Cap is enforced against registered + in-flight launches: launching up
// to computeMaxInstances (8 in this fixture) succeeds, the next is
// rejected, and freeing one (KILL) makes room again. Guards C3 — the
// pending-launch reservation must release exactly on registration so the
// boundary launch isn't double-counted and rejected one early.
BOOST_AUTO_TEST_CASE(LaunchRespectsInstanceCap) {
  CES_REQUIRE_OK(createSource(ownerKey, ownerPath, 1'000'000'000));

  CesComputeClient cc;
  cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));

  // Fill the cap (computeMaxInstances = 8).
  std::vector<uint64_t> ids;
  for (int i = 0; i < 8; ++i) {
    uint64_t id = 0, started = 0;
    CES_REQUIRE_OK(cc.launch(ownerPath, id, started));
    BOOST_CHECK(id > 0);
    ids.push_back(id);
  }

  // One past the cap is rejected.
  uint64_t overId = 0, overStarted = 0;
  uint8_t rc = cc.launch(ownerPath, overId, overStarted);
  BOOST_CHECK_MESSAGE(rc == CES_ERROR_COMPUTE_MAX_INSTANCES,
                      "expected MAX_INSTANCES, got " << int(rc));

  // Free a slot, then a launch fits again.
  CES_REQUIRE_OK(cc.kill(ids[0]));
  uint64_t againId = 0, againStarted = 0;
  CES_REQUIRE_OK(cc.launch(ownerPath, againId, againStarted));
  BOOST_CHECK(againId > 0);

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

// ---------------------------------------------------------------------------
// Standalone: a child that never connects back must not wedge the strand.
// ---------------------------------------------------------------------------
//
// Regression for the synchronous poll()-accept that used to block
// rpcTaskIO_ for up to kAcceptTimeoutMs on every LAUNCH. The accept is
// now async + deadline-bounded: a child that fails to connect back (here
// a nonexistent child binary, so the forked child's execvp fails and it
// exits immediately) makes LAUNCH return an error at the deadline, leaks
// no instance, and leaves the channel responsive to further verbs.

BOOST_AUTO_TEST_CASE(ComputeLaunchAcceptTimeoutIsClean) {
  fs::path tmp = makeUniqueTempDir("compute_e2e_accept_timeout");

  minx::Hash priv; priv.fill(0xCC);
  CesConfig cfg = makeTestConfig(
    tmp, priv, std::numeric_limits<uint64_t>::max());

  cfg.rpcPort = 0;
  cfg.rpcAutoPort = true;
  cfg.cesplexMounts = {
    {"/ces/file/1",    "builtin:file"},
    {"/ces/compute/1", "builtin:compute"},
  };
  cfg.cesFileStoreMaxBytes = 128ull * 1024 * 1024;
  cfg.feeFileRent = 1;
  cfg.computeMaxInstances = 8;
  cfg.feeComputeSlotSec = 1;
  // Nonexistent child binary: fork() succeeds, the child's execvp fails
  // and it exits without ever connecting back, so the accept must hit
  // its deadline rather than a connection.
  cfg.cesComputeChildBinary = (tmp / "no_such_child_binary").string();
  cfg.cesComputeWorkDir = (tmp / "cescompute").string();

  auto server = std::make_unique<CesServer>(cfg);
  server->start(0);
  uint16_t rpcPort = server->_rpcBoundPort();
  BOOST_REQUIRE(rpcPort > 0);

  KeyPair ownerKey;
  server->_brr(ownerKey.getPublicKeyAsHash(), 10'000'000'000);
  std::string ownerPath = "/h/" + ownerKey.getPublicKeyHexStr() + "/prog.bin";

  wait_net();

  // Source file, funded so the upfront commitment fee clears.
  {
    CesFileClient fc;
    fc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(fc.connect("localhost", rpcPort, ownerKey));
    uint64_t outBal = 0, outCost = 0;
    CES_REQUIRE_OK(fc.create(ownerPath, /*size=*/1, /*pricePerKb=*/0,
                             /*deposit=*/1'000'000,
                             "application/octet-stream", outBal, outCost));
    fc.disconnect();
  }

  CesComputeClient cc;
  cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));

  uint64_t instId = 0, startedAt = 0;
  uint8_t rc = cc.launch(ownerPath, instId, startedAt);
  BOOST_CHECK_MESSAGE(rc != CES_OK,
                      "LAUNCH must fail when the child never connects back");

  // Strand not wedged: a follow-up verb on the same channel still
  // answers, and no ghost instance was registered for the source.
  std::vector<CesComputeClient::InstanceInfo> insts;
  CES_REQUIRE_OK(cc.list(insts));
  BOOST_CHECK_EQUAL(insts.size(), 0u);

  std::vector<uint64_t> ids;
  CES_REQUIRE_OK(cc.instances(ownerPath, ids));
  BOOST_CHECK_EQUAL(ids.size(), 0u);

  cc.disconnect();
  server->stop();
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  boost::system::error_code ec;
  fs::remove_all(tmp, ec);
}

// ---------------------------------------------------------------------------
// Standalone: each LAUNCH is independently charged (not NONCELESS-deduped).
// ---------------------------------------------------------------------------
//
// Regression for C4. Two LAUNCHes of the same source on one channel carry
// an identical signature (preamble = [CES_NONCELESS][name]). The old code
// dedup-skipped the second's query fee while still spawning it; LAUNCH now
// opts out of the dedup, so the signer's account is debited feeQuery on
// BOTH launches. Discount is pinned off so feeQuery is exact.
BOOST_AUTO_TEST_CASE(LaunchIsNotDeduped) {
  fs::path tmp = makeUniqueTempDir("compute_e2e_launch_charge");

  minx::Hash priv; priv.fill(0xBB);
  CesConfig cfg = makeTestConfig(
    tmp, priv, std::numeric_limits<uint64_t>::max());

  cfg.rpcPort = 0;
  cfg.rpcAutoPort = true;
  cfg.cesplexMounts = {
    {"/ces/file/1",    "builtin:file"},
    {"/ces/compute/1", "builtin:compute"},
  };
  cfg.cesFileStoreMaxBytes = 128ull * 1024 * 1024;
  cfg.feeFileRent = 1;
  cfg.computeMaxInstances = 8;
  cfg.feeComputeSlotSec = 1;
  // Full fees: pin the load discount off so feeQuery is charged exactly.
  cfg.feeDiscountEnabled = false;
  cfg.feeQuery = 1'000'000;
  cfg.cesComputeChildBinary = ces::e2e::findBinary("cescompmockd");
  cfg.cesComputeWorkDir = (tmp / "cescompute").string();

  auto server = std::make_unique<CesServer>(cfg);
  server->start(0);
  uint16_t rpcPort = server->_rpcBoundPort();
  BOOST_REQUIRE(rpcPort > 0);

  KeyPair ownerKey;
  server->_brr(ownerKey.getPublicKeyAsHash(), 10'000'000'000);
  std::string ownerPath = "/h/" + ownerKey.getPublicKeyHexStr() + "/prog.bin";

  wait_net();

  // Source, funded so the per-launch upfront (from file_balance, not the
  // account) never limits us — the account only pays feeQuery per launch.
  {
    CesFileClient fc;
    fc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(fc.connect("localhost", rpcPort, ownerKey));
    uint64_t outBal = 0, outCost = 0;
    CES_REQUIRE_OK(fc.create(ownerPath, /*size=*/1, /*pricePerKb=*/0,
                             /*deposit=*/1'000'000'000,
                             "application/octet-stream", outBal, outCost));
    fc.disconnect();
  }

  CesComputeClient cc;
  cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));

  const minx::Hash ownerPk = ownerKey.getPublicKeyAsHash();
  int64_t bal0 = server->_l2ProgramAccountBalanceSync(ownerPk);

  // Two LAUNCHes of the SAME path on the SAME channel → identical sig.
  uint64_t a = 0, as = 0, b = 0, bs = 0;
  CES_REQUIRE_OK(cc.launch(ownerPath, a, as));
  CES_REQUIRE_OK(cc.launch(ownerPath, b, bs));
  BOOST_CHECK(a != 0 && b != 0 && a != b);   // two distinct instances

  int64_t bal1 = server->_l2ProgramAccountBalanceSync(ownerPk);
  // Both launches charged feeQuery: the dedup did NOT skip the second.
  BOOST_CHECK_EQUAL(bal0 - bal1, int64_t(2) * int64_t(cfg.feeQuery));

  cc.disconnect();
  server->stop();
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  boost::system::error_code ec;
  fs::remove_all(tmp, ec);
}

// ---------------------------------------------------------------------------
// Static compute port range — allocation, free-on-kill reuse, exhaustion.
// ---------------------------------------------------------------------------
//
// These exercise the server-side allocator only (mock children don't bind
// the port). The instance's assigned port is read via the
// _computeTestInstanceClientPort hook.

BOOST_AUTO_TEST_SUITE(ComputePortTests)

namespace {
// A compute server with a configured static port range and one shared
// source file. Instances launch from it, each claiming a server-assigned
// port from [base, base + count - 1]. `count` is independent of the
// instance cap `maxInst`.
struct PortServer {
  fs::path dir;
  std::unique_ptr<CesServer> server;
  uint16_t rpcPort = 0;
  KeyPair ownerKey;
  std::string src;

  PortServer(uint16_t base, uint16_t count, uint32_t maxInst) {
    blog::init();
    blog::set_level(blog::fatal);
    dir = makeUniqueTempDir("compute_port");
    minx::Hash priv; priv.fill(0xC7);
    CesConfig cfg = makeTestConfig(dir, priv,
                                   std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = {
      {"/ces/file/1",    "builtin:file"},
      {"/ces/compute/1", "builtin:compute"},
    };
    cfg.cesFileStoreMaxBytes = 16ull * 1024 * 1024;
    cfg.feeFileRent = 1;
    cfg.computeMaxInstances = maxInst;
    cfg.computePortBase = base;
    cfg.computePortCount = count;
    cfg.feeComputeSlotSec = 1;
    cfg.cesComputeChildBinary = ces::e2e::findBinary("cescompmockd");
    cfg.cesComputeWorkDir = (dir / "cescompute").string();
    server = std::make_unique<CesServer>(cfg);
    server->start(0);
    rpcPort = server->_rpcBoundPort();
    server->_brr(ownerKey.getPublicKeyAsHash(), 10'000'000'000);
    src = "/h/" + ownerKey.getPublicKeyHexStr() + "/p.bin";
    wait_net();
    CesFileClient fc;
    fc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(fc.connect("localhost", rpcPort, ownerKey));
    uint64_t b = 0, c = 0;
    CES_REQUIRE_OK(fc.create(src, 1, 0, 1'000'000'000,
                             "application/octet-stream", b, c));
    fc.disconnect();
  }
  ~PortServer() {
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    boost::system::error_code ec;
    fs::remove_all(dir, ec);
  }
};
} // namespace

// Two-port allocation: each launch leases TWO ports from the range — the
// child's outbound CES-client port, then its inbound /ces/luarpc/1 host
// port — lowest-free first. KILL returns both to the pool; the next launch
// reuses the freed pair.
BOOST_AUTO_TEST_CASE(TwoPortsAllocatedAndReused) {
  PortServer ps(/*base=*/41000, /*count=*/6, /*maxInst=*/8);
  CesComputeClient cc;
  cc.setServerPubkey(ps.server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(cc.connect("localhost", ps.rpcPort, ps.ownerKey));

  uint64_t a = 0, b = 0, d = 0, s = 0;
  CES_REQUIRE_OK(cc.launch(ps.src, a, s));
  CES_REQUIRE_OK(cc.launch(ps.src, b, s));
  // Both of a's ports allocated, distinct, lowest-first; b takes the next pair.
  BOOST_CHECK_EQUAL(int(_computeTestInstanceClientPort(a)), 41000);
  BOOST_CHECK_EQUAL(int(_computeTestInstanceRpcPort(a)),    41001);
  BOOST_CHECK_EQUAL(int(_computeTestInstanceClientPort(b)), 41002);
  BOOST_CHECK_EQUAL(int(_computeTestInstanceRpcPort(b)),    41003);

  // Kill a → frees 41000+41001; the next launch reuses the lowest free pair.
  CES_REQUIRE_OK(cc.kill(a));
  CES_REQUIRE_OK(cc.launch(ps.src, d, s));
  BOOST_CHECK_EQUAL(int(_computeTestInstanceClientPort(d)), 41000);
  BOOST_CHECK_EQUAL(int(_computeTestInstanceRpcPort(d)),    41001);

  cc.disconnect();
}

// One port available ⇒ the CES port gets it, the rpc port misses (0). Both
// leases are best-effort and independent, so a partial allocation still
// launches.
BOOST_AUTO_TEST_CASE(OnePortAllocated) {
  PortServer ps(/*base=*/41000, /*count=*/1, /*maxInst=*/4);
  CesComputeClient cc;
  cc.setServerPubkey(ps.server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(cc.connect("localhost", ps.rpcPort, ps.ownerKey));

  uint64_t a = 0, s = 0;
  CES_REQUIRE_OK(cc.launch(ps.src, a, s));
  BOOST_CHECK_EQUAL(int(_computeTestInstanceClientPort(a)), 41000);
  BOOST_CHECK_EQUAL(int(_computeTestInstanceRpcPort(a)),    0);

  cc.disconnect();
}

// No configured range ⇒ both ports 0. The instance still launches (it stays
// reachable via the server's own rpc port); the child reads 0 as "no
// network" / "hosts nothing".
BOOST_AUTO_TEST_CASE(ZeroPortsAllocated) {
  PortServer ps(/*base=*/0, /*count=*/0, /*maxInst=*/4);
  CesComputeClient cc;
  cc.setServerPubkey(ps.server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(cc.connect("localhost", ps.rpcPort, ps.ownerKey));

  uint64_t a = 0, s = 0;
  CES_REQUIRE_OK(cc.launch(ps.src, a, s));   // launch still succeeds
  BOOST_CHECK_EQUAL(int(_computeTestInstanceClientPort(a)), 0);
  BOOST_CHECK_EQUAL(int(_computeTestInstanceRpcPort(a)),    0);

  cc.disconnect();
}

// Draining the pool across instances is never a launch failure: as the
// range empties, instances get 2 ports, then 1, then 0 — all launch.
BOOST_AUTO_TEST_CASE(PortsDrainAcrossInstancesAllLaunch) {
  // 3 ports, 8 slots ⇒ instance 1 takes 2, instance 2 takes 1, instance 3
  // takes 0.
  PortServer ps(/*base=*/41000, /*count=*/3, /*maxInst=*/8);
  CesComputeClient cc;
  cc.setServerPubkey(ps.server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(cc.connect("localhost", ps.rpcPort, ps.ownerKey));

  uint64_t a = 0, b = 0, cId = 0, s = 0;
  CES_REQUIRE_OK(cc.launch(ps.src, a, s));    // 41000 + 41001
  CES_REQUIRE_OK(cc.launch(ps.src, b, s));    // 41002 + 0
  CES_REQUIRE_OK(cc.launch(ps.src, cId, s));  // 0 + 0
  BOOST_CHECK_EQUAL(int(_computeTestInstanceClientPort(a)),   41000);
  BOOST_CHECK_EQUAL(int(_computeTestInstanceRpcPort(a)),      41001);
  BOOST_CHECK_EQUAL(int(_computeTestInstanceClientPort(b)),   41002);
  BOOST_CHECK_EQUAL(int(_computeTestInstanceRpcPort(b)),      0);
  BOOST_CHECK_EQUAL(int(_computeTestInstanceClientPort(cId)), 0);
  BOOST_CHECK_EQUAL(int(_computeTestInstanceRpcPort(cId)),    0);

  cc.disconnect();
}

BOOST_AUTO_TEST_SUITE_END()

