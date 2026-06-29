#include "test_common.h"
#include <ces/cesvm.h>
#include <ces/util/vmprogram.h>
#include <functional>

BOOST_AUTO_TEST_SUITE(PersistenceTests)

BOOST_AUTO_TEST_CASE(Test_FastUpdate_Volatile_Crash) {
  LOGINFO << "TEST: Starting FastUpdate_Volatile_Crash";

  fs::path pDir = makeUniqueTempDir("ces_fast_vol");
  minx::Hash sPriv;
  sPriv.fill(0xEE);

  minx::Hash aid = makeHash("VOLATILE_ASSET");
  AssetData originalContent;
  originalContent.fill(0xAA);
  AssetData fastContent;
  fastContent.fill(0xBB);
  KeyPair user;

  // --- PHASE 1: Create, Update RAM, Crash ---
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv(cfg);
    uint16_t port = srv.start(0);

    CesClient cli(testServerEp(port), false);
    cli.start(0);
    cli.setKey(user);
    cli.connect();

    // 1. Create (Persisted via WAL)
    srv._brr(user.getPublicKeyAsHash(), 10'000'000'000);
    srv._drainLogic();
    cli.createAsset(aid, originalContent, 10);
    srv._drainLogic();

    // 2. Fast Update (Memory Only)
    cli.updateAssetFast(aid, fastContent);
    srv._drainLogic();

    // Sanity Check: Verify it is updated in memory
    HashPrefix o;
    AssetData c;
    uint16_t d;
    uint32_t p;
    cli.queryAsset(aid, o, c, d, p);
    BOOST_REQUIRE(c == fastContent);

    cli.stop();
    // 3. Destructor runs -> stops threads -> SKIPS SNAPSHOT
  }

  // --- PHASE 2: Restart & Verify Revert ---
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv2(cfg);
    uint16_t port2 = srv2.start(0);

    CesClient cli2(testServerEp(port2), false);
    cli2.start(0);
    cli2.connect();

    HashPrefix owner;
    AssetData content;
    uint16_t days;
    uint32_t price;

    cli2.queryAsset(aid, owner, content, days, price);

    BOOST_CHECK_MESSAGE(
      content == originalContent,
      "Fast update persisted after crash! It should be volatile.");
    BOOST_CHECK(content != fastContent);

    cli2.stop();
    srv2.stop();
  }
  fs::remove_all(pDir);
}

BOOST_AUTO_TEST_CASE(Test_FastUpdate_Persist_On_Snapshot) {
  LOGINFO << "TEST: Starting FastUpdate_Persist_On_Snapshot";

  fs::path pDir = makeUniqueTempDir("ces_fast_snap");
  minx::Hash sPriv;
  sPriv.fill(0xEE);

  minx::Hash aid = makeHash("SNAPSHOT_ASSET");
  AssetData fastContent;
  fastContent.fill(0xCC);
  KeyPair user;

  // --- PHASE 1: Update & Clean Stop ---
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv(cfg);
    uint16_t port = srv.start(0);

    CesClient cli(testServerEp(port), false);
    cli.start(0);
    cli.setKey(user);
    cli.connect();

    srv._brr(user.getPublicKeyAsHash(), 10'000'000'000);
    srv._drainLogic();

    AssetData initial;
    initial.fill(0x00);
    cli.createAsset(aid, initial, 10);
    srv._drainLogic();

    // Fast Update
    cli.updateAssetFast(aid, fastContent);
    srv._drainLogic();

    cli.stop();
    srv.stop(false);
    srv._save(); // Explicit snapshot to persist fast-update content
  }

  // --- PHASE 2: Restart & Verify Persistence ---
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv2(cfg);
    uint16_t port2 = srv2.start(0);

    CesClient cli2(testServerEp(port2), false);
    cli2.start(0);
    cli2.connect();

    HashPrefix owner;
    AssetData content;
    uint16_t days;
    uint32_t price;

    cli2.queryAsset(aid, owner, content, days, price);

    BOOST_CHECK_MESSAGE(content == fastContent,
                        "Fast update lost despite clean snapshot!");

    cli2.stop();
    srv2.stop();
  }
  fs::remove_all(pDir);
}

BOOST_AUTO_TEST_CASE(Test_MetaUpdate_PartialPersistence) {
  LOGINFO << "TEST: Starting MetaUpdate_PartialPersistence";

  fs::path pDir = makeUniqueTempDir("ces_meta_persist");
  minx::Hash sPriv;
  sPriv.fill(0xEE);

  minx::Hash aid = makeHash("HEAVY_ASSET");
  AssetData heavyContent;
  heavyContent.fill(0xFF);
  KeyPair user;

  // --- PHASE 1: Create & Meta Update ---
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv(cfg);
    uint16_t port = srv.start(0);

    CesClient cli(testServerEp(port), false);
    cli.start(0);
    cli.setKey(user);
    cli.connect();

    srv._brr(user.getPublicKeyAsHash(), 10'000'000'000);
    srv._drainLogic();

    // 1. Create
    cli.createAsset(aid, heavyContent, 10);
    srv._drainLogic();

    // 2. Meta Update (Set Price = 999)
    cli.updateAssetMeta(aid, Account::getMapKey(user.getPublicKeyAsHash()), 999);
    srv._drainLogic();

    cli.stop();
    srv.stop(); // Clean stop
  }

  // --- PHASE 2: Restart & Verify ---
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv2(cfg);
    uint16_t port2 = srv2.start(0);

    CesClient cli2(testServerEp(port2), false);
    cli2.start(0);
    cli2.connect();

    HashPrefix owner;
    AssetData content;
    uint16_t days;
    uint32_t price;

    cli2.queryAsset(aid, owner, content, days, price);

    // 1. Check Meta
    BOOST_CHECK_EQUAL(price, 999);

    // 2. Check Content Integrity
    BOOST_CHECK_MESSAGE(content == heavyContent,
                        "Heavy content corrupted after meta update!");

    cli2.stop();
    srv2.stop();
  }
  fs::remove_all(pDir);
}

BOOST_AUTO_TEST_CASE(Test_Mixed_Mode_Partial_Isolation) {
  LOGINFO << "TEST: Starting Mixed_Mode_Partial_Isolation";

  fs::path pDir = makeUniqueTempDir("ces_mixed");
  minx::Hash sPriv;
  sPriv.fill(0xEE);

  minx::Hash aid = makeHash("MIXED_TEST");
  AssetData contentA;
  contentA.fill(0xAA);
  AssetData contentB;
  contentB.fill(0xBB);
  KeyPair user;

  // --- PHASE 1: Create, Fast Update, Meta Update, Crash ---
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv(cfg);
    uint16_t port = srv.start(0);

    CesClient cli(testServerEp(port), false);
    cli.start(0);
    cli.setKey(user);
    cli.connect();

    srv._brr(user.getPublicKeyAsHash(), 10'000'000'000);
    srv._drainLogic();

    // 1. Create (Content A) -> Writes to WAL
    cli.createAsset(aid, contentA, 10);
    srv._drainLogic();

    // 2. Fast Update (Content B) -> RAM Only
    cli.updateAssetFast(aid, contentB);
    srv._drainLogic();

    // Check RAM is B
    HashPrefix o;
    AssetData c;
    uint16_t d;
    uint32_t p;
    cli.queryAsset(aid, o, c, d, p);
    BOOST_REQUIRE(c == contentB);

    // 3. Meta Update (Price 999) -> Writes Partial Event to WAL
    cli.updateAssetMeta(aid, Account::getMapKey(user.getPublicKeyAsHash()), 999);
    srv._drainLogic();

    cli.stop();
    // 4. Crash (Skip Snapshot)
  }

  // --- PHASE 2: Restart & Verify Isolation ---
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv2(cfg);
    uint16_t port2 = srv2.start(0);

    CesClient cli2(testServerEp(port2), false);
    cli2.start(0);
    cli2.connect();

    HashPrefix owner;
    AssetData content;
    uint16_t days;
    uint32_t price;

    cli2.queryAsset(aid, owner, content, days, price);

    // CHECK 1: Meta update survived (WAL replay worked)
    BOOST_CHECK_EQUAL(price, 999);

    // CHECK 2: Fast update was DISCARDED
    BOOST_CHECK_MESSAGE(content == contentA,
                        "Partial update leaked RAM content to disk! Serializer "
                        "is not strictly partial.");
    BOOST_CHECK(content != contentB);

    cli2.stop();
    srv2.stop();
  }
  fs::remove_all(pDir);
}

// Transfer receipt survives crash (WAL replay, no snapshot)
BOOST_AUTO_TEST_CASE(Receipt_SurvivesWALReplay) {
  fs::path pDir = makeUniqueTempDir("ces_rcpt_wal");
  minx::Hash sPriv;
  sPriv.fill(0xEE);
  KeyPair user;
  HashPrefix userId = Account::getMapKey(user.getPublicKeyAsHash());

  KeyPair bob;
  while (Account::getMapKey(bob.getPublicKeyAsHash()) == userId)
    bob = KeyPair();
  HashPrefix bobId = Account::getMapKey(bob.getPublicKeyAsHash());

  // Phase 1: create, transfer, CRASH (no snapshot)
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv(cfg);
    uint16_t port = srv.start(0);

    CesClient cli(testServerEp(port), false);
    cli.start(0);
    cli.setKey(user);
    cli.connect();

    srv._brr(user.getPublicKeyAsHash(), 10'000'000'000);
    srv._drainLogic();

    int64_t newBal;
    uint8_t rc = cli.openTransfer(bob.getPublicKeyAsHash(), 4242, newBal);
    CES_REQUIRE_OK(rc);
    srv._drainLogic();

    cli.stop();
    // NO srv.stop() — simulate crash, no snapshot written
  }

  // Phase 2: restart from WAL replay
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv2(cfg);
    srv2.start(0);

    HashPrefix dest;
    uint64_t amount;
    uint32_t time;
    int64_t _bal = 0; uint32_t _nonce = 0;
    srv2.unsignedQueryAccount(userId, _bal, _nonce, dest, amount, time);
    BOOST_CHECK(dest == bobId);
    BOOST_CHECK_EQUAL(amount, 4242u);
    BOOST_CHECK(time > 0);

    srv2.stop();
  }

  boost::system::error_code ec;
  fs::remove_all(pDir, ec);
}

// BalanceNonce WAL update after transfer must NOT clobber xfer fields
BOOST_AUTO_TEST_CASE(Receipt_BalanceNonceDoesNotClobberOnReplay) {
  fs::path pDir = makeUniqueTempDir("ces_rcpt_noclob");
  minx::Hash sPriv;
  sPriv.fill(0xEE);
  KeyPair user;
  HashPrefix userId = Account::getMapKey(user.getPublicKeyAsHash());

  KeyPair bob;
  while (Account::getMapKey(bob.getPublicKeyAsHash()) == userId)
    bob = KeyPair();
  HashPrefix bobId = Account::getMapKey(bob.getPublicKeyAsHash());

  // Phase 1: transfer, then credit (BalanceNonce), then CRASH
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv(cfg);
    uint16_t port = srv.start(0);

    CesClient cli(testServerEp(port), false);
    cli.start(0);
    cli.setKey(user);
    cli.connect();

    srv._brr(user.getPublicKeyAsHash(), 10'000'000'000);
    srv._drainLogic();

    int64_t newBal;
    uint8_t rc = cli.openTransfer(bob.getPublicKeyAsHash(), 3333, newBal);
    CES_REQUIRE_OK(rc);
    srv._drainLogic();

    // This credit writes a BalanceNonce (0x01) WAL entry AFTER the
    // Transfer (0x03) entry. On replay, the 0x01 entry must not
    // zero out the xfer fields that were set by the 0x03 entry.
    srv._brr(user.getPublicKeyAsHash(), 500);
    srv._drainLogic();

    cli.stop();
    // NO srv.stop() — crash
  }

  // Phase 2: WAL replay — xfer fields must survive the 0x01 entry
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv2(cfg);
    srv2.start(0);

    HashPrefix dest;
    uint64_t amount;
    uint32_t time;
    int64_t _bal = 0; uint32_t _nonce = 0;
    srv2.unsignedQueryAccount(userId, _bal, _nonce, dest, amount, time);
    BOOST_CHECK(dest == bobId);
    BOOST_CHECK_EQUAL(amount, 3333u);
    BOOST_CHECK(time > 0);

    srv2.stop();
  }

  boost::system::error_code ec;
  fs::remove_all(pDir, ec);
}

// Receipt survives clean snapshot and restore
BOOST_AUTO_TEST_CASE(Receipt_PersistsThroughRestart) {
  fs::path pDir = makeUniqueTempDir("ces_rcpt");
  minx::Hash sPriv;
  sPriv.fill(0xEE);
  KeyPair user;
  HashPrefix userId = Account::getMapKey(user.getPublicKeyAsHash());

  KeyPair bob;
  while (Account::getMapKey(bob.getPublicKeyAsHash()) == userId)
    bob = KeyPair();
  HashPrefix bobId = Account::getMapKey(bob.getPublicKeyAsHash());

  // Phase 1: create account, transfer, stop server (writes snapshot)
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv(cfg);
    uint16_t port = srv.start(0);

    CesClient cli(testServerEp(port), false);
    cli.start(0);
    cli.setKey(user);
    cli.connect();

    srv._brr(user.getPublicKeyAsHash(), 10'000'000'000);
    srv._drainLogic();

    int64_t newBal;
    uint8_t rc = cli.openTransfer(bob.getPublicKeyAsHash(), 7777, newBal);
    CES_REQUIRE_OK(rc);
    srv._drainLogic();

    // Verify before shutdown
    HashPrefix dest;
    uint64_t amount;
    uint32_t time;
    int64_t _bal = 0; uint32_t _nonce = 0;
    srv.unsignedQueryAccount(userId, _bal, _nonce, dest, amount, time);
    BOOST_CHECK(dest == bobId);
    BOOST_CHECK_EQUAL(amount, 7777u);

    cli.stop();
    srv.stop();
  }

  // Phase 2: restart and verify fields survived
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv2(cfg);
    srv2.start(0);

    HashPrefix dest;
    uint64_t amount;
    uint32_t time;
    int64_t _bal = 0; uint32_t _nonce = 0;
    srv2.unsignedQueryAccount(userId, _bal, _nonce, dest, amount, time);
    BOOST_CHECK(dest == bobId);
    BOOST_CHECK_EQUAL(amount, 7777u);
    BOOST_CHECK(time > 0);

    srv2.stop();
  }

  boost::system::error_code ec;
  fs::remove_all(pDir, ec);
}

// Balance-only WAL entry (fundAsset) survives crash
BOOST_AUTO_TEST_CASE(Asset_BalanceUpdate_SurvivesCrash) {
  fs::path pDir = makeUniqueTempDir("ces_ast_bal");
  minx::Hash sPriv;
  sPriv.fill(0xEE);

  minx::Hash aid = makeHash("BAL_ASSET");
  AssetData content;
  content.fill(0x42);
  KeyPair user;

  // Phase 1: create, fund, crash
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv(cfg);
    uint16_t port = srv.start(0);

    CesClient cli(testServerEp(port), false);
    cli.start(0);
    cli.setKey(user);
    cli.connect();

    srv._brr(user.getPublicKeyAsHash(), 10'000'000'000);
    srv._drainLogic();

    cli.createAsset(aid, content, 5);
    srv._drainLogic();

    cli.fundAsset(aid, 20);
    srv._drainLogic();

    // Verify in RAM: balance should be 1+5+20 = 26
    HashPrefix o;
    AssetData c;
    uint16_t days;
    uint32_t p;
    cli.queryAsset(aid, o, c, days, p);
    BOOST_REQUIRE_EQUAL(days, 26);

    cli.stop();
    // NO srv.stop() — crash
  }

  // Phase 2: WAL replay
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv2(cfg);
    uint16_t port2 = srv2.start(0);

    CesClient cli2(testServerEp(port2), false);
    cli2.start(0);
    cli2.connect();

    HashPrefix owner;
    AssetData c2;
    uint16_t days;
    uint32_t price;
    cli2.queryAsset(aid, owner, c2, days, price);

    BOOST_CHECK_EQUAL(days, 26);
    BOOST_CHECK(c2 == content);

    cli2.stop();
    srv2.stop();
  }

  boost::system::error_code ec;
  fs::remove_all(pDir, ec);
}

// Balance WAL entry must not clobber owner/price/content on replay
BOOST_AUTO_TEST_CASE(Asset_BalanceDoesNotClobberOnReplay) {
  fs::path pDir = makeUniqueTempDir("ces_ast_noclob");
  minx::Hash sPriv;
  sPriv.fill(0xEE);

  minx::Hash aid = makeHash("NOCLOB_ASSET");
  AssetData content;
  content.fill(0x77);
  KeyPair user;

  // Phase 1: create with price, then fund (balance-only WAL), crash
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv(cfg);
    uint16_t port = srv.start(0);

    CesClient cli(testServerEp(port), false);
    cli.start(0);
    cli.setKey(user);
    cli.connect();

    srv._brr(user.getPublicKeyAsHash(), 10'000'000'000);
    srv._drainLogic();

    cli.createAsset(aid, content, 10);
    srv._drainLogic();

    // Set a price via meta update
    cli.updateAssetMeta(aid, Account::getMapKey(user.getPublicKeyAsHash()), 555);
    srv._drainLogic();

    // Fund (writes Balance-only WAL entry after the Meta entry)
    cli.fundAsset(aid, 5);
    srv._drainLogic();

    cli.stop();
    // NO srv.stop() — crash
  }

  // Phase 2: WAL replay — balance entry must not zero out price/content
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv2(cfg);
    uint16_t port2 = srv2.start(0);

    CesClient cli2(testServerEp(port2), false);
    cli2.start(0);
    cli2.connect();

    HashPrefix owner;
    AssetData c2;
    uint16_t days;
    uint32_t price;
    cli2.queryAsset(aid, owner, c2, days, price);

    BOOST_CHECK_EQUAL(price, 555);
    BOOST_CHECK_EQUAL(days, 16); // 1+10+5
    BOOST_CHECK(c2 == content);
    BOOST_CHECK(owner == Account::getMapKey(user.getPublicKeyAsHash()));

    cli2.stop();
    srv2.stop();
  }

  boost::system::error_code ec;
  fs::remove_all(pDir, ec);
}

// transferOwnership (buy/give) Meta WAL entry survives crash
BOOST_AUTO_TEST_CASE(Asset_TransferOwnership_SurvivesCrash) {
  fs::path pDir = makeUniqueTempDir("ces_ast_xfer");
  minx::Hash sPriv;
  sPriv.fill(0xEE);

  minx::Hash aid = makeHash("GIVE_ASSET");
  AssetData content;
  content.fill(0x55);
  KeyPair creator;
  KeyPair receiver;

  HashPrefix creatorId = Account::getMapKey(creator.getPublicKeyAsHash());
  HashPrefix receiverId = Account::getMapKey(receiver.getPublicKeyAsHash());
  // Ensure distinct prefixes
  while (receiverId == creatorId) {
    receiver = KeyPair();
    receiverId = Account::getMapKey(receiver.getPublicKeyAsHash());
  }

  // Phase 1: create, give, crash
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv(cfg);
    uint16_t port = srv.start(0);

    CesClient cli(testServerEp(port), false);
    cli.start(0);
    cli.setKey(creator);
    cli.connect();

    srv._brr(creator.getPublicKeyAsHash(), 10'000'000'000);
    srv._drainLogic();

    cli.createAsset(aid, content, 10);
    srv._drainLogic();

    // Set a price first
    cli.updateAssetMeta(aid, creatorId, 1000);
    srv._drainLogic();

    // Give away (transferOwnership sets owner=receiver, price=0)
    cli.giveAsset(aid, receiverId);
    srv._drainLogic();

    cli.stop();
    // NO srv.stop() — crash
  }

  // Phase 2: WAL replay
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv2(cfg);
    uint16_t port2 = srv2.start(0);

    CesClient cli2(testServerEp(port2), false);
    cli2.start(0);
    cli2.connect();

    HashPrefix owner;
    AssetData c2;
    uint16_t days;
    uint32_t price;
    cli2.queryAsset(aid, owner, c2, days, price);

    BOOST_CHECK(owner == receiverId);
    BOOST_CHECK_EQUAL(price, 0); // give resets price
    BOOST_CHECK(c2 == content);

    cli2.stop();
    srv2.stop();
  }

  boost::system::error_code ec;
  fs::remove_all(pDir, ec);
}

// Full update (updateAsset) persists all fields through crash
BOOST_AUTO_TEST_CASE(Asset_FullUpdate_SurvivesCrash) {
  fs::path pDir = makeUniqueTempDir("ces_ast_full");
  minx::Hash sPriv;
  sPriv.fill(0xEE);

  minx::Hash aid = makeHash("FULL_UPD_ASSET");
  AssetData contentA;
  contentA.fill(0x11);
  AssetData contentB;
  contentB.fill(0x22);
  KeyPair user;
  HashPrefix userId = Account::getMapKey(user.getPublicKeyAsHash());

  // Phase 1: create with contentA, full update to contentB + price, crash
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv(cfg);
    uint16_t port = srv.start(0);

    CesClient cli(testServerEp(port), false);
    cli.start(0);
    cli.setKey(user);
    cli.connect();

    srv._brr(user.getPublicKeyAsHash(), 10'000'000'000);
    srv._drainLogic();

    cli.createAsset(aid, contentA, 10);
    srv._drainLogic();

    // Full update: new content + price
    cli.updateAsset(aid, userId, contentB, 777);
    srv._drainLogic();

    cli.stop();
    // NO srv.stop() — crash
  }

  // Phase 2: WAL replay
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv2(cfg);
    uint16_t port2 = srv2.start(0);

    CesClient cli2(testServerEp(port2), false);
    cli2.start(0);
    cli2.connect();

    HashPrefix owner;
    AssetData c2;
    uint16_t days;
    uint32_t price;
    cli2.queryAsset(aid, owner, c2, days, price);

    BOOST_CHECK(c2 == contentB);
    BOOST_CHECK_EQUAL(price, 777);
    BOOST_CHECK(owner == userId);

    cli2.stop();
    srv2.stop();
  }

  boost::system::error_code ec;
  fs::remove_all(pDir, ec);
}

// ===========================================================================
// VM ledger effects must survive crash-recovery (WAL replay, no snapshot).
//
// A CES_RUN_ASSET commits its ledger writes straight into the in-memory store
// via the undo log (getObjects()), which emits NO WAL event — only the gas
// debit/refund journal. So on an unclean restart (WAL replay without a
// snapshot) the VM's writes are lost, while the gas refund's absolute-balance
// persist leaks the caller's in-VM debit into the WAL. One leg of a transfer
// survives, the other vanishes → conservation breaks. These tests pin the
// boundary: the committed VM state must reproduce exactly after WAL replay.
// ===========================================================================

// Append a 32-byte hash (4 cells) to a VM input buffer.
static void viAppend(ces::Bytes& b, const minx::Hash& h) {
  b.insert(b.end(), h.begin(), h.end());
}
// Append an 8-byte HashPrefix (1 cell) to a VM input buffer.
static void viAppend(ces::Bytes& b, const HashPrefix& p) {
  b.insert(b.end(), p.begin(), p.end());
}

// Shared harness for the commit/revert durability matrix. Deploys a program
// under a freshly-funded caller, runs it once, then simulates a crash (no
// snapshot) and reloads from the WAL. Conservation (_getTotalCredits) is
// asserted to reproduce exactly across every cycle — so every probe doubles
// as a regression for the gas-refund/VM-mutation flush — and the probe's
// `verify` hook checks per-cell expectations on the reloaded server.
//   build  : returns the program bytecode (may reference the caller key).
//   input  : returns the run input (dest keys, asset keys, content, …).
//   prep   : phase-1 setup after connect + 10B prefund (extra accounts/assets);
//            gets the bound port so it can spin up clients for other identities.
//   verify : phase-2 assertions on the reloaded (WAL-replayed) server.
// expectVmError defaults to CESVM_OK (commit path); set CESVM_ABORT for the
// revert-path probes.
struct VmCommitProbe {
  std::function<AssetData(const KeyPair&)> build;
  std::function<ces::Bytes(const KeyPair&)> input;
  std::function<void(CesServer&, CesClient&, uint16_t, const KeyPair&)> prep;
  std::function<void(CesServer&, const KeyPair&)> verify;
  uint64_t expectVmError = CESVM_OK;
};

static void runVmCommitProbe(const std::string& tag, const VmCommitProbe& p) {
  fs::path pDir = makeUniqueTempDir(tag);
  minx::Hash sPriv;
  sPriv.fill(0xEE);
  KeyPair user;
  minx::Hash progId = makeHash("VMCRC_PROG");

  int64_t totalAfterRun = 0;

  // Phase 1: deploy + run, then CRASH (no snapshot).
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv(cfg);
    uint16_t port = srv.start(0);

    CesClient cli(testServerEp(port), false);
    cli.start(0);
    cli.setKey(user);
    cli.connect();

    srv._brr(user.getPublicKeyAsHash(), 10'000'000'000);
    srv._drainLogic();

    if (p.prep) {
      p.prep(srv, cli, port, user);
      cli.setKey(user); // prep may have switched the signing key
    }

    uint8_t rc = cli.createAsset(progId, p.build(user), 30);
    CES_REQUIRE_OK(rc);
    srv._drainLogic();

    ces::Bytes in = p.input ? p.input(user) : ces::Bytes{};
    uint64_t vmError = 0, budgetUsed = 0;
    ces::Bytes output;
    rc = cli.runAsset(progId, 1'000'000'000, in, vmError, budgetUsed, output);
    BOOST_REQUIRE_EQUAL(vmError, p.expectVmError);
    srv._drainLogic();

    totalAfterRun = srv._getTotalCredits();

    cli.stop();
    // NO srv.stop() — crash.
  }

  // Phase 2: WAL replay. Conservation reproduces, plus per-cell checks.
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv2(cfg);
    srv2.start(0);

    BOOST_CHECK_EQUAL(srv2._getTotalCredits(), totalAfterRun);
    if (p.verify) p.verify(srv2, user);

    srv2.stop();
  }

  boost::system::error_code ec;
  fs::remove_all(pDir, ec);
}

// SYS_TRANSFER (caller -> dest) inside a VM run must survive WAL replay, and
// the conservation invariant must hold across the crash.
BOOST_AUTO_TEST_CASE(VmTransfer_SurvivesWALReplay) {
  fs::path pDir = makeUniqueTempDir("ces_vm_xfer_wal");
  minx::Hash sPriv;
  sPriv.fill(0xEE);

  KeyPair user;
  HashPrefix userId = Account::getMapKey(user.getPublicKeyAsHash());
  KeyPair dest;
  HashPrefix destId = Account::getMapKey(dest.getPublicKeyAsHash());
  while (destId == userId) {
    dest = KeyPair();
    destId = Account::getMapKey(dest.getPublicKeyAsHash());
  }

  minx::Hash progId = makeHash("VM_XFER_PROG");
  const uint64_t kAmount   = 50'000;
  const int64_t  kDestSeed = 1'000;

  int64_t userBalAfterRun = 0, destBalAfterRun = 0, totalAfterRun = 0;

  // Phase 1: deploy a transfer program, run it, CRASH (no snapshot).
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv(cfg);
    uint16_t port = srv.start(0);

    CesClient cli(testServerEp(port), false);
    cli.start(0);
    cli.setKey(user);
    cli.connect();

    srv._brr(user.getPublicKeyAsHash(), 10'000'000'000);
    srv._brr(dest.getPublicKeyAsHash(), kDestSeed);
    srv._drainLogic();

    // Program: SYS_TRANSFER caller -> (dest key from input), kAmount.
    VmProgram pgm;
    Region destKeyReg = pgm.allocHash();
    pgm.copyFromInput(destKeyReg, 0);
    pgm.sysTransfer({destKeyReg, Imm(kAmount)});
    pgm.term();

    uint8_t rc = cli.createAsset(progId, pgm.buildBootBlock(), 30);
    CES_REQUIRE_OK(rc);
    srv._drainLogic();

    ces::Bytes input(dest.getPublicKeyAsHash().begin(),
                     dest.getPublicKeyAsHash().end());
    uint64_t vmError = 0, budgetUsed = 0;
    ces::Bytes output;
    rc = cli.runAsset(progId, 1'000'000'000, input, vmError, budgetUsed, output);
    CES_REQUIRE_OK(rc);
    BOOST_REQUIRE_EQUAL(vmError, static_cast<uint64_t>(CESVM_OK));
    srv._drainLogic();

    // Capture the committed, in-RAM truth before the crash.
    HashPrefix xd; uint64_t xa; uint32_t xt, xn;
    srv.unsignedQueryAccount(userId, userBalAfterRun, xn, xd, xa, xt);
    srv.unsignedQueryAccount(destId, destBalAfterRun, xn, xd, xa, xt);
    totalAfterRun = srv._getTotalCredits();

    // Sanity: the transfer really landed in RAM.
    BOOST_REQUIRE_EQUAL(destBalAfterRun, kDestSeed + static_cast<int64_t>(kAmount));

    cli.stop();
    // NO srv.stop() — crash, no snapshot written.
  }

  // Phase 2: WAL replay. The committed VM state must reproduce exactly.
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv2(cfg);
    srv2.start(0);

    HashPrefix xd; uint64_t xa; uint32_t xt, xn;
    int64_t userBal = 0, destBal = 0;
    srv2.unsignedQueryAccount(userId, userBal, xn, xd, xa, xt);
    srv2.unsignedQueryAccount(destId, destBal, xn, xd, xa, xt);

    // The dest credit must survive the crash (today it's lost).
    BOOST_CHECK_EQUAL(destBal, destBalAfterRun);
    // The caller balance must too (today it's correct — the refund leaked it).
    BOOST_CHECK_EQUAL(userBal, userBalAfterRun);
    // Conservation must hold across recovery (today short by kAmount).
    BOOST_CHECK_EQUAL(srv2._getTotalCredits(), totalAfterRun);

    srv2.stop();
  }

  boost::system::error_code ec;
  fs::remove_all(pDir, ec);
}

// SYS_CREATE_ASSET inside a VM run must survive WAL replay — the created cell
// is emplaced in-memory only, so today it vanishes on an unclean restart.
BOOST_AUTO_TEST_CASE(VmCreateAsset_SurvivesWALReplay) {
  fs::path pDir = makeUniqueTempDir("ces_vm_mkasset_wal");
  minx::Hash sPriv;
  sPriv.fill(0xEE);

  KeyPair user;
  minx::Hash progId = makeHash("VM_MKASSET_PROG");
  minx::Hash bornId = makeHash("VM_BORN_ASSET");

  // Phase 1: deploy a create-asset program, run it, CRASH.
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv(cfg);
    uint16_t port = srv.start(0);

    CesClient cli(testServerEp(port), false);
    cli.start(0);
    cli.setKey(user);
    cli.connect();

    srv._brr(user.getPublicKeyAsHash(), 10'000'000'000);
    srv._drainLogic();

    // Program: SYS_CREATE_ASSET at (key from input) with 10 days.
    VmProgram pgm;
    Region keyReg = pgm.allocHash();
    pgm.copyFromInput(keyReg, 0);
    Region content = pgm.allocContent();
    pgm.sysCreateAsset({keyReg, content, Imm(10)});
    pgm.term();

    uint8_t rc = cli.createAsset(progId, pgm.buildBootBlock(), 30);
    CES_REQUIRE_OK(rc);
    srv._drainLogic();

    ces::Bytes input(bornId.begin(), bornId.end());
    uint64_t vmError = 0, budgetUsed = 0;
    ces::Bytes output;
    rc = cli.runAsset(progId, 1'000'000'000, input, vmError, budgetUsed, output);
    CES_REQUIRE_OK(rc);
    BOOST_REQUIRE_EQUAL(vmError, static_cast<uint64_t>(CESVM_OK));
    srv._drainLogic();

    // Sanity: the VM-born asset exists in RAM (1 + 10 days).
    HashPrefix o; AssetData c; uint16_t d = 0; uint32_t p;
    rc = cli.queryAsset(bornId, o, c, d, p);
    CES_REQUIRE_OK(rc);
    BOOST_REQUIRE_EQUAL(d & 0x1FFF, 11);

    cli.stop();
    // NO srv.stop() — crash.
  }

  // Phase 2: WAL replay — the VM-born asset must still be there.
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv2(cfg);
    uint16_t port2 = srv2.start(0);

    CesClient cli2(testServerEp(port2), false);
    cli2.start(0);
    cli2.connect();

    HashPrefix o; AssetData c; uint16_t d = 0; uint32_t p;
    uint8_t rc = cli2.queryAsset(bornId, o, c, d, p);
    BOOST_CHECK_EQUAL(rc, static_cast<uint8_t>(CES_OK));  // today: ASSET_NOT_FOUND
    BOOST_CHECK_EQUAL(d & 0x1FFF, 11);

    cli2.stop();
    srv2.stop();
  }

  boost::system::error_code ec;
  fs::remove_all(pDir, ec);
}

// SYS_FUND_ASSET — the day-counter extension must survive the crash.
BOOST_AUTO_TEST_CASE(VmFundAsset_SurvivesWALReplay) {
  minx::Hash target = makeHash("VM_FUND_TARGET");
  VmCommitProbe p;
  p.prep = [target](CesServer&, CesClient& cli, uint16_t, const KeyPair&) {
    AssetData content; content.fill(0x10);
    CES_REQUIRE_OK(cli.createAsset(target, content, 5)); // 1 + 5 = 6 days
  };
  p.build = [](const KeyPair&) {
    VmProgram pgm;
    Region keyReg = pgm.allocHash();
    pgm.copyFromInput(keyReg, 0);
    pgm.sysFundAsset({keyReg, Imm(20)}); // 6 + 20 = 26 days
    pgm.term();
    return pgm.buildBootBlock();
  };
  p.input = [target](const KeyPair&) {
    ces::Bytes in;
    viAppend(in, target);
    return in;
  };
  p.verify = [target](CesServer& srv, const KeyPair&) {
    HashPrefix o; AssetData c; uint16_t days = 0; uint32_t pr;
    srv.unsignedQueryAsset(target, o, c, days, pr);
    BOOST_CHECK_EQUAL(days, 26);
  };
  runVmCommitProbe("ces_vm_fund_wal", p);
}

// SYS_UPDATE_ASSET — the content overwrite must survive the crash.
BOOST_AUTO_TEST_CASE(VmUpdateAsset_SurvivesWALReplay) {
  minx::Hash target = makeHash("VM_UPD_TARGET");
  AssetData contentB; contentB.fill(0xB7);
  VmCommitProbe p;
  p.prep = [target](CesServer&, CesClient& cli, uint16_t, const KeyPair&) {
    AssetData a; a.fill(0xA1);
    CES_REQUIRE_OK(cli.createAsset(target, a, 10));
  };
  p.build = [](const KeyPair&) {
    VmProgram pgm;
    Region keyReg = pgm.allocHash();
    pgm.copyFromInput(keyReg, 0);
    Region contentReg = pgm.allocContent();
    pgm.copyFromInput(contentReg, 4); // content begins at input cell 4
    pgm.sysUpdateAsset({keyReg, contentReg});
    pgm.term();
    return pgm.buildBootBlock();
  };
  p.input = [target, contentB](const KeyPair&) {
    ces::Bytes in;
    viAppend(in, target);
    in.insert(in.end(), contentB.begin(), contentB.end());
    return in;
  };
  p.verify = [target, contentB](CesServer& srv, const KeyPair&) {
    HashPrefix o; AssetData c; uint16_t days = 0; uint32_t pr;
    srv.unsignedQueryAsset(target, o, c, days, pr);
    BOOST_CHECK(c == contentB);
  };
  runVmCommitProbe("ces_vm_upd_wal", p);
}

// SYS_UPDATE_ASSET_META — the price (list-for-sale) must survive the crash.
BOOST_AUTO_TEST_CASE(VmUpdateAssetMeta_SurvivesWALReplay) {
  minx::Hash target = makeHash("VM_META_TARGET");
  VmCommitProbe p;
  p.prep = [target](CesServer&, CesClient& cli, uint16_t, const KeyPair&) {
    AssetData a; a.fill(0x3C);
    CES_REQUIRE_OK(cli.createAsset(target, a, 10));
  };
  p.build = [](const KeyPair&) {
    VmProgram pgm;
    Region keyReg = pgm.allocHash();
    pgm.copyFromInput(keyReg, 0);
    Region ownerReg = pgm.allocHashPrefix();
    pgm.copyFromInput(ownerReg, 4); // keep owner = caller (prefix at cell 4)
    pgm.sysUpdateAssetMeta({keyReg, ownerReg, Imm(4242)});
    pgm.term();
    return pgm.buildBootBlock();
  };
  p.input = [target](const KeyPair& user) {
    ces::Bytes in;
    viAppend(in, target);
    viAppend(in, Account::getMapKey(user.getPublicKeyAsHash()));
    return in;
  };
  p.verify = [target](CesServer& srv, const KeyPair& user) {
    HashPrefix o; AssetData c; uint16_t days = 0; uint32_t pr;
    srv.unsignedQueryAsset(target, o, c, days, pr);
    BOOST_CHECK_EQUAL(pr, 4242u);
    BOOST_CHECK(o == Account::getMapKey(user.getPublicKeyAsHash()));
  };
  runVmCommitProbe("ces_vm_meta_wal", p);
}

// SYS_GIVE_ASSET — the ownership hand-off (and price reset) must survive.
BOOST_AUTO_TEST_CASE(VmGiveAsset_SurvivesWALReplay) {
  minx::Hash target = makeHash("VM_GIVE_TARGET");
  KeyPair newOwner;
  HashPrefix newOwnerId = Account::getMapKey(newOwner.getPublicKeyAsHash());
  VmCommitProbe p;
  p.prep = [target](CesServer&, CesClient& cli, uint16_t, const KeyPair&) {
    AssetData a; a.fill(0x5A);
    CES_REQUIRE_OK(cli.createAsset(target, a, 10));
  };
  p.build = [](const KeyPair&) {
    VmProgram pgm;
    Region keyReg = pgm.allocHash();
    pgm.copyFromInput(keyReg, 0);
    Region ownerReg = pgm.allocHashPrefix();
    pgm.copyFromInput(ownerReg, 4);
    pgm.sysGiveAsset({keyReg, ownerReg});
    pgm.term();
    return pgm.buildBootBlock();
  };
  p.input = [target, newOwnerId](const KeyPair&) {
    ces::Bytes in;
    viAppend(in, target);
    viAppend(in, newOwnerId);
    return in;
  };
  p.verify = [target, newOwnerId](CesServer& srv, const KeyPair&) {
    HashPrefix o; AssetData c; uint16_t days = 0; uint32_t pr;
    srv.unsignedQueryAsset(target, o, c, days, pr);
    BOOST_CHECK(o == newOwnerId);
    BOOST_CHECK_EQUAL(pr, 0u);
  };
  runVmCommitProbe("ces_vm_give_wal", p);
}

// SYS_BUY_ASSET — a credit-moving asset op: caller pays the seller and takes
// ownership. The seller's credit surviving the crash is enforced by the
// harness conservation check (a lost credit would drop the total); here we
// also assert the ownership/price change persisted.
BOOST_AUTO_TEST_CASE(VmBuyAsset_SurvivesWALReplay) {
  minx::Hash target = makeHash("VM_BUY_TARGET");
  KeyPair seller;
  HashPrefix sellerId = Account::getMapKey(seller.getPublicKeyAsHash());
  VmCommitProbe p;
  p.prep = [target, seller, sellerId](CesServer& srv, CesClient&, uint16_t port,
                                       const KeyPair&) {
    srv._brr(seller.getPublicKeyAsHash(), 10'000'000'000);
    srv._drainLogic();
    CesClient sc(testServerEp(port), false);
    sc.start(0);
    sc.setKey(seller);
    sc.connect();
    AssetData a; a.fill(0x77);
    CES_REQUIRE_OK(sc.createAsset(target, a, 10));
    srv._drainLogic();
    CES_REQUIRE_OK(sc.updateAssetMeta(target, sellerId, 1)); // price 1 -> 1*PRICE_UNIT
    srv._drainLogic();
    sc.stop();
  };
  p.build = [](const KeyPair&) {
    VmProgram pgm;
    Region keyReg = pgm.allocHash();
    pgm.copyFromInput(keyReg, 0);
    pgm.sysBuyAsset({keyReg, Imm(1'000'000'000)}); // maxPrice cap well above 1e8
    pgm.term();
    return pgm.buildBootBlock();
  };
  p.input = [target](const KeyPair&) {
    ces::Bytes in;
    viAppend(in, target);
    return in;
  };
  p.verify = [target](CesServer& srv, const KeyPair& user) {
    HashPrefix o; AssetData c; uint16_t days = 0; uint32_t pr;
    srv.unsignedQueryAsset(target, o, c, days, pr);
    BOOST_CHECK(o == Account::getMapKey(user.getPublicKeyAsHash()));
    BOOST_CHECK_EQUAL(pr, 0u);
  };
  runVmCommitProbe("ces_vm_buy_wal", p);
}

// Multiple mutations in one run must commit atomically: two transfers plus an
// asset creation, all of which must reproduce together after WAL replay.
BOOST_AUTO_TEST_CASE(VmMultiMutation_SurvivesWALReplay) {
  KeyPair dest1, dest2;
  HashPrefix dest1Id = Account::getMapKey(dest1.getPublicKeyAsHash());
  HashPrefix dest2Id = Account::getMapKey(dest2.getPublicKeyAsHash());
  minx::Hash born = makeHash("VM_MULTI_BORN");
  const uint64_t kA = 11'111, kB = 22'222;
  VmCommitProbe p;
  p.build = [kA, kB](const KeyPair&) {
    VmProgram pgm;
    Region d1 = pgm.allocHash(); pgm.copyFromInput(d1, 0);
    Region d2 = pgm.allocHash(); pgm.copyFromInput(d2, 4);
    Region bk = pgm.allocHash(); pgm.copyFromInput(bk, 8);
    Region content = pgm.allocContent();
    pgm.sysTransfer({d1, Imm(kA)});
    pgm.sysTransfer({d2, Imm(kB)});
    pgm.sysCreateAsset({bk, content, Imm(7)}); // 1 + 7 = 8 days
    pgm.term();
    return pgm.buildBootBlock();
  };
  p.input = [dest1, dest2, born](const KeyPair&) {
    ces::Bytes in;
    viAppend(in, dest1.getPublicKeyAsHash());
    viAppend(in, dest2.getPublicKeyAsHash());
    viAppend(in, born);
    return in;
  };
  p.verify = [dest1Id, dest2Id, born, kA, kB](CesServer& srv, const KeyPair&) {
    HashPrefix xd; uint64_t xa; uint32_t xt, xn;
    int64_t b1 = 0, b2 = 0;
    srv.unsignedQueryAccount(dest1Id, b1, xn, xd, xa, xt);
    srv.unsignedQueryAccount(dest2Id, b2, xn, xd, xa, xt);
    BOOST_CHECK_EQUAL(b1, static_cast<int64_t>(kA));
    BOOST_CHECK_EQUAL(b2, static_cast<int64_t>(kB));
    HashPrefix o; AssetData c; uint16_t days = 0; uint32_t pr;
    srv.unsignedQueryAsset(born, o, c, days, pr);
    BOOST_CHECK_EQUAL(days, 8);
  };
  runVmCommitProbe("ces_vm_multi_wal", p);
}

// A VM run that mutates several cells and then ABORTs must roll everything
// back — and a crash right after must leave NOTHING on the WAL (no leak), with
// conservation intact (only gas was spent; the abort-path refund must also be
// durable, which is what the conservation check enforces here).
BOOST_AUTO_TEST_CASE(VmAbortThenCrash_NoLeak) {
  KeyPair dest;
  HashPrefix destId = Account::getMapKey(dest.getPublicKeyAsHash());
  minx::Hash born = makeHash("VM_ABORT_BORN");
  VmCommitProbe p;
  p.expectVmError = CESVM_ABORT;
  p.build = [](const KeyPair&) {
    VmProgram pgm;
    Region d = pgm.allocHash(); pgm.copyFromInput(d, 0);
    Region bk = pgm.allocHash(); pgm.copyFromInput(bk, 4);
    Region content = pgm.allocContent();
    pgm.sysTransfer({d, Imm(33'333)});
    pgm.sysCreateAsset({bk, content, Imm(9)});
    pgm.abort(); // unwind both mutations
    pgm.term();
    return pgm.buildBootBlock();
  };
  p.input = [dest, born](const KeyPair&) {
    ces::Bytes in;
    viAppend(in, dest.getPublicKeyAsHash());
    viAppend(in, born);
    return in;
  };
  p.verify = [destId, born](CesServer& srv, const KeyPair&) {
    HashPrefix xd; uint64_t xa; uint32_t xt, xn;
    int64_t b = 0;
    srv.unsignedQueryAccount(destId, b, xn, xd, xa, xt);
    BOOST_CHECK_EQUAL(b, 0); // transfer reverted: dest never created
    HashPrefix o; AssetData c; uint16_t days = 0; uint32_t pr;
    srv.unsignedQueryAsset(born, o, c, days, pr);
    BOOST_CHECK_EQUAL(days, 0); // create reverted: asset absent
  };
  runVmCommitProbe("ces_vm_abort_wal", p);
}

// A read-only VM run still reserves the full budget up front; the unused
// remainder is refunded after the run, and that refund must be durable across
// a crash. (This was the half-state that leaked before the fix — the gas debit
// flushed, the refund did not.)
BOOST_AUTO_TEST_CASE(VmRefund_SurvivesWALReplay) {
  fs::path pDir = makeUniqueTempDir("ces_vm_refund_wal");
  minx::Hash sPriv;
  sPriv.fill(0xEE);
  KeyPair user;
  HashPrefix userId = Account::getMapKey(user.getPublicKeyAsHash());
  minx::Hash progId = makeHash("VM_NOP_PROG");
  int64_t userBalAfterRun = 0;

  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv(cfg);
    uint16_t port = srv.start(0);
    CesClient cli(testServerEp(port), false);
    cli.start(0);
    cli.setKey(user);
    cli.connect();

    srv._brr(user.getPublicKeyAsHash(), 10'000'000'000);
    srv._drainLogic();

    VmProgram pgm;
    pgm.term();
    CES_REQUIRE_OK(cli.createAsset(progId, pgm.buildBootBlock(), 30));
    srv._drainLogic();

    uint64_t vmError = 0, budgetUsed = 0;
    ces::Bytes output;
    uint8_t rc = cli.runAsset(progId, 1'000'000'000, {}, vmError, budgetUsed,
                              output);
    CES_REQUIRE_OK(rc);
    BOOST_REQUIRE_EQUAL(vmError, static_cast<uint64_t>(CESVM_OK));
    srv._drainLogic();

    HashPrefix xd; uint64_t xa; uint32_t xt, xn;
    srv.unsignedQueryAccount(userId, userBalAfterRun, xn, xd, xa, xt);
    cli.stop();
    // crash — no snapshot.
  }
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv2(cfg);
    srv2.start(0);
    HashPrefix xd; uint64_t xa; uint32_t xt, xn;
    int64_t bal = 0;
    srv2.unsignedQueryAccount(userId, bal, xn, xd, xa, xt);
    BOOST_CHECK_EQUAL(bal, userBalAfterRun); // refund survived
    srv2.stop();
  }

  boost::system::error_code ec;
  fs::remove_all(pDir, ec);
}

// The cron path (executeScheduledRun) now shares executeVmRun with the wire
// path, so a scheduled run must be atomic and durable exactly like a wire run.
// A scheduled SYS_TRANSFER must survive crash-recovery with conservation
// intact — before unification, cron mutated directly (unjournalled) and its
// refund went unflushed, so both legs vanished on a crash.
BOOST_AUTO_TEST_CASE(CronTransfer_SurvivesWALReplay) {
  fs::path pDir = makeUniqueTempDir("ces_cron_xfer_wal");
  minx::Hash sPriv;
  sPriv.fill(0xEE);

  KeyPair user;
  HashPrefix userId = Account::getMapKey(user.getPublicKeyAsHash());
  KeyPair dest;
  HashPrefix destId = Account::getMapKey(dest.getPublicKeyAsHash());
  while (destId == userId) {
    dest = KeyPair();
    destId = Account::getMapKey(dest.getPublicKeyAsHash());
  }

  minx::Hash progId = makeHash("CRON_XFER_PROG");
  const uint64_t kAmount = 50'000;
  const int64_t kDestSeed = 1'000;

  int64_t destBalAfterRun = 0, totalAfterRun = 0;

  // Phase 1: deploy a transfer program, fire it through the CRON path, CRASH.
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv(cfg);
    uint16_t port = srv.start(0);
    CesClient cli(testServerEp(port), false);
    cli.start(0);
    cli.setKey(user);
    cli.connect();

    srv._brr(user.getPublicKeyAsHash(), 10'000'000'000);
    srv._brr(dest.getPublicKeyAsHash(), kDestSeed);
    srv._drainLogic();

    VmProgram pgm;
    Region destKeyReg = pgm.allocHash();
    pgm.copyFromInput(destKeyReg, 0);
    pgm.sysTransfer({destKeyReg, Imm(kAmount)});
    pgm.term();
    CES_REQUIRE_OK(cli.createAsset(progId, pgm.buildBootBlock(), 30));
    srv._drainLogic();

    // Drive the CRON path (executeScheduledRun), not the wire path.
    ces::Bytes input(dest.getPublicKeyAsHash().begin(),
                     dest.getPublicKeyAsHash().end());
    bool ok = srv._executeScheduledRunSync(
      userId, progId, 1'000'000'000,
      std::numeric_limits<uint64_t>::max(), input);
    BOOST_REQUIRE(ok);
    srv._drainLogic();

    HashPrefix xd; uint64_t xa; uint32_t xt, xn;
    srv.unsignedQueryAccount(destId, destBalAfterRun, xn, xd, xa, xt);
    totalAfterRun = srv._getTotalCredits();
    BOOST_REQUIRE_EQUAL(destBalAfterRun, kDestSeed + static_cast<int64_t>(kAmount));

    cli.stop();
    // NO srv.stop() — crash.
  }

  // Phase 2: WAL replay — the scheduled transfer must reproduce.
  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv2(cfg);
    srv2.start(0);
    HashPrefix xd; uint64_t xa; uint32_t xt, xn;
    int64_t destBal = 0;
    srv2.unsignedQueryAccount(destId, destBal, xn, xd, xa, xt);
    BOOST_CHECK_EQUAL(destBal, destBalAfterRun);
    BOOST_CHECK_EQUAL(srv2._getTotalCredits(), totalAfterRun);
    srv2.stop();
  }

  boost::system::error_code ec;
  fs::remove_all(pDir, ec);
}

// A cron run that mutates then ABORTs must roll back (cron now has an undo
// log) and leave nothing on the WAL after a crash, with conservation intact —
// proving the cron path is fully atomic, not merely durable.
BOOST_AUTO_TEST_CASE(CronAbortThenCrash_NoLeak) {
  fs::path pDir = makeUniqueTempDir("ces_cron_abort_wal");
  minx::Hash sPriv;
  sPriv.fill(0xEE);

  KeyPair user;
  HashPrefix userId = Account::getMapKey(user.getPublicKeyAsHash());
  KeyPair dest;
  HashPrefix destId = Account::getMapKey(dest.getPublicKeyAsHash());
  while (destId == userId) {
    dest = KeyPair();
    destId = Account::getMapKey(dest.getPublicKeyAsHash());
  }
  minx::Hash progId = makeHash("CRON_ABORT_PROG");
  minx::Hash born = makeHash("CRON_ABORT_BORN");

  int64_t totalAfterRun = 0;

  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv(cfg);
    uint16_t port = srv.start(0);
    CesClient cli(testServerEp(port), false);
    cli.start(0);
    cli.setKey(user);
    cli.connect();

    srv._brr(user.getPublicKeyAsHash(), 10'000'000'000);
    srv._drainLogic();

    VmProgram pgm;
    Region d = pgm.allocHash(); pgm.copyFromInput(d, 0);
    Region bk = pgm.allocHash(); pgm.copyFromInput(bk, 4);
    Region content = pgm.allocContent();
    pgm.sysTransfer({d, Imm(33'333)});
    pgm.sysCreateAsset({bk, content, Imm(9)});
    pgm.abort();
    pgm.term();
    CES_REQUIRE_OK(cli.createAsset(progId, pgm.buildBootBlock(), 30));
    srv._drainLogic();

    ces::Bytes input;
    input.insert(input.end(), dest.getPublicKeyAsHash().begin(),
                 dest.getPublicKeyAsHash().end());
    input.insert(input.end(), born.begin(), born.end());
    bool ok = srv._executeScheduledRunSync(
      userId, progId, 1'000'000'000,
      std::numeric_limits<uint64_t>::max(), input);
    BOOST_REQUIRE(ok); // executeScheduledRun returns true even on VM abort
    srv._drainLogic();

    totalAfterRun = srv._getTotalCredits();
    cli.stop();
    // crash.
  }

  {
    CesConfig cfg = makeTestConfig(pDir, sPriv, 0);
    CesServer srv2(cfg);
    srv2.start(0);
    HashPrefix xd; uint64_t xa; uint32_t xt, xn;
    int64_t destBal = 0;
    srv2.unsignedQueryAccount(destId, destBal, xn, xd, xa, xt);
    BOOST_CHECK_EQUAL(destBal, 0); // transfer reverted
    HashPrefix o; AssetData c; uint16_t days = 0; uint32_t pr;
    srv2.unsignedQueryAsset(born, o, c, days, pr);
    BOOST_CHECK_EQUAL(days, 0); // asset create reverted
    BOOST_CHECK_EQUAL(srv2._getTotalCredits(), totalAfterRun);
    srv2.stop();
  }

  boost::system::error_code ec;
  fs::remove_all(pDir, ec);
}

BOOST_AUTO_TEST_SUITE_END()
