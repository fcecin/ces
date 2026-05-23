#include "test_common.h"

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
    wait_net();
    cli.createAsset(aid, originalContent, 10);
    wait_net();

    // 2. Fast Update (Memory Only)
    cli.updateAssetFast(aid, fastContent);
    wait_net();

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
    wait_net();

    AssetData initial;
    initial.fill(0x00);
    cli.createAsset(aid, initial, 10);
    wait_net();

    // Fast Update
    cli.updateAssetFast(aid, fastContent);
    wait_net();

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
    wait_net();

    // 1. Create
    cli.createAsset(aid, heavyContent, 10);
    wait_net();

    // 2. Meta Update (Set Price = 999)
    cli.updateAssetMeta(aid, Account::getMapKey(user.getPublicKeyAsHash()), 999);
    wait_net();

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
    wait_net();

    // 1. Create (Content A) -> Writes to WAL
    cli.createAsset(aid, contentA, 10);
    wait_net();

    // 2. Fast Update (Content B) -> RAM Only
    cli.updateAssetFast(aid, contentB);
    wait_net();

    // Check RAM is B
    HashPrefix o;
    AssetData c;
    uint16_t d;
    uint32_t p;
    cli.queryAsset(aid, o, c, d, p);
    BOOST_REQUIRE(c == contentB);

    // 3. Meta Update (Price 999) -> Writes Partial Event to WAL
    cli.updateAssetMeta(aid, Account::getMapKey(user.getPublicKeyAsHash()), 999);
    wait_net();

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
    wait_net();

    int64_t newBal;
    uint8_t rc = cli.openTransfer(bob.getPublicKeyAsHash(), 4242, newBal);
    CES_REQUIRE_OK(rc);
    wait_net();

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
    wait_net();

    int64_t newBal;
    uint8_t rc = cli.openTransfer(bob.getPublicKeyAsHash(), 3333, newBal);
    CES_REQUIRE_OK(rc);
    wait_net();

    // This credit writes a BalanceNonce (0x01) WAL entry AFTER the
    // Transfer (0x03) entry. On replay, the 0x01 entry must not
    // zero out the xfer fields that were set by the 0x03 entry.
    srv._brr(user.getPublicKeyAsHash(), 500);
    wait_net();

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
    wait_net();

    int64_t newBal;
    uint8_t rc = cli.openTransfer(bob.getPublicKeyAsHash(), 7777, newBal);
    CES_REQUIRE_OK(rc);
    wait_net();

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
    wait_net();

    cli.createAsset(aid, content, 5);
    wait_net();

    cli.fundAsset(aid, 20);
    wait_net();

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
    wait_net();

    cli.createAsset(aid, content, 10);
    wait_net();

    // Set a price via meta update
    cli.updateAssetMeta(aid, Account::getMapKey(user.getPublicKeyAsHash()), 555);
    wait_net();

    // Fund (writes Balance-only WAL entry after the Meta entry)
    cli.fundAsset(aid, 5);
    wait_net();

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
    wait_net();

    cli.createAsset(aid, content, 10);
    wait_net();

    // Set a price first
    cli.updateAssetMeta(aid, creatorId, 1000);
    wait_net();

    // Give away (transferOwnership sets owner=receiver, price=0)
    cli.giveAsset(aid, receiverId);
    wait_net();

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
    wait_net();

    cli.createAsset(aid, contentA, 10);
    wait_net();

    // Full update: new content + price
    cli.updateAsset(aid, userId, contentB, 777);
    wait_net();

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

BOOST_AUTO_TEST_SUITE_END()
