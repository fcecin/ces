#include "test_common.h"

BOOST_FIXTURE_TEST_SUITE(AssetTests, CesFixture)

BOOST_AUTO_TEST_CASE(Test06_CreateAndQueryAsset) {
  LOGINFO << "TEST: Starting CreateAndQueryAsset";
  minx::Hash aid = makeHash("TEST_TOKEN");
  AssetData data;
  data.fill(0xAA);

  uint8_t rc = client->createAsset(aid, data, 10);
  BOOST_REQUIRE_MESSAGE(rc == CES_OK, "Create Asset Failed RC: " << (int)rc);

  std::vector<AssetEntry> res;
  rc = client->queryAssetSigned(aid, 0, res);
  CES_REQUIRE_OK(rc);
  BOOST_REQUIRE_EQUAL(res.size(), 1);
  BOOST_CHECK(res[0].content == data);
  BOOST_CHECK_EQUAL(res[0].balance, 10 + 1);
}

BOOST_AUTO_TEST_CASE(Test07_UpdateAsset) {
  LOGINFO << "TEST: Starting UpdateAsset";
  minx::Hash aid = makeHash("MUTABLE");
  AssetData d;
  d.fill(0);
  client->createAsset(aid, d, 10);

  d.fill(0xFF);
  uint8_t rc = client->updateAsset(aid, getMyId(), d, 500);
  CES_CHECK_OK(rc);

  std::vector<AssetEntry> res;
  client->queryAssetSigned(aid, 0, res);
  BOOST_REQUIRE(!res.empty());
  BOOST_CHECK_EQUAL(res[0].price, 500);
  BOOST_CHECK(res[0].content == d);
}

BOOST_AUTO_TEST_CASE(Test08_FundAsset) {
  LOGINFO << "TEST: Starting FundAsset";
  minx::Hash aid = makeHash("RENTAL");
  AssetData d;
  d.fill(0);
  client->createAsset(aid, d, 5);

  uint8_t rc = client->fundAsset(aid, 20);
  CES_CHECK_OK(rc);

  std::vector<AssetEntry> res;
  client->queryAssetSigned(aid, 0, res);
  BOOST_REQUIRE(!res.empty());
  BOOST_CHECK_EQUAL(res[0].balance, 25 + 1);
}

BOOST_AUTO_TEST_CASE(Test09_GiveAsset) {
  LOGINFO << "TEST: Starting GiveAsset";
  minx::Hash aid = makeHash("GIFT");
  AssetData d;
  d.fill(0);
  client->createAsset(aid, d, 10);

  // Set a non-zero price so the post-give reset is actually observable.
  // transferOwnership is supposed to clear the price to 0 — if it regresses
  // and the price survives the handoff, the new owner silently keeps the
  // old listing (attacker-auctioned inventory pattern).
  uint8_t rc = client->updateAsset(aid, getMyId(), d, 1234);
  CES_REQUIRE_OK(rc);

  KeyPair friendKey;
  HashPrefix friendId = Account::getMapKey(friendKey.getPublicKeyAsHash());

  rc = client->giveAsset(aid, friendId);
  CES_CHECK_OK(rc);

  std::vector<AssetEntry> res;
  client->queryAssetSigned(aid, 0, res);
  BOOST_REQUIRE(!res.empty());
  BOOST_CHECK(res[0].ownerId == friendId);
  BOOST_CHECK_EQUAL(res[0].price, 0);
}

BOOST_AUTO_TEST_CASE(Test10_BuyAsset) {
  LOGINFO << "TEST: Starting BuyAsset";
  minx::Hash aid = makeHash("VENDING");
  AssetData d;
  d.fill(0);
  client->createAsset(aid, d, 10);
  client->updateAsset(aid, getMyId(), d, 10);

  CesClient buyer(testServerEp(serverPort), false);
  buyer.start(0);
  KeyPair buyerKey;
  buyer.setKey(buyerKey);
  buyer.connect();
  server->_brr(buyerKey.getPublicKeyAsHash(), 100'000'000'000LL);
  wait_net();

  // Snapshot the seller's balance just before the buy so we can check the
  // transfer leg of buyAsset actually credited them. Without this the test
  // only proves ownership flipped — a bug that burns the sale price on the
  // floor instead of paying the seller would pass.
  int64_t sellerBalBefore = 0;
  uint32_t sellerNonceBefore = 0;
  BOOST_REQUIRE_EQUAL(
    (int)client->queryAccount(getMyId(), sellerBalBefore, sellerNonceBefore),
    (int)CES_OK);

  uint64_t offerPrice = (uint64_t)10 * ces::PRICE_UNIT;
  uint8_t rc = buyer.buyAsset(aid, offerPrice);
  BOOST_REQUIRE_MESSAGE(rc == CES_OK, "Buy Asset Failed RC: " << (int)rc);

  std::vector<AssetEntry> res;
  buyer.queryAssetSigned(aid, 0, res);
  BOOST_REQUIRE(!res.empty());
  BOOST_CHECK(res[0].ownerId == Account::getMapKey(buyerKey.getPublicKeyAsHash()));
  BOOST_CHECK_EQUAL(res[0].price, 0);

  int64_t sellerBalAfter = 0;
  uint32_t sellerNonceAfter = 0;
  BOOST_REQUIRE_EQUAL(
    (int)client->queryAccount(getMyId(), sellerBalAfter, sellerNonceAfter),
    (int)CES_OK);
  BOOST_CHECK_EQUAL(sellerBalAfter - sellerBalBefore,
                    static_cast<int64_t>(offerPrice));
}

BOOST_AUTO_TEST_CASE(Test11_AssetExpirationLogic) {
  LOGINFO << "TEST: Starting AssetExpirationLogic";
  minx::Hash aid = makeHash("TEMP");
  AssetData d;
  d.fill(0);
  client->createAsset(aid, d, 1);

  std::vector<AssetEntry> res;
  BOOST_CHECK_EQUAL((int)client->queryAssetSigned(aid, 0, res), (int)CES_OK);

  server->_runDailyMaintenance();

  uint8_t rc = client->queryAssetSigned(aid, 0, res);
  CES_CHECK_OK(rc);

  server->_runDailyMaintenance();

  rc = client->queryAssetSigned(aid, 0, res);
  CES_CHECK_RC_EQ(rc, CES_ERROR_ASSET_NOT_FOUND);
}

BOOST_AUTO_TEST_CASE(Test13_AssetCollision) {
  LOGINFO << "TEST: Starting AssetCollision";
  minx::Hash aid = makeHash("UNIQUE_ASSET");
  AssetData d;
  d.fill(1);

  // 1. Alice creates it
  uint8_t rc = client->createAsset(aid, d, 10);
  CES_CHECK_OK(rc);

  // 2. Bob tries to create SAME asset ID
  CesClient bob(testServerEp(serverPort), false);
  bob.start(0);
  KeyPair bobKey;
  bob.setKey(bobKey);
  bob.connect();

  server->_brr(bobKey.getPublicKeyAsHash(), (2 + 10) * BASE_FEE_ASSET + BASE_FEE_TRANSACTION);
  wait_net();

  rc = bob.createAsset(aid, d, 10);
  CES_CHECK_RC_EQ(rc, CES_ERROR_ASSET_EXISTS);
}

BOOST_AUTO_TEST_CASE(Test14_AssetTheftProtection) {
  LOGINFO << "TEST: Starting AssetTheftProtection";
  minx::Hash aid = makeHash("MY_PRECIOUS");
  AssetData d;
  d.fill(1);

  // 1. Client owns it
  client->createAsset(aid, d, 10);

  // 2. Thief tries to update it
  CesClient thief(testServerEp(serverPort), false);
  thief.start(0);
  KeyPair thiefKey;
  thief.setKey(thiefKey);
  thief.connect();

  server->_brr(thiefKey.getPublicKeyAsHash(), 100'000'000);
  wait_net();

  // Try Update
  uint8_t rc =
    thief.updateAsset(aid, Account::getMapKey(thiefKey.getPublicKeyAsHash()), d, 0);
  CES_CHECK_RC_EQ(rc, CES_ERROR_NOT_OWNER);

  // Try Give
  rc = thief.giveAsset(aid, Account::getMapKey(thiefKey.getPublicKeyAsHash()));
  CES_CHECK_RC_EQ(rc, CES_ERROR_NOT_OWNER);
}

BOOST_AUTO_TEST_CASE(Test15_BuyValidation) {
  LOGINFO << "TEST: Starting BuyValidation";
  minx::Hash aid = makeHash("EXPENSIVE_ART");
  AssetData d;
  d.fill(0);

  // Create and set price to 5
  client->createAsset(aid, d, 10);
  client->updateAsset(aid, getMyId(), d, 5);

  // Buyer
  CesClient buyer(testServerEp(serverPort), false);
  buyer.start(0);
  KeyPair buyerKey;
  buyer.setKey(buyerKey);
  buyer.connect();
  server->_brr(buyerKey.getPublicKeyAsHash(), 100'000'000'000LL);
  wait_net();

  // 1. Try Lowball (Offer 1 when price is 5)
  uint64_t lowball = (uint64_t)1 * ces::PRICE_UNIT;
  uint8_t rc = buyer.buyAsset(aid, lowball);
  CES_CHECK_RC_EQ(rc, CES_ERROR_INSUFFICIENT_PAYMENT);

  // 2. Try Buy Not For Sale
  client->updateAsset(aid, getMyId(), d, 0);

  uint64_t validOffer = (uint64_t)5 * ces::PRICE_UNIT;
  rc = buyer.buyAsset(aid, validOffer);
  CES_CHECK_RC_EQ(rc, CES_ERROR_NOT_FOR_SALE);
}

BOOST_AUTO_TEST_CASE(Test20_UnsignedAssetQuery) {
  LOGINFO << "TEST: Starting UnsignedAssetQuery";
  minx::Hash aid = makeHash("UNSIGNED_TEST");
  AssetData data;
  data.fill(0xBB);
  uint16_t initialDays = 50;

  // 1. Create the Asset
  uint8_t rc = client->createAsset(aid, data, initialDays);
  BOOST_REQUIRE_MESSAGE(rc == CES_OK, "Create Asset Failed RC: " << (int)rc);

  // 2. Query it using the Unsigned API
  HashPrefix owner;
  AssetData content;
  uint16_t days;
  uint32_t price;

  rc = client->queryAsset(aid, owner, content, days, price);
  CES_CHECK_OK(rc);
  BOOST_CHECK(content == data);
  BOOST_CHECK_EQUAL(days, initialDays + 1);
  BOOST_CHECK(owner == getMyId());

  // 3. Query a non-existent asset
  minx::Hash ghostAid = makeHash("GHOST_ASSET");
  rc = client->queryAsset(ghostAid, owner, content, days, price);

  CES_CHECK_OK(rc);
  BOOST_CHECK_EQUAL(days, 0);
}

// --- Balance bits: PRIVATE (bit 15), ASSET_OWNED (bit 14),
//                    IMMUTABLE (bit 13), days (bits 0-12) ---

BOOST_AUTO_TEST_CASE(BalanceBitUtilities) {
  // assetDays extracts lower 13 bits
  BOOST_CHECK_EQUAL(assetDays(0x0000), 0);
  BOOST_CHECK_EQUAL(assetDays(0x1FFF), 0x1FFF);  // max days = 8191
  BOOST_CHECK_EQUAL(assetDays(0x8000), 0);        // bit 15 only = 0 days
  BOOST_CHECK_EQUAL(assetDays(0xFFFF), 0x1FFF);   // all bits = max days
  BOOST_CHECK_EQUAL(assetDays(0x4000), 0);         // bit 14 only = 0 days
  BOOST_CHECK_EQUAL(assetDays(0x2000), 0);         // bit 13 only (IMMUTABLE) = 0 days
  BOOST_CHECK_EQUAL(assetDays(0xE000), 0);         // bits 15+14+13 = 0 days

  // isAssetPrivate checks bit 15
  BOOST_CHECK(!isAssetPrivate(0x0000));
  BOOST_CHECK(!isAssetPrivate(0x1FFF));
  BOOST_CHECK(!isAssetPrivate(0x4000));  // asset-owned but not private
  BOOST_CHECK(!isAssetPrivate(0x2000));  // immutable but not private
  BOOST_CHECK(isAssetPrivate(0x8000));
  BOOST_CHECK(isAssetPrivate(0xFFFF));

  // isAssetOwned checks bit 14
  BOOST_CHECK(!isAssetOwned(0x0000));
  BOOST_CHECK(!isAssetOwned(0x8000));   // private but not asset-owned
  BOOST_CHECK(!isAssetOwned(0x2000));   // immutable but not asset-owned
  BOOST_CHECK(isAssetOwned(0x4000));
  BOOST_CHECK(isAssetOwned(0xC000));    // private + asset-owned
  BOOST_CHECK(isAssetOwned(0x5FFF));    // asset-owned + max days

  // isAssetImmutable checks bit 13
  BOOST_CHECK(!isAssetImmutable(0x0000));
  BOOST_CHECK(!isAssetImmutable(0x8000));   // private only
  BOOST_CHECK(!isAssetImmutable(0x4000));   // asset-owned only
  BOOST_CHECK(isAssetImmutable(0x2000));
  BOOST_CHECK(isAssetImmutable(0xE000));    // all three flags
  BOOST_CHECK(isAssetImmutable(0x3FFF));    // immutable + max days

  // assetBalance reconstructs
  BOOST_CHECK_EQUAL(assetBalance(100, false), 100);
  BOOST_CHECK_EQUAL(assetBalance(100, true), 0x8064);
  BOOST_CHECK_EQUAL(assetBalance(100, false, true), 0x4064);
  BOOST_CHECK_EQUAL(assetBalance(100, true, true), 0xC064);
  BOOST_CHECK_EQUAL(assetBalance(100, false, false, true), 0x2064);
  BOOST_CHECK_EQUAL(assetBalance(100, true, false, true), 0xA064);
  BOOST_CHECK_EQUAL(assetBalance(100, false, true, true), 0x6064);
  BOOST_CHECK_EQUAL(assetBalance(100, true, true, true), 0xE064);
  BOOST_CHECK_EQUAL(assetBalance(0x1FFF, false), 0x1FFF);
  BOOST_CHECK_EQUAL(assetBalance(0x1FFF, true), 0x9FFF);
  BOOST_CHECK_EQUAL(assetBalance(0x1FFF, true, true), 0xDFFF);
  BOOST_CHECK_EQUAL(assetBalance(0x1FFF, true, true, true), 0xFFFF);
  BOOST_CHECK_EQUAL(assetBalance(0, true), 0x8000);
  // Days argument exceeding 13 bits is masked.
  BOOST_CHECK_EQUAL(assetBalance(0x3FFF, false), 0x1FFF);

  // Round-trip
  uint16_t raw = assetBalance(7000, true, true, true);
  BOOST_CHECK(isAssetPrivate(raw));
  BOOST_CHECK(isAssetOwned(raw));
  BOOST_CHECK(isAssetImmutable(raw));
  BOOST_CHECK_EQUAL(assetDays(raw), 7000);
}

BOOST_AUTO_TEST_CASE(FundAssetDaysCappedAt8191) {
  // Fund the account enough to cover two max-days fund operations
  int64_t fundCost = static_cast<int64_t>(8191) * BASE_FEE_ASSET + BASE_FEE_TRANSACTION;
  server->_brr(clientKey.getPublicKeyAsHash(), fundCost * 3);
  wait_net();

  minx::Hash aid = makeHash("CAP_TEST");
  AssetData data{};
  uint8_t rc = client->createAsset(aid, data, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  wait_net();

  // Fund with 8191 — should cap at 0x1FFF, not overflow into flag bits.
  rc = client->fundAsset(aid, 8191);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  wait_net();

  HashPrefix owner;
  AssetData content;
  uint16_t days = 0;
  uint32_t price = 0;
  rc = client->queryAsset(aid, owner, content, days, price);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_TEST_MESSAGE("Days after fund +8191: " << days);
  BOOST_CHECK(days <= 8191);
  BOOST_CHECK(days > 0);

  // Fund again — should stay capped
  rc = client->fundAsset(aid, 8191);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  wait_net();

  rc = client->queryAsset(aid, owner, content, days, price);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_TEST_MESSAGE("Days after second fund +8191: " << days);
  BOOST_CHECK_EQUAL(days, 8191);  // capped at max
}

// --- Private assets ---

BOOST_AUTO_TEST_CASE(PrivateAssetUnsignedQueryHidesContent) {
  minx::Hash aid = makeHash("PRIV_TEST1");
  AssetData data;
  data.fill(0xAA);
  uint8_t rc = client->createAsset(aid, data, 30, true);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  wait_net();

  // Unsigned query should return zero content
  HashPrefix owner;
  AssetData content;
  uint16_t days = 0;
  uint32_t price = 0;
  rc = client->queryAsset(aid, owner, content, days, price);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK(days > 0);
  // Content should be all zeros (hidden)
  bool allZero = true;
  for (auto b : content) if (b != 0) { allZero = false; break; }
  BOOST_CHECK(allZero);
}

BOOST_AUTO_TEST_CASE(PrivateAssetSignedQueryByOwnerShowsContent) {
  minx::Hash aid = makeHash("PRIV_TEST2");
  AssetData data;
  data.fill(0xBB);
  uint8_t rc = client->createAsset(aid, data, 30, true);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  wait_net();

  // Signed query by owner should return real content
  std::vector<AssetEntry> results;
  rc = client->queryAssetSigned(aid, 0, results);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_REQUIRE(!results.empty());
  BOOST_CHECK_EQUAL(results[0].content[0], 0xBB);
}

BOOST_AUTO_TEST_CASE(PublicAssetUnsignedQueryShowsContent) {
  minx::Hash aid = makeHash("PUB_TEST");
  AssetData data;
  data.fill(0xCC);
  uint8_t rc = client->createAsset(aid, data, 30, false);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  wait_net();

  HashPrefix owner;
  AssetData content;
  uint16_t days = 0;
  uint32_t price = 0;
  rc = client->queryAsset(aid, owner, content, days, price);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(content[0], 0xCC);
}

BOOST_AUTO_TEST_CASE(PrivateAssetSignedQueryByNonOwnerHidesContent) {
  minx::Hash aid = makeHash("PRIV_TEST3");
  AssetData data;
  data.fill(0xDD);
  uint8_t rc = client->createAsset(aid, data, 30, true);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  wait_net();

  // Create a second client with a different key
  KeyPair otherKey;
  server->_brr(otherKey.getPublicKeyAsHash(), 10'000'000'000);
  wait_net();

  boost::asio::ip::udp::endpoint ep(
    boost::asio::ip::address_v6::loopback(), serverPort);
  CesClient otherClient(ep, false);
  otherClient.start(0);
  otherClient.setKey(otherKey);
  BOOST_REQUIRE(otherClient.connect());

  // Signed query by non-owner should return NOT FOUND (asset is invisible)
  std::vector<AssetEntry> results;
  rc = otherClient.queryAssetSigned(aid, 0, results);
  BOOST_CHECK_EQUAL(rc, CES_ERROR_ASSET_NOT_FOUND);

  otherClient.stop();
}

BOOST_AUTO_TEST_CASE(FundPrivateAssetPreservesPrivacy) {
  minx::Hash aid = makeHash("PRIV_FUND");
  AssetData data;
  data.fill(0xEE);
  uint8_t rc = client->createAsset(aid, data, 10, true);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  wait_net();

  // Fund it
  rc = client->fundAsset(aid, 20);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  wait_net();

  // Unsigned query should still hide content
  HashPrefix owner;
  AssetData content;
  uint16_t days = 0;
  uint32_t price = 0;
  rc = client->queryAsset(aid, owner, content, days, price);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK(days >= 30); // 10+1 created + 20 funded
  bool allZero = true;
  for (auto b : content) if (b != 0) { allZero = false; break; }
  BOOST_CHECK(allZero); // still private
}

BOOST_AUTO_TEST_CASE(PrivateAssetSkippedInRangeQuery) {
  // Create 3 assets: public, private (other owner), public
  // A range query starting from the first should skip the private one
  minx::Hash aid1 = makeHash("RANGE_PUB1");
  minx::Hash aid2 = makeHash("RANGE_PRIV");
  minx::Hash aid3 = makeHash("RANGE_PUB2");

  AssetData d1{}; d1[0] = 0x11;
  AssetData d2{}; d2[0] = 0x22;
  AssetData d3{}; d3[0] = 0x33;

  uint8_t rc = client->createAsset(aid1, d1, 30, false);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  rc = client->createAsset(aid2, d2, 30, true); // private, owned by client
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  rc = client->createAsset(aid3, d3, 30, false);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  wait_net();

  // Create a second client
  KeyPair otherKey;
  server->_brr(otherKey.getPublicKeyAsHash(), 10'000'000'000);
  wait_net();

  boost::asio::ip::udp::endpoint ep(
    boost::asio::ip::address_v6::loopback(), serverPort);
  CesClient otherClient(ep, false);
  otherClient.start(0);
  otherClient.setKey(otherKey);
  BOOST_REQUIRE(otherClient.connect());

  // Other client does a range query for aid2 (private, not theirs) → NOT_FOUND
  std::vector<AssetEntry> results;
  rc = otherClient.queryAssetSigned(aid2, 0, results);
  BOOST_CHECK_EQUAL(rc, CES_ERROR_ASSET_NOT_FOUND);

  // Owner queries aid2 → should find it
  results.clear();
  rc = client->queryAssetSigned(aid2, 0, results);
  BOOST_CHECK_EQUAL(rc, CES_OK);
  BOOST_REQUIRE(!results.empty());
  BOOST_CHECK_EQUAL(results[0].content[0], 0x22);

  otherClient.stop();
}

// --- IMMUTABLE assets ---

BOOST_AUTO_TEST_CASE(ImmutableAssetCreate) {
  minx::Hash aid = makeHash("IMM_CREATE");
  AssetData data;
  data.fill(0xAB);
  uint8_t rc = client->createAsset(aid, data, 30, /*priv=*/false,
                                   /*immutable=*/true);
  CES_REQUIRE_OK(rc);
  wait_net();

  HashPrefix owner;
  AssetData got;
  uint16_t days = 0;
  uint32_t price = 0;
  rc = client->queryAsset(aid, owner, got, days, price);
  CES_REQUIRE_OK(rc);
  BOOST_CHECK_EQUAL(got[0], 0xAB);
  BOOST_CHECK(days >= 30);
}

BOOST_AUTO_TEST_CASE(ImmutableAssetRejectsUpdate) {
  minx::Hash aid = makeHash("IMM_UPDATE");
  AssetData data;
  data.fill(0x11);
  uint8_t rc = client->createAsset(aid, data, 30, false, /*immutable=*/true);
  CES_REQUIRE_OK(rc);
  wait_net();

  // Try full update — must fail with CES_ERROR_IMMUTABLE
  AssetData newData;
  newData.fill(0x22);
  rc = client->updateAsset(aid, getMyId(), newData, 0);
  CES_CHECK_RC_EQ(rc, CES_ERROR_IMMUTABLE);
  wait_net();

  // Content unchanged
  HashPrefix owner;
  AssetData got;
  uint16_t days = 0;
  uint32_t price = 0;
  rc = client->queryAsset(aid, owner, got, days, price);
  CES_REQUIRE_OK(rc);
  BOOST_CHECK_EQUAL(got[0], 0x11);
}

BOOST_AUTO_TEST_CASE(ImmutableAssetRejectsUpdateFast) {
  minx::Hash aid = makeHash("IMM_FAST");
  AssetData data;
  data.fill(0x33);
  uint8_t rc = client->createAsset(aid, data, 30, false, true);
  CES_REQUIRE_OK(rc);
  wait_net();

  AssetData newData;
  newData.fill(0x44);
  rc = client->updateAssetFast(aid, newData);
  CES_CHECK_RC_EQ(rc, CES_ERROR_IMMUTABLE);
  wait_net();

  HashPrefix owner;
  AssetData got;
  uint16_t days = 0;
  uint32_t price = 0;
  rc = client->queryAsset(aid, owner, got, days, price);
  CES_REQUIRE_OK(rc);
  BOOST_CHECK_EQUAL(got[0], 0x33);
}

BOOST_AUTO_TEST_CASE(ImmutableAssetAllowsMetaUpdate) {
  // updateAssetMeta changes owner+price, NOT content. Must be allowed.
  minx::Hash aid = makeHash("IMM_META");
  AssetData data;
  data.fill(0x55);
  uint8_t rc = client->createAsset(aid, data, 30, false, true);
  CES_REQUIRE_OK(rc);
  wait_net();

  // Set a price (owner unchanged, content unchanged) — should succeed.
  rc = client->updateAssetMeta(aid, getMyId(), 42);
  CES_CHECK_OK(rc);
  wait_net();

  HashPrefix owner;
  AssetData got;
  uint16_t days = 0;
  uint32_t price = 0;
  rc = client->queryAsset(aid, owner, got, days, price);
  CES_REQUIRE_OK(rc);
  BOOST_CHECK_EQUAL(price, 42u);
  BOOST_CHECK_EQUAL(got[0], 0x55);
}

BOOST_AUTO_TEST_CASE(ImmutableAssetAllowsFunding) {
  // fundAsset adds days, doesn't touch content. Must be allowed.
  // Also verifies the IMMUTABLE bit survives the balance recompute.
  minx::Hash aid = makeHash("IMM_FUND");
  AssetData data;
  data.fill(0x77);
  uint8_t rc = client->createAsset(aid, data, 30, false, true);
  CES_REQUIRE_OK(rc);
  wait_net();

  rc = client->fundAsset(aid, 100);
  CES_CHECK_OK(rc);
  wait_net();

  // Content still rejects update (IMMUTABLE bit preserved through funding).
  AssetData newData;
  newData.fill(0x99);
  rc = client->updateAsset(aid, getMyId(), newData, 0);
  CES_CHECK_RC_EQ(rc, CES_ERROR_IMMUTABLE);
  wait_net();
}

BOOST_AUTO_TEST_CASE(NonImmutableAssetCanBeUpdated) {
  // Sanity: assets created without --immutable are still updatable.
  minx::Hash aid = makeHash("NORMAL_UPDATE");
  AssetData data;
  data.fill(0xCC);
  uint8_t rc = client->createAsset(aid, data, 30); // default immutable=false
  CES_REQUIRE_OK(rc);
  wait_net();

  AssetData newData;
  newData.fill(0xDD);
  rc = client->updateAsset(aid, getMyId(), newData, 0);
  CES_CHECK_OK(rc);
  wait_net();

  HashPrefix owner;
  AssetData got;
  uint16_t days = 0;
  uint32_t price = 0;
  rc = client->queryAsset(aid, owner, got, days, price);
  CES_REQUIRE_OK(rc);
  BOOST_CHECK_EQUAL(got[0], 0xDD);
}

BOOST_AUTO_TEST_SUITE_END()
