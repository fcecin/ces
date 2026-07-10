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

// Regression (B1): createAsset stored `1 + days`; at the documented max
// (4095 days) that is 4096, which the 12-bit day field truncates to 0
// (4096 & 0x0FFF). A max-life asset was created with ZERO days -- dead on
// the next daily maintenance -- even though the cost charged for ~4097 days.
// The stored day count must clamp to the field max, never wrap to 0.
BOOST_AUTO_TEST_CASE(CreateAssetMaxDaysDoesNotWrapToZero) {
  minx::Hash aid = makeHash("MAX_DAYS_TOKEN");
  AssetData data;
  data.fill(0xCD);

  // 4095 days of asset rent is ~4097 x feeAsset (~210B at stock fees);
  // fund the client well past that so the create reaches the day-clamp.
  server->_brr(clientKey.getPublicKeyAsHash(), 100'000'000'000'000LL);

  uint8_t rc = client->createAsset(aid, data, 0x0FFF);  // 4095 = max days
  CES_REQUIRE_OK(rc);

  std::vector<AssetEntry> res;
  rc = client->queryAssetSigned(aid, 0, res);
  CES_REQUIRE_OK(rc);
  BOOST_REQUIRE_EQUAL(res.size(), 1);
  BOOST_CHECK_EQUAL((int)ces::assetDays(res[0].balance), 0x0FFF);
}

// Regression (BUG3): fundAsset billed for the full requested days, but the
// day field caps at 0x0FFF -- funding an asset already at the cap grants 0
// days yet (pre-fix) charged thousands of days of rent. A fund that adds no
// days must cost only the flat fund fee.
BOOST_AUTO_TEST_CASE(FundAssetPastCapDoesNotOvercharge) {
  server->_brr(clientKey.getPublicKeyAsHash(), 1'000'000'000'000LL);
  minx::Hash aid = makeHash("FUND_CAP_TOKEN");
  AssetData data;
  data.fill(0x77);
  CES_REQUIRE_OK(client->createAsset(aid, data, 0x0FFF));  // -> stored at 0x0FFF cap

  HashPrefix d{}; uint32_t n = 0, t = 0; uint64_t a = 0;
  int64_t before = 0;
  server->unsignedQueryAccount(getMyId(), before, n, d, a, t);

  CES_REQUIRE_OK(client->fundAsset(aid, 8000));  // 0 days actually granted

  int64_t after = 0;
  server->unsignedQueryAccount(getMyId(), after, n, d, a, t);
  int64_t fundCost = before - after;
  // 8000 days of asset rent is ~200B; granting 0 days must cost ~0 (just the
  // flat fund fee), far under 1B.
  BOOST_CHECK_MESSAGE(fundCost < 1'000'000'000LL,
    "fundAsset overcharged for ungranted days; cost=" << fundCost);
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
  server->_drainLogic();

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
  server->_drainLogic();

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
  server->_drainLogic();

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
  server->_drainLogic();

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

// --- Balance bits: PRIVATE (15), ASSET_OWNED (14), IMMUTABLE (13),
//                    OWNER_PAYS (12), days (bits 0-11, max 4095) ---

BOOST_AUTO_TEST_CASE(BalanceBitUtilities) {
  // assetDays extracts the lower 12 bits
  BOOST_CHECK_EQUAL(assetDays(0x0000), 0);
  BOOST_CHECK_EQUAL(assetDays(0x0FFF), 0x0FFF);  // max days = 4095
  BOOST_CHECK_EQUAL(assetDays(0x8000), 0);        // bit 15 only = 0 days
  BOOST_CHECK_EQUAL(assetDays(0xFFFF), 0x0FFF);   // all bits = max days
  BOOST_CHECK_EQUAL(assetDays(0x4000), 0);         // bit 14 only = 0 days
  BOOST_CHECK_EQUAL(assetDays(0x2000), 0);         // bit 13 only (IMMUTABLE) = 0 days
  BOOST_CHECK_EQUAL(assetDays(0x1000), 0);         // bit 12 only (OWNER_PAYS) = 0 days
  BOOST_CHECK_EQUAL(assetDays(0xF000), 0);         // bits 15+14+13+12 = 0 days

  // isAssetPrivate checks bit 15
  BOOST_CHECK(!isAssetPrivate(0x0000));
  BOOST_CHECK(!isAssetPrivate(0x0FFF));
  BOOST_CHECK(!isAssetPrivate(0x4000));  // asset-owned but not private
  BOOST_CHECK(isAssetPrivate(0x8000));
  BOOST_CHECK(isAssetPrivate(0xFFFF));

  // isAssetOwned checks bit 14
  BOOST_CHECK(!isAssetOwned(0x0000));
  BOOST_CHECK(!isAssetOwned(0x8000));   // private but not asset-owned
  BOOST_CHECK(isAssetOwned(0x4000));
  BOOST_CHECK(isAssetOwned(0xC000));    // private + asset-owned

  // isAssetImmutable checks bit 13
  BOOST_CHECK(!isAssetImmutable(0x0000));
  BOOST_CHECK(!isAssetImmutable(0x8000));   // private only
  BOOST_CHECK(isAssetImmutable(0x2000));
  BOOST_CHECK(isAssetImmutable(0xE000));    // priv + owned + immut

  // isAssetOwnerPays checks bit 12
  BOOST_CHECK(!isAssetOwnerPays(0x0000));
  BOOST_CHECK(!isAssetOwnerPays(0x0FFF));   // max days, no flags
  BOOST_CHECK(!isAssetOwnerPays(0xE000));   // other three flags, not owner-pays
  BOOST_CHECK(isAssetOwnerPays(0x1000));
  BOOST_CHECK(isAssetOwnerPays(0xFFFF));

  // assetBalance reconstructs (priv, owned, immut, ownerPays)
  BOOST_CHECK_EQUAL(assetBalance(100, false), 100);
  BOOST_CHECK_EQUAL(assetBalance(100, true), 0x8064);
  BOOST_CHECK_EQUAL(assetBalance(100, false, true), 0x4064);
  BOOST_CHECK_EQUAL(assetBalance(100, true, true), 0xC064);
  BOOST_CHECK_EQUAL(assetBalance(100, false, false, true), 0x2064);
  BOOST_CHECK_EQUAL(assetBalance(100, false, false, false, true), 0x1064);
  BOOST_CHECK_EQUAL(assetBalance(0x0FFF, false), 0x0FFF);
  BOOST_CHECK_EQUAL(assetBalance(0x0FFF, true), 0x8FFF);
  BOOST_CHECK_EQUAL(assetBalance(0x0FFF, true, true), 0xCFFF);
  BOOST_CHECK_EQUAL(assetBalance(0x0FFF, true, true, true), 0xEFFF);
  BOOST_CHECK_EQUAL(assetBalance(0x0FFF, true, true, true, true), 0xFFFF);
  BOOST_CHECK_EQUAL(assetBalance(0, true), 0x8000);
  // Days argument exceeding 12 bits is masked.
  BOOST_CHECK_EQUAL(assetBalance(0x3FFF, false), 0x0FFF);

  // Round-trip (all four flags + a 12-bit day count)
  uint16_t raw = assetBalance(3000, true, true, true, true);
  BOOST_CHECK(isAssetPrivate(raw));
  BOOST_CHECK(isAssetOwned(raw));
  BOOST_CHECK(isAssetImmutable(raw));
  BOOST_CHECK(isAssetOwnerPays(raw));
  BOOST_CHECK_EQUAL(assetDays(raw), 3000);
}

BOOST_AUTO_TEST_CASE(FundAssetDaysCappedAt4095) {
  // Fund the account enough to cover two max-days fund operations
  int64_t fundCost = static_cast<int64_t>(4095) * BASE_FEE_ASSET + BASE_FEE_TRANSACTION;
  server->_brr(clientKey.getPublicKeyAsHash(), fundCost * 3);
  server->_drainLogic();

  minx::Hash aid = makeHash("CAP_TEST");
  AssetData data{};
  uint8_t rc = client->createAsset(aid, data, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  server->_drainLogic();

  // Fund with 4095 -- should cap at 0x0FFF, not overflow into flag bits.
  rc = client->fundAsset(aid, 4095);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  server->_drainLogic();

  HashPrefix owner;
  AssetData content;
  uint16_t days = 0;
  uint32_t price = 0;
  rc = client->queryAsset(aid, owner, content, days, price);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_TEST_MESSAGE("Days after fund +4095: " << days);
  BOOST_CHECK(days <= 4095);
  BOOST_CHECK(days > 0);

  // Fund again -- should stay capped
  rc = client->fundAsset(aid, 4095);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  server->_drainLogic();

  rc = client->queryAsset(aid, owner, content, days, price);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_TEST_MESSAGE("Days after second fund +4095: " << days);
  BOOST_CHECK_EQUAL(days, 4095);  // capped at max
}

// --- Private assets ---

BOOST_AUTO_TEST_CASE(PrivateAssetUnsignedQueryHidesContent) {
  minx::Hash aid = makeHash("PRIV_TEST1");
  AssetData data;
  data.fill(0xAA);
  uint8_t rc = client->createAsset(aid, data, 30, true);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  server->_drainLogic();

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
  server->_drainLogic();

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
  server->_drainLogic();

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
  server->_drainLogic();

  // Create a second client with a different key
  KeyPair otherKey;
  server->_brr(otherKey.getPublicKeyAsHash(), 10'000'000'000);
  server->_drainLogic();

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
  server->_drainLogic();

  // Fund it
  rc = client->fundAsset(aid, 20);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  server->_drainLogic();

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
  server->_drainLogic();

  // Create a second client
  KeyPair otherKey;
  server->_brr(otherKey.getPublicKeyAsHash(), 10'000'000'000);
  server->_drainLogic();

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
  server->_drainLogic();

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
  server->_drainLogic();

  // Try full update — must fail with CES_ERROR_IMMUTABLE
  AssetData newData;
  newData.fill(0x22);
  rc = client->updateAsset(aid, getMyId(), newData, 0);
  CES_CHECK_RC_EQ(rc, CES_ERROR_IMMUTABLE);
  server->_drainLogic();

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
  server->_drainLogic();

  AssetData newData;
  newData.fill(0x44);
  rc = client->updateAssetFast(aid, newData);
  CES_CHECK_RC_EQ(rc, CES_ERROR_IMMUTABLE);
  server->_drainLogic();

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
  server->_drainLogic();

  // Set a price (owner unchanged, content unchanged) — should succeed.
  rc = client->updateAssetMeta(aid, getMyId(), 42);
  CES_CHECK_OK(rc);
  server->_drainLogic();

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
  server->_drainLogic();

  rc = client->fundAsset(aid, 100);
  CES_CHECK_OK(rc);
  server->_drainLogic();

  // Content still rejects update (IMMUTABLE bit preserved through funding).
  AssetData newData;
  newData.fill(0x99);
  rc = client->updateAsset(aid, getMyId(), newData, 0);
  CES_CHECK_RC_EQ(rc, CES_ERROR_IMMUTABLE);
  server->_drainLogic();
}

BOOST_AUTO_TEST_CASE(NonImmutableAssetCanBeUpdated) {
  // Sanity: assets created without --immutable are still updatable.
  minx::Hash aid = makeHash("NORMAL_UPDATE");
  AssetData data;
  data.fill(0xCC);
  uint8_t rc = client->createAsset(aid, data, 30); // default immutable=false
  CES_REQUIRE_OK(rc);
  server->_drainLogic();

  AssetData newData;
  newData.fill(0xDD);
  rc = client->updateAsset(aid, getMyId(), newData, 0);
  CES_CHECK_OK(rc);
  server->_drainLogic();

  HashPrefix owner;
  AssetData got;
  uint16_t days = 0;
  uint32_t price = 0;
  rc = client->queryAsset(aid, owner, got, days, price);
  CES_REQUIRE_OK(rc);
  BOOST_CHECK_EQUAL(got[0], 0xDD);
}

// --- Owner-pays (auto-fund) assets ---
// A custom server: feeAsset pinned, no account rent, discount off, so the daily
// auto-fund charge is exact. A well-funded payer bears the create cost while the
// owner account carries a controlled balance -- createAsset debits the origin,
// not the owner -- so the auto-fund path is fully deterministic.
struct AutoFundFixture {
  std::unique_ptr<CesServer> server;
  fs::path tempDir;
  KeyPair payer;

  AutoFundFixture() {
    blog::init();
    tempDir = makeUniqueTempDir("ces_autofund");
    minx::Hash sPriv; sPriv.fill(0xEE);
    CesConfig cfg =
      makeTestConfig(tempDir, sPriv, std::numeric_limits<uint64_t>::max());
    cfg.feeAsset = 1000;
    cfg.feeAccount = 0;
    cfg.feeTx = 0;
    cfg.feeQuery = 0;
    server = std::make_unique<CesServer>(cfg);
    server->start(0);
    server->_brr(payer.getPublicKeyAsHash(), 100'000'000'000LL);
    server->_drainLogic();
  }
  ~AutoFundFixture() {
    if (server) server->stop();
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }

  void fund(const minx::Hash& k, int64_t amt) {
    server->_brr(k, amt);
    server->_drainLogic();
  }
  int64_t bal(const minx::Hash& k) { return server->_balanceOf(k); }

  // Owner-pays (or plain) asset owned by ownerPfx; create cost billed to payer.
  uint8_t create(const HashPrefix& ownerPfx, const minx::Hash& aid,
                 uint16_t days, bool ownerPays) {
    AssetData c{};
    uint8_t rc = server->createAsset(
      payer.getPublicKeyAsHash(), ownerPfx, aid, c,
      assetBalance(days, false, false, false, ownerPays), 0);
    server->_drainLogic();
    return rc;
  }
  CesServer::AdminAsset qa(const minx::Hash& aid) {
    return server->_adminQueryAsset(aid);
  }
};

// Owner-pays asset at the floor: owner charged one feeAsset, asset held at 0
// days with the bit preserved.
BOOST_FIXTURE_TEST_CASE(OwnerPaysChargesOwnerAndSurvivesAtZeroDays, AutoFundFixture) {
  KeyPair b;
  HashPrefix bPfx = Account::getMapKey(b.getPublicKeyAsHash());
  fund(b.getPublicKeyAsHash(), 1'000'000);
  minx::Hash aid = makeHash("AUTOFUND_SURVIVE");
  CES_CHECK_OK(create(bPfx, aid, /*days=*/0, /*ownerPays=*/true));
  int64_t before = bal(b.getPublicKeyAsHash());
  server->_runDailyMaintenance();
  server->_drainLogic();
  BOOST_CHECK_EQUAL(bal(b.getPublicKeyAsHash()), before - 1000);  // charged feeAsset
  auto q = qa(aid);
  BOOST_CHECK(q.exists);
  BOOST_CHECK_EQUAL(ces::assetDays(q.balance), 0);          // held at 0 days
  BOOST_CHECK(ces::isAssetOwnerPays(q.balance));            // bit preserved
}

// Owner cannot afford the day: the asset dies and the owner is left untouched.
BOOST_FIXTURE_TEST_CASE(OwnerPaysDiesWhenOwnerCannotPay, AutoFundFixture) {
  KeyPair b;
  HashPrefix bPfx = Account::getMapKey(b.getPublicKeyAsHash());
  fund(b.getPublicKeyAsHash(), 500);          // < feeAsset (1000)
  minx::Hash aid = makeHash("AUTOFUND_BROKE");
  CES_CHECK_OK(create(bPfx, aid, 0, true));   // payer bears create cost; b stays 500
  server->_runDailyMaintenance();
  server->_drainLogic();
  BOOST_CHECK(!qa(aid).exists);               // owner cannot pay -> dies
  BOOST_CHECK_EQUAL(bal(b.getPublicKeyAsHash()), 500);  // owner untouched
}

// Owner account does not exist: the asset dies (no one to charge).
BOOST_FIXTURE_TEST_CASE(OwnerPaysDiesWhenOwnerGone, AutoFundFixture) {
  HashPrefix phantom{};
  phantom.fill(0xAB);                         // no account at this prefix
  minx::Hash aid = makeHash("AUTOFUND_GONE");
  CES_CHECK_OK(create(phantom, aid, 0, true));
  server->_runDailyMaintenance();
  server->_drainLogic();
  BOOST_CHECK(!qa(aid).exists);               // owner absent -> dies
}

// Without the bit, a floored asset dies as before and the owner is never billed.
BOOST_FIXTURE_TEST_CASE(NonOwnerPaysDiesAtFloor, AutoFundFixture) {
  KeyPair b;
  HashPrefix bPfx = Account::getMapKey(b.getPublicKeyAsHash());
  fund(b.getPublicKeyAsHash(), 1'000'000);
  minx::Hash aid = makeHash("AUTOFUND_PLAIN");
  CES_CHECK_OK(create(bPfx, aid, 0, /*ownerPays=*/false));
  int64_t before = bal(b.getPublicKeyAsHash());
  server->_runDailyMaintenance();
  server->_drainLogic();
  BOOST_CHECK(!qa(aid).exists);               // no owner-pays -> dies at floor
  BOOST_CHECK_EQUAL(bal(b.getPublicKeyAsHash()), before);  // owner not charged
}

// Prepaid days deplete first: while a buffer remains the owner is not billed and
// the bit rides through the decrement.
BOOST_FIXTURE_TEST_CASE(OwnerPaysBitPreservedWhilePrepaidRemains, AutoFundFixture) {
  KeyPair b;
  HashPrefix bPfx = Account::getMapKey(b.getPublicKeyAsHash());
  fund(b.getPublicKeyAsHash(), 1'000'000);
  minx::Hash aid = makeHash("AUTOFUND_BUFFER");
  CES_CHECK_OK(create(bPfx, aid, /*days=*/5, true));  // stored 6 days
  int64_t before = bal(b.getPublicKeyAsHash());
  server->_runDailyMaintenance();
  server->_drainLogic();
  auto q = qa(aid);
  BOOST_CHECK(q.exists);
  BOOST_CHECK_EQUAL(ces::assetDays(q.balance), 5);    // 6 -> 5 (prepaid depletes)
  BOOST_CHECK(ces::isAssetOwnerPays(q.balance));       // bit preserved
  BOOST_CHECK_EQUAL(bal(b.getPublicKeyAsHash()), before);  // owner not billed yet
}

// Owner flips the bit on an existing asset both ways; days and other flags ride
// through unchanged.
BOOST_FIXTURE_TEST_CASE(SetAssetOwnerPaysTogglesBit, AutoFundFixture) {
  KeyPair a;
  HashPrefix aPfx = Account::getMapKey(a.getPublicKeyAsHash());
  fund(a.getPublicKeyAsHash(), 10'000'000);        // owner account must exist
  minx::Hash aid = makeHash("FLIP_TOKEN");
  CES_CHECK_OK(create(aPfx, aid, /*days=*/30, /*ownerPays=*/false));  // plain
  BOOST_CHECK(!ces::isAssetOwnerPays(qa(aid).balance));

  BOOST_REQUIRE_EQUAL(
    server->setAssetOwnerPays(a.getPublicKeyAsHash(), aid, true, 0), CES_OK);
  server->_drainLogic();
  auto q = qa(aid);
  BOOST_CHECK(ces::isAssetOwnerPays(q.balance));            // on
  BOOST_CHECK_EQUAL(ces::assetDays(q.balance), 31);         // days preserved (30+1)

  BOOST_REQUIRE_EQUAL(
    server->setAssetOwnerPays(a.getPublicKeyAsHash(), aid, false, 0), CES_OK);
  server->_drainLogic();
  q = qa(aid);
  BOOST_CHECK(!ces::isAssetOwnerPays(q.balance));           // off
  BOOST_CHECK_EQUAL(ces::assetDays(q.balance), 31);         // still preserved
}

// Only the owner may flip it.
BOOST_FIXTURE_TEST_CASE(SetAssetOwnerPaysNonOwnerRejected, AutoFundFixture) {
  KeyPair a, other;
  HashPrefix aPfx = Account::getMapKey(a.getPublicKeyAsHash());
  fund(a.getPublicKeyAsHash(), 10'000'000);
  fund(other.getPublicKeyAsHash(), 10'000'000);   // non-owner signer must exist
  minx::Hash aid = makeHash("FLIP_AUTH");
  CES_CHECK_OK(create(aPfx, aid, 30, false));      // owned by a
  BOOST_CHECK_EQUAL(
    server->setAssetOwnerPays(other.getPublicKeyAsHash(), aid, true, 0),
    CES_ERROR_NOT_OWNER);
  server->_drainLogic();
  BOOST_CHECK(!ces::isAssetOwnerPays(qa(aid).balance));  // unchanged
}

// Time-warp: an owner-pays asset survives repeated daily passes, draining the
// owner one feeAsset per day. Flip it off and it dies on the very next pass --
// but the owner account lives on.
BOOST_FIXTURE_TEST_CASE(OwnerPaysDrainsOverDaysThenFlipOffKillsAssetNotAccount,
                        AutoFundFixture) {
  KeyPair b;
  HashPrefix bPfx = Account::getMapKey(b.getPublicKeyAsHash());
  fund(b.getPublicKeyAsHash(), 100'000);
  minx::Hash aid = makeHash("TIMEWARP");
  CES_CHECK_OK(create(bPfx, aid, /*days=*/0, /*ownerPays=*/true));  // stored at 1 day
  int64_t start = bal(b.getPublicKeyAsHash());

  // Three daily passes: owner drained one feeAsset each; asset held at 0 days.
  for (int i = 0; i < 3; ++i) {
    server->_runDailyMaintenance();
    server->_drainLogic();
    BOOST_REQUIRE(qa(aid).exists);
  }
  BOOST_CHECK_EQUAL(bal(b.getPublicKeyAsHash()), start - 3000);  // 3 x feeAsset
  BOOST_CHECK(ces::isAssetOwnerPays(qa(aid).balance));

  // Turn auto-fund off: now a plain asset sitting at 0 days.
  BOOST_REQUIRE_EQUAL(
    server->setAssetOwnerPays(b.getPublicKeyAsHash(), aid, false, 0), CES_OK);
  server->_drainLogic();
  int64_t afterFlip = bal(b.getPublicKeyAsHash());

  // One more pass: the asset dies; the owner account survives, uncharged.
  server->_runDailyMaintenance();
  server->_drainLogic();
  BOOST_CHECK(!qa(aid).exists);                                  // asset gone
  BOOST_CHECK(server->_accountExists(b.getPublicKeyAsHash()));   // account lives
  BOOST_CHECK_EQUAL(bal(b.getPublicKeyAsHash()), afterFlip);     // not charged
}

// CES_CREATE_ASSET_RANGE: the client picks a prefix and creates N account-owned
// cells atomically. All exist and share the client's ownership; cell 0 carries
// N; cell N does not exist (bounded). Re-claiming the prefix collides; count 0
// is rejected. Small indices keep the native LE index in the low byte.
BOOST_FIXTURE_TEST_CASE(CreateAssetRange, CesFixture) {
  const uint32_t N = 4;
  minx::Hash firstKey{};
  for (int i = 0; i < 24; ++i) firstKey[i] = static_cast<uint8_t>(0x40 + i);

  BOOST_REQUIRE_EQUAL(client->createAssetRange(firstKey, N, 30), CES_OK);

  HashPrefix me = getMyId();
  for (uint32_t i = 0; i < N; ++i) {
    minx::Hash key = firstKey;
    key[24] = static_cast<uint8_t>(i);   // i < 256, so the low index byte
    HashPrefix owner{};
    AssetData content{};
    uint16_t bal = 0;
    uint32_t price = 0;
    BOOST_REQUIRE_EQUAL(client->queryAsset(key, owner, content, bal, price),
                        CES_OK);
    BOOST_CHECK(owner == me);
    if (i == 0) BOOST_CHECK_EQUAL(content[0], static_cast<uint8_t>(N));
  }

  // cell N was never created: the range is exactly N wide.
  {
    minx::Hash key = firstKey;
    key[24] = static_cast<uint8_t>(N);
    HashPrefix owner{};
    AssetData content{};
    uint16_t bal = 0;
    uint32_t price = 0;
    client->queryAsset(key, owner, content, bal, price);
    BOOST_CHECK(!(owner == me));
  }

  // Re-claiming the same prefix collides.
  BOOST_CHECK_EQUAL(client->createAssetRange(firstKey, N, 30),
                    static_cast<uint8_t>(CES_ERROR_ASSET_EXISTS));

  // Count 0 is rejected.
  minx::Hash fk2{};
  for (int i = 0; i < 24; ++i) fk2[i] = static_cast<uint8_t>(0x90 + i);
  BOOST_CHECK_EQUAL(client->createAssetRange(fk2, 0, 30),
                    static_cast<uint8_t>(CES_ERROR_BAD_INPUT));
}

BOOST_AUTO_TEST_SUITE_END()
