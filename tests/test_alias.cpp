// Alias ledger ops: set (upsert) / query / delete, the id generator,
// id-stability across edits, delete-to-rotate, the store cap, and daily rent
// (charge + reclaim). Direct server methods (like transfer), nonce-skip
// (reqNonce=0). Fees are pinned so charges are exact.

#include "test_common.h"

#include <ces/account.h>
#include <ces/alias.h>
#include <ces/types.h>

#include <string>
#include <vector>

BOOST_AUTO_TEST_SUITE(AliasTests)

namespace {

struct AliasFixtureBase {
  std::unique_ptr<CesServer> server;
  fs::path tempDir;
  uint16_t serverPort;

  void boot(uint64_t feeAccount, uint64_t feeQuery, uint64_t maxAlias) {
    blog::init();
    tempDir = makeUniqueTempDir("ces_alias");
    minx::Hash serverPriv;
    serverPriv.fill(0xEE);
    CesConfig cfg =
      makeTestConfig(tempDir, serverPriv, std::numeric_limits<uint64_t>::max());
    cfg.feeAccount = feeAccount;
    cfg.feeQuery = feeQuery;
    cfg.feeTx = 0;
    cfg.feeAsset = 0;
    cfg.maxAlias = maxAlias;
    server = std::make_unique<CesServer>(cfg);
    serverPort = server->start(0);
    BOOST_REQUIRE(serverPort > 0);
  }

  ~AliasFixtureBase() {
    if (server) server->stop();
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }

  void fund(const minx::Hash& k, int64_t amt) {
    server->_brr(k, amt);
    server->_drainLogic();
  }
  int64_t bal(const minx::Hash& k) { return server->_balanceOf(k); }
  uint32_t aliasIdOf(const minx::Hash& k) { return server->_aliasIdOf(k); }

  ces::AliasData str(const std::string& s) {
    ces::AliasData d{};
    for (std::size_t i = 0; i < s.size() && i < d.size(); ++i)
      d[i] = static_cast<uint8_t>(s[i]);
    return d;
  }

  uint8_t setAlias(const minx::Hash& k, uint16_t op, const ces::AliasData& c,
                   uint32_t& outId) {
    uint8_t rc = server->setAlias(k, op, c, 0, outId);
    server->_drainLogic();
    return rc;
  }
  uint8_t deleteAlias(const minx::Hash& k) {
    uint8_t rc = server->deleteAlias(k, 0);
    server->_drainLogic();
    return rc;
  }
};

struct AliasFixture : AliasFixtureBase {
  AliasFixture() { boot(/*feeAccount=*/0, /*feeQuery=*/0, /*maxAlias=*/1000); }
};

struct AliasRentFixture : AliasFixtureBase {
  AliasRentFixture() { boot(/*feeAccount=*/1000, /*feeQuery=*/0, /*maxAlias=*/1000); }
};

struct AliasCapFixture : AliasFixtureBase {
  AliasCapFixture() { boot(/*feeAccount=*/0, /*feeQuery=*/0, /*maxAlias=*/2); }
};

}  // namespace

BOOST_FIXTURE_TEST_CASE(SetOnFreshAllocatesAndReadsBack, AliasFixture) {
  KeyPair a;
  fund(a.getPublicKeyAsHash(), 1'000'000);
  uint32_t id = 0;
  CES_CHECK_OK(setAlias(a.getPublicKeyAsHash(), ces::ALIAS_OP_STRING,
                        str("hello shop"), id));
  BOOST_CHECK(id > 0);
  BOOST_CHECK_EQUAL(aliasIdOf(a.getPublicKeyAsHash()), id);

  ces::Alias out;
  BOOST_CHECK(server->queryAlias(id, out));
  BOOST_CHECK_EQUAL(out.getOp(), ces::ALIAS_OP_STRING);
  BOOST_CHECK(out.getOwner() ==
              ces::Account::getMapKey(a.getPublicKeyAsHash()));
  BOOST_CHECK_EQUAL(out.getContent()[0], static_cast<uint8_t>('h'));
}

// The core upsert property: setting again keeps the same id and overwrites op
// and content in place (a dependable id survives edits).
BOOST_FIXTURE_TEST_CASE(SetKeepsIdAndOverwrites, AliasFixture) {
  KeyPair a;
  fund(a.getPublicKeyAsHash(), 1'000'000);
  uint32_t id1 = 0, id2 = 0;
  CES_CHECK_OK(setAlias(a.getPublicKeyAsHash(), ces::ALIAS_OP_STRING, str("one"), id1));
  CES_CHECK_OK(setAlias(a.getPublicKeyAsHash(), ces::ALIAS_OP_NONE, str("two"), id2));
  BOOST_CHECK_EQUAL(id2, id1);                                // same id kept
  BOOST_CHECK_EQUAL(aliasIdOf(a.getPublicKeyAsHash()), id1);

  ces::Alias out;
  BOOST_CHECK(server->queryAlias(id1, out));                  // one cell, still live
  BOOST_CHECK_EQUAL(out.getOp(), ces::ALIAS_OP_NONE);         // op overwritten
  BOOST_CHECK_EQUAL(out.getContent()[0], static_cast<uint8_t>('t'));  // content overwritten
}

// Delete is the only way to drop / rotate the id: after delete, a fresh set
// allocates a new id.
BOOST_FIXTURE_TEST_CASE(DeleteThenSetMintsNewId, AliasFixture) {
  KeyPair a;
  fund(a.getPublicKeyAsHash(), 1'000'000);
  uint32_t id1 = 0, id2 = 0;
  CES_CHECK_OK(setAlias(a.getPublicKeyAsHash(), ces::ALIAS_OP_STRING, str("one"), id1));
  CES_CHECK_OK(deleteAlias(a.getPublicKeyAsHash()));
  BOOST_CHECK_EQUAL(aliasIdOf(a.getPublicKeyAsHash()), 0u);
  CES_CHECK_OK(setAlias(a.getPublicKeyAsHash(), ces::ALIAS_OP_STRING, str("two"), id2));
  BOOST_CHECK(id2 != id1);                                    // delete rotated the id
  BOOST_CHECK_EQUAL(aliasIdOf(a.getPublicKeyAsHash()), id2);
  ces::Alias out;
  BOOST_CHECK(!server->queryAlias(id1, out));                 // old cell gone
  BOOST_CHECK(server->queryAlias(id2, out));                  // new cell lives
}

BOOST_FIXTURE_TEST_CASE(DeleteClearsLink, AliasFixture) {
  KeyPair a;
  fund(a.getPublicKeyAsHash(), 1'000'000);
  uint32_t id = 0;
  CES_CHECK_OK(setAlias(a.getPublicKeyAsHash(), ces::ALIAS_OP_STRING, str("x"), id));
  CES_CHECK_OK(deleteAlias(a.getPublicKeyAsHash()));
  BOOST_CHECK_EQUAL(aliasIdOf(a.getPublicKeyAsHash()), 0u);
  ces::Alias out;
  BOOST_CHECK(!server->queryAlias(id, out));
}

BOOST_FIXTURE_TEST_CASE(DeleteWithoutAliasFails, AliasFixture) {
  KeyPair a;
  fund(a.getPublicKeyAsHash(), 1'000'000);
  CES_CHECK_RC_EQ(deleteAlias(a.getPublicKeyAsHash()), CES_ERROR_ALIAS_NOT_FOUND);
}

BOOST_FIXTURE_TEST_CASE(IdsDistinctAcrossAccounts, AliasFixture) {
  std::vector<uint32_t> ids;
  for (int i = 0; i < 5; ++i) {
    KeyPair a;
    fund(a.getPublicKeyAsHash(), 1'000'000);
    uint32_t id = 0;
    CES_CHECK_OK(setAlias(a.getPublicKeyAsHash(), ces::ALIAS_OP_STRING, str("x"), id));
    BOOST_CHECK(id != 0);
    for (uint32_t prev : ids) BOOST_CHECK(id != prev);
    ids.push_back(id);
  }
}

BOOST_FIXTURE_TEST_CASE(QueryUnknownAndGeneratorReturnFalse, AliasFixture) {
  ces::Alias out;
  BOOST_CHECK(!server->queryAlias(0, out));        // generator cell
  BOOST_CHECK(!server->queryAlias(999999, out));   // never allocated
}

// Generator forced onto a live id: it must skip the occupied slot.
BOOST_FIXTURE_TEST_CASE(GeneratorSkipsOccupiedId, AliasFixture) {
  KeyPair a, b;
  fund(a.getPublicKeyAsHash(), 1'000'000);
  fund(b.getPublicKeyAsHash(), 1'000'000);
  uint32_t idA = 0;
  CES_CHECK_OK(setAlias(a.getPublicKeyAsHash(), ces::ALIAS_OP_STRING, str("a"), idA));

  server->_setAliasNextId(idA);   // point next-id back at A's live slot
  uint32_t idB = 0;
  CES_CHECK_OK(setAlias(b.getPublicKeyAsHash(), ces::ALIAS_OP_STRING, str("b"), idB));
  BOOST_CHECK(idB != idA);        // skipped the occupied slot
  BOOST_CHECK(idB != 0);          // and never hands out the generator cell

  ces::Alias out;
  BOOST_CHECK(server->queryAlias(idA, out));   // A untouched
  BOOST_CHECK(server->queryAlias(idB, out));   // B distinct and live
}

// Generator forced to the 32-bit ceiling: it allocates UINT32_MAX, then wraps
// to 1 (skipping id 0 and the now-occupied ceiling).
BOOST_FIXTURE_TEST_CASE(GeneratorWrapsPastCeiling, AliasFixture) {
  KeyPair a, b;
  fund(a.getPublicKeyAsHash(), 1'000'000);
  fund(b.getPublicKeyAsHash(), 1'000'000);

  server->_setAliasNextId(UINT32_MAX);
  uint32_t idMax = 0;
  CES_CHECK_OK(setAlias(a.getPublicKeyAsHash(), ces::ALIAS_OP_STRING, str("a"), idMax));
  BOOST_CHECK_EQUAL(idMax, UINT32_MAX);   // allocated the ceiling id

  uint32_t idWrap = 0;
  CES_CHECK_OK(setAlias(b.getPublicKeyAsHash(), ces::ALIAS_OP_STRING, str("b"), idWrap));
  BOOST_CHECK(idWrap != 0);               // wrapped past id 0
  BOOST_CHECK(idWrap != UINT32_MAX);      // and past the occupied ceiling
  BOOST_CHECK_EQUAL(idWrap, 1u);          // wraps to 1
}

// Next-id of 0 is normalized to 1: id 0 is the generator cell, never handed out.
BOOST_FIXTURE_TEST_CASE(GeneratorNeverAllocatesZero, AliasFixture) {
  KeyPair a;
  fund(a.getPublicKeyAsHash(), 1'000'000);
  server->_setAliasNextId(0);
  uint32_t id = 0;
  CES_CHECK_OK(setAlias(a.getPublicKeyAsHash(), ces::ALIAS_OP_STRING, str("a"), id));
  BOOST_CHECK_EQUAL(id, 1u);
}

BOOST_FIXTURE_TEST_CASE(StoreFullRejects, AliasCapFixture) {
  // maxAlias=2: the generator cell + one alias fill it; the next allocate fails.
  KeyPair a, b;
  fund(a.getPublicKeyAsHash(), 1'000'000);
  fund(b.getPublicKeyAsHash(), 1'000'000);
  uint32_t id = 0;
  CES_CHECK_OK(setAlias(a.getPublicKeyAsHash(), ces::ALIAS_OP_STRING, str("x"), id));
  CES_CHECK_RC_EQ(setAlias(b.getPublicKeyAsHash(), ces::ALIAS_OP_STRING, str("y"), id),
                  CES_ERROR_INTERNAL);
}

// Editing in place does not consume a new slot: with the store full, a second
// set on the SAME account (which edits, not allocates) still succeeds.
BOOST_FIXTURE_TEST_CASE(EditInPlaceDoesNotHitCap, AliasCapFixture) {
  KeyPair a;
  fund(a.getPublicKeyAsHash(), 1'000'000);
  uint32_t id1 = 0, id2 = 0;
  CES_CHECK_OK(setAlias(a.getPublicKeyAsHash(), ces::ALIAS_OP_STRING, str("x"), id1));
  CES_CHECK_OK(setAlias(a.getPublicKeyAsHash(), ces::ALIAS_OP_STRING, str("y"), id2));
  BOOST_CHECK_EQUAL(id2, id1);   // edit in place, no new slot needed
}

BOOST_FIXTURE_TEST_CASE(SetChargesOneDay, AliasRentFixture) {
  KeyPair a;
  fund(a.getPublicKeyAsHash(), 1'000'000);
  int64_t before = bal(a.getPublicKeyAsHash());
  uint32_t id = 0;
  CES_CHECK_OK(setAlias(a.getPublicKeyAsHash(), ces::ALIAS_OP_STRING, str("x"), id));
  BOOST_CHECK_EQUAL(bal(a.getPublicKeyAsHash()), before - 1000);   // one day = feeAccount
}

BOOST_FIXTURE_TEST_CASE(DailyRentChargesOwner, AliasRentFixture) {
  KeyPair a;
  fund(a.getPublicKeyAsHash(), 1'000'000);
  uint32_t id = 0;
  CES_CHECK_OK(setAlias(a.getPublicKeyAsHash(), ces::ALIAS_OP_STRING, str("x"), id));
  int64_t before = bal(a.getPublicKeyAsHash());
  server->_runDailyMaintenance();
  server->_drainLogic();
  // account rent (1000) + alias rent (1000) = 2000.
  BOOST_CHECK_EQUAL(bal(a.getPublicKeyAsHash()), before - 2000);
  ces::Alias out;
  BOOST_CHECK(server->queryAlias(id, out));   // still alive
  BOOST_CHECK_EQUAL(aliasIdOf(a.getPublicKeyAsHash()), id);
}

BOOST_FIXTURE_TEST_CASE(DailyRentReclaimsWhenOwnerCannotPay, AliasRentFixture) {
  KeyPair a;
  fund(a.getPublicKeyAsHash(), 2500);
  uint32_t id = 0;
  CES_CHECK_OK(setAlias(a.getPublicKeyAsHash(), ces::ALIAS_OP_STRING, str("x"), id));
  BOOST_CHECK_EQUAL(bal(a.getPublicKeyAsHash()), 1500);   // set charged 1000
  server->_runDailyMaintenance();
  server->_drainLogic();
  // account rent 1000 -> 500 (survives); alias rent 1000 > 500 -> reclaimed.
  BOOST_CHECK(server->_accountExists(a.getPublicKeyAsHash()));
  BOOST_CHECK_EQUAL(bal(a.getPublicKeyAsHash()), 500);
  ces::Alias out;
  BOOST_CHECK(!server->queryAlias(id, out));                    // reclaimed
  BOOST_CHECK_EQUAL(aliasIdOf(a.getPublicKeyAsHash()), 0u);     // link cleared
}

// Owner account deleted (not just broke): the alias sweep runs after the
// account sweep in the same daily pass, finds the owner gone, and reclaims the
// orphan via the owner-gone branch (distinct from the cannot-pay branch above).
BOOST_FIXTURE_TEST_CASE(DailyRentReclaimsWhenOwnerAccountGone, AliasRentFixture) {
  KeyPair a;
  fund(a.getPublicKeyAsHash(), 1500);
  uint32_t id = 0;
  CES_CHECK_OK(setAlias(a.getPublicKeyAsHash(), ces::ALIAS_OP_STRING, str("x"), id));
  BOOST_CHECK_EQUAL(bal(a.getPublicKeyAsHash()), 500);   // set charged 1000
  server->_runDailyMaintenance();
  server->_drainLogic();
  // Account rent 1000 > A's 500 -> A deleted in the account sweep; the later
  // alias sweep sees the owner gone and reclaims the orphaned alias.
  BOOST_CHECK(!server->_accountExists(a.getPublicKeyAsHash()));
  ces::Alias out;
  BOOST_CHECK(!server->queryAlias(id, out));
}

// Full wire path: client SDK -> protocol -> server dispatch -> result, over the
// real UDP transport (CesFixture: funded client + live server, PoW diff 1).
// Also pins id-stability across a wire edit.
BOOST_FIXTURE_TEST_CASE(OverTheWireSetQueryDelete, CesFixture) {
  ces::AliasData content{};
  const char* s = "wire test";
  for (std::size_t i = 0; s[i]; ++i)
    content[i] = static_cast<uint8_t>(s[i]);

  uint32_t id = 0;
  CES_REQUIRE_OK(client->setAlias(ces::ALIAS_OP_STRING, content, id));   // allocate
  BOOST_CHECK(id > 0);

  HashPrefix owner{};
  uint16_t op = 0;
  ces::AliasData out{};
  bool found = false;
  CES_REQUIRE_OK(client->queryAlias(id, owner, op, out, found));
  BOOST_CHECK(found);
  BOOST_CHECK_EQUAL(op, ces::ALIAS_OP_STRING);
  BOOST_CHECK_EQUAL(out[0], static_cast<uint8_t>('w'));

  uint32_t id2 = 0;
  CES_CHECK_OK(client->setAlias(ces::ALIAS_OP_NONE, content, id2));       // edit in place
  BOOST_CHECK_EQUAL(id2, id);                                             // id stable
  CES_REQUIRE_OK(client->queryAlias(id, owner, op, out, found));
  BOOST_CHECK(found);
  BOOST_CHECK_EQUAL(op, ces::ALIAS_OP_NONE);

  CES_CHECK_OK(client->deleteAlias());
  CES_REQUIRE_OK(client->queryAlias(id, owner, op, out, found));
  BOOST_CHECK(!found);
}

BOOST_AUTO_TEST_SUITE_END()
