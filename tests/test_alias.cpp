// Alias ledger ops: patch write (upsert on own alias) / windowed query /
// delete, the id generator, id-stability across edits, delete-to-rotate, the
// editor grant (content-only patch floor), patch bounds, the store cap, and
// daily rent (charge + reclaim). Direct server methods (like transfer),
// nonce-skip (reqNonce=0). Fees are pinned so charges are exact.

#include "test_common.h"

#include <ces/account.h>
#include <ces/alias.h>
#include <ces/types.h>

#include <cstring>
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
    cfg.feeAccount = feeAccount;   // alias rent derives from this (x16)
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

  ces::Bytes str(const std::string& s) {
    ces::Bytes b;
    b.assign(s.begin(), s.end());
    return b;
  }

  uint8_t patchAlias(const minx::Hash& k, uint32_t aliasId, uint16_t offset,
                     const ces::Bytes& bytes, uint32_t& outId) {
    uint8_t rc = server->setAlias(k, aliasId, offset, bytes, 0, outId);
    server->_drainLogic();
    return rc;
  }
  // Convenience: write op + content in one patch on the signer's own alias
  // (op is host-endian in the image; LE on all supported targets).
  uint8_t setAlias(const minx::Hash& k, uint16_t op, const ces::Bytes& content,
                   uint32_t& outId) {
    ces::Bytes b(2 + content.size());
    std::memcpy(b.data(), &op, sizeof(op));
    std::memcpy(b.data() + 2, content.data(), content.size());
    return patchAlias(k, 0, ces::ALIAS_OFF_OP, b, outId);
  }
  uint8_t deleteAlias(const minx::Hash& k) {
    uint8_t rc = server->deleteAlias(k, 0);
    server->_drainLogic();
    return rc;
  }
  ces::HashPrefix pfx(KeyPair& kp) {
    return ces::Account::getMapKey(kp.getPublicKeyAsHash());
  }
  ces::Bytes pfxBytes(KeyPair& kp) {
    ces::HashPrefix p = pfx(kp);
    ces::Bytes b;
    b.assign(p.begin(), p.end());
    return b;
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
  // one day of alias rent = feeAccount(1000) x ALIAS_BYTES/ACCOUNT_BYTES(16).
  BOOST_CHECK_EQUAL(bal(a.getPublicKeyAsHash()), before - 16000);
}

BOOST_FIXTURE_TEST_CASE(DailyRentChargesOwner, AliasRentFixture) {
  KeyPair a;
  fund(a.getPublicKeyAsHash(), 1'000'000);
  uint32_t id = 0;
  CES_CHECK_OK(setAlias(a.getPublicKeyAsHash(), ces::ALIAS_OP_STRING, str("x"), id));
  int64_t before = bal(a.getPublicKeyAsHash());
  server->_runDailyMaintenance();
  server->_drainLogic();
  // account rent (1000) + alias rent (16000) = 17000.
  BOOST_CHECK_EQUAL(bal(a.getPublicKeyAsHash()), before - 17000);
  ces::Alias out;
  BOOST_CHECK(server->queryAlias(id, out));   // still alive
  BOOST_CHECK_EQUAL(aliasIdOf(a.getPublicKeyAsHash()), id);
}

BOOST_FIXTURE_TEST_CASE(DailyRentReclaimsWhenOwnerCannotPay, AliasRentFixture) {
  KeyPair a;
  fund(a.getPublicKeyAsHash(), 17500);
  uint32_t id = 0;
  CES_CHECK_OK(setAlias(a.getPublicKeyAsHash(), ces::ALIAS_OP_STRING, str("x"), id));
  BOOST_CHECK_EQUAL(bal(a.getPublicKeyAsHash()), 1500);   // set charged 16000
  server->_runDailyMaintenance();
  server->_drainLogic();
  // account rent 1000 -> 500 (survives); alias rent 16000 > 500 -> reclaimed.
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
  fund(a.getPublicKeyAsHash(), 16500);
  uint32_t id = 0;
  CES_CHECK_OK(setAlias(a.getPublicKeyAsHash(), ces::ALIAS_OP_STRING, str("x"), id));
  BOOST_CHECK_EQUAL(bal(a.getPublicKeyAsHash()), 500);   // set charged 16000
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
// Pins id-stability across a wire patch, the windowed read (skip-the-header
// pattern), and out-of-bounds window rejection.
BOOST_FIXTURE_TEST_CASE(OverTheWireWriteReadDelete, CesFixture) {
  const std::string s = "wire test";
  ces::Bytes content;
  content.assign(s.begin(), s.end());

  uint32_t id = 0;
  CES_REQUIRE_OK(client->writeAlias(0, ces::ALIAS_OFF_CONTENT, content, id));
  BOOST_CHECK(id > 0);

  // Windowed read of the content only (header skipped).
  ces::Bytes out;
  bool found = false;
  CES_REQUIRE_OK(client->readAlias(id, ces::ALIAS_OFF_CONTENT,
                                   static_cast<uint16_t>(content.size()),
                                   out, found));
  BOOST_CHECK(found);
  BOOST_REQUIRE_EQUAL(out.size(), content.size());
  BOOST_CHECK_EQUAL(out[0], static_cast<uint8_t>('w'));

  // Patch a single byte in place; the id is stable.
  ces::Bytes one;
  one.push_back('W');
  uint32_t id2 = 0;
  CES_CHECK_OK(client->writeAlias(0, ces::ALIAS_OFF_CONTENT, one, id2));
  BOOST_CHECK_EQUAL(id2, id);
  CES_REQUIRE_OK(client->readAlias(id, ces::ALIAS_OFF_CONTENT, 1, out, found));
  BOOST_CHECK(found);
  BOOST_REQUIRE_EQUAL(out.size(), 1u);
  BOOST_CHECK_EQUAL(out[0], static_cast<uint8_t>('W'));

  // An out-of-bounds window reads as not-found.
  CES_REQUIRE_OK(client->readAlias(id, ces::ALIAS_VALUE_BYTES - 1, 2, out, found));
  BOOST_CHECK(!found);

  CES_CHECK_OK(client->deleteAlias());
  CES_REQUIRE_OK(client->readAlias(id, 0, 1, out, found));
  BOOST_CHECK(!found);
}

// Owner grants an editor by patching the editor field; the editor may then
// patch content on the owner's cell, but never the header, and a stranger may
// not patch at all.
BOOST_FIXTURE_TEST_CASE(EditorGrantAndPatchFloors, AliasFixture) {
  KeyPair a, b, c;
  fund(a.getPublicKeyAsHash(), 1'000'000);
  fund(b.getPublicKeyAsHash(), 1'000'000);
  fund(c.getPublicKeyAsHash(), 1'000'000);

  uint32_t id = 0;
  CES_CHECK_OK(setAlias(a.getPublicKeyAsHash(), ces::ALIAS_OP_NONE,
                        str("owner data"), id));

  // Grant B: owner patches the editor field.
  uint32_t idEdit = 0;
  CES_CHECK_OK(patchAlias(a.getPublicKeyAsHash(), 0, ces::ALIAS_OFF_EDITOR,
                          pfxBytes(b), idEdit));
  BOOST_CHECK_EQUAL(idEdit, id);

  // B patches content on A's cell by id.
  uint32_t idB = 0;
  CES_CHECK_OK(patchAlias(b.getPublicKeyAsHash(), id, ces::ALIAS_OFF_CONTENT,
                          str("from B"), idB));
  BOOST_CHECK_EQUAL(idB, id);
  ces::Alias out;
  BOOST_CHECK(server->queryAlias(id, out));
  BOOST_CHECK_EQUAL(out.getContent()[0], static_cast<uint8_t>('f'));
  BOOST_CHECK(out.getOwner() == pfx(a));      // header untouched
  BOOST_CHECK(out.getEditor() == pfx(b));

  // B may not touch the header: editor, op, or the last header byte.
  CES_CHECK_RC_EQ(patchAlias(b.getPublicKeyAsHash(), id, ces::ALIAS_OFF_EDITOR,
                             pfxBytes(b), idB), CES_ERROR_NOT_OWNER);
  CES_CHECK_RC_EQ(patchAlias(b.getPublicKeyAsHash(), id, ces::ALIAS_OFF_OP,
                             str("xx"), idB), CES_ERROR_NOT_OWNER);
  CES_CHECK_RC_EQ(patchAlias(b.getPublicKeyAsHash(), id,
                             ces::ALIAS_OFF_CONTENT - 1, str("x"), idB),
                  CES_ERROR_NOT_OWNER);

  // A stranger may not patch at all.
  CES_CHECK_RC_EQ(patchAlias(c.getPublicKeyAsHash(), id, ces::ALIAS_OFF_CONTENT,
                             str("intruder"), idB), CES_ERROR_NOT_OWNER);

  // Owner revokes: zero the editor field; B loses write access.
  ces::Bytes zero(sizeof(ces::HashPrefix), 0);
  CES_CHECK_OK(patchAlias(a.getPublicKeyAsHash(), 0, ces::ALIAS_OFF_EDITOR,
                          zero, idEdit));
  CES_CHECK_RC_EQ(patchAlias(b.getPublicKeyAsHash(), id, ces::ALIAS_OFF_CONTENT,
                             str("late"), idB), CES_ERROR_NOT_OWNER);
}

// Patch bounds: nobody writes the owner field, and no patch may run past the
// end of the value image. An editor grant does not create cells: patching a
// dead id fails.
BOOST_FIXTURE_TEST_CASE(PatchBoundsAndTargets, AliasFixture) {
  KeyPair a;
  fund(a.getPublicKeyAsHash(), 1'000'000);
  uint32_t id = 0;

  // Owner field is server-set; offset 0 rejects even for the owner.
  CES_CHECK_RC_EQ(patchAlias(a.getPublicKeyAsHash(), 0, ces::ALIAS_OFF_OWNER,
                             str("xxxxxxxx"), id), CES_ERROR_BAD_INPUT);

  // Past-the-end rejects whole.
  CES_CHECK_RC_EQ(patchAlias(a.getPublicKeyAsHash(), 0,
                             ces::ALIAS_VALUE_BYTES - 1, str("xy"), id),
                  CES_ERROR_BAD_INPUT);

  // A nonzero target must exist.
  CES_CHECK_RC_EQ(patchAlias(a.getPublicKeyAsHash(), 999999,
                             ces::ALIAS_OFF_CONTENT, str("x"), id),
                  CES_ERROR_ALIAS_NOT_FOUND);

  // A partial patch preserves the rest of the image.
  CES_CHECK_OK(setAlias(a.getPublicKeyAsHash(), ces::ALIAS_OP_STRING,
                        str("abcdef"), id));
  ces::Bytes mid;
  mid.push_back('X');
  uint32_t id2 = 0;
  CES_CHECK_OK(patchAlias(a.getPublicKeyAsHash(), 0,
                          ces::ALIAS_OFF_CONTENT + 2, mid, id2));
  BOOST_CHECK_EQUAL(id2, id);
  ces::Alias out;
  BOOST_CHECK(server->queryAlias(id, out));
  BOOST_CHECK_EQUAL(out.getOp(), ces::ALIAS_OP_STRING);   // op preserved
  BOOST_CHECK_EQUAL(out.getContent()[0], static_cast<uint8_t>('a'));
  BOOST_CHECK_EQUAL(out.getContent()[1], static_cast<uint8_t>('b'));
  BOOST_CHECK_EQUAL(out.getContent()[2], static_cast<uint8_t>('X'));
  BOOST_CHECK_EQUAL(out.getContent()[3], static_cast<uint8_t>('d'));
}

BOOST_AUTO_TEST_SUITE_END()
