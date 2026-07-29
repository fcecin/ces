// key_names: the crypto-owned local name registry. Two layers:
//  - KeyNames wrapper: forward store + derived reverse index, uniqueness,
//    rename, clear, and the reverse index REBUILT FROM DISK on reload
//    (snapshot == replay for the derived map).
//  - Full round-trip through CesClient/CesServer: register/query/clear and
//    a second key rejected on a taken name.

#include "test_common.h"

#include <ces/keynames.h>

#include <boost/test/unit_test.hpp>

using namespace ces;

namespace {
KeyNameData nd(const char* s) {
  KeyNameData d{};
  for (size_t i = 0; s[i] && i < d.size(); ++i)
    d[i] = static_cast<uint8_t>(s[i]);
  return d;
}
Hash keyOf(uint8_t fill) {
  Hash h{};
  h.fill(fill);
  return h;
}
ces::Bytes nb(const char* s) {
  ces::Bytes b;
  for (size_t i = 0; s[i]; ++i) b.push_back(static_cast<uint8_t>(s[i]));
  return b;
}
}  // namespace

BOOST_AUTO_TEST_SUITE(KeyNameTests)

// --- wrapper-level: normalization, validity, uniqueness, rename, clear ---

BOOST_AUTO_TEST_CASE(NormalizeAndValidate) {
  // Spaces and underscores are the same char; boundary ones are stripped.
  BOOST_CHECK(KeyNames::normalize(nd("Ada Lovelace")) == nd("Ada_Lovelace"));
  BOOST_CHECK(KeyNames::normalize(nd("_Ada_")) == nd("Ada"));      // trim '_'
  BOOST_CHECK(KeyNames::normalize(nd("  hi  ")) == nd("hi"));      // trim space
  BOOST_CHECK(KeyNames::normalize(nd("snake_case")) == nd("snake_case"));
  // Space form and underscore form normalize to the SAME key (they collide).
  BOOST_CHECK(KeyNames::normalize(nd("a b")) == KeyNames::normalize(nd("a_b")));
  BOOST_CHECK(KeyNames::normalize(nd("a b")) == nd("a_b"));
  // validName is checked on the normalized form.
  BOOST_CHECK(KeyNames::validName(nd("fabiana")));
  BOOST_CHECK(KeyNames::validName(KeyNames::normalize(nd("Ada Lovelace"))));
  BOOST_CHECK(KeyNames::validName(nd("fcecin_42")));
  BOOST_CHECK(!KeyNames::validName(nd("")));               // empty
  BOOST_CHECK(!KeyNames::validName(nd("a/b")));            // path breaker
  BOOST_CHECK(!KeyNames::validName(nd("a:b")));
  BOOST_CHECK(!KeyNames::validName(nd("_hidden")));        // leading underscore
  BOOST_CHECK(!KeyNames::validName(nd(".dot")));           // leading dot
  BOOST_CHECK(!KeyNames::validName(nd("-opt")));           // leading dash
}

BOOST_AUTO_TEST_CASE(UniquenessRenameClear) {
  auto dir = makeUniqueTempDir("kn_unit");
  {
    KeyNames kn(dir.string(), 1024, std::numeric_limits<uint64_t>::max());
    const Hash a = keyOf(0xA1), b = keyOf(0xB2);

    BOOST_CHECK(kn.registerName(a, nd("fabiana"), 0) ==
                KeyNames::RegisterResult::Ok);
    // A second key cannot take it (either spelling, via normalization).
    BOOST_CHECK(kn.registerName(b, nd("fabiana"), 0) ==
                KeyNames::RegisterResult::NameTaken);
    BOOST_CHECK(kn.registerName(b, nd("fabiana"), 0) ==  // underscore form
                KeyNames::RegisterResult::NameTaken);

    // Round-trip resolves both ways.
    Hash outKey{};
    KeyNameData outName{};
    BOOST_CHECK(kn.keyForName(KeyNames::normalize(nd("fabiana")), outKey));
    BOOST_CHECK(outKey == a);
    BOOST_CHECK(kn.nameForKey(a, outName));
    BOOST_CHECK(outName == nd("fabiana"));

    // Rename frees the old name for b.
    BOOST_CHECK(kn.registerName(a, nd("fabi"), 0) ==
                KeyNames::RegisterResult::Ok);
    BOOST_CHECK(!kn.keyForName(KeyNames::normalize(nd("fabiana")), outKey));
    BOOST_CHECK(kn.registerName(b, nd("fabiana"), 0) ==
                KeyNames::RegisterResult::Ok);

    // Clear removes it.
    BOOST_CHECK(kn.clearName(a));
    BOOST_CHECK(!kn.nameForKey(a, outName));
    BOOST_CHECK(!kn.keyForName(KeyNames::normalize(nd("fabi")), outKey));
  }
  boost::system::error_code ec;
  fs::remove_all(dir, ec);
}

// Space form and underscore form are ONE name: registering "Ada Lovelace"
// blocks "Ada_Lovelace" for anyone else, and the stored/queried form is the
// underscore normalization. Boundary underscores/spaces are stripped.
BOOST_AUTO_TEST_CASE(SpaceUnderscoreEquivalence) {
  auto dir = makeUniqueTempDir("kn_equiv");
  {
    KeyNames kn(dir.string(), 1024, std::numeric_limits<uint64_t>::max());
    const Hash a = keyOf(0xA1), b = keyOf(0xB2);

    BOOST_CHECK(kn.registerName(a, nd("Ada Lovelace"), 0) ==
                KeyNames::RegisterResult::Ok);
    // The stored name is the underscore form.
    KeyNameData outName{};
    BOOST_CHECK(kn.nameForKey(a, outName));
    BOOST_CHECK(outName == nd("Ada_Lovelace"));
    // A different key cannot take the underscore spelling: same name.
    BOOST_CHECK(kn.registerName(b, nd("Ada_Lovelace"), 0) ==
                KeyNames::RegisterResult::NameTaken);
    // Boundary underscores/spaces are stripped: "_Bob_" -> "Bob".
    BOOST_CHECK(kn.registerName(b, nd("_Bob_"), 0) ==
                KeyNames::RegisterResult::Ok);
    BOOST_CHECK(kn.nameForKey(b, outName));
    BOOST_CHECK(outName == nd("Bob"));
    // A name that is only boundary chars normalizes to empty -> BadName.
    BOOST_CHECK(kn.registerName(keyOf(0xC3), nd("__ __"), 0) ==
                KeyNames::RegisterResult::BadName);
  }
  boost::system::error_code ec;
  fs::remove_all(dir, ec);
}

// The capacity cap: maxKeyName bounds the table; a rename of an EXISTING key is
// not a new cell and is never blocked by the cap.
BOOST_AUTO_TEST_CASE(CapacityCap) {
  auto dir = makeUniqueTempDir("kn_cap");
  {
    KeyNames kn(dir.string(), 1024, std::numeric_limits<uint64_t>::max());
    const Hash a = keyOf(0xD1), b = keyOf(0xD2);
    BOOST_CHECK(kn.registerName(a, nd("one"), 1) ==
                KeyNames::RegisterResult::Ok);         // first fills the cap
    BOOST_CHECK(kn.registerName(b, nd("two"), 1) ==
                KeyNames::RegisterResult::CapacityFull);
    BOOST_CHECK(kn.registerName(a, nd("uno"), 1) ==
                KeyNames::RegisterResult::Ok);          // rename: not a new cell
  }
  boost::system::error_code ec;
  fs::remove_all(dir, ec);
}

// THE persistence concern: the reverse index is DERIVED, so it must be rebuilt
// identically from disk on reload -- snapshot == replay.
BOOST_AUTO_TEST_CASE(ReloadRebuildsReverseIndex) {
  auto dir = makeUniqueTempDir("kn_reload");
  const Hash a = keyOf(0x11);
  {
    KeyNames kn(dir.string(), 1024, std::numeric_limits<uint64_t>::max());
    BOOST_CHECK(kn.registerName(a, nd("persisted name"), 0) ==
                KeyNames::RegisterResult::Ok);
    kn->flush(true);
    kn->save(logkv::StoreSaveMode::syncSave);
  }
  {
    KeyNames kn(dir.string(), 1024, std::numeric_limits<uint64_t>::max());
    KeyNameData outName{};
    Hash outKey{};
    BOOST_CHECK_MESSAGE(kn.nameForKey(a, outName), "forward lost on reload");
    // The STORED form is normalized (underscores), not the raw input.
    BOOST_CHECK(outName == nd("persisted_name"));
    // The reverse map was NOT persisted; it must be rebuilt from the forward
    // store on load. Either spelling resolves (both normalize the same).
    BOOST_CHECK_MESSAGE(
        kn.keyForName(KeyNames::normalize(nd("persisted name")), outKey),
        "reverse index not rebuilt on reload");
    BOOST_CHECK(outKey == a);
    BOOST_CHECK(kn.keyForName(KeyNames::normalize(nd("persisted_name")), outKey));
    BOOST_CHECK(outKey == a);
  }
  boost::system::error_code ec;
  fs::remove_all(dir, ec);
}

// --- full round-trip through the client/server ---

BOOST_FIXTURE_TEST_CASE(RegisterQueryClearRoundTrip, CesFixture) {
  const Hash myKey = clientKey.getPublicKeyAsHash();

  BOOST_CHECK_EQUAL(client->registerKeyName(nb("fabiana")), CES_OK);

  ces::Bytes gotName;
  bool found = false;
  BOOST_CHECK_EQUAL(client->queryKeyName(myKey, gotName, found), CES_OK);
  BOOST_CHECK(found);
  BOOST_CHECK(gotName == nb("fabiana"));

  Hash gotKey{};
  found = false;
  BOOST_CHECK_EQUAL(client->queryKeyNameByName(nb("fabiana"), gotKey, found),
                    CES_OK);
  BOOST_CHECK(found);
  BOOST_CHECK(gotKey == myKey);

  // Clear it.
  BOOST_CHECK_EQUAL(client->clearKeyName(), CES_OK);
  found = true;
  BOOST_CHECK_EQUAL(client->queryKeyName(myKey, gotName, found), CES_OK);
  BOOST_CHECK(!found);
}

BOOST_FIXTURE_TEST_CASE(SecondKeyRejectedOnTakenName, CesFixture) {
  BOOST_CHECK_EQUAL(client->registerKeyName(nb("taken")), CES_OK);

  // A second, funded client with a different key.
  KeyPair otherKey;
  server->_brr(otherKey.getPublicKeyAsHash(), 10'000'000'000);
  server->_drainLogic();
  boost::asio::ip::udp::endpoint ep(boost::asio::ip::address_v6::loopback(),
                                    serverPort);
  auto other = std::make_unique<CesClient>(ep, false);
  other->start(0);
  other->setKey(otherKey);
  BOOST_REQUIRE(other->connect());

  BOOST_CHECK_EQUAL(other->registerKeyName(nb("taken")),
                    CES_ERROR_KEYNAME_TAKEN);
  // ... but a free name works.
  BOOST_CHECK_EQUAL(other->registerKeyName(nb("free")), CES_OK);
  other->stop();
}

// Daily maintenance charges key_name rent and RECLAIMS a cell whose account is
// gone / cannot pay -- then rebuilds the reverse index off the swept store. The
// survivor must still resolve both ways; the reclaimed name must resolve
// NEITHER way (the derived index cannot keep a ghost).
BOOST_FIXTURE_TEST_CASE(DailyRentReclaimsAndRebuildsReverse, CesFixture) {
  const Hash a = keyOf(0x51), b = keyOf(0x52);
  server->_brr(a, 10'000'000'000);  // Alice pays her rent forever
  server->_brr(b, 1);               // Bob is below account rent: deleted first
  server->_drainLogic();
  BOOST_REQUIRE(server->_registerKeyName(a, "alice"));
  BOOST_REQUIRE(server->_registerKeyName(b, "bob"));

  // Both resolve before the sweep.
  ces::Bytes name;
  Hash outKey{};
  bool found = false;
  BOOST_CHECK_EQUAL(client->queryKeyNameByName(nb("bob"), outKey, found), CES_OK);
  BOOST_CHECK(found);

  server->_runDailyMaintenance();
  server->_drainLogic();

  // Alice survives: forward and reverse both resolve to her.
  found = false;
  BOOST_CHECK_EQUAL(client->queryKeyName(a, name, found), CES_OK);
  BOOST_CHECK(found);
  BOOST_CHECK(name == nb("alice"));
  found = false;
  BOOST_CHECK_EQUAL(client->queryKeyNameByName(nb("alice"), outKey, found),
                    CES_OK);
  BOOST_CHECK(found);
  BOOST_CHECK(outKey == a);

  // Bob was reclaimed: the rebuilt reverse index holds no ghost, and the
  // forward store is empty for him.
  found = true;
  BOOST_CHECK_EQUAL(client->queryKeyName(b, name, found), CES_OK);
  BOOST_CHECK(!found);
  found = true;
  BOOST_CHECK_EQUAL(client->queryKeyNameByName(nb("bob"), outKey, found), CES_OK);
  BOOST_CHECK(!found);
}

BOOST_AUTO_TEST_SUITE_END()
