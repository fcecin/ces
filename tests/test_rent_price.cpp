// File rent priced by store utilization (FileHandler::rentBp). The rent
// multiplier is the used fraction of the metered store, floored at 1 bp, and
// the store-meta writer keeps it current. The upfront 15-minute rent at
// CREATE shows the price with no waiting: at base rent (fee_file_rent = 1) a
// 1 MiB file needs 1048576 * 900 / 86400 = 10922 raw units upfront. The
// upfront rent uses the multiplier after the request adds its bytes.
//
// Rent for past time follows the multiplier over that time, not the
// multiplier at the moment of the charge. The tests make time pass with
// ageFile: it moves the last rent charge of a file back, as if the time had
// passed at a given multiplier.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"

#include <ces/keys.h>
#include <ces/server.h>
#include <ces/l2/file_client.h>
#include <ces/l2/file_handler.h>
#include <ces/util/rent_index.h>

#include <boost/test/unit_test.hpp>
#include <toml++/toml.hpp>

#include <fstream>
#include <string>
#include <thread>

using namespace ces;

namespace {

constexpr uint64_t kMiB = 1024 * 1024;
constexpr uint64_t kCap = 16 * kMiB;
constexpr uint64_t kHourUs = 3600ull * 1'000'000;

// Rent on `size` bytes at fee 1 and multiplier `bp`, for `us` microseconds.
uint64_t rentFor(uint64_t size, uint64_t bp, uint64_t us) {
  return static_cast<uint64_t>(static_cast<__uint128_t>(size) * us * bp /
                               (86400ull * 1'000'000 * 10000));
}

// Upfront rent (15 min) on `size` bytes at fee 1 and multiplier `bp`.
uint64_t upfrontAt(uint64_t size, uint64_t bp) {
  return size * 900ull * bp / (86400ull * 10000ull);
}

struct RentFixture {
  fs::path dir;
  CesConfig cfg;
  std::unique_ptr<CesServer> server;
  uint16_t rpcPort = 0;
  KeyPair ownerKey;

  RentFixture() {
    blog::init();
    blog::set_level(blog::fatal);
    dir = makeUniqueTempDir("rentprice");
    minx::Hash priv;
    priv.fill(0xE3);
    cfg = makeTestConfig(dir, priv,
                                   std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = {{"/ces/file/1", "builtin:file"}};
    cfg.cesFileStoreDir = (dir / "cesfilestore").string();
    cfg.cesFileStoreMaxBytes = kCap;
    cfg.feeFileRent = 1;
    cfg.feeFileWrite = 1;
    cfg.feeQuery = 0;
    server = std::make_unique<CesServer>(cfg);
    server->start(0);
    rpcPort = server->_rpcBoundPort();
    server->_brr(ownerKey.getPublicKeyAsHash(), 10'000'000'000);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  ~RentFixture() {
    if (server) server->stop();
    boost::system::error_code ec;
    fs::remove_all(dir, ec);
  }
  FileHandler* fh() { return server->fileHandler(); }
  uint8_t create(const std::string& name, uint64_t size, uint64_t deposit) {
    CesFileClient fc;
    fc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    if (fc.connect("localhost", rpcPort, ownerKey) != CES_OK)
      return CES_ERROR_INTERNAL;
    uint64_t fb = 0, cost = 0;
    uint8_t rc = fc.create(name, size, 0, deposit, fb, cost);
    fc.disconnect();
    return rc;
  }
  uint8_t stat(const std::string& name, CesFileClient::StatInfo& info) {
    CesFileClient fc;
    fc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    if (fc.connect("localhost", rpcPort, ownerKey) != CES_OK)
      return CES_ERROR_INTERNAL;
    uint8_t rc = fc.stat(name, info);
    fc.disconnect();
    return rc;
  }
  fs::path sidecarOf(const std::string& name) {
    return fs::path(cfg.cesFileStoreDir) / (name.substr(1) + ".sidecar.toml");
  }
  // Move the last rent charge of `name` back by `ageUs`, as if that time had
  // passed at multiplier `bp`. `keepIndex` false removes the rent index from
  // the sidecar, as in a sidecar from before the index.
  void ageFile(const std::string& name, uint64_t ageUs, uint64_t bp,
               bool keepIndex = true) {
    const fs::path sp = sidecarOf(name);
    toml::table t = toml::parse_file(sp.string());
    const int64_t last = t["last_rent_us"].value_or<int64_t>(0);
    t.insert_or_assign("last_rent_us", last - static_cast<int64_t>(ageUs));
    if (auto idx = t["rent_index"].value<int64_t>()) {
      if (keepIndex)
        t.insert_or_assign("rent_index",
                           *idx - static_cast<int64_t>(ageUs / 1000 * bp));
      else
        t.erase("rent_index");
    }
    std::ofstream(sp, std::ios::trunc) << t << '\n';
  }
};

}  // namespace

// The rent index alone: it moves at the current bp, a new bp applies from
// the moment it is set, a clock that goes back does not move it back, and a
// span at full bp costs the same as the base rent for that time.
BOOST_AUTO_TEST_SUITE(RentIndexTests)

BOOST_AUTO_TEST_CASE(Index_IntegratesBp) {
  const uint64_t t0 = 1'000'000'000'000ull;   // us
  RentIndex ri(RentIndex::fresh(t0));
  const uint64_t i0 = ri.at(t0);
  BOOST_CHECK_EQUAL(i0, t0 / 1000 * 10000);
  BOOST_CHECK_EQUAL(ri.at(t0 + 1'000'000) - i0, 10'000'000u);   // 1 s at full
  ri.setBp(500, t0 + 1'000'000);
  BOOST_CHECK_EQUAL(ri.at(t0 + 3'000'000) - i0, 10'000'000u + 1'000'000u);
  BOOST_CHECK_EQUAL(ri.at(t0 - 5), ri.at(t0 + 1'000'000));   // no move back
  ri.setBp(1, t0 - 5);   // a clock that went back moves nothing
  BOOST_CHECK_EQUAL(ri.at(t0 + 1'000'000) - i0, 10'000'000u);
  BOOST_CHECK_EQUAL(ri.at(t0 + 2'000'000) - i0, 10'000'000u + 1000u);
}

BOOST_AUTO_TEST_CASE(SpanAtFullBp_IsBaseRent) {
  const uint64_t day = 86'400'000ull * 10000;   // one day at full, bp*ms
  BOOST_CHECK_EQUAL(rentForIndexSpan(kMiB, 1, day), kMiB);
  BOOST_CHECK_EQUAL(rentForIndexSpan(kMiB, 1500, day / 2), kMiB * 750);
  BOOST_CHECK_EQUAL(rentForIndexSpan(0, 1, day), 0u);
  BOOST_CHECK_EQUAL(rentForIndexSpan(kMiB, 0, day), 0u);
  BOOST_CHECK_EQUAL(rentForIndexSpan(UINT64_MAX, INT64_MAX, UINT64_MAX),
                    UINT64_MAX);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(RentPriceTests, RentFixture)

// The multiplier is the used fraction, floored at 1 bp, capped at full.
BOOST_AUTO_TEST_CASE(RentBp_FollowsStoreBytes) {
  fh()->noteStoreBytes(0);
  BOOST_CHECK_EQUAL(fh()->rentBp(), 1);
  fh()->noteStoreBytes(kCap / 2);
  BOOST_CHECK_EQUAL(fh()->rentBp(), 5000);
  fh()->noteStoreBytes(kCap / 4 * 3);
  BOOST_CHECK_EQUAL(fh()->rentBp(), 7500);
  fh()->noteStoreBytes(kCap);
  BOOST_CHECK_EQUAL(fh()->rentBp(), 10000);
  fh()->noteStoreBytes(kCap * 3);
  BOOST_CHECK_EQUAL(fh()->rentBp(), 10000);
  fh()->_testPinRentBp(7);
  BOOST_CHECK_EQUAL(fh()->rentBp(), 7);
}

// The upfront rent is priced after the request adds its bytes. In an empty
// store the first 1 MiB of 16 MiB pays at 625 bp, not at the 1 bp of the
// empty store. A request cannot buy cheap rent from the empty store and
// then raise the price for everyone else.
BOOST_AUTO_TEST_CASE(UpfrontRent_UsesPriceAfterTheRequest) {
  const std::string home = "/h/" + ownerKey.getPublicKeyHexStr() + "/";
  BOOST_REQUIRE_EQUAL(fh()->rentBp(), 1);
  const uint64_t first = upfrontAt(kMiB, 625);
  BOOST_REQUIRE_EQUAL(first, 682u);   // 10922 at base
  BOOST_CHECK_EQUAL(create(home + "a", kMiB, first - 1),
                    CES_ERROR_INSUFFICIENT_BALANCE);
  CES_REQUIRE_OK(create(home + "a", kMiB, first));
  BOOST_REQUIRE_EQUAL(fh()->rentBp(), 625);

  // The second MiB takes the store to 1250 bp.
  const uint64_t second = upfrontAt(kMiB, 1250);
  BOOST_CHECK_EQUAL(create(home + "b", kMiB, second - 1),
                    CES_ERROR_INSUFFICIENT_BALANCE);
  CES_REQUIRE_OK(create(home + "b", kMiB, second));
  BOOST_CHECK_EQUAL(fh()->rentBp(), 1250);
}

// A full store pays the base rent.
BOOST_AUTO_TEST_CASE(FullStore_PaysBaseRent) {
  const std::string home = "/h/" + ownerKey.getPublicKeyHexStr() + "/";
  fh()->noteStoreBytes(kCap);
  const uint64_t base = upfrontAt(kMiB, 10000);
  BOOST_REQUIRE_EQUAL(base, 10922u);
  BOOST_CHECK_EQUAL(create(home + "c", kMiB, base - 1),
                    CES_ERROR_INSUFFICIENT_BALANCE);
}

// GC finds broke files with the same price that the rent charge uses. A file
// paid at the low price is not broke, and an oversized CREATE (which runs
// GC at no cost to its sender) does not delete it.
BOOST_AUTO_TEST_CASE(Gc_UsesTheChargedPrice) {
  const std::string home = "/h/" + ownerKey.getPublicKeyHexStr() + "/";
  const std::string a = home + "a";
  const uint64_t day = rentFor(kMiB, 625, 24 * kHourUs);   // 65536
  CES_REQUIRE_OK(create(a, kMiB, upfrontAt(kMiB, 625) + day));
  BOOST_REQUIRE_EQUAL(fh()->rentBp(), 625);

  // Two hours pass at 625 bp. At the base price the file would owe
  // 87381, more than its balance.
  ageFile(a, 2 * kHourUs, 625);
  BOOST_REQUIRE_GT(rentFor(kMiB, 10000, 2 * kHourUs), day);

  // An oversized CREATE fails and runs GC.
  BOOST_CHECK_EQUAL(create(home + "big", 64 * kMiB, 0),
                    CES_ERROR_STORE_FULL);

  CesFileClient::StatInfo info;
  CES_REQUIRE_OK(stat(a, info));
  const uint64_t want = day - rentFor(kMiB, 625, 2 * kHourUs);   // 60075
  BOOST_CHECK_LE(info.fileBalance, want);
  BOOST_CHECK_GE(info.fileBalance + 50, want);
}

// Rent for past time is charged at the multiplier of that time. A file paid
// at 625 bp that is touched after the store fills up does not owe the full
// price for the hours before.
BOOST_AUTO_TEST_CASE(Touch_ChargesThePriceOverTime) {
  const std::string home = "/h/" + ownerKey.getPublicKeyHexStr() + "/";
  const std::string a = home + "a";
  const uint64_t day = rentFor(kMiB, 625, 24 * kHourUs);   // 65536
  CES_REQUIRE_OK(create(a, kMiB, upfrontAt(kMiB, 625) + day));
  ageFile(a, 4 * kHourUs, 625);

  // Fill the store: the price is now the base price.
  CES_REQUIRE_OK(create(home + "b", 15 * kMiB,
                        upfrontAt(15 * kMiB, 10000)));
  BOOST_REQUIRE_EQUAL(fh()->rentBp(), 10000);

  CesFileClient::StatInfo info;
  CES_REQUIRE_OK(stat(a, info));
  const uint64_t want = day - rentFor(kMiB, 625, 4 * kHourUs);   // 54614
  BOOST_CHECK_LE(info.fileBalance, want);
  BOOST_CHECK_GE(info.fileBalance + 50, want);
}

// A sidecar from before the rent index pays the base price for the time
// since its last charge, as it did before. Then it gets an index.
BOOST_AUTO_TEST_CASE(SidecarWithoutIndex_PaysBaseRent) {
  const std::string home = "/h/" + ownerKey.getPublicKeyHexStr() + "/";
  const std::string a = home + "a";
  const uint64_t base2h = rentFor(kMiB, 10000, 2 * kHourUs);   // 87381
  const uint64_t deposit = 3 * base2h;
  CES_REQUIRE_OK(create(a, kMiB, upfrontAt(kMiB, 625) + deposit));
  ageFile(a, 2 * kHourUs, 625, /*keepIndex=*/false);

  CesFileClient::StatInfo info;
  CES_REQUIRE_OK(stat(a, info));
  BOOST_CHECK_LE(info.fileBalance, deposit - base2h);
  BOOST_CHECK_GE(info.fileBalance + 50, deposit - base2h);
  toml::table t = toml::parse_file(sidecarOf(a).string());
  BOOST_CHECK(t["rent_index"].value<int64_t>().has_value());
}

// The rent index is saved with the store totals and goes on after a
// restart, so a restart does not give files free (or extra) rent.
BOOST_AUTO_TEST_CASE(RentIndex_SurvivesRestart) {
  const std::string home = "/h/" + ownerKey.getPublicKeyHexStr() + "/";
  CES_REQUIRE_OK(create(home + "a", kMiB, upfrontAt(kMiB, 625)));
  const uint64_t before = fh()->rentIndex();
  server->stop();
  server.reset();
  server = std::make_unique<CesServer>(cfg);
  server->start(0);
  rpcPort = server->_rpcBoundPort();
  const uint64_t after = fh()->rentIndex();
  BOOST_CHECK_GE(after, before);
  // A fresh index would be near now_ms * 10000, far above an index that
  // moved at a low bp since the first start.
  BOOST_CHECK_LT(after, RentIndex::fresh(getMicrosSinceEpoch()).index);
  BOOST_CHECK_EQUAL(fh()->rentBp(), 625);
}

BOOST_AUTO_TEST_SUITE_END()
