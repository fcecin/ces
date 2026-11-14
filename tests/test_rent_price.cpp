// File rent priced by store utilization (FileHandler::rentBp). The rent
// multiplier is the used fraction of the metered store, floored at 1 bp, and
// the store-meta writer keeps it current. The upfront 15-minute rent at
// CREATE shows the price with no waiting: at base rent (fee_file_rent = 1) a
// 1 MiB file needs 1048576 * 900 / 86400 = 10922 raw units upfront.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"

#include <ces/keys.h>
#include <ces/server.h>
#include <ces/l2/file_client.h>
#include <ces/l2/file_handler.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <thread>

using namespace ces;

namespace {

constexpr uint64_t kMiB = 1024 * 1024;
constexpr uint64_t kCap = 16 * kMiB;

// Upfront rent (15 min) on `size` bytes at fee 1 and multiplier `bp`.
uint64_t upfrontAt(uint64_t size, uint64_t bp) {
  return size * 900ull * bp / (86400ull * 10000ull);
}

struct RentFixture {
  fs::path dir;
  std::unique_ptr<CesServer> server;
  uint16_t rpcPort = 0;
  KeyPair ownerKey;

  RentFixture() {
    blog::init();
    blog::set_level(blog::fatal);
    dir = makeUniqueTempDir("rentprice");
    minx::Hash priv;
    priv.fill(0xE3);
    CesConfig cfg = makeTestConfig(dir, priv,
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
};

}  // namespace

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

// In an empty store the upfront rent is at 1 bp; the CREATE then moves the
// gauge, so the next file pays the new, higher price.
BOOST_AUTO_TEST_CASE(EmptyStore_RentIsDiscounted_AndRisesWithUse) {
  const std::string home = "/h/" + ownerKey.getPublicKeyHexStr() + "/";
  BOOST_REQUIRE_EQUAL(fh()->rentBp(), 1);
  const uint64_t first = upfrontAt(kMiB, 1);
  BOOST_REQUIRE_EQUAL(first, 1u);   // 10922 at base
  BOOST_CHECK_EQUAL(create(home + "a", kMiB, 0),
                    CES_ERROR_INSUFFICIENT_BALANCE);
  CES_REQUIRE_OK(create(home + "a", kMiB, first));

  // One MiB of sixteen is used: 625 bp.
  BOOST_REQUIRE_EQUAL(fh()->rentBp(), 625);
  const uint64_t second = upfrontAt(kMiB, 625);
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

BOOST_AUTO_TEST_SUITE_END()
