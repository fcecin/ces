#include "test_common.h"
#include <ces/util/metrics.h>
#include <ces/feemult.h>

// Pure-math unit tests for gauge primitives and the prepay-cost
// formula. No fixture, no I/O, no sleeps. Instant.
BOOST_AUTO_TEST_SUITE(MetricsMathTests)

BOOST_AUTO_TEST_CASE(BucketGaugeRollAndSum) {
  ces::BucketGauge<4> g;
  g.record(10);
  g.roll();    // bucket 0=10, write head -> 1
  g.record(20);
  g.roll();    // bucket 1=20, head -> 2
  g.record(7);
  // sum across all 4 slots; head bucket is 7, others are 10+20=30
  BOOST_CHECK_EQUAL(g.sum(), 37u);
  BOOST_CHECK_EQUAL(g.average(), 37u / 4);

  // Roll past the window so the original 10 falls off.
  g.roll(); g.roll(); g.roll();
  // After three more rolls and no records, sums should reflect
  // only the entries still in the window.
  BOOST_CHECK_LE(g.sum(), 37u);
}

BOOST_AUTO_TEST_CASE(ClampBpRange) {
  BOOST_CHECK_EQUAL(ces::clampBp(0u),     0);
  BOOST_CHECK_EQUAL(ces::clampBp(5000u),  5000);
  BOOST_CHECK_EQUAL(ces::clampBp(10000u), 10000);
  BOOST_CHECK_EQUAL(ces::clampBp(99999u), 10000);
}

BOOST_AUTO_TEST_CASE(PrepayCostSaturationIsFlat) {
  // bp=10000 means the discount is off → cost is N * fee, no math.
  uint64_t c = ces::computePrepayCost(/*feePerDay=*/100,
                                      /*bp=*/10000, /*days=*/30, /*held=*/0);
  BOOST_CHECK_EQUAL(c, 30u * 100u);
}

BOOST_AUTO_TEST_CASE(PrepayCostBeyondWindowIsFullPrice) {
  // Funding starting >= 90 days out: every day pays full price.
  uint64_t c = ces::computePrepayCost(100, 0, /*days=*/10, /*held=*/100);
  BOOST_CHECK_EQUAL(c, 10u * 100u);
}

BOOST_AUTO_TEST_CASE(PrepayCostIdleNearTermDeepDiscount) {
  // bp=0 (idle), buying day 1 only: D=1, att = 1-1/90 = 89/90.
  // eff_bp = (10000 - 10000 * 89/90) = 10000/90 ≈ 111.
  // cost  ≈ 100 * 111 / 10000 ≈ 1.
  uint64_t c = ces::computePrepayCost(100, 0, 1, 0);
  BOOST_CHECK_GE(c, 0u);
  BOOST_CHECK_LE(c, 5u);  // generous upper bound
}

BOOST_AUTO_TEST_CASE(PrepayCostIdleBulkApproachesFullPrice) {
  // Funding 1000 days at idle bp=0: ~89 days near-zero + 911 days
  // at full → total close to 911 * fee.
  uint64_t c = ces::computePrepayCost(100, 0, 1000, 0);
  BOOST_CHECK_GE(c, 911u * 100u);          // floor
  BOOST_CHECK_LE(c, 1000u * 100u);         // ceiling
}

BOOST_AUTO_TEST_CASE(PrepayCostMonotonicInBp) {
  // Higher bp must mean higher cost (less discount).
  auto c0 = ces::computePrepayCost(100, 0,    50, 0);
  auto c1 = ces::computePrepayCost(100, 5000, 50, 0);
  auto c2 = ces::computePrepayCost(100, 9999, 50, 0);
  BOOST_CHECK_LE(c0, c1);
  BOOST_CHECK_LE(c1, c2);
}

BOOST_AUTO_TEST_SUITE_END()


BOOST_FIXTURE_TEST_SUITE(MetricsTests, CesFixture)

// Smoke-level only: server gauges depend on host-wide state and on real
// /proc, so deterministic values aren't achievable. We assert that
// readouts stay within [0, 10000] and that gauges driven by activity
// move when activity happens. Tests use runMetricsTickOnce() instead
// of waiting for the 1Hz timer so the suite stays instant.

BOOST_AUTO_TEST_CASE(GaugesWithinBpRange) {
  server->runMetricsTickOnce();
  BOOST_CHECK_LE(server->getL1cpuBp(),  10000);
  BOOST_CHECK_LE(server->getL2cpuBp(),  10000);
  BOOST_CHECK_LE(server->getL1memacBp(),10000);
  BOOST_CHECK_LE(server->getL1memasBp(),10000);
  BOOST_CHECK_LE(server->getL2memBp(),  10000);
  BOOST_CHECK_LE(server->getNetBp(),    10000);
}

BOOST_AUTO_TEST_CASE(L1cpuRecordsStrandBusyTime) {
  // postLogic instrumentation accumulates busy_ns per strand handler.
  // Drive cheap unsigned queries; the raw busy-ns sum must increase
  // even if it doesn't clear bp's ~6 ms / 60s threshold.
  uint64_t before = server->getL1cpuBusyNs();
  for (int i = 0; i < 10; ++i) {
    int64_t bal = 0;
    uint32_t nonce = 0;
    client->queryAccount(getMyId(), bal, nonce);
  }
  uint64_t after = server->getL1cpuBusyNs();
  BOOST_CHECK_GT(after, before);
}

BOOST_AUTO_TEST_CASE(StoreOccupancyReflectsConfiguredCap) {
  // Account/asset bp is computed on the metrics tick from store sizes.
  // After one tick they must be populated and within range.
  server->runMetricsTickOnce();
  // The store-size sample is hopped onto logicStrand_ from inside
  // runMetricsTickOnce — give it a beat to land.
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  BOOST_CHECK_LE(server->getL1memacBp(), 10000);
  BOOST_CHECK_LE(server->getL1memasBp(), 10000);
}

BOOST_AUTO_TEST_CASE(FeeMultiplierPinnedWhenDiscountDisabled) {
  // CesFixture sets feeDiscountEnabled=false so every multiplier
  // stays at 10000 (full price). Tests across the rest of the suite
  // depend on this — verify it directly here.
  server->runMetricsTickOnce();
  BOOST_CHECK_EQUAL(server->getFeeMult(FeeKind::Tx),          10000);
  BOOST_CHECK_EQUAL(server->getFeeMult(FeeKind::Query),       10000);
  BOOST_CHECK_EQUAL(server->getFeeMult(FeeKind::AccountRent), 10000);
  BOOST_CHECK_EQUAL(server->getFeeMult(FeeKind::AssetRent),   10000);
  BOOST_CHECK_EQUAL(server->getFeeMult(FeeKind::ComputeSlot), 10000);
}

BOOST_AUTO_TEST_SUITE_END()

// ----------------------------------------------------------------------------
// Bare-server fee-multiplier safety tests
// ----------------------------------------------------------------------------
//
// CesFixture pins feeDiscountEnabled=false, which side-steps the
// dynamic-discount path entirely. These tests construct a CesServer
// directly with feeDiscountEnabled=true so the mapper runs for real,
// and verify the invariant: every FeeKind multiplier is always in
// [1, 10000], regardless of whether the per-gauge source is
// well-defined. The invariant must hold both before the first metrics
// tick and after a tick when a source gauge is undefined (e.g.
// maxAcc=0 → l1memacBp_ never gets written and stays at 0).

namespace {

ces::CesConfig makeDiscountConfig(const fs::path& dir,
                                  uint64_t maxAcc,
                                  uint64_t maxAsset) {
  minx::Hash key;
  key.fill(0xEE);
  ces::CesConfig cfg;
  cfg.dataDir = dir;
  cfg.serverPrivKey = key;
  cfg.minAcc = maxAcc > 0 ? 100 : 0;
  cfg.maxAcc = maxAcc;
  cfg.minDiff = 1;
  cfg.spendSlotSize = 10;
  cfg.minProveWorkTimestamp = 0;
  cfg.taskThreads = 2;
  cfg.minAsset = maxAsset > 0 ? 100 : 0;
  cfg.maxAsset = maxAsset;
  cfg.flushValue = std::numeric_limits<uint64_t>::max();
  cfg.feeDiscountEnabled = true;
  return cfg;
}

} // namespace

BOOST_AUTO_TEST_SUITE(FeeMultiplierSafetyTests)

BOOST_AUTO_TEST_CASE(MultsAreSafeBeforeFirstMetricsTick) {
  auto dir = makeUniqueTempDir("ces_feemult_pretick");
  auto cfg = makeDiscountConfig(dir, /*maxAcc=*/100, /*maxAsset=*/100);
  ces::CesServer srv(cfg);
  // No start(), no metrics tick — multipliers must already be the
  // fail-safe default (10000 = full price).
  BOOST_CHECK_EQUAL(srv.getFeeMult(ces::FeeKind::Tx),            10000);
  BOOST_CHECK_EQUAL(srv.getFeeMult(ces::FeeKind::Query),         10000);
  BOOST_CHECK_EQUAL(srv.getFeeMult(ces::FeeKind::AccountRent),   10000);
  BOOST_CHECK_EQUAL(srv.getFeeMult(ces::FeeKind::AssetRent),     10000);
  BOOST_CHECK_EQUAL(srv.getFeeMult(ces::FeeKind::VMMult),        10000);
  BOOST_CHECK_EQUAL(srv.getFeeMult(ces::FeeKind::ComputeSlot),   10000);
  BOOST_CHECK_EQUAL(srv.getFeeMult(ces::FeeKind::ComputeCpu),    10000);
  BOOST_CHECK_EQUAL(srv.getFeeMult(ces::FeeKind::ComputeRss),    10000);
  BOOST_CHECK_EQUAL(srv.getFeeMult(ces::FeeKind::BucketByteSec), 10000);
  BOOST_CHECK_EQUAL(srv.getFeeMult(ces::FeeKind::Net),           10000);
  fs::remove_all(dir);
}

BOOST_AUTO_TEST_CASE(AccountRentMultIsSafeWhenMaxAccIsZero) {
  // maxAcc=0 → the metrics tick skips updating l1memacBp_, leaving
  // the source gauge at 0. The mapper must NOT write that 0 into
  // AccountRent's multiplier — that would charge zero account rent.
  auto dir = makeUniqueTempDir("ces_feemult_noacc");
  auto cfg = makeDiscountConfig(dir, /*maxAcc=*/0, /*maxAsset=*/100);
  ces::CesServer srv(cfg);
  srv.start(0);
  srv.runMetricsTickOnce();
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  BOOST_CHECK_GE(srv.getFeeMult(ces::FeeKind::AccountRent), 1);
  BOOST_CHECK_LE(srv.getFeeMult(ces::FeeKind::AccountRent), 10000);
  srv.stop();
  fs::remove_all(dir);
}

BOOST_AUTO_TEST_CASE(AssetRentMultIsSafeWhenMaxAssetIsZero) {
  auto dir = makeUniqueTempDir("ces_feemult_noast");
  auto cfg = makeDiscountConfig(dir, /*maxAcc=*/100, /*maxAsset=*/0);
  ces::CesServer srv(cfg);
  srv.start(0);
  srv.runMetricsTickOnce();
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  BOOST_CHECK_GE(srv.getFeeMult(ces::FeeKind::AssetRent), 1);
  BOOST_CHECK_LE(srv.getFeeMult(ces::FeeKind::AssetRent), 10000);
  srv.stop();
  fs::remove_all(dir);
}

BOOST_AUTO_TEST_SUITE_END()
