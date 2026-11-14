// HeatSubsidy: the global discount that cools while idle and heats with use.
// A fake clock drives the cooling. The key property is the ceiling: over any
// window T the subsidy given is at most budget + T * budget / tau, whatever
// the pattern of use.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"

#include <ces/util/heat_subsidy.h>

#include <boost/test/unit_test.hpp>

#include <cmath>
#include <cstdint>
#include <string>

using namespace ces;

namespace {

struct Clock {
  uint64_t us = 1'000'000'000'000ull;
  std::function<uint64_t()> fn() {
    return [this] { return us; };
  }
  void advanceSecs(double s) { us += static_cast<uint64_t>(s * 1e6); }
};

HeatSubsidy::Config cfgOf(uint64_t budget, uint64_t tau, uint16_t floorBp,
                          std::string path = {}) {
  HeatSubsidy::Config c;
  c.budget = budget;
  c.tauSecs = tau;
  c.floorBp = floorBp;
  c.statePath = std::move(path);
  return c;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(HeatSubsidyTests)

BOOST_AUTO_TEST_CASE(Off_WhenAnyKnobIsZero) {
  Clock c;
  for (auto cfg : {cfgOf(0, 100, 1), cfgOf(1000, 0, 1),
                   cfgOf(1000, 100, 10000)}) {
    HeatSubsidy s(cfg, c.fn());
    uint64_t r = 99;
    BOOST_CHECK(!s.enabled());
    BOOST_CHECK_EQUAL(s.reserve(1000, r), 10000);   // full price
    BOOST_CHECK_EQUAL(r, 0u);
  }
}

// At rest the price multiplier is the floor (1 bp); use heats it toward
// 10000 (full price), as with the fee multipliers.
BOOST_AUTO_TEST_CASE(AtRest_FullDiscount_ThenHeats) {
  Clock c;
  HeatSubsidy s(cfgOf(1'000'000, 3600, 1), c.fn());
  BOOST_CHECK_EQUAL(s.multBp(), 1);
  uint64_t r = 0;
  BOOST_CHECK_EQUAL(s.reserve(10'000, r), 1);
  BOOST_CHECK_EQUAL(r, 9999u);              // floor(10000 * 9999 / 10000)
  BOOST_CHECK_EQUAL(s.heat(), 9999u);
  // 1% of the budget used: the price rises by about 1% of the range.
  BOOST_CHECK_EQUAL(s.multBp(), 101);
  s.release(9999);
  BOOST_CHECK_EQUAL(s.heat(), 0u);
  BOOST_CHECK_EQUAL(s.multBp(), 1);
}

// A grant never takes the heat past the budget.
BOOST_AUTO_TEST_CASE(Grant_NeverPassesBudget) {
  Clock c;
  HeatSubsidy s(cfgOf(1000, 3600, 1), c.fn());
  uint64_t total = 0;
  for (int i = 0; i < 100; ++i) {
    uint64_t r = 0;
    s.reserve(700, r);
    total += r;
    BOOST_REQUIRE_LE(s.heat(), 1000u);
  }
  BOOST_CHECK_LE(total, 1000u);
  BOOST_CHECK_GT(total, 900u);   // most of the budget does go out
}

// Heat decays as exp(-t / tau).
BOOST_AUTO_TEST_CASE(Cools_Exponentially) {
  Clock c;
  HeatSubsidy s(cfgOf(1'000'000, 1000, 1), c.fn());
  uint64_t r = 0;
  s.reserve(500'000, r);
  const double h0 = static_cast<double>(s.heat());
  c.advanceSecs(1000);
  BOOST_CHECK_CLOSE(static_cast<double>(s.heat()), h0 * std::exp(-1.0), 0.01);
  c.advanceSecs(19000);   // 20 tau in all: about 1e-9 of the heat left
  BOOST_CHECK_LT(s.heat(), 1u);
  BOOST_CHECK_EQUAL(s.multBp(), 1);
}

// The ceiling: an attacker who takes every grant it can, as often as it can,
// gets at most budget + T * budget / tau over a window T.
BOOST_AUTO_TEST_CASE(Ceiling_HoldsUnderAttack) {
  Clock c;
  const uint64_t B = 100'000, tau = 600;
  HeatSubsidy s(cfgOf(B, tau, 1), c.fn());
  const double T = 6 * 3600;   // six hours, one grab per second
  double total = 0;
  for (int t = 0; t < static_cast<int>(T); ++t) {
    uint64_t r = 0;
    s.reserve(1'000'000, r);
    total += static_cast<double>(r);
    c.advanceSecs(1);
  }
  const double ceiling = static_cast<double>(B) + T * B / tau;
  BOOST_CHECK_LE(total, ceiling);
  BOOST_CHECK_GT(total, 0.5 * ceiling);   // and it is not a loose bound
}

// The heat survives a restart and cools for the downtime. With no state
// file the service starts at rest.
BOOST_AUTO_TEST_CASE(State_PersistsAndCoolsForDowntime) {
  fs::path dir = makeUniqueTempDir("heatsub");
  const std::string path = (dir / "think_subsidy.state").string();
  Clock c;
  {
    HeatSubsidy s(cfgOf(1'000'000, 1000, 1, path), c.fn());
    BOOST_CHECK_EQUAL(s.heat(), 0u);   // first start: at rest
    uint64_t r = 0;
    s.reserve(800'000, r);
    BOOST_CHECK_EQUAL(s.heat(), r);
  }
  c.advanceSecs(1000);   // down for one tau
  {
    HeatSubsidy s(cfgOf(1'000'000, 1000, 1, path), c.fn());
    BOOST_CHECK_CLOSE(static_cast<double>(s.heat()),
                      799'920 * std::exp(-1.0), 0.01);
  }
  boost::system::error_code ec;
  fs::remove_all(dir, ec);
}

BOOST_AUTO_TEST_SUITE_END()
