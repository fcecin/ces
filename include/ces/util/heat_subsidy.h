// heat_subsidy.h - a global price discount that cools while a service is
// idle and heats up while it is used.
//
// The heat H is the subsidy (raw credit units) granted recently. It decays
// as H * exp(-t / tau). The price multiplier, in basis points of the full
// price as in feemult.h (10000 = full price), is
// floorBp + (10000 - floorBp) * H / budget. So an idle service charges
// floorBp of the price and a busy one charges the full price. Each grant
// adds to H, and a grant never takes H past the budget. So over any window
// of length T the total subsidy is at most budget + T * budget / tau, for any
// pattern of use. That is the most the operator can lose.
//
// The heat is saved to a state file after each change. With no state file
// (the first start ever) the service starts at rest (H = 0). On a restart the
// saved heat cools for the time the server was down.

#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>

namespace ces {

class HeatSubsidy {
 public:
  struct Config {
    uint64_t budget = 0;     // heat capacity, raw credit units (0 = off)
    uint64_t tauSecs = 0;    // cool-down time constant (0 = off)
    uint16_t floorBp = 10000;  // price multiplier at rest (1 = 99.99% off;
                               // 10000 = no discount)
    std::string statePath;   // "" = do not persist
  };

  explicit HeatSubsidy(Config cfg,
                       std::function<uint64_t()> nowUs = nullptr);

  bool enabled() const { return enabled_; }

  // Reserve a discount for a charge of at most `full` raw units. Returns
  // the price multiplier in basis points (10000 = full price) and sets
  // `reserved` to the subsidy it adds to the heat,
  // floor(full * (10000 - mult) / 10000). 10000 when off or hot.
  uint16_t reserve(uint64_t full, uint64_t& reserved);
  // Give back reserved subsidy that the charge did not use.
  void release(uint64_t amount);

  // The heat now, after cooling.
  uint64_t heat();
  // The price multiplier a small charge would get now (10000 = full).
  uint16_t multBp();

 private:
  void coolLocked();
  uint16_t multLocked() const;
  void saveLocked();

  Config cfg_;
  bool enabled_ = false;
  std::function<uint64_t()> now_;
  std::mutex mu_;
  double heat_ = 0;        // raw credit units
  uint64_t lastUs_ = 0;    // when heat_ was last cooled
};

}  // namespace ces
