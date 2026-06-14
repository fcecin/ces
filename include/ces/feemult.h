#pragma once

// Per-fee discount multiplier (basis points, 0..10000).
//
// Each named fee constant in CesConfig is associated with exactly one
// FeeKind. The metrics pulse refreshes feeMult_[k] from the gauge bp
// it's mapped to (l1cpu, l2cpu, l1memac, l1memas, l2mem, net). Debit
// sites then bill `raw * feeMult_[k] / 10000` instead of `raw`.
//
// Idle bp ≈ 0 → fees subsidized; saturation bp = 10000 → full price.
//
// Fees that prepay future days (CES_FUND_ASSET, CES_CREATE_ASSET initial
// days) attenuate the discount linearly to zero over kPrepaidDiscountWindowDays
// so users can't lock in cheap rates by funding years during idle periods.
//
// CesConfig::feeDiscountEnabled = false pins every multiplier to 10000.
// Default true in production; tests flip it off to keep static-fee assertions.

#include <cstddef>
#include <cstdint>

namespace ces {

enum class FeeKind : uint8_t {
  Tx = 0,            // feeTx — protocol op CPU cost
  Query,             // feeQuery — signed query CPU cost
  AccountRent,       // feeAccount daily — account slot pressure
  AssetRent,         // feeAsset daily / fund — asset slot pressure (attenuated)
  VMMult,            // feeVMMult — VM gas
  ComputeSlot,       // feeComputeSlotSec — compute supervisor slot rent
  ComputeCpu,        // feeComputeCpuSec — compute child CPU cost
  ComputeRss,        // feeComputeRssByteDay — compute child RSS rent
  BucketByteSec,     // feeBucketByteSec — Lua bucket capacity rent
  Net,               // feeNet* — ChannelMeter per-channel RUDP rates
  Count_             // sentinel for sizing
};

constexpr std::size_t kFeeKindCount =
  static_cast<std::size_t>(FeeKind::Count_);

// Attenuation window for prepaid-days fees: any day at distance D from
// today ramps the discount linearly toward 0 (full price) at D = window.
constexpr int kPrepaidDiscountWindowDays = 90;

// Sum cost of prepaying `daysAdded` days at `feePerDay`, with the
// discount attenuated linearly to full price across kPrepaidDiscountWindowDays.
// `bp` is the AssetRent / AccountRent multiplier in basis points (0..10000);
// at saturation (bp=10000) cost collapses to flat. Distant days pay full
// price so funding deep into the future can't lock in a low rate.
inline uint64_t computePrepayCost(uint64_t feePerDay, uint16_t bp,
                                  uint32_t daysAdded, uint32_t daysHeld) {
  if (daysAdded == 0 || feePerDay == 0)
    return 0;
  if (bp >= 10000)
    return static_cast<uint64_t>(daysAdded) * feePerDay;
  constexpr uint32_t W = static_cast<uint32_t>(kPrepaidDiscountWindowDays);
  uint64_t total = 0;
  for (uint32_t i = 1; i <= daysAdded; ++i) {
    uint32_t D = daysHeld + i;
    uint64_t effBp;
    if (D >= W) {
      effBp = 10000;
    } else {
      // eff_bp = 10000 - (10000 - bp) * (W - D) / W
      uint64_t deficit   = static_cast<uint64_t>(10000 - bp);
      uint64_t windowGap = static_cast<uint64_t>(W - D);
      effBp = 10000 - (deficit * windowGap) / W;
    }
    total += feePerDay * effBp / 10000;
  }
  return total;
}

}  // namespace ces
