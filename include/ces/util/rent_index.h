// rent_index.h - the time integral of the file rent multiplier.
//
// The rent multiplier (FileHandler::rentBp, basis points of fee_file_rent)
// changes with the store use. The rent of a file for a time span must follow
// the multiplier over that span, not the multiplier at the moment of the
// charge. Otherwise a caller can raise the multiplier for a short time and
// then make other files pay the high price for all the time since their
// last charge.
//
// The index is the sum of bp over time, in bp * milliseconds. It moves
// forward at the current bp. A file keeps the index of its last charge, and
// owes size * fee_file_rent * (index_now - index_then) / (ms per day * 10000).
// A store with no saved index starts at now_ms * 10000, as if the base price
// had always applied. So a file that has no index of its own can pay the
// base price since its last charge, and the two kinds of file agree.
//
// Not thread-safe. The owner serializes access.

#pragma once

#include <cstdint>

namespace ces {

__extension__ typedef unsigned __int128 RentU128;   // exact bp * time sums

class RentIndex {
 public:
  struct State {
    uint64_t index = 0;   // bp * ms at `atUs`
    uint64_t atUs = 0;    // wall clock of `index`
    uint16_t bp = 10000;  // multiplier from `atUs` on
  };

  // The index of a store that has no saved index.
  static State fresh(uint64_t nowUs) {
    return State{nowUs / 1000 * 10000, nowUs, 10000};
  }

  RentIndex() = default;
  explicit RentIndex(State s) : s_(s) {}

  // The index at `nowUs`. A clock that goes back does not move it back.
  uint64_t at(uint64_t nowUs) const {
    if (nowUs <= s_.atUs) return s_.index;
    const RentU128 add = static_cast<RentU128>(nowUs - s_.atUs) * s_.bp / 1000;
    const RentU128 v = s_.index + add;
    return v > UINT64_MAX ? UINT64_MAX : static_cast<uint64_t>(v);
  }

  // Move the index to `nowUs` at the old bp, then use `bp` from there on.
  void setBp(uint16_t bp, uint64_t nowUs) {
    if (nowUs > s_.atUs) {
      s_.index = at(nowUs);
      s_.atUs = nowUs;
    }
    s_.bp = bp;
  }

  uint16_t bp() const { return s_.bp; }
  const State& state() const { return s_; }

 private:
  State s_;
};

// Rent in raw units on `size` bytes at `feeRent` per byte-day, for an index
// span of `span` (bp * ms). Floored. Clamped to UINT64_MAX.
inline uint64_t rentForIndexSpan(uint64_t size, int64_t feeRent,
                                 uint64_t span) {
  if (feeRent <= 0 || size == 0 || span == 0) return 0;
  constexpr uint64_t kMsPerDay = 86'400'000ull;
  const RentU128 v = static_cast<RentU128>(size) *
                     static_cast<uint64_t>(feeRent);
  // Split the division to keep the products small, and saturate: only
  // absurd inputs pass 128 bits, and they clamp to UINT64_MAX.
  using U128 = RentU128;
  const U128 kMax = ~U128(0);
  auto mul = [kMax](U128 a, U128 b) -> U128 {
    return (a != 0 && b > kMax / a) ? kMax : a * b;
  };
  const U128 d = static_cast<U128>(kMsPerDay) * 10000u;
  const U128 whole = mul(v, span / d);
  const U128 part = mul(v, span % d) / d;
  if (whole > UINT64_MAX || part > UINT64_MAX - whole) return UINT64_MAX;
  return static_cast<uint64_t>(whole + part);
}

}  // namespace ces
