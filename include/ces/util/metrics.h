#pragma once

// Server-side runtime gauges driven by a 1Hz pulse.
//
// Two shapes:
//   - BucketGauge<N>   ring of N atomic accumulators rolled by the pulse.
//                      Workers call record(v); the pulse advances the
//                      write index every second. sum() returns the total
//                      across the window. average() is sum()/N.
//   - PointGauge       single atomic value resampled by the pulse.
//
// All values are unsigned 64-bit. Conversion to 0..10000 basis points
// is the caller's job (each gauge has a different scale).

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace ces {

template <std::size_t N = 60>
class BucketGauge {
 public:
  static constexpr std::size_t BUCKET_COUNT = N;

  BucketGauge() {
    for (auto& b : buckets_) b.store(0, std::memory_order_relaxed);
  }

  // Add v to the current write bucket. Lock-free; safe from any thread.
  void record(uint64_t v) {
    std::size_t idx = idx_.load(std::memory_order_relaxed);
    buckets_[idx].fetch_add(v, std::memory_order_relaxed);
  }

  // Advance to the next bucket and zero it. Called once per pulse tick.
  void roll() {
    std::size_t cur = idx_.load(std::memory_order_relaxed);
    std::size_t next = (cur + 1) % N;
    buckets_[next].store(0, std::memory_order_relaxed);
    idx_.store(next, std::memory_order_relaxed);
  }

  uint64_t sum() const {
    uint64_t s = 0;
    for (const auto& b : buckets_) s += b.load(std::memory_order_relaxed);
    return s;
  }

  uint64_t average() const { return sum() / N; }

 private:
  std::array<std::atomic<uint64_t>, N> buckets_{};
  std::atomic<std::size_t> idx_{0};
};

class PointGauge {
 public:
  void store(uint64_t v) { value_.store(v, std::memory_order_relaxed); }
  uint64_t load() const { return value_.load(std::memory_order_relaxed); }

 private:
  std::atomic<uint64_t> value_{0};
};

// Clamp a uint64_t to the basis-points range [0, 10000].
inline uint16_t clampBp(uint64_t v) {
  return v > 10000 ? static_cast<uint16_t>(10000) : static_cast<uint16_t>(v);
}

}  // namespace ces
