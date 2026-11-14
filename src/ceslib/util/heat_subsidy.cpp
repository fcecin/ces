// heat_subsidy.cpp - see heat_subsidy.h.

#include <ces/util/heat_subsidy.h>

#include <ces/types.h>   // getMicrosSinceEpoch

#include <algorithm>
#include <cmath>
#include <filesystem>
#include <fstream>

namespace ces {

HeatSubsidy::HeatSubsidy(Config cfg, std::function<uint64_t()> nowUs)
    : cfg_(std::move(cfg)), now_(std::move(nowUs)) {
  if (!now_) now_ = [] { return getMicrosSinceEpoch(); };
  if (cfg_.floorBp > 10000) cfg_.floorBp = 10000;
  enabled_ = cfg_.budget > 0 && cfg_.tauSecs > 0 && cfg_.floorBp < 10000;
  lastUs_ = now_();
  heat_ = 0;   // at rest when there is no saved state
  if (!enabled_ || cfg_.statePath.empty()) return;
  std::ifstream f(cfg_.statePath);
  double h = 0;
  uint64_t at = 0;
  if (f >> h >> at) {
    heat_ = std::clamp(h, 0.0, static_cast<double>(cfg_.budget));
    if (at > 0 && at <= lastUs_) lastUs_ = at;   // cools for the downtime
    coolLocked();
  }
}

void HeatSubsidy::coolLocked() {
  const uint64_t now = now_();
  if (now <= lastUs_) return;
  const double dt = static_cast<double>(now - lastUs_) / 1e6;
  heat_ *= std::exp(-dt / static_cast<double>(cfg_.tauSecs));
  lastUs_ = now;
}

uint16_t HeatSubsidy::multLocked() const {
  const double hot = heat_ / static_cast<double>(cfg_.budget);
  if (hot >= 1) return 10000;
  // Nearest, so a service that has cooled down charges floorBp again. The
  // budget clamp in reserve() bounds the grant, not this rounding.
  return static_cast<uint16_t>(
      std::lround(cfg_.floorBp + (10000.0 - cfg_.floorBp) * hot));
}

void HeatSubsidy::saveLocked() {
  if (cfg_.statePath.empty()) return;
  const std::string tmp = cfg_.statePath + ".tmp";
  {
    std::ofstream f(tmp, std::ios::trunc);
    if (!f) return;
    f.precision(17);
    f << heat_ << " " << lastUs_ << "\n";
    if (!f.good()) return;
  }
  std::error_code ec;
  std::filesystem::rename(tmp, cfg_.statePath, ec);
}

uint16_t HeatSubsidy::reserve(uint64_t full, uint64_t& reserved) {
  reserved = 0;
  if (!enabled_ || full == 0) return 10000;
  std::lock_guard<std::mutex> lk(mu_);
  coolLocked();
  // The discount is 10000 - mult basis points of the price.
  uint16_t off = static_cast<uint16_t>(10000 - multLocked());
  if (off == 0) return 10000;
  // Never take the heat past the budget: lower the discount to what fits.
  const double room = static_cast<double>(cfg_.budget) - heat_;
  const double want = static_cast<double>(full) * off / 10000.0;
  if (want > room) {
    off = static_cast<uint16_t>(
        std::max(0.0, std::floor(room * 10000.0 / static_cast<double>(full))));
  }
  if (off == 0) return 10000;
  __extension__ typedef unsigned __int128 U128;
  reserved = static_cast<uint64_t>(static_cast<U128>(full) * off / 10000u);
  heat_ += static_cast<double>(reserved);
  saveLocked();
  return static_cast<uint16_t>(10000 - off);
}

void HeatSubsidy::release(uint64_t amount) {
  if (!enabled_ || amount == 0) return;
  std::lock_guard<std::mutex> lk(mu_);
  coolLocked();
  heat_ = std::max(0.0, heat_ - static_cast<double>(amount));
  saveLocked();
}

uint64_t HeatSubsidy::heat() {
  std::lock_guard<std::mutex> lk(mu_);
  if (enabled_) coolLocked();
  return static_cast<uint64_t>(heat_);
}

uint16_t HeatSubsidy::multBp() {
  if (!enabled_) return 10000;
  std::lock_guard<std::mutex> lk(mu_);
  coolLocked();
  return multLocked();
}

}  // namespace ces
