// account_holds.h - credits that a call in flight took from an account and
// will partly give back.
//
// A think call burns a hold (its worst-case cost) from the payer before it
// starts, and refunds the unused part when it ends. The held credits still
// belong to the payer until then. When the payer is a file's program
// account, the rent and compute charges on that account must not take the
// file for "no balance" while the hold can still come back. The file store
// asks this table how much is held for an account before it deletes a file
// for exhaustion.
//
// Thread-safe.

#pragma once

#include <minx/types.h>

#include <cstdint>
#include <map>
#include <mutex>

namespace ces {

class AccountHolds {
 public:
  void add(const minx::Hash& account, uint64_t amount) {
    if (amount == 0) return;
    std::lock_guard<std::mutex> lk(mu_);
    held_[account] += amount;
  }
  void remove(const minx::Hash& account, uint64_t amount) {
    if (amount == 0) return;
    std::lock_guard<std::mutex> lk(mu_);
    auto it = held_.find(account);
    if (it == held_.end()) return;
    if (it->second <= amount) held_.erase(it);
    else it->second -= amount;
  }
  uint64_t of(const minx::Hash& account) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = held_.find(account);
    return it == held_.end() ? 0 : it->second;
  }

 private:
  mutable std::mutex mu_;
  std::map<minx::Hash, uint64_t> held_;
};

}  // namespace ces
