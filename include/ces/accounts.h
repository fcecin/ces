#pragma once

#include <ces/account.h>
#include <ces/types.h>
#include <logkv/store.h>

#include <mutex>
#include <string>

#include <boost/unordered/unordered_flat_map.hpp>

namespace ces {

class Accounts {
public:
  using AccountStore =
    logkv::Store<boost::unordered_flat_map, HashPrefix, Account>;

  struct ActiveAccount {
    Accounts& parent;
    HashPrefix id;
    AccountStore::iterator it;

    bool exists() const;
    Account& data();
    const Account& data() const;
    int64_t balance() const;
    uint32_t nonce() const;
    uint8_t validateSpend(uint64_t amount, uint64_t fee, uint32_t reqNonce,
                          int64_t errFee);
    void debit(uint64_t totalAmount);
    void debitTransfer(uint64_t totalAmount, const HashPrefix& destId,
                       uint64_t xferAmount);
    void credit(uint64_t amount);
    void settlePayment(uint64_t amount);
    void chargeError(int64_t errFee);
  };

  Accounts(const std::string& dataDir, uint64_t minAcc, uint64_t flushValue,
           size_t bufferSize = 1 << 19);
  AccountStore& getStore() { return store_; }
  AccountStore* operator->() { return &store_; }
  const AccountStore* operator->() const { return &store_; }
  AccountStore& operator*() { return store_; }
  const AccountStore& operator*() const { return store_; }
  std::unique_lock<std::mutex> lock() {
    return std::unique_lock<std::mutex>(mutex_);
  }

  ActiveAccount get(const HashPrefix& id);
  ActiveAccount get(const minx::Hash& key);
  ActiveAccount getFirst();
  void createAccount(const HashPrefix& id, const Account& acc);
  static bool checkAddOverflow(uint64_t a, uint64_t b, uint64_t& res);
  void checkFlush(uint64_t amount);

  int64_t getTotalCredits() const { return totalCredits_; }
  void adjustTotalCredits(int64_t delta) { totalCredits_ += delta; }

  // Exclude one account (by HashPrefix) from totalCredits_ and from all
  // credit/debit/createAccount/settlePayment/chargeError updates. Used for the
  // server's own account. Call once after the store loads; subtracts any
  // existing balance from totalCredits_ at call time.
  void setUncountedAccount(const HashPrefix& id);

private:
  friend struct ActiveAccount;

  AccountStore store_;
  std::mutex mutex_;
  uint64_t flushValue_;
  uint64_t flushAccumulator_ = 0;
  int64_t totalCredits_ = 0;
  HashPrefix uncountedId_{};
  bool hasUncounted_ = false;

  // Helper: true iff the given id is the uncounted account.
  bool isUncounted(const HashPrefix& id) const {
    return hasUncounted_ && id == uncountedId_;
  }
};

} // namespace ces