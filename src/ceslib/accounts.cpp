#include <ces/accounts.h>
#include <chrono>
#include <limits>
#include <minx/blog.h>

LOG_MODULE("acc");

namespace ces {

Accounts::Accounts(const std::string& dataDir, uint64_t minAcc,
                   uint64_t flushValue, size_t bufferSize)
    : store_(dataDir, logkv::StoreFlags::createDir, bufferSize),
      flushValue_(flushValue) {
  store_.getObjects().reserve(minAcc);
  // Sum positive balances only (negative = payment markers)
  for (const auto& [key, acc] : store_.getObjects()) {
    if (acc.getBalance() > 0)
      totalCredits_ += acc.getBalance();
  }
}

Accounts::ActiveAccount Accounts::get(const HashPrefix& id) {
  return ActiveAccount{*this, id, store_.find(id)};
}

Accounts::ActiveAccount Accounts::get(const minx::Hash& key) {
  return get(Account::getMapKey(key));
}

Accounts::ActiveAccount Accounts::getFirst() {
  auto it = store_.begin();
  if (it != store_.end()) {
    return ActiveAccount{*this, it->first, it};
  }
  return ActiveAccount{*this, HashPrefix{}, it};
}

void Accounts::createAccount(const HashPrefix& id, const Account& acc) {
  {
    Account::SerModeGuard guard(Account::SerMode::Full);
    store_.update(id, acc);
  }
  if (acc.getBalance() > 0)
    totalCredits_ += acc.getBalance();
  LOGTRACE << "createAccount" << VAR(id) << VAR(acc.getBalance());
}

void Accounts::checkFlush(uint64_t amount) {
  flushAccumulator_ += amount;
  if (flushAccumulator_ > flushValue_) {
    flushAccumulator_ = 0;
    store_.flush();
  }
}

bool Accounts::checkAddOverflow(uint64_t a, uint64_t b, uint64_t& res) {
#if defined(__GNUC__) || defined(__clang__)
  return __builtin_add_overflow(a, b, &res);
#else
  res = a + b;
  return res < a;
#endif
}

bool Accounts::ActiveAccount::exists() const {
  return it != parent.store_.end();
}

Account& Accounts::ActiveAccount::data() { return it->second; }

const Account& Accounts::ActiveAccount::data() const { return it->second; }

int64_t Accounts::ActiveAccount::balance() const {

  return exists() ? it->second.getBalance() : 0;
}

uint32_t Accounts::ActiveAccount::nonce() const {

  return exists() ? it->second.getNonce() : 0;
}

uint8_t Accounts::ActiveAccount::validateSpend(uint64_t amount, uint64_t fee,
                                               uint32_t reqNonce,
                                               int64_t errFee) {
  if (!exists()) {
    LOGDEBUG << "validateSpend: origin not found";
    return CES_ERROR_ORIGIN_NOT_FOUND;
  }

  uint64_t totalDeduction;
  if (Accounts::checkAddOverflow(amount, fee, totalDeduction)) {
    LOGDEBUG << "validateSpend: overflow" << VAR(id) << VAR(amount) << VAR(fee);
    chargeError(errFee);
    return CES_ERROR_INSUFFICIENT_BALANCE;
  }

  int64_t bal = balance();
  if (bal < 0 || static_cast<uint64_t>(bal) < totalDeduction) {
    LOGDEBUG << "validateSpend: insufficient" << VAR(id) << VAR(bal)
             << VAR(totalDeduction);
    chargeError(errFee);
    return CES_ERROR_INSUFFICIENT_BALANCE;
  }

  if (reqNonce != 0 &&
      reqNonce != CES_NONCELESS &&
      reqNonce != nonce() + 1) {
    LOGDEBUG << "validateSpend: wrong nonce" << VAR(id) << VAR(reqNonce)
             << VAR(nonce());
    chargeError(errFee);
    return CES_ERROR_WRONG_NONCE;
  }

  return CES_OK;
}

void Accounts::ActiveAccount::debit(uint64_t totalAmount) {
  if (!exists())
    return;

  int64_t oldBal = balance();
  int64_t newBal = oldBal - static_cast<int64_t>(totalAmount);

  if (newBal <= 0) {
    parent.totalCredits_ -= std::max<int64_t>(0, oldBal);
    parent.store_.erase(it);
    it = parent.store_.end();
    LOGTRACE << "debit: account deleted" << VAR(id) << VAR(oldBal)
             << VAR(totalAmount);
  } else {
    parent.totalCredits_ -= static_cast<int64_t>(totalAmount);
    data().setBalance(newBal);
    data().setNonce(nonce() + 1);
    parent.store_.persist(it);
    LOGTRACE << "debit" << VAR(id) << VAR(newBal);
  }
}

void Accounts::ActiveAccount::debitTransfer(uint64_t totalAmount,
                                              const HashPrefix& destId,
                                              uint64_t xferAmount) {
  if (!exists())
    return;

  int64_t oldBal = balance();
  int64_t newBal = oldBal - static_cast<int64_t>(totalAmount);

  if (newBal <= 0) {
    parent.totalCredits_ -= std::max<int64_t>(0, oldBal);
    parent.store_.erase(it);
    it = parent.store_.end();
    LOGTRACE << "debitTransfer: account deleted" << VAR(id) << VAR(oldBal)
             << VAR(totalAmount);
  } else {
    parent.totalCredits_ -= static_cast<int64_t>(totalAmount);
    data().setBalance(newBal);
    data().setNonce(nonce() + 1);
    data().setLastXferDest(destId);
    data().setLastXferAmount(xferAmount);
    data().setLastXferTime(static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count()));
    Account::SerModeGuard guard(Account::SerMode::Transfer);
    parent.store_.persist(it);
    LOGTRACE << "debitTransfer" << VAR(id) << VAR(newBal) << VAR(destId)
             << VAR(xferAmount);
  }
}

void Accounts::ActiveAccount::credit(uint64_t amount) {
  if (!exists())
    return;

  int64_t current = balance();
  int64_t newBal;
  if (static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) -
        static_cast<uint64_t>(current) >=
      amount) {
    newBal = current + static_cast<int64_t>(amount);
  } else {
    newBal = std::numeric_limits<int64_t>::max();
  }
  parent.totalCredits_ += (newBal - current);
  data().setBalance(newBal);
  parent.store_.persist(it);
  LOGTRACE << "credit" << VAR(id) << VAR(amount) << VAR(newBal);
}

void Accounts::ActiveAccount::settlePayment(uint64_t amount) {
  if (!exists())
    return;
  parent.totalCredits_ += static_cast<int64_t>(amount);
  data().setBalance(amount);
  data().setNonce(0);
  parent.store_.persist(it);
  LOGTRACE << "settlePayment" << VAR(id) << VAR(amount);
}

void Accounts::ActiveAccount::chargeError(int64_t errFee) {
  if (!exists())
    return;

  int64_t oldBal = balance();
  // Payment accounts (balance < 0) hold no spendable credits. Charging an error
  // fee gives b = oldBal - errFee <= 0, which would erase the account — so any
  // failed signed op from the payee's key (e.g. a signed self-query) would
  // destroy the pending payment. Skip the fee; it settles or expires via daily
  // maintenance. (The negative balance is excluded from totalCredits_.)
  if (oldBal < 0)
    return;

  int64_t b = oldBal - errFee;
  if (b <= 0) {
    parent.totalCredits_ -= std::max<int64_t>(0, oldBal);
    parent.store_.erase(it);
    it = parent.store_.end();
    LOGTRACE << "chargeError: account deleted" << VAR(id) << VAR(oldBal)
             << VAR(errFee);
  } else {
    parent.totalCredits_ -= errFee;
    data().setBalance(b);
    parent.store_.persist(it);
    LOGTRACE << "chargeError" << VAR(id) << VAR(errFee) << VAR(b);
  }
  parent.checkFlush(errFee);
}

} // namespace ces
