#pragma once
// The single atomic ledger transaction available to an L2 verb. A verb does its
// disk and validation work off the logic strand, then makes at most one
// CesServer::_l2Transact(fn) call; inside fn it touches accounts and assets
// atomically through this interface. CesServer implements it over its stores.

#include <ces/account.h>   // minx::Hash, HashPrefix

#include <cstdint>

namespace ces {

struct LedgerTxn {
  // Network billing: validateSpend then debit on success. Burns the amount.
  // Returns the CES rc.
  virtual uint8_t signerSpend(const minx::Hash& signer, uint64_t amount,
                              uint32_t reqNonce, int64_t errFee) = 0;

  // Program-account billing: balance check then debit. false on missing
  // account or insufficient balance.
  virtual bool    debitAccount(const minx::Hash& pubkey, uint64_t amount) = 0;

  // Adds to balance, creating the account if missing.
  virtual void    credit(const minx::Hash& pubkey, int64_t amount) = 0;

  // 0 if the account does not exist.
  virtual int64_t balance(const minx::Hash& pubkey) = 0;

  // NONCELESS dedup, keyed on the op sig-hash.
  virtual bool    isReplay(uint64_t sigHash) = 0;
  virtual void    recordDedup(uint64_t sigHash) = 0;

  // Asset ownership read, for /f/ zone authz inside the txn.
  virtual bool    assetOwnedBy(const minx::Hash& assetId, const minx::Hash& who) = 0;

  virtual ~LedgerTxn() = default;
};

} // namespace ces
