#pragma once

#include <ces/persisted.h>
#include <ces/types.h>
#include <logkv/autoser.h>

namespace ces {

/**
 * Ledger account, stored in logkv::Store<boost::unordered_flat_map, HashPrefix,
 * Account>. The map entry is pair<const HashPrefix, Account>: an 8-byte key and
 * this 56-byte value, 64 bytes total, one cache line. Fields are ordered for
 * zero padding; the layout is pinned in tests/test_account_layout.cpp.
 *
 * keyTail combines with the 8-byte map key to form the full 32-byte account
 * key. balance and nonce are the core state; lastXferDest/Amount/Time hold the
 * last outgoing single-transfer receipt. balance and lastXferAmount are stored
 * in 48 bits (Int48/UInt48, capping an account at ~1.4M credits) to free the
 * 32-bit aliasId without growing the row.
 */
struct Account {

  Account()
      : keyTail_{}, balance_(0), lastXferAmount_(0), lastXferDest_{},
        lastXferTime_(0), nonce_(0), aliasId_(0) {}

  Account(const HashTail& keyTail, int64_t balance, uint32_t nonce)
      : keyTail_(keyTail), balance_(balance), lastXferAmount_(0),
        lastXferDest_{}, lastXferTime_(0), nonce_(nonce), aliasId_(0) {}

  Account(const Hash& key, int64_t balance, uint32_t nonce)
      : balance_(balance), lastXferAmount_(0), lastXferDest_{},
        lastXferTime_(0), nonce_(nonce), aliasId_(0) {
    setKeyTail(key);
  }

  Account(const Account&) = default;
  Account(Account&&) = default;
  Account& operator=(const Account&) = default;
  Account& operator=(Account&&) = default;

  auto operator<=>(const Account&) const = default;

  uint32_t getNonce() const { return nonce_; }
  void setNonce(uint32_t nonce) { nonce_ = nonce; }

  int64_t getBalance() const { return balance_.get(); }
  void setBalance(int64_t balance) { balance_.set(balance); }

  HashTail& getKeyTail() { return keyTail_; }
  const HashTail& getKeyTail() const { return keyTail_; }
  void setKeyTail(const HashTail& keyTail) { keyTail_ = keyTail; }
  void setKeyTail(const Hash& fullKey) { keyTail_ = getHashTail(fullKey); }

  Hash getKey(const HashPrefix& mapKey) const {
    return getHash(mapKey, keyTail_);
  }

  static HashPrefix getMapKey(const Hash& fullKey) {
    return getHashPrefix(fullKey);
  }

  HashPrefix getLastXferDest() const { return lastXferDest_; }
  void setLastXferDest(const HashPrefix& dest) { lastXferDest_ = dest; }

  uint64_t getLastXferAmount() const { return lastXferAmount_.get(); }
  void setLastXferAmount(uint64_t amount) { lastXferAmount_.set(amount); }

  uint32_t getLastXferTime() const { return lastXferTime_; }
  void setLastXferTime(uint32_t time) { lastXferTime_ = time; }

  uint32_t getAliasId() const { return aliasId_; }
  void setAliasId(uint32_t aliasId) { aliasId_ = aliasId; }

  const HashTail*   keyTailPtr()        const { return &keyTail_; }
  const Int48*      balancePtr()        const { return &balance_; }
  const uint32_t*   noncePtr()          const { return &nonce_; }
  const HashPrefix* lastXferDestPtr()   const { return &lastXferDest_; }
  const UInt48*     lastXferAmountPtr() const { return &lastXferAmount_; }
  const uint32_t*   lastXferTimePtr()   const { return &lastXferTime_; }
  const uint32_t*   aliasIdPtr()       const { return &aliasId_; }

  enum class SerMode : uint8_t {
    Full = 0x00,         // all fields (account creation, snapshots)
    BalanceNonce = 0x01, // balance + nonce (PoW, credits, errors, bulk xfer)
    None = 0x02,         // erased object
    Transfer = 0x03      // balance + nonce + lastXferDest + lastXferAmount + lastXferTime
  };

  CES_PERSISTED_BOILERPLATE(SerMode::BalanceNonce)

private:
  HashTail keyTail_;
  Int48 balance_;
  UInt48 lastXferAmount_;
  HashPrefix lastXferDest_;
  uint32_t lastXferTime_;
  uint32_t nonce_;
  uint32_t aliasId_;
};

} // namespace ces

// --- Custom logkv serializer for ces::Account ---

namespace logkv {

template <>
struct serializer<ces::Account> {

  using SerMode = ces::Account::SerMode;

  // Field group sizes for serialization
  static constexpr size_t SZ_KEY_TAIL = sizeof(ces::HashTail);
  static constexpr size_t SZ_BALANCE = 6;   // 48-bit, low32 + high16
  static constexpr size_t SZ_NONCE = sizeof(uint32_t);
  static constexpr size_t SZ_XFER_DEST = sizeof(ces::HashPrefix);
  static constexpr size_t SZ_XFER_AMOUNT = 6;   // 48-bit, low32 + high16
  static constexpr size_t SZ_XFER_TIME = sizeof(uint32_t);
  static constexpr size_t SZ_ALIAS_ID = sizeof(uint32_t);

  static constexpr size_t SZ_HEADER = 1;
  static constexpr size_t SZ_BALANCE_NONCE = SZ_BALANCE + SZ_NONCE;
  static constexpr size_t SZ_XFER = SZ_XFER_DEST + SZ_XFER_AMOUNT + SZ_XFER_TIME;
  static constexpr size_t SZ_ALL =
      SZ_KEY_TAIL + SZ_BALANCE_NONCE + SZ_XFER + SZ_ALIAS_ID;

  // 48-bit codec: low 32 bits then high 16 bits, in the Writer's byte order.
  static void write48(Writer& w, uint64_t v) {
    w.write(static_cast<uint32_t>(v));
    w.write(static_cast<uint16_t>(v >> 32));
  }
  static uint64_t read48(Reader& r) {
    uint32_t lo; uint16_t hi;
    r.read(lo);
    r.read(hi);
    return static_cast<uint64_t>(lo) | (static_cast<uint64_t>(hi) << 32);
  }

  static bool is_empty(const ces::Account& obj) {
    return serializer<ces::HashTail>::is_empty(obj.getKeyTail()) &&
           obj.getBalance() == 0 && obj.getNonce() == 0;
  }

  static size_t get_size(const ces::Account& obj) {
    if (ces::Account::_logkvStoreSnapshot())
      return SZ_ALL;

    SerMode mode = ces::Account::_getSerMode();

    if (is_empty(obj))
      return SZ_HEADER;

    switch (mode) {
    case SerMode::Full:
      return SZ_HEADER + SZ_ALL;
    case SerMode::BalanceNonce:
      return SZ_HEADER + SZ_BALANCE_NONCE;
    case SerMode::Transfer:
      return SZ_HEADER + SZ_BALANCE_NONCE + SZ_XFER;
    case SerMode::None:
      return SZ_HEADER;
    }
    return SZ_HEADER;
  }

  static size_t write(char* dest, size_t size, const ces::Account& obj) {
    Writer writer(dest, size);
    bool isSnapshot = ces::Account::_logkvStoreSnapshot();

    try {
      if (isSnapshot) {
        // Snapshot: write all fields, no header
        writer.write(obj.getKeyTail());
        write48(writer, static_cast<uint64_t>(obj.getBalance()));
        writer.write(obj.getNonce());
        writer.write(obj.getLastXferDest());
        write48(writer, obj.getLastXferAmount());
        writer.write(obj.getLastXferTime());
        writer.write(obj.getAliasId());
        return writer.bytes_processed();
      }

      bool objectIsEmpty = is_empty(obj);
      SerMode mode = ces::Account::_getSerMode();

      uint8_t header;
      if (objectIsEmpty) {
        header = static_cast<uint8_t>(SerMode::None);
      } else {
        header = static_cast<uint8_t>(mode);
      }
      writer.write(header);

      if (!objectIsEmpty) {
        switch (mode) {
        case SerMode::Full:
          writer.write(obj.getKeyTail());
          write48(writer, static_cast<uint64_t>(obj.getBalance()));
          writer.write(obj.getNonce());
          writer.write(obj.getLastXferDest());
          write48(writer, obj.getLastXferAmount());
          writer.write(obj.getLastXferTime());
          writer.write(obj.getAliasId());
          break;
        case SerMode::BalanceNonce:
          write48(writer, static_cast<uint64_t>(obj.getBalance()));
          writer.write(obj.getNonce());
          break;
        case SerMode::Transfer:
          write48(writer, static_cast<uint64_t>(obj.getBalance()));
          writer.write(obj.getNonce());
          writer.write(obj.getLastXferDest());
          write48(writer, obj.getLastXferAmount());
          writer.write(obj.getLastXferTime());
          break;
        case SerMode::None:
          break;
        }
      }
    } catch (const insufficient_buffer& e) {
      return writer.bytes_processed() + e.get_required_bytes();
    }
    return writer.bytes_processed();
  }

  static size_t read(const char* src, size_t size, ces::Account& obj) {
    Reader reader(src, size);
    bool isSnapshot = ces::Account::_logkvStoreSnapshot();

    try {
      if (isSnapshot) {
        ces::HashTail kt;
        ces::HashPrefix xferDest;
        uint32_t nonce, xferTime, aliasId;
        reader.read(kt);
        int64_t bal = static_cast<int64_t>(read48(reader) << 16) >> 16;
        reader.read(nonce);
        reader.read(xferDest);
        uint64_t xferAmount = read48(reader);
        reader.read(xferTime);
        reader.read(aliasId);
        obj.getKeyTail() = kt;
        obj.setBalance(bal);
        obj.setNonce(nonce);
        obj.setLastXferDest(xferDest);
        obj.setLastXferAmount(xferAmount);
        obj.setLastXferTime(xferTime);
        obj.setAliasId(aliasId);
        return reader.bytes_processed();
      }

      uint8_t header;
      reader.read(header);

      switch (static_cast<SerMode>(header)) {
      case SerMode::None:
        obj = ces::Account();
        break;
      case SerMode::Full: {
        ces::HashTail kt;
        ces::HashPrefix xferDest;
        uint32_t nonce, xferTime, aliasId;
        reader.read(kt);
        int64_t bal = static_cast<int64_t>(read48(reader) << 16) >> 16;
        reader.read(nonce);
        reader.read(xferDest);
        uint64_t xferAmount = read48(reader);
        reader.read(xferTime);
        reader.read(aliasId);
        obj.getKeyTail() = kt;
        obj.setBalance(bal);
        obj.setNonce(nonce);
        obj.setLastXferDest(xferDest);
        obj.setLastXferAmount(xferAmount);
        obj.setLastXferTime(xferTime);
        obj.setAliasId(aliasId);
        break;
      }
      case SerMode::BalanceNonce: {
        int64_t bal = static_cast<int64_t>(read48(reader) << 16) >> 16;
        uint32_t nonce;
        reader.read(nonce);
        obj.setBalance(bal);
        obj.setNonce(nonce);
        break;
      }
      case SerMode::Transfer: {
        ces::HashPrefix xferDest;
        uint32_t nonce, xferTime;
        int64_t bal = static_cast<int64_t>(read48(reader) << 16) >> 16;
        reader.read(nonce);
        reader.read(xferDest);
        uint64_t xferAmount = read48(reader);
        reader.read(xferTime);
        obj.setBalance(bal);
        obj.setNonce(nonce);
        obj.setLastXferDest(xferDest);
        obj.setLastXferAmount(xferAmount);
        obj.setLastXferTime(xferTime);
        break;
      }
      default:
        throw std::runtime_error("Invalid Account serialization header");
      }
    } catch (const insufficient_buffer& e) {
      return reader.bytes_processed() + e.get_required_bytes();
    }
    return reader.bytes_processed();
  }
};

} // namespace logkv
