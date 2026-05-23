#pragma once

#include <algorithm>
#include <ces/types.h>
#include <logkv/autoser.h>

namespace ces {

/**
 * Accounts are 64-byte cache-line-aligned structures.
 *
 * Core fields (44 bytes):
 * - HashTail keyTail (24 bytes, combined with 8-byte HashPrefix map key = 32)
 * - int64_t balance (8 bytes)
 * - uint32_t nonce (4 bytes)
 *
 * Last outgoing single-transfer receipt fields (20 bytes):
 * - HashPrefix lastXferDest (8 bytes)
 * - uint64_t lastXferAmount (8 bytes)
 * - uint32_t lastXferTime (4 bytes, Unix epoch seconds, uint32_t)
 */
struct Account {

  Account()
      : keyTail_{}, balance_(0), nonce_(0), lastXferDest_{}, lastXferAmount_(0),
        lastXferTime_(0) {}

  Account(const HashTail& keyTail, int64_t balance, uint32_t nonce)
      : keyTail_(keyTail), balance_(balance), nonce_(nonce), lastXferDest_{},
        lastXferAmount_(0), lastXferTime_(0) {}

  Account(const Hash& key, int64_t balance, uint32_t nonce)
      : balance_(balance), nonce_(nonce), lastXferDest_{}, lastXferAmount_(0),
        lastXferTime_(0) {
    setKeyTail(key);
  }

  Account(const Account&) = default;
  Account(Account&&) = default;
  Account& operator=(const Account&) = default;
  Account& operator=(Account&&) = default;

  auto operator<=>(const Account&) const = default;

  uint32_t getNonce() const { return nonce_; }
  void setNonce(uint32_t nonce) { nonce_ = nonce; }

  int64_t getBalance() const { return balance_; }
  void setBalance(int64_t balance) { balance_ = balance; }

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

  uint64_t getLastXferAmount() const { return lastXferAmount_; }
  void setLastXferAmount(uint64_t amount) { lastXferAmount_ = amount; }

  uint32_t getLastXferTime() const { return lastXferTime_; }
  void setLastXferTime(uint32_t time) { lastXferTime_ = time; }

  // --- Serialization mode control ---

  enum class SerMode : uint8_t {
    Full = 0x00,        // all fields (account creation, snapshots)
    BalanceNonce = 0x01, // balance + nonce (PoW, credits, errors, bulk xfer)
    None = 0x02,         // erased object
    Transfer = 0x03      // balance + nonce + lastXferDest + lastXferAmount + lastXferTime
  };

  static void _setSerMode(SerMode m) { serMode_ = m; }
  static SerMode _getSerMode() { return serMode_; }

  static void _logkvStoreSnapshot(bool s) { snapshotFlag_ = s; }
  static bool _logkvStoreSnapshot() { return snapshotFlag_; }

  // Scoped override of the thread-local SerMode. Restores the previous
  // value on destruction even if the guarded operation throws.
  struct SerModeGuard {
    SerMode prev;
    explicit SerModeGuard(SerMode m) : prev(Account::_getSerMode()) {
      Account::_setSerMode(m);
    }
    ~SerModeGuard() { Account::_setSerMode(prev); }
    SerModeGuard(const SerModeGuard&) = delete;
    SerModeGuard& operator=(const SerModeGuard&) = delete;
  };

private:
  HashTail keyTail_;
  int64_t balance_;
  uint32_t nonce_;
  HashPrefix lastXferDest_;
  uint64_t lastXferAmount_;
  uint32_t lastXferTime_;

  inline static thread_local SerMode serMode_ = SerMode::BalanceNonce;
  inline static thread_local bool snapshotFlag_ = false;
};

} // namespace ces

// --- Custom logkv serializer for ces::Account ---

namespace logkv {

template <>
struct serializer<ces::Account> {

  using SerMode = ces::Account::SerMode;

  // Field group sizes for serialization
  static constexpr size_t SZ_KEY_TAIL = sizeof(ces::HashTail);       // 24
  static constexpr size_t SZ_BALANCE = sizeof(int64_t);              // 8
  static constexpr size_t SZ_NONCE = sizeof(uint32_t);               // 4
  static constexpr size_t SZ_XFER_DEST = sizeof(ces::HashPrefix);   // 8
  static constexpr size_t SZ_XFER_AMOUNT = sizeof(uint64_t);        // 8
  static constexpr size_t SZ_XFER_TIME = sizeof(uint32_t);          // 4

  static constexpr size_t SZ_HEADER = 1;
  static constexpr size_t SZ_BALANCE_NONCE = SZ_BALANCE + SZ_NONCE;
  static constexpr size_t SZ_XFER = SZ_XFER_DEST + SZ_XFER_AMOUNT + SZ_XFER_TIME;
  static constexpr size_t SZ_ALL = SZ_KEY_TAIL + SZ_BALANCE_NONCE + SZ_XFER;

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
        writer.write(obj.getBalance());
        writer.write(obj.getNonce());
        writer.write(obj.getLastXferDest());
        writer.write(obj.getLastXferAmount());
        writer.write(obj.getLastXferTime());
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
          writer.write(obj.getBalance());
          writer.write(obj.getNonce());
          writer.write(obj.getLastXferDest());
          writer.write(obj.getLastXferAmount());
          writer.write(obj.getLastXferTime());
          break;
        case SerMode::BalanceNonce:
          writer.write(obj.getBalance());
          writer.write(obj.getNonce());
          break;
        case SerMode::Transfer:
          writer.write(obj.getBalance());
          writer.write(obj.getNonce());
          writer.write(obj.getLastXferDest());
          writer.write(obj.getLastXferAmount());
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
        int64_t bal;
        uint32_t nonce;
        ces::HashPrefix xferDest;
        uint64_t xferAmount;
        uint32_t xferTime;
        reader.read(kt);
        reader.read(bal);
        reader.read(nonce);
        reader.read(xferDest);
        reader.read(xferAmount);
        reader.read(xferTime);
        obj.getKeyTail() = kt;
        obj.setBalance(bal);
        obj.setNonce(nonce);
        obj.setLastXferDest(xferDest);
        obj.setLastXferAmount(xferAmount);
        obj.setLastXferTime(xferTime);
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
        int64_t bal;
        uint32_t nonce;
        ces::HashPrefix xferDest;
        uint64_t xferAmount;
        uint32_t xferTime;
        reader.read(kt);
        reader.read(bal);
        reader.read(nonce);
        reader.read(xferDest);
        reader.read(xferAmount);
        reader.read(xferTime);
        obj.getKeyTail() = kt;
        obj.setBalance(bal);
        obj.setNonce(nonce);
        obj.setLastXferDest(xferDest);
        obj.setLastXferAmount(xferAmount);
        obj.setLastXferTime(xferTime);
        break;
      }
      case SerMode::BalanceNonce: {
        int64_t bal;
        uint32_t nonce;
        reader.read(bal);
        reader.read(nonce);
        obj.setBalance(bal);
        obj.setNonce(nonce);
        break;
      }
      case SerMode::Transfer: {
        int64_t bal;
        uint32_t nonce;
        ces::HashPrefix xferDest;
        uint64_t xferAmount;
        uint32_t xferTime;
        reader.read(bal);
        reader.read(nonce);
        reader.read(xferDest);
        reader.read(xferAmount);
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
