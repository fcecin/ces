#pragma once

#include <ces/persisted.h>
#include <ces/types.h>
#include <logkv/autoser.h>

namespace ces {

using AssetData = std::array<uint8_t, 210>;

/**
 * Assets are 256-byte memory cells for rent, indexed by
 * application-defined 32-byte binary keys.
 *
 * Metadata fields:
 * - HashPrefix owner
 * - uint16_t balance (bit-packed prepaid-days counter plus flag bits;
 *   see assetDays() / isAsset* in types.h)
 * - uint32_t price (whole credits; multiply by PRICE_UNIT for internal units)
 *
 * content carries the AssetData payload.
 */
struct Asset {

  Asset() : ownerId_{}, content_{}, balance_(0), price_(0) {}

  Asset(HashPrefix ownerId, const AssetData& content, uint16_t balance,
        uint32_t price)
      : ownerId_(ownerId), content_(content), balance_(balance), price_(price) {}

  void setOwnerId(HashPrefix ownerId) { ownerId_ = ownerId; }
  void setOwnerId(const Hash& ownerFullKey) {
    ownerId_ = getHashPrefix(ownerFullKey);
  }
  HashPrefix getOwnerId() const { return ownerId_; }

  void setPrice(uint32_t price) { price_ = price; }
  uint32_t getPrice() const { return price_; }

  void setBalance(uint16_t balance) { balance_ = balance; }
  uint16_t getBalance() const { return balance_; }

  void setContent(const AssetData& content) { content_ = content; }
  const AssetData& getContent() const { return content_; }
  AssetData& accessContent() { return content_; }

  enum class SerMode : uint8_t {
    Full = 0x00,    // all fields (create, full update, snapshots)
    Content = 0x01, // content only (NOTE: intentionally unused)
    Meta = 0x02,    // ownerId + price (updateAssetMeta, buy, give)
    Balance = 0x03, // balance only (fund, daily maintenance)
    None = 0x04     // erased object
  };

  CES_PERSISTED_BOILERPLATE(SerMode::Full)

private:
  HashPrefix ownerId_;
  AssetData content_;
  uint16_t balance_;
  uint32_t price_;
};

} // namespace ces

// --- Custom logkv serializer for ces::Asset ---

namespace logkv {

template <>
struct serializer<ces::Asset> {

  using SerMode = ces::Asset::SerMode;

  static constexpr size_t SZ_OWNER = sizeof(ces::HashPrefix);
  static constexpr size_t SZ_CONTENT = sizeof(ces::AssetData);
  static constexpr size_t SZ_BALANCE = sizeof(uint16_t);
  static constexpr size_t SZ_PRICE = sizeof(uint32_t);

  static constexpr size_t SZ_HEADER = 1;
  static constexpr size_t SZ_META = SZ_OWNER + SZ_PRICE;
  static constexpr size_t SZ_ALL = SZ_OWNER + SZ_CONTENT + SZ_BALANCE + SZ_PRICE;

  static bool is_empty(const ces::Asset& obj) {
    return ces::assetDays(obj.getBalance()) == 0 && obj.getPrice() == 0 &&
           obj.getOwnerId() == ces::HashPrefix{};
  }

  static size_t get_size(const ces::Asset& obj) {
    if (ces::Asset::_logkvStoreSnapshot())
      return SZ_ALL;

    SerMode mode = ces::Asset::_getSerMode();

    if (is_empty(obj))
      return SZ_HEADER;

    switch (mode) {
    case SerMode::Full:
      return SZ_HEADER + SZ_ALL;
    case SerMode::Content:
      return SZ_HEADER + SZ_CONTENT;
    case SerMode::Meta:
      return SZ_HEADER + SZ_META;
    case SerMode::Balance:
      return SZ_HEADER + SZ_BALANCE;
    case SerMode::None:
      return SZ_HEADER;
    }
    return SZ_HEADER;
  }

  static size_t write(char* dest, size_t size, const ces::Asset& obj) {
    Writer writer(dest, size);

    try {
      if (ces::Asset::_logkvStoreSnapshot()) {
        writer.write(obj.getOwnerId());
        writer.write(obj.getBalance());
        writer.write(obj.getPrice());
        writer.write(obj.getContent());
        return writer.bytes_processed();
      }

      bool objectIsEmpty = is_empty(obj);
      SerMode mode = ces::Asset::_getSerMode();

      uint8_t header = objectIsEmpty
        ? static_cast<uint8_t>(SerMode::None)
        : static_cast<uint8_t>(mode);
      writer.write(header);

      if (!objectIsEmpty) {
        switch (mode) {
        case SerMode::Full:
          writer.write(obj.getOwnerId());
          writer.write(obj.getBalance());
          writer.write(obj.getPrice());
          writer.write(obj.getContent());
          break;
        case SerMode::Content:
          writer.write(obj.getContent());
          break;
        case SerMode::Meta:
          writer.write(obj.getOwnerId());
          writer.write(obj.getPrice());
          break;
        case SerMode::Balance:
          writer.write(obj.getBalance());
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

  static size_t read(const char* src, size_t size, ces::Asset& obj) {
    Reader reader(src, size);

    try {
      if (ces::Asset::_logkvStoreSnapshot()) {
        ces::HashPrefix owner;
        uint16_t balance;
        uint32_t price;
        ces::AssetData content;
        reader.read(owner);
        reader.read(balance);
        reader.read(price);
        reader.read(content);
        obj = ces::Asset(owner, content, balance, price);
        return reader.bytes_processed();
      }

      uint8_t header;
      reader.read(header);

      switch (static_cast<SerMode>(header)) {
      case SerMode::None:
        obj = ces::Asset();
        break;
      case SerMode::Full: {
        ces::HashPrefix owner;
        uint16_t balance;
        uint32_t price;
        ces::AssetData content;
        reader.read(owner);
        reader.read(balance);
        reader.read(price);
        reader.read(content);
        obj = ces::Asset(owner, content, balance, price);
        break;
      }
      case SerMode::Content: {
        ces::AssetData content;
        reader.read(content);
        obj.setContent(content);
        break;
      }
      case SerMode::Meta: {
        ces::HashPrefix owner;
        uint32_t price;
        reader.read(owner);
        reader.read(price);
        obj.setOwnerId(owner);
        obj.setPrice(price);
        break;
      }
      case SerMode::Balance: {
        uint16_t balance;
        reader.read(balance);
        obj.setBalance(balance);
        break;
      }
      default:
        throw std::runtime_error("Invalid Asset serialization header");
      }
    } catch (const insufficient_buffer& e) {
      return reader.bytes_processed() + e.get_required_bytes();
    }
    return reader.bytes_processed();
  }
};

} // namespace logkv
