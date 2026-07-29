#pragma once

#include <ces/persisted.h>
#include <ces/types.h>

#include <logkv/autoser.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

// A key_name entry: the ledger's local, crypto-owned name registry.
//
// Map key = a 32-byte PUBLIC KEY. The key IS the owner -- there is no owner
// field, so only the holder of that key can register/update/delete its entry
// (the register op's signer must equal the map key). Value = the NAME, 32
// bytes UTF-8. So one entry is 32 (key) + 32 (name) = 64 bytes on the wire.
//
// Rent is NOT a per-entry balance: like an alias, the entry is funded by its
// key's ACCOUNT (getMapKey of the key) via the daily maintenance pass at the
// key_name rent rate (derived from feeAccount at the byte ratio, x2); an
// account that cannot pay loses its key_name(s).
//
// Uniqueness is bidirectional: one key -> at most one name (map-key unique,
// free), and one name -> at most one key (a reverse index the KeyNames wrapper
// maintains, checked under logicStrand_ at register time). The reverse index
// is DERIVED from this store, never a second authoritative copy, so snapshot
// and WAL replay reconstruct the same state.
namespace ces {

constexpr size_t KEYNAME_NAME_BYTES = 32;
using KeyNameData = std::array<uint8_t, KEYNAME_NAME_BYTES>;

struct KeyName {
  KeyName() : name_{} {}
  explicit KeyName(const KeyNameData& name) : name_(name) {}

  void setName(const KeyNameData& name) { name_ = name; }
  const KeyNameData& getName() const { return name_; }
  KeyNameData& accessName() { return name_; }

  enum class SerMode : uint8_t {
    Full = 0x00,  // name (set, snapshots)
    None = 0x01   // erased object
  };

  CES_PERSISTED_BOILERPLATE(SerMode::Full)

 private:
  KeyNameData name_;
};

static_assert(sizeof(KeyName) == KEYNAME_NAME_BYTES);
static_assert(std::is_standard_layout_v<KeyName>);
static_assert(std::is_trivially_copyable_v<KeyName>);

}  // namespace ces

// --- Custom logkv serializer for ces::KeyName ---

namespace logkv {

template <>
struct serializer<ces::KeyName> {
  using SerMode = ces::KeyName::SerMode;

  static constexpr size_t SZ_NAME = sizeof(ces::KeyNameData);
  static constexpr size_t SZ_HEADER = 1;

  // An empty (erased) entry has an all-zero name (a valid name is never empty).
  static bool is_empty(const ces::KeyName& obj) {
    return obj.getName() == ces::KeyNameData{};
  }

  static size_t get_size(const ces::KeyName& obj) {
    if (ces::KeyName::_logkvStoreSnapshot())
      return SZ_NAME;
    if (is_empty(obj))
      return SZ_HEADER;
    return SZ_HEADER + SZ_NAME;
  }

  static size_t write(char* dest, size_t size, const ces::KeyName& obj) {
    Writer writer(dest, size);
    try {
      if (ces::KeyName::_logkvStoreSnapshot()) {
        writer.write(obj.getName());
        return writer.bytes_processed();
      }
      const bool empty = is_empty(obj);
      writer.write(static_cast<uint8_t>(empty ? SerMode::None : SerMode::Full));
      if (!empty)
        writer.write(obj.getName());
    } catch (const insufficient_buffer& e) {
      return writer.bytes_processed() + e.get_required_bytes();
    }
    return writer.bytes_processed();
  }

  static size_t read(const char* src, size_t size, ces::KeyName& obj) {
    Reader reader(src, size);
    try {
      if (ces::KeyName::_logkvStoreSnapshot()) {
        ces::KeyNameData name;
        reader.read(name);
        obj = ces::KeyName(name);
        return reader.bytes_processed();
      }
      uint8_t header;
      reader.read(header);
      if (static_cast<SerMode>(header) == SerMode::None) {
        obj = ces::KeyName();
        return reader.bytes_processed();
      }
      ces::KeyNameData name;
      reader.read(name);
      obj = ces::KeyName(name);
    } catch (const insufficient_buffer&) {
      return 0;
    }
    return reader.bytes_processed();
  }
};

}  // namespace logkv
