#pragma once

#include <ces/persisted.h>
#include <ces/types.h>
#include <logkv/autoser.h>

namespace ces {

using AliasData = std::array<uint8_t, 50>;

// Alias op enum: the uint16 in the value, a hardcoded system operation code.
// 16 bits (65536 codes); the vocabulary grows as features land.
constexpr uint16_t ALIAS_OP_NONE   = 0x0000; // raw uninterpreted bytes (default); render as hex
constexpr uint16_t ALIAS_OP_STRING = 0x0001; // UTF-8 text; render as text
constexpr uint16_t ALIAS_OP_SYSTEM = 0xFFFF; // reserved: the id-generator cell (id 0)

/**
 * Alias: a server-allocated, ID-keyed 64-byte sidecar bound to one account.
 * The boost flat-map entry is pair<const uint32_t, Alias>: a 4-byte id key and
 * this 60-byte value, 64 bytes total, one cache line. Fields are ordered for
 * zero padding; the layout is pinned in tests/test_alias_layout.cpp.
 *
 * - owner: HashPrefix, the owning account (server-set at create, not forgeable).
 * - op: uint16_t, the system operation enum (hardcoded; see local/aliases.md).
 * - content: 50 bytes of payload whose meaning is defined by op.
 *
 * No per-cell balance: an alias is funded by its owner account (daily rent at
 * the feeAccount rate). One alias per account; the account holds its id in
 * aliasId.
 */
struct Alias {

  Alias() : owner_{}, op_(0), content_{} {}

  Alias(HashPrefix owner, uint16_t op, const AliasData& content)
      : owner_(owner), op_(op), content_(content) {}

  void setOwner(HashPrefix owner) { owner_ = owner; }
  void setOwner(const Hash& ownerFullKey) {
    owner_ = getHashPrefix(ownerFullKey);
  }
  HashPrefix getOwner() const { return owner_; }

  void setOp(uint16_t op) { op_ = op; }
  uint16_t getOp() const { return op_; }

  void setContent(const AliasData& content) { content_ = content; }
  const AliasData& getContent() const { return content_; }
  AliasData& accessContent() { return content_; }

  const HashPrefix* ownerPtr()   const { return &owner_; }
  const uint16_t*   opPtr()      const { return &op_; }
  const AliasData*  contentPtr() const { return &content_; }

  enum class SerMode : uint8_t {
    Full = 0x00, // owner + op + content (set, snapshots)
    None = 0x01  // erased object
  };

  CES_PERSISTED_BOILERPLATE(SerMode::Full)

private:
  HashPrefix owner_;
  uint16_t op_;
  AliasData content_;
};

} // namespace ces

// --- Custom logkv serializer for ces::Alias ---

namespace logkv {

template <>
struct serializer<ces::Alias> {

  using SerMode = ces::Alias::SerMode;

  static constexpr size_t SZ_OWNER = sizeof(ces::HashPrefix);
  static constexpr size_t SZ_OP = sizeof(uint16_t);
  static constexpr size_t SZ_CONTENT = sizeof(ces::AliasData);

  static constexpr size_t SZ_HEADER = 1;
  static constexpr size_t SZ_ALL = SZ_OWNER + SZ_OP + SZ_CONTENT;

  // An alias is empty (erased) only when owner and op are both zero. Entry 0
  // (the id generator) carries a non-zero system op, so it is never empty.
  static bool is_empty(const ces::Alias& obj) {
    return obj.getOwner() == ces::HashPrefix{} && obj.getOp() == 0;
  }

  static size_t get_size(const ces::Alias& obj) {
    if (ces::Alias::_logkvStoreSnapshot())
      return SZ_ALL;
    if (is_empty(obj))
      return SZ_HEADER;
    return SZ_HEADER + SZ_ALL;
  }

  static size_t write(char* dest, size_t size, const ces::Alias& obj) {
    Writer writer(dest, size);
    try {
      if (ces::Alias::_logkvStoreSnapshot()) {
        writer.write(obj.getOwner());
        writer.write(obj.getOp());
        writer.write(obj.getContent());
        return writer.bytes_processed();
      }

      bool objectIsEmpty = is_empty(obj);
      uint8_t header = objectIsEmpty
        ? static_cast<uint8_t>(SerMode::None)
        : static_cast<uint8_t>(SerMode::Full);
      writer.write(header);

      if (!objectIsEmpty) {
        writer.write(obj.getOwner());
        writer.write(obj.getOp());
        writer.write(obj.getContent());
      }
    } catch (const insufficient_buffer& e) {
      return writer.bytes_processed() + e.get_required_bytes();
    }
    return writer.bytes_processed();
  }

  static size_t read(const char* src, size_t size, ces::Alias& obj) {
    Reader reader(src, size);
    try {
      if (ces::Alias::_logkvStoreSnapshot()) {
        ces::HashPrefix owner;
        uint16_t op;
        ces::AliasData content;
        reader.read(owner);
        reader.read(op);
        reader.read(content);
        obj = ces::Alias(owner, op, content);
        return reader.bytes_processed();
      }

      uint8_t header;
      reader.read(header);

      switch (static_cast<SerMode>(header)) {
      case SerMode::None:
        obj = ces::Alias();
        break;
      case SerMode::Full: {
        ces::HashPrefix owner;
        uint16_t op;
        ces::AliasData content;
        reader.read(owner);
        reader.read(op);
        reader.read(content);
        obj = ces::Alias(owner, op, content);
        break;
      }
      default:
        throw std::runtime_error("Invalid Alias serialization header");
      }
    } catch (const insufficient_buffer& e) {
      return reader.bytes_processed() + e.get_required_bytes();
    }
    return reader.bytes_processed();
  }
};

} // namespace logkv
