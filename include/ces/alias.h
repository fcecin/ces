#pragma once

#include <ces/persisted.h>
#include <ces/types.h>
#include <logkv/autoser.h>

#include <cstddef>
#include <type_traits>

namespace ces {

// Alias layout, single source of truth. The flat-map entry is a 4-byte id key
// plus the value image; the image is owner | editor | op | content with zero
// padding, so every offset derives from the field sizes. Patch writes and
// windowed reads address the value image by these offsets. The op field is
// host-endian in the image (little-endian on all supported targets).
constexpr size_t ALIAS_ENTRY_BYTES = 1024;               // id key + value image
constexpr size_t ALIAS_ID_BYTES    = sizeof(uint32_t);
constexpr size_t ALIAS_VALUE_BYTES = ALIAS_ENTRY_BYTES - ALIAS_ID_BYTES;

constexpr size_t ALIAS_OFF_OWNER   = 0;
constexpr size_t ALIAS_OFF_EDITOR  = ALIAS_OFF_OWNER + sizeof(HashPrefix);
constexpr size_t ALIAS_OFF_OP      = ALIAS_OFF_EDITOR + sizeof(HashPrefix);
constexpr size_t ALIAS_OFF_CONTENT = ALIAS_OFF_OP + sizeof(uint16_t);
constexpr size_t ALIAS_CONTENT_BYTES = ALIAS_VALUE_BYTES - ALIAS_OFF_CONTENT;

// Patch floors: the owner may write everything but the server-set owner field;
// the editor may write content only, never the header.
constexpr size_t ALIAS_PATCH_MIN_OWNER  = ALIAS_OFF_EDITOR;
constexpr size_t ALIAS_PATCH_MIN_EDITOR = ALIAS_OFF_CONTENT;

// Inline program layout: for the ALIAS_OP_INLINE_* ops the content is split
// into a fixed-size code area (always loaded whole, zero-padded, so
// SYS_LOAD_CODE bases stay link-time constants) and an 8-byte trailer
// carrying the hook refill ceiling (u64 LE; meaningful for INLINE_HOOK_WATCH,
// forced 0 for gates like the pointer form).
constexpr size_t ALIAS_INLINE_CEILING_BYTES = sizeof(uint64_t);
constexpr size_t ALIAS_INLINE_CODE_BYTES =
  ALIAS_CONTENT_BYTES - ALIAS_INLINE_CEILING_BYTES;
constexpr size_t ALIAS_OFF_INLINE_CEILING =
  ALIAS_OFF_CONTENT + ALIAS_INLINE_CODE_BYTES;

using AliasData = std::array<uint8_t, ALIAS_CONTENT_BYTES>;

// Alias op enum: the uint16 in the value, a hardcoded system operation code.
// 16 bits (65536 codes); the vocabulary grows as features land.
constexpr uint16_t ALIAS_OP_NONE   = 0x0000; // raw uninterpreted bytes (default); render as hex
constexpr uint16_t ALIAS_OP_STRING = 0x0001; // UTF-8 text; render as text
// Account hooks (CESVM triggers). The op selects when the trigger runs and its
// failure mode; the content's first 32 bytes are the trigger program's asset
// key (see local/account_hooks_design.md). Set-time: the server enforces the
// target asset is IMMUTABLE or owned by the setter (CES_ERROR_HOOK_TARGET).
constexpr uint16_t ALIAS_OP_HOOK_GATE  = 0x0010; // runs before the credit; may
                                                 // reject (fail-closed). v1.
constexpr uint16_t ALIAS_OP_HOOK_WATCH = 0x0011; // runs after the credit;
                                                 // observe-only (fail-open). v2.
// Inline programs: the content IS the bytecode (ALIAS_INLINE_CODE_BYTES at
// base 0 + the ceiling trailer), no trigger asset, no set-time target check.
// Code in the owner's own cell is consented code: the cell's owner is the
// run's programOwner (gates stay principal-less for purity).
constexpr uint16_t ALIAS_OP_INLINE_HOOK_GATE  = 0x0012; // inline fail-closed gate
constexpr uint16_t ALIAS_OP_INLINE_HOOK_WATCH = 0x0013; // inline fail-open watch
constexpr uint16_t ALIAS_OP_INLINE_PROGRAM    = 0x0014; // publicly invocable
                                                        // (CES_RUN_ALIAS /
                                                        // SYS_SCHEDULE_ALIAS);
                                                        // never deposit-fired
constexpr uint16_t ALIAS_OP_SYSTEM = 0xFFFF; // reserved: the id-generator cell (id 0)

// True if an alias op is a POINTER account-hook (content[0..32) = trigger
// asset key; the set-time immutable-or-owned target check applies).
inline bool aliasOpIsHook(uint16_t op) {
  return op == ALIAS_OP_HOOK_GATE || op == ALIAS_OP_HOOK_WATCH;
}
// True if the content is inline bytecode (any ALIAS_OP_INLINE_* op).
inline bool aliasOpIsInline(uint16_t op) {
  return op == ALIAS_OP_INLINE_HOOK_GATE || op == ALIAS_OP_INLINE_HOOK_WATCH ||
         op == ALIAS_OP_INLINE_PROGRAM;
}
// Hook class matchers across pointer and inline forms.
inline bool aliasOpIsGate(uint16_t op) {
  return op == ALIAS_OP_HOOK_GATE || op == ALIAS_OP_INLINE_HOOK_GATE;
}
inline bool aliasOpIsWatch(uint16_t op) {
  return op == ALIAS_OP_HOOK_WATCH || op == ALIAS_OP_INLINE_HOOK_WATCH;
}

/**
 * Alias: a server-allocated, ID-keyed sidecar bound to one account.
 * The boost flat-map entry is pair<const uint32_t, Alias>: a 4-byte id key and
 * a 1020-byte value, 1024 bytes total with zero padding anywhere. The layout
 * is pinned in tests/test_alias_layout.cpp.
 *
 * - owner: HashPrefix, the owning account (server-set at create, not
 *   forgeable; may never be patched).
 * - editor: HashPrefix, an account granted content-only write access
 *   (all-zero = no grant). Owner-set via patch.
 * - op: uint16_t, the system operation enum (hardcoded). Owner-set.
 * - content: ALIAS_CONTENT_BYTES of payload whose meaning is defined by op.
 *
 * No per-cell balance: an alias is funded by its owner account (daily rent at
 * the feeAlias rate). One alias per account; the account holds its id in
 * aliasId.
 */
struct Alias {

  Alias() : owner_{}, editor_{}, op_(0), content_{} {}

  Alias(HashPrefix owner, HashPrefix editor, uint16_t op,
        const AliasData& content)
      : owner_(owner), editor_(editor), op_(op), content_(content) {}

  void setOwner(HashPrefix owner) { owner_ = owner; }
  void setOwner(const Hash& ownerFullKey) {
    owner_ = getHashPrefix(ownerFullKey);
  }
  HashPrefix getOwner() const { return owner_; }

  void setEditor(HashPrefix editor) { editor_ = editor; }
  HashPrefix getEditor() const { return editor_; }

  void setOp(uint16_t op) { op_ = op; }
  uint16_t getOp() const { return op_; }

  void setContent(const AliasData& content) { content_ = content; }
  const AliasData& getContent() const { return content_; }
  AliasData& accessContent() { return content_; }

  // Raw value image (owner|editor|op|content) for patch writes and windowed
  // reads. Valid because the layout is standard, trivially copyable, and
  // padding-free (static_asserts below; pinned in tests/test_alias_layout.cpp).
  uint8_t* imageData() { return reinterpret_cast<uint8_t*>(this); }
  const uint8_t* imageData() const {
    return reinterpret_cast<const uint8_t*>(this);
  }

  const HashPrefix* ownerPtr()   const { return &owner_; }
  const HashPrefix* editorPtr()  const { return &editor_; }
  const uint16_t*   opPtr()      const { return &op_; }
  const AliasData*  contentPtr() const { return &content_; }

  enum class SerMode : uint8_t {
    Full = 0x00, // owner + editor + op + content (set, snapshots)
    None = 0x01  // erased object
  };

  CES_PERSISTED_BOILERPLATE(SerMode::Full)

private:
  HashPrefix owner_;
  HashPrefix editor_;
  uint16_t op_;
  AliasData content_;
};

static_assert(sizeof(Alias) == ALIAS_VALUE_BYTES);
static_assert(std::is_standard_layout_v<Alias>);
static_assert(std::is_trivially_copyable_v<Alias>);

} // namespace ces

// --- Custom logkv serializer for ces::Alias ---

namespace logkv {

template <>
struct serializer<ces::Alias> {

  using SerMode = ces::Alias::SerMode;

  static constexpr size_t SZ_OWNER = sizeof(ces::HashPrefix);
  static constexpr size_t SZ_EDITOR = sizeof(ces::HashPrefix);
  static constexpr size_t SZ_OP = sizeof(uint16_t);
  static constexpr size_t SZ_CONTENT = sizeof(ces::AliasData);

  static constexpr size_t SZ_HEADER = 1;
  static constexpr size_t SZ_ALL = SZ_OWNER + SZ_EDITOR + SZ_OP + SZ_CONTENT;

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
        writer.write(obj.getEditor());
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
        writer.write(obj.getEditor());
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
        ces::HashPrefix editor;
        uint16_t op;
        ces::AliasData content;
        reader.read(owner);
        reader.read(editor);
        reader.read(op);
        reader.read(content);
        obj = ces::Alias(owner, editor, op, content);
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
        ces::HashPrefix editor;
        uint16_t op;
        ces::AliasData content;
        reader.read(owner);
        reader.read(editor);
        reader.read(op);
        reader.read(content);
        obj = ces::Alias(owner, editor, op, content);
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
