// Pins the physical byte layout of ces::Alias and of the boost flat-map entry
// pair<const uint32_t, Alias> the alias store holds. The value image is
// owner(8) | editor(8) | op(2) | content(1002) = 1020 bytes with zero padding;
// the entry is 1024 bytes (4-byte id key + 1020-byte value, no tail pad).
// The patch/read wire ops address this exact image, so drift here is a
// protocol break. Also round-trips every field through the accessors and the
// serializer, and cross-pins the ALIAS_* layout constexprs.

#include "test_common.h"

#include <ces/alias.h>
#include <ces/types.h>

#include <boost/unordered/unordered_flat_map.hpp>

#include <array>
#include <cstddef>
#include <cstring>
#include <string>
#include <type_traits>

BOOST_AUTO_TEST_SUITE(AliasLayoutTests)

using AliasMap = boost::unordered_flat_map<uint32_t, ces::Alias>;
using AliasEntry = AliasMap::value_type;   // pair<const uint32_t, Alias>

// Field order: owner 0, editor 8, op 16, content 18. Value 1020, entry 1024.
namespace expected {
constexpr std::size_t kSzOwner   = 8,    kAlOwner   = 1;
constexpr std::size_t kSzEditor  = 8,    kAlEditor  = 1;
constexpr std::size_t kSzOp      = 2,    kAlOp      = 2;
constexpr std::size_t kSzContent = 1002, kAlContent = 1;

constexpr std::size_t kOffOwner   = 0;
constexpr std::size_t kOffEditor  = 8;
constexpr std::size_t kOffOp      = 16;
constexpr std::size_t kOffContent = 18;

constexpr std::size_t kSzAlias = 1020;
constexpr std::size_t kAlAlias = 2;

constexpr std::size_t kSumPayload = kSzOwner + kSzEditor + kSzOp + kSzContent;
constexpr std::size_t kPadding = kSzAlias - kSumPayload;

constexpr std::size_t kSzKey     = 4;
constexpr std::size_t kOffSecond = 4;
constexpr std::size_t kEntryPad  = 0;   // 4 + 1020 is already 4-aligned
constexpr std::size_t kSzEntry   = 1024;
constexpr std::size_t kAlEntry   = 4;
} // namespace expected

static_assert(sizeof(ces::Alias) == expected::kSzAlias, "Alias value is 1020 bytes");
static_assert(alignof(ces::Alias) == expected::kAlAlias);
static_assert(sizeof(ces::Alias) % alignof(ces::Alias) == 0);
static_assert(std::is_standard_layout_v<ces::Alias>);
static_assert(std::is_trivially_copyable_v<ces::Alias>);
static_assert(sizeof(ces::HashPrefix) == expected::kSzOwner);
static_assert(sizeof(uint16_t) == expected::kSzOp);
static_assert(sizeof(ces::AliasData) == expected::kSzContent);
static_assert(sizeof(uint32_t) == expected::kSzKey);
static_assert(sizeof(AliasEntry) == expected::kSzEntry, "alias entry is 1024 bytes");
static_assert(alignof(AliasEntry) == expected::kAlEntry);
static_assert(expected::kSumPayload == 1020);
static_assert(expected::kPadding == 0);

// The layout constexprs the patch/read ops are built on must match the pinned
// physical layout.
static_assert(ces::ALIAS_ENTRY_BYTES == expected::kSzEntry);
static_assert(ces::ALIAS_ID_BYTES == expected::kSzKey);
static_assert(ces::ALIAS_VALUE_BYTES == expected::kSzAlias);
static_assert(ces::ALIAS_OFF_OWNER == expected::kOffOwner);
static_assert(ces::ALIAS_OFF_EDITOR == expected::kOffEditor);
static_assert(ces::ALIAS_OFF_OP == expected::kOffOp);
static_assert(ces::ALIAS_OFF_CONTENT == expected::kOffContent);
static_assert(ces::ALIAS_CONTENT_BYTES == expected::kSzContent);
static_assert(ces::ALIAS_PATCH_MIN_OWNER == expected::kOffEditor);
static_assert(ces::ALIAS_PATCH_MIN_EDITOR == expected::kOffContent);

static std::size_t fieldOffset(const ces::Alias& a, const void* field) {
  return static_cast<std::size_t>(reinterpret_cast<const std::byte*>(field) -
                                  reinterpret_cast<const std::byte*>(&a));
}

BOOST_AUTO_TEST_CASE(StructSizeAlignTraits) {
  BOOST_CHECK_EQUAL(sizeof(ces::Alias),  expected::kSzAlias);
  BOOST_CHECK_EQUAL(alignof(ces::Alias), expected::kAlAlias);
  BOOST_CHECK(std::is_standard_layout_v<ces::Alias>);
  BOOST_CHECK(std::is_trivially_copyable_v<ces::Alias>);
  BOOST_CHECK_EQUAL(expected::kPadding, 0u);
  BOOST_CHECK_EQUAL(expected::kSumPayload, sizeof(ces::Alias));
}

BOOST_AUTO_TEST_CASE(FieldOffsets) {
  ces::Alias a;
  BOOST_CHECK_EQUAL(fieldOffset(a, a.ownerPtr()),   expected::kOffOwner);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.editorPtr()),  expected::kOffEditor);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.opPtr()),      expected::kOffOp);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.contentPtr()), expected::kOffContent);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.editorPtr()) - fieldOffset(a, a.ownerPtr()),
                    expected::kSzOwner);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.opPtr()) - fieldOffset(a, a.editorPtr()),
                    expected::kSzEditor);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.contentPtr()) - fieldOffset(a, a.opPtr()),
                    expected::kSzOp);
  BOOST_CHECK_EQUAL(sizeof(ces::Alias) - fieldOffset(a, a.contentPtr()),
                    expected::kSzContent);
  // imageData() is the address of the whole value image.
  BOOST_CHECK_EQUAL(fieldOffset(a, a.imageData()), 0u);
}

BOOST_AUTO_TEST_CASE(MapEntrySplit) {
  BOOST_CHECK_EQUAL(offsetof(AliasEntry, first),  0u);
  BOOST_CHECK_EQUAL(offsetof(AliasEntry, second), expected::kOffSecond);
  BOOST_CHECK_EQUAL(sizeof(AliasEntry),           expected::kSzEntry);
  BOOST_CHECK_EQUAL(sizeof(AliasEntry),
                    offsetof(AliasEntry, second) + sizeof(ces::Alias) +
                        expected::kEntryPad);
}

static ces::Alias makeDistinctAlias() {
  ces::HashPrefix owner; owner.fill(0x5A);
  ces::HashPrefix editor; editor.fill(0x3C);
  ces::AliasData content;
  for (std::size_t i = 0; i < content.size(); ++i)
    content[i] = static_cast<uint8_t>(i + 1);
  return ces::Alias(owner, editor, static_cast<uint16_t>(0xBEEF), content);
}

static void checkAlias(const ces::Alias& a) {
  ces::HashPrefix owner; owner.fill(0x5A);
  ces::HashPrefix editor; editor.fill(0x3C);
  BOOST_CHECK(a.getOwner() == owner);
  BOOST_CHECK(a.getEditor() == editor);
  BOOST_CHECK_EQUAL(a.getOp(), static_cast<uint16_t>(0xBEEF));
  for (std::size_t i = 0; i < a.getContent().size(); ++i)
    BOOST_CHECK_EQUAL(a.getContent()[i], static_cast<uint8_t>(i + 1));
}

BOOST_AUTO_TEST_CASE(AccessorRoundTrip) {
  checkAlias(makeDistinctAlias());
}

// A patch through imageData() at the pinned offsets lands in the right fields.
BOOST_AUTO_TEST_CASE(ImagePatchHitsFields) {
  ces::Alias a = makeDistinctAlias();
  ces::HashPrefix newEditor; newEditor.fill(0x77);
  std::memcpy(a.imageData() + ces::ALIAS_OFF_EDITOR, newEditor.data(),
              newEditor.size());
  uint16_t newOp = 0x1234;
  std::memcpy(a.imageData() + ces::ALIAS_OFF_OP, &newOp, sizeof(newOp));
  uint8_t b = 0xAB;
  std::memcpy(a.imageData() + ces::ALIAS_OFF_CONTENT + 5, &b, 1);
  BOOST_CHECK(a.getEditor() == newEditor);
  BOOST_CHECK_EQUAL(a.getOp(), newOp);
  BOOST_CHECK_EQUAL(a.getContent()[5], 0xAB);
  BOOST_CHECK_EQUAL(a.getContent()[4], 5);   // neighbors untouched
  BOOST_CHECK_EQUAL(a.getContent()[6], 7);
}

BOOST_AUTO_TEST_CASE(FullSerializerRoundTrip) {
  ces::Alias in = makeDistinctAlias();
  char buf[2048];
  size_t n = logkv::serializer<ces::Alias>::write(buf, sizeof(buf), in);
  BOOST_REQUIRE(n > 0 && n <= sizeof(buf));
  ces::Alias out;
  logkv::serializer<ces::Alias>::read(buf, n, out);
  checkAlias(out);
}

BOOST_AUTO_TEST_SUITE_END()
