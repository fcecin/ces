// Pins the physical byte layout of ces::Alias and of the boost flat-map entry
// pair<const uint32_t, Alias> the alias store holds. The value is 60 bytes with
// zero padding; the entry is 64 bytes (4-byte id key + 60-byte value), one cache
// line. Also round-trips every field through the accessors and the serializer.

#include "test_common.h"

#include <ces/alias.h>
#include <ces/types.h>

#include <boost/unordered/unordered_flat_map.hpp>

#include <array>
#include <cstddef>
#include <string>
#include <type_traits>

BOOST_AUTO_TEST_SUITE(AliasLayoutTests)

using AliasMap = boost::unordered_flat_map<uint32_t, ces::Alias>;
using AliasEntry = AliasMap::value_type;   // pair<const uint32_t, Alias>

// Field order: owner 0, op 8, content 10. Value 60, entry 64.
namespace expected {
constexpr std::size_t kSzOwner   = 8,  kAlOwner   = 1;
constexpr std::size_t kSzOp      = 2,  kAlOp      = 2;
constexpr std::size_t kSzContent = 50, kAlContent = 1;

constexpr std::size_t kOffOwner   = 0;
constexpr std::size_t kOffOp      = 8;
constexpr std::size_t kOffContent = 10;

constexpr std::size_t kSzAlias = 60;
constexpr std::size_t kAlAlias = 2;

constexpr std::size_t kSumPayload = kSzOwner + kSzOp + kSzContent;
constexpr std::size_t kPadding = kSzAlias - kSumPayload;

constexpr std::size_t kSzKey     = 4;
constexpr std::size_t kOffSecond = 4;
constexpr std::size_t kSzEntry   = 64;
constexpr std::size_t kAlEntry   = 4;
} // namespace expected

static_assert(sizeof(ces::Alias) == expected::kSzAlias, "Alias value is 60 bytes");
static_assert(alignof(ces::Alias) == expected::kAlAlias);
static_assert(sizeof(ces::Alias) % alignof(ces::Alias) == 0);
static_assert(std::is_standard_layout_v<ces::Alias>);
static_assert(std::is_trivially_copyable_v<ces::Alias>);
static_assert(sizeof(ces::HashPrefix) == expected::kSzOwner);
static_assert(sizeof(uint16_t) == expected::kSzOp);
static_assert(sizeof(ces::AliasData) == expected::kSzContent);
static_assert(sizeof(uint32_t) == expected::kSzKey);
static_assert(sizeof(AliasEntry) == expected::kSzEntry, "alias entry is 64 bytes (one cache line)");
static_assert(alignof(AliasEntry) == expected::kAlEntry);
static_assert(expected::kSumPayload == 60);
static_assert(expected::kPadding == 0);

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
  BOOST_CHECK_EQUAL(fieldOffset(a, a.opPtr()),      expected::kOffOp);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.contentPtr()), expected::kOffContent);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.opPtr()) - fieldOffset(a, a.ownerPtr()),
                    expected::kSzOwner);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.contentPtr()) - fieldOffset(a, a.opPtr()),
                    expected::kSzOp);
  BOOST_CHECK_EQUAL(sizeof(ces::Alias) - fieldOffset(a, a.contentPtr()),
                    expected::kSzContent);
}

BOOST_AUTO_TEST_CASE(MapEntrySplit) {
  BOOST_CHECK_EQUAL(offsetof(AliasEntry, first),  0u);
  BOOST_CHECK_EQUAL(offsetof(AliasEntry, second), expected::kOffSecond);
  BOOST_CHECK_EQUAL(sizeof(AliasEntry),           expected::kSzEntry);
  BOOST_CHECK_EQUAL(sizeof(AliasEntry),
                    offsetof(AliasEntry, second) + sizeof(ces::Alias));
}

static ces::Alias makeDistinctAlias() {
  ces::HashPrefix owner; owner.fill(0x5A);
  ces::AliasData content;
  for (std::size_t i = 0; i < content.size(); ++i)
    content[i] = static_cast<uint8_t>(i + 1);
  return ces::Alias(owner, static_cast<uint16_t>(0xBEEF), content);
}

static void checkAlias(const ces::Alias& a) {
  ces::HashPrefix owner; owner.fill(0x5A);
  BOOST_CHECK(a.getOwner() == owner);
  BOOST_CHECK_EQUAL(a.getOp(), static_cast<uint16_t>(0xBEEF));
  for (std::size_t i = 0; i < a.getContent().size(); ++i)
    BOOST_CHECK_EQUAL(a.getContent()[i], static_cast<uint8_t>(i + 1));
}

BOOST_AUTO_TEST_CASE(AccessorRoundTrip) {
  checkAlias(makeDistinctAlias());
}

BOOST_AUTO_TEST_CASE(FullSerializerRoundTrip) {
  ces::Alias in = makeDistinctAlias();
  char buf[128];
  size_t n = logkv::serializer<ces::Alias>::write(buf, sizeof(buf), in);
  BOOST_REQUIRE(n > 0 && n <= sizeof(buf));
  ces::Alias out;
  logkv::serializer<ces::Alias>::read(buf, n, out);
  checkAlias(out);
}

BOOST_AUTO_TEST_SUITE_END()
