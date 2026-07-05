// Pins the physical byte layout of ces::Asset and of the boost flat-map entry
// pair<const minx::Hash, Asset> the asset store holds. The value is 224 bytes
// with zero padding; the entry is 256 bytes (32-byte key + 224-byte value).
// Field sizes, alignments, offsets, and consecutive deltas are checked on both
// a naked stack struct and a live map entry, through Asset's typed field
// pointers. A drift fails a static_assert at build time or a check at run time.

#include "test_common.h"

#include <ces/asset.h>
#include <ces/types.h>

#include <boost/unordered/unordered_flat_map.hpp>

#include <cstddef>
#include <string>
#include <type_traits>

BOOST_AUTO_TEST_SUITE(AssetLayoutTests)

using AssetMap = boost::unordered_flat_map<minx::Hash, ces::Asset>;
using AssetEntry = AssetMap::value_type;   // pair<const minx::Hash, Asset>

// Field order: ownerId 0, content 8, balance 218, price 220. Value 224, entry 256.
namespace expected {
constexpr std::size_t kSzOwner   = 8,   kAlOwner   = 1;
constexpr std::size_t kSzContent = 210, kAlContent = 1;
constexpr std::size_t kSzBalance = 2,   kAlBalance = 2;
constexpr std::size_t kSzPrice   = 4,   kAlPrice   = 4;

constexpr std::size_t kOffOwner   = 0;
constexpr std::size_t kOffContent = 8;
constexpr std::size_t kOffBalance = 218;
constexpr std::size_t kOffPrice   = 220;

constexpr std::size_t kDeltaOwnerToContent   = 8;
constexpr std::size_t kDeltaContentToBalance = 210;
constexpr std::size_t kDeltaBalanceToPrice   = 2;
constexpr std::size_t kDeltaPriceToEnd       = 4;

constexpr std::size_t kSzAsset = 224;
constexpr std::size_t kAlAsset = 4;

constexpr std::size_t kSumPayload = kSzOwner + kSzContent + kSzBalance + kSzPrice;
constexpr std::size_t kPadding = kSzAsset - kSumPayload;

constexpr std::size_t kSzKey     = 32;
constexpr std::size_t kOffSecond = 32;
constexpr std::size_t kSzEntry   = 256;
constexpr std::size_t kAlEntry   = 4;
} // namespace expected

static_assert(sizeof(ces::Asset) == expected::kSzAsset, "Asset value is 224 bytes");
static_assert(alignof(ces::Asset) == expected::kAlAsset);
static_assert(sizeof(ces::Asset) % alignof(ces::Asset) == 0);
static_assert(std::is_standard_layout_v<ces::Asset>);
static_assert(std::is_trivially_copyable_v<ces::Asset>);
static_assert(sizeof(ces::HashPrefix) == expected::kSzOwner);
static_assert(alignof(ces::HashPrefix) == expected::kAlOwner);
static_assert(sizeof(ces::AssetData) == expected::kSzContent);
static_assert(alignof(ces::AssetData) == expected::kAlContent);
static_assert(sizeof(uint16_t) == expected::kSzBalance);
static_assert(sizeof(uint32_t) == expected::kSzPrice);
static_assert(sizeof(minx::Hash) == expected::kSzKey);
static_assert(alignof(minx::Hash) == 1);
static_assert(sizeof(AssetEntry) == expected::kSzEntry, "asset entry is 256 bytes");
static_assert(alignof(AssetEntry) == expected::kAlEntry);
static_assert(expected::kSumPayload == 224);
static_assert(expected::kPadding == 0);

// Byte offset of a field within an object.
static std::size_t fieldOffset(const ces::Asset& a, const void* field) {
  return static_cast<std::size_t>(reinterpret_cast<const std::byte*>(field) -
                                  reinterpret_cast<const std::byte*>(&a));
}

// Offsets and deltas of every field, checked against any Asset instance.
static void checkFullFieldLayout(const ces::Asset& a, const std::string& origin) {
  BOOST_TEST_INFO("origin=" << origin);

  const std::size_t offOwner   = fieldOffset(a, a.ownerIdPtr());
  const std::size_t offContent = fieldOffset(a, a.contentPtr());
  const std::size_t offBalance = fieldOffset(a, a.balancePtr());
  const std::size_t offPrice   = fieldOffset(a, a.pricePtr());

  BOOST_CHECK_EQUAL(offOwner,   expected::kOffOwner);
  BOOST_CHECK_EQUAL(offContent, expected::kOffContent);
  BOOST_CHECK_EQUAL(offBalance, expected::kOffBalance);
  BOOST_CHECK_EQUAL(offPrice,   expected::kOffPrice);

  BOOST_CHECK_EQUAL(offContent - offOwner,   expected::kDeltaOwnerToContent);
  BOOST_CHECK_EQUAL(offBalance - offContent, expected::kDeltaContentToBalance);
  BOOST_CHECK_EQUAL(offPrice   - offBalance, expected::kDeltaBalanceToPrice);
  BOOST_CHECK_EQUAL(sizeof(ces::Asset) - offPrice, expected::kDeltaPriceToEnd);

  BOOST_CHECK_EQUAL(offOwner, 0u);
  BOOST_CHECK_EQUAL(offPrice + expected::kSzPrice, sizeof(ces::Asset));

  const std::size_t tiled =
      (offContent - offOwner) + (offBalance - offContent) +
      (offPrice - offBalance) + (sizeof(ces::Asset) - offPrice);
  BOOST_CHECK_EQUAL(tiled, sizeof(ces::Asset));
}

static minx::Hash makeKey(uint8_t seed) {
  minx::Hash h{};
  for (std::size_t i = 0; i < h.size(); ++i)
    h[i] = static_cast<uint8_t>(seed + i);
  return h;
}

// Field type sizes and alignments.
BOOST_AUTO_TEST_CASE(TypeSizesAndAligns) {
  BOOST_CHECK_EQUAL(sizeof(ces::HashPrefix),  expected::kSzOwner);
  BOOST_CHECK_EQUAL(alignof(ces::HashPrefix), expected::kAlOwner);
  BOOST_CHECK_EQUAL(sizeof(ces::AssetData),   expected::kSzContent);
  BOOST_CHECK_EQUAL(alignof(ces::AssetData),  expected::kAlContent);
  BOOST_CHECK_EQUAL(sizeof(uint16_t),         expected::kSzBalance);
  BOOST_CHECK_EQUAL(alignof(uint16_t),        expected::kAlBalance);
  BOOST_CHECK_EQUAL(sizeof(uint32_t),         expected::kSzPrice);
  BOOST_CHECK_EQUAL(alignof(uint32_t),        expected::kAlPrice);
}

// Struct size, alignment, standard-layout traits.
BOOST_AUTO_TEST_CASE(StructSizeAlignAndTraits) {
  BOOST_CHECK_EQUAL(sizeof(ces::Asset),  expected::kSzAsset);
  BOOST_CHECK_EQUAL(alignof(ces::Asset), expected::kAlAsset);
  BOOST_CHECK_EQUAL(sizeof(ces::Asset) % alignof(ces::Asset), 0u);
  BOOST_CHECK(std::is_standard_layout_v<ces::Asset>);
  BOOST_CHECK(std::is_trivially_copyable_v<ces::Asset>);
}

// Field payloads sum to sizeof: zero padding.
BOOST_AUTO_TEST_CASE(PaddingAccounting) {
  BOOST_CHECK_EQUAL(expected::kSumPayload, 224u);
  BOOST_CHECK_EQUAL(expected::kPadding, 0u);
  BOOST_CHECK_EQUAL(expected::kSumPayload, sizeof(ces::Asset));
}

// Naked stack struct: field offsets.
BOOST_AUTO_TEST_CASE(NakedStruct_FieldOffsets) {
  ces::Asset a;
  BOOST_CHECK_EQUAL(fieldOffset(a, a.ownerIdPtr()), expected::kOffOwner);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.contentPtr()), expected::kOffContent);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.balancePtr()), expected::kOffBalance);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.pricePtr()),   expected::kOffPrice);
}

// Naked stack struct: consecutive field deltas.
BOOST_AUTO_TEST_CASE(NakedStruct_FieldDeltas) {
  ces::Asset a;
  BOOST_CHECK_EQUAL(fieldOffset(a, a.contentPtr()) - fieldOffset(a, a.ownerIdPtr()), expected::kDeltaOwnerToContent);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.balancePtr()) - fieldOffset(a, a.contentPtr()), expected::kDeltaContentToBalance);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.pricePtr())   - fieldOffset(a, a.balancePtr()), expected::kDeltaBalanceToPrice);
  BOOST_CHECK_EQUAL(sizeof(ces::Asset)             - fieldOffset(a, a.pricePtr()),   expected::kDeltaPriceToEnd);
}

BOOST_AUTO_TEST_CASE(NakedStruct_FullLayout) {
  ces::Asset a;
  checkFullFieldLayout(a, "naked-stack-struct");
}

// Map entry: whole-entry size and key/value split.
BOOST_AUTO_TEST_CASE(MapEntry_SizeAndSplit) {
  BOOST_CHECK_EQUAL(sizeof(minx::Hash),           expected::kSzKey);
  BOOST_CHECK_EQUAL(offsetof(AssetEntry, first),  0u);
  BOOST_CHECK_EQUAL(offsetof(AssetEntry, second), expected::kOffSecond);
  BOOST_CHECK_EQUAL(sizeof(AssetEntry),           expected::kSzEntry);
  BOOST_CHECK_EQUAL(alignof(AssetEntry),          expected::kAlEntry);
  BOOST_CHECK_EQUAL(offsetof(AssetEntry, second), sizeof(minx::Hash));
  BOOST_CHECK_EQUAL(sizeof(AssetEntry),
                    offsetof(AssetEntry, second) + sizeof(ces::Asset));
}

// Live map entry: value offset within the pair.
BOOST_AUTO_TEST_CASE(MapEntry_LiveValueSplit) {
  AssetMap map;
  const minx::Hash key = makeKey(1);
  map.emplace(key, ces::Asset());
  auto it = map.find(key);
  BOOST_REQUIRE(it != map.end());

  const AssetEntry& entry = *it;
  const auto* entryBase = reinterpret_cast<const std::byte*>(&entry);
  const auto* keyBase   = reinterpret_cast<const std::byte*>(&entry.first);
  const auto* valueBase = reinterpret_cast<const std::byte*>(&entry.second);

  BOOST_CHECK_EQUAL(static_cast<std::size_t>(keyBase - entryBase), 0u);
  BOOST_CHECK_EQUAL(static_cast<std::size_t>(valueBase - entryBase), expected::kOffSecond);
}

// Live map entry: mapped-value field offsets match the naked struct.
BOOST_AUTO_TEST_CASE(MapEntry_FieldOffsets) {
  AssetMap map;
  const minx::Hash key = makeKey(10);
  map.emplace(key, ces::Asset());
  const ces::Asset& v = map.find(key)->second;

  BOOST_CHECK_EQUAL(fieldOffset(v, v.ownerIdPtr()), expected::kOffOwner);
  BOOST_CHECK_EQUAL(fieldOffset(v, v.contentPtr()), expected::kOffContent);
  BOOST_CHECK_EQUAL(fieldOffset(v, v.balancePtr()), expected::kOffBalance);
  BOOST_CHECK_EQUAL(fieldOffset(v, v.pricePtr()),   expected::kOffPrice);
}

// Live map entry: consecutive field deltas.
BOOST_AUTO_TEST_CASE(MapEntry_FieldDeltas) {
  AssetMap map;
  const minx::Hash key = makeKey(20);
  map.emplace(key, ces::Asset());
  const ces::Asset& v = map.find(key)->second;

  BOOST_CHECK_EQUAL(fieldOffset(v, v.contentPtr()) - fieldOffset(v, v.ownerIdPtr()), expected::kDeltaOwnerToContent);
  BOOST_CHECK_EQUAL(fieldOffset(v, v.balancePtr()) - fieldOffset(v, v.contentPtr()), expected::kDeltaContentToBalance);
  BOOST_CHECK_EQUAL(fieldOffset(v, v.pricePtr())   - fieldOffset(v, v.balancePtr()), expected::kDeltaBalanceToPrice);
  BOOST_CHECK_EQUAL(sizeof(ces::Asset)             - fieldOffset(v, v.pricePtr()),   expected::kDeltaPriceToEnd);
}

BOOST_AUTO_TEST_CASE(MapEntry_FullLayout) {
  AssetMap map;
  const minx::Hash key = makeKey(30);
  map.emplace(key, ces::Asset());
  checkFullFieldLayout(map.find(key)->second, "boost-flat-map-value");
}

// Live map entry: absolute field offset within the entry = value split + field offset.
BOOST_AUTO_TEST_CASE(MapEntry_AbsoluteFieldOffsetsWithinEntry) {
  AssetMap map;
  const minx::Hash key = makeKey(40);
  map.emplace(key, ces::Asset());
  const AssetEntry& entry = *map.find(key);
  const ces::Asset& v = entry.second;

  const auto* entryBase = reinterpret_cast<const std::byte*>(&entry);
  auto absOff = [&](const void* field) {
    return static_cast<std::size_t>(
        reinterpret_cast<const std::byte*>(field) - entryBase);
  };

  BOOST_CHECK_EQUAL(absOff(v.ownerIdPtr()), expected::kOffSecond + expected::kOffOwner);
  BOOST_CHECK_EQUAL(absOff(v.contentPtr()), expected::kOffSecond + expected::kOffContent);
  BOOST_CHECK_EQUAL(absOff(v.balancePtr()), expected::kOffSecond + expected::kOffBalance);
  BOOST_CHECK_EQUAL(absOff(v.pricePtr()),   expected::kOffSecond + expected::kOffPrice);
  BOOST_CHECK_EQUAL(absOff(v.pricePtr()) + expected::kSzPrice, sizeof(AssetEntry));
}

// Naked struct and mapped value report identical field offsets.
BOOST_AUTO_TEST_CASE(NakedAndMap_IdenticalFieldOffsets) {
  ces::Asset naked;
  AssetMap map;
  const minx::Hash key = makeKey(50);
  map.emplace(key, ces::Asset());
  const ces::Asset& mapped = map.find(key)->second;

  BOOST_CHECK_EQUAL(fieldOffset(naked, naked.ownerIdPtr()), fieldOffset(mapped, mapped.ownerIdPtr()));
  BOOST_CHECK_EQUAL(fieldOffset(naked, naked.contentPtr()), fieldOffset(mapped, mapped.contentPtr()));
  BOOST_CHECK_EQUAL(fieldOffset(naked, naked.balancePtr()), fieldOffset(mapped, mapped.balancePtr()));
  BOOST_CHECK_EQUAL(fieldOffset(naked, naked.pricePtr()),   fieldOffset(mapped, mapped.pricePtr()));
}

BOOST_AUTO_TEST_SUITE_END()
