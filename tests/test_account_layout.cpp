// Pins the physical byte layout of ces::Account and of the boost flat-map entry
// pair<const HashPrefix, Account> the account store holds. The value is 56 bytes
// with zero padding; the entry is 64 bytes (8-byte key + 56-byte value), one
// cache line. Field sizes, alignments, offsets, and consecutive deltas are
// checked on both a naked stack struct and a live map entry, through Account's
// typed field pointers. A drift fails a static_assert at build time or a check
// at run time.

#include "test_common.h"

#include <ces/account.h>
#include <ces/types.h>

#include <boost/unordered/unordered_flat_map.hpp>

#include <cstddef>
#include <string>
#include <type_traits>

BOOST_AUTO_TEST_SUITE(AccountLayoutTests)

using AccountMap = boost::unordered_flat_map<ces::HashPrefix, ces::Account>;
using AccountEntry = AccountMap::value_type;   // pair<const HashPrefix, Account>

// Field order: keyTail 0, balance 24, lastXferAmount 32, lastXferDest 40,
// lastXferTime 48, nonce 52. Value 56, entry 64.
namespace expected {
constexpr std::size_t kSzKeyTail    = 24, kAlKeyTail    = 1;
constexpr std::size_t kSzBalance    = 8,  kAlBalance    = 8;
constexpr std::size_t kSzNonce      = 4,  kAlNonce      = 4;
constexpr std::size_t kSzXferDest   = 8,  kAlXferDest   = 1;
constexpr std::size_t kSzXferAmount = 8,  kAlXferAmount = 8;
constexpr std::size_t kSzXferTime   = 4,  kAlXferTime   = 4;

constexpr std::size_t kOffKeyTail    = 0;
constexpr std::size_t kOffBalance    = 24;
constexpr std::size_t kOffXferAmount = 32;
constexpr std::size_t kOffXferDest   = 40;
constexpr std::size_t kOffXferTime   = 48;
constexpr std::size_t kOffNonce      = 52;

constexpr std::size_t kDeltaKeyTailToBalance   = 24;
constexpr std::size_t kDeltaBalanceToAmount    = 8;
constexpr std::size_t kDeltaAmountToXferDest   = 8;
constexpr std::size_t kDeltaXferDestToXferTime = 8;
constexpr std::size_t kDeltaXferTimeToNonce    = 4;
constexpr std::size_t kDeltaNonceToEnd         = 4;

constexpr std::size_t kSzAccount = 56;
constexpr std::size_t kAlAccount = 8;

constexpr std::size_t kSumPayload =
    kSzKeyTail + kSzBalance + kSzNonce + kSzXferDest + kSzXferAmount + kSzXferTime;
constexpr std::size_t kPadding = kSzAccount - kSumPayload;

constexpr std::size_t kSzKey     = 8;
constexpr std::size_t kOffSecond = 8;
constexpr std::size_t kSzEntry   = 64;
constexpr std::size_t kAlEntry   = 8;
} // namespace expected

static_assert(sizeof(ces::Account) == expected::kSzAccount, "Account value is 56 bytes");
static_assert(alignof(ces::Account) == expected::kAlAccount);
static_assert(sizeof(ces::Account) % alignof(ces::Account) == 0);
static_assert(std::is_standard_layout_v<ces::Account>);
static_assert(std::is_trivially_copyable_v<ces::Account>);
static_assert(sizeof(ces::HashTail) == expected::kSzKeyTail);
static_assert(alignof(ces::HashTail) == expected::kAlKeyTail);
static_assert(sizeof(int64_t) == expected::kSzBalance);
static_assert(sizeof(uint32_t) == expected::kSzNonce);
static_assert(sizeof(ces::HashPrefix) == expected::kSzXferDest);
static_assert(alignof(ces::HashPrefix) == expected::kAlXferDest);
static_assert(sizeof(uint64_t) == expected::kSzXferAmount);
static_assert(sizeof(ces::HashPrefix) == expected::kSzKey);
static_assert(sizeof(AccountEntry) == expected::kSzEntry, "account entry is 64 bytes (one cache line)");
static_assert(alignof(AccountEntry) == expected::kAlEntry);
static_assert(expected::kSumPayload == 56);
static_assert(expected::kPadding == 0);

// Byte offset of a field within an object.
static std::size_t fieldOffset(const ces::Account& a, const void* field) {
  return static_cast<std::size_t>(reinterpret_cast<const std::byte*>(field) -
                                  reinterpret_cast<const std::byte*>(&a));
}

// Offsets and deltas of every field, checked against any Account instance.
static void checkFullFieldLayout(const ces::Account& a, const std::string& origin) {
  BOOST_TEST_INFO("origin=" << origin);

  const std::size_t offKeyTail  = fieldOffset(a, a.keyTailPtr());
  const std::size_t offBalance  = fieldOffset(a, a.balancePtr());
  const std::size_t offAmount   = fieldOffset(a, a.lastXferAmountPtr());
  const std::size_t offXferDest = fieldOffset(a, a.lastXferDestPtr());
  const std::size_t offXferTime = fieldOffset(a, a.lastXferTimePtr());
  const std::size_t offNonce    = fieldOffset(a, a.noncePtr());

  BOOST_CHECK_EQUAL(offKeyTail,  expected::kOffKeyTail);
  BOOST_CHECK_EQUAL(offBalance,  expected::kOffBalance);
  BOOST_CHECK_EQUAL(offAmount,   expected::kOffXferAmount);
  BOOST_CHECK_EQUAL(offXferDest, expected::kOffXferDest);
  BOOST_CHECK_EQUAL(offXferTime, expected::kOffXferTime);
  BOOST_CHECK_EQUAL(offNonce,    expected::kOffNonce);

  BOOST_CHECK_EQUAL(offBalance  - offKeyTail,  expected::kDeltaKeyTailToBalance);
  BOOST_CHECK_EQUAL(offAmount   - offBalance,  expected::kDeltaBalanceToAmount);
  BOOST_CHECK_EQUAL(offXferDest - offAmount,   expected::kDeltaAmountToXferDest);
  BOOST_CHECK_EQUAL(offXferTime - offXferDest, expected::kDeltaXferDestToXferTime);
  BOOST_CHECK_EQUAL(offNonce    - offXferTime, expected::kDeltaXferTimeToNonce);
  BOOST_CHECK_EQUAL(sizeof(ces::Account) - offNonce, expected::kDeltaNonceToEnd);

  BOOST_CHECK_EQUAL(offKeyTail, 0u);
  BOOST_CHECK_EQUAL(offNonce + expected::kSzNonce, sizeof(ces::Account));

  const std::size_t tiled =
      (offBalance - offKeyTail) + (offAmount - offBalance) +
      (offXferDest - offAmount) + (offXferTime - offXferDest) +
      (offNonce - offXferTime) + (sizeof(ces::Account) - offNonce);
  BOOST_CHECK_EQUAL(tiled, sizeof(ces::Account));
}

static ces::HashPrefix makeKey(uint8_t seed) {
  return ces::HashPrefix{{seed, uint8_t(seed + 1), uint8_t(seed + 2),
                          uint8_t(seed + 3), uint8_t(seed + 4),
                          uint8_t(seed + 5), uint8_t(seed + 6),
                          uint8_t(seed + 7)}};
}

// Field type sizes and alignments.
BOOST_AUTO_TEST_CASE(TypeSizesAndAligns) {
  BOOST_CHECK_EQUAL(sizeof(ces::HashTail),    expected::kSzKeyTail);
  BOOST_CHECK_EQUAL(alignof(ces::HashTail),   expected::kAlKeyTail);
  BOOST_CHECK_EQUAL(sizeof(int64_t),          expected::kSzBalance);
  BOOST_CHECK_EQUAL(alignof(int64_t),         expected::kAlBalance);
  BOOST_CHECK_EQUAL(sizeof(uint32_t),         expected::kSzNonce);
  BOOST_CHECK_EQUAL(alignof(uint32_t),        expected::kAlNonce);
  BOOST_CHECK_EQUAL(sizeof(ces::HashPrefix),  expected::kSzXferDest);
  BOOST_CHECK_EQUAL(alignof(ces::HashPrefix), expected::kAlXferDest);
  BOOST_CHECK_EQUAL(sizeof(uint64_t),         expected::kSzXferAmount);
  BOOST_CHECK_EQUAL(alignof(uint64_t),        expected::kAlXferAmount);
}

// Struct size, alignment, standard-layout traits.
BOOST_AUTO_TEST_CASE(StructSizeAlignAndTraits) {
  BOOST_CHECK_EQUAL(sizeof(ces::Account),  expected::kSzAccount);
  BOOST_CHECK_EQUAL(alignof(ces::Account), expected::kAlAccount);
  BOOST_CHECK_EQUAL(sizeof(ces::Account) % alignof(ces::Account), 0u);
  BOOST_CHECK(std::is_standard_layout_v<ces::Account>);
  BOOST_CHECK(std::is_trivially_copyable_v<ces::Account>);
}

// Field payloads sum to sizeof: zero padding.
BOOST_AUTO_TEST_CASE(PaddingAccounting) {
  BOOST_CHECK_EQUAL(expected::kSumPayload, 56u);
  BOOST_CHECK_EQUAL(expected::kPadding, 0u);
  BOOST_CHECK_EQUAL(expected::kSumPayload, sizeof(ces::Account));
}

// Naked stack struct: field offsets.
BOOST_AUTO_TEST_CASE(NakedStruct_FieldOffsets) {
  ces::Account a;
  BOOST_CHECK_EQUAL(fieldOffset(a, a.keyTailPtr()),        expected::kOffKeyTail);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.balancePtr()),        expected::kOffBalance);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.lastXferAmountPtr()), expected::kOffXferAmount);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.lastXferDestPtr()),   expected::kOffXferDest);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.lastXferTimePtr()),   expected::kOffXferTime);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.noncePtr()),          expected::kOffNonce);
}

// Naked stack struct: consecutive field deltas.
BOOST_AUTO_TEST_CASE(NakedStruct_FieldDeltas) {
  ces::Account a;
  BOOST_CHECK_EQUAL(fieldOffset(a, a.balancePtr())        - fieldOffset(a, a.keyTailPtr()),        expected::kDeltaKeyTailToBalance);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.lastXferAmountPtr()) - fieldOffset(a, a.balancePtr()),        expected::kDeltaBalanceToAmount);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.lastXferDestPtr())   - fieldOffset(a, a.lastXferAmountPtr()), expected::kDeltaAmountToXferDest);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.lastXferTimePtr())   - fieldOffset(a, a.lastXferDestPtr()),   expected::kDeltaXferDestToXferTime);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.noncePtr())          - fieldOffset(a, a.lastXferTimePtr()),   expected::kDeltaXferTimeToNonce);
  BOOST_CHECK_EQUAL(sizeof(ces::Account)                  - fieldOffset(a, a.noncePtr()),          expected::kDeltaNonceToEnd);
}

BOOST_AUTO_TEST_CASE(NakedStruct_FullLayout) {
  ces::Account a;
  checkFullFieldLayout(a, "naked-stack-struct");
}

// Map entry: whole-entry size and key/value split.
BOOST_AUTO_TEST_CASE(MapEntry_SizeAndSplit) {
  BOOST_CHECK_EQUAL(sizeof(ces::HashPrefix),        expected::kSzKey);
  BOOST_CHECK_EQUAL(offsetof(AccountEntry, first),  0u);
  BOOST_CHECK_EQUAL(offsetof(AccountEntry, second), expected::kOffSecond);
  BOOST_CHECK_EQUAL(sizeof(AccountEntry),           expected::kSzEntry);
  BOOST_CHECK_EQUAL(alignof(AccountEntry),          expected::kAlEntry);
  BOOST_CHECK_EQUAL(offsetof(AccountEntry, second), sizeof(ces::HashPrefix));
  BOOST_CHECK_EQUAL(sizeof(AccountEntry),
                    offsetof(AccountEntry, second) + sizeof(ces::Account));
}

// Live map entry: value offset within the pair.
BOOST_AUTO_TEST_CASE(MapEntry_LiveValueSplit) {
  AccountMap map;
  const ces::HashPrefix key = makeKey(1);
  map.emplace(key, ces::Account());
  auto it = map.find(key);
  BOOST_REQUIRE(it != map.end());

  const AccountEntry& entry = *it;
  const auto* entryBase = reinterpret_cast<const std::byte*>(&entry);
  const auto* keyBase   = reinterpret_cast<const std::byte*>(&entry.first);
  const auto* valueBase = reinterpret_cast<const std::byte*>(&entry.second);

  BOOST_CHECK_EQUAL(static_cast<std::size_t>(keyBase - entryBase), 0u);
  BOOST_CHECK_EQUAL(static_cast<std::size_t>(valueBase - entryBase), expected::kOffSecond);
}

// Live map entry: mapped-value field offsets match the naked struct.
BOOST_AUTO_TEST_CASE(MapEntry_FieldOffsets) {
  AccountMap map;
  const ces::HashPrefix key = makeKey(10);
  map.emplace(key, ces::Account());
  const ces::Account& v = map.find(key)->second;

  BOOST_CHECK_EQUAL(fieldOffset(v, v.keyTailPtr()),        expected::kOffKeyTail);
  BOOST_CHECK_EQUAL(fieldOffset(v, v.balancePtr()),        expected::kOffBalance);
  BOOST_CHECK_EQUAL(fieldOffset(v, v.lastXferAmountPtr()), expected::kOffXferAmount);
  BOOST_CHECK_EQUAL(fieldOffset(v, v.lastXferDestPtr()),   expected::kOffXferDest);
  BOOST_CHECK_EQUAL(fieldOffset(v, v.lastXferTimePtr()),   expected::kOffXferTime);
  BOOST_CHECK_EQUAL(fieldOffset(v, v.noncePtr()),          expected::kOffNonce);
}

// Live map entry: consecutive field deltas.
BOOST_AUTO_TEST_CASE(MapEntry_FieldDeltas) {
  AccountMap map;
  const ces::HashPrefix key = makeKey(20);
  map.emplace(key, ces::Account());
  const ces::Account& v = map.find(key)->second;

  BOOST_CHECK_EQUAL(fieldOffset(v, v.balancePtr())        - fieldOffset(v, v.keyTailPtr()),        expected::kDeltaKeyTailToBalance);
  BOOST_CHECK_EQUAL(fieldOffset(v, v.lastXferAmountPtr()) - fieldOffset(v, v.balancePtr()),        expected::kDeltaBalanceToAmount);
  BOOST_CHECK_EQUAL(fieldOffset(v, v.lastXferDestPtr())   - fieldOffset(v, v.lastXferAmountPtr()), expected::kDeltaAmountToXferDest);
  BOOST_CHECK_EQUAL(fieldOffset(v, v.lastXferTimePtr())   - fieldOffset(v, v.lastXferDestPtr()),   expected::kDeltaXferDestToXferTime);
  BOOST_CHECK_EQUAL(fieldOffset(v, v.noncePtr())          - fieldOffset(v, v.lastXferTimePtr()),   expected::kDeltaXferTimeToNonce);
  BOOST_CHECK_EQUAL(sizeof(ces::Account)                  - fieldOffset(v, v.noncePtr()),          expected::kDeltaNonceToEnd);
}

BOOST_AUTO_TEST_CASE(MapEntry_FullLayout) {
  AccountMap map;
  const ces::HashPrefix key = makeKey(30);
  map.emplace(key, ces::Account());
  checkFullFieldLayout(map.find(key)->second, "boost-flat-map-value");
}

// Live map entry: absolute field offset within the entry = value split + field offset.
BOOST_AUTO_TEST_CASE(MapEntry_AbsoluteFieldOffsetsWithinEntry) {
  AccountMap map;
  const ces::HashPrefix key = makeKey(40);
  map.emplace(key, ces::Account());
  const AccountEntry& entry = *map.find(key);
  const ces::Account& v = entry.second;

  const auto* entryBase = reinterpret_cast<const std::byte*>(&entry);
  auto absOff = [&](const void* field) {
    return static_cast<std::size_t>(
        reinterpret_cast<const std::byte*>(field) - entryBase);
  };

  BOOST_CHECK_EQUAL(absOff(v.keyTailPtr()),        expected::kOffSecond + expected::kOffKeyTail);
  BOOST_CHECK_EQUAL(absOff(v.balancePtr()),        expected::kOffSecond + expected::kOffBalance);
  BOOST_CHECK_EQUAL(absOff(v.lastXferAmountPtr()), expected::kOffSecond + expected::kOffXferAmount);
  BOOST_CHECK_EQUAL(absOff(v.lastXferDestPtr()),   expected::kOffSecond + expected::kOffXferDest);
  BOOST_CHECK_EQUAL(absOff(v.lastXferTimePtr()),   expected::kOffSecond + expected::kOffXferTime);
  BOOST_CHECK_EQUAL(absOff(v.noncePtr()),          expected::kOffSecond + expected::kOffNonce);
  BOOST_CHECK_EQUAL(absOff(v.noncePtr()) + expected::kSzNonce, sizeof(AccountEntry));
}

// Naked struct and mapped value report identical field offsets.
BOOST_AUTO_TEST_CASE(NakedAndMap_IdenticalFieldOffsets) {
  ces::Account naked;
  AccountMap map;
  const ces::HashPrefix key = makeKey(50);
  map.emplace(key, ces::Account());
  const ces::Account& mapped = map.find(key)->second;

  BOOST_CHECK_EQUAL(fieldOffset(naked, naked.keyTailPtr()),        fieldOffset(mapped, mapped.keyTailPtr()));
  BOOST_CHECK_EQUAL(fieldOffset(naked, naked.balancePtr()),        fieldOffset(mapped, mapped.balancePtr()));
  BOOST_CHECK_EQUAL(fieldOffset(naked, naked.lastXferAmountPtr()), fieldOffset(mapped, mapped.lastXferAmountPtr()));
  BOOST_CHECK_EQUAL(fieldOffset(naked, naked.lastXferDestPtr()),   fieldOffset(mapped, mapped.lastXferDestPtr()));
  BOOST_CHECK_EQUAL(fieldOffset(naked, naked.lastXferTimePtr()),   fieldOffset(mapped, mapped.lastXferTimePtr()));
  BOOST_CHECK_EQUAL(fieldOffset(naked, naked.noncePtr()),          fieldOffset(mapped, mapped.noncePtr()));
}

BOOST_AUTO_TEST_SUITE_END()
