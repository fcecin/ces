// Pins the physical byte layout of ces::Account and of the boost flat-map entry
// pair<const HashPrefix, Account> the account store holds. The value is 56 bytes
// with zero padding; the entry is 64 bytes (8-byte key + 56-byte value), one
// cache line. balance and lastXferAmount are 48-bit (Int48/UInt48), which frees
// the trailing 32-bit aliasId without growing the row. Field sizes,
// alignments, offsets, and consecutive deltas are checked on both a naked stack
// struct and a live map entry, through Account's typed field pointers. A drift
// fails a static_assert at build time or a check at run time.

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

// Field order: keyTail 0, balance 24, lastXferAmount 30, lastXferDest 36,
// lastXferTime 44, nonce 48, aliasId 52. Value 56, entry 64.
namespace expected {
constexpr std::size_t kSzKeyTail    = 24, kAlKeyTail    = 1;
constexpr std::size_t kSzBalance    = 6,  kAlBalance    = 1;
constexpr std::size_t kSzXferAmount = 6,  kAlXferAmount = 1;
constexpr std::size_t kSzXferDest   = 8,  kAlXferDest   = 1;
constexpr std::size_t kSzXferTime   = 4,  kAlXferTime   = 4;
constexpr std::size_t kSzNonce      = 4,  kAlNonce      = 4;
constexpr std::size_t kSzAliasId   = 4,  kAlAliasId   = 4;

constexpr std::size_t kOffKeyTail    = 0;
constexpr std::size_t kOffBalance    = 24;
constexpr std::size_t kOffXferAmount = 30;
constexpr std::size_t kOffXferDest   = 36;
constexpr std::size_t kOffXferTime   = 44;
constexpr std::size_t kOffNonce      = 48;
constexpr std::size_t kOffAliasId   = 52;

constexpr std::size_t kDeltaKeyTailToBalance   = 24;
constexpr std::size_t kDeltaBalanceToAmount    = 6;
constexpr std::size_t kDeltaAmountToXferDest   = 6;
constexpr std::size_t kDeltaXferDestToXferTime = 8;
constexpr std::size_t kDeltaXferTimeToNonce    = 4;
constexpr std::size_t kDeltaNonceToAliasId    = 4;
constexpr std::size_t kDeltaAliasIdToEnd      = 4;

constexpr std::size_t kSzAccount = 56;
constexpr std::size_t kAlAccount = 4;

constexpr std::size_t kSumPayload =
    kSzKeyTail + kSzBalance + kSzXferAmount + kSzXferDest + kSzXferTime +
    kSzNonce + kSzAliasId;
constexpr std::size_t kPadding = kSzAccount - kSumPayload;

constexpr std::size_t kSzKey     = 8;
constexpr std::size_t kOffSecond = 8;
constexpr std::size_t kSzEntry   = 64;
constexpr std::size_t kAlEntry   = 4;
} // namespace expected

static_assert(sizeof(ces::Account) == expected::kSzAccount, "Account value is 56 bytes");
static_assert(alignof(ces::Account) == expected::kAlAccount);
static_assert(sizeof(ces::Account) % alignof(ces::Account) == 0);
static_assert(std::is_standard_layout_v<ces::Account>);
static_assert(std::is_trivially_copyable_v<ces::Account>);
static_assert(std::is_standard_layout_v<ces::Int48>);
static_assert(std::is_trivially_copyable_v<ces::Int48>);
static_assert(std::is_standard_layout_v<ces::UInt48>);
static_assert(std::is_trivially_copyable_v<ces::UInt48>);
static_assert(sizeof(ces::HashTail) == expected::kSzKeyTail);
static_assert(alignof(ces::HashTail) == expected::kAlKeyTail);
static_assert(sizeof(ces::Int48) == expected::kSzBalance);
static_assert(alignof(ces::Int48) == expected::kAlBalance);
static_assert(sizeof(ces::UInt48) == expected::kSzXferAmount);
static_assert(alignof(ces::UInt48) == expected::kAlXferAmount);
static_assert(sizeof(uint32_t) == expected::kSzNonce);
static_assert(sizeof(uint32_t) == expected::kSzAliasId);
static_assert(sizeof(ces::HashPrefix) == expected::kSzXferDest);
static_assert(alignof(ces::HashPrefix) == expected::kAlXferDest);
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
  const std::size_t offAliasId = fieldOffset(a, a.aliasIdPtr());

  BOOST_CHECK_EQUAL(offKeyTail,  expected::kOffKeyTail);
  BOOST_CHECK_EQUAL(offBalance,  expected::kOffBalance);
  BOOST_CHECK_EQUAL(offAmount,   expected::kOffXferAmount);
  BOOST_CHECK_EQUAL(offXferDest, expected::kOffXferDest);
  BOOST_CHECK_EQUAL(offXferTime, expected::kOffXferTime);
  BOOST_CHECK_EQUAL(offNonce,    expected::kOffNonce);
  BOOST_CHECK_EQUAL(offAliasId, expected::kOffAliasId);

  BOOST_CHECK_EQUAL(offBalance  - offKeyTail,  expected::kDeltaKeyTailToBalance);
  BOOST_CHECK_EQUAL(offAmount   - offBalance,  expected::kDeltaBalanceToAmount);
  BOOST_CHECK_EQUAL(offXferDest - offAmount,   expected::kDeltaAmountToXferDest);
  BOOST_CHECK_EQUAL(offXferTime - offXferDest, expected::kDeltaXferDestToXferTime);
  BOOST_CHECK_EQUAL(offNonce    - offXferTime, expected::kDeltaXferTimeToNonce);
  BOOST_CHECK_EQUAL(offAliasId - offNonce,    expected::kDeltaNonceToAliasId);
  BOOST_CHECK_EQUAL(sizeof(ces::Account) - offAliasId, expected::kDeltaAliasIdToEnd);

  BOOST_CHECK_EQUAL(offKeyTail, 0u);
  BOOST_CHECK_EQUAL(offAliasId + expected::kSzAliasId, sizeof(ces::Account));

  const std::size_t tiled =
      (offBalance - offKeyTail) + (offAmount - offBalance) +
      (offXferDest - offAmount) + (offXferTime - offXferDest) +
      (offNonce - offXferTime) + (offAliasId - offNonce) +
      (sizeof(ces::Account) - offAliasId);
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
  BOOST_CHECK_EQUAL(sizeof(ces::Int48),       expected::kSzBalance);
  BOOST_CHECK_EQUAL(alignof(ces::Int48),      expected::kAlBalance);
  BOOST_CHECK_EQUAL(sizeof(ces::UInt48),      expected::kSzXferAmount);
  BOOST_CHECK_EQUAL(alignof(ces::UInt48),     expected::kAlXferAmount);
  BOOST_CHECK_EQUAL(sizeof(uint32_t),         expected::kSzNonce);
  BOOST_CHECK_EQUAL(alignof(uint32_t),        expected::kAlNonce);
  BOOST_CHECK_EQUAL(sizeof(uint32_t),         expected::kSzAliasId);
  BOOST_CHECK_EQUAL(alignof(uint32_t),        expected::kAlAliasId);
  BOOST_CHECK_EQUAL(sizeof(ces::HashPrefix),  expected::kSzXferDest);
  BOOST_CHECK_EQUAL(alignof(ces::HashPrefix), expected::kAlXferDest);
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
  BOOST_CHECK_EQUAL(fieldOffset(a, a.aliasIdPtr()),       expected::kOffAliasId);
}

// Naked stack struct: consecutive field deltas.
BOOST_AUTO_TEST_CASE(NakedStruct_FieldDeltas) {
  ces::Account a;
  BOOST_CHECK_EQUAL(fieldOffset(a, a.balancePtr())        - fieldOffset(a, a.keyTailPtr()),        expected::kDeltaKeyTailToBalance);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.lastXferAmountPtr()) - fieldOffset(a, a.balancePtr()),        expected::kDeltaBalanceToAmount);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.lastXferDestPtr())   - fieldOffset(a, a.lastXferAmountPtr()), expected::kDeltaAmountToXferDest);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.lastXferTimePtr())   - fieldOffset(a, a.lastXferDestPtr()),   expected::kDeltaXferDestToXferTime);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.noncePtr())          - fieldOffset(a, a.lastXferTimePtr()),   expected::kDeltaXferTimeToNonce);
  BOOST_CHECK_EQUAL(fieldOffset(a, a.aliasIdPtr())       - fieldOffset(a, a.noncePtr()),          expected::kDeltaNonceToAliasId);
  BOOST_CHECK_EQUAL(sizeof(ces::Account)                  - fieldOffset(a, a.aliasIdPtr()),       expected::kDeltaAliasIdToEnd);
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
  BOOST_CHECK_EQUAL(fieldOffset(v, v.aliasIdPtr()),       expected::kOffAliasId);
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
  BOOST_CHECK_EQUAL(fieldOffset(v, v.aliasIdPtr())       - fieldOffset(v, v.noncePtr()),          expected::kDeltaNonceToAliasId);
  BOOST_CHECK_EQUAL(sizeof(ces::Account)                  - fieldOffset(v, v.aliasIdPtr()),       expected::kDeltaAliasIdToEnd);
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
  BOOST_CHECK_EQUAL(absOff(v.aliasIdPtr()),       expected::kOffSecond + expected::kOffAliasId);
  BOOST_CHECK_EQUAL(absOff(v.aliasIdPtr()) + expected::kSzAliasId, sizeof(AccountEntry));
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
  BOOST_CHECK_EQUAL(fieldOffset(naked, naked.aliasIdPtr()),       fieldOffset(mapped, mapped.aliasIdPtr()));
}

// Value round-trip: Int48/UInt48 preserve every boundary value, and an
// Account's balance/lastXferAmount survive storage in 6 bytes. This locks the
// sign-extension (the only real logic in the 48-bit codec), which the layout
// checks above do not exercise.
BOOST_AUTO_TEST_CASE(Int48ValueRoundTrip) {
  constexpr int64_t kI48Max = (int64_t(1) << 47) - 1;   // 2^47-1
  constexpr int64_t kI48Min = -(int64_t(1) << 47);      // -2^47
  const int64_t signedCases[] = {
      0, 1, -1, 2, -2, 255, -255, 65535, -65535, 1000, -1000,
      10'000'000'000LL,           // fixture prefund
      int64_t(1) << 46,           // self-account target (bit 46 set)
      kI48Max, kI48Min, kI48Max - 1, kI48Min + 1};
  for (int64_t v : signedCases) {
    BOOST_TEST_INFO("v=" << v);
    BOOST_CHECK_EQUAL(ces::Int48(v).get(), v);
    ces::Account a;
    a.setBalance(v);
    BOOST_CHECK_EQUAL(a.getBalance(), v);
  }

  constexpr uint64_t kU48Max = (uint64_t(1) << 48) - 1;   // 2^48-1
  const uint64_t unsignedCases[] = {
      0, 1, 2, 255, 65535, 1000, 10'000'000'000ULL,
      uint64_t(1) << 32, uint64_t(1) << 47, kU48Max, kU48Max - 1};
  for (uint64_t v : unsignedCases) {
    BOOST_TEST_INFO("v=" << v);
    BOOST_CHECK_EQUAL(ces::UInt48(v).get(), v);
    ces::Account a;
    a.setLastXferAmount(v);
    BOOST_CHECK_EQUAL(a.getLastXferAmount(), v);
  }
}

// An Account with every field set to a distinct recognizable value. If any
// accessor or serializer step clobbered a neighbor, one of these read-backs
// would come out wrong.
static ces::Account makeDistinctAccount() {
  ces::Account a;
  ces::HashTail kt; kt.fill(0x11);
  a.setKeyTail(kt);
  a.setBalance(0x1122334455LL);          // fits int48
  a.setLastXferAmount(0xAABBCCDDEEull);  // fits uint48
  ces::HashPrefix dst; dst.fill(0x22);
  a.setLastXferDest(dst);
  a.setLastXferTime(0x33445566u);
  a.setNonce(0x778899AAu);
  a.setAliasId(0xCAFEBABEu);
  return a;
}

static void checkAllFields(const ces::Account& a) {
  ces::HashTail kt; kt.fill(0x11);
  ces::HashPrefix dst; dst.fill(0x22);
  BOOST_CHECK(a.getKeyTail() == kt);
  BOOST_CHECK_EQUAL(a.getBalance(), 0x1122334455LL);
  BOOST_CHECK_EQUAL(a.getLastXferAmount(), 0xAABBCCDDEEull);
  BOOST_CHECK(a.getLastXferDest() == dst);
  BOOST_CHECK_EQUAL(a.getLastXferTime(), 0x33445566u);
  BOOST_CHECK_EQUAL(a.getNonce(), 0x778899AAu);
  BOOST_CHECK_EQUAL(a.getAliasId(), 0xCAFEBABEu);
}

// aliasId is real and no accessor clobbers a neighbor: set all seven fields to
// distinct values, read all seven back.
BOOST_AUTO_TEST_CASE(AllFieldsIndependentThroughAccessors) {
  checkAllFields(makeDistinctAccount());
}

// aliasId survives serialization: the Full path (create / snapshot) round-trips
// every field, including aliasId, which is otherwise always 0 in the suite.
BOOST_AUTO_TEST_CASE(FullSerializerRoundTripIncludingAliasId) {
  ces::Account in = makeDistinctAccount();
  char buf[256];
  size_t n;
  {
    ces::Account::SerModeGuard guard(ces::Account::SerMode::Full);
    n = logkv::serializer<ces::Account>::write(buf, sizeof(buf), in);
  }
  BOOST_REQUIRE(n > 0 && n <= sizeof(buf));
  ces::Account out;
  logkv::serializer<ces::Account>::read(buf, n, out);   // header-driven
  checkAllFields(out);
  BOOST_CHECK(in == out);
}

// A hot-path partial write (BalanceNonce) must NOT clobber a aliasId set by an
// earlier Full write — the WAL-replay case: create (Full, carries aliasId) then
// balance-update (BalanceNonce, must preserve it).
BOOST_AUTO_TEST_CASE(PartialModeWritePreservesAliasId) {
  ces::Account target = makeDistinctAccount();   // aliasId 0xCAFEBABE
  ces::Account update;
  update.setBalance(0x0000AAAAAAAAll);
  update.setNonce(0x0000BBBBu);

  char buf[64];
  size_t n;
  {
    ces::Account::SerModeGuard guard(ces::Account::SerMode::BalanceNonce);
    n = logkv::serializer<ces::Account>::write(buf, sizeof(buf), update);
  }
  logkv::serializer<ces::Account>::read(buf, n, target);

  BOOST_CHECK_EQUAL(target.getBalance(), 0x0000AAAAAAAAll);   // updated
  BOOST_CHECK_EQUAL(target.getNonce(), 0x0000BBBBu);          // updated
  BOOST_CHECK_EQUAL(target.getAliasId(), 0xCAFEBABEu);         // preserved
  ces::HashPrefix dst; dst.fill(0x22);
  BOOST_CHECK(target.getLastXferDest() == dst);               // preserved
  BOOST_CHECK_EQUAL(target.getLastXferTime(), 0x33445566u);   // preserved
}

BOOST_AUTO_TEST_SUITE_END()
