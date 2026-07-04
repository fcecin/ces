// countCanonicalKvKeyPrefix: account/entry cell counting over a hyle-canonical KV dump.
// Pure byte parsing, no hyle dependency -- builds canonical buffers by hand and asserts counts.

#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include <ces/buffer.h>
#include <ces/util/kvcount.h>

#include <string>
#include <utility>
#include <vector>

using ces::Buffer;
using ces::Bytes;

namespace {

// Serialize [u32 count] then per (key,val) [u32 klen][key][u32 vlen][val], like State::canonical().
Bytes canon(const std::vector<std::pair<std::string, std::string>>& kvs) {
  Buffer b;
  b.put<uint32_t>(static_cast<uint32_t>(kvs.size()));
  for (const auto& kv : kvs) {
    b.put<uint32_t>(static_cast<uint32_t>(kv.first.size()));
    b.putBytes(kv.first);
    b.put<uint32_t>(static_cast<uint32_t>(kv.second.size()));
    b.putBytes(kv.second);
  }
  return std::move(b).take();
}

uint64_t count(const Bytes& b, uint8_t prefix) {
  return ces::countCanonicalKvKeyPrefix(std::span<const uint8_t>(b.data(), b.size()), prefix);
}

// An account cell key: 'a' + 32-byte pubkey.
std::string acctKey(char fill) { return std::string("a") + std::string(32, fill); }

}  // namespace

BOOST_AUTO_TEST_SUITE(KvCountTests)

BOOST_AUTO_TEST_CASE(EmptyState) {
  Bytes b = canon({});
  BOOST_CHECK_EQUAL(count(b, 'a'), 0u);
  BOOST_CHECK_EQUAL(count(b, 'e'), 0u);
}

BOOST_AUTO_TEST_CASE(GenesisSingleAccount) {
  Bytes b = canon({{acctKey('\x11'), std::string(16, '\0')}});
  BOOST_CHECK_EQUAL(count(b, 'a'), 1u);
  BOOST_CHECK_EQUAL(count(b, 'e'), 0u);
}

BOOST_AUTO_TEST_CASE(MixedAccountsAndEntries) {
  Bytes b = canon({
    {acctKey('\x01'), "v1"},
    {"ename-one", "payload"},
    {acctKey('\x02'), "v2"},
    {"ename-two", ""},          // empty value
    {"en3", "x"},
  });
  BOOST_CHECK_EQUAL(count(b, 'a'), 2u);
  BOOST_CHECK_EQUAL(count(b, 'e'), 3u);
  BOOST_CHECK_EQUAL(count(b, 'z'), 0u);  // unknown prefix
}

BOOST_AUTO_TEST_CASE(EmptyKeyNeverCounts) {
  Bytes b = canon({{"", "v"}, {acctKey('\x03'), "v"}});
  BOOST_CHECK_EQUAL(count(b, 'a'), 1u);
  BOOST_CHECK_EQUAL(count(b, '\0'), 0u);  // a zero-length key matches no prefix
}

BOOST_AUTO_TEST_CASE(CountHeaderLiesHigh) {
  // header claims 5 entries, only 1 serialized -> stop at the truncation, count what is real
  Bytes b = canon({{acctKey('\x05'), "v"}});
  b[0] = 0; b[1] = 0; b[2] = 0; b[3] = 5;
  BOOST_CHECK_EQUAL(count(b, 'a'), 1u);
}

BOOST_AUTO_TEST_CASE(ShortHeaderIsZero) {
  BOOST_CHECK_EQUAL(count(Bytes{}, 'a'), 0u);
  BOOST_CHECK_EQUAL(count(Bytes{0x00, 0x00}, 'a'), 0u);
}

BOOST_AUTO_TEST_CASE(TornValueLengthStopsWalk) {
  // entry1 intact, entry2 declares a value longer than what remains -> walk stops after entry1
  Bytes b = canon({
    {acctKey('\x06'), "v"},
    {"elater", "vv"},
  });
  // find entry2's vlen (last 4+2 bytes: [u32 vlen=2]["vv"]) and inflate it
  b[b.size() - 6] = 0xFF;
  BOOST_CHECK_EQUAL(count(b, 'a'), 1u);  // entry1 still counted
  BOOST_CHECK_EQUAL(count(b, 'e'), 1u);  // entry2 key was intact and read before its bad value
}

BOOST_AUTO_TEST_SUITE_END()
