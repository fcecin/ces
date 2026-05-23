#include "test_common.h"

#include <ces/util/hex.h>

#include <stdexcept>

BOOST_AUTO_TEST_SUITE(HexTests)

// --- parseHex ---

BOOST_AUTO_TEST_CASE(ParseHex_Empty) {
  auto bytes = ces::parseHex("");
  BOOST_CHECK(bytes.empty());
}

BOOST_AUTO_TEST_CASE(ParseHex_LowerAndUpper) {
  auto a = ces::parseHex("0123456789abcdef");
  auto b = ces::parseHex("0123456789ABCDEF");
  BOOST_REQUIRE_EQUAL(a.size(), 8u);
  BOOST_CHECK(a == b);
  BOOST_CHECK_EQUAL(a[0], 0x01);
  BOOST_CHECK_EQUAL(a[7], 0xEF);
}

BOOST_AUTO_TEST_CASE(ParseHex_OddTailIgnored) {
  // Existing cesh behavior: odd trailing char silently dropped.
  auto bytes = ces::parseHex("aabbc");
  BOOST_REQUIRE_EQUAL(bytes.size(), 2u);
  BOOST_CHECK_EQUAL(bytes[0], 0xAA);
  BOOST_CHECK_EQUAL(bytes[1], 0xBB);
}

BOOST_AUTO_TEST_CASE(ParseHex_NonHexThrows) {
  BOOST_CHECK_THROW(ces::parseHex("xx"), std::invalid_argument);
  BOOST_CHECK_THROW(ces::parseHex("a!"), std::invalid_argument);
  BOOST_CHECK_THROW(ces::parseHex("  "), std::invalid_argument);
}

// --- bytesToHex ---

BOOST_AUTO_TEST_CASE(BytesToHex_Empty) {
  ces::Bytes v;
  BOOST_CHECK_EQUAL(ces::bytesToHex(v), "");
}

BOOST_AUTO_TEST_CASE(BytesToHex_KnownBytes) {
  ces::Bytes v = {0x00, 0x0F, 0xA5, 0xFF};
  BOOST_CHECK_EQUAL(ces::bytesToHex(v), "000fa5ff");
}

BOOST_AUTO_TEST_CASE(BytesToHex_Lowercase) {
  ces::Bytes v = {0xDE, 0xAD, 0xBE, 0xEF};
  // The contract is lowercase output.
  BOOST_CHECK_EQUAL(ces::bytesToHex(v), "deadbeef");
}

// --- Round trip ---

BOOST_AUTO_TEST_CASE(RoundTrip) {
  ces::Bytes original;
  for (int i = 0; i < 256; ++i)
    original.push_back(static_cast<uint8_t>(i));
  std::string hex = ces::bytesToHex(original);
  auto back = ces::parseHex(hex);
  BOOST_CHECK(back == original);
}

BOOST_AUTO_TEST_SUITE_END()
