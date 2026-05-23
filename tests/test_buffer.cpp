#include "test_common.h"

#include <ces/buffer.h>

#include <stdexcept>

BOOST_AUTO_TEST_SUITE(BufferTests)

// ---- get<T> short-read regression ----
//
// Before the fix: ces::Buffer::get<T>() on a too-short buffer silently
// returned a default-constructed T (e.g. 0) AND advanced the read
// cursor by the missing-bytes count (returned by
// logkv::serializer::read when it can't satisfy the read). Result:
// callers got garbage data and every following get<> was desynced —
// no exception, no signal. After the fix: get<T>() throws on short
// read and leaves the read cursor untouched.

BOOST_AUTO_TEST_CASE(Get_ShortReadThrows) {
  ces::Bytes shortData{0x01, 0x02, 0x03};
  ces::Buffer buf(std::move(shortData));
  BOOST_CHECK_THROW(buf.get<uint64_t>(), std::out_of_range);
}

BOOST_AUTO_TEST_CASE(Get_ShortReadCursorIntact) {
  ces::Bytes data{0xAA, 0xBB, 0xCC};
  ces::Buffer buf(std::move(data));
  try { buf.get<uint64_t>(); } catch (const std::out_of_range&) {}
  BOOST_CHECK_EQUAL(buf.readPos(), 0u);
  // After the failed read, the bytes should still be available.
  BOOST_CHECK_EQUAL(buf.get<uint8_t>(), 0xAAu);
  BOOST_CHECK_EQUAL(buf.get<uint8_t>(), 0xBBu);
  BOOST_CHECK_EQUAL(buf.get<uint8_t>(), 0xCCu);
}

BOOST_AUTO_TEST_CASE(Get_ExactSizeWorks) {
  ces::Buffer buf;
  buf.put<uint64_t>(0x0123456789abcdefULL);
  ces::Buffer parser(std::move(buf).take());
  BOOST_CHECK_EQUAL(parser.get<uint64_t>(), 0x0123456789abcdefULL);
  BOOST_CHECK_EQUAL(parser.remaining(), 0u);
  // One more get<> past the end must throw, not silently return 0.
  BOOST_CHECK_THROW(parser.get<uint8_t>(), std::out_of_range);
}

// ---- runtime-width putLE regression ----
//
// Before the fix: ces::Buffer::putLE(Bytes&, T, uint8_t byteCount)
// did not enforce its documented precondition (1 <= byteCount <=
// sizeof(T)). byteCount == 0 silently no-ops the resize and memcpy.
// byteCount > sizeof(T) reads past the local `le` variable on the
// stack (UB). After the fix: precondition is asserted.

BOOST_AUTO_TEST_CASE(PutLE_RuntimeWidth_ZeroByteCountAsserts) {
  ces::Bytes v;
  BOOST_CHECK_THROW(
    (ces::Buffer::putLE<uint64_t>(v, 0xff, 0)),
    std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(PutLE_RuntimeWidth_OversizeByteCountAsserts) {
  ces::Bytes v;
  // sizeof(uint32_t) == 4; passing 5 must trip the precondition.
  BOOST_CHECK_THROW(
    (ces::Buffer::putLE<uint32_t>(v, 0xff, 5)),
    std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(PutLE_RuntimeWidth_HappyPath) {
  ces::Bytes v;
  ces::Buffer::putLE<uint64_t>(v, 0x123456, 3);  // emit 3 low bytes
  BOOST_REQUIRE_EQUAL(v.size(), 3u);
  BOOST_CHECK_EQUAL(v[0], 0x56u);
  BOOST_CHECK_EQUAL(v[1], 0x34u);
  BOOST_CHECK_EQUAL(v[2], 0x12u);
}

// ---- serializer<PublicKey> ----
//
// PublicKey IS a Hash with a lazily-cached hex string. Its serializer
// must delegate to serializer<Hash> — same 32 raw bytes, no custom
// lifting. Wire-decoded PublicKeys must not pay for hex encoding
// until something actually asks for it.

BOOST_AUTO_TEST_CASE(PublicKeySerializer_RoundTripMatchesHash) {
  ces::Hash h{};
  for (size_t i = 0; i < h.size(); ++i)
    h[i] = static_cast<uint8_t>(0xA0 + i);
  ces::PublicKey pkIn(h);

  ces::Buffer pkBuf;
  pkBuf.put(pkIn);
  ces::Buffer hashBuf;
  hashBuf.put(h);

  BOOST_REQUIRE_EQUAL(pkBuf.size(), hashBuf.size());
  BOOST_CHECK_EQUAL_COLLECTIONS(pkBuf.vec().begin(), pkBuf.vec().end(),
                                hashBuf.vec().begin(), hashBuf.vec().end());

  ces::Buffer parser(std::move(pkBuf).take());
  auto pkOut = parser.get<ces::PublicKey>();
  BOOST_CHECK(pkOut.getHash() == h);
  BOOST_CHECK_EQUAL(parser.remaining(), 0u);
}

BOOST_AUTO_TEST_CASE(PublicKeySerializer_LazyHex) {
  // A wire-decoded PublicKey should NOT have a populated hex string
  // until something asks for it. Probe via the const accessor and a
  // before/after check on what getHexStr returns.
  ces::Hash h{};
  h[0] = 0xDE; h[1] = 0xAD; h[2] = 0xBE; h[3] = 0xEF;
  ces::Buffer buf;
  buf.put(ces::PublicKey(h));
  ces::Buffer parser(std::move(buf).take());
  auto pk = parser.get<ces::PublicKey>();

  // First call computes; result has the correct length.
  const std::string& hex = pk.getHexStr();
  BOOST_CHECK_EQUAL(hex.size(), 64u);
  BOOST_CHECK_EQUAL(hex.substr(0, 8), "deadbeef");

  // Second call returns the same cached string by reference.
  BOOST_CHECK(&pk.getHexStr() == &hex);
}

BOOST_AUTO_TEST_CASE(PublicKeySerializer_ShortReadThrows) {
  // Buffer.get<T>'s short-read guard must apply for PublicKey too —
  // delegating to serializer<Hash> means same contract.
  ces::Bytes shortData(10, 0xAB);  // only 10 of the 32 needed
  ces::Buffer buf(std::move(shortData));
  BOOST_CHECK_THROW(buf.get<ces::PublicKey>(), std::out_of_range);
}

BOOST_AUTO_TEST_SUITE_END()
