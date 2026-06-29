// test_serversign.cpp -- CesServer::serverSign, the server-key delegation primitive that
// privileged /s/ extensions use (ces.serverSign) to make a relayed attestation attributable
// to the server identity. The host signs SHA256(DOMAIN_TAG || bytes), never the raw bytes,
// so an attestation signature can never be reinterpreted as another server-key op (lock 2
// of the accountable-formation design), including the 32-byte-input footgun.

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstring>
#include <string>
#include <vector>

#include <ces/keys.h>
#include <ces/ramfilestore.h>   // ces::sha256
#include "test_common.h"

namespace {

constexpr char kAttestTag[] = "CES_EXT_ATTEST_V1";   // MUST match CesServer::serverSign

// The digest the host actually signs for input `bytes`.
ces::Hash taggedDigest(const std::string& bytes) {
  std::vector<uint8_t> buf;
  buf.insert(buf.end(), kAttestTag, kAttestTag + (sizeof(kAttestTag) - 1));
  buf.insert(buf.end(), bytes.begin(), bytes.end());
  return ces::sha256(buf.data(), buf.size());
}

bool verifyOver(const ces::PublicKey& pub, const std::string& data, const ces::Signature& sig) {
  return pub.verifySignature(data.data(), data.size(), sig);
}

}  // namespace

BOOST_AUTO_TEST_SUITE(ServerSignTests)

// serverSign over arbitrary bytes verifies against the server pubkey ONLY when verified
// over the tagged digest, and never over the raw input. So the signature lives in a domain
// disjoint from every other server-key op.
BOOST_FIXTURE_TEST_CASE(SignsTaggedDigestNotRaw, CesFixture) {
  const ces::PublicKey pub(server->_serverKeyPair().getPublicKeyAsHash());

  const std::string msg = "coalition/1\2somefingerprintbytes....";
  ces::Signature sig = server->serverSign(
      reinterpret_cast<const uint8_t*>(msg.data()), msg.size());

  // Valid only over SHA256(tag || msg).
  const ces::Hash digest = taggedDigest(msg);
  const std::string digestStr(reinterpret_cast<const char*>(digest.data()), digest.size());
  BOOST_CHECK(verifyOver(pub, digestStr, sig));

  // NOT valid over the raw message (would be a non-domain-separated signature).
  BOOST_CHECK(!verifyOver(pub, msg, sig));
}

// The footgun: keys.h signData treats a 32-byte input as a pre-computed digest and signs it
// raw. If serverSign forwarded its argument to signData, a caller could pass X = SHA256(a
// real settlement op) and obtain a signature valid for that op. Because the host hashes
// tag||X itself, the signature is over SHA256(tag || X), NOT over X. So a 32-byte input is
// still domain-separated and cannot be a raw pre-image of another op's signature.
BOOST_FIXTURE_TEST_CASE(ThirtyTwoByteInputIsStillTagged, CesFixture) {
  const ces::PublicKey pub(server->_serverKeyPair().getPublicKeyAsHash());

  const std::string x(32, '\xA5');   // exactly 32 bytes: the dangerous length
  ces::Signature sig = server->serverSign(
      reinterpret_cast<const uint8_t*>(x.data()), x.size());

  // Verifies over the tagged digest...
  const ces::Hash digest = taggedDigest(x);
  const std::string digestStr(reinterpret_cast<const char*>(digest.data()), digest.size());
  BOOST_CHECK(verifyOver(pub, digestStr, sig));

  // ...and NOT over the raw 32 bytes (which is what an attacker would have crafted as a
  // digest of some other server op). Footgun closed.
  BOOST_CHECK(!verifyOver(pub, x, sig));
}

// Distinct inputs yield distinct, independently-verifiable signatures (sanity that the tag
// does not collapse different messages).
BOOST_FIXTURE_TEST_CASE(DistinctInputsDistinctSigs, CesFixture) {
  const ces::PublicKey pub(server->_serverKeyPair().getPublicKeyAsHash());

  ces::Signature a = server->serverSign(reinterpret_cast<const uint8_t*>("aaa"), 3);
  ces::Signature b = server->serverSign(reinterpret_cast<const uint8_t*>("bbb"), 3);
  BOOST_CHECK(a != b);

  const ces::Hash da = taggedDigest("aaa"), db = taggedDigest("bbb");
  const std::string sa(reinterpret_cast<const char*>(da.data()), da.size());
  const std::string sb(reinterpret_cast<const char*>(db.data()), db.size());
  BOOST_CHECK(verifyOver(pub, sa, a));
  BOOST_CHECK(verifyOver(pub, sb, b));
  BOOST_CHECK(!verifyOver(pub, sa, b));   // a's digest does not verify b's signature
}

BOOST_AUTO_TEST_SUITE_END()
