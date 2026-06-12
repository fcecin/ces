// net_envelope.cpp — implementation of the bind contract + per-op
// envelope helpers. See include/ces/l2/net_envelope.h for the design.
//
// All wire serialization goes through ces::Buffer / minx::Buffer /
// logkv::serializer — no hand-rolled BE shifts here.

#include <ces/l2/net_envelope.h>
#include <ces/buffer.h>
#include <ces/util/hash.h>

#include <cryptopp/sha.h>

#include <cstring>

namespace ces {

// ---------------------------------------------------------------------------
// Bind preamble — client side
// ---------------------------------------------------------------------------

std::array<uint8_t, CES_PLEX_SHA256_SIZE>
computeBindRequestDigest(std::span<const uint8_t> name,
                         uint64_t clientTimeUs,
                         std::span<const uint8_t> clientPubkey) {
  CryptoPP::SHA256 h;
  ces::shaUpdate(h, static_cast<uint16_t>(name.size()));
  if (!name.empty()) h.Update(name.data(), name.size());
  ces::shaUpdate(h, clientTimeUs);
  h.Update(clientPubkey.data(), clientPubkey.size());
  std::array<uint8_t, CES_PLEX_SHA256_SIZE> out;
  h.Final(out.data());
  return out;
}

minx::Bytes buildBindRequest(const std::string& name,
                              uint64_t clientTimeUs,
                              const KeyPair& clientKey) {
  const auto& pkArr = clientKey.getPublicKeyAsHash();
  std::span<const uint8_t> nameSpan(
    reinterpret_cast<const uint8_t*>(name.data()), name.size());
  std::span<const uint8_t> pkSpan(pkArr.data(), pkArr.size());
  auto digest = computeBindRequestDigest(nameSpan, clientTimeUs, pkSpan);

  Signature sig = clientKey.signData(
    std::span<const uint8_t>(digest.data(), digest.size()));

  const size_t total =
      CES_PLEX_NAME_LEN_SIZE + name.size() + CES_PLEX_BIND_REQ_TAIL_SIZE;
  minx::Bytes bytes(total);
  minx::Buffer buf(bytes);
  buf.put<uint16_t>(static_cast<uint16_t>(name.size()));
  buf.put(nameSpan);
  buf.put<uint64_t>(clientTimeUs);
  buf.put(pkArr);
  buf.put(digest);
  buf.put(sig);
  return bytes;
}

// ---------------------------------------------------------------------------
// Bind reply — server side
// ---------------------------------------------------------------------------

namespace {

// Build the bytes-to-be-hashed for the reply digest:
// status || clientSha256 || serverTimeUs || serverPubkey ||
// channelSessionToken || serverProtoVersion || 4 fee fields.
std::array<uint8_t, CES_PLEX_SHA256_SIZE>
computeBindReplyDigestRaw(uint8_t status,
                          std::span<const uint8_t> clientSha256,
                          uint64_t serverTimeUs,
                          std::span<const uint8_t> serverPubkey,
                          uint64_t channelSessionToken,
                          uint32_t serverProtoVersion,
                          uint64_t feeNetChannelSec,
                          uint64_t feeNetMemByteDay,
                          uint64_t feeNetByteSent,
                          uint64_t feeNetByteReceived) {
  CryptoPP::SHA256 h;
  h.Update(&status, 1);
  h.Update(clientSha256.data(), clientSha256.size());
  ces::shaUpdate(h, serverTimeUs);
  h.Update(serverPubkey.data(), serverPubkey.size());
  ces::shaUpdate(h, channelSessionToken);
  ces::shaUpdate(h, serverProtoVersion);
  ces::shaUpdate(h, feeNetChannelSec);
  ces::shaUpdate(h, feeNetMemByteDay);
  ces::shaUpdate(h, feeNetByteSent);
  ces::shaUpdate(h, feeNetByteReceived);
  std::array<uint8_t, CES_PLEX_SHA256_SIZE> out;
  h.Final(out.data());
  return out;
}

} // namespace

std::array<uint8_t, CES_PLEX_SHA256_SIZE>
computeBindReplyDigest(const ParsedBindReply& reply,
                       std::span<const uint8_t> clientSha256) {
  std::span<const uint8_t> pkSpan(
    reply.serverPubkey.data(), reply.serverPubkey.size());
  return computeBindReplyDigestRaw(
    reply.status, clientSha256, reply.serverTimeUs, pkSpan,
    reply.channelSessionToken, reply.serverProtoVersion,
    reply.feeNetChannelSec, reply.feeNetMemByteDay,
    reply.feeNetByteSent, reply.feeNetByteReceived);
}

minx::Bytes buildBindReply(const BindReplyFields& fields,
                            std::span<const uint8_t> clientSha256,
                            const KeyPair& serverKey) {
  const auto& pkArr = serverKey.getPublicKeyAsHash();
  std::span<const uint8_t> pkSpan(pkArr.data(), pkArr.size());
  auto digest = computeBindReplyDigestRaw(
    fields.status, clientSha256, fields.serverTimeUs, pkSpan,
    fields.channelSessionToken, fields.serverProtoVersion,
    fields.feeNetChannelSec, fields.feeNetMemByteDay,
    fields.feeNetByteSent, fields.feeNetByteReceived);

  Signature sig = serverKey.signData(
    std::span<const uint8_t>(digest.data(), digest.size()));

  minx::Bytes bytes(CES_PLEX_BIND_REPLY_TOTAL_SIZE);
  minx::Buffer buf(bytes);
  buf.put<uint8_t>(fields.status);
  buf.put<uint64_t>(fields.serverTimeUs);
  buf.put(pkArr);
  buf.put<uint64_t>(fields.channelSessionToken);
  buf.put<uint32_t>(fields.serverProtoVersion);
  buf.put<uint64_t>(fields.feeNetChannelSec);
  buf.put<uint64_t>(fields.feeNetMemByteDay);
  buf.put<uint64_t>(fields.feeNetByteSent);
  buf.put<uint64_t>(fields.feeNetByteReceived);
  buf.put(digest);
  buf.put(sig);
  return bytes;
}

ParsedBindReply parseBindReply(
    std::span<const uint8_t, CES_PLEX_BIND_REPLY_TOTAL_SIZE> buf) {
  ParsedBindReply r;
  std::span<const uint8_t> bufSpan(buf);
  minx::ConstBuffer reader(bufSpan);
  reader.get(r.status);
  reader.get(r.serverTimeUs);
  reader.get(r.serverPubkey);
  reader.get(r.channelSessionToken);
  reader.get(r.serverProtoVersion);
  reader.get(r.feeNetChannelSec);
  reader.get(r.feeNetMemByteDay);
  reader.get(r.feeNetByteSent);
  reader.get(r.feeNetByteReceived);
  reader.get(r.sha256);
  reader.get(r.sig);
  return r;
}

bool verifyBindReply(const ParsedBindReply& reply,
                     std::span<const uint8_t> clientSha256) {
  auto computed = computeBindReplyDigest(reply, clientSha256);
  if (computed != reply.sha256) return false;
  minx::Hash pkHash;
  std::memcpy(pkHash.data(), reply.serverPubkey.data(), pkHash.size());
  PublicKey serverPk(pkHash);
  return serverPk.verifySignature(
    std::span<const uint8_t>(computed.data(), computed.size()),
    reply.sig);
}

// ---------------------------------------------------------------------------
// Per-op envelope
// ---------------------------------------------------------------------------

std::array<uint8_t, CES_PLEX_SHA256_SIZE>
computePerOpDigest(uint8_t verb,
                   std::span<const uint8_t> preamble,
                   uint64_t sessionToken) {
  CryptoPP::SHA256 h;
  h.Update(&verb, 1);
  if (!preamble.empty()) h.Update(preamble.data(), preamble.size());
  ces::shaUpdate(h, sessionToken);
  std::array<uint8_t, CES_PLEX_SHA256_SIZE> out;
  h.Final(out.data());
  return out;
}

Signature signPerOp(const KeyPair& signer,
                    uint8_t verb,
                    std::span<const uint8_t> preamble,
                    uint64_t sessionToken) {
  auto digest = computePerOpDigest(verb, preamble, sessionToken);
  return signer.signData(
    std::span<const uint8_t>(digest.data(), digest.size()));
}

bool verifyPerOp(const BoundChannelContext& bound,
                 uint8_t verb,
                 std::span<const uint8_t> preamble,
                 const Signature& sig) {
  auto digest = computePerOpDigest(verb, preamble, bound.sessionToken);
  return bound.boundPubkey.verifySignature(
    std::span<const uint8_t>(digest.data(), digest.size()), sig);
}

uint64_t sigDedupHash(const Signature& sig) {
  // Skip the 1-byte algorithm decorator at sig[0] and read sig[1..8]
  // as a big-endian u64.
  return ces::Buffer::peek<uint64_t>(
    std::span<const uint8_t>(sig.data() + 1, 8), 0);
}

ces::Bytes buildPerOpResponse(const KeyPair& serverKey,
                              uint8_t verb,
                              uint8_t status,
                              std::span<const uint8_t> preamble,
                              uint64_t reqSigHash) {
  const uint64_t timeUs = getMicrosSinceEpoch();

  // Digest binds the verb: status || verb || preamble || time_us ||
  // req_sig_hash. verb is hashed but not emitted on the wire.
  ces::Buffer hashIn;
  hashIn.put<uint8_t>(status)
        .put<uint8_t>(verb)
        .putBytes(preamble)
        .put<uint64_t>(timeUs)
        .put<uint64_t>(reqSigHash);
  // Plain single SHA256 of the buffer — identical to ces::sha256, which is
  // what the client recomputes to verify (kept inline so this low-level
  // envelope module doesn't pull in a higher-layer header for it).
  minx::Hash digest;
  CryptoPP::SHA256().CalculateDigest(
      digest.data(), hashIn.data(), hashIn.size());

  // Wire: [status][preamble][time_us][req_sig_hash][sha256][sig].
  ces::Buffer out(
      CES_PLEX_STATUS_SIZE + preamble.size() + CES_PLEX_RESP_TRAILER_SIZE);
  out.put<uint8_t>(status)
     .putBytes(preamble)
     .put<uint64_t>(timeUs)
     .put<uint64_t>(reqSigHash)
     .put(digest);
  Signature sig = serverKey.signData(
      std::span<const uint8_t>(digest.data(), digest.size()));
  out.put(sig);
  return std::move(out).take();
}

} // namespace ces
