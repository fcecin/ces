// wire.cpp — implementation of the bind contract + per-op
// envelope helpers. See include/ces/cesplex/wire.h for the design.
//
// All wire serialization goes through ces::Buffer / minx::Buffer /
// logkv::serializer — no hand-rolled BE shifts here.

#include <ces/cesplex/wire.h>
#include <ces/buffer.h>
#include <ces/util/hash.h>

#include <cryptopp/sha.h>

#include <cstring>

namespace ces {

// ---------------------------------------------------------------------------
// Server hello
// ---------------------------------------------------------------------------

uint64_t newChallenge() {
  uint64_t c = 0;
  while (c == 0) {
    getThreadLocalPRNG().GenerateBlock(
      reinterpret_cast<CryptoPP::byte*>(&c), sizeof(c));
  }
  return c;
}

minx::Bytes buildServerHello(const ServerHello& hello) {
  minx::Bytes bytes(CES_PLEX_HELLO_SIZE);
  minx::Buffer buf(bytes);
  buf.put(hello.serverPubkey);
  buf.put<uint64_t>(hello.challenge);
  return bytes;
}

ServerHello parseServerHello(
    std::span<const uint8_t, CES_PLEX_HELLO_SIZE> bytes) {
  ServerHello hello;
  minx::ConstBuffer reader{std::span<const uint8_t>(bytes)};
  reader.get(hello.serverPubkey);
  reader.get(hello.challenge);
  return hello;
}

// ---------------------------------------------------------------------------
// Bind preamble — client side
// ---------------------------------------------------------------------------

std::array<uint8_t, CES_PLEX_SHA256_SIZE>
computeBindRequestDigest(std::span<const uint8_t> name,
                         uint64_t clientTimeUs,
                         std::span<const uint8_t> clientPubkey,
                         const ServerHello& hello) {
  CryptoPP::SHA256 h;
  ces::shaUpdate(h, static_cast<uint16_t>(name.size()));
  if (!name.empty()) h.Update(name.data(), name.size());
  ces::shaUpdate(h, clientTimeUs);
  h.Update(clientPubkey.data(), clientPubkey.size());
  h.Update(hello.serverPubkey.data(), hello.serverPubkey.size());
  ces::shaUpdate(h, hello.challenge);
  std::array<uint8_t, CES_PLEX_SHA256_SIZE> out;
  h.Final(out.data());
  return out;
}

namespace {

// [u16 name_len][name][u64 client_time_us][client_pubkey][client_sha256][sig].
minx::Bytes serializeBindRequest(
    std::span<const uint8_t> name, uint64_t clientTimeUs,
    std::span<const uint8_t> clientPubkey,
    const std::array<uint8_t, CES_PLEX_SHA256_SIZE>& digest,
    const Signature& sig) {
  const size_t total =
      CES_PLEX_NAME_LEN_SIZE + name.size() + CES_PLEX_BIND_REQ_TAIL_SIZE;
  minx::Bytes bytes(total);
  minx::Buffer buf(bytes);
  buf.put<uint16_t>(static_cast<uint16_t>(name.size()));
  buf.put(name);
  buf.put<uint64_t>(clientTimeUs);
  buf.put(clientPubkey);
  buf.put(digest);
  buf.put(sig);
  return bytes;
}

} // namespace

minx::Bytes buildBindRequest(const std::string& name,
                              uint64_t clientTimeUs,
                              const KeyPair& clientKey,
                              const ServerHello& hello) {
  const auto& pkArr = clientKey.getPublicKeyAsHash();
  std::span<const uint8_t> nameSpan(
    reinterpret_cast<const uint8_t*>(name.data()), name.size());
  std::span<const uint8_t> pkSpan(pkArr.data(), pkArr.size());
  auto digest =
    computeBindRequestDigest(nameSpan, clientTimeUs, pkSpan, hello);
  Signature sig = clientKey.signData(
    std::span<const uint8_t>(digest.data(), digest.size()));
  return serializeBindRequest(nameSpan, clientTimeUs, pkSpan, digest, sig);
}

minx::Bytes buildBindRequestSigned(const std::string& name,
                                   uint64_t clientTimeUs,
                                   std::span<const uint8_t> clientPubkey,
                                   const ServerHello& hello,
                                   const Signature& sig) {
  std::span<const uint8_t> nameSpan(
    reinterpret_cast<const uint8_t*>(name.data()), name.size());
  auto digest =
    computeBindRequestDigest(nameSpan, clientTimeUs, clientPubkey, hello);
  return serializeBindRequest(nameSpan, clientTimeUs, clientPubkey, digest, sig);
}

std::optional<std::array<uint8_t, CES_PLEX_SHA256_SIZE>>
bindRequestDigest(const minx::Bytes& request) {
  if (request.size() < CES_PLEX_NAME_LEN_SIZE + CES_PLEX_BIND_REQ_TAIL_SIZE)
    return std::nullopt;
  // The request ends with [32 client_sha256][65 sig].
  std::array<uint8_t, CES_PLEX_SHA256_SIZE> out{};
  const size_t off =
    request.size() - CES_PLEX_SIG_SIZE - CES_PLEX_SHA256_SIZE;
  std::memcpy(out.data(), request.data() + off, out.size());
  return out;
}

minx::Bytes buildBindName(const std::string& name) {
  minx::Bytes bytes(CES_PLEX_NAME_LEN_SIZE + name.size());
  minx::Buffer buf(bytes);
  buf.put<uint16_t>(static_cast<uint16_t>(name.size()));
  buf.put(std::span<const uint8_t>(
    reinterpret_cast<const uint8_t*>(name.data()), name.size()));
  return bytes;
}

std::optional<minx::Bytes> bindRequestTail(const minx::Bytes& request) {
  if (request.size() < CES_PLEX_NAME_LEN_SIZE) return std::nullopt;
  const size_t nameLen = ces::Buffer::peek<uint16_t>(
    std::span<const uint8_t>(
      reinterpret_cast<const uint8_t*>(request.data()), request.size()), 0);
  const size_t head = CES_PLEX_NAME_LEN_SIZE + nameLen;
  if (request.size() != head + CES_PLEX_BIND_REQ_TAIL_SIZE) return std::nullopt;
  return minx::Bytes(request.begin() + head, request.end());
}

// ---------------------------------------------------------------------------
// Bind reply — server side
// ---------------------------------------------------------------------------

namespace {

// Build the bytes-to-be-hashed for the reply digest:
// status || clientSha256 || serverTimeUs || serverPubkey ||
// challenge || serverProtoVersion.
std::array<uint8_t, CES_PLEX_SHA256_SIZE>
computeBindReplyDigestRaw(uint8_t status,
                          std::span<const uint8_t> clientSha256,
                          uint64_t serverTimeUs,
                          std::span<const uint8_t> serverPubkey,
                          uint64_t challenge,
                          uint32_t serverProtoVersion) {
  CryptoPP::SHA256 h;
  h.Update(&status, 1);
  h.Update(clientSha256.data(), clientSha256.size());
  ces::shaUpdate(h, serverTimeUs);
  h.Update(serverPubkey.data(), serverPubkey.size());
  ces::shaUpdate(h, challenge);
  ces::shaUpdate(h, serverProtoVersion);
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
    reply.challenge, reply.serverProtoVersion);
}

minx::Bytes buildBindReply(const BindReplyFields& fields,
                            std::span<const uint8_t> clientSha256,
                            const KeyPair& serverKey) {
  const auto& pkArr = serverKey.getPublicKeyAsHash();
  std::span<const uint8_t> pkSpan(pkArr.data(), pkArr.size());
  auto digest = computeBindReplyDigestRaw(
    fields.status, clientSha256, fields.serverTimeUs, pkSpan,
    fields.challenge, fields.serverProtoVersion);

  Signature sig = serverKey.signData(
    std::span<const uint8_t>(digest.data(), digest.size()));

  minx::Bytes bytes(CES_PLEX_BIND_REPLY_TOTAL_SIZE);
  minx::Buffer buf(bytes);
  buf.put<uint8_t>(fields.status);
  buf.put<uint64_t>(fields.serverTimeUs);
  buf.put(pkArr);
  buf.put<uint64_t>(fields.challenge);
  buf.put<uint32_t>(fields.serverProtoVersion);
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
  reader.get(r.challenge);
  reader.get(r.serverProtoVersion);
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
                   const BindDigest& bindDigest) {
  CryptoPP::SHA256 h;
  h.Update(&verb, 1);
  if (!preamble.empty()) h.Update(preamble.data(), preamble.size());
  h.Update(bindDigest.data(), bindDigest.size());
  std::array<uint8_t, CES_PLEX_SHA256_SIZE> out;
  h.Final(out.data());
  return out;
}

Signature signPerOp(const KeyPair& signer,
                    uint8_t verb,
                    std::span<const uint8_t> preamble,
                    const BindDigest& bindDigest) {
  auto digest = computePerOpDigest(verb, preamble, bindDigest);
  return signer.signData(
    std::span<const uint8_t>(digest.data(), digest.size()));
}

bool verifyPerOp(const BoundChannelContext& bound,
                 uint8_t verb,
                 std::span<const uint8_t> preamble,
                 const Signature& sig) {
  auto digest = computePerOpDigest(verb, preamble, bound.bindDigest);
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
