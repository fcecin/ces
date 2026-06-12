// file_client.cpp - CesFileClient.
//
// A thin verb layer over CesPlexClient (see cesplex.h), which owns all the
// MINX/Rudp/threads/bind plumbing. Each method here is just the verb's
// preamble building, optional streamed body, and response parsing; the
// shared client drives the wire (including the per-op signed envelope and
// the server-signed response trailer).

#include <ces/l2/file_client.h>
#include <ces/l2/cesplex.h>
#include <ces/buffer.h>
#include <ces/ramfilestore.h> // ces::sha256
#include <ces/types.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <span>
#include <vector>

namespace ces {

namespace {

constexpr uint8_t kVerbCreate   = 0x01;
constexpr uint8_t kVerbWrite    = 0x02;
constexpr uint8_t kVerbRead     = 0x03;
constexpr uint8_t kVerbStat     = 0x04;
constexpr uint8_t kVerbDeposit  = 0x05;
constexpr uint8_t kVerbWithdraw = 0x06;
constexpr uint8_t kVerbSetPrice = 0x07;
constexpr uint8_t kVerbDelete   = 0x08;
constexpr uint8_t kVerbAppend   = 0x09;
constexpr uint8_t kVerbResize   = 0x0a;

constexpr const char* kFileProto = "/ces/file/1";

} // namespace

class CesFileClient::Impl {
public:
  CesPlexClient base;
};

CesFileClient::CesFileClient() : impl_(std::make_unique<Impl>()) {}
CesFileClient::~CesFileClient() = default;

uint8_t CesFileClient::connect(const std::string& host, uint16_t rpcPort,
                               const KeyPair& signerKey) {
  return impl_->base.connect(host, rpcPort, kFileProto, signerKey);
}

void CesFileClient::disconnect() { impl_->base.disconnect(); }

void CesFileClient::setServerPubkey(const minx::Hash& pk) {
  impl_->base.setServerPubkey(pk);
}

// ---- CREATE ----
uint8_t CesFileClient::create(
    const std::string& name,
    uint64_t size, uint64_t pricePerKb, uint64_t initialDeposit,
    const std::string& contentType,
    uint64_t& outFileBalance, uint64_t& outCostDebited) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint64_t>(pre, size);
  ces::Buffer::put<uint64_t>(pre, pricePerKb);
  ces::Buffer::put<uint64_t>(pre, initialDeposit);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(contentType.size()));
  pre.insert(pre.end(), contentType.begin(), contentType.end());
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = impl_->base.buildEnvelope(kVerbCreate, pre);

  ces::Bytes resp, body;
  uint8_t rc = impl_->base.driveVerb(kVerbCreate, env, /*fixedPre=*/16,
                                     nullptr, nullptr, {}, resp, body);
  if (rc != CES_OK) return rc;
  outFileBalance = ces::Buffer::peek<uint64_t>(resp.data());
  outCostDebited = ces::Buffer::peek<uint64_t>(resp.data() + 8);
  return CES_OK;
}

// ---- WRITE ----
uint8_t CesFileClient::write(
    const std::string& name,
    uint64_t offset, const ces::Bytes& content,
    uint64_t& outFileBalance) {
  minx::Hash contentHash = ces::sha256(content.data(), content.size());
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint64_t>(pre, offset);
  ces::Buffer::put<uint32_t>(pre, static_cast<uint32_t>(content.size()));
  pre.insert(pre.end(), contentHash.begin(), contentHash.end());
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = impl_->base.buildEnvelope(kVerbWrite, pre);

  ces::Bytes resp, body;
  uint8_t rc = impl_->base.driveVerb(kVerbWrite, env, /*fixedPre=*/8,
                                     nullptr, nullptr, content, resp, body);
  if (rc != CES_OK) return rc;
  outFileBalance = ces::Buffer::peek<uint64_t>(resp.data());
  return CES_OK;
}

// ---- READ ----
uint8_t CesFileClient::read(
    const std::string& name,
    uint64_t offset, uint32_t length,
    ces::Bytes& outContent, minx::Hash& outRangeHash) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint64_t>(pre, offset);
  ces::Buffer::put<uint32_t>(pre, length);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = impl_->base.buildEnvelope(kVerbRead, pre);

  ces::Bytes resp, body;
  uint8_t rc = impl_->base.driveVerb(
    kVerbRead, env,
    /*fixedPre=*/sizeof(uint64_t) + sizeof(minx::Hash),
    nullptr,
    [](const ces::Bytes& p) -> uint64_t {
      return ces::Buffer::peek<uint64_t>(p.data());
    },
    {}, resp, body);
  if (rc != CES_OK) return rc;
  std::memcpy(outRangeHash.data(), resp.data() + sizeof(uint64_t),
              sizeof(minx::Hash));
  outContent = std::move(body);
  return CES_OK;
}

// ---- STAT ----
uint8_t CesFileClient::stat(const std::string& name, StatInfo& outInfo) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = impl_->base.buildEnvelope(kVerbStat, pre);

  // STAT fixed preamble: owner_pubkey + file_balance + price_per_kb +
  // size + content_type_len; the variable hook pulls content_type + the
  // two timestamps.
  constexpr size_t kStatFixedPre =
      ces::KEY_SIZE + sizeof(uint64_t) * 3 + sizeof(uint16_t);
  ces::Bytes resp, body;
  uint8_t rc = impl_->base.driveVerb(
    kVerbStat, env,
    /*fixedPre=*/kStatFixedPre,
    [this](ces::Bytes& p) -> bool {
      uint16_t ctLen = ces::Buffer::peek<uint16_t>(
          p.data() + (kStatFixedPre - sizeof(uint16_t)));
      if (ctLen > 0) {
        ces::Bytes ct;
        if (!impl_->base.readExact(ct, ctLen)) return false;
        p.insert(p.end(), ct.begin(), ct.end());
      }
      ces::Bytes ts;
      if (!impl_->base.readExact(ts, 16)) return false;
      p.insert(p.end(), ts.begin(), ts.end());
      return true;
    },
    nullptr, {}, resp, body);
  if (rc != CES_OK) return rc;

  ces::Buffer buf(std::move(resp));
  try {
    outInfo.ownerPubkey = buf.get<std::array<uint8_t, 32>>();
    outInfo.fileBalance = buf.get<uint64_t>();
    outInfo.pricePerKb = buf.get<uint64_t>();
    outInfo.size = buf.get<uint64_t>();
    uint16_t ctLen = buf.get<uint16_t>();
    outInfo.contentType = buf.getBytes<std::string>(ctLen);
    outInfo.createdUs = buf.get<uint64_t>();
    outInfo.modifiedUs = buf.get<uint64_t>();
  } catch (const std::out_of_range&) {
    return CES_ERROR_INTERNAL;
  }
  return CES_OK;
}

// ---- DEPOSIT ----
uint8_t CesFileClient::deposit(const std::string& name,
                               uint64_t amount, uint64_t& outFileBalance) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint64_t>(pre, amount);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = impl_->base.buildEnvelope(kVerbDeposit, pre);

  ces::Bytes resp, body;
  uint8_t rc = impl_->base.driveVerb(kVerbDeposit, env, /*fixedPre=*/8,
                                     nullptr, nullptr, {}, resp, body);
  if (rc != CES_OK) return rc;
  outFileBalance = ces::Buffer::peek<uint64_t>(resp.data());
  return CES_OK;
}

// ---- WITHDRAW ----
uint8_t CesFileClient::withdraw(const std::string& name,
                                uint64_t amount, uint64_t& outFileBalance) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint64_t>(pre, amount);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = impl_->base.buildEnvelope(kVerbWithdraw, pre);

  ces::Bytes resp, body;
  uint8_t rc = impl_->base.driveVerb(kVerbWithdraw, env, /*fixedPre=*/8,
                                     nullptr, nullptr, {}, resp, body);
  if (rc != CES_OK) return rc;
  outFileBalance = ces::Buffer::peek<uint64_t>(resp.data());
  return CES_OK;
}

// ---- SET_PRICE ----
uint8_t CesFileClient::setPrice(const std::string& name,
                                uint64_t newPrice, uint64_t& outPrice) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint64_t>(pre, newPrice);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = impl_->base.buildEnvelope(kVerbSetPrice, pre);

  ces::Bytes resp, body;
  uint8_t rc = impl_->base.driveVerb(kVerbSetPrice, env, /*fixedPre=*/8,
                                     nullptr, nullptr, {}, resp, body);
  if (rc != CES_OK) return rc;
  outPrice = ces::Buffer::peek<uint64_t>(resp.data());
  return CES_OK;
}

// ---- DELETE ----
uint8_t CesFileClient::deleteFile(const std::string& name,
                                  uint64_t& outRefunded) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = impl_->base.buildEnvelope(kVerbDelete, pre);

  ces::Bytes resp, body;
  uint8_t rc = impl_->base.driveVerb(kVerbDelete, env, /*fixedPre=*/8,
                                     nullptr, nullptr, {}, resp, body);
  if (rc != CES_OK) return rc;
  outRefunded = ces::Buffer::peek<uint64_t>(resp.data());
  return CES_OK;
}

// ---- APPEND ----
uint8_t CesFileClient::append(const std::string& name,
                              const ces::Bytes& content,
                              uint64_t& outFileBalance,
                              uint64_t& outNewSize) {
  minx::Hash contentHash = ces::sha256(content.data(), content.size());
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint32_t>(pre, static_cast<uint32_t>(content.size()));
  pre.insert(pre.end(), contentHash.begin(), contentHash.end());
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = impl_->base.buildEnvelope(kVerbAppend, pre);

  ces::Bytes resp, body;
  uint8_t rc = impl_->base.driveVerb(
    kVerbAppend, env, /*fixedPre=*/sizeof(uint64_t) + sizeof(uint64_t),
    nullptr, nullptr, content, resp, body);
  if (rc != CES_OK) return rc;
  outFileBalance = ces::Buffer::peek<uint64_t>(resp.data());
  outNewSize = ces::Buffer::peek<uint64_t>(resp.data() + 8);
  return CES_OK;
}

// ---- RESIZE ----
uint8_t CesFileClient::resize(const std::string& name,
                              uint64_t newSize, uint64_t& outNewSize) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint64_t>(pre, newSize);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = impl_->base.buildEnvelope(kVerbResize, pre);

  ces::Bytes resp, body;
  uint8_t rc = impl_->base.driveVerb(kVerbResize, env, /*fixedPre=*/8,
                                     nullptr, nullptr, {}, resp, body);
  if (rc != CES_OK) return rc;
  outNewSize = ces::Buffer::peek<uint64_t>(resp.data());
  return CES_OK;
}

} // namespace ces
