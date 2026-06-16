// file_client.cpp - CesFileClient.
//
// A thin verb layer over a CesPlexChannel (see cesplex/session.h) — the
// shared CesPlex client protocol. Each method here is just the verb's
// preamble building, optional streamed body, and response parsing; the
// channel drives the wire (the per-op signed envelope + the server-signed
// response trailer) on whatever transport it was handed: a CesPlexClient's
// owned socket via connect(), or an external endpoint via attach().

#include <ces/l2/file_client.h>
#include <ces/cesplex/session.h>
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
  // Owned transport, used by connect() (the cesh / test path). In attach()
  // mode `owned` stays idle and `chan` points at a channel the caller owns
  // (e.g. the compute child's CesPlex endpoint), so the verb codec below is
  // one implementation regardless of who owns the socket.
  CesPlexClient owned;
  CesPlexChannel* chan = nullptr;
};

CesFileClient::CesFileClient() : impl_(std::make_unique<Impl>()) {}
CesFileClient::~CesFileClient() = default;

uint8_t CesFileClient::connect(const std::string& host, uint16_t rpcPort,
                               const KeyPair& signerKey) {
  uint8_t rc = impl_->owned.connect(host, rpcPort, kFileProto, signerKey);
  if (rc == CES_OK) impl_->chan = impl_->owned.channel();
  return rc;
}

// Drive verbs over a channel the caller owns + has already select()ed (e.g.
// the compute child's CesPlex endpoint). Mutually exclusive with connect().
void CesFileClient::attach(CesPlexChannel& channel) { impl_->chan = &channel; }

void CesFileClient::disconnect() {
  impl_->owned.disconnect();
  impl_->chan = nullptr;
}

void CesFileClient::setServerPubkey(const minx::Hash& pk) {
  if (impl_->chan) impl_->chan->setServerPubkey(pk);
  else impl_->owned.setServerPubkey(pk);
}

// ---- CREATE ----
uint8_t CesFileClient::create(
    const std::string& name,
    uint64_t size, uint64_t pricePerKb, uint64_t initialDeposit,
    uint64_t& outFileBalance, uint64_t& outCostDebited) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint64_t>(pre, size);
  ces::Buffer::put<uint64_t>(pre, pricePerKb);
  ces::Buffer::put<uint64_t>(pre, initialDeposit);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = impl_->chan->buildEnvelope(kVerbCreate, pre);

  ces::Bytes resp, body;
  uint8_t rc = impl_->chan->driveVerb(kVerbCreate, env, /*fixedPre=*/16,
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
  auto env = impl_->chan->buildEnvelope(kVerbWrite, pre);

  ces::Bytes resp, body;
  uint8_t rc = impl_->chan->driveVerb(kVerbWrite, env, /*fixedPre=*/8,
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
  auto env = impl_->chan->buildEnvelope(kVerbRead, pre);

  ces::Bytes resp, body;
  uint8_t rc = impl_->chan->driveVerb(
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
  auto env = impl_->chan->buildEnvelope(kVerbStat, pre);

  // STAT fixed preamble: owner_pubkey + file_balance + price_per_kb +
  // size; the variable hook pulls the two timestamps.
  constexpr size_t kStatFixedPre =
      ces::KEY_SIZE + sizeof(uint64_t) * 3;
  ces::Bytes resp, body;
  uint8_t rc = impl_->chan->driveVerb(
    kVerbStat, env,
    /*fixedPre=*/kStatFixedPre,
    [this](ces::Bytes& p) -> bool {
      ces::Bytes ts;
      if (!impl_->chan->readExact(ts, 16)) return false;
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
  auto env = impl_->chan->buildEnvelope(kVerbDeposit, pre);

  ces::Bytes resp, body;
  uint8_t rc = impl_->chan->driveVerb(kVerbDeposit, env, /*fixedPre=*/8,
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
  auto env = impl_->chan->buildEnvelope(kVerbWithdraw, pre);

  ces::Bytes resp, body;
  uint8_t rc = impl_->chan->driveVerb(kVerbWithdraw, env, /*fixedPre=*/8,
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
  auto env = impl_->chan->buildEnvelope(kVerbSetPrice, pre);

  ces::Bytes resp, body;
  uint8_t rc = impl_->chan->driveVerb(kVerbSetPrice, env, /*fixedPre=*/8,
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
  auto env = impl_->chan->buildEnvelope(kVerbDelete, pre);

  ces::Bytes resp, body;
  uint8_t rc = impl_->chan->driveVerb(kVerbDelete, env, /*fixedPre=*/8,
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
  auto env = impl_->chan->buildEnvelope(kVerbAppend, pre);

  ces::Bytes resp, body;
  uint8_t rc = impl_->chan->driveVerb(
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
  auto env = impl_->chan->buildEnvelope(kVerbResize, pre);

  ces::Bytes resp, body;
  uint8_t rc = impl_->chan->driveVerb(kVerbResize, env, /*fixedPre=*/8,
                                     nullptr, nullptr, {}, resp, body);
  if (rc != CES_OK) return rc;
  outNewSize = ces::Buffer::peek<uint64_t>(resp.data());
  return CES_OK;
}

} // namespace ces
