// think_client.cpp - CesThinkClient. See think_client.h.

#include <ces/l2/think_client.h>
#include <ces/cesplex/session.h>
#include <ces/buffer.h>
#include <ces/ramfilestore.h>   // ces::sha256
#include <ces/types.h>

#include <chrono>
#include <cstdint>
#include <cstring>

namespace ces {

namespace {

constexpr uint8_t kVerbThink = 1;
constexpr const char* kThinkProto = "/ces/think/1";
// The longest wait for one reply frame. The server's own call timeout ends
// a call first; this only catches a server that went silent.
constexpr auto kFrameTimeout = std::chrono::minutes(15);
constexpr size_t kOkPreamble = 8 + 32;   // [u64 charged][32 reply hash]

}  // namespace

class CesThinkClient::Impl {
public:
  CesPlexClient owned;
  CesPlexChannel* chan = nullptr;
};

CesThinkClient::CesThinkClient() : impl_(std::make_unique<Impl>()) {}
CesThinkClient::~CesThinkClient() = default;

uint8_t CesThinkClient::connect(const std::string& host, uint16_t rpcPort,
                                const KeyPair& signerKey) {
  uint8_t rc = impl_->owned.connect(host, rpcPort, kThinkProto, signerKey);
  if (rc == CES_OK) impl_->chan = impl_->owned.channel();
  return rc;
}

void CesThinkClient::attach(CesPlexChannel& channel) {
  impl_->chan = &channel;
}

void CesThinkClient::disconnect() {
  impl_->owned.disconnect();
  impl_->chan = nullptr;
}

void CesThinkClient::setServerPubkey(const minx::Hash& pk) {
  if (impl_->chan) impl_->chan->setServerPubkey(pk);
  else impl_->owned.setServerPubkey(pk);
}

uint8_t CesThinkClient::think(
    const std::string& prompt,
    const std::function<void(std::string_view)>& onText, std::string& reply,
    uint64_t& charged) {
  reply.clear();
  charged = 0;
  if (!impl_->chan) return CES_ERROR_INTERNAL;
  if (prompt.empty() || prompt.size() > UINT32_MAX) return CES_ERROR_BAD_INPUT;

  ces::Bytes body(prompt.begin(), prompt.end());
  minx::Hash h = ces::sha256(body.data(), body.size());
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint32_t>(pre, static_cast<uint32_t>(body.size()));
  pre.insert(pre.end(), h.begin(), h.end());
  auto env = impl_->chan->buildEnvelope(kVerbThink, pre);

  ces::Bytes outPre;
  uint8_t rc = impl_->chan->driveStreamVerb(
      kVerbThink, env, body,
      [&](const ces::Bytes& frame) {
        std::string_view piece(reinterpret_cast<const char*>(frame.data()),
                               frame.size());
        reply.append(piece);
        if (onText) onText(piece);
      },
      kFrameTimeout, kOkPreamble, outPre);
  if (rc != CES_OK) return rc;
  if (outPre.size() != kOkPreamble) return CES_ERROR_INTERNAL;
  charged = ces::Buffer::peek<uint64_t>(outPre.data());
  minx::Hash got = ces::sha256(
      reinterpret_cast<const uint8_t*>(reply.data()), reply.size());
  if (std::memcmp(got.data(), outPre.data() + 8, 32) != 0)
    return CES_ERROR_INTERNAL;
  return CES_OK;
}

}  // namespace ces
