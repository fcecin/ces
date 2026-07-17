// mail_client.cpp - CesMailClient. See mail_client.h.
//
// One verb (SEND) over a CesPlexChannel: build the preamble, drive the wire.
// The transport is whatever the channel was handed (connect() = owned socket,
// attach() = external).

#include <ces/l2/mail_client.h>
#include <ces/cesplex/session.h>
#include <ces/buffer.h>
#include <ces/ramfilestore.h> // ces::sha256
#include <ces/types.h>

#include <cstdint>

namespace ces {

namespace {

constexpr uint8_t kVerbMailSend = 1;
constexpr const char* kMailProto = "/ces/mail/1";

}  // namespace

class CesMailClient::Impl {
public:
  // As in CesFileClient::Impl: `owned` drives connect(); attach() points `chan`
  // at a channel the caller owns. The verb codec rides `chan`.
  CesPlexClient owned;
  CesPlexChannel* chan = nullptr;
};

CesMailClient::CesMailClient() : impl_(std::make_unique<Impl>()) {}
CesMailClient::~CesMailClient() = default;

uint8_t CesMailClient::connect(const std::string& host, uint16_t rpcPort,
                               const KeyPair& signerKey) {
  uint8_t rc = impl_->owned.connect(host, rpcPort, kMailProto, signerKey);
  if (rc == CES_OK) impl_->chan = impl_->owned.channel();
  return rc;
}

void CesMailClient::attach(CesPlexChannel& channel) {
  impl_->chan = &channel;
}

void CesMailClient::disconnect() {
  impl_->owned.disconnect();
  impl_->chan = nullptr;
}

void CesMailClient::setServerPubkey(const minx::Hash& pk) {
  if (impl_->chan) impl_->chan->setServerPubkey(pk);
  else impl_->owned.setServerPubkey(pk);
}

uint8_t CesMailClient::send(const std::string& to, const std::string& subject,
                            const ces::Bytes& text,
                            const std::string& attachmentPath) {
  // Headers ride the signed preamble, which must fit the MTU-bounded
  // envelope (~1.2 KB total); 1024 leaves margin for the framing. The body
  // streams separately (hash-committed), so its size is not envelope-bounded.
  if (to.size() + subject.size() + attachmentPath.size() > 1024 ||
      text.size() > UINT32_MAX)
    return CES_ERROR_BAD_INPUT;

  minx::Hash textHash = ces::sha256(text.data(), text.size());
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(to.size()));
  pre.insert(pre.end(), to.begin(), to.end());
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(subject.size()));
  pre.insert(pre.end(), subject.begin(), subject.end());
  ces::Buffer::put<uint32_t>(pre, static_cast<uint32_t>(text.size()));
  pre.insert(pre.end(), textHash.begin(), textHash.end());
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(attachmentPath.size()));
  pre.insert(pre.end(), attachmentPath.begin(), attachmentPath.end());
  auto env = impl_->chan->buildEnvelope(kVerbMailSend, pre);

  ces::Bytes outPre, outBody;
  return impl_->chan->driveVerb(kVerbMailSend, env, /*fixedPre=*/0,
                                /*readVariablePreamble=*/nullptr,
                                /*respBodyLen=*/nullptr,
                                /*extraBodyToSend=*/text, outPre, outBody);
}

}  // namespace ces
