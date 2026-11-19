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
constexpr uint8_t kVerbChat = 2;
constexpr const char* kThinkProto = "/ces/think/1";
// The longest wait for one reply frame. The server sends a keepalive at
// least every 20 s while a call runs, so a longer silence means it is gone.
constexpr auto kFrameTimeout = std::chrono::minutes(2);
// The longest whole reply, and the largest. The server's own limits end a
// call well before these; they only stop a server that never ends.
constexpr auto kTotalTimeout = std::chrono::minutes(30);
constexpr size_t kMaxReply = 64u * 1024u * 1024u;
constexpr size_t kOkPreamble = 8 + 32 + 1;   // [u64 charged][32 hash][u8 appendError]
// The report after the preamble (see think_handler.h): [u8 usageKnown]
// [u64 prompt][u64 cached][u64 output][u32 maxInput][u32 maxOut][u32 context].
constexpr size_t kReportLen = 1 + 8 * 3 + 4 * 3;
constexpr uint8_t kFlagReport = 0x01;   // request flags, bit 0
constexpr uint8_t kReportBit = 0x80;    // in the appendError byte

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

namespace {

// What one THINK or CHAT asks for, and where its answer goes.
struct Call {
  uint8_t verb = kVerbThink;
  ces::Bytes body;
  ces::Bytes preTail;   // the preamble after [u32 len][32 hash]
  const std::function<void(std::string_view)>* onText = nullptr;
  std::string* reply = nullptr;
  uint64_t* charged = nullptr;
  uint8_t* appendError = nullptr;
  ThinkReport* report = nullptr;
  ThinkChatEnd* end = nullptr;   // CHAT
};

uint8_t drive(CesPlexChannel& chan, Call& c) {
  minx::Hash h = ces::sha256(c.body.data(), c.body.size());
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint32_t>(pre, static_cast<uint32_t>(c.body.size()));
  pre.insert(pre.end(), h.begin(), h.end());
  pre.insert(pre.end(), c.preTail.begin(), c.preTail.end());
  auto env = chan.buildEnvelope(c.verb, pre);

  std::string& reply = *c.reply;
  ces::Bytes outPre;
  uint8_t rc = chan.driveStreamVerb(
      c.verb, env, c.body,
      [&](const ces::Bytes& frame) {
        if (reply.size() + frame.size() > kMaxReply) return false;
        std::string_view piece(reinterpret_cast<const char*>(frame.data()),
                               frame.size());
        reply.append(piece);
        if (*c.onText) (*c.onText)(piece);
        return true;
      },
      kFrameTimeout, kTotalTimeout, kOkPreamble,
      [&](ces::Bytes& p) {
        if (p.size() != kOkPreamble) return true;
        ces::Bytes rest;
        // Bit 7 of the last fixed byte says that the report follows. A server
        // that does not know the flag never sets it.
        if (p[40] & kReportBit) {
          if (!chan.readExact(rest, kReportLen)) return false;
          p.insert(p.end(), rest.begin(), rest.end());
        }
        if (c.end) {   // CHAT: [u32 len][the end of the reply]
          if (!chan.readExact(rest, 4)) return false;
          p.insert(p.end(), rest.begin(), rest.end());
          const uint32_t n = ces::Buffer::peek<uint32_t>(rest.data());
          if (n > kMaxReply || !chan.readExact(rest, n)) return false;
          p.insert(p.end(), rest.begin(), rest.end());
        }
        return true;
      },
      outPre);
  if (rc != CES_OK) return rc;
  if (outPre.size() < kOkPreamble) return CES_ERROR_INTERNAL;
  const bool hasReport = (outPre[40] & kReportBit) != 0;
  size_t off = kOkPreamble + (hasReport ? kReportLen : 0);
  if (outPre.size() < off) return CES_ERROR_INTERNAL;
  std::string_view endJson;
  if (c.end) {
    if (outPre.size() < off + 4) return CES_ERROR_INTERNAL;
    const uint32_t n = ces::Buffer::peek<uint32_t>(outPre.data() + off);
    off += 4;
    if (outPre.size() != off + n) return CES_ERROR_INTERNAL;
    endJson = std::string_view(reinterpret_cast<const char*>(outPre.data() + off), n);
    off += n;
  }
  if (outPre.size() != off) return CES_ERROR_INTERNAL;
  *c.charged = ces::Buffer::peek<uint64_t>(outPre.data());
  minx::Hash got = ces::sha256(
      reinterpret_cast<const uint8_t*>(reply.data()), reply.size());
  if (std::memcmp(got.data(), outPre.data() + 8, 32) != 0)
    return CES_ERROR_INTERNAL;
  if (c.end && !thinkChatEndParse(endJson, *c.end)) return CES_ERROR_INTERNAL;
  if (c.appendError) *c.appendError = static_cast<uint8_t>(outPre[40] & ~kReportBit);
  if (hasReport && c.report) {
    const uint8_t* r = outPre.data() + kOkPreamble;
    c.report->usageKnown = r[0] != 0;
    c.report->usage.promptTokens = ces::Buffer::peek<uint64_t>(r + 1);
    c.report->usage.cachedTokens = ces::Buffer::peek<uint64_t>(r + 9);
    c.report->usage.outputTokens = ces::Buffer::peek<uint64_t>(r + 17);
    c.report->maxInputBytes = ces::Buffer::peek<uint32_t>(r + 25);
    c.report->maxOutTokens = ces::Buffer::peek<uint32_t>(r + 29);
    c.report->contextTokens = ces::Buffer::peek<uint32_t>(r + 33);
  }
  return CES_OK;
}

}  // namespace

uint8_t CesThinkClient::think(
    const std::string& prompt,
    const std::function<void(std::string_view)>& onText, std::string& reply,
    uint64_t& charged, const std::string& file, uint8_t* appendError,
    ThinkReport* report) {
  reply.clear();
  charged = 0;
  if (appendError) *appendError = CES_OK;
  if (report) *report = ThinkReport{};
  if (!impl_->chan) return CES_ERROR_INTERNAL;
  if (prompt.empty() || prompt.size() > UINT32_MAX || file.size() > 1024)
    return CES_ERROR_BAD_INPUT;
  Call c;
  c.verb = kVerbThink;
  c.body.assign(prompt.begin(), prompt.end());
  ces::Buffer::put<uint16_t>(c.preTail, static_cast<uint16_t>(file.size()));
  c.preTail.insert(c.preTail.end(), file.begin(), file.end());
  if (report) ces::Buffer::put<uint8_t>(c.preTail, kFlagReport);
  c.onText = &onText;
  c.reply = &reply;
  c.charged = &charged;
  c.appendError = appendError;
  c.report = report;
  return drive(*impl_->chan, c);
}

uint8_t CesThinkClient::chat(
    const std::string& request,
    const std::function<void(std::string_view)>& onText, std::string& reply,
    ThinkChatEnd& end, uint64_t& charged, ThinkReport* report) {
  reply.clear();
  end = ThinkChatEnd{};
  charged = 0;
  if (report) *report = ThinkReport{};
  if (!impl_->chan) return CES_ERROR_INTERNAL;
  if (request.empty() || request.size() > UINT32_MAX) return CES_ERROR_BAD_INPUT;
  Call c;
  c.verb = kVerbChat;
  c.body.assign(request.begin(), request.end());
  ces::Buffer::put<uint8_t>(c.preTail, report ? kFlagReport : 0);
  c.onText = &onText;
  c.reply = &reply;
  c.charged = &charged;
  c.report = report;
  c.end = &end;
  return drive(*impl_->chan, c);
}

}  // namespace ces
