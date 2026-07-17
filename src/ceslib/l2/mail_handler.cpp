// mail_handler.cpp - see mail_handler.h.

#ifdef CES_MAIL

#include <ces/l2/mail_handler.h>

#include <ces/buffer.h>
#include <ces/cesplex/session.h>
#include <ces/l2/file_handler.h>
#include <ces/ramfilestore.h> // ces::sha256
#include <ces/server.h>
#include <ces/util/log.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>

LOG_MODULE("mail")

namespace ces {
namespace {

constexpr uint8_t kVerbMailSend = 1;
constexpr uint64_t kOneMB = 1024ull * 1024;

uint64_t ceilMB(uint64_t bytes) { return (bytes + kOneMB - 1) / kOneMB; }

// Estimate the encoded (on-the-wire) size of a message from its parts, without
// doing any encoding. base64 is deterministic (+~33% plus CRLF wrapping); the
// fixed 300s cover the RFC 5322 / MIME headers.
uint64_t estimateEncoded(size_t textLen, uint64_t attSize, bool hasAtt) {
  uint64_t total = 300 + textLen;
  if (hasAtt) {
    uint64_t b64 = ((attSize + 2) / 3) * 4;   // base64 length
    b64 += (b64 / 76) * 2;                    // CRLF line wrapping
    total += b64 + 300;                       // + MIME part headers
  }
  return total;
}

std::string baseName(const std::string& path) {
  auto p = path.find_last_of('/');
  return p == std::string::npos ? path : path.substr(p + 1);
}

// For an /m/<64hex>/... path, is it owned by `payer`? The 64-hex is the owner.
bool mZoneOwnedBy(const std::string& path, const minx::Hash& payer) {
  if (path.size() < 3 + 64 || path[1] != 'm' || path[2] != '/') return false;
  static const char* H = "0123456789abcdef";
  std::string payerHex;
  payerHex.reserve(64);
  for (uint8_t b : payer) {
    payerHex.push_back(H[b >> 4]);
    payerHex.push_back(H[b & 0xF]);
  }
  return path.compare(3, 64, payerHex) == 0;
}

// SEND. The body text streams as the request body (hash-committed in the
// preamble, like file WRITE / compute CALL), so it is not bounded by the
// envelope; only the small headers ride the signed preamble.
// Preamble (after nonce): [u16 toLen][to][u16 sjLen][subject]
// [u32 textLen][32 textHash][u16 pathLen][path]; body = text bytes.
void dispatchSend(std::shared_ptr<CesPlexRequest> req, ces::Bytes pre,
                  MailHandler* self) {
  ces::Buffer buf(std::move(pre));
  std::string to, subject, path;
  uint32_t textLen = 0;
  std::array<uint8_t, 32> textHash{};
  try {
    uint16_t toLen = buf.get<uint16_t>();
    to = buf.getBytes<std::string>(toLen);
    uint16_t sjLen = buf.get<uint16_t>();
    subject = buf.getBytes<std::string>(sjLen);
    textLen = buf.get<uint32_t>();
    textHash = buf.get<std::array<uint8_t, 32>>();
    uint16_t pLen = buf.get<uint16_t>();
    path = buf.getBytes<std::string>(pLen);
  } catch (const std::out_of_range&) {
    req->errorAndClose(CES_ERROR_BAD_INPUT);   // body length unknown
    return;
  }
  const auto& cfg = static_cast<CesServer*>(req->host)->_config();
  if (to.empty() || textLen > cfg.mailMaxEncodedBytes) {
    req->errorAndClose(CES_ERROR_BAD_INPUT);   // body in flight -> close
    return;
  }
  // Consume the body before any check that could loop, so the wire stays in
  // sync (mirrors compute CALL). textLen == 0 is a valid empty-body message.
  auto text = std::make_shared<ces::Bytes>(textLen);
  auto finish = [req, to, subject, path, text, textHash, self]() {
    minx::Hash got = ces::sha256(text->data(), text->size());
    if (std::memcmp(got.data(), textHash.data(), 32) != 0) {
      req->error(CES_ERROR_INTERNAL);
      return;
    }
    minx::Hash signer = req->bound.boundPubkey.getHash();
    uint8_t status = self->mailSubmit(
        signer, to, subject, std::string(text->begin(), text->end()), path);
    req->respond(status, {});
  };
  if (textLen == 0) { finish(); return; }
  boost::asio::async_read(
    *req->stream, boost::asio::buffer(*text),
    [finish](const boost::system::error_code& ec, std::size_t) {
      if (ec) return;   // stream dead
      finish();
    });
}

}  // namespace

void MailHandler::serve(std::shared_ptr<minx::RudpStream> stream,
                        BoundChannelContext bound) {
  MailHandler* self = this;
  CesPlexProtocol proto;
  proto.accepts = [this](uint8_t verb) {
    return !stopped_.load() && verb == kVerbMailSend;
  };
  proto.dispatch = [self](std::shared_ptr<CesPlexRequest> req, ces::Bytes pre) {
    dispatchSend(req, std::move(pre), self);
  };
  cesPlexServe(std::move(stream), std::move(bound), server_, std::move(proto));
}

uint8_t MailHandler::mailSubmit(const minx::Hash& payer, const std::string& to,
                                const std::string& subject,
                                const std::string& text,
                                const std::string& attachmentPath) {
  const auto& cfg = server_->_config();
  const bool hasAtt = !attachmentPath.empty();
  uint64_t attSize = 0;
  if (hasAtt) {
    // A private /m/ attachment may be sent only by its owner (the payer).
    if (attachmentPath.size() > 1 && attachmentPath[1] == 'm' &&
        !mZoneOwnedBy(attachmentPath, payer))
      return CES_ERROR_NOT_OWNER;
    if (!server_->fileHandler() ||
        !server_->fileHandler()->attachmentSize(attachmentPath, attSize))
      return CES_ERROR_FILE_NOT_FOUND;
  }
  const uint64_t encoded = estimateEncoded(text.size(), attSize, hasAtt);
  if (encoded > cfg.mailMaxEncodedBytes) return CES_ERROR_BAD_INPUT;  // too big
  const uint64_t price = ceilMB(encoded) * cfg.mailFeePerMB;
  if (!server_->mailChargeSync(payer, price))
    return CES_ERROR_INSUFFICIENT_BALANCE;

  // Charged (fee burned). Now do the encode/send work.
  CesServer::MailMessage m;
  m.to = to;
  m.subject = subject;
  m.body = text;
  if (hasAtt) {
    ces::Bytes content;
    uint8_t rc = server_->fileHandler()->readAttachment(
        attachmentPath, cfg.mailMaxEncodedBytes, content);
    if (rc != CES_OK) return rc;   // the fee is already burned (anti-spam)
    m.attachmentName = baseName(attachmentPath);
    m.attachmentData.assign(content.begin(), content.end());
  }
  server_->mailDeliver(m);
  return CES_OK;
}

}  // namespace ces

#endif  // CES_MAIL
