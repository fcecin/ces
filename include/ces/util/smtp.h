// smtp.h - SMTP submission client for the outbound mail relay (--mail only).
//
// Synchronous SMTP: EHLO / opportunistic STARTTLS / optional AUTH LOGIN / MAIL /
// RCPT / DATA. If the relay advertises STARTTLS the connection upgrades to TLS
// (OpenSSL, via boost::asio::ssl) and everything after (AUTH, envelope, body)
// rides the encrypted channel, with a fresh EHLO after the upgrade per RFC 3207.
// A relay that does not advertise STARTTLS is spoken to in plaintext. The peer
// certificate is not verified.
//
// Blocking: call OFF the CesPlex strand. CesServer::mailDeliver runs it on a
// worker thread; tests call it directly against an in-process mock server.

#pragma once

#ifdef CES_MAIL

#include <cstdint>
#include <string>

namespace ces {

struct SmtpConfig {
  std::string host;
  uint16_t    port = 587;
  std::string from;
  std::string user;   // empty => skip AUTH
  std::string pass;
  uint32_t    timeout_secs = 60;   // per-connection watchdog: a relay that
                                   // accepts then stalls cannot hang the caller
                                   // past this; the send fails instead.
};

// One optional file attachment. `data` is the already-read raw bytes (bounded
// by the server's max message size, so it fits in memory). With an attachment
// present the message is sent as MIME multipart/mixed: a text part plus a
// base64 attachment part.
struct MailAttachment {
  std::string filename;
  std::string contentType = "application/octet-stream";
  std::string data;
};

// Submit one message (optionally with one attachment). Returns true on a 2xx
// final reply. On failure returns false and, if `errOut` is non-null, a short
// diagnostic.
bool smtpSend(const SmtpConfig& cfg, const std::string& to,
              const std::string& subject, const std::string& body,
              const MailAttachment* attachment = nullptr,
              std::string* errOut = nullptr);

}  // namespace ces

#endif  // CES_MAIL
