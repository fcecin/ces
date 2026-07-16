// mail_handler.h - builtin:mail, the outbound email RPC service.
//
// A CesPlex handler with one verb (SEND). The server estimates the encoded
// (on-the-wire) message size, burns a per-MB fee from the signer (anti-spam;
// no payee, the fee is destroyed), then relays via the SMTP client. One
// optional file attachment, referenced by store path; a private /m/ attachment
// is readable only here, owner-gated. Two front doors share mailSubmit(): the
// SEND verb (users) and ces.mail.send (programs, charged from their account).

#pragma once

#ifdef CES_MAIL

#include <ces/cesplex/mux.h>
#include <ces/keys.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

namespace ces {

class CesServer;

class MailHandler : public CesPlexHandler {
 public:
  explicit MailHandler(CesServer* server) : server_(server) {}

  void serve(std::shared_ptr<minx::RudpStream> stream,
             BoundChannelContext bound) override;
  void stop() { stopped_ = true; }

  // estimate -> max-size gate -> burn `payer` -> read attachment -> send.
  // `payer` is the account charged (burned). Returns a CES status.
  uint8_t mailSubmit(const minx::Hash& payer, const std::string& to,
                     const std::string& subject, const std::string& text,
                     const std::string& attachmentPath);

 private:
  CesServer* server_ = nullptr;
  std::atomic<bool> stopped_{false};
};

}  // namespace ces

#endif  // CES_MAIL
