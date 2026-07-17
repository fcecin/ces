// mail_client.h - blocking client for the L2 mail protocol (/ces/mail/1).
//
// One verb (SEND). A thin wrapper over a CesPlexChannel, the same shape as
// CesFileClient / CesComputeClient: one instance, one RUDP channel, one server.
// Pure wire -- it never touches SMTP, so it is built regardless of CES_MAIL and
// works against any server that mounts builtin:mail. The server burns a per-MB
// anti-spam fee from the bound signer and relays the message.

#pragma once

#include <ces/buffer.h>
#include <ces/keys.h>
#include <ces/types.h>

#include <cstdint>
#include <memory>
#include <string>

namespace ces {

class CesPlexChannel;

class CesMailClient {
public:
  CesMailClient();
  ~CesMailClient();

  CesMailClient(const CesMailClient&) = delete;
  CesMailClient& operator=(const CesMailClient&) = delete;

  // Open a UDP socket, wire up Rudp, and perform the signed CesPlex bind
  // handshake for "/ces/mail/1". `signerKey` becomes the channel principal:
  // the SEND is signed by and billed (fee burned) against its pubkey.
  uint8_t connect(const std::string& host, uint16_t rpcPort,
                  const KeyPair& signerKey);

  // Drive the verb over a CesPlexChannel the caller owns and has already
  // bound. Mutually exclusive with connect().
  void attach(CesPlexChannel& channel);

  // Tear down the channel and I/O threads. Safe to call more than once.
  void disconnect();

  // Provide the server's 32-byte public key so the response signature can be
  // verified. Unset = responses treated as unverifiable (one LOGERROR each).
  void setServerPubkey(const minx::Hash& pk);

  // SEND: relay one message. `text` is the plain-text body (binary-safe
  // bytes); it streams as the request body (hash-committed in the preamble),
  // so it is bounded by the server's mailMaxEncodedBytes, not the envelope.
  // to/subject/attachmentPath ride the envelope (<= 1024 bytes combined).
  // `attachmentPath` is an optional store path to one file attachment ("" =
  // none; a private /m/<hex>/ path must be owned by the signer). Returns the
  // server's CES status (CES_OK = charged + queued for delivery).
  uint8_t send(const std::string& to, const std::string& subject,
               const ces::Bytes& text, const std::string& attachmentPath);

  // Implementation detail; public only so the .cpp-local helpers can take
  // Impl& without forward-declaring everything inside the .cpp.
  class Impl;

private:
  std::unique_ptr<Impl> impl_;
};

}  // namespace ces
