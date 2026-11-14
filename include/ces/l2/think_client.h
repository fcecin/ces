// think_client.h - blocking client for the L2 think protocol (/ces/think/1).
//
// One verb (THINK): send a prompt text, get the reply text as a stream. A
// thin wrapper over a CesPlexChannel, the same shape as CesMailClient. Pure
// wire, so it is built in every configuration and works against any server
// that mounts builtin:think. The bound signer pays (see think_handler.h).

#pragma once

#include <ces/keys.h>
#include <ces/types.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace ces {

class CesPlexChannel;

class CesThinkClient {
public:
  CesThinkClient();
  ~CesThinkClient();

  CesThinkClient(const CesThinkClient&) = delete;
  CesThinkClient& operator=(const CesThinkClient&) = delete;

  // Open a UDP socket, wire up Rudp, and do the signed CesPlex bind for
  // "/ces/think/1". `signerKey` becomes the channel principal and the payer.
  uint8_t connect(const std::string& host, uint16_t rpcPort,
                  const KeyPair& signerKey);

  // Drive the verb over a CesPlexChannel the caller owns and has already
  // bound. Mutually exclusive with connect().
  void attach(CesPlexChannel& channel);

  // Tear down the channel and I/O threads. Safe to call more than once.
  void disconnect();

  // Provide the server's public key so the response signature can be
  // verified. Unset = responses are unverifiable (one LOGERROR each).
  void setServerPubkey(const minx::Hash& pk);

  // THINK: send `prompt` (UTF-8, not empty). onText (may be empty) gets each
  // piece of the reply as it arrives. `reply` gets the full reply text,
  // which is partial when the status is not CES_OK. On CES_OK, `charged` is
  // the cost in raw credit units, and the reply text matches the hash that
  // the server signed (else CES_ERROR_INTERNAL).
  //
  // `file` (optional) names a conversation file in the server's store: the
  // server puts its content before the prompt, and after a complete reply
  // appends the prompt and the reply to it if the signer owns it and can pay
  // the append. `updated` (optional) tells whether that happened.
  uint8_t think(const std::string& prompt,
                const std::function<void(std::string_view)>& onText,
                std::string& reply, uint64_t& charged,
                const std::string& file = {}, bool* updated = nullptr);

  class Impl;

private:
  std::unique_ptr<Impl> impl_;
};

}  // namespace ces
