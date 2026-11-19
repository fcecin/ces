// think_client.h - blocking client for the L2 think protocol (/ces/think/1).
//
// THINK sends a prompt text, and CHAT sends a chat request with messages and
// tools. Both stream the reply text, and CHAT also gets the tool calls at the
// end. The client wraps a CesPlexChannel, as CesMailClient does. It has only
// wire code, so every configuration builds it, and it works with any server
// that mounts builtin:think. The bound signer pays (see think_handler.h).

#pragma once

#include <ces/keys.h>
#include <ces/l2/think_backend.h>   // ThinkReport, ThinkChatEnd
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
  // the append. `appendError` (optional) gets the APPEND's status: CES_OK
  // when appended (or with no file), else its error code.
  // `report` (optional) asks the server for the report: what the call used
  // (the prompt tokens, the cached ones, the output tokens) and its limits.
  // It stays default (usageKnown false, limits 0) when the server is older
  // and does not send it.
  uint8_t think(const std::string& prompt,
                const std::function<void(std::string_view)>& onText,
                std::string& reply, uint64_t& charged,
                const std::string& file = {},
                uint8_t* appendError = nullptr,
                ThinkReport* report = nullptr);

  // CHAT: send `request`, a chat request (JSON with messages and tools, see
  // thinkChatCheck). onText (may be empty) gets each piece of the reply text
  // as it arrives, and `reply` gets the whole text. On CES_OK, `end` gets the
  // tool calls, the reasoning and the finish reason. The server signed them
  // and the text. A server older than CHAT drops the channel, so the call
  // fails and costs nothing. `charged` and `report` work as for think.
  uint8_t chat(const std::string& request,
               const std::function<void(std::string_view)>& onText,
               std::string& reply, ThinkChatEnd& end, uint64_t& charged,
               ThinkReport* report = nullptr);

  class Impl;

private:
  std::unique_ptr<Impl> impl_;
};

}  // namespace ces
