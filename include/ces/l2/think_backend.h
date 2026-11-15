// think_backend.h - the backend of builtin:think, and the pure helpers that
// speak the OpenAI chat-completions format.
//
// A ThinkBackend turns one prompt text into reply text. It calls onText for
// each piece of the reply as the piece arrives, and returns the outcome with
// the token usage when the backend reported it. The handler owns billing and
// the wire; the backend knows only the model API. ThinkHttpsBackend
// (think_https.h, CES_THINK builds) is the real one. Tests install their own.
//
// The helpers below have no network and no state outside their objects:
// the request JSON, the server-sent-events (SSE) parser for a streamed
// reply, the error-message reader, the base URL parser, and a UTF-8 check.

#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

namespace ces {

struct ThinkUsage {
  uint64_t promptTokens = 0;   // all input tokens, cached ones included
  uint64_t cachedTokens = 0;   // input tokens served from the prompt cache
  uint64_t outputTokens = 0;   // reply tokens, reasoning tokens included
};

// What a call used, and the limits of the server, for a caller that asks
// (THINK with the report flag): a harness uses it to keep its prompt inside
// the model's window and to show how much of the prompt the cache served.
struct ThinkReport {
  bool usageKnown = false;      // false: the backend reported no usage
  ThinkUsage usage;
  uint32_t maxInputBytes = 0;   // think_max_input_bytes
  uint32_t maxOutTokens = 0;    // think_max_out_tokens
  uint32_t contextTokens = 0;   // think_context_tokens (0 = not stated)
};

struct ThinkOutcome {
  // How the handler must bill the call.
  //   kNone     the backend did no billable work (e.g. connect failed).
  //   kEstimate the backend did work but did not report usage.
  //   kUsage    `usage` holds the counts the backend reported.
  enum Billing : uint8_t { kNone, kEstimate, kUsage };
  uint8_t status = 0;          // CES status. 0 = the reply is complete.
  Billing billing = kNone;
  ThinkUsage usage;
  // Bytes of reply and reasoning text the backend produced, for the estimate
  // (kEstimate). 0 = unknown: the handler counts the text it got.
  uint64_t outBytes = 0;
  std::string detail;          // for the log only; never sent to clients
};

class ThinkBackend {
 public:
  virtual ~ThinkBackend() = default;
  // Produce the reply to `prompt`, at most `maxOut` tokens. Call onText with
  // each piece of reply text, in order. When onText returns false, or when
  // `stop` becomes true, end the call soon. Blocks; the handler calls it on a
  // worker thread, and several calls can run at the same time.
  virtual ThinkOutcome run(const std::string& prompt, uint32_t maxOut,
                           const std::atomic<bool>& stop,
                           const std::function<bool(std::string_view)>& onText)
      = 0;
};

// The chat-completions request body for one prompt: one user message, the
// configured model, max_tokens, streaming with usage. `reasoning` sets the
// DeepSeek "thinking" field (other OpenAI-format servers ignore it).
std::string thinkRequestJson(const std::string& model,
                             const std::string& prompt, uint32_t maxOut,
                             bool reasoning);

// Reads a streamed chat-completions body (text/event-stream). Feed it the
// body bytes in any split. It calls onText for each content delta, keeps the
// last usage object, and records an error object if the stream has one.
// Reasoning deltas are not reply text: they are counted, not forwarded.
// After onText returns false the parser forwards no more text, but it still
// reads the stream to its usage report and its end, so the caller can bill
// the call by usage.
class ThinkSseParser {
 public:
  // False when an event is malformed JSON, or when more than 1 MiB arrives
  // with no event end. Stops at "[DONE]".
  bool feed(std::string_view bytes,
            const std::function<bool(std::string_view)>& onText);
  bool done() const { return done_; }         // "[DONE]" seen
  bool stopped() const { return stopped_; }   // onText returned false
  // Bytes of reply text and of reasoning text seen, forwarded or not. For
  // the billing estimate when the stream has no usage report.
  uint64_t textBytes() const { return textBytes_; }
  uint64_t reasoningBytes() const { return reasoningBytes_; }
  bool hasUsage() const { return hasUsage_; }
  const ThinkUsage& usage() const { return usage_; }
  const std::string& error() const { return error_; }   // "" = none

 private:
  bool event(std::string_view data,
             const std::function<bool(std::string_view)>& onText);
  std::string buf_;
  bool done_ = false;
  bool stopped_ = false;
  bool hasUsage_ = false;
  uint64_t textBytes_ = 0;
  uint64_t reasoningBytes_ = 0;
  ThinkUsage usage_;
  std::string error_;
};

// The message of an OpenAI-format error body ({"error":{"message":...}}), or
// the first bytes of the body when it has no such field.
std::string thinkErrorMessage(std::string_view body);

// Split "https://host[:port][/path]" (or http://). The request path is
// `prefix` + "/chat/completions". False on anything else.
bool thinkParseBaseUrl(const std::string& url, bool& tls, std::string& host,
                       std::string& port, std::string& prefix);

// True when `s` is well-formed UTF-8.
bool thinkValidUtf8(std::string_view s);

}  // namespace ces
