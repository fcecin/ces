// think_backend.h - the backend of builtin:think, and the pure helpers that
// speak the OpenAI chat-completions format.
//
// A ThinkBackend sends one input to the model and gets the reply. The input
// is a prompt text, or a chat request with messages and tools. The backend
// gives each piece of the reply to onText as the piece arrives. It returns
// the outcome, with the token usage when the model API reports it, and with
// the tool calls of a chat reply. The handler does the billing and the wire,
// and the backend does only the model API. ThinkHttpsBackend (think_https.h,
// CES_THINK builds) is the real backend. Tests install their own.
//
// The helpers below use no network and keep no state outside their objects.
// They check a chat request, write the request JSON, parse a streamed reply
// (server-sent events, SSE), read an error message, parse the base URL and
// check UTF-8.

#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include <boost/json/fwd.hpp>

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

// The input of one call. Without `chat`, `text` is a prompt, and the model
// gets it as one user message. With `chat`, `text` is a chat request that
// thinkChatCheck wrote, and the model gets its messages and tools as they are.
struct ThinkInput {
  std::string text;
  bool chat = false;
};

// The parts of a chat reply other than its text.
struct ThinkChatEnd {
  // The tool calls as a JSON array of
  // {"id":S,"type":"function","function":{"name":S,"arguments":S}}, or ""
  // for none. The model writes the arguments, so they can be bad JSON.
  std::string toolCalls;
  std::string reasoning;      // the reasoning text, or "" for none
  std::string finishReason;   // "stop", "tool_calls", "length", ..., or "" for none
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
  ThinkChatEnd chat;           // the tool calls, the reasoning, the finish reason
  std::string detail;          // for the log only; never sent to clients
};

class ThinkBackend {
 public:
  virtual ~ThinkBackend() = default;
  // Produce the reply to `input`, at most `maxOut` tokens. Call onText with
  // each piece of reply text, in order. When onText returns false, or when
  // `stop` becomes true, end the call soon. Blocks; the handler calls it on a
  // worker thread, and several calls can run at the same time.
  virtual ThinkOutcome run(const ThinkInput& input, uint32_t maxOut,
                           const std::atomic<bool>& stop,
                           const std::function<bool(std::string_view)>& onText)
      = 0;
  // The model's context window in tokens, as the model API states it; 0 when
  // the API does not state it. May block once, to ask the API.
  virtual uint32_t contextWindow() { return 0; }
};

// Checks a chat request, and writes it to `out` with only the fields below,
// in this order. Returns false, with the reason in `why`, when the request
// does not match.
//   {"messages":    [message, ...],   at least one
//    "tools":       [{"type":"function","function":{"name":N,
//                     "description":S?,"parameters":{...}?}}, ...]?,
//    "tool_choice": "auto" | "none" | "required"
//                   | {"type":"function","function":{"name":N}}?}
// A message is one of
//   {"role":"system","content":S}      {"role":"user","content":S}
//   {"role":"assistant","content":S|null?,"reasoning_content":S?,
//    "tool_calls":[{"id":S,"type":"function",
//                   "function":{"name":N,"arguments":S}}, ...]?}
//   {"role":"tool","tool_call_id":S,"content":S}
// An assistant message has content or tool calls. A name N has 1 to 64
// letters, digits, '_' and '-'. Other fields make the check fail.
bool thinkChatCheck(std::string_view request, std::string& out,
                    std::string* why = nullptr);

// The chat-completions request body of one call. It has the configured
// model, the messages of the input (one user message for a prompt),
// max_tokens, and streaming with usage. `reasoning` sets the DeepSeek
// "thinking" field, which other OpenAI-format servers ignore.
std::string thinkRequestJson(const std::string& model, const ThinkInput& input,
                             uint32_t maxOut, bool reasoning);

// The end of a chat reply as the CHAT verb sends it, one JSON object
// {"tool_calls":[...],"reasoning_content":S,"finish_reason":S}. It has
// reasoning_content only when the reply has reasoning.
std::string thinkChatEndJson(const ThinkChatEnd& end);
// Reads that object back. Returns false when it does not parse.
bool thinkChatEndParse(std::string_view json, ThinkChatEnd& end);
// A whole chat reply as one JSON object for programs,
// {"content":S,"tool_calls":[...],"reasoning_content":S,"finish_reason":S}.
// It has reasoning_content only when the reply has reasoning. To send the
// reply back to the model, remove finish_reason and add "role":"assistant".
std::string thinkChatReplyJson(const std::string& content,
                               const ThinkChatEnd& end);

// Reads a streamed chat-completions body (text/event-stream). Feed it the
// body bytes in any split. It calls onText for each content delta, keeps the
// last usage object, and records an error object if the stream has one.
// The parser keeps the reasoning deltas apart from the reply text, and does
// not give them to onText. It joins the tool call deltas into whole calls, by
// their index.
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
  uint64_t toolBytes() const { return toolBytes_; }
  // The tool calls, the reasoning and the finish reason seen so far.
  ThinkChatEnd chatEnd() const;
  bool hasUsage() const { return hasUsage_; }
  const ThinkUsage& usage() const { return usage_; }
  const std::string& error() const { return error_; }   // "" = none

 private:
  struct ToolCall {
    std::string id, type, name, arguments;
  };
  bool event(std::string_view data,
             const std::function<bool(std::string_view)>& onText);
  // Join one delta's "tool_calls" into calls_. False when it is malformed.
  bool toolDeltas(const boost::json::value* deltas);
  std::string buf_;
  std::vector<ToolCall> calls_;   // by the delta's index
  std::string reasoning_;
  std::string finishReason_;
  uint64_t toolBytes_ = 0;
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

// The context window of `model` in a model list (GET <base>/models): the
// "context_window" of the entry whose "id" is `model`. 0 when the list does
// not parse, has no such entry, or the entry does not state it. There is no
// standard field for it; this is the one that DeepSeek's API sends.
uint32_t thinkModelWindow(std::string_view modelsJson, const std::string& model);

// The window told to callers: the API's, or the operator's ceiling
// (think_context_tokens) when that is lower; the ceiling alone when the API
// does not state one. 0 = not stated.
uint32_t thinkWindow(uint32_t ceiling, uint32_t fromApi);

}  // namespace ces
