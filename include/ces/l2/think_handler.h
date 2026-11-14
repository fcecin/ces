// think_handler.h - builtin:think, text in, text out.
//
// Two front doors share one core (submit): the THINK verb on /ces/think/1,
// paid by the bound signer, and the ces.think host call from a compute
// instance, paid by the file's program account. The caller of submit names
// the payer, and each front door takes it from an authenticated source (the
// bind signature, or the server's own instance record), never from the
// request.
//
// A CesPlex handler with one verb (THINK). The signer sends one prompt text.
// The server streams the reply text back as it arrives from the backend
// model, then sends one status byte (0 = the reply is complete). The model,
// its limits and its prices are server config. The client picks nothing.
//
// THINK request: preamble (after nonce) [u32 textLen][32 sha256(text)],
// body = the text (UTF-8). Reply: CesPlexReplyStream frames of reply text,
// then the signed response. On CES_OK the response preamble is
// [u64 charged][32 sha256(all reply text)], so the server signature covers
// the full reply. On an error the preamble is empty and the frames before
// it (if any) are a partial reply.
//
// The API is stateless: a conversation is the caller's text. To continue
// one, send the transcript again with the new part at its end. The backend's
// prompt cache bills the repeated prefix at the cached-input price.
//
// Subsidy: a global discount (HeatSubsidy, think_subsidy_*). While nobody
// thinks the price multiplier cools to think_subsidy_floor_bp of the price;
// with use it heats back to the full price. It applies to the hold and the charge alike. Its total over any
// window T is at most budget + T * budget / tau.
//
// Billing: before the call the server burns a hold from the signer, the
// most the call can cost (every prompt byte as one token, plus the max
// output tokens). When the call ends it charges the cost of the token usage
// that the backend reported and gives the rest of the hold back. A call
// that fails before the backend does work costs nothing. A call that ends
// with no usage report is charged an estimate from the text sizes.

#pragma once

#include <ces/cesplex/mux.h>
#include <ces/keys.h>
#include <ces/l2/think_backend.h>
#include <ces/util/heat_subsidy.h>

#include <atomic>
#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>

namespace ces {

class CesServer;

// Prices in raw credit units per one million tokens.
struct ThinkFees {
  uint64_t in = 0;         // input tokens not in the prompt cache
  uint64_t cachedIn = 0;   // input tokens served from the prompt cache
  uint64_t out = 0;        // output tokens (reasoning tokens included)
};

// Input tokens that the chat template adds to a prompt, for the hold.
inline constexpr uint64_t kThinkPromptOverhead = 64;

// The cost of reported usage, rounded up.
uint64_t thinkCost(const ThinkFees& fees, const ThinkUsage& usage);
// The hold for a prompt of `promptBytes`: the cost if every byte were one
// uncached token and the reply used all `maxOut` tokens.
uint64_t thinkHold(const ThinkFees& fees, uint64_t promptBytes,
                   uint32_t maxOut);
// The charge for a call with no usage report: about three bytes per token
// for the prompt and the reply text.
uint64_t thinkEstimate(const ThinkFees& fees, uint64_t promptBytes,
                       uint64_t replyBytes);

// Where one call's reply goes: the THINK verb's channel, or a compute
// instance (ces.think). The handler calls these from the call's worker
// thread; an implementation hops to its own executor.
class ThinkSink {
 public:
  virtual ~ThinkSink() = default;
  // False when nobody will read the reply any more. The call then stops.
  virtual bool open() = 0;
  // One piece of reply text, in order.
  virtual void piece(std::string_view text) = 0;
  // Called once, last. On a refusal before the call started, charged is 0
  // and text is empty. On an error after it started, text is partial.
  virtual void finish(uint8_t status, uint64_t charged,
                      const std::string& text) = 0;
};

class ThinkHandler : public CesPlexHandler {
 public:
  // Builds the backend from the server config: in a CES_THINK build, the
  // HTTPS backend when think_api_key_file names a readable key. Else none,
  // and THINK answers CES_ERROR_DISABLED.
  explicit ThinkHandler(CesServer* server);
  ~ThinkHandler() override;

  void serve(std::shared_ptr<minx::RudpStream> stream,
             BoundChannelContext bound) override;

  // Stop new calls, stop the calls in flight, and join their threads.
  void stop();

  // True when THINK can serve: a backend is set and the input and output
  // prices are not zero.
  bool enabled() const;

  // Calls in flight.
  size_t active();

  // Test hook: replace the backend.
  void _testSetBackend(std::shared_ptr<ThinkBackend> backend);

  // The global price discount (think_subsidy_*). Never null; off when the
  // budget or tau is 0 or the floor is 10000.
  HeatSubsidy* subsidy() { return subsidy_.get(); }

  // Run one call billed to `payer`: check, hold, call the backend on a
  // worker thread, settle. Every outcome, refusals included, ends in one
  // sink->finish. The caller decides who `payer` is and must have
  // authenticated it: the bound signer for THINK, the instance's program
  // account for ces.think.
  void submit(const minx::Hash& payer, std::string prompt,
              std::shared_ptr<ThinkSink> sink);

 private:
  struct Job {
    std::thread thread;
    std::atomic<bool> stop{false};
    std::atomic<bool> done{false};
  };
  void reapLocked();   // join finished jobs; mu_ held

  CesServer* server_ = nullptr;
  std::atomic<bool> stopped_{false};
  mutable std::mutex mu_;              // backend_ and jobs_
  std::shared_ptr<ThinkBackend> backend_;
  std::list<std::shared_ptr<Job>> jobs_;
  std::unique_ptr<HeatSubsidy> subsidy_;
};

}  // namespace ces
