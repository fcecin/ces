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
// THINK request: preamble (after nonce) [u32 textLen][32 sha256(text)]
// [u16 pathLen][path], body = the text (UTF-8). The path is optional
// (pathLen 0, or absent): it names a conversation file (see ThinkFile).
// Reply: CesPlexReplyStream frames of reply text, then the signed response.
// On CES_OK the response preamble is [u64 charged][32 sha256(all reply
// text)][u8 appendError], so the server signature covers the full reply. On an
// error the preamble is empty and the frames before it (if any) are a
// partial reply.
//
// The backend API is stateless, so a conversation is text. With a file the
// server keeps it: the caller sends only the new part, and the server sends
// the backend the file's content plus that part, then appends the part and
// the reply. Without a file the caller sends the whole transcript. The
// backend's prompt cache bills a repeated long prefix at the cached price.
//
// Subsidy: a global discount (HeatSubsidy, think_subsidy_*). While nobody
// thinks the price multiplier cools to think_subsidy_floor_bp of the price;
// with use it heats back to the full price. It applies to the hold and the charge alike. Its total over any
// window T is at most budget + T * budget / tau.
//
// Billing: each THINK pays fee_query, with replay dedup, as other signed
// verbs do. Before the call the server burns a hold from the payer, the
// most the call can cost (every prompt byte as one token, plus the max
// output tokens). While the call runs the hold is listed in
// CesServer::accountHolds, so the file store does not take a program file
// for exhaustion that the hold can cover. When the call ends the server
// charges the cost of the token usage that the backend reported and gives
// the rest of the hold back. A call that fails before the backend does work
// costs nothing. A call that ends with no usage report is charged an
// estimate from the text sizes.

#pragma once

#include <ces/cesplex/mux.h>
#include <ces/keys.h>
#include <ces/l2/think_backend.h>
#include <ces/util/heat_subsidy.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <set>
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
// The charge for a call with no usage report: each prompt byte as one token
// (as the hold: a caller can make text that is one token per byte), and
// about three bytes per token for the reply and reasoning text.
uint64_t thinkEstimate(const ThinkFees& fees, uint64_t promptBytes,
                       uint64_t replyBytes);
// The expected cost of a call, for the subsidy reservation: about three
// prompt bytes per token, and all `maxOut` tokens. Not above the hold.
uint64_t thinkExpected(const ThinkFees& fees, uint64_t promptBytes,
                       uint32_t maxOut);

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
  // `appendError` is the status of the APPEND to the call's file: CES_OK when
  // it was appended, or when there was no file (the caller knows which it
  // asked for), else the APPEND's error (NOT_OWNER, INSUFFICIENT_BALANCE when
  // the file's balance cannot pay, FILE_NOT_FOUND, STORE_FULL, ...).
  virtual void finish(uint8_t status, uint64_t charged,
                      const std::string& text, uint8_t appendError) = 0;
};

// A call's conversation file. The file's content goes before the prompt.
// After a complete reply, the prompt and the reply are appended to it, if
// `caller` may APPEND to it (the file's owner). Every read and append is an
// ordinary FileHandler verb with its usual owner check and fees: the payer
// below pays the caller-side fees, and, as with every APPEND, the write fee
// and the upfront rent come from the file's own balance. A file that cannot
// pay for its growth is left as it was.
struct ThinkFile {
  std::string path;                     // "" = no file
  std::array<uint8_t, 32> caller{};     // the identity for READ and APPEND
  // Who pays the file fees: an account (the THINK signer), or else the
  // source file of a program (ces.think, as for ces.file_*).
  bool payByAccount = false;
  std::array<uint8_t, 32> payerAccount{};
  std::string sourceName;
};

// Who pays a call, and where its refund goes.
struct ThinkPayer {
  ThinkPayer() = default;
  ThinkPayer(const minx::Hash& a) : account(a) {}   // a plain account
  minx::Hash account{};   // pays the hold and the charge
  // For ces.think: the program file whose program account `account` is.
  // When that file is gone at the end of the call, the refund goes to
  // `owner`, as the file's balance does at DELETE. "" = a plain account.
  std::string source;
  minx::Hash owner{};
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
  // With a file that the caller owns, at most one call runs on a path at a
  // time (a second gets CES_ERROR_QUEUE_FULL), so two turns never answer
  // the same transcript. A caller who does not own the file cannot append
  // to it, so its call takes no lock. The /m/ mail zone is refused
  // (NOT_OWNER), as on the wire.
  void submit(const ThinkPayer& payer, std::string prompt,
              std::shared_ptr<ThinkSink> sink, ThinkFile file = {});

 private:
  struct Job {
    std::thread thread;
    std::atomic<bool> stop{false};
    std::atomic<bool> done{false};
  };
  void reapLocked();   // join finished jobs; mu_ held
  // One call, on its worker thread.
  void run(Job& job, ThinkBackend& backend, const ThinkPayer& payer,
           std::string prompt, const ThinkFile& file, ThinkSink& sink);
  // The part of run() between the file read and the append: hold, backend,
  // settle. Sets `text`, `charge` and returns the outcome.
  ThinkOutcome callAndSettle(Job& job, ThinkBackend& backend,
                             const ThinkPayer& payer, const std::string& input,
                             ThinkSink& sink, std::string& text,
                             uint64_t& charge);

  CesServer* server_ = nullptr;
  std::atomic<bool> stopped_{false};
  mutable std::mutex mu_;              // backend_ and jobs_
  std::shared_ptr<ThinkBackend> backend_;
  std::list<std::shared_ptr<Job>> jobs_;
  std::set<std::string> busyPaths_;    // owned files with a call in flight
  std::unique_ptr<HeatSubsidy> subsidy_;
};

}  // namespace ces
