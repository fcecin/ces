// net_billing.h — per-channel RUDP billing
//
// A 60s tick walks tracked channels, computes the per-tick debit from
// four billable dimensions × the live rates from CesConfig, and
// bills the bound payer on logicStrand_. Channels whose payer can't
// cover the tick debit are evicted via Rudp::closeChannel.
//
// Billable dimensions:
//   - bytes sent / received   (wire bandwidth)
//   - memory-byte-seconds     (RUDP buffer residency in RAM)
//   - channel age in seconds  (the "channel is open" supervisor cost)
//
// Note on units: feeNetMemByteDay is a rate in credits per byte×day,
// while the metric delta (deltaMemByteSeconds) is in byte×seconds.
// computeDebit() converts.
//
// Known coverage gap: a channel that opens and closes within one tick
// window (<= 60s) never participates in a tick, so its feeNetChannelSec
// age accrual is zero. Sub-tick channels are effectively a free tier;
// closing this would require flushing a partial tick on close.
//
// All public methods (track / snapshot / _runTick) post onto the
// io_context they were constructed with — typically rpcTaskIO_, the
// same strand the Rudp itself runs on. snapshot() blocks the caller
// until the post completes.

#pragma once

#include <ces/keys.h>
#include <ces/types.h>
#include <minx/rudp/rudp.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>

#include <chrono>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace ces {

class CesServer;

class NetworkBilling {
public:
  // `server` is required for the per-tick debit hook: NetworkBilling
  // reads the live feeNet* rates from server->_config() each tick and
  // bills via server->_l2DebitNetworkBill on logicStrand_. Pass null
  // for observability-only mode (delta tracking but no debits, no
  // evictions) — used by tests.
  NetworkBilling(minx::Rudp& rudp,
                 boost::asio::io_context& io,
                 CesServer* server = nullptr,
                 std::chrono::seconds tickInterval = std::chrono::seconds(60));
  ~NetworkBilling();

  NetworkBilling(const NetworkBilling&) = delete;
  NetworkBilling& operator=(const NetworkBilling&) = delete;
  NetworkBilling(NetworkBilling&&) = delete;
  NetworkBilling& operator=(NetworkBilling&&) = delete;

  // Begin tracking (peer, channelId). The framework calls track()
  // exactly once per channel after a successful bind, with the
  // payerPfx from the bound principal. Posts onto the construction
  // io_context; safe to call from any thread.
  //
  // payerPfx default = HashPrefix{} is for tests / observability paths
  // where there's no payer to bill (server == nullptr or the operator
  // wants delta tracking without billing).
  //
  // Idempotent: a second call with the same (peer, channelId) updates
  // tag/payer in place; counters and deltas keep accruing.
  void track(const minx::SockAddr& peer, uint32_t channelId,
             std::string tag, HashPrefix payerPfx = {});

  // Per-channel snapshot, by value. Posts onto the construction
  // io_context and waits for the post to run, so this BLOCKS the
  // caller. Used by cesco `netbill` and tests; not for hot paths.
  struct ChannelSnapshot {
    minx::SockAddr peer;
    uint32_t channelId = 0;
    std::string tag;
    HashPrefix payerPfx{};
    minx::Rudp::ChannelMetrics metrics{};
    // Last per-tick delta (zero before the first tick has run).
    uint64_t deltaBytesSent = 0;
    uint64_t deltaBytesReceived = 0;
    uint64_t deltaMemByteSeconds = 0;
    uint64_t deltaAgeSec = 0;
    // Last per-tick debit. Zero if no tick has run yet, the server
    // has zero rates configured, or no payer (server == nullptr).
    uint64_t deltaDebit = 0;
    // Total credits debited over this channel's lifetime.
    uint64_t totalDebit = 0;
  };
  std::vector<ChannelSnapshot> snapshot() const;

  // Test hook: run one tick synchronously, blocking until done.
  // Real tick cadence is 60 s; tests use this to fast-forward delta
  // computation + debit + eviction without sleeping a minute.
  void _runTick();

  // Test hook: force a tracked channel's last-seen counter baselines (the
  // values the NEXT tick computes its deltas against). Used to simulate a
  // reused (peer, channelId) whose stale baseline exceeds a fresh channel's
  // smaller counters — the regression that would unsigned-underflow the delta.
  // Blocks until applied. No-op if the channel isn't tracked.
  void _testSetBaseline(const minx::SockAddr& peer, uint32_t channelId,
                        uint64_t lastBytesSent, uint64_t lastBytesReceived,
                        uint64_t lastMemByteSeconds);

private:
  struct ChannelBill {
    std::string tag;
    HashPrefix payerPfx{};
    // Last-seen counter values (for delta computation).
    uint64_t lastBytesSent = 0;
    uint64_t lastBytesReceived = 0;
    uint64_t lastMemByteSeconds = 0;
    uint64_t lastBilledAtUs = 0;
    // Last per-tick delta.
    uint64_t deltaBytesSent = 0;
    uint64_t deltaBytesReceived = 0;
    uint64_t deltaMemByteSeconds = 0;
    uint64_t deltaAgeSec = 0;
    // Last per-tick debit + lifetime total.
    uint64_t deltaDebit = 0;
    uint64_t totalDebit = 0;
  };

  using ChannelKey = std::pair<minx::SockAddr, uint32_t>;

  // Compute the per-tick debit from a channel's deltas × the four
  // current rate values (read fresh from CesConfig each tick).
  static uint64_t computeDebit(const ChannelBill& b,
                                uint64_t feeNetChannelSec,
                                uint64_t feeNetMemByteDay,
                                uint64_t feeNetByteSent,
                                uint64_t feeNetByteReceived);

  void scheduleTick();
  void doTick();

  minx::Rudp& rudp_;
  boost::asio::io_context& io_;
  CesServer* server_;
  std::chrono::seconds tickInterval_;
  // Touched only on io_'s strand. No mutex needed if all access posts
  // through io_, which is the contract.
  std::map<ChannelKey, ChannelBill> channels_;
  std::shared_ptr<boost::asio::steady_timer> timer_;
};

} // namespace ces
