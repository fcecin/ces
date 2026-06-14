// meter.h — per-channel RUDP resource meter (ChannelMeter)
//
// A 60s tick walks tracked channels and measures each one's resource
// deltas, then reports them to the host (CesPlexHost::cesplexReportUsage).
// The meter does NOT price, charge, or evict — the host prices the usage
// in its own units, charges the payer, and closes the channel if it can't
// cover the tick. A channel the host closes simply vanishes from
// metricsFor() on the next tick and is dropped here.
//
// Measured dimensions (raw, no credits):
//   - bytes sent / received   (wire bandwidth)
//   - memory-byte-seconds     (RUDP buffer residency in RAM)
//   - channel age in seconds  (the "channel is open" duration)
//
// Known coverage gap: a channel that opens and closes within one tick
// window (<= 60s) never participates in a tick, so its age usage is
// never reported. Sub-tick channels are effectively a free tier; closing
// this would require flushing a partial tick on close.
//
// All public methods (track / snapshot / _runTick) post onto the
// io_context they were constructed with — typically rpcTaskIO_, the
// same strand the Rudp itself runs on. snapshot() blocks the caller
// until the post completes.

#pragma once

#include <ces/keys.h>
#include <ces/types.h>
#include <ces/cesplex/mux.h>   // CesPlexHost (the host seam)
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

class ChannelMeter {
public:
  // Each tick the meter measures every tracked channel's resource deltas
  // and reports them to `host` via host->cesplexReportUsage(); the host
  // prices them, charges, and closes. Pass a null host for
  // observability-only mode (delta tracking, nothing reported) — used by
  // tests and by a host that wants the bus without metering.
  ChannelMeter(minx::Rudp& rudp,
                 boost::asio::io_context& io,
                 CesPlexHost* host = nullptr,
                 std::chrono::seconds tickInterval = std::chrono::seconds(60));
  ~ChannelMeter();

  ChannelMeter(const ChannelMeter&) = delete;
  ChannelMeter& operator=(const ChannelMeter&) = delete;
  ChannelMeter(ChannelMeter&&) = delete;
  ChannelMeter& operator=(ChannelMeter&&) = delete;

  // Begin tracking (peer, channelId). The framework calls track()
  // exactly once per channel after a successful bind, with the
  // payerPfx from the bound principal. Posts onto the construction
  // io_context; safe to call from any thread.
  //
  // payerPfx default = HashPrefix{} is for tests / observability paths
  // where there's no bound payer (no host, or the operator wants delta
  // tracking without reporting usage).
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
    // Last per-tick resource delta (zero before the first tick has run).
    // Credits are not here — the meter measures resources; the host prices
    // them.
    uint64_t deltaBytesSent = 0;
    uint64_t deltaBytesReceived = 0;
    uint64_t deltaMemByteSeconds = 0;
    uint64_t deltaAgeSec = 0;
  };
  std::vector<ChannelSnapshot> snapshot() const;

  // Test hook: run one tick synchronously, blocking until done.
  // Real tick cadence is 60 s; tests use this to fast-forward delta
  // computation + the usage report without sleeping a minute.
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
  struct MeteredChannel {
    std::string tag;
    HashPrefix payerPfx{};
    // Last-seen counter values (for delta computation).
    uint64_t lastBytesSent = 0;
    uint64_t lastBytesReceived = 0;
    uint64_t lastMemByteSeconds = 0;
    uint64_t lastMeteredAtUs = 0;
    // Last per-tick resource delta.
    uint64_t deltaBytesSent = 0;
    uint64_t deltaBytesReceived = 0;
    uint64_t deltaMemByteSeconds = 0;
    uint64_t deltaAgeSec = 0;
  };

  using ChannelKey = std::pair<minx::SockAddr, uint32_t>;

  void scheduleTick();
  void doTick();

  minx::Rudp& rudp_;
  boost::asio::io_context& io_;
  CesPlexHost* host_;
  std::chrono::seconds tickInterval_;
  // Touched only on io_'s strand. No mutex needed if all access posts
  // through io_, which is the contract.
  std::map<ChannelKey, MeteredChannel> channels_;
  std::shared_ptr<boost::asio::steady_timer> timer_;
};

} // namespace ces
