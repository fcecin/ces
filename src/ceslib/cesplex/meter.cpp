// meter.cpp — implementation of ChannelMeter.

#include <ces/cesplex/meter.h>
#include <ces/util/sync_call.h>

#include <minx/blog.h>

#include <boost/asio/post.hpp>

#include <chrono>
#include <future>
#include <iomanip>
#include <sstream>

LOG_MODULE("plex");

namespace ces {

namespace {

constexpr uint64_t kMicrosPerSecond = 1'000'000;

uint64_t nowMicros() {
  return static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string hexPrefix(const HashPrefix& p) {
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(16);
  for (auto b : p) {
    out.push_back(kHex[(b >> 4) & 0xF]);
    out.push_back(kHex[b & 0xF]);
  }
  return out;
}

bool isZeroPrefix(const HashPrefix& p) {
  for (auto b : p) if (b != 0) return false;
  return true;
}

// Per-tick delta from a monotonic cumulative counter, guarded against
// regression. RUDP counters increase within a channel incarnation, but a
// (peer, channelId) reused by a fresh channel before the stale MeteredChannel is
// evicted resets the counter to a small value — so `cur - last` would
// unsigned-underflow to a near-2^64 delta (a huge spurious usage spike).
// Treat a regression as a fresh incarnation: measure the new counter from zero.
inline uint64_t guardedDelta(uint64_t cur, uint64_t last) {
  return cur >= last ? cur - last : cur;
}

} // namespace

ChannelMeter::ChannelMeter(minx::Rudp& rudp,
                               boost::asio::io_context& io,
                               CesPlexHost* host,
                               std::chrono::seconds tickInterval)
  : rudp_(rudp), io_(io), host_(host), tickInterval_(tickInterval),
    timer_(std::make_shared<boost::asio::steady_timer>(io)) {
  // A channel that closes between two ticks still pays for its last
  // stretch: the Rudp gives its final metrics when it closes.
  rudp_.setClosedObserver([this](const minx::SockAddr& peer, uint32_t channelId,
                                 const minx::Rudp::ChannelMetrics& final) {
    closed(peer, channelId, final);
  });
  // Kick the first tick from io_'s strand. The timer's lambda owns
  // its own copy of the shared_ptr<timer> so cancel() at destruction
  // suffices to break the chain even if we destruct mid-tick.
  boost::asio::post(io_, [this]() { scheduleTick(); });
  LOGINFO << "ChannelMeter started"
          << VAR(tickInterval_.count());
}

ChannelMeter::~ChannelMeter() {
  // Cancel the timer chain. Pending tick lambdas observe the cancel
  // (ec != 0) and return without rearming. The chain dies when the
  // last shared_ptr<timer> ref drops.
  if (timer_) {
    timer_->cancel();
  }
  // The owner stops the Rudp's threads, then destroys the meter before the
  // Rudp, so no close can call this meter after this line.
  rudp_.setClosedObserver(nullptr);
  // No logging here. This destructor can run during static destruction (its owner
  // is a file-scope global in cesluajitd's luarpc endpoint), after Boost.Log's core
  // is already destroyed, which would SEGV. Lifecycle is visible from the matching
  // construction log instead.
}

template <class F> void ChannelMeter::runOnIo(F&& f) {
  if (io_.get_executor().running_in_this_thread())
    f();
  else
    boost::asio::post(io_, std::forward<F>(f));
}

void ChannelMeter::track(const minx::SockAddr& peer, uint32_t channelId,
                           std::string tag, HashPrefix payerPfx) {
  trackCalls_.fetch_add(1);
  runOnIo(
    [this, peer, channelId, tag = std::move(tag), payerPfx]
    () mutable {
      // A channel that closed before this ran is gone: its close found no
      // row, and a row now would bill a later channel of the same id.
      if (!rudp_.metricsFor(peer, channelId)) return;
      auto key = std::make_pair(peer, channelId);
      auto& mc = channels_[key];
      mc.tag = std::move(tag);
      mc.payerPfx = payerPfx;
      // Seed lastMeteredAtUs so the first tick's deltaAgeSec measures
      // from track() instead of from epoch zero.
      if (mc.lastMeteredAtUs == 0) {
        mc.lastMeteredAtUs = nowMicros();
      }
      LOGDEBUG << "track" << SVAR(peer) << VAR(channelId)
               << SVAR(mc.tag)
               << SVAR(hexPrefix(mc.payerPfx));
    });
}

void ChannelMeter::setPayee(const minx::SockAddr& peer, uint32_t channelId,
                            HashPrefix payeePfx) {
  runOnIo([this, peer, channelId, payeePfx]() {
    auto it = channels_.find(std::make_pair(peer, channelId));
    if (it == channels_.end()) return;
    it->second.payeePfx = payeePfx;
  });
}

std::vector<ChannelMeter::ChannelSnapshot>
ChannelMeter::snapshot() const {
  // const-cast: we only read channels_, but we need a mutable lambda
  // to capture this for the post. The post itself touches only
  // channels_, which is owned by io_'s strand — no concurrent
  // writers from outside.
  auto self = const_cast<ChannelMeter*>(this);
  return runSync(io_.get_executor(), [self]() {
    std::vector<ChannelSnapshot> out;
    out.reserve(self->channels_.size());
    for (const auto& [key, mc] : self->channels_) {
      ChannelSnapshot s;
      s.peer = key.first;
      s.channelId = key.second;
      s.tag = mc.tag;
      s.payerPfx = mc.payerPfx;
      s.payeePfx = mc.payeePfx;
      auto m = self->rudp_.metricsFor(key.first, key.second);
      if (m) s.metrics = *m;
      s.deltaBytesSent = mc.deltaBytesSent;
      s.deltaBytesReceived = mc.deltaBytesReceived;
      s.deltaMemByteSeconds = mc.deltaMemByteSeconds;
      s.deltaAgeSec = mc.deltaAgeSec;
      out.push_back(std::move(s));
    }
    return out;
  });
}

void ChannelMeter::_runTick() {
  runSync(io_.get_executor(), [this]() { doTick(); });
}

void ChannelMeter::_testSetBaseline(const minx::SockAddr& peer,
                                      uint32_t channelId,
                                      uint64_t lastBytesSent,
                                      uint64_t lastBytesReceived,
                                      uint64_t lastMemByteSeconds) {
  runSync(io_.get_executor(), [=, this]() {
    auto it = channels_.find(std::make_pair(peer, channelId));
    if (it != channels_.end()) {
      it->second.lastBytesSent      = lastBytesSent;
      it->second.lastBytesReceived  = lastBytesReceived;
      it->second.lastMemByteSeconds = lastMemByteSeconds;
    }
  });
}

void ChannelMeter::scheduleTick() {
  if (!timer_) return;
  timer_->expires_after(tickInterval_);
  auto t = timer_;  // keep alive
  t->async_wait([this, t](const boost::system::error_code& ec) {
    if (ec) return;  // cancelled
    doTick();
    scheduleTick();
  });
}

void ChannelMeter::doTick() {
  const uint64_t now = nowMicros();
  // Walk channels_ and report this tick's measured resource usage. The
  // meter measures; it does not price, account, or close — the host does
  // all of that. A channel that closes is reported and forgotten in
  // closed(), so a channel gone from metricsFor() here ended with no close
  // event, and is dropped.
  for (auto it = channels_.begin(); it != channels_.end(); ) {
    auto m = rudp_.metricsFor(it->first.first, it->first.second);
    if (!m) {
      LOGDEBUG << "evict (channel gone)"
               << SVAR(it->first.first) << VAR(it->first.second)
               << SVAR(it->second.tag);
      it = channels_.erase(it);
      continue;
    }
    report(it->first, it->second, *m, now, false);
    ++it;
  }
}

void ChannelMeter::closed(const minx::SockAddr& peer, uint32_t channelId,
                          const minx::Rudp::ChannelMetrics& final) {
  auto it = channels_.find(std::make_pair(peer, channelId));
  if (it == channels_.end()) return;
  report(it->first, it->second, final, nowMicros(), true);
  channels_.erase(it);
}

void ChannelMeter::report(const ChannelKey& key, MeteredChannel& mc,
                          const minx::Rudp::ChannelMetrics& m, uint64_t now,
                          bool final) {
  mc.deltaBytesSent      = guardedDelta(m.bytesSent, mc.lastBytesSent);
  mc.deltaBytesReceived  = guardedDelta(m.bytesReceived, mc.lastBytesReceived);
  mc.deltaMemByteSeconds = guardedDelta(m.memoryByteSeconds, mc.lastMemByteSeconds);
  // Guard a backwards system-clock jump (now < lastMeteredAtUs) the same way
  // guardedDelta guards the byte counters, so a clock step can't bill a huge
  // spurious age.
  mc.deltaAgeSec = (now > mc.lastMeteredAtUs)
                     ? (now - mc.lastMeteredAtUs) / kMicrosPerSecond
                     : 0;

  // Report measured usage to the host. It prices the usage in its own
  // units, charges the payer, and closes (peer, channelId) itself if the
  // payer can't cover it. Skipped when there's no host (observability
  // mode) or no bound payer.
  if (host_ && !isZeroPrefix(mc.payerPfx)) {
    host_->cesplexReportUsage(
      mc.payerPfx, mc.payeePfx, key.first, key.second,
      CesPlexUsage{.bytesSent = mc.deltaBytesSent,
                   .bytesReceived = mc.deltaBytesReceived,
                   .memByteSeconds = mc.deltaMemByteSeconds,
                   .ageSeconds = mc.deltaAgeSec,
                   .final = final});
  }

  LOGDEBUG << "usage"
           << SVAR(mc.tag)
           << SVAR(hexPrefix(mc.payerPfx))
           << SVAR(key.first) << VAR(key.second)
           << VAR(mc.deltaBytesSent)
           << VAR(mc.deltaBytesReceived)
           << VAR(mc.deltaMemByteSeconds)
           << VAR(mc.deltaAgeSec);
  mc.lastBytesSent      = m.bytesSent;
  mc.lastBytesReceived  = m.bytesReceived;
  mc.lastMemByteSeconds = m.memoryByteSeconds;
  mc.lastMeteredAtUs    = now;
}

} // namespace ces
