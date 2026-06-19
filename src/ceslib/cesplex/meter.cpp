// meter.cpp — implementation of ChannelMeter.

#include <ces/cesplex/meter.h>

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
    boost::system::error_code ec;
    timer_->cancel(ec);
  }
  LOGINFO << "ChannelMeter stopped";
}

void ChannelMeter::track(const minx::SockAddr& peer, uint32_t channelId,
                           std::string tag, HashPrefix payerPfx) {
  boost::asio::post(io_,
    [this, peer, channelId, tag = std::move(tag), payerPfx]
    () mutable {
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

std::vector<ChannelMeter::ChannelSnapshot>
ChannelMeter::snapshot() const {
  // const-cast: we only read channels_, but we need a mutable lambda
  // to capture this for the post. The post itself touches only
  // channels_, which is owned by io_'s strand — no concurrent
  // writers from outside.
  auto self = const_cast<ChannelMeter*>(this);
  auto promise = std::make_shared<std::promise<std::vector<ChannelSnapshot>>>();
  auto future = promise->get_future();
  boost::asio::post(io_, [self, promise]() {
    std::vector<ChannelSnapshot> out;
    out.reserve(self->channels_.size());
    for (const auto& [key, mc] : self->channels_) {
      ChannelSnapshot s;
      s.peer = key.first;
      s.channelId = key.second;
      s.tag = mc.tag;
      s.payerPfx = mc.payerPfx;
      auto m = self->rudp_.metricsFor(key.first, key.second);
      if (m) s.metrics = *m;
      s.deltaBytesSent = mc.deltaBytesSent;
      s.deltaBytesReceived = mc.deltaBytesReceived;
      s.deltaMemByteSeconds = mc.deltaMemByteSeconds;
      s.deltaAgeSec = mc.deltaAgeSec;
      out.push_back(std::move(s));
    }
    promise->set_value(std::move(out));
  });
  return future.get();
}

void ChannelMeter::_runTick() {
  auto promise = std::make_shared<std::promise<void>>();
  auto fut = promise->get_future();
  boost::asio::post(io_, [this, promise]() {
    doTick();
    promise->set_value();
  });
  fut.get();
}

void ChannelMeter::_testSetBaseline(const minx::SockAddr& peer,
                                      uint32_t channelId,
                                      uint64_t lastBytesSent,
                                      uint64_t lastBytesReceived,
                                      uint64_t lastMemByteSeconds) {
  auto promise = std::make_shared<std::promise<void>>();
  auto fut = promise->get_future();
  boost::asio::post(io_, [=, this]() {
    auto it = channels_.find(std::make_pair(peer, channelId));
    if (it != channels_.end()) {
      it->second.lastBytesSent      = lastBytesSent;
      it->second.lastBytesReceived  = lastBytesReceived;
      it->second.lastMemByteSeconds = lastMemByteSeconds;
    }
    promise->set_value();
  });
  fut.get();
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
  // Walk channels_: drop those whose Rudp metrics are gone (the host
  // closed them), and report this tick's measured resource usage for the
  // rest. The meter measures; it does not price, account, or close — the
  // host does all of that. A channel the host closes for non-payment
  // simply vanishes from metricsFor() on the next tick and is dropped.
  for (auto it = channels_.begin(); it != channels_.end(); ) {
    const auto& key = it->first;
    auto& mc = it->second;
    auto m = rudp_.metricsFor(key.first, key.second);
    if (!m) {
      LOGDEBUG << "evict (channel gone)"
               << SVAR(key.first) << VAR(key.second)
               << SVAR(mc.tag);
      it = channels_.erase(it);
      continue;
    }
    mc.deltaBytesSent       = guardedDelta(m->bytesSent, mc.lastBytesSent);
    mc.deltaBytesReceived   = guardedDelta(m->bytesReceived,
                                             mc.lastBytesReceived);
    mc.deltaMemByteSeconds  = guardedDelta(m->memoryByteSeconds,
                                             mc.lastMemByteSeconds);
    mc.deltaAgeSec          = (now - mc.lastMeteredAtUs) / kMicrosPerSecond;

    // Report measured usage to the host. It prices the usage in its own
    // units, charges the payer, and closes (peer, channelId) itself if the
    // payer can't cover it. Skipped when there's no host (observability
    // mode) or no bound payer.
    if (host_ && !isZeroPrefix(mc.payerPfx)) {
      host_->cesplexReportUsage(
        mc.payerPfx, key.first, key.second,
        CesPlexUsage{.bytesSent = mc.deltaBytesSent,
                     .bytesReceived = mc.deltaBytesReceived,
                     .memByteSeconds = mc.deltaMemByteSeconds,
                     .ageSeconds = mc.deltaAgeSec});
    }

    LOGDEBUG << "tick"
             << SVAR(mc.tag)
             << SVAR(hexPrefix(mc.payerPfx))
             << SVAR(key.first) << VAR(key.second)
             << VAR(mc.deltaBytesSent)
             << VAR(mc.deltaBytesReceived)
             << VAR(mc.deltaMemByteSeconds)
             << VAR(mc.deltaAgeSec);
    mc.lastBytesSent       = m->bytesSent;
    mc.lastBytesReceived   = m->bytesReceived;
    mc.lastMemByteSeconds  = m->memoryByteSeconds;
    mc.lastMeteredAtUs      = now;
    ++it;
  }
}

} // namespace ces
