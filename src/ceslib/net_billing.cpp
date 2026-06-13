// net_billing.cpp — implementation of NetworkBilling.

#include <ces/l2/net_billing.h>

#include <ces/server.h>
#include <minx/blog.h>

#include <boost/asio/post.hpp>

#include <chrono>
#include <future>
#include <iomanip>
#include <sstream>

LOG_MODULE("netbill");

namespace ces {

namespace {

constexpr uint64_t kSecondsPerDay  = 86400;
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
// (peer, channelId) reused by a fresh channel before the stale ChannelBill is
// evicted resets the counter to a small value — so `cur - last` would
// unsigned-underflow to a near-2^64 delta (a huge spurious debit). Treat a
// regression as a fresh incarnation: bill the new counter from zero.
inline uint64_t guardedDelta(uint64_t cur, uint64_t last) {
  return cur >= last ? cur - last : cur;
}

} // namespace

NetworkBilling::NetworkBilling(minx::Rudp& rudp,
                               boost::asio::io_context& io,
                               CesServer* server,
                               std::chrono::seconds tickInterval)
  : rudp_(rudp), io_(io), server_(server), tickInterval_(tickInterval),
    timer_(std::make_shared<boost::asio::steady_timer>(io)) {
  // Kick the first tick from io_'s strand. The timer's lambda owns
  // its own copy of the shared_ptr<timer> so cancel() at destruction
  // suffices to break the chain even if we destruct mid-tick.
  boost::asio::post(io_, [this]() { scheduleTick(); });
  LOGINFO << "NetworkBilling started"
          << VAR(tickInterval_.count());
}

NetworkBilling::~NetworkBilling() {
  // Cancel the timer chain. Pending tick lambdas observe the cancel
  // (ec != 0) and return without rearming. The chain dies when the
  // last shared_ptr<timer> ref drops.
  if (timer_) {
    boost::system::error_code ec;
    timer_->cancel(ec);
  }
  LOGINFO << "NetworkBilling stopped";
}

void NetworkBilling::track(const minx::SockAddr& peer, uint32_t channelId,
                           std::string tag, HashPrefix payerPfx) {
  boost::asio::post(io_,
    [this, peer, channelId, tag = std::move(tag), payerPfx]
    () mutable {
      auto key = std::make_pair(peer, channelId);
      auto& bill = channels_[key];
      bill.tag = std::move(tag);
      bill.payerPfx = payerPfx;
      // Seed lastBilledAtUs so the first tick's deltaAgeSec measures
      // from track() instead of from epoch zero.
      if (bill.lastBilledAtUs == 0) {
        bill.lastBilledAtUs = nowMicros();
      }
      LOGDEBUG << "track" << SVAR(peer) << VAR(channelId)
               << SVAR(bill.tag)
               << SVAR(hexPrefix(bill.payerPfx));
    });
}

std::vector<NetworkBilling::ChannelSnapshot>
NetworkBilling::snapshot() const {
  // const-cast: we only read channels_, but we need a mutable lambda
  // to capture this for the post. The post itself touches only
  // channels_, which is owned by io_'s strand — no concurrent
  // writers from outside.
  auto self = const_cast<NetworkBilling*>(this);
  auto promise = std::make_shared<std::promise<std::vector<ChannelSnapshot>>>();
  auto future = promise->get_future();
  boost::asio::post(io_, [self, promise]() {
    std::vector<ChannelSnapshot> out;
    out.reserve(self->channels_.size());
    for (const auto& [key, bill] : self->channels_) {
      ChannelSnapshot s;
      s.peer = key.first;
      s.channelId = key.second;
      s.tag = bill.tag;
      s.payerPfx = bill.payerPfx;
      auto m = self->rudp_.metricsFor(key.first, key.second);
      if (m) s.metrics = *m;
      s.deltaBytesSent = bill.deltaBytesSent;
      s.deltaBytesReceived = bill.deltaBytesReceived;
      s.deltaMemByteSeconds = bill.deltaMemByteSeconds;
      s.deltaAgeSec = bill.deltaAgeSec;
      s.deltaDebit = bill.deltaDebit;
      s.totalDebit = bill.totalDebit;
      out.push_back(std::move(s));
    }
    promise->set_value(std::move(out));
  });
  return future.get();
}

void NetworkBilling::_runTick() {
  auto promise = std::make_shared<std::promise<void>>();
  auto fut = promise->get_future();
  boost::asio::post(io_, [this, promise]() {
    doTick();
    promise->set_value();
  });
  fut.get();
}

void NetworkBilling::_testSetBaseline(const minx::SockAddr& peer,
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

void NetworkBilling::scheduleTick() {
  if (!timer_) return;
  timer_->expires_after(tickInterval_);
  auto t = timer_;  // keep alive
  t->async_wait([this, t](const boost::system::error_code& ec) {
    if (ec) return;  // cancelled
    doTick();
    scheduleTick();
  });
}

uint64_t NetworkBilling::computeDebit(const ChannelBill& b,
                                       uint64_t feeNetChannelSec,
                                       uint64_t feeNetMemByteDay,
                                       uint64_t feeNetByteSent,
                                       uint64_t feeNetByteReceived) {
  // Per-tick debit = sum of the four billable dimensions, each
  // multiplied by its current rate. mem-byte-seconds is converted
  // to mem-byte-days for the rate (rate is per-byte-day, gauge is
  // in byte-seconds, divide by 86400). Use __uint128_t to avoid
  // overflow on the byte-day conversion.
  __uint128_t debit = 0;
  debit += static_cast<__uint128_t>(b.deltaBytesSent)
         * static_cast<__uint128_t>(feeNetByteSent);
  debit += static_cast<__uint128_t>(b.deltaBytesReceived)
         * static_cast<__uint128_t>(feeNetByteReceived);
  debit += (static_cast<__uint128_t>(b.deltaMemByteSeconds)
            * static_cast<__uint128_t>(feeNetMemByteDay))
         / static_cast<__uint128_t>(kSecondsPerDay);
  debit += static_cast<__uint128_t>(b.deltaAgeSec)
         * static_cast<__uint128_t>(feeNetChannelSec);
  if (debit > std::numeric_limits<uint64_t>::max()) {
    return std::numeric_limits<uint64_t>::max();
  }
  return static_cast<uint64_t>(debit);
}

void NetworkBilling::doTick() {
  const uint64_t now = nowMicros();
  // Read live rates once per tick, then apply the dynamic discount.
  // All four NetworkBilling rates share FeeKind::Net (mapped to
  // netBp_ — host bandwidth saturation). If no server is bound (test
  // / observability mode) all four rates default to 0 and
  // computeDebit returns 0 — we still walk channels for delta
  // tracking.
  uint64_t feeChanSec = 0, feeMemDay = 0, feeBSent = 0, feeBRecv = 0;
  if (server_) {
    const auto& cfg = server_->_config();
    feeChanSec = server_->discountFee(FeeKind::Net, cfg.feeNetChannelSec);
    feeMemDay  = server_->discountFee(FeeKind::Net, cfg.feeNetMemByteDay);
    feeBSent   = server_->discountFee(FeeKind::Net, cfg.feeNetByteSent);
    feeBRecv   = server_->discountFee(FeeKind::Net, cfg.feeNetByteReceived);
  }
  // Walk channels_: evict those whose Rudp metrics are gone, compute
  // and bill the per-tick debit for the rest, evict on insufficient
  // funds via Rudp::closeChannel.
  for (auto it = channels_.begin(); it != channels_.end(); ) {
    const auto& key = it->first;
    auto& bill = it->second;
    auto m = rudp_.metricsFor(key.first, key.second);
    if (!m) {
      LOGDEBUG << "evict (channel gone)"
               << SVAR(key.first) << VAR(key.second)
               << SVAR(bill.tag);
      it = channels_.erase(it);
      continue;
    }
    bill.deltaBytesSent       = guardedDelta(m->bytesSent, bill.lastBytesSent);
    bill.deltaBytesReceived   = guardedDelta(m->bytesReceived,
                                             bill.lastBytesReceived);
    bill.deltaMemByteSeconds  = guardedDelta(m->memoryByteSeconds,
                                             bill.lastMemByteSeconds);
    bill.deltaAgeSec          = (now - bill.lastBilledAtUs) / kMicrosPerSecond;
    bill.deltaDebit           = computeDebit(bill, feeChanSec, feeMemDay,
                                              feeBSent, feeBRecv);

    // Bill the bound payer if the debit is non-zero and we have
    // both a payer and a server hook. Skip free channels (e.g.
    // tests with server == nullptr or zero-rate config).
    if (bill.deltaDebit > 0 && server_ && !isZeroPrefix(bill.payerPfx)) {
      const auto chPeer = key.first;
      const auto chCid  = key.second;
      const auto pfx    = bill.payerPfx;
      const auto debit  = bill.deltaDebit;
      const auto tag    = bill.tag;
      // Server hook posts to logicStrand_, runs the debit, posts
      // the callback back to io_ so the closeChannel happens on the
      // Rudp's strand (same as ours). totalDebit is incremented in
      // the callback so it reflects what was actually charged — a
      // hung-up account doesn't pad lifetime totals with phantoms.
      server_->_l2DebitNetworkBill(
        pfx, static_cast<int64_t>(debit),
        [this, chPeer, chCid, tag, debit](bool ok) {
          if (ok) {
            auto it = channels_.find(std::make_pair(chPeer, chCid));
            if (it != channels_.end()) it->second.totalDebit += debit;
            return;
          }
          LOGDEBUG << "bill: insufficient funds → close"
                   << SVAR(chPeer) << VAR(chCid) << SVAR(tag)
                   << VAR(debit);
          rudp_.closeChannel(chPeer, chCid);
          // The next tick will see metricsFor() return nullopt and
          // evict the bill entry.
        },
        io_.get_executor());
    }

    LOGDEBUG << "tick"
             << SVAR(bill.tag)
             << SVAR(hexPrefix(bill.payerPfx))
             << SVAR(key.first) << VAR(key.second)
             << VAR(bill.deltaBytesSent)
             << VAR(bill.deltaBytesReceived)
             << VAR(bill.deltaMemByteSeconds)
             << VAR(bill.deltaAgeSec)
             << VAR(bill.deltaDebit);
    bill.lastBytesSent       = m->bytesSent;
    bill.lastBytesReceived   = m->bytesReceived;
    bill.lastMemByteSeconds  = m->memoryByteSeconds;
    bill.lastBilledAtUs      = now;
    ++it;
  }
}

} // namespace ces
