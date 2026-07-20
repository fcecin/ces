// peer_handler.cpp - builtin:peer handler (per-server object). See the header.
//
// One PeerHandler per CesServer; no process-global state. Owns the link state
// machine, the reconcile pass, and the service-tagged message bus extensions
// ride. The lower-pubkey side dials, the higher accepts.
//
// A link keeps TWO RUDP channels to its peer: a control channel and a bulk
// channel, both bound to /ces/peer/1 and both delivering identical frames to
// the same service router. Outbound frames are split by SIZE -- small ones ride
// control, large ones ride bulk -- so a long download never head-of-line-blocks
// consensus. The two channels are independent RUDP streams, so this is a purely
// local routing choice: the peers need not agree which channel is which. A link
// needs only ONE channel up to work; if the other never opens or dies, every
// frame rides the survivor (a latency/QoS regression, not a lost link) until the
// reconcile pass regenerates it. On establish each channel is marked persistent
// (RudpStream::setPersistent) so RUDP's idle GC never closes it.

#include <ces/l2/peer_handler.h>
#include <ces/buffer.h>

#include <ces/cesplex/wire.h>
#include <ces/keys.h>
#include <ces/l2/compute_handler.h>
#include <ces/server.h>
#include <ces/types.h>

#include <minx/blog.h>
#include <minx/rudp/rudp.h>
#include <minx/rudp/rudp_stream.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <chrono>
#include <cstring>
#include <deque>
#include <future>
#include <random>
#include <span>
#include <vector>

LOG_MODULE("plex");

namespace ces {

namespace {

// Reconcile cadence: dial missing links, regenerate a link's missing channel,
// drop links whose peer left the table. No keepalive role (channels persistent).
constexpr int kReconcileIntervalMs = 15000;
// Bind-handshake deadline; a dial whose peer never replies is torn down and
// retried on the next reconcile.
constexpr int kDialTimeoutSec = 10;
// Max bytes in one mesh-message frame (after the 4-byte length prefix). Large
// enough for a bulk sync piece; a degraded single-channel link carries such a
// piece on the control channel too. Kept well under the RUDP per-channel reorder
// cap (1 MB) so a fully-reordered frame still reassembles. Server-to-server mesh
// only, so a trusted bound.
constexpr uint32_t kMaxPeerFrame = 256 * 1024;
// Frames larger than this take the bulk channel, smaller ones the control channel.
// Set just under a full bulk piece (max_message, 64 KiB) so only max-sized chunker
// pieces leave the control lane; a consensus proposal, even a large one, stays on it.
// Only a QoS choice: both lanes feed one handler and pieces reassemble by offset.
constexpr uint32_t kBulkThreshold = 60 * 1024;

uint64_t nowMicros() {
  return static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count());
}

}  // namespace

// One physical RUDP channel of a link (control or bulk). A link holds two.
struct PeerChannel {
  uint32_t channelId = 0;
  std::shared_ptr<minx::RudpStream> stream;
  bool established = false;
  bool dialing = false;                    // a dial handshake is in flight
  std::array<uint8_t, 8 * 1024> readBuf{};
  ces::Bytes rxBuf;                        // inbound framing accumulator
  std::deque<std::shared_ptr<ces::Bytes>> writeQueue;
  bool writing = false;
  // Dial-phase scratch.
  minx::Bytes bindReqBuf;
  std::array<uint8_t, ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE> bindReplyBuf{};
  std::array<uint8_t, ces::CES_PLEX_SHA256_SIZE> bindReqDigest{};
  std::shared_ptr<boost::asio::steady_timer> dialTimer;

  bool up() const { return established && stream != nullptr; }
};

struct PeerLink : std::enable_shared_from_this<PeerLink> {
  minx::Hash ckey{};                       // remote peer identity
  minx::SockAddr endpoint;                 // remote plex endpoint (dial only)
  bool outbound = false;                   // true = we dialed (we regenerate channels)
  bool closed = false;
  PeerChannel ctrl;                        // small frames
  PeerChannel bulk;                        // large frames
  bool anyUp() const { return ctrl.up() || bulk.up(); }
};

// ---------------------------------------------------------------------------
// Pure reconcile decision (free, stateless)
// ---------------------------------------------------------------------------

PeerLinkActions computePeerLinkActions(
    const std::vector<PeerLinkTarget>& peers,
    const minx::Hash& ourKey,
    const std::set<minx::Hash>& currentLinks) {
  PeerLinkActions out;
  std::set<minx::Hash> peerSet;
  for (const auto& p : peers) peerSet.insert(p.ckey);
  for (const auto& ck : currentLinks) {
    if (!peerSet.count(ck)) out.toDrop.push_back(ck);
  }
  for (const auto& p : peers) {
    if (!p.dialable) continue;
    if (currentLinks.count(p.ckey)) continue;
    if (!(ourKey < p.ckey)) continue;  // higher side waits for inbound
    out.toDial.push_back(p.ckey);
  }
  return out;
}

// ---------------------------------------------------------------------------
// PeerHandler
// ---------------------------------------------------------------------------

PeerHandler::PeerHandler(CesServer* server) : server_(server) {}

PeerHandler::~PeerHandler() { stop(); }

void PeerHandler::teardownLink(std::shared_ptr<PeerLink> link) {
  if (!link || link->closed) return;
  link->closed = true;
  for (PeerChannel* ch : {&link->ctrl, &link->bulk}) {
    if (ch->dialTimer) {
      boost::system::error_code ec;
      ch->dialTimer->cancel(ec);
      ch->dialTimer.reset();
    }
    if (ch->stream) {
      ch->stream->shutdown(kRudpStreamCloseTimeout);
      ch->stream.reset();
    }
  }
  {
    std::lock_guard<std::mutex> lk(linkMutex_);
    established_.erase(link->ckey);
  }
  auto it = links_.find(link->ckey);
  if (it != links_.end() && it->second == link) links_.erase(it);
}

// Close ONE channel of a link. The link survives on the other channel; only when
// both are down does the link tear down. The dialer regenerates the gap on the
// next reconcile.
void PeerHandler::closeChannel(std::shared_ptr<PeerLink> link, bool bulk) {
  if (!link || link->closed) return;
  PeerChannel& ch = bulk ? link->bulk : link->ctrl;
  if (ch.dialTimer) {
    boost::system::error_code ec;
    ch.dialTimer->cancel(ec);
    ch.dialTimer.reset();
  }
  if (ch.stream) {
    ch.stream->shutdown(kRudpStreamCloseTimeout);
    ch.stream.reset();
  }
  ch.established = false;
  ch.dialing = false;
  ch.writing = false;
  ch.rxBuf.clear();
  ch.writeQueue.clear();
  if (!link->anyUp()) {
    teardownLink(link);
    return;
  }
  LOGDEBUG << "peer " << (bulk ? "bulk" : "control") << " channel down"
           << SVAR(minx::hashToString(link->ckey));
}

void PeerHandler::establishChannel(std::shared_ptr<PeerLink> link, bool bulk) {
  if (link->closed) return;
  PeerChannel& ch = bulk ? link->bulk : link->ctrl;
  const bool wasUp = link->anyUp();
  ch.established = true;
  ch.dialing = false;
  if (ch.dialTimer) {
    boost::system::error_code ec;
    ch.dialTimer->cancel(ec);
    ch.dialTimer.reset();
  }
  if (ch.stream) ch.stream->setPersistent();
  if (!wasUp) {
    std::lock_guard<std::mutex> lk(linkMutex_);
    established_.insert(link->ckey);
  }
  LOGINFO << (wasUp ? (bulk ? "peer bulk channel up" : "peer control channel up") : "peer-link up")
          << VAR(link->outbound) << SVAR(minx::hashToString(link->ckey));
  channelReadLoop(link, bulk);
}

void PeerHandler::channelReadLoop(std::shared_ptr<PeerLink> link, bool bulk) {
  if (link->closed) return;
  PeerChannel& setup = bulk ? link->bulk : link->ctrl;
  if (!setup.stream) return;
  auto stream = setup.stream;
  stream->async_read_some(
    boost::asio::buffer(setup.readBuf),
    [this, link, bulk](const boost::system::error_code& ec, std::size_t n) {
      if (link->closed) return;
      PeerChannel& ch = bulk ? link->bulk : link->ctrl;
      if (ec) { closeChannel(link, bulk); return; }
      if (n > 0) {
        ch.rxBuf.insert(ch.rxBuf.end(), ch.readBuf.data(), ch.readBuf.data() + n);
      }
      // Frames: [u32 total][u16 service_len][service][payload].
      size_t off = 0;
      while (ch.rxBuf.size() - off >= sizeof(uint32_t)) {
        uint32_t total = ces::Buffer::peek<uint32_t>(ch.rxBuf.data() + off);
        if (total < sizeof(uint16_t) || total > kMaxPeerFrame) {
          closeChannel(link, bulk);
          return;
        }
        if (ch.rxBuf.size() - off < sizeof(uint32_t) + total) break;
        const uint8_t* f = ch.rxBuf.data() + off + sizeof(uint32_t);
        uint16_t slen = ces::Buffer::peek<uint16_t>(f);
        if (sizeof(uint16_t) + static_cast<uint32_t>(slen) > total) {
          closeChannel(link, bulk);
          return;
        }
        std::string service(reinterpret_cast<const char*>(f + sizeof(uint16_t)), slen);
        const uint8_t* payload = f + sizeof(uint16_t) + slen;
        size_t plen = total - sizeof(uint16_t) - slen;
        if (ComputeHandler* h = server_->computeHandler())
          h->routePeerMsg(service, link->ckey, payload, plen);
        if (link->closed) return;
        off += sizeof(uint32_t) + total;
      }
      if (off > 0) {
        ch.rxBuf.erase(ch.rxBuf.begin(), ch.rxBuf.begin() + off);
      }
      channelReadLoop(link, bulk);
    });
}

void PeerHandler::kickWrite(std::shared_ptr<PeerLink> link, bool bulk) {
  PeerChannel& ch = bulk ? link->bulk : link->ctrl;
  if (ch.writing || ch.writeQueue.empty() || link->closed || !ch.stream) return;
  ch.writing = true;
  auto head = ch.writeQueue.front();
  auto stream = ch.stream;
  boost::asio::async_write(
    *stream, boost::asio::buffer(*head),
    [this, link, bulk, head](const boost::system::error_code& ec, std::size_t) {
      if (link->closed) return;
      PeerChannel& ch = bulk ? link->bulk : link->ctrl;
      ch.writing = false;
      if (!ch.writeQueue.empty()) ch.writeQueue.pop_front();
      if (ec) { closeChannel(link, bulk); return; }
      kickWrite(link, bulk);
    });
}

void PeerHandler::readDialBindReply(std::shared_ptr<PeerLink> link, bool bulk) {
  PeerChannel& ch = bulk ? link->bulk : link->ctrl;
  auto stream = ch.stream;
  boost::asio::async_read(
    *stream, boost::asio::buffer(ch.bindReplyBuf),
    [this, link, bulk](const boost::system::error_code& ec, std::size_t) {
      if (link->closed) return;
      PeerChannel& ch = bulk ? link->bulk : link->ctrl;
      if (ec) { closeChannel(link, bulk); return; }
      auto r = ces::parseBindReply(
        std::span<const uint8_t, ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE>(
          ch.bindReplyBuf.data(), ch.bindReplyBuf.size()));
      if (r.status != ces::CES_PLEX_OK) { closeChannel(link, bulk); return; }
      if (!ces::verifyBindReply(
            r, std::span<const uint8_t>(ch.bindReqDigest.data(),
                                        ch.bindReqDigest.size()))) {
        closeChannel(link, bulk);
        return;
      }
      if (std::memcmp(r.serverPubkey.data(), link->ckey.data(),
                      link->ckey.size()) != 0) {
        closeChannel(link, bulk);  // misroute / MITM
        return;
      }
      establishChannel(link, bulk);
      // Once control is up, open the bulk channel for QoS. Bulk failing later is
      // harmless -- reconcile retries and the link runs degraded meanwhile.
      if (!bulk && link->outbound && !link->bulk.up() && !link->bulk.dialing)
        dialChannel(link, /*bulk=*/true);
    });
}

void PeerHandler::dialChannel(std::shared_ptr<PeerLink> link, bool bulk) {
  if (link->closed) return;
  PeerChannel& ch = bulk ? link->bulk : link->ctrl;
  if (ch.up() || ch.dialing) return;
  minx::Rudp* rudp = server_->_rpcRudp();
  if (!rudp) return;
  auto exec = server_->_rpcTaskIOExecutor();
  if (!exec) return;

  ch.dialing = true;
  std::random_device rd;
  ch.channelId = static_cast<uint32_t>(rd());
  ch.stream = std::make_shared<minx::RudpStream>(exec);

  rudp->tick(nowMicros());
  if (!rudp->registerChannel(link->endpoint, ch.channelId, ch.stream)) {
    closeChannel(link, bulk);
    return;
  }

  ch.dialTimer = std::make_shared<boost::asio::steady_timer>(exec);
  ch.dialTimer->expires_after(std::chrono::seconds(kDialTimeoutSec));
  std::weak_ptr<PeerLink> wl = link;
  ch.dialTimer->async_wait([this, wl, bulk](const boost::system::error_code& ec) {
    if (ec) return;
    if (auto l = wl.lock()) {
      PeerChannel& c = bulk ? l->bulk : l->ctrl;
      if (!c.up()) closeChannel(l, bulk);
    }
  });

  const uint64_t now = nowMicros();
  ch.bindReqBuf = ces::buildBindRequest(
    CES_PEER_PROTO, now, server_->_serverKeyPair());
  {
    const auto& pkArr = server_->_serverKeyPair().getPublicKeyAsHash();
    std::span<const uint8_t> nameSpan(
      reinterpret_cast<const uint8_t*>(CES_PEER_PROTO),
      std::strlen(CES_PEER_PROTO));
    ch.bindReqDigest = ces::computeBindRequestDigest(
      nameSpan, now,
      std::span<const uint8_t>(pkArr.data(), pkArr.size()));
  }
  auto stream = ch.stream;
  boost::asio::async_write(
    *stream, boost::asio::buffer(ch.bindReqBuf),
    [this, link, bulk](const boost::system::error_code& ec, std::size_t) {
      if (link->closed) return;
      if (ec) { closeChannel(link, bulk); return; }
      readDialBindReply(link, bulk);
    });
}

void PeerHandler::dialPeer(const minx::Hash& ckey,
                           const minx::SockAddr& endpoint) {
  if (links_.count(ckey)) return;  // already linked or dialing
  auto link = std::make_shared<PeerLink>();
  link->ckey = ckey;
  link->endpoint = endpoint;
  link->outbound = true;
  links_[ckey] = link;  // reserve so reconcile won't redial
  dialChannel(link, /*bulk=*/false);  // control first; bulk follows on establish
}

void PeerHandler::reconcileOnce() {
  auto peers = server_->_peerLinkTargets();
  const minx::Hash ourKey = server_->_serverKeyPair().getPublicKeyAsHash();
  std::set<minx::Hash> current;
  for (const auto& [k, _] : links_) current.insert(k);

  auto actions = computePeerLinkActions(peers, ourKey, current);
  for (const auto& ck : actions.toDrop) {
    auto it = links_.find(ck);
    if (it != links_.end()) teardownLink(it->second);
  }
  for (const auto& ck : actions.toDial) {
    for (const auto& p : peers) {
      if (p.ckey == ck && p.dialable) { dialPeer(ck, p.endpoint); break; }
    }
  }
  // Regenerate a missing channel on our outbound links (control died, or the
  // bulk channel never opened / dropped). Snapshot first: dialing can teardown.
  std::vector<std::shared_ptr<PeerLink>> outbound;
  for (const auto& [k, link] : links_)
    if (!link->closed && link->outbound) outbound.push_back(link);
  for (const auto& link : outbound) {
    if (link->closed) continue;
    if (!link->ctrl.up() && !link->ctrl.dialing) dialChannel(link, /*bulk=*/false);
    if (link->anyUp() && !link->bulk.up() && !link->bulk.dialing)
      dialChannel(link, /*bulk=*/true);
  }
}

void PeerHandler::scheduleReconcile() {
  if (!reconcileTimer_ || !running_.load()) return;
  reconcileTimer_->expires_after(
    std::chrono::milliseconds(kReconcileIntervalMs));
  auto t = reconcileTimer_;
  t->async_wait([this, t](const boost::system::error_code& ec) {
    if (ec) return;
    if (!running_.load()) return;
    reconcileOnce();
    scheduleReconcile();
  });
}

void PeerHandler::serve(std::shared_ptr<minx::RudpStream> stream,
                        BoundChannelContext bound) {
  minx::Hash ckey = bound.boundPubkey.getHash();
  // Every server speaks /ces/peer/1 (a builtin), so the bind always succeeds;
  // the mesh is peer-only, so a binder not in our peer table is refused HERE.
  if (!server_->_isPeerByKey(ckey)) {
    stream->shutdown(kRudpStreamCloseTimeout);
    return;
  }
  std::shared_ptr<PeerLink> link;
  bool bulk = false;
  auto it = links_.find(ckey);
  if (it != links_.end() && !it->second->closed) {
    link = it->second;
    if (!link->ctrl.up()) {
      bulk = false;             // (re)fill the control slot
    } else if (!link->bulk.up()) {
      bulk = true;              // fill the bulk slot
    } else {
      // Both channels already up: a fresh bind means the peer restarted /
      // re-dialed. Replace the link and take this as its new control channel.
      teardownLink(link);
      link.reset();
    }
  }
  if (!link) {
    link = std::make_shared<PeerLink>();
    link->ckey = ckey;
    link->outbound = false;
    links_[ckey] = link;
    bulk = false;
  }
  PeerChannel& ch = bulk ? link->bulk : link->ctrl;
  if (ch.stream) {  // drop a stale half-open stream in this slot
    ch.stream->shutdown(kRudpStreamCloseTimeout);
    ch.stream.reset();
  }
  ch.stream = std::move(stream);
  ch.channelId = 0;  // inbound; the id is the dialer's, not tracked here
  establishChannel(link, bulk);
}

void PeerHandler::start() {
  running_.store(true);
  auto exec = server_->_rpcTaskIOExecutor();
  if (!exec) return;
  reconcileTimer_ = std::make_shared<boost::asio::steady_timer>(exec);
  boost::asio::post(exec, [this]() {
    if (!running_.load()) return;
    reconcileOnce();
    scheduleReconcile();
  });
}

void PeerHandler::stop() {
  running_.store(false);
  if (reconcileTimer_) {
    boost::system::error_code ec;
    reconcileTimer_->cancel(ec);
    reconcileTimer_.reset();
  }
  for (auto& [k, link] : links_) {
    link->closed = true;
    for (PeerChannel* ch : {&link->ctrl, &link->bulk}) {
      if (ch->dialTimer) {
        boost::system::error_code ec;
        ch->dialTimer->cancel(ec);
      }
      if (ch->stream) {
        ch->stream->shutdown(kRudpStreamCloseTimeout);
        ch->stream.reset();
      }
    }
  }
  links_.clear();
  {
    std::lock_guard<std::mutex> lk(linkMutex_);
    established_.clear();
  }
}

bool PeerHandler::isLinked(const minx::Hash& ckey) {
  std::lock_guard<std::mutex> lk(linkMutex_);
  return established_.count(ckey) > 0;
}

bool PeerHandler::hasLink(const minx::Hash& destKey) {
  auto it = links_.find(destKey);
  return it != links_.end() && !it->second->closed && it->second->anyUp();
}

void PeerHandler::reconcileNow() {
  auto exec = server_->_rpcTaskIOExecutor();
  if (!exec) return;
  std::promise<void> done;
  boost::asio::post(exec, [this, &done]() {
    reconcileOnce();
    done.set_value();
  });
  done.get_future().get();
}

void PeerHandler::sendMessage(const minx::Hash& destKey,
                              const std::string& service,
                              const uint8_t* data, std::size_t len) {
  auto it = links_.find(destKey);
  if (it == links_.end()) return;
  auto link = it->second;
  if (link->closed || !link->anyUp()) return;
  if (service.size() > 0xFFFF) return;
  uint32_t total =
    static_cast<uint32_t>(sizeof(uint16_t) + service.size() + len);
  if (total > kMaxPeerFrame) return;

  // Prefer the size-appropriate channel; fall back to the survivor when only one
  // is up (degraded latency, still delivered).
  const bool big = total > kBulkThreshold;
  bool bulk;
  if ((big ? link->bulk : link->ctrl).up()) bulk = big;
  else if ((big ? link->ctrl : link->bulk).up()) bulk = !big;
  else return;

  PeerChannel& ch = bulk ? link->bulk : link->ctrl;
  auto frame = std::make_shared<ces::Bytes>();
  frame->reserve(sizeof(uint32_t) + total);
  ces::Buffer::put<uint32_t>(*frame, total);
  ces::Buffer::put<uint16_t>(*frame, static_cast<uint16_t>(service.size()));
  frame->insert(frame->end(), service.begin(), service.end());
  if (len > 0) frame->insert(frame->end(), data, data + len);
  ch.writeQueue.push_back(frame);
  kickWrite(link, bulk);
}

} // namespace ces
