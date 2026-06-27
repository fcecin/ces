// peer_handler.cpp - builtin:peer handler (per-server object). See the header.
//
// One PeerHandler per CesServer; no process-global state. Owns the link state
// machine, the reconcile pass, and the service-tagged message bus extensions
// ride. The lower-pubkey side dials, the higher accepts; on establish the
// channel is marked persistent (RudpStream::setPersistent) so RUDP's idle GC
// never closes it (no keepalive; liveness from the peer table). A fresh inbound
// bind replaces a stale link. sendMessage() frames (service, payload) onto a
// link; inbound frames route by service tag to the local compute instance
// that registered for it (computeRoutePeerMsg).

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

LOG_MODULE("plex");

namespace ces {

namespace {

// Reconcile cadence: dial missing links, drop links whose peer left the table
// or went unreachable. No keepalive role (channels are persistent).
constexpr int kReconcileIntervalMs = 15000;
// Bind-handshake deadline; a dial whose peer never replies is torn down and
// retried on the next reconcile.
constexpr int kDialTimeoutSec = 10;
// Max bytes in one mesh-message frame (after the 4-byte length prefix).
constexpr uint32_t kMaxPeerFrame = 64 * 1024;

uint64_t nowMicros() {
  return static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count());
}

}  // namespace

struct PeerLink : std::enable_shared_from_this<PeerLink> {
  minx::Hash ckey{};                       // remote peer identity
  minx::SockAddr endpoint;                 // remote plex endpoint (dial only)
  uint32_t channelId = 0;
  std::shared_ptr<minx::RudpStream> stream;
  bool outbound = false;                   // true = we dialed
  bool established = false;
  bool closed = false;
  std::array<uint8_t, 8 * 1024> readBuf{};
  ces::Bytes rxBuf;                        // inbound framing accumulator
  std::deque<std::shared_ptr<ces::Bytes>> writeQueue;
  bool writing = false;
  // Dial-phase scratch.
  minx::Bytes bindReqBuf;
  std::array<uint8_t, ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE> bindReplyBuf{};
  std::array<uint8_t, ces::CES_PLEX_SHA256_SIZE> bindReqDigest{};
  std::shared_ptr<boost::asio::steady_timer> dialTimer;
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
  if (link->dialTimer) {
    boost::system::error_code ec;
    link->dialTimer->cancel(ec);
  }
  {
    std::lock_guard<std::mutex> lk(linkMutex_);
    established_.erase(link->ckey);
  }
  auto it = links_.find(link->ckey);
  if (it != links_.end() && it->second == link) links_.erase(it);
  if (link->stream) {
    link->stream->shutdown(kRudpStreamCloseTimeout);
    link->stream.reset();
  }
}

void PeerHandler::establishLink(std::shared_ptr<PeerLink> link) {
  if (link->closed) return;
  link->established = true;
  // Exempt from RUDP idle GC: a peer link is long-lived and may be quiet.
  if (link->stream) link->stream->setPersistent();
  {
    std::lock_guard<std::mutex> lk(linkMutex_);
    established_.insert(link->ckey);
  }
  LOGINFO << "peer-link up" << VAR(link->outbound)
          << SVAR(minx::hashToString(link->ckey));
  peerReadLoop(link);
}

void PeerHandler::peerReadLoop(std::shared_ptr<PeerLink> link) {
  if (link->closed || !link->stream) return;
  auto stream = link->stream;
  stream->async_read_some(
    boost::asio::buffer(link->readBuf),
    [this, link](const boost::system::error_code& ec, std::size_t n) {
      if (ec) { teardownLink(link); return; }
      if (n > 0) {
        link->rxBuf.insert(link->rxBuf.end(),
                           link->readBuf.data(), link->readBuf.data() + n);
      }
      // Frames: [u32 total][u16 service_len][service][payload].
      size_t off = 0;
      while (link->rxBuf.size() - off >= sizeof(uint32_t)) {
        uint32_t total = ces::Buffer::peek<uint32_t>(link->rxBuf.data() + off);
        if (total < sizeof(uint16_t) || total > kMaxPeerFrame) {
          teardownLink(link);
          return;
        }
        if (link->rxBuf.size() - off < sizeof(uint32_t) + total) break;
        const uint8_t* f = link->rxBuf.data() + off + sizeof(uint32_t);
        uint16_t slen = ces::Buffer::peek<uint16_t>(f);
        if (sizeof(uint16_t) + static_cast<uint32_t>(slen) > total) {
          teardownLink(link);
          return;
        }
        std::string service(reinterpret_cast<const char*>(f + sizeof(uint16_t)),
                            slen);
        const uint8_t* payload = f + sizeof(uint16_t) + slen;
        size_t plen = total - sizeof(uint16_t) - slen;
        if (ComputeHandler* h = server_->computeHandler())
          h->routePeerMsg(service, link->ckey, payload, plen);
        if (link->closed) return;
        off += sizeof(uint32_t) + total;
      }
      if (off > 0) {
        link->rxBuf.erase(link->rxBuf.begin(), link->rxBuf.begin() + off);
      }
      peerReadLoop(link);
    });
}

void PeerHandler::kickWrite(std::shared_ptr<PeerLink> link) {
  if (link->writing || link->writeQueue.empty() || link->closed
      || !link->stream) {
    return;
  }
  link->writing = true;
  auto head = link->writeQueue.front();
  auto stream = link->stream;
  boost::asio::async_write(
    *stream, boost::asio::buffer(*head),
    [this, link, head](const boost::system::error_code& ec, std::size_t) {
      link->writing = false;
      if (!link->writeQueue.empty()) link->writeQueue.pop_front();
      if (ec) { teardownLink(link); return; }
      kickWrite(link);
    });
}

void PeerHandler::readDialBindReply(std::shared_ptr<PeerLink> link) {
  auto stream = link->stream;
  boost::asio::async_read(
    *stream, boost::asio::buffer(link->bindReplyBuf),
    [this, link](const boost::system::error_code& ec, std::size_t) {
      if (ec) { teardownLink(link); return; }
      auto r = ces::parseBindReply(
        std::span<const uint8_t, ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE>(
          link->bindReplyBuf.data(), link->bindReplyBuf.size()));
      if (r.status != ces::CES_PLEX_OK) { teardownLink(link); return; }
      if (!ces::verifyBindReply(
            r, std::span<const uint8_t>(link->bindReqDigest.data(),
                                        link->bindReqDigest.size()))) {
        teardownLink(link);
        return;
      }
      if (std::memcmp(r.serverPubkey.data(), link->ckey.data(),
                      link->ckey.size()) != 0) {
        teardownLink(link);  // misroute / MITM
        return;
      }
      if (link->dialTimer) {
        boost::system::error_code ec2;
        link->dialTimer->cancel(ec2);
      }
      establishLink(link);
    });
}

void PeerHandler::dialPeer(const minx::Hash& ckey,
                           const minx::SockAddr& endpoint) {
  if (links_.count(ckey)) return;  // already linked or dialing
  minx::Rudp* rudp = server_->_rpcRudp();
  if (!rudp) return;
  auto exec = server_->_rpcTaskIOExecutor();
  if (!exec) return;

  auto link = std::make_shared<PeerLink>();
  link->ckey = ckey;
  link->endpoint = endpoint;
  link->outbound = true;
  std::random_device rd;
  link->channelId = static_cast<uint32_t>(rd());
  link->stream = std::make_shared<minx::RudpStream>(exec);
  links_[ckey] = link;  // reserve so reconcile won't redial

  rudp->tick(nowMicros());
  if (!rudp->registerChannel(endpoint, link->channelId, link->stream)) {
    teardownLink(link);
    return;
  }

  link->dialTimer = std::make_shared<boost::asio::steady_timer>(exec);
  link->dialTimer->expires_after(std::chrono::seconds(kDialTimeoutSec));
  std::weak_ptr<PeerLink> wl = link;
  link->dialTimer->async_wait([this, wl](const boost::system::error_code& ec) {
    if (ec) return;
    if (auto l = wl.lock()) if (!l->established) teardownLink(l);
  });

  const uint64_t now = nowMicros();
  link->bindReqBuf = ces::buildBindRequest(
    CES_PEER_PROTO, now, server_->_serverKeyPair());
  {
    const auto& pkArr = server_->_serverKeyPair().getPublicKeyAsHash();
    std::span<const uint8_t> nameSpan(
      reinterpret_cast<const uint8_t*>(CES_PEER_PROTO),
      std::strlen(CES_PEER_PROTO));
    link->bindReqDigest = ces::computeBindRequestDigest(
      nameSpan, now,
      std::span<const uint8_t>(pkArr.data(), pkArr.size()));
  }
  auto stream = link->stream;
  boost::asio::async_write(
    *stream, boost::asio::buffer(link->bindReqBuf),
    [this, link](const boost::system::error_code& ec, std::size_t) {
      if (ec) { teardownLink(link); return; }
      readDialBindReply(link);
    });
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
  // Every server speaks /ces/peer/1 (it is a builtin), so the bind always
  // succeeds; the mesh is peer-only, so a binder that is not in our peer
  // table is refused HERE in the handler (accept, then close) rather than
  // with a bind-handshake NACK.
  if (!server_->_isPeerByKey(ckey)) {
    stream->shutdown(kRudpStreamCloseTimeout);
    return;
  }
  auto existing = links_.find(ckey);
  if (existing != links_.end()) {
    // Fresh inbound bind from a peer we hold a link to => that link is stale
    // (the peer restarted / re-dialed). Replace it.
    teardownLink(existing->second);
  }
  auto link = std::make_shared<PeerLink>();
  link->ckey = ckey;
  link->stream = std::move(stream);
  link->outbound = false;
  links_[ckey] = link;
  establishLink(link);
}

void PeerHandler::start() {
  running_.store(true);
  auto exec = server_->_rpcTaskIOExecutor();
  if (!exec) return;
  reconcileTimer_ = std::make_shared<boost::asio::steady_timer>(exec);
  boost::asio::post(exec, [this]() {
    if (running_.load()) reconcileOnce();
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
    if (link->dialTimer) {
      boost::system::error_code ec;
      link->dialTimer->cancel(ec);
    }
    if (link->stream) {
      link->stream->shutdown(kRudpStreamCloseTimeout);
      link->stream.reset();
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
  return it != links_.end() && it->second->established && !it->second->closed;
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
  if (!link->established || link->closed || !link->stream) return;
  if (service.size() > 0xFFFF) return;
  uint32_t total =
    static_cast<uint32_t>(sizeof(uint16_t) + service.size() + len);
  if (total > kMaxPeerFrame) return;
  auto frame = std::make_shared<ces::Bytes>();
  frame->reserve(sizeof(uint32_t) + total);
  ces::Buffer::put<uint32_t>(*frame, total);
  ces::Buffer::put<uint16_t>(*frame, static_cast<uint16_t>(service.size()));
  frame->insert(frame->end(), service.begin(), service.end());
  if (len > 0) frame->insert(frame->end(), data, data + len);
  link->writeQueue.push_back(frame);
  kickWrite(link);
}

} // namespace ces
