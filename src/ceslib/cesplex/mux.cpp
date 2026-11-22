// mux.cpp — CesPlex implementation
//
// See include/ces/cesplex/mux.h for the design. This file
// implements the CesPlex class: per-session bind-handshake state
// machine, wiring into Rudp's channel-opened + receive callbacks, and
// the hand-off to mounted handlers on OK.

#include <ces/cesplex/mux.h>
#include <ces/buffer.h>

#include <ces/cesplex/meter.h>
#include <minx/blog.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <chrono>
#include <cstring>
#include <span>
#include <vector>

LOG_MODULE("plex");

namespace ces {

// ---------------------------------------------------------------------------
// Session — per-channel state for the bind handshake
// ---------------------------------------------------------------------------
//
// Lifecycle:
//   1. Created when CesPlex::acceptInbound fires from the server's
//      Rudp::Listener::onAccept. The Session owns a freshly-built
//      RudpStream that RUDP wires as the channel handler.
//   2. Read the protocol name: [u16 name_len] [name]. The client speaks
//      first: its channel packet carries the RUDP session token, so it
//      proves the address of the open. The session sends nothing before it.
//   3. Write the server hello: [32 host pubkey][u64 challenge], with a
//      fresh challenge for this channel, then read the rest of the bind
//      request, a fixed-size tail of 137 B:
//        [u64 client_time_us] [32 client_pubkey] [32 sha256] [65 sig]
//   4. Recompute the digest with this session's hello, and verify the sig
//      with client_pubkey. If either fails or the name's not bound, send a
//      signed NACK reply and drop. Otherwise build BoundChannelContext from
//      the verified pubkey and the digest of the bind.
//   5. Build + write the signed bind reply. On write success, hand the
//      stream + bound context to handler->serve(), drop our reference.
//
// Continuations capture `self = shared_from_this()`; sessions_ holds
// a strong ref until handoff or NACK-completion.

struct CesPlex::Session : std::enable_shared_from_this<CesPlex::Session> {
  CesPlex& parent;
  minx::SockAddr peer;
  uint32_t channelId;

  // The RudpStream IS the channel handler in the new RUDP API.
  // The Session holds it across the bind handshake; on OK the strong
  // ref is moved to the application handler.
  std::shared_ptr<minx::RudpStream> stream;

  // The server hello of this channel. Its challenge exists only here: the
  // digest check takes it from this session, never from the wire.
  ServerHello hello;
  minx::Bytes helloBuf;

  // Bind-preamble read buffers.
  std::array<uint8_t, 2> lenBuf{};
  ces::Bytes nameBuf;
  // Tail = [u64 time_us][32 pubkey][32 sha256][65 sig] = 137 bytes.
  std::array<uint8_t, CES_PLEX_BIND_REQ_TAIL_SIZE> tailBuf{};

  // Outbound bind reply. Held as a member so the async_write has a
  // stable buffer address.
  minx::Bytes replyBuf;

  // The parent's alive_ flag. Each completion returns if it is false: the
  // parent, its map and its handlers are gone then.
  std::shared_ptr<const bool> alive;

  Session(CesPlex& p, const minx::SockAddr& pr, uint32_t ch,
          std::shared_ptr<minx::RudpStream> s)
    : parent(p), peer(pr), channelId(ch), stream(std::move(s)),
      alive(p.alive_) {}

  void start() {
    readNameLen();
  }

  // After the name: the hello, then the rest of the request.
  void writeHello() {
    // No host (a test path): no key to send. verifyAndDispatch drops.
    if (!parent.host_) {
      readTail();
      return;
    }
    hello.serverPubkey = parent.host_->cesplexSigningKey().getPublicKeyAsHash();
    hello.challenge = newChallenge();
    helloBuf = buildServerHello(hello);
    auto self = shared_from_this();
    boost::asio::async_write(
      *stream, boost::asio::buffer(helloBuf),
      [self](const boost::system::error_code& ec, std::size_t) {
        if (!*self->alive) return;
        if (ec) { self->drop("write hello"); return; }
        self->readTail();
      });
  }

  void readNameLen() {
    auto self = shared_from_this();
    boost::asio::async_read(
      *stream, boost::asio::buffer(lenBuf),
      [self](const boost::system::error_code& ec, std::size_t) {
        if (!*self->alive) return;
        if (ec) { self->drop("read name length"); return; }
        const uint16_t len = ces::Buffer::peek<uint16_t>(self->lenBuf.data());
        if (len == 0 || len > CES_PLEX_MAX_NAME_LEN) {
          // No reply: the client waits for a hello here, so a NACK would
          // be read as one. Only a client with a caller error gets here.
          LOGDEBUG << "CesPlex: bad bind name length"
                   << SVAR(self->peer) << VAR(self->channelId)
                   << VAR(len);
          self->drop("bad name length");
          return;
        }
        self->nameBuf.resize(len);
        self->readName();
      });
  }

  void readName() {
    auto self = shared_from_this();
    boost::asio::async_read(
      *stream, boost::asio::buffer(nameBuf),
      [self](const boost::system::error_code& ec, std::size_t) {
        if (!*self->alive) return;
        if (ec) { self->drop("read name"); return; }
        self->writeHello();
      });
  }

  void readTail() {
    auto self = shared_from_this();
    boost::asio::async_read(
      *stream, boost::asio::buffer(tailBuf),
      [self](const boost::system::error_code& ec, std::size_t) {
        if (!*self->alive) return;
        if (ec) { self->drop("read bind tail"); return; }
        self->verifyAndDispatch();
      });
  }

  void verifyAndDispatch() {
    if (!parent.host_) {
      // No host (test path): no hello was sent, and no reply can be signed.
      LOGWARNING << "CesPlex: no host, cannot check or sign a bind";
      drop("no host keypair");
      return;
    }
    // Tail layout: [u64 time_us][32 pubkey][32 sha256][65 sig].
    std::span<const uint8_t> tailSpan(tailBuf.data(), tailBuf.size());
    minx::ConstBuffer reader(tailSpan);
    auto clientTimeUs = reader.get<uint64_t>();
    auto clientPubkey = reader.get<PublicKey>();
    auto claimedSha = reader.get<std::array<uint8_t, CES_PLEX_SHA256_SIZE>>();
    auto sig = reader.get<Signature>();

    // Recompute the digest with this session's own hello. A bind signed
    // for another server or another channel does not match.
    const auto& pkBytes = clientPubkey.getHash();
    auto computed = computeBindRequestDigest(
      std::span<const uint8_t>(nameBuf.data(), nameBuf.size()),
      clientTimeUs,
      std::span<const uint8_t>(pkBytes.data(), pkBytes.size()),
      hello);
    if (computed != claimedSha) {
      LOGDEBUG << "CesPlex: bind digest mismatch"
               << SVAR(peer) << VAR(channelId);
      sendNackAndDrop("digest mismatch");
      return;
    }

    if (!clientPubkey.verifySignature(
          std::span<const uint8_t>(computed.data(), computed.size()),
          sig)) {
      LOGDEBUG << "CesPlex: bind sig verify FAILED"
               << SVAR(peer) << VAR(channelId);
      sendNackAndDrop("sig verify failed");
      return;
    }

    // Clock check. The challenge already makes the bind good on this
    // channel only.
    const uint64_t nowUs = nowMicrosForCesplex();
    if (clientTimeUs > nowUs + CES_PLEX_BIND_FUTURE_DRIFT_US ||
        clientTimeUs + CES_PLEX_BIND_MAX_AGE_US < nowUs) {
      LOGDEBUG << "CesPlex: stale bind time"
               << SVAR(peer) << VAR(channelId)
               << VAR(clientTimeUs) << VAR(nowUs);
      sendNackAndDrop("stale bind time");
      return;
    }

    // Lookup handler.
    const std::string name(
      reinterpret_cast<const char*>(nameBuf.data()), nameBuf.size());
    auto it = parent.bindings_.find(name);
    if (it == parent.bindings_.end()) {
      LOGDEBUG << "CesPlex: NACK — no handler"
               << SVAR(peer) << VAR(channelId) << SVAR(name);
      sendNackAndDrop("unknown protocol");
      return;
    }

    LOGDEBUG << "CesPlex: bind OK"
             << SVAR(peer) << VAR(channelId) << SVAR(name);

    // Build the BoundChannelContext we'll hand to the application
    // handler. Per-op sigs sign the digest of this bind.
    BoundChannelContext bound;
    bound.boundPubkey = clientPubkey;
    bound.payerPfx = getHashPrefix(clientPubkey.getHash());
    bound.bindDigest = computed;
    bound.peer = peer;
    bound.channelId = channelId;

    BindReplyFields reply;
    reply.status = CES_PLEX_OK;
    reply.serverTimeUs = nowMicrosForCesplex();
    reply.challenge = hello.challenge;
    reply.serverProtoVersion = CES_PLEX_PROTO_VERSION_V1;
    bound.serverBoundAtUs = reply.serverTimeUs;

    // Sign the reply with the host's keypair.
    replyBuf = buildBindReply(
      reply,
      std::span<const uint8_t>(claimedSha.data(), claimedSha.size()),
      parent.host_->cesplexSigningKey());

    // Begin metering this channel. Each tick measures its resource deltas
    // and reports them to the host, which prices them however it likes.
    // The host may opt a protocol out (server-to-server peer mesh).
    if (parent.channelMeter_ && parent.host_->cesplexChannelMetered(name)) {
      parent.channelMeter_->track(
        peer, channelId, "plex:" + name, bound.payerPfx);
    }

    sendReplyAndHandOff(it->second, std::move(bound));
  }

  void sendReplyAndHandOff(CesPlexHandler* handler,
                            BoundChannelContext bound) {
    auto self = shared_from_this();
    boost::asio::async_write(
      *stream, boost::asio::buffer(replyBuf),
      [self, handler, bound = std::move(bound)]
      (const boost::system::error_code& ec, std::size_t) mutable {
        if (!*self->alive) return;
        if (ec) { self->drop("write bind reply"); return; }
        // Move the stream to the handler. RUDP keeps its own
        // shared_ptr (the stream is the channel handler), so per-
        // channel bytes keep flowing.
        auto streamToPass = std::move(self->stream);
        self->parent.sessions_.erase(
          std::make_pair(self->peer, self->channelId));
        handler->serve(std::move(streamToPass), std::move(bound));
      });
  }

  // NACK path: send a signed reply with status=NACK so the client can
  // surface a clean PROTO_REJECTED instead of a hang. The reply is
  // signed with the server key; clientSha256 is whatever the client
  // sent (we still bind to it so the client can verify the reply was
  // for their bind attempt).
  void sendNackAndDrop(const char* why) {
    LOGDEBUG << "CesPlex: sending NACK reply"
             << SVAR(peer) << VAR(channelId) << SVAR(why);
    if (!parent.host_) {
      // Can't sign — just drop without reply.
      drop(why);
      return;
    }
    BindReplyFields reply;
    reply.status = CES_PLEX_NACK;
    reply.serverTimeUs = nowMicrosForCesplex();
    reply.challenge = hello.challenge;
    reply.serverProtoVersion = CES_PLEX_PROTO_VERSION_V1;

    // Each NACK comes after the tail, so it binds to the client's claimed
    // sha256, and the client can check it.
    std::array<uint8_t, CES_PLEX_SHA256_SIZE> clientSha{};
    std::memcpy(clientSha.data(),
                tailBuf.data() + sizeof(uint64_t) + CES_PLEX_PUBKEY_SIZE,
                CES_PLEX_SHA256_SIZE);

    replyBuf = buildBindReply(
      reply,
      std::span<const uint8_t>(clientSha.data(), clientSha.size()),
      parent.host_->cesplexSigningKey());
    auto self = shared_from_this();
    boost::asio::async_write(
      *stream, boost::asio::buffer(replyBuf),
      [self, why](const boost::system::error_code&, std::size_t) {
        if (!*self->alive) return;
        self->drop(why);
      });
  }

  void drop(const char* why) {
    LOGTRACE << "CesPlex: dropping session"
             << SVAR(peer) << VAR(channelId) << SVAR(why);
    // Graceful close: let the in-flight NACK (or whatever the caller
    // queued just before drop) drain into Rudp's sendBuf, then fire
    // HS_CLOSE within kRudpStreamCloseTimeout. Skipping shutdown()
    // here would leave the channel alive until idle GC (60s) — correct,
    // but a long stall for a waiting dial client.
    if (stream) {
      stream->shutdown(kRudpStreamCloseTimeout);
      stream.reset();
    }
    parent.sessions_.erase(std::make_pair(peer, channelId));
  }

  static uint64_t nowMicrosForCesplex() {
    return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
  }
};

// ---------------------------------------------------------------------------
// CesPlex
// ---------------------------------------------------------------------------

CesPlex::CesPlex(boost::asio::io_context& io,
                 CesPlexHost* host,
                 ChannelMeter* meter)
  : io_(io), host_(host), channelMeter_(meter) {
  // No bindings at construction: the host mounts handler objects via mount().
  LOGINFO << "CesPlex: constructed";
}

CesPlex::~CesPlex() {
  // The owner joined the thread of io_ before this, so nothing runs here.
  // A session that waits for a read is held by its own stream (the pending
  // read holds the session, which holds the stream), so clearing the map
  // does not free it. Detach each stream: that ends the pending operations
  // with eof, and their completions, when io_ runs them, see alive_ false
  // and only drop their references. detach() leaves the RUDP channel alone.
  *alive_ = false;
  for (auto& [key, session] : sessions_) {
    if (session->stream) session->stream->detach();
  }
  sessions_.clear();
}

void CesPlex::mount(const std::string& proto, CesPlexHandler* handler) {
  if (handler) {
    bindings_[proto] = handler;
    LOGINFO << "CesPlex: mount instance" << SVAR(proto);
  } else {
    bindings_.erase(proto);
  }
}

std::shared_ptr<minx::Rudp::ChannelHandler> CesPlex::acceptInbound(
    const minx::SockAddr& peer, uint32_t channelId) {
  // Build the per-channel stream first — RUDP wires it as the
  // channel handler at registration time and dispatches per-channel
  // events (bytes, close) directly to it. The Session uses the
  // stream as a regular Asio AsyncStream to drive the bind
  // handshake.
  auto key = std::make_pair(peer, channelId);
  if (sessions_.find(key) != sessions_.end()) {
    // Duplicate accept for coords we already track: reject so RUDP does not
    // wire a second stream over the in-flight one (see the header contract).
    LOGDEBUG << "CesPlex: duplicate inbound accept, rejecting"
             << SVAR(peer) << VAR(channelId);
    return nullptr;
  }
  auto stream = std::make_shared<minx::RudpStream>(io_.get_executor());
  auto session =
    std::make_shared<Session>(*this, peer, channelId, stream);
  sessions_.emplace(key, session);
  session->start();
  LOGTRACE << "CesPlex: new inbound channel"
           << SVAR(peer) << VAR(channelId);
  return stream;
}

} // namespace ces
