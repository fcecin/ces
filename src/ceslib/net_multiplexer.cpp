// net_multiplexer.cpp — CesPlex implementation
//
// See include/ces/l2/net_multiplexer.h for the design. This file
// implements:
//
//   - The process-wide builtin registry (Meyer-style static).
//   - registerCesPlexBuiltin / findCesPlexBuiltin entrypoints.
//   - The CesPlex class: per-session bind-handshake state machine,
//     wiring into Rudp's channel-opened + receive callbacks, and
//     the hand-off to registered handlers on OK.

#include <ces/l2/net_multiplexer.h>
#include <ces/buffer.h>

#include <ces/l2/net_billing.h>
#include <ces/server.h>
#include <minx/blog.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <chrono>
#include <cstring>
#include <mutex>
#include <vector>

LOG_MODULE("plex");

// ---------------------------------------------------------------------------
// Translation-unit anchors for builtin handlers
// ---------------------------------------------------------------------------
//
// Each handler .cpp file that participates in the static-registration
// pattern must export an anchor symbol and be referenced here. Without
// the reference, the linker strips the handler's TU from ceslib (it
// sees no external symbols used, and static-init alone doesn't count).
// The address-of in the array below counts as a use.
//
// When adding a new handler, add `extern "C" int <anchor_name>;` and
// `&<anchor_name>,` to the array. Keep this list in sync with the
// handler files in this directory.

extern "C" int file_handler_anchor;
extern "C" int compute_handler_anchor;
extern "C" int compute_lua_handler_anchor;

namespace {
  [[maybe_unused]] int* const _cesplex_tu_anchors[] = {
    &file_handler_anchor,
    &compute_handler_anchor,
    &compute_lua_handler_anchor,
  };
}

namespace ces {

// ---------------------------------------------------------------------------
// Builtin registry — Meyer-style function-local static, safe against
// translation-unit init order. Mutex guards against the (unlikely) case
// of a background thread registering during startup; in practice all
// registration happens from main-thread static-init before any CesPlex
// exists.
// ---------------------------------------------------------------------------

namespace {

struct Registry {
  std::mutex mu;
  std::map<std::string, CesPlexHandler*> map;
};

Registry& registry() {
  static Registry r;
  return r;
}

} // namespace

void registerCesPlexBuiltin(const std::string& name,
                            CesPlexHandler* handler) {
  if (!handler) return;
  auto& r = registry();
  std::lock_guard<std::mutex> lk(r.mu);
  auto [it, inserted] = r.map.emplace(name, handler);
  if (!inserted) {
    // Duplicate registration. Keep the first; complain. This can
    // happen if two translation units try to register the same name,
    // which is almost certainly a bug — the later registration loses.
    LOGWARNING << "CesPlex: duplicate builtin registration ignored"
               << SVAR(name);
  }
}

CesPlexHandler* findCesPlexBuiltin(const std::string& name) {
  auto& r = registry();
  std::lock_guard<std::mutex> lk(r.mu);
  auto it = r.map.find(name);
  return it == r.map.end() ? nullptr : it->second;
}

// ---------------------------------------------------------------------------
// Session — per-channel state for the select handshake
// ---------------------------------------------------------------------------
//
// Lifecycle:
//   1. Created when CesPlex::acceptInbound fires from the server's
//      Rudp::Listener::onAccept. The Session owns a freshly-built
//      RudpStream that RUDP wires as the channel handler.
//   2. Read the bind preamble (variable name + fixed-size tail of 137 B):
//        [u16 name_len] [name] [u64 client_time_us]
//        [32 client_pubkey] [32 sha256] [65 sig]
//   3. Verify sig over recomputed digest using client_pubkey. If
//      verify fails or the name's not bound, send a signed NACK reply
//      and drop. Otherwise build BoundChannelContext from the verified
//      pubkey + the channel's sessionToken.
//   4. Build + write the signed bind reply (status=OK + current rate
//      disclosure). On write success, hand the stream + bound context
//      to handler->serve(), drop our reference.
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

  // Bind-preamble read buffers.
  std::array<uint8_t, 2> lenBuf{};
  ces::Bytes nameBuf;
  // Tail = [u64 time_us][32 pubkey][32 sha256][65 sig] = 137 bytes.
  std::array<uint8_t, CES_PLEX_BIND_REQ_TAIL_SIZE> tailBuf{};

  // Outbound bind reply. Held as a member so the async_write has a
  // stable buffer address.
  minx::Bytes replyBuf;

  Session(CesPlex& p, const minx::SockAddr& pr, uint32_t ch,
          std::shared_ptr<minx::RudpStream> s)
    : parent(p), peer(pr), channelId(ch), stream(std::move(s)) {}

  void start() {
    readNameLen();
  }

  void readNameLen() {
    auto self = shared_from_this();
    boost::asio::async_read(
      *stream, boost::asio::buffer(lenBuf),
      [self](const boost::system::error_code& ec, std::size_t) {
        if (ec) { self->drop("read name length"); return; }
        const uint16_t len = ces::Buffer::peek<uint16_t>(self->lenBuf.data());
        if (len == 0 || len > CES_PLEX_MAX_NAME_LEN) {
          LOGDEBUG << "CesPlex: bad bind name length"
                   << SVAR(self->peer) << VAR(self->channelId)
                   << VAR(len);
          self->sendNackAndDrop("bad name length");
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
        if (ec) { self->drop("read name"); return; }
        self->readTail();
      });
  }

  void readTail() {
    auto self = shared_from_this();
    boost::asio::async_read(
      *stream, boost::asio::buffer(tailBuf),
      [self](const boost::system::error_code& ec, std::size_t) {
        if (ec) { self->drop("read bind tail"); return; }
        self->verifyAndDispatch();
      });
  }

  void verifyAndDispatch() {
    // Tail layout: [u64 time_us][32 pubkey][32 sha256][65 sig].
    std::span<const uint8_t> tailSpan(tailBuf.data(), tailBuf.size());
    minx::ConstBuffer reader(tailSpan);
    auto clientTimeUs = reader.get<uint64_t>();
    auto clientPubkey = reader.get<PublicKey>();
    auto claimedSha = reader.get<std::array<uint8_t, CES_PLEX_SHA256_SIZE>>();
    auto sig = reader.get<Signature>();

    // Recompute digest.
    const auto& pkBytes = clientPubkey.getHash();
    auto computed = computeBindRequestDigest(
      std::span<const uint8_t>(nameBuf.data(), nameBuf.size()),
      clientTimeUs,
      std::span<const uint8_t>(pkBytes.data(), pkBytes.size()));
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
    // handler. Anchored by the RUDP session token.
    BoundChannelContext bound;
    bound.boundPubkey = clientPubkey;
    bound.payerPfx = getHashPrefix(clientPubkey.getHash());
    bound.sessionToken = parent.rudp_.sessionToken(peer, channelId);

    BindReplyFields reply;
    reply.status = CES_PLEX_OK;
    reply.serverTimeUs = nowMicrosForCesplex();
    reply.channelSessionToken = bound.sessionToken;
    reply.serverProtoVersion = CES_PLEX_PROTO_VERSION_V1;
    if (parent.server_) {
      const auto& cfg = parent.server_->_config();
      reply.feeNetChannelSec   = cfg.feeNetChannelSec;
      reply.feeNetMemByteDay   = cfg.feeNetMemByteDay;
      reply.feeNetByteSent     = cfg.feeNetByteSent;
      reply.feeNetByteReceived = cfg.feeNetByteReceived;
    }
    bound.serverBoundAtUs = reply.serverTimeUs;

    // Sign the reply with the server's keypair.
    if (!parent.server_) {
      // No server (legacy test path) — can't sign. Drop.
      LOGWARNING << "CesPlex: no server, cannot sign bind reply";
      drop("no server keypair");
      return;
    }
    replyBuf = buildBindReply(
      reply,
      std::span<const uint8_t>(claimedSha.data(), claimedSha.size()),
      parent.server_->_serverKeyPair());

    // Begin per-channel billing. The rates the per-tick debit uses
    // are always live values from CesConfig — what we disclosed in
    // the bind reply was a courtesy snapshot, not a contract.
    if (parent.netBilling_) {
      parent.netBilling_->track(
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
    if (!parent.server_) {
      // Can't sign — just drop without reply.
      drop(why);
      return;
    }
    BindReplyFields reply;
    reply.status = CES_PLEX_NACK;
    reply.serverTimeUs = nowMicrosForCesplex();
    reply.channelSessionToken = parent.rudp_.sessionToken(peer, channelId);
    reply.serverProtoVersion = CES_PLEX_PROTO_VERSION_V1;
    // No rates on NACK — channel never bound.

    // Use the client's claimed sha256 if we got far enough to read
    // the tail; otherwise zero. Bind reply digest covers it either
    // way; client may not be able to verify a NACK that came before
    // it sent its preamble.
    std::array<uint8_t, CES_PLEX_SHA256_SIZE> clientSha{};
    std::memcpy(clientSha.data(),
                tailBuf.data() + sizeof(uint64_t) + CES_PLEX_PUBKEY_SIZE,
                CES_PLEX_SHA256_SIZE);

    replyBuf = buildBindReply(
      reply,
      std::span<const uint8_t>(clientSha.data(), clientSha.size()),
      parent.server_->_serverKeyPair());
    auto self = shared_from_this();
    boost::asio::async_write(
      *stream, boost::asio::buffer(replyBuf),
      [self, why](const boost::system::error_code&, std::size_t) {
        self->drop(why);
      });
  }

  void drop(const char* why) {
    LOGTRACE << "CesPlex: dropping session"
             << SVAR(peer) << VAR(channelId) << SVAR(why);
    // Graceful close: let the in-flight NACK (or whatever the caller
    // queued just before drop) drain into Rudp's sendBuf, then fire
    // HS_CLOSE within kRudpStreamCloseTimeout. Skipping shutdown()
    // here would leave the channel alive until idle GC (60s) — fine
    // semantically, brutal on dial-side UX.
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

CesPlex::CesPlex(const std::map<std::string, std::string>& mounts,
                 minx::Rudp& rudp,
                 boost::asio::io_context& io,
                 CesServer* server,
                 NetworkBilling* netBilling)
  : rudp_(rudp), io_(io), server_(server), netBilling_(netBilling) {
  // Resolve each mount's target string against the builtin registry.
  // Unresolvable targets are logged and skipped.
  for (const auto& [proto, target] : mounts) {
    constexpr const char* kBuiltinPrefix = "builtin:";
    if (target.rfind(kBuiltinPrefix, 0) == 0) {
      std::string name = target.substr(std::strlen(kBuiltinPrefix));
      CesPlexHandler* h = findCesPlexBuiltin(name);
      if (!h) {
        LOGWARNING << "CesPlex: mount skipped — unknown builtin"
                   << SVAR(proto) << SVAR(target);
        continue;
      }
      bindings_.emplace(proto, h);
      LOGINFO << "CesPlex: mount"
              << SVAR(proto) << SVAR(target);
    } else {
      LOGWARNING << "CesPlex: mount skipped — unrecognized target"
                 << " (expected 'builtin:...')"
                 << SVAR(proto) << SVAR(target);
    }
  }

  LOGINFO << "CesPlex: constructed"
          << VAR(bindings_.size())
          << VAR(mounts.size());
}

CesPlex::~CesPlex() {
  // Sessions that are still mid-handshake just get dropped — their
  // streams will close when the last reference goes. The callbacks
  // on rpcRudp_ that point at us are cleared by CesServer before
  // destruction; this is just defensive cleanup.
  sessions_.clear();
}

std::shared_ptr<minx::Rudp::ChannelHandler> CesPlex::acceptInbound(
    const minx::SockAddr& peer, uint32_t channelId) {
  // Build the per-channel stream first — RUDP wires it as the
  // channel handler at registration time and dispatches per-channel
  // events (bytes, close) directly to it. The Session uses the
  // stream as a regular Asio AsyncStream to drive the select
  // handshake.
  auto stream = std::make_shared<minx::RudpStream>(io_.get_executor());
  auto session =
    std::make_shared<Session>(*this, peer, channelId, stream);
  sessions_.emplace(std::make_pair(peer, channelId), session);
  session->start();
  LOGTRACE << "CesPlex: new inbound channel"
           << SVAR(peer) << VAR(channelId);
  return stream;
}

} // namespace ces
