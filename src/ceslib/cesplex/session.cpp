// session.cpp — the per-op CesPlex layer for handlers and clients (see mux.h).
//
// Two halves: the server-side signed-request loop (cesPlexServe /
// CesPlexRequest) that builtin:file and builtin:compute drive their verb
// streams through, and the client-side CesPlexChannel (the protocol, over an
// injected transport) that CesPlexClient and the compute child's endpoint both
// compose, and that CesFileClient / CesComputeClient are thin verb wrappers
// over.

#include <ces/cesplex/session.h>
#include <ces/cesplex/mux.h>   // kRudpStreamCloseTimeout, CesPlexHost
#include <ces/buffer.h>
#include <ces/ramfilestore.h>         // ces::sha256
#include <ces/types.h>
#include <ces/util/helpers.h>         // runGuardedThread

#include <minx/blog.h>
#include <minx/minx.h>
#include <minx/rudp/rudp.h>
#include <minx/rudp/rudp_stream.h>
#include <minx/stdext.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/udp.hpp>

#include <array>
#include <chrono>
#include <cstring>
#include <future>
#include <memory>
#include <random>
#include <span>
#include <thread>

LOG_MODULE("plex");

namespace ces {

// ===========================================================================
// Server side — signed-request loop
// ===========================================================================

namespace {

void plexReadVerb(std::shared_ptr<minx::RudpStream> stream,
                  BoundChannelContext bound, CesPlexHost* host,
                  std::shared_ptr<CesPlexProtocol> proto);

// Read [u32 preamble_len][preamble][65 sig], verify, peel reqNonce,
// dispatch. On any wire error the chain just stops (the channel closes
// when its captured stream refs release).
void plexReadEnvelope(std::shared_ptr<CesPlexRequest> req) {
  auto self = req;
  auto lenBuf = std::make_shared<std::array<uint8_t, 4>>();
  boost::asio::async_read(
    *req->stream, boost::asio::buffer(*lenBuf),
    [self, lenBuf](const boost::system::error_code& ec, std::size_t) {
      if (ec) return;
      uint32_t preLen = ces::Buffer::peek<uint32_t>(lenBuf->data());
      if (preLen == 0 || preLen > 4096) {
        // Envelope length out of bounds — caller wire bug, BAD_INPUT.
        self->error(CES_ERROR_BAD_INPUT);
        return;
      }
      auto preBuf = std::make_shared<ces::Bytes>(preLen);
      boost::asio::async_read(
        *self->stream, boost::asio::buffer(*preBuf),
        [self, preBuf](const boost::system::error_code& e2, std::size_t) {
          if (e2) return;
          auto tail =
            std::make_shared<std::array<uint8_t, CES_PLEX_SIG_SIZE>>();
          boost::asio::async_read(
            *self->stream, boost::asio::buffer(*tail),
            [self, preBuf, tail]
            (const boost::system::error_code& e3, std::size_t) {
              if (e3) return;
              std::memcpy(self->sig.data(), tail->data(), CES_PLEX_SIG_SIZE);
              self->reqSigHash = ces::sigDedupHash(self->sig);
              if (!ces::verifyPerOp(
                    self->bound, self->verb,
                    std::span<const uint8_t>(preBuf->data(), preBuf->size()),
                    self->sig)) {
                // Per-op sig didn't verify against the bound pubkey.
                self->error(CES_ERROR_BAD_INPUT);
                return;
              }
              // Preamble = [8B per-op salt][4B reqNonce][verb args]. The
              // salt is a client uniquifier folded into the sig (so a
              // repeated op doesn't collide in dedup); the server skips it.
              if (preBuf->size() < sizeof(uint64_t) + sizeof(uint32_t)) {
                self->error(CES_ERROR_BAD_INPUT);
                return;
              }
              self->reqNonce = ces::Buffer::peek<uint32_t>(
                preBuf->data() + sizeof(uint64_t));
              ces::Bytes preRest(
                preBuf->begin() + sizeof(uint64_t) + sizeof(uint32_t),
                preBuf->end());
              self->proto->dispatch(self, std::move(preRest));
            });
        });
    });
}

// Read one verb byte; if the handler accepts it, build a request and
// read its envelope. An unaccepted verb (unknown, or handler unbound —
// accepts() folds in the bound check) ends the channel.
void plexReadVerb(std::shared_ptr<minx::RudpStream> stream,
                  BoundChannelContext bound, CesPlexHost* host,
                  std::shared_ptr<CesPlexProtocol> proto) {
  auto verbBuf = std::make_shared<std::array<uint8_t, 1>>();
  auto sharedStream = stream;
  auto sharedBound = std::make_shared<BoundChannelContext>(std::move(bound));
  boost::asio::async_read(
    *sharedStream, boost::asio::buffer(*verbBuf),
    [verbBuf, sharedStream, host, sharedBound, proto]
    (const boost::system::error_code& ec, std::size_t) {
      if (ec) return;
      uint8_t verb = (*verbBuf)[0];
      if (!proto->accepts || !proto->accepts(verb)) {
        LOGDEBUG << "cesplex: unaccepted verb; dropping channel"
                 << VAR(int(verb));
        return;  // drop — stream closes when captured refs release
      }
      auto req = std::make_shared<CesPlexRequest>();
      req->stream = sharedStream;
      req->host = host;
      req->verb = verb;
      req->bound = *sharedBound;
      req->proto = proto;
      plexReadEnvelope(req);
    });
}

} // namespace

void cesPlexServe(std::shared_ptr<minx::RudpStream> stream,
                  BoundChannelContext bound, CesPlexHost* host,
                  CesPlexProtocol proto) {
  plexReadVerb(std::move(stream), std::move(bound), host,
               std::make_shared<CesPlexProtocol>(std::move(proto)));
}

void CesPlexRequest::respond(uint8_t status, ces::Bytes preamble,
                             ces::Bytes extraBody) {
  auto str = stream;
  auto bnd = bound;
  auto h = host;
  auto prt = proto;
  auto env = std::make_shared<ces::Bytes>(
    buildPerOpResponse(h->cesplexSigningKey(), verb, status,
                       preamble, reqSigHash));
  auto body = std::make_shared<ces::Bytes>(std::move(extraBody));
  boost::asio::async_write(
    *str, boost::asio::buffer(*env),
    [str, env, body, bnd, h, prt]
    (const boost::system::error_code& ec, std::size_t) mutable {
      if (ec) return;
      if (!body->empty()) {
        boost::asio::async_write(
          *str, boost::asio::buffer(*body),
          [str, body, bnd, h, prt]
          (const boost::system::error_code& ec2, std::size_t) mutable {
            if (ec2) return;
            plexReadVerb(str, std::move(bnd), h, prt);
          });
      } else {
        plexReadVerb(str, std::move(bnd), h, prt);
      }
    });
}

void CesPlexRequest::respondAndClose(uint8_t status, ces::Bytes preamble) {
  auto str = stream;
  auto env = std::make_shared<ces::Bytes>(
    buildPerOpResponse(host->cesplexSigningKey(), verb, status,
                       preamble, reqSigHash));
  boost::asio::async_write(
    *str, boost::asio::buffer(*env),
    [str, env](const boost::system::error_code&, std::size_t) {
      // Graceful close after the error reply drains into Rudp's sendBuf.
      str->shutdown(kRudpStreamCloseTimeout);
    });
  stream.reset();
}

// ===========================================================================
// Client side — CesPlexChannel (protocol) + CesPlexClient (owned transport)
// ===========================================================================

namespace {

constexpr auto kVerbTimeout = std::chrono::seconds(60);
constexpr auto kConnectTimeout = std::chrono::seconds(10);

uint64_t nowMicros() {
  return static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count());
}

class NoopMinxListener : public minx::MinxListener {};

// Outbound-only Rudp::Listener: forwards onSend to the local Minx,
// rejects any inbound HS_OPEN.
class PlexClientRudpListener : public minx::Rudp::Listener {
public:
  void setMinx(minx::Minx* m) { minx_ = m; }
  void onSend(const minx::SockAddr& peer,
              const minx::Bytes& bytes) override {
    if (!minx_) return;
    try {
      minx_->sendExtension(peer, bytes);
    } catch (const std::exception&) {
      // Socket already closed during teardown.
    }
  }
private:
  minx::Minx* minx_ = nullptr;
};

} // namespace

// ---------------------------------------------------------------------------
// CesPlexChannel::Impl — the per-channel CesPlex client PROTOCOL over an
// INJECTED transport. Owns no mechanics: it borrows a task io_context (where
// its async stream ops run) and a Rudp (where it opens its channel). The bind
// handshake, per-op envelope signing, and the verb drive loop all live here,
// once — so CesPlexClient (owned Minx/Rudp/threads) and the compute child's
// CesPlex endpoint (an already-running Rudp) share one client codec.
//
// Threading: the borrowed taskIO_ must be run by some OTHER thread; every verb
// posts its async I/O there and blocks the CALLING thread on a future (caller
// thread must differ from the taskIO_ thread, else deadlock).
// ---------------------------------------------------------------------------
class CesPlexChannel::Impl {
public:
  Impl(boost::asio::io_context& taskIO, minx::Rudp* rudp)
    : taskIO_(taskIO), rudp_(rudp) {}

  // Open a fresh channel to `peer` and run the signed bind for `protocol`,
  // signed by `signerKey` (also the per-op signer + billed principal).
  uint8_t select(const minx::SockAddr& peer, const std::string& protocol,
                 const KeyPair& signerKey) {
    peer_ = peer;
    protocol_ = protocol;
    signerKey_ = std::make_unique<KeyPair>(signerKey);
    std::mt19937 rng(std::random_device{}());
    channel_ = 0;
    while (channel_ == 0) channel_ = rng();
    return doSelect();
  }

  void reset() { stream_.reset(); }

  void setServerPubkey(const minx::Hash& pk) {
    serverPk_ = pk;
    hasServerPk_ = true;
  }

  const KeyPair& signerKey() const { return *signerKey_; }
  uint64_t boundSessionToken() const { return boundSessionToken_; }

  // Reopen the channel with a fresh channel_id + select handshake, used
  // after the server closes the channel following an error. A short
  // delay lets the peer's HS_CLOSE for the old channel land first.
  uint8_t reselect() {
    stream_.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    std::mt19937 rng(std::random_device{}());
    channel_ = 0;
    while (channel_ == 0) channel_ = rng();
    return doSelect();
  }

  void markDirty() { streamDirty_ = true; }

  uint8_t ensureClean() {
    if (!streamDirty_) return CES_OK;
    streamDirty_ = false;
    return reselect();
  }

  // Read + verify the server-signed response trailer. Hash/sig failures
  // are advisory (logged, returns true); returns false only on read error.
  bool readAndVerifyTail(uint8_t status, uint8_t verb,
                         const ces::Bytes& preamble) {
    if (!stream_) return false;
    // Heap-owned so a late read after a wait_for timeout can't write into
    // a freed stack buffer (the async read isn't cancelled on timeout).
    auto tail =
      std::make_shared<std::array<uint8_t, ces::CES_PLEX_RESP_TRAILER_SIZE>>();
    auto run = std::make_shared<std::promise<bool>>();
    auto fut = run->get_future();
    auto strm = stream_;
    boost::asio::post(taskIO_, [strm, tail, run]() mutable {
      boost::asio::async_read(
        *strm, boost::asio::buffer(*tail),
        [run, tail](const boost::system::error_code& ec, std::size_t) {
          run->set_value(!ec);
        });
    });
    if (fut.wait_for(kVerbTimeout) != std::future_status::ready) return false;
    if (!fut.get()) return false;

    // Trailer: [u64 time_us][u64 req_sig_hash][sha256 digest][sig].
    constexpr size_t kReqSigHashOff = ces::CES_PLEX_TIME_US_SIZE;
    constexpr size_t kDigestOff =
        kReqSigHashOff + ces::CES_PLEX_REQ_SIG_HASH_SIZE;
    constexpr size_t kSigOff = kDigestOff + ces::CES_PLEX_SHA256_SIZE;

    uint64_t timeUs = ces::Buffer::peek<uint64_t>(tail->data());
    std::array<uint8_t, ces::CES_PLEX_REQ_SIG_HASH_SIZE> reqSigHash{};
    std::memcpy(reqSigHash.data(), tail->data() + kReqSigHashOff,
                reqSigHash.size());
    std::array<uint8_t, ces::CES_PLEX_SHA256_SIZE> claimedHash{};
    std::memcpy(claimedHash.data(), tail->data() + kDigestOff,
                claimedHash.size());
    Signature sig{};
    std::memcpy(sig.data(), tail->data() + kSigOff, sig.size());

    ces::Buffer hashIn(ces::CES_PLEX_STATUS_SIZE + ces::CES_PLEX_VERB_SIZE
                       + preamble.size() + ces::CES_PLEX_TIME_US_SIZE
                       + ces::CES_PLEX_REQ_SIG_HASH_SIZE);
    hashIn.put<uint8_t>(status)
          .put<uint8_t>(verb)
          .putBytes(std::span<const uint8_t>(preamble))
          .put<uint64_t>(timeUs)
          .putBytes(std::span<const uint8_t>(
            reqSigHash.data(), reqSigHash.size()));
    minx::Hash computed = ces::sha256(hashIn.data(), hashIn.size());

    if (std::memcmp(computed.data(), claimedHash.data(),
                    claimedHash.size()) != 0) {
      LOGERROR << "cesplexclient: response hash mismatch";
      return true;
    }
    if (!hasServerPk_) {
      LOGERROR
        << "cesplexclient: server pubkey not set; response sig unverified";
      return true;
    }
    PublicKey pk(serverPk_);
    if (!pk.verifySignature(
          std::span<const uint8_t>(computed.data(), computed.size()), sig)) {
      LOGERROR << "cesplexclient: response sig verification FAILED";
    }
    return true;
  }

  // Blocking write posted on taskIO_. Two overloads: minx::Bytes for the
  // bind-bounded envelopes (≤1280), ces::Bytes for larger payloads.
  bool writeAll(const minx::Bytes& bytes) {
    return writeAllImpl(std::make_shared<minx::Bytes>(bytes));
  }
  bool writeAll(const ces::Bytes& bytes) {
    return writeAllImpl(std::make_shared<ces::Bytes>(bytes));
  }

  bool readExact(ces::Bytes& out, size_t n) {
    if (!stream_) return false;
    // Heap-owned (see readAndVerifyTail): survives a post-timeout late read.
    auto buf = std::make_shared<ces::Bytes>(n);
    auto run = std::make_shared<std::promise<bool>>();
    auto fut = run->get_future();
    auto strm = stream_;
    boost::asio::post(taskIO_,
      [strm, buf, run]() mutable {
        boost::asio::async_read(
          *strm, boost::asio::buffer(*buf),
          [run, buf](const boost::system::error_code& ec, std::size_t) {
            run->set_value(!ec);
          });
      });
    if (fut.wait_for(kVerbTimeout) != std::future_status::ready) return false;
    if (!fut.get()) return false;
    out = std::move(*buf);
    return true;
  }

  minx::Bytes buildEnvelope(uint8_t verb,
                            std::span<const uint8_t> preamble) {
    // Prepend an 8-byte per-op salt so two ops with identical (verb,
    // preamble) still sign differently — otherwise the server's sig-dedup
    // treats a repeated query as a replay and skips its fee. The salt is
    // framework header (the server strips it); monotonic per client is
    // enough, since the sig also covers the per-channel sessionToken.
    ces::Bytes signedPre;
    signedPre.reserve(sizeof(uint64_t) + preamble.size());
    ces::Buffer::put<uint64_t>(signedPre, opSalt_++);
    signedPre.insert(signedPre.end(), preamble.begin(), preamble.end());
    std::span<const uint8_t> sp(signedPre.data(), signedPre.size());

    Signature sig = ces::signPerOp(*signerKey_, verb, sp, boundSessionToken_);
    // [u32 len][salt+preamble][65 sig]
    const size_t total = 4 + signedPre.size() + ces::CES_PLEX_SIG_SIZE;
    minx::Bytes wire(total);
    minx::Buffer buf(wire);
    buf.put<uint32_t>(static_cast<uint32_t>(signedPre.size()));
    buf.put(sp);
    buf.put(sig);
    return wire;
  }

  uint8_t driveVerb(
      uint8_t verb,
      const minx::Bytes& envelope,
      size_t respFixedPreambleLen,
      const std::function<bool(ces::Bytes&)>& readVariablePreamble,
      const std::function<uint64_t(const ces::Bytes&)>& respBodyLen,
      const ces::Bytes& extraBodyToSend,
      ces::Bytes& outPreamble,
      ces::Bytes& outBody) {
    if (ensureClean() != CES_OK) return CES_ERROR_INTERNAL;

    auto fail = [&](uint8_t rc) -> uint8_t {
      markDirty();
      return rc;
    };

    ces::Bytes verbByte{verb};
    if (!writeAll(verbByte)) return fail(CES_ERROR_INTERNAL);
    if (!writeAll(envelope)) return fail(CES_ERROR_INTERNAL);
    if (!extraBodyToSend.empty() && !writeAll(extraBodyToSend))
      return fail(CES_ERROR_INTERNAL);

    ces::Bytes statusBuf;
    if (!readExact(statusBuf, 1)) return fail(CES_ERROR_INTERNAL);
    uint8_t status = statusBuf[0];

    outPreamble.clear();
    outBody.clear();
    if (status == CES_OK) {
      if (respFixedPreambleLen > 0 &&
          !readExact(outPreamble, respFixedPreambleLen))
        return fail(CES_ERROR_INTERNAL);
      if (readVariablePreamble && !readVariablePreamble(outPreamble))
        return fail(CES_ERROR_INTERNAL);
    }

    if (!readAndVerifyTail(status, verb, outPreamble))
      return fail(CES_ERROR_INTERNAL);

    if (status != CES_OK) return status;

    if (respBodyLen) {
      uint64_t bodyLen = respBodyLen(outPreamble);
      if (bodyLen > 0 && !readExact(outBody, bodyLen))
        return fail(CES_ERROR_INTERNAL);
    }
    return CES_OK;
  }

private:
  bool writeAllImpl(std::shared_ptr<minx::Bytes> buf) {
    if (!stream_) return false;
    auto run = std::make_shared<std::promise<bool>>();
    auto fut = run->get_future();
    auto strm = stream_;
    boost::asio::post(taskIO_, [strm, buf, run]() mutable {
      boost::asio::async_write(
        *strm, boost::asio::buffer(*buf),
        [run, buf](const boost::system::error_code& ec, std::size_t) {
          run->set_value(!ec);
        });
    });
    if (fut.wait_for(kVerbTimeout) != std::future_status::ready) return false;
    return fut.get();
  }
  bool writeAllImpl(std::shared_ptr<ces::Bytes> buf) {
    if (!stream_) return false;
    auto run = std::make_shared<std::promise<bool>>();
    auto fut = run->get_future();
    auto strm = stream_;
    boost::asio::post(taskIO_, [strm, buf, run]() mutable {
      boost::asio::async_write(
        *strm, boost::asio::buffer(*buf),
        [run, buf](const boost::system::error_code& ec, std::size_t) {
          run->set_value(!ec);
        });
    });
    if (fut.wait_for(kVerbTimeout) != std::future_status::ready) return false;
    return fut.get();
  }

  // Parse + verify the signed bind reply. On OK, stash sessionToken and
  // TOFU-capture the server pubkey if not already pinned.
  uint8_t parseBindReply(
      const std::array<uint8_t, ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE>& buf,
      const std::array<uint8_t, ces::CES_PLEX_SHA256_SIZE>& clientDigest) {
    auto r = ces::parseBindReply(
      std::span<const uint8_t, ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE>(
        buf.data(), buf.size()));
    if (r.status != ces::CES_PLEX_OK) return CES_ERROR_PROTO_REJECTED;
    if (!ces::verifyBindReply(
          r,
          std::span<const uint8_t>(clientDigest.data(), clientDigest.size()))) {
      LOGERROR << "cesplexclient: bind reply digest/sig verify FAILED";
      return CES_ERROR_INTERNAL;
    }
    if (hasServerPk_) {
      if (std::memcmp(serverPk_.data(), r.serverPubkey.data(),
                      serverPk_.size()) != 0) {
        LOGERROR << "cesplexclient: bind reply pubkey ≠ expected";
        return CES_ERROR_INTERNAL;
      }
    } else {
      std::memcpy(serverPk_.data(), r.serverPubkey.data(), serverPk_.size());
      hasServerPk_ = true;
    }
    boundSessionToken_ = r.channelSessionToken;
    return CES_OK;
  }

  uint8_t doSelect() {
    auto run = std::make_shared<std::promise<uint8_t>>();
    auto fut = run->get_future();
    boost::asio::post(taskIO_, [this, run]() {
      // Seed Rudp's clock before registerChannel so the fresh channel
      // isn't idle-GC'd on the next tick.
      rudp_->tick(nowMicros());
      stream_ = std::make_shared<minx::RudpStream>(taskIO_.get_executor());
      if (!rudp_->registerChannel(peer_, channel_, stream_)) {
        run->set_value(CES_ERROR_INTERNAL);
        return;
      }

      const uint64_t bindNowUs = nowMicros();
      auto bindReq = std::make_shared<minx::Bytes>(
        ces::buildBindRequest(protocol_, bindNowUs, *signerKey_));
      const auto& pkArr = signerKey_->getPublicKeyAsHash();
      auto clientDigest = std::make_shared<
        std::array<uint8_t, ces::CES_PLEX_SHA256_SIZE>>(
          ces::computeBindRequestDigest(
            std::span<const uint8_t>(
              reinterpret_cast<const uint8_t*>(protocol_.data()),
              protocol_.size()),
            bindNowUs,
            std::span<const uint8_t>(pkArr.data(), pkArr.size())));

      boost::asio::async_write(
        *stream_, boost::asio::buffer(*bindReq),
        [this, bindReq, clientDigest, run]
        (const boost::system::error_code& ec, std::size_t) {
          if (ec) { run->set_value(CES_ERROR_INTERNAL); return; }
          auto reply = std::make_shared<
            std::array<uint8_t, ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE>>();
          boost::asio::async_read(
            *stream_, boost::asio::buffer(*reply),
            [this, reply, clientDigest, run]
            (const boost::system::error_code& ec2, std::size_t) {
              if (ec2) { run->set_value(CES_ERROR_INTERNAL); return; }
              run->set_value(parseBindReply(*reply, *clientDigest));
            });
        });
    });
    if (fut.wait_for(kConnectTimeout) != std::future_status::ready) {
      LOGERROR << "cesplexclient: bind handshake timed out";
      return CES_ERROR_INTERNAL;
    }
    uint8_t rc = fut.get();
    LOGDEBUG << "cesplexclient: bind complete"
             << VAR(int(rc)) << VAR(channel_) << SVAR(protocol_);
    return rc;
  }

  boost::asio::io_context& taskIO_;   // borrowed: run by another thread
  minx::Rudp* rudp_;                  // borrowed: where we open our channel

  std::string protocol_;
  minx::SockAddr peer_;
  uint32_t channel_ = 0;
  std::shared_ptr<minx::RudpStream> stream_;

  bool hasServerPk_ = false;
  minx::Hash serverPk_{};

  std::unique_ptr<KeyPair> signerKey_;
  uint64_t boundSessionToken_ = 0;
  uint64_t opSalt_ = 1;          // per-op envelope uniquifier (see buildEnvelope)

  bool streamDirty_ = false;
};

// ---- CesPlexChannel public forwards ----

CesPlexChannel::CesPlexChannel(boost::asio::io_context& taskIO,
                               minx::Rudp* rudp)
  : impl_(std::make_unique<Impl>(taskIO, rudp)) {}
CesPlexChannel::~CesPlexChannel() = default;

uint8_t CesPlexChannel::select(const minx::SockAddr& peer,
                               const std::string& protocol,
                               const KeyPair& signerKey) {
  return impl_->select(peer, protocol, signerKey);
}

void CesPlexChannel::reset() { impl_->reset(); }

void CesPlexChannel::setServerPubkey(const minx::Hash& pk) {
  impl_->setServerPubkey(pk);
}

uint64_t CesPlexChannel::boundSessionToken() const {
  return impl_->boundSessionToken();
}

minx::Bytes CesPlexChannel::buildEnvelope(
    uint8_t verb, std::span<const uint8_t> preamble) {
  return impl_->buildEnvelope(verb, preamble);
}

uint8_t CesPlexChannel::driveVerb(
    uint8_t verb,
    const minx::Bytes& envelope,
    size_t respFixedPreambleLen,
    const std::function<bool(ces::Bytes&)>& readVariablePreamble,
    const std::function<uint64_t(const ces::Bytes&)>& respBodyLen,
    const ces::Bytes& extraBodyToSend,
    ces::Bytes& outPreamble,
    ces::Bytes& outBody) {
  return impl_->driveVerb(verb, envelope, respFixedPreambleLen,
                          readVariablePreamble, respBodyLen,
                          extraBodyToSend, outPreamble, outBody);
}

uint8_t CesPlexChannel::driveVerb(
    uint8_t verb,
    const minx::Bytes& envelope,
    size_t respFixedPreambleLen,
    const std::function<bool(ces::Bytes&)>& readVariablePreamble,
    ces::Bytes& outPreamble) {
  ces::Bytes dummyBody;
  return impl_->driveVerb(verb, envelope, respFixedPreambleLen,
                          readVariablePreamble, nullptr, {}, outPreamble,
                          dummyBody);
}

bool CesPlexChannel::readExact(ces::Bytes& out, size_t n) {
  return impl_->readExact(out, n);
}

// ---------------------------------------------------------------------------
// CesPlexClient::Impl — owned mechanics (Minx + Rudp + two io threads + tick)
// composing one CesPlexChannel over them. This is cesh's / the tests' client;
// a process that already runs a Rudp builds a CesPlexChannel directly instead.
// ---------------------------------------------------------------------------
class CesPlexClient::Impl {
public:
  Impl() : listener_(std::make_unique<NoopMinxListener>()) {}
  ~Impl() { stop(); }

  uint8_t connect(const std::string& host, uint16_t rpcPort,
                  const std::string& protocol, const KeyPair& signerKey) {
    boost::system::error_code ec;
    boost::asio::io_context ioc;
    boost::asio::ip::udp::resolver res(ioc);
    boost::asio::ip::address addr;
    auto results = res.resolve(host, std::to_string(rpcPort), ec);
    if (ec || results.empty()) {
      LOGERROR << "cesplexclient: resolve failed"
               << SVAR(host) << SVAR(ec.message());
      return CES_ERROR_INTERNAL;
    }
    addr = results.begin()->endpoint().address();
    if (addr.is_v4()) {
      // Normalize v4 to v4-mapped-v6 so the server's v6 SockAddr keys match.
      addr = boost::asio::ip::make_address_v6(
        boost::asio::ip::v4_mapped, addr.to_v4());
    }
    minx::SockAddr peer(addr, rpcPort);

    minx::MinxConfig mc{};
    mc.instanceName = "plexc";
    mc.randomXVMsToKeep = 0;
    mc.randomXInitThreads = 0;
    mc.trustLoopback = true;
    minx_ = std::make_unique<minx::Minx>(listener_.get(), mc);

    // Margin for reselect() racing an old channel's teardown; tight tick
    // cadence (1 ms) so bulk WRITE/READ aren't throttled by RUDP's pulse.
    minx::RudpConfig rcfg{};
    rcfg.maxChannelsPerPeer = 8;
    rcfg.baseTickInterval = std::chrono::milliseconds(1);
    rudpListener_.setMinx(minx_.get());
    rudp_ = std::make_unique<minx::Rudp>(&rudpListener_, rcfg);

    {
      minx::MinxStdExtensions stdExt;
      stdExt.registerExtension(
        minx::Rudp::KEY_V0,
        [this](const minx::SockAddr& p, uint64_t key,
               const minx::Bytes& payload) {
          if (rudp_) rudp_->onPacket(p, key, payload, nowMicros());
        });
      minx_->setExtensionHandler(std::move(stdExt).build());
    }

    boundPort_ = minx_->openSocket(
      boost::asio::ip::address_v6::any(), 0, netIO_, taskIO_);
    if (boundPort_ == 0) {
      LOGERROR << "cesplexclient: failed to open local UDP socket";
      return CES_ERROR_INTERNAL;
    }

    netGuard_ = std::make_unique<WorkGuard>(netIO_.get_executor());
    taskGuard_ = std::make_unique<WorkGuard>(taskIO_.get_executor());
    netThread_ = std::thread(
      [this]() { runGuardedThread([this]{ netIO_.run(); }, "cesplexClientNetIO"); });
    taskThread_ = std::thread(
      [this]() { runGuardedThread([this]{ taskIO_.run(); }, "cesplexClientTaskIO"); });

    tickTimer_ = std::make_shared<boost::asio::steady_timer>(taskIO_);
    boost::asio::post(taskIO_, [this]() { scheduleTick(); });

    // The protocol driver rides our owned transport.
    chan_ = std::make_unique<CesPlexChannel>(taskIO_, rudp_.get());
    if (hasPendingServerPk_) chan_->setServerPubkey(pendingServerPk_);
    return chan_->select(peer, protocol, signerKey);
  }

  void stop() {
    if (!minx_) return;
    if (tickTimer_) {
      boost::system::error_code ec;
      tickTimer_->cancel(ec);
    }
    minx_->closeSocket(false);
    if (netGuard_) netGuard_->reset();
    if (taskGuard_) taskGuard_->reset();
    netIO_.stop();
    taskIO_.stop();
    if (netThread_.joinable()) netThread_.join();
    if (taskThread_.joinable()) taskThread_.join();
    chan_.reset();
    tickTimer_.reset();
    rudp_.reset();
    minx_.reset();
    rudpListener_.setMinx(nullptr);
    netGuard_.reset();
    taskGuard_.reset();
    boundPort_ = 0;
  }

  CesPlexChannel* channel() { return chan_.get(); }

  void setServerPubkey(const minx::Hash& pk) {
    // Usually called BEFORE connect() — chan_ isn't built yet. Remember it
    // and pin it onto the channel at connect time, so the bind reply is
    // verified against the caller's expected pubkey instead of TOFU'd.
    pendingServerPk_ = pk;
    hasPendingServerPk_ = true;
    if (chan_) chan_->setServerPubkey(pk);
  }
  minx::Bytes buildEnvelope(uint8_t verb, std::span<const uint8_t> preamble) {
    return chan_ ? chan_->buildEnvelope(verb, preamble) : minx::Bytes{};
  }
  uint8_t driveVerb(
      uint8_t verb,
      const minx::Bytes& envelope,
      size_t respFixedPreambleLen,
      const std::function<bool(ces::Bytes&)>& readVariablePreamble,
      const std::function<uint64_t(const ces::Bytes&)>& respBodyLen,
      const ces::Bytes& extraBodyToSend,
      ces::Bytes& outPreamble,
      ces::Bytes& outBody) {
    if (!chan_) return CES_ERROR_INTERNAL;
    return chan_->driveVerb(verb, envelope, respFixedPreambleLen,
                            readVariablePreamble, respBodyLen,
                            extraBodyToSend, outPreamble, outBody);
  }
  bool readExact(ces::Bytes& out, size_t n) {
    return chan_ && chan_->readExact(out, n);
  }

private:
  using WorkGuard = boost::asio::executor_work_guard<
    boost::asio::io_context::executor_type>;

  void scheduleTick() {
    if (!tickTimer_ || !rudp_) return;
    tickTimer_->expires_after(std::chrono::milliseconds(10));
    tickTimer_->async_wait(
      [this](const boost::system::error_code& ec) {
        if (ec || !rudp_) return;
        rudp_->tick(nowMicros());
        scheduleTick();
      });
  }

  std::unique_ptr<NoopMinxListener> listener_;
  PlexClientRudpListener rudpListener_;
  std::unique_ptr<minx::Minx> minx_;
  std::unique_ptr<minx::Rudp> rudp_;
  boost::asio::io_context netIO_;
  boost::asio::io_context taskIO_;
  std::unique_ptr<WorkGuard> netGuard_;
  std::unique_ptr<WorkGuard> taskGuard_;
  std::thread netThread_;
  std::thread taskThread_;
  std::shared_ptr<boost::asio::steady_timer> tickTimer_;
  uint16_t boundPort_ = 0;
  bool hasPendingServerPk_ = false;
  minx::Hash pendingServerPk_{};
  // Declared last → destroyed first, before the taskIO_/rudp_ it borrows.
  std::unique_ptr<CesPlexChannel> chan_;
};

// ---- CesPlexClient public forwards ----

CesPlexClient::CesPlexClient() : impl_(std::make_unique<Impl>()) {}
CesPlexClient::~CesPlexClient() = default;

uint8_t CesPlexClient::connect(const std::string& host, uint16_t rpcPort,
                               const std::string& protocol,
                               const KeyPair& signerKey) {
  return impl_->connect(host, rpcPort, protocol, signerKey);
}

void CesPlexClient::disconnect() { impl_->stop(); }

CesPlexChannel* CesPlexClient::channel() { return impl_->channel(); }

void CesPlexClient::setServerPubkey(const minx::Hash& pk) {
  impl_->setServerPubkey(pk);
}

minx::Bytes CesPlexClient::buildEnvelope(
    uint8_t verb, std::span<const uint8_t> preamble) {
  return impl_->buildEnvelope(verb, preamble);
}

uint8_t CesPlexClient::driveVerb(
    uint8_t verb,
    const minx::Bytes& envelope,
    size_t respFixedPreambleLen,
    const std::function<bool(ces::Bytes&)>& readVariablePreamble,
    const std::function<uint64_t(const ces::Bytes&)>& respBodyLen,
    const ces::Bytes& extraBodyToSend,
    ces::Bytes& outPreamble,
    ces::Bytes& outBody) {
  return impl_->driveVerb(verb, envelope, respFixedPreambleLen,
                          readVariablePreamble, respBodyLen,
                          extraBodyToSend, outPreamble, outBody);
}

uint8_t CesPlexClient::driveVerb(
    uint8_t verb,
    const minx::Bytes& envelope,
    size_t respFixedPreambleLen,
    const std::function<bool(ces::Bytes&)>& readVariablePreamble,
    ces::Bytes& outPreamble) {
  ces::Bytes dummyBody;
  return impl_->driveVerb(verb, envelope, respFixedPreambleLen,
                          readVariablePreamble, nullptr, {}, outPreamble,
                          dummyBody);
}

bool CesPlexClient::readExact(ces::Bytes& out, size_t n) {
  return impl_->readExact(out, n);
}

} // namespace ces
