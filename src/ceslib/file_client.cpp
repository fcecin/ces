// file_client.cpp - implementation of CesFileClient.
//
// One instance owns: a MINX socket + a Rudp state machine + two io_contexts
// (netIO for UDP I/O, taskIO for MINX dispatch + Rudp tick) + threads for
// each. On connect(), the select handshake binds a RudpStream to the
// protocol name "/ces/file/1"; every verb from that point on is a
// request-then-response exchange on that stream.
//
// Public verb methods are blocking. They post an async chain onto taskIO,
// wait on a std::promise, return. Errors mid-chain resolve the promise
// early with an error code; the stream may be closed by the server
// (business error) which we detect as a read failure on a subsequent op.

#include <ces/l2/file_client.h>
#include <ces/buffer.h>
#include <ces/ramfilestore.h> // ces::sha256
#include <ces/l2/net_envelope.h>
#include <ces/types.h>

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
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/address.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <span>
#include <thread>
#include <vector>

LOG_MODULE("cfc");

namespace ces {

namespace {

// Wire constants — mirror file_handler.cpp.
constexpr uint8_t kVerbCreate   = 0x01;
constexpr uint8_t kVerbWrite    = 0x02;
constexpr uint8_t kVerbRead     = 0x03;
constexpr uint8_t kVerbStat     = 0x04;
constexpr uint8_t kVerbDeposit  = 0x05;
constexpr uint8_t kVerbWithdraw = 0x06;
constexpr uint8_t kVerbSetPrice = 0x07;
constexpr uint8_t kVerbDelete   = 0x08;
constexpr uint8_t kVerbAppend   = 0x09;
constexpr uint8_t kVerbResize   = 0x0a;

constexpr const char* kFileProto = "/ces/file/1";

// Long enough for a 1 MB WRITE/READ over RUDP fragmentation +
// retransmits. Bump if flakes appear on lossy networks.
constexpr auto kVerbTimeout = std::chrono::seconds(60);
constexpr auto kConnectTimeout = std::chrono::seconds(10);

// All BE serialization goes through ces::Buffer (see ces/buffer.h).

uint64_t nowMicros() {
  return static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count());
}

// Build the per-op envelope (signed bind contract).
// Wire shape: [u32 preamble_len][preamble bytes][65 sig].
// Sig is over sha256(verb || preamble || sessionToken). The pubkey
// is implicit (channel-bound); no per-op timestamp.
minx::Bytes buildSignedEnvelope(
    const KeyPair& signer, uint8_t verb,
    std::span<const uint8_t> preamble,
    uint64_t sessionToken) {
  Signature sig = ces::signPerOp(signer, verb, preamble, sessionToken);

  // [u32 len][preamble][65 sig]
  const size_t total = 4 + preamble.size() + ces::CES_PLEX_SIG_SIZE;
  minx::Bytes wire(total);
  minx::Buffer buf(wire);
  buf.put<uint32_t>(static_cast<uint32_t>(preamble.size()));
  buf.put(preamble);
  buf.put(sig);
  return wire;
}

class NoopMinxListener : public minx::MinxListener {};

// Outbound-only Rudp::Listener: forwards onSend to the local Minx,
// rejects any inbound HS_OPEN. Holds a Minx* set by the owning Impl
// once the local Minx is constructed.
class FileClientRudpListener : public minx::Rudp::Listener {
public:
  void setMinx(minx::Minx* m) { minx_ = m; }
  void onSend(const minx::SockAddr& peer,
              const minx::Bytes& bytes) override {
    // Swallow the "no socket" exception during teardown — Rudp can
    // emit HS_CLOSE at any point in the shutdown sequence.
    if (!minx_) return;
    try {
      minx_->sendExtension(peer, bytes);
    } catch (const std::exception&) {
      // Socket already closed; nothing to do.
    }
  }
  // Default onAccept returns nullptr — rejects inbound HS_OPENs.
private:
  minx::Minx* minx_ = nullptr;
};

} // namespace

// ---------------------------------------------------------------------------
// Impl
// ---------------------------------------------------------------------------

class CesFileClient::Impl {
public:
  Impl() : listener_(std::make_unique<NoopMinxListener>()) {}

  ~Impl() { stop(); }

  uint8_t connect(const std::string& host, uint16_t rpcPort,
                   const KeyPair& signerKey) {
    signerKey_ = std::make_unique<KeyPair>(signerKey);
    boost::system::error_code ec;
    // Resolve host. CES servers bind on ip::address_v6::any() (dual
    // stack), so we normalize any v4 result to v4-mapped-v6.
    boost::asio::io_context ioc;
    boost::asio::ip::udp::resolver res(ioc);
    boost::asio::ip::address addr;
    auto results = res.resolve(host, std::to_string(rpcPort), ec);
    if (ec || results.empty()) {
      LOGERROR << "cesfileclient: resolve failed"
               << SVAR(host) << SVAR(ec.message());
      return CES_ERROR_INTERNAL;
    }
    addr = results.begin()->endpoint().address();
    if (addr.is_v4()) {
      // Convert to v4-mapped-v6 so the server's v6 SockAddr keys match.
      addr = boost::asio::ip::make_address_v6(
        boost::asio::ip::v4_mapped, addr.to_v4());
    }
    peer_ = minx::SockAddr(addr, rpcPort);

    minx::MinxConfig mc{};
    mc.instanceName = "cfc";
    mc.randomXVMsToKeep = 0;
    mc.randomXInitThreads = 0;
    mc.trustLoopback = true;
    minx_ = std::make_unique<minx::Minx>(listener_.get(), mc);

    // CesFileClient may reselect (open a fresh channel) after any
    // per-verb error — if the client's local cap is 1, the new
    // HS_OPEN can race with the old channel's teardown. Give
    // ourselves a small margin.
    minx::RudpConfig rcfg{};
    rcfg.maxChannelsPerPeer = 8;
    // Tight tick cadence for bulk uploads. RUDP's default 100 ms pulse
    // emits only one packet per channel-with-data per pulse — that
    // caps a single 512 KB WRITE at ~350 packets × 100 ms = 35 s on
    // loopback, crushing throughput. 1 ms gives ~1000 pkt/s per
    // channel. For a quiet connection the tick is cheap — the pulse
    // only fires when there's data in the send buffer.
    rcfg.baseTickInterval = std::chrono::milliseconds(1);
    // The Rudp::Listener forwards onSend → minx_->sendExtension and
    // rejects inbound HS_OPENs. The listener exists as a value
    // member so its address is stable across the Rudp's lifetime.
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
      LOGERROR << "cesfileclient: failed to open local UDP socket";
      return CES_ERROR_INTERNAL;
    }

    // Keep io_contexts alive until we explicitly stop.
    netGuard_ = std::make_unique<WorkGuard>(netIO_.get_executor());
    taskGuard_ = std::make_unique<WorkGuard>(taskIO_.get_executor());
    netThread_ = std::thread([this]() { netIO_.run(); });
    taskThread_ = std::thread([this]() { taskIO_.run(); });

    // Drive Rudp ticks so handshakes and retransmits fire.
    tickTimer_ = std::make_shared<boost::asio::steady_timer>(taskIO_);
    boost::asio::post(taskIO_, [this]() { scheduleTick(); });

    // Pick a random channel_id for this invocation.
    std::mt19937 rng(std::random_device{}());
    channel_ = 0;
    while (channel_ == 0) channel_ = rng();

    // Select the file protocol. Returns CES_OK / CES_ERROR_PROTO_REJECTED
    // / CES_ERROR_INTERNAL.
    return doSelect();
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
    stream_.reset();
    tickTimer_.reset();
    rudp_.reset();
    minx_.reset();
    rudpListener_.setMinx(nullptr);
    netGuard_.reset();
    taskGuard_.reset();
    boundPort_ = 0;
  }

  void setServerPubkey(const minx::Hash& pk) {
    serverPk_ = pk;
    hasServerPk_ = true;
  }

  boost::asio::io_context& taskIO() { return taskIO_; }
  std::shared_ptr<minx::RudpStream> stream() { return stream_; }
  // For per-op signing: bound channel state established by doSelect.
  const KeyPair& signerKey() const { return *signerKey_; }
  uint64_t boundSessionToken() const { return boundSessionToken_; }

  // Reopen the CesPlex channel with a fresh channel_id + select
  // handshake. Used after the server closes the channel following an
  // error response. Keeps Minx + Rudp + threads alive — only the
  // stream is replaced.
  //
  // A short delay between drop and new HS_OPEN gives the peer's
  // HS_CLOSE (for the old channel) time to arrive before we open a
  // new one. Without it, maxChannelsPerPeer=1 on the server may
  // reject the new HS_OPEN because the old channel's teardown hasn't
  // completed yet.
  uint8_t reselect() {
    stream_.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    std::mt19937 rng(std::random_device{}());
    channel_ = 0;
    while (channel_ == 0) channel_ = rng();
    return doSelect();
  }

  // Called by the verb layer after a wire read/write failure, to mark
  // the stream dirty so the next verb starts with a fresh channel.
  void markDirty() { streamDirty_ = true; }

  // If the stream is known-dirty, reopen before the next verb.
  uint8_t ensureClean() {
    if (!streamDirty_) return CES_OK;
    streamDirty_ = false;
    return reselect();
  }

  // Server-signed-response parser. Reads the fixed tail (time, reqSigHash,
  // sha256, sig), verifies hash + sig given `verb`, `status`, `preamble`.
  // If verification fails, logs LOGERROR and returns `CES_OK` anyway —
  // the hash/sig check is advisory, per CesFileClient contract.
  // Returns false on stream read error.
  bool readAndVerifyTail(uint8_t status, uint8_t verb,
                         const ces::Bytes& preamble) {
    if (!stream_) return false;
    std::array<uint8_t, 8 + 8 + 32 + 65> tail{};
    auto run = std::make_shared<std::promise<bool>>();
    auto fut = run->get_future();
    auto strm = stream_;
    boost::asio::post(taskIO_, [strm, &tail, run]() mutable {
      boost::asio::async_read(
        *strm, boost::asio::buffer(tail),
        [run](const boost::system::error_code& ec, std::size_t) {
          run->set_value(!ec);
        });
    });
    if (fut.wait_for(kVerbTimeout) != std::future_status::ready) return false;
    if (!fut.get()) return false;

    uint64_t timeUs = ces::Buffer::peek<uint64_t>(tail.data());
    std::array<uint8_t, 8> reqSigHash{};
    std::memcpy(reqSigHash.data(), tail.data() + 8, 8);
    std::array<uint8_t, 32> claimedHash{};
    std::memcpy(claimedHash.data(), tail.data() + 16, 32);
    Signature sig{};
    std::memcpy(sig.data(), tail.data() + 48, 65);

    // Recompute sha256(status || verb || preamble || time || reqSigHash).
    ces::Buffer hashIn(2 + preamble.size() + 8 + 8);
    hashIn.put<uint8_t>(status)
          .put<uint8_t>(verb)
          .putBytes(std::span<const uint8_t>(preamble))
          .put<uint64_t>(timeUs)
          .putBytes(std::span<const uint8_t>(
            reqSigHash.data(), reqSigHash.size()));
    minx::Hash computed = ces::sha256(hashIn.data(), hashIn.size());

    if (std::memcmp(computed.data(), claimedHash.data(), 32) != 0) {
      LOGERROR << "cesfileclient: response hash mismatch";
      return true; // read succeeded; verification failed (non-fatal)
    }
    if (!hasServerPk_) {
      LOGERROR
        << "cesfileclient: server pubkey not set; response sig unverified";
      return true;
    }
    PublicKey pk(serverPk_);
    if (!pk.verifySignature(
          std::span<const uint8_t>(computed.data(), computed.size()), sig)) {
      LOGERROR << "cesfileclient: response sig verification FAILED";
    }
    return true;
  }

  // Blocking I/O helpers posted on taskIO_. Two overloads — minx::Bytes
  // for the bind-bounded envelopes (≤1280), ces::Bytes for
  // the larger payloads (file bodies up to 1 MB) that exceed Bytes' cap.
  bool writeAll(const minx::Bytes& bytes) {
    if (!stream_) return false;
    auto run = std::make_shared<std::promise<bool>>();
    auto fut = run->get_future();
    auto strm = stream_;
    auto buf = std::make_shared<minx::Bytes>(bytes);
    boost::asio::post(taskIO_, [strm, buf, run]() mutable {
      boost::asio::async_write(
        *strm, boost::asio::buffer(*buf),
        [run, buf](const boost::system::error_code& ec, std::size_t) {
          run->set_value(!ec);
        });
    });
    return fut.get();
  }
  bool writeAll(const ces::Bytes& bytes) {
    if (!stream_) return false;
    auto run = std::make_shared<std::promise<bool>>();
    auto fut = run->get_future();
    auto strm = stream_;
    auto buf = std::make_shared<ces::Bytes>(bytes);
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

  bool readExact(ces::Bytes& out, size_t n) {
    if (!stream_) return false;
    out.resize(n);
    auto run = std::make_shared<std::promise<bool>>();
    auto fut = run->get_future();
    auto strm = stream_;
    boost::asio::post(taskIO_,
      [strm, &out, run]() mutable {
        boost::asio::async_read(
          *strm, boost::asio::buffer(out),
          [run](const boost::system::error_code& ec, std::size_t) {
            run->set_value(!ec);
          });
      });
    if (fut.wait_for(kVerbTimeout) != std::future_status::ready) return false;
    return fut.get();
  }

private:
  using WorkGuard = boost::asio::executor_work_guard<
    boost::asio::io_context::executor_type>;

  void scheduleTick() {
    if (!tickTimer_ || !rudp_) return;
    // Tick() is allowed to be called less often than baseTickInterval
    // (1 ms) — each late invocation fires N pulses = elapsedUs/base,
    // capped at 100. So a 10 ms timer gives 10 pulses/call × 100
    // calls/sec = 1000 pkt/sec/channel, same as a 1 ms timer with
    // 1/10th the wakeup cost. scheduleHalvedFire() pulls the next
    // pulse forward on inbound traffic anyway.
    tickTimer_->expires_after(std::chrono::milliseconds(10));
    tickTimer_->async_wait(
      [this](const boost::system::error_code& ec) {
        if (ec || !rudp_) return;
        rudp_->tick(nowMicros());
        scheduleTick();
      });
  }

  // Parse + verify a signed bind reply. On success, stashes the
  // bound sessionToken (and TOFU-captures the server pubkey if not
  // already set). Runs the four mandatory client-side checks:
  //   1. Reply sig verifies against in-reply pubkey (self-consistency).
  //   2. clientSha256 in the reply matches what we just sent.
  //   3. If hasServerPk_ is set, the in-reply pubkey must match it.
  //      Otherwise (TOFU): capture the in-reply pubkey for subsequent
  //      response-sig verification.
  //   4. Status == OK.
  // Returns CES_OK / CES_ERROR_PROTO_REJECTED / CES_ERROR_INTERNAL.
  uint8_t parseBindReply(
      const std::array<uint8_t, ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE>& buf,
      const std::array<uint8_t, ces::CES_PLEX_SHA256_SIZE>& clientDigest) {
    auto r = ces::parseBindReply(
      std::span<const uint8_t, ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE>(
        buf.data(), buf.size()));
    if (r.status != ces::CES_PLEX_OK) {
      // Server NACKed (e.g. unknown protocol). Status takes precedence
      // over sig verification — a NACK reply may have been sent before
      // the server even read the rest of our preamble.
      return CES_ERROR_PROTO_REJECTED;
    }
    if (!ces::verifyBindReply(
          r,
          std::span<const uint8_t>(clientDigest.data(), clientDigest.size()))) {
      LOGERROR << "cesfileclient: bind reply digest/sig verify FAILED";
      return CES_ERROR_INTERNAL;
    }
    // Expected pubkey: hard-fail on mismatch if set; otherwise TOFU-
    // capture for subsequent response-sig verify.
    if (hasServerPk_) {
      if (std::memcmp(serverPk_.data(), r.serverPubkey.data(),
                      serverPk_.size()) != 0) {
        LOGERROR << "cesfileclient: bind reply pubkey ≠ expected";
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
      // Seed Rudp's clock before registerChannel — registerChannel
      // stamps the channel's lastActivityUs from currentTimeUs_,
      // which is zero until the first tick. The next tick would
      // jump the clock and idle-GC the fresh channel.
      rudp_->tick(nowMicros());
      stream_ = std::make_shared<minx::RudpStream>(
        taskIO_.get_executor());
      if (!rudp_->registerChannel(peer_, channel_, stream_)) {
        run->set_value(CES_ERROR_INTERNAL);
        return;
      }

      // Build the signed bind preamble for kFileProto. Sign with the
      // connect-time signerKey_; the server will bind this channel
      // to signerKey_.getPublicKeyAsHash() as the principal identity.
      const uint64_t bindNowUs = nowMicros();
      auto bindReq = std::make_shared<minx::Bytes>(
        ces::buildBindRequest(kFileProto, bindNowUs, *signerKey_));
      // Stash the digest so we can check the reply binds to it.
      const auto& pkArr = signerKey_->getPublicKeyAsHash();
      auto clientDigest = std::make_shared<
        std::array<uint8_t, ces::CES_PLEX_SHA256_SIZE>>(
          ces::computeBindRequestDigest(
            std::span<const uint8_t>(
              reinterpret_cast<const uint8_t*>(kFileProto),
              std::strlen(kFileProto)),
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
      LOGERROR << "cesfileclient: bind handshake timed out";
      return CES_ERROR_INTERNAL;
    }
    uint8_t rc = fut.get();
    LOGDEBUG << "cesfileclient: bind complete"
             << VAR(int(rc)) << VAR(channel_);
    return rc;
  }

  std::unique_ptr<NoopMinxListener> listener_;
  FileClientRudpListener rudpListener_;
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

  minx::SockAddr peer_;
  uint32_t channel_ = 0;
  std::shared_ptr<minx::RudpStream> stream_;

  bool hasServerPk_ = false;
  minx::Hash serverPk_{};

  // Channel-bound state set during the signed bind.
  std::unique_ptr<KeyPair> signerKey_;  // captured at connect()
  uint64_t boundSessionToken_ = 0;       // from signed bind reply

  // When true, the next verb must reselect() before touching the
  // stream. Set by the verb layer on any read/write failure and by
  // the server's error-then-close discipline.
  bool streamDirty_ = false;
};

// ---------------------------------------------------------------------------
// Helpers used by verb methods — keep the per-verb code short
// ---------------------------------------------------------------------------

namespace {

// Signed-verb common path: build + send verb byte + envelope (preamble-sized),
// optionally a streamed body, then read status. Returns CES_OK (and the
// response preamble bytes + optional response body bytes), or error.
//
// - `respFixedPreambleLen`: server-side fixed preamble bytes on OK. 0 if none.
// - `readVariablePreamble`: optional callback to read more preamble bytes
//   after the fixed chunk (STAT uses this for u16 ct_len + ct + u64 ts × 2).
// - `respBodyLengthFromPreamble`: callback returning optional body length
//   based on preamble (READ uses this). Return 0 for "no body".
//
// On error status (not CES_OK), preamble is empty, bodyLen is 0, rc is set.
uint8_t driveVerb(
    CesFileClient::Impl& impl,
    uint8_t verb,
    const minx::Bytes& envelope,
    size_t respFixedPreambleLen,
    const std::function<bool(ces::Bytes& preamble)>& readVariablePreamble,
    const std::function<uint64_t(const ces::Bytes&)>& respBodyLengthFromPreamble,
    const ces::Bytes& extraBodyToSend,
    ces::Bytes& outPreamble,
    ces::Bytes& outBody) {
  // Reopen the channel if a prior op closed it.
  if (impl.ensureClean() != CES_OK) return CES_ERROR_INTERNAL;

  auto fail = [&](uint8_t rc) -> uint8_t {
    impl.markDirty();
    return rc;
  };

  ces::Bytes verbByte{verb};
  if (!impl.writeAll(verbByte)) return fail(CES_ERROR_INTERNAL);
  if (!impl.writeAll(envelope)) return fail(CES_ERROR_INTERNAL);
  if (!extraBodyToSend.empty() && !impl.writeAll(extraBodyToSend))
    return fail(CES_ERROR_INTERNAL);

  ces::Bytes statusBuf;
  if (!impl.readExact(statusBuf, 1)) return fail(CES_ERROR_INTERNAL);
  uint8_t status = statusBuf[0];

  outPreamble.clear();
  outBody.clear();
  if (status == CES_OK) {
    if (respFixedPreambleLen > 0 &&
        !impl.readExact(outPreamble, respFixedPreambleLen))
      return fail(CES_ERROR_INTERNAL);
    if (readVariablePreamble && !readVariablePreamble(outPreamble))
      return fail(CES_ERROR_INTERNAL);
  }

  // Server-signed tail is always present.
  if (!impl.readAndVerifyTail(status, verb, outPreamble))
    return fail(CES_ERROR_INTERNAL);

  if (status != CES_OK) {
    // Server loops on most errors (keeps channel open). For WRITE
    // / APPEND pre-body rejects the server closes; we'll detect
    // that via an I/O failure on the next verb's write and mark
    // dirty at that point. No need to pre-emptively reselect.
    return status;
  }

  if (respBodyLengthFromPreamble) {
    uint64_t bodyLen = respBodyLengthFromPreamble(outPreamble);
    if (bodyLen > 0 && !impl.readExact(outBody, bodyLen))
      return fail(CES_ERROR_INTERNAL);
  }
  return CES_OK;
}

} // namespace

// ---------------------------------------------------------------------------
// CesFileClient public methods
// ---------------------------------------------------------------------------

CesFileClient::CesFileClient() : impl_(std::make_unique<Impl>()) {}
CesFileClient::~CesFileClient() = default;

uint8_t CesFileClient::connect(const std::string& host, uint16_t rpcPort, const KeyPair& signerKey) {
  return impl_->connect(host, rpcPort, signerKey);
}

void CesFileClient::disconnect() { impl_->stop(); }

void CesFileClient::setServerPubkey(const minx::Hash& pk) {
  impl_->setServerPubkey(pk);
}

// ---- CREATE ----
uint8_t CesFileClient::create(
    const std::string& name,
    uint64_t size, uint64_t pricePerKb, uint64_t initialDeposit,
    const std::string& contentType,
    uint64_t& outFileBalance, uint64_t& outCostDebited) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint64_t>(pre, size);
  ces::Buffer::put<uint64_t>(pre, pricePerKb);
  ces::Buffer::put<uint64_t>(pre, initialDeposit);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(contentType.size()));
  pre.insert(pre.end(), contentType.begin(), contentType.end());
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(impl_->signerKey(), kVerbCreate, pre, impl_->boundSessionToken());

  ces::Bytes resp, body;
  uint8_t rc = driveVerb(*impl_, kVerbCreate, env, /*fixedPre=*/16,
                         nullptr, nullptr, {}, resp, body);
  if (rc != CES_OK) return rc;
  outFileBalance = ces::Buffer::peek<uint64_t>(resp.data());
  outCostDebited = ces::Buffer::peek<uint64_t>(resp.data() + 8);
  return CES_OK;
}

// ---- WRITE ----
uint8_t CesFileClient::write(
    const std::string& name,
    uint64_t offset, const ces::Bytes& content,
    uint64_t& outFileBalance) {
  minx::Hash contentHash = ces::sha256(content.data(), content.size());
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint64_t>(pre, offset);
  ces::Buffer::put<uint32_t>(pre, static_cast<uint32_t>(content.size()));
  pre.insert(pre.end(), contentHash.begin(), contentHash.end());
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(impl_->signerKey(), kVerbWrite, pre, impl_->boundSessionToken());

  ces::Bytes resp, body;
  uint8_t rc = driveVerb(*impl_, kVerbWrite, env, /*fixedPre=*/8,
                         nullptr, nullptr, content, resp, body);
  if (rc != CES_OK) return rc;
  outFileBalance = ces::Buffer::peek<uint64_t>(resp.data());
  return CES_OK;
}

// ---- READ ----
uint8_t CesFileClient::read(
    const std::string& name,
    uint64_t offset, uint32_t length,
    ces::Bytes& outContent, minx::Hash& outRangeHash) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint64_t>(pre, offset);
  ces::Buffer::put<uint32_t>(pre, length);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(impl_->signerKey(), kVerbRead, pre, impl_->boundSessionToken());

  ces::Bytes resp, body;
  uint8_t rc = driveVerb(*impl_, kVerbRead, env, /*fixedPre=*/8 + 32,
                         nullptr,
                         [](const ces::Bytes& p) -> uint64_t {
                           return ces::Buffer::peek<uint64_t>(p.data());
                         },
                         {}, resp, body);
  if (rc != CES_OK) return rc;
  std::memcpy(outRangeHash.data(), resp.data() + 8, 32);
  outContent = std::move(body);
  return CES_OK;
}

// ---- STAT (signed; same envelope as every other verb) ----
uint8_t CesFileClient::stat(const std::string& name, StatInfo& outInfo) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(impl_->signerKey(), kVerbStat, pre,
                                  impl_->boundSessionToken());

  // Variable-length response preamble (content_type is variable).
  // Use the readVariablePreamble hook to extend after the fixed prefix.
  ces::Bytes resp, body;
  uint8_t rc = driveVerb(
    *impl_, kVerbStat, env,
    /*fixedPre=*/32 + 8 + 8 + 8 + 2,
    [this](ces::Bytes& p) -> bool {
      uint16_t ctLen = ces::Buffer::peek<uint16_t>(p.data() + 32 + 8 + 8 + 8);
      if (ctLen > 0) {
        ces::Bytes ct;
        if (!impl_->readExact(ct, ctLen)) return false;
        p.insert(p.end(), ct.begin(), ct.end());
      }
      ces::Bytes ts;
      if (!impl_->readExact(ts, 16)) return false;
      p.insert(p.end(), ts.begin(), ts.end());
      return true;
    },
    nullptr, {}, resp, body);
  if (rc != CES_OK) return rc;

  size_t off = 0;
  std::memcpy(outInfo.ownerPubkey.data(), resp.data() + off, 32); off += 32;
  outInfo.fileBalance = ces::Buffer::peek<uint64_t>(resp.data() + off); off += 8;
  outInfo.pricePerKb = ces::Buffer::peek<uint64_t>(resp.data() + off); off += 8;
  outInfo.size = ces::Buffer::peek<uint64_t>(resp.data() + off); off += 8;
  uint16_t ctLen = ces::Buffer::peek<uint16_t>(resp.data() + off); off += 2;
  outInfo.contentType.assign(
    reinterpret_cast<const char*>(resp.data() + off), ctLen);
  off += ctLen;
  outInfo.createdUs = ces::Buffer::peek<uint64_t>(resp.data() + off); off += 8;
  outInfo.modifiedUs = ces::Buffer::peek<uint64_t>(resp.data() + off); off += 8;
  return CES_OK;
}

// ---- DEPOSIT ----
uint8_t CesFileClient::deposit(const std::string& name,
                                uint64_t amount, uint64_t& outFileBalance) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint64_t>(pre, amount);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(impl_->signerKey(), kVerbDeposit, pre, impl_->boundSessionToken());

  ces::Bytes resp, body;
  uint8_t rc = driveVerb(*impl_, kVerbDeposit, env, /*fixedPre=*/8,
                         nullptr, nullptr, {}, resp, body);
  if (rc != CES_OK) return rc;
  outFileBalance = ces::Buffer::peek<uint64_t>(resp.data());
  return CES_OK;
}

// ---- WITHDRAW ----
uint8_t CesFileClient::withdraw(const std::string& name,
                                 uint64_t amount, uint64_t& outFileBalance) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint64_t>(pre, amount);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(impl_->signerKey(), kVerbWithdraw, pre, impl_->boundSessionToken());

  ces::Bytes resp, body;
  uint8_t rc = driveVerb(*impl_, kVerbWithdraw, env, /*fixedPre=*/8,
                         nullptr, nullptr, {}, resp, body);
  if (rc != CES_OK) return rc;
  outFileBalance = ces::Buffer::peek<uint64_t>(resp.data());
  return CES_OK;
}

// ---- SET_PRICE ----
uint8_t CesFileClient::setPrice(const std::string& name,
                                 uint64_t newPrice, uint64_t& outPrice) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint64_t>(pre, newPrice);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(impl_->signerKey(), kVerbSetPrice, pre, impl_->boundSessionToken());

  ces::Bytes resp, body;
  uint8_t rc = driveVerb(*impl_, kVerbSetPrice, env, /*fixedPre=*/8,
                         nullptr, nullptr, {}, resp, body);
  if (rc != CES_OK) return rc;
  outPrice = ces::Buffer::peek<uint64_t>(resp.data());
  return CES_OK;
}

// ---- DELETE ----
uint8_t CesFileClient::deleteFile(const std::string& name,
                                   uint64_t& outRefunded) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(impl_->signerKey(), kVerbDelete, pre, impl_->boundSessionToken());

  ces::Bytes resp, body;
  uint8_t rc = driveVerb(*impl_, kVerbDelete, env, /*fixedPre=*/8,
                         nullptr, nullptr, {}, resp, body);
  if (rc != CES_OK) return rc;
  outRefunded = ces::Buffer::peek<uint64_t>(resp.data());
  return CES_OK;
}

// ---- APPEND ----
uint8_t CesFileClient::append(const std::string& name,
                               const ces::Bytes& content,
                               uint64_t& outFileBalance,
                               uint64_t& outNewSize) {
  minx::Hash contentHash = ces::sha256(content.data(), content.size());
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint32_t>(pre, static_cast<uint32_t>(content.size()));
  pre.insert(pre.end(), contentHash.begin(), contentHash.end());
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(impl_->signerKey(), kVerbAppend, pre, impl_->boundSessionToken());

  ces::Bytes resp, body;
  uint8_t rc = driveVerb(*impl_, kVerbAppend, env, /*fixedPre=*/8 + 8,
                         nullptr, nullptr, content, resp, body);
  if (rc != CES_OK) return rc;
  outFileBalance = ces::Buffer::peek<uint64_t>(resp.data());
  outNewSize = ces::Buffer::peek<uint64_t>(resp.data() + 8);
  return CES_OK;
}

// ---- RESIZE ----
uint8_t CesFileClient::resize(const std::string& name,
                               uint64_t newSize, uint64_t& outNewSize) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint64_t>(pre, newSize);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(impl_->signerKey(), kVerbResize, pre, impl_->boundSessionToken());

  ces::Bytes resp, body;
  uint8_t rc = driveVerb(*impl_, kVerbResize, env, /*fixedPre=*/8,
                         nullptr, nullptr, {}, resp, body);
  if (rc != CES_OK) return rc;
  outNewSize = ces::Buffer::peek<uint64_t>(resp.data());
  return CES_OK;
}

} // namespace ces
