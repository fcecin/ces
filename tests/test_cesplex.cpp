// ===========================================================================
// CesPlex end-to-end tests
// ===========================================================================
//
// Exercises the protocol-select handshake on a CES server's secondary
// port. For each test, we stand up a CesServer with a specific
// cesplexMounts config and a MINX/Rudp "client" in-process that opens
// a channel to the server's rpc port and speaks the select wire
// protocol directly.
//
// Wire format (see include/ces/cesplex/mux.h):
//
//   Client → Server: [u16 BE proto_name_len][proto_name_bytes]
//   Server → Client: [u8 status]     0x01 = OK, 0x00 = NACK
//
// After OK, bytes are handed to the registered handler; after NACK,
// the channel is closed.
//
// The echo handler is a plain object the fixture mounts on the server's
// CesPlex via _mountCesPlexHandler (object mount path) — there is no global
// registry. Any given CesServer serves only handlers it explicitly mounts.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"
#include "test_echo_handler.h"

#include <ces/cesplex/mux.h>
#include <ces/l2/file_handler.h>
#include <ces/buffer.h>
#include <ces/ramfilestore.h>
#include <ces/cesplex/wire.h>
#include <ces/server.h>

#include <minx/minx.h>
#include <minx/rudp/rudp.h>
#include <minx/rudp/rudp_stream.h>
#include <minx/stdext.h>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace {

// EchoHandler (test-only length-prefixed byte echo) lives in
// test_echo_handler.h so this suite and the channel-meter suite each mount
// their own instance. gEchoHandler is mounted by the fixture as an object.
ces::EchoHandler gEchoHandler;

} // namespace

// ---------------------------------------------------------------------------
// PlexTestPeer — in-process Minx + Rudp "client" that initiates a
// channel to the server's rpc port and speaks the select wire
// protocol. Mirrors the MockRpcServer pattern in test_sysrpc.cpp but
// on the outbound-client side.
// ---------------------------------------------------------------------------

namespace {

static uint64_t nowMicros() {
  return static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count());
}

class NoopMinxListener : public minx::MinxListener {};

// Outbound-only Rudp::Listener for the test peer. Forwards onSend
// to the local Minx; default onAccept rejects inbound HS_OPENs.
class PlexPeerRudpListener : public minx::Rudp::Listener {
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

class PlexTestPeer {
public:
  PlexTestPeer() = default;
  ~PlexTestPeer() { stop(); }

  // Bring the peer up and return its bound port. 0 on failure.
  uint16_t start() {
    minx_ = std::make_unique<minx::Minx>(
      &listener_, minx::MinxConfig{
        .instanceName = "peer",
        .randomXVMsToKeep = 0,
        .randomXInitThreads = 0,
        .trustLoopback = true});

    rudpListener_.setMinx(minx_.get());
    rudp_ = std::make_unique<minx::Rudp>(&rudpListener_);

    {
      minx::MinxStdExtensions stdExt;
      stdExt.registerExtension(
        minx::Rudp::KEY_V0,
        [this](const minx::SockAddr& peer, uint64_t key,
               const minx::Bytes& payload) {
          if (rudp_) rudp_->onPacket(peer, key, payload, nowMicros());
        });
      minx_->setExtensionHandler(std::move(stdExt).build());
    }

    port_ = minx_->openSocket(
      boost::asio::ip::address_v6::loopback(), 0,
      netIO_, taskIO_);
    if (port_ == 0) return 0;

    // Work guards keep run() from returning before we've posted any
    // actual work. Without these, taskIO_.run() races against the
    // later scheduleTick() post and can exit the thread first,
    // leaving the tick never scheduled and no packets ever sent.
    netGuard_ = std::make_unique<
      boost::asio::executor_work_guard<
        boost::asio::io_context::executor_type>>(
      netIO_.get_executor());
    taskGuard_ = std::make_unique<
      boost::asio::executor_work_guard<
        boost::asio::io_context::executor_type>>(
      taskIO_.get_executor());

    netThread_ = std::thread([this]() { netIO_.run(); });
    taskThread_ = std::thread([this]() { taskIO_.run(); });

    // Drive Rudp ticks so handshakes/retransmits fire.
    tickTimer_ = std::make_shared<boost::asio::steady_timer>(taskIO_);
    boost::asio::post(taskIO_, [this]() { scheduleTick(); });

    return port_;
  }

  void stop() {
    if (!minx_) return;
    if (tickTimer_) {
      boost::system::error_code ec;
      tickTimer_->cancel(ec);
    }
    minx_->closeSocket(false);
    // Release the work guards so run() can return once socket close
    // drains the outstanding async ops.
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
    port_ = 0;
  }

  // Synchronously (from the test thread) open a channel, select
  // `protoName`, and return the status byte. If the status is OK
  // (0x01), the caller gets a RudpStream they can async-read/write.
  // If NACK (0x00) or timeout, stream is null.
  //
  // The call blocks (with timeout) on the test thread while the
  // ack arrives via taskIO_.
  struct SelectResult {
    uint8_t status = 0xFF;   // 0xFF = timeout / error / not attempted
    std::shared_ptr<minx::RudpStream> stream;
    // Bound sessionToken from the signed bind reply. Tests that build
    // per-op sigs need this — they hash (verb || preamble || token).
    uint64_t sessionToken = 0;
  };

  boost::asio::io_context& taskIO() { return taskIO_; }

  // Step 3: signed bind handshake. `signer` is the principal pubkey
  // the channel will be bound to; the bind preamble is signed by it.
  // Returns SelectResult with status=OK (0x01), the bound stream, and
  // the bound sessionToken on success; status=NACK (0x00) on a clean
  // PROTO_REJECTED reply; status=0xFF on transport/verify failure
  // or timeout.
  SelectResult select(uint16_t targetPort, const std::string& protoName,
                      const ces::KeyPair& signer,
                      std::chrono::milliseconds timeout =
                        std::chrono::milliseconds(3000),
                      uint64_t bindTimeOverrideUs = 0) {
    currentPeer_ = minx::SockAddr(
      boost::asio::ip::address_v6::loopback(), targetPort);
    currentChannel_ = 1;  // peer-chosen; arbitrary, unique within peer

    auto done = std::make_shared<std::atomic<bool>>(false);
    auto result = std::make_shared<SelectResult>();
    auto mu = std::make_shared<std::mutex>();
    auto cv = std::make_shared<std::condition_variable>();

    boost::asio::post(taskIO_,
      [this, protoName, &signer, done, result, mu, cv, bindTimeOverrideUs]() {
      // Seed Rudp's clock before registerChannel (avoid idle-GC).
      rudp_->tick(nowMicros());
      stream_ = std::make_shared<minx::RudpStream>(
        taskIO_.get_executor());
      if (!rudp_->registerChannel(
            currentPeer_, currentChannel_, stream_)) {
        finish(done, result, mu, cv, 0xFF, nullptr, 0);
        return;
      }

      // Build signed bind preamble.
      const uint64_t bindNowUs =
        bindTimeOverrideUs ? bindTimeOverrideUs : nowMicros();
      auto bindReq = std::make_shared<minx::Bytes>(
        ces::buildBindRequest(protoName, bindNowUs, signer));
      const auto& pkArr = signer.getPublicKeyAsHash();
      auto clientDigest = std::make_shared<
        std::array<uint8_t, ces::CES_PLEX_SHA256_SIZE>>(
          ces::computeBindRequestDigest(
            std::span<const uint8_t>(
              reinterpret_cast<const uint8_t*>(protoName.data()),
              protoName.size()),
            bindNowUs,
            std::span<const uint8_t>(pkArr.data(), pkArr.size())));

      boost::asio::async_write(
        *stream_, boost::asio::buffer(*bindReq),
        [this, bindReq, clientDigest, done, result, mu, cv]
        (const boost::system::error_code& ec, std::size_t) {
          if (ec) {
            finish(done, result, mu, cv, 0xFF, nullptr, 0);
            return;
          }
          auto reply = std::make_shared<
            std::array<uint8_t, ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE>>();
          boost::asio::async_read(
            *stream_, boost::asio::buffer(*reply),
            [this, reply, clientDigest, done, result, mu, cv]
            (const boost::system::error_code& ec2, std::size_t) {
              if (ec2) {
                finish(done, result, mu, cv, 0xFF, nullptr, 0);
                return;
              }
              const uint8_t status = (*reply)[0];
              if (status != ces::CES_PLEX_OK) {
                finish(done, result, mu, cv, status, nullptr, 0);
                return;
              }
              uint64_t st = ces::Buffer::peek<uint64_t>(
                reply->data() + 1 + 8 + 32);
              finish(done, result, mu, cv, status, stream_, st);
            });
        });
    });

    std::unique_lock<std::mutex> lk(*mu);
    cv->wait_for(lk, timeout, [&]() { return done->load(); });
    return *result;
  }

private:
  void scheduleTick() {
    if (!tickTimer_ || !rudp_) return;
    tickTimer_->expires_after(std::chrono::milliseconds(20));
    tickTimer_->async_wait(
      [this](const boost::system::error_code& ec) {
        if (ec || !rudp_) return;
        rudp_->tick(nowMicros());
        scheduleTick();
      });
  }

  void finish(std::shared_ptr<std::atomic<bool>> done,
              std::shared_ptr<SelectResult> result,
              std::shared_ptr<std::mutex> mu,
              std::shared_ptr<std::condition_variable> cv,
              uint8_t status,
              std::shared_ptr<minx::RudpStream> stream,
              uint64_t sessionToken) {
    {
      std::lock_guard<std::mutex> lk(*mu);
      result->status = status;
      result->stream = std::move(stream);
      result->sessionToken = sessionToken;
      done->store(true);
    }
    cv->notify_all();
  }

  NoopMinxListener listener_;
  PlexPeerRudpListener rudpListener_;
  std::unique_ptr<minx::Minx> minx_;
  std::unique_ptr<minx::Rudp> rudp_;
  boost::asio::io_context netIO_;
  boost::asio::io_context taskIO_;
  std::unique_ptr<
    boost::asio::executor_work_guard<
      boost::asio::io_context::executor_type>> netGuard_;
  std::unique_ptr<
    boost::asio::executor_work_guard<
      boost::asio::io_context::executor_type>> taskGuard_;
  std::thread netThread_;
  std::thread taskThread_;
  std::shared_ptr<boost::asio::steady_timer> tickTimer_;
  uint16_t port_ = 0;

  // Only one live channel at a time in these tests.
  minx::SockAddr currentPeer_;
  uint32_t currentChannel_ = 0;
  std::shared_ptr<minx::RudpStream> stream_;
};

// ---------------------------------------------------------------------------
// Fixture — starts a fresh CesServer with a caller-supplied
// cesplexMounts on an ephemeral rpcPort, tears it down on drop.
// ---------------------------------------------------------------------------

struct CesPlexFixture {
  fs::path tempDir;
  std::unique_ptr<CesServer> server;
  uint16_t rpcPort = 0;

  explicit CesPlexFixture(
      const std::map<std::string, std::string>& mounts,
      const std::map<std::string, ces::CesPlexHandler*>& objMounts = {}) {
    blog::init();
    blog::set_level(blog::info);
    blog::set_level("plex", blog::debug);

    tempDir = makeUniqueTempDir("cesplex_test");

    minx::Hash serverPriv;
    serverPriv.fill(0xCE);

    CesConfig cfg = makeTestConfig(
      tempDir, serverPriv, std::numeric_limits<uint64_t>::max());
    // OS-allocated rpc port (rpcAutoPort → openSocket(0) picks a guaranteed-
    // free port). Manually picking risked colliding with the OS ephemeral
    // range that client sockets bind into.
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = mounts;
    // Enable the file-store feature for any test that wants it;
    // 1 GB is plenty for unit tests.
    cfg.cesFileStoreMaxBytes = 1ull * 1024 * 1024 * 1024;
    // Minimum non-zero rent rate: with size=1 KB and sub-second
    // test ops, owed rounds to zero via integer floor
    // (size × 1 × us / 86.4e9 ≪ 1). Tests that want rent to
    // actually kill a file use a larger size (e.g. 1 MB) + sleep.
    cfg.feeFileRent = 1;

    server = std::make_unique<CesServer>(cfg);
    server->start();
    rpcPort = server->_rpcBoundPort();
    BOOST_REQUIRE_MESSAGE(rpcPort != 0,
      "CesServer failed to bind secondary port for CesPlex test");
    // Mount non-core test handlers (e.g. echo) directly as objects; there is
    // no global registry, so the host mounts what it serves.
    for (const auto& [proto, h] : objMounts)
      server->_mountCesPlexHandler(proto, h);
  }

  ~CesPlexFixture() {
    if (server) server->stop(false);
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }
};

} // namespace

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_SUITE(CesPlexSuite)

BOOST_AUTO_TEST_CASE(NackUnknownProtocol) {
  // With no bindings, CesPlex rejects inbound HS_OPEN at Accept — we
  // wouldn't get far enough to see a NACK. So we mount something unrelated
  // (file) to give CesPlex a binding, then select an unrelated name to
  // exercise the per-protocol NACK path.
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });

  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);

  ces::KeyPair signer;
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();
  auto r = peer.select(fx.rpcPort, "/ces/nope/1", signer);
  BOOST_CHECK_EQUAL(int(r.status), 0x00);
  BOOST_CHECK(r.stream == nullptr);
}

BOOST_AUTO_TEST_CASE(EchoRoundTrip) {
  CesPlexFixture fx({}, { {"/ces/test/echo/1", &gEchoHandler} });

  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);

  ces::KeyPair signer;
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();
  auto r = peer.select(fx.rpcPort, "/ces/test/echo/1", signer);
  BOOST_REQUIRE_EQUAL(int(r.status), 0x01);
  BOOST_REQUIRE(r.stream != nullptr);

  // RudpStream is async-only (no write_some/read_some). Drive the
  // exchange on the peer's taskIO_ thread via chained async ops and
  // use a std::promise to deliver the result back to the test
  // thread. Echoes the length-prefixed message; we read the same
  // length + body back.
  const std::string msg = "hello plex";

  struct Exchange : std::enable_shared_from_this<Exchange> {
    std::shared_ptr<minx::RudpStream> stream;
    std::string msg;
    std::array<uint8_t, 8> txLen{};
    std::array<uint8_t, 8> rxLen{};
    ces::Bytes rxBody;
    std::promise<std::string> prom;

    void run() {
      ces::Buffer::poke<uint64_t>(txLen.data(), msg.size());
      auto self = shared_from_this();
      boost::asio::async_write(
        *stream, boost::asio::buffer(txLen),
        [self](const boost::system::error_code& ec, std::size_t) {
          if (ec) { self->prom.set_value({}); return; }
          boost::asio::async_write(
            *self->stream, boost::asio::buffer(self->msg),
            [self](const boost::system::error_code& ec2, std::size_t) {
              if (ec2) { self->prom.set_value({}); return; }
              boost::asio::async_read(
                *self->stream, boost::asio::buffer(self->rxLen),
                [self](const boost::system::error_code& ec3, std::size_t) {
                  if (ec3) { self->prom.set_value({}); return; }
                  uint64_t rxN = ces::Buffer::peek<uint64_t>(self->rxLen.data());
                  self->rxBody.resize(rxN);
                  boost::asio::async_read(
                    *self->stream, boost::asio::buffer(self->rxBody),
                    [self](const boost::system::error_code& ec4,
                           std::size_t) {
                      if (ec4) { self->prom.set_value({}); return; }
                      self->prom.set_value(
                        std::string(self->rxBody.begin(),
                                    self->rxBody.end()));
                    });
                });
            });
        });
    }
  };

  auto ex = std::make_shared<Exchange>();
  ex->stream = r.stream;
  ex->msg = msg;
  auto fut = ex->prom.get_future();
  boost::asio::post(peer.taskIO(), [ex]() { ex->run(); });

  auto status = fut.wait_for(std::chrono::seconds(3));
  BOOST_REQUIRE(status == std::future_status::ready);
  const std::string got = fut.get();
  BOOST_CHECK_EQUAL(got, msg);
}

BOOST_AUTO_TEST_CASE(FileSelectAccepts) {
  // Sanity: builtin:file mounted on /ces/file/1 accepts the select.
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::KeyPair signer;
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();
  auto r = peer.select(fx.rpcPort, "/ces/file/1", signer);
  BOOST_CHECK_EQUAL(int(r.status), 0x01);
  BOOST_REQUIRE(r.stream != nullptr);
}

// A bind request carries a signed client_time_us but binds no
// channelId/sessionToken; without a freshness check a captured bind replays on
// fresh channels (re-binding as the victim, accruing ChannelMeter). A bind
// whose timestamp is outside the freshness window must NACK. (Fresh binds still
// succeed — see FileSelectAccepts above.)
BOOST_AUTO_TEST_CASE(BindRejectsStaleTime) {
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::KeyPair signer;
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();
  // Bind timestamp 10 minutes in the past — beyond CES_PLEX_BIND_MAX_AGE_US (5m).
  const uint64_t staleUs =
    ces::getMicrosSinceEpoch() - 10ull * 60 * 1'000'000;
  auto r = peer.select(fx.rpcPort, "/ces/file/1", signer,
                       std::chrono::milliseconds(3000), staleUs);
  BOOST_CHECK_EQUAL(int(r.status), 0x00);   // NACK; pre-fix this was 0x01
  BOOST_CHECK(r.stream == nullptr);
}

// ---------------------------------------------------------------------------
// File handler v2 — exercises the 8-verb file-as-wallet protocol.
// ---------------------------------------------------------------------------

namespace {

// All BE serialization goes through ces::Buffer (see ces/buffer.h).

// ---------------------------------------------------------------------------
// FileClient — a thin sync-ish wrapper that builds signed v2 envelopes
// and drives them over a RudpStream returned by PlexTestPeer::select.
// All verbs run on the peer's taskIO via async ops + promise.
// Error responses just land in the `status` field.
// ---------------------------------------------------------------------------

// Build the per-op envelope for the bind-contract wire (Step 3).
// Wire shape after the verb byte: [u32 preamble_len][salt+preamble][65 sig].
// Sig is over sha256(verb || salt || preamble || sessionToken).
static ces::Bytes buildSignedEnvelope(
    const ces::KeyPair& signer,
    uint8_t verb,
    const ces::Bytes& preamble,
    uint64_t sessionToken) {
  // Match CesPlexClient: prepend an 8-byte per-op salt so repeated ops
  // sign differently (a static counter gives uniqueness across calls).
  static uint64_t opSalt = 1;
  ces::Bytes signedPre;
  ces::Buffer::put<uint64_t>(signedPre, opSalt++);
  signedPre.insert(signedPre.end(), preamble.begin(), preamble.end());
  ces::Signature sig = ces::signPerOp(
    signer, verb,
    std::span<const uint8_t>(signedPre.data(), signedPre.size()),
    sessionToken);
  ces::Bytes wire;
  ces::Buffer::put<uint32_t>(wire, static_cast<uint32_t>(signedPre.size()));
  wire.insert(wire.end(), signedPre.begin(), signedPre.end());
  wire.insert(wire.end(), sig.begin(), sig.end());
  return wire;
}

// Response-envelope reader: reads preamble bytes (caller says how
// many), then 8+8+32+65 tail, returns {status, preamble}.
// `expectedPreambleLen` is the fixed number of bytes the verb's
// response preamble is known to consume AFTER the status byte. For
// variable-length responses (STAT has ct, READ has content stream),
// we handle those specially.
struct RespTail {
  uint8_t status = 0xFF;
  ces::Bytes preamble;
};

static RespTail readFixedResponse(
    boost::asio::io_context& ioc,
    std::shared_ptr<minx::RudpStream> stream,
    size_t preambleLen) {
  struct Run : std::enable_shared_from_this<Run> {
    std::shared_ptr<minx::RudpStream> stream;
    size_t preambleLen = 0;
    std::array<uint8_t, 1> statusBuf{};
    ces::Bytes preambleBuf;
    std::array<uint8_t, 8 + 8 + 32 + 65> tail{};
    std::promise<RespTail> prom;
    void run() {
      auto self = shared_from_this();
      boost::asio::async_read(
        *stream, boost::asio::buffer(statusBuf),
        [self](const boost::system::error_code& ec, std::size_t) {
          if (ec) { self->prom.set_value({}); return; }
          if (self->statusBuf[0] != CES_OK) {
            // Error response: preamble is empty, tail still present.
            boost::asio::async_read(
              *self->stream, boost::asio::buffer(self->tail),
              [self](const boost::system::error_code& e2, std::size_t) {
                RespTail r;
                r.status = self->statusBuf[0];
                if (e2) { /* leave empty */ }
                self->prom.set_value(std::move(r));
              });
            return;
          }
          self->preambleBuf.resize(self->preambleLen);
          auto readTail = [self]() {
            boost::asio::async_read(
              *self->stream, boost::asio::buffer(self->tail),
              [self](const boost::system::error_code& ec3, std::size_t) {
                RespTail r;
                r.status = self->statusBuf[0];
                if (ec3) { self->prom.set_value(std::move(r)); return; }
                r.preamble = std::move(self->preambleBuf);
                self->prom.set_value(std::move(r));
              });
          };
          if (self->preambleLen == 0) {
            readTail();
          } else {
            boost::asio::async_read(
              *self->stream, boost::asio::buffer(self->preambleBuf),
              [self, readTail](const boost::system::error_code& ec2,
                               std::size_t) {
                if (ec2) { self->prom.set_value({}); return; }
                readTail();
              });
          }
        });
    }
  };
  auto r = std::make_shared<Run>();
  r->stream = std::move(stream);
  r->preambleLen = preambleLen;
  auto fut = r->prom.get_future();
  boost::asio::post(ioc, [r]() { r->run(); });
  if (fut.wait_for(std::chrono::seconds(5)) != std::future_status::ready)
    return {};
  return fut.get();
}

// Drive a verb: write [verb][envelope], read the fixed response.
static RespTail driveVerb(
    boost::asio::io_context& ioc,
    std::shared_ptr<minx::RudpStream> stream,
    uint8_t verb,
    const ces::Bytes& envelope,
    size_t respPreambleLen,
    const ces::Bytes& extraBodyToSend = {}) {
  struct Run : std::enable_shared_from_this<Run> {
    std::shared_ptr<minx::RudpStream> stream;
    std::array<uint8_t, 1> verbBuf{};
    ces::Bytes env;
    ces::Bytes body;
    std::promise<void> done;
    void run() {
      auto self = shared_from_this();
      boost::asio::async_write(
        *stream, boost::asio::buffer(verbBuf),
        [self](const boost::system::error_code& ec, std::size_t) {
          if (ec) { self->done.set_value(); return; }
          boost::asio::async_write(
            *self->stream, boost::asio::buffer(self->env),
            [self](const boost::system::error_code& e2, std::size_t) {
              if (e2) { self->done.set_value(); return; }
              if (self->body.empty()) { self->done.set_value(); return; }
              boost::asio::async_write(
                *self->stream, boost::asio::buffer(self->body),
                [self](const boost::system::error_code&, std::size_t) {
                  self->done.set_value();
                });
            });
        });
    }
  };
  auto r = std::make_shared<Run>();
  r->stream = stream;
  r->verbBuf[0] = verb;
  r->env = envelope;
  r->body = extraBodyToSend;
  auto fut = r->done.get_future();
  boost::asio::post(ioc, [r]() { r->run(); });
  fut.wait();
  return readFixedResponse(ioc, stream, respPreambleLen);
}

// --- CREATE ---
static RespTail fileCreate(boost::asio::io_context& ioc,
                           std::shared_ptr<minx::RudpStream> stream,
                           const ces::KeyPair& signer,
                           uint64_t sessionToken,
                           uint32_t reqNonce,
                           uint64_t size, uint64_t pricePerKb,
                           uint64_t initialDeposit,
                           const std::string& name) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, reqNonce);
  ces::Buffer::put<uint64_t>(pre, size);
  ces::Buffer::put<uint64_t>(pre, pricePerKb);
  ces::Buffer::put<uint64_t>(pre, initialDeposit);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(signer, 0x01, pre, sessionToken);
  return driveVerb(ioc, stream, 0x01, env, /*respPreambleLen=*/16);
}

// --- WRITE ---
static RespTail ramfileWrite(boost::asio::io_context& ioc,
                          std::shared_ptr<minx::RudpStream> stream,
                          const ces::KeyPair& signer,
                          uint64_t sessionToken,
                          uint32_t reqNonce,
                          uint64_t offset,
                          const ces::Bytes& content,
                          const std::string& name) {
  minx::Hash contentHash = ces::sha256(content.data(), content.size());
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, reqNonce);
  ces::Buffer::put<uint64_t>(pre, offset);
  ces::Buffer::put<uint32_t>(pre, static_cast<uint32_t>(content.size()));
  pre.insert(pre.end(), contentHash.begin(), contentHash.end());
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(signer, 0x02, pre, sessionToken);
  return driveVerb(ioc, stream, 0x02, env,
                   /*respPreambleLen=*/8,
                   /*extraBodyToSend=*/content);
}

// --- READ ---
struct ReadResult {
  uint8_t status = 0xFF;
  uint64_t length = 0;
  std::array<uint8_t, 32> hash{};
  ces::Bytes bytes;
};

static ReadResult ramfileRead(boost::asio::io_context& ioc,
                           std::shared_ptr<minx::RudpStream> stream,
                           const ces::KeyPair& signer,
                           uint64_t sessionToken,
                           uint32_t reqNonce,
                           uint64_t offset, uint32_t length,
                           const std::string& name) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, reqNonce);
  ces::Buffer::put<uint64_t>(pre, offset);
  ces::Buffer::put<uint32_t>(pre, length);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(signer, 0x03, pre, sessionToken);

  // Write verb + env first.
  struct Run : std::enable_shared_from_this<Run> {
    std::shared_ptr<minx::RudpStream> stream;
    std::array<uint8_t, 1> verbBuf{0x03};
    ces::Bytes env;
    std::promise<void> done;
    void run() {
      auto self = shared_from_this();
      boost::asio::async_write(
        *stream, boost::asio::buffer(verbBuf),
        [self](const boost::system::error_code& ec, std::size_t) {
          if (ec) { self->done.set_value(); return; }
          boost::asio::async_write(
            *self->stream, boost::asio::buffer(self->env),
            [self](const boost::system::error_code&, std::size_t) {
              self->done.set_value();
            });
        });
    }
  };
  auto r = std::make_shared<Run>();
  r->stream = stream;
  r->env = env;
  auto fut = r->done.get_future();
  boost::asio::post(ioc, [r]() { r->run(); });
  fut.wait();

  // Read status + fixed preamble (length + hash) + tail.
  auto fixed = readFixedResponse(ioc, stream, 8 + 32);
  ReadResult out;
  out.status = fixed.status;
  if (out.status != CES_OK) return out;
  out.length = ces::Buffer::peek<uint64_t>(fixed.preamble.data());
  std::memcpy(out.hash.data(), fixed.preamble.data() + 8, 32);
  // Now stream the body.
  struct Body : std::enable_shared_from_this<Body> {
    std::shared_ptr<minx::RudpStream> stream;
    ces::Bytes buf;
    std::promise<void> done;
    void run() {
      if (buf.empty()) { done.set_value(); return; }
      auto self = shared_from_this();
      boost::asio::async_read(
        *stream, boost::asio::buffer(buf),
        [self](const boost::system::error_code&, std::size_t) {
          self->done.set_value();
        });
    }
  };
  auto b = std::make_shared<Body>();
  b->stream = stream;
  b->buf.resize(out.length);
  auto bf = b->done.get_future();
  boost::asio::post(ioc, [b]() { b->run(); });
  bf.wait();
  out.bytes = std::move(b->buf);
  return out;
}

// --- STAT (unsigned) ---
struct StatResult {
  uint8_t status = 0xFF;
  std::array<uint8_t, 32> ownerPubkey{};
  uint64_t fileBalance = 0;
  uint64_t pricePerKb = 0;
  uint64_t size = 0;
};

static StatResult fileStat(boost::asio::io_context& ioc,
                           std::shared_ptr<minx::RudpStream> stream,
                           const ces::KeyPair& signer,
                           uint64_t sessionToken,
                           const std::string& name) {
  // Step 3: STAT is signed like every other verb. Preamble is
  // [u32 reqNonce][u16 name_len][name].
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(signer, 0x04, pre, sessionToken);

  struct Run : std::enable_shared_from_this<Run> {
    std::shared_ptr<minx::RudpStream> stream;
    std::array<uint8_t, 1> verbBuf{0x04};
    ces::Bytes envBuf;
    std::promise<void> done;
    void run() {
      auto self = shared_from_this();
      boost::asio::async_write(
        *stream, boost::asio::buffer(verbBuf),
        [self](const boost::system::error_code& ec, std::size_t) {
          if (ec) { self->done.set_value(); return; }
          boost::asio::async_write(
            *self->stream, boost::asio::buffer(self->envBuf),
            [self](const boost::system::error_code&, std::size_t) {
              self->done.set_value();
            });
        });
    }
  };
  auto r = std::make_shared<Run>();
  r->stream = stream;
  r->envBuf = std::move(env);
  auto fut = r->done.get_future();
  boost::asio::post(ioc, [r]() { r->run(); });
  fut.wait();

  // STAT response:
  //   [u8 status][32 owner][u64 balance][u64 price][u64 size]
  //   [u64 created][u64 modified]
  //   [tail]
  // Fixed part of preamble = 32+8+8+8 = 56; timestamps follow.
  struct R2 : std::enable_shared_from_this<R2> {
    std::shared_ptr<minx::RudpStream> stream;
    std::array<uint8_t, 1> statusBuf{};
    std::array<uint8_t, 56> fixed{};
    std::array<uint8_t, 16> tsBuf{};
    std::array<uint8_t, 8 + 8 + 32 + 65> envTail{};
    std::promise<StatResult> prom;
    void run() {
      auto self = shared_from_this();
      boost::asio::async_read(
        *stream, boost::asio::buffer(statusBuf),
        [self](const boost::system::error_code& ec, std::size_t) {
          if (ec) { self->prom.set_value({}); return; }
          if (self->statusBuf[0] != CES_OK) {
            StatResult r; r.status = self->statusBuf[0];
            boost::asio::async_read(
              *self->stream, boost::asio::buffer(self->envTail),
              [self, r](const boost::system::error_code&, std::size_t) {
                self->prom.set_value(r);
              });
            return;
          }
          boost::asio::async_read(
            *self->stream, boost::asio::buffer(self->fixed),
            [self](const boost::system::error_code& e2, std::size_t) {
              if (e2) { self->prom.set_value({}); return; }
              boost::asio::async_read(
                *self->stream, boost::asio::buffer(self->tsBuf),
                [self](const boost::system::error_code& e3, std::size_t) {
                  if (e3) { self->prom.set_value({}); return; }
                  boost::asio::async_read(
                    *self->stream, boost::asio::buffer(self->envTail),
                    [self](const boost::system::error_code&, std::size_t) {
                      StatResult r;
                      r.status = CES_OK;
                      std::memcpy(r.ownerPubkey.data(),
                                  self->fixed.data(), 32);
                      r.fileBalance = ces::Buffer::peek<uint64_t>(self->fixed.data() + 32);
                      r.pricePerKb  = ces::Buffer::peek<uint64_t>(self->fixed.data() + 40);
                      r.size        = ces::Buffer::peek<uint64_t>(self->fixed.data() + 48);
                      self->prom.set_value(std::move(r));
                    });
                });
            });
        });
    }
  };
  auto r2 = std::make_shared<R2>();
  r2->stream = stream;
  auto f2 = r2->prom.get_future();
  boost::asio::post(ioc, [r2]() { r2->run(); });
  if (f2.wait_for(std::chrono::seconds(5)) != std::future_status::ready)
    return {};
  return f2.get();
}

// --- DEPOSIT / WITHDRAW / SET_PRICE / DELETE (all u64 + name) ---
static RespTail fileDeposit(boost::asio::io_context& ioc,
                            std::shared_ptr<minx::RudpStream> stream,
                            const ces::KeyPair& signer,
                            uint64_t sessionToken,
                            uint32_t reqNonce, uint64_t amount,
                            const std::string& name) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, reqNonce);
  ces::Buffer::put<uint64_t>(pre, amount);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(signer, 0x05, pre, sessionToken);
  return driveVerb(ioc, stream, 0x05, env, /*respPreambleLen=*/8);
}
static RespTail fileWithdraw(boost::asio::io_context& ioc,
                             std::shared_ptr<minx::RudpStream> stream,
                             const ces::KeyPair& signer,
                             uint64_t sessionToken,
                             uint32_t reqNonce, uint64_t amount,
                             const std::string& name) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, reqNonce);
  ces::Buffer::put<uint64_t>(pre, amount);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(signer, 0x06, pre, sessionToken);
  return driveVerb(ioc, stream, 0x06, env, /*respPreambleLen=*/8);
}
static RespTail fileSetPrice(boost::asio::io_context& ioc,
                             std::shared_ptr<minx::RudpStream> stream,
                             const ces::KeyPair& signer,
                             uint64_t sessionToken,
                             uint32_t reqNonce, uint64_t price,
                             const std::string& name) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, reqNonce);
  ces::Buffer::put<uint64_t>(pre, price);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(signer, 0x07, pre, sessionToken);
  return driveVerb(ioc, stream, 0x07, env, /*respPreambleLen=*/8);
}
static RespTail fileDelete(boost::asio::io_context& ioc,
                           std::shared_ptr<minx::RudpStream> stream,
                           const ces::KeyPair& signer,
                           uint64_t sessionToken,
                           uint32_t reqNonce,
                           const std::string& name) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, reqNonce);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(signer, 0x08, pre, sessionToken);
  return driveVerb(ioc, stream, 0x08, env, /*respPreambleLen=*/8);
}

// --- APPEND ---
// Response preamble: [u64 file_balance][u64 new_size].
static RespTail fileAppend(boost::asio::io_context& ioc,
                           std::shared_ptr<minx::RudpStream> stream,
                           const ces::KeyPair& signer,
                           uint64_t sessionToken,
                           uint32_t reqNonce,
                           const ces::Bytes& content,
                           const std::string& name) {
  minx::Hash contentHash = ces::sha256(content.data(), content.size());
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, reqNonce);
  ces::Buffer::put<uint32_t>(pre, static_cast<uint32_t>(content.size()));
  pre.insert(pre.end(), contentHash.begin(), contentHash.end());
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(signer, 0x09, pre, sessionToken);
  return driveVerb(ioc, stream, 0x09, env,
                   /*respPreambleLen=*/8 + 8,
                   /*extraBodyToSend=*/content);
}

// --- RESIZE ---
// Response preamble: [u64 new_size].
static RespTail ramfileResize(boost::asio::io_context& ioc,
                           std::shared_ptr<minx::RudpStream> stream,
                           const ces::KeyPair& signer,
                           uint64_t sessionToken,
                           uint32_t reqNonce,
                           uint64_t newSize,
                           const std::string& name) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, reqNonce);
  ces::Buffer::put<uint64_t>(pre, newSize);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(signer, 0x0a, pre, sessionToken);
  return driveVerb(ioc, stream, 0x0a, env,
                   /*respPreambleLen=*/8);
}

// Build the 4-part PUT envelope (verb+body_len+body+time+sender+sha+sig).
// Returns the bytes to send after the 0x01 verb.
struct PutEnvelope {
  ces::Bytes wire; // starts with u32 bodyLen
};

static PutEnvelope buildPutEnvelope(
    const ces::KeyPair& signer,
    uint32_t reqNonce, uint64_t allowance, uint32_t days,
    const std::string& name,
    const ces::Bytes& content) {
  // Body
  ces::Bytes body;
  ces::Buffer::put<uint32_t>(body, reqNonce);
  ces::Buffer::put<uint64_t>(body, allowance);
  ces::Buffer::put<uint32_t>(body, days);
  ces::Buffer::put<uint16_t>(body, static_cast<uint16_t>(name.size()));
  body.insert(body.end(), name.begin(), name.end());
  ces::Buffer::put<uint32_t>(body, static_cast<uint32_t>(content.size()));
  body.insert(body.end(), content.begin(), content.end());

  // time + sender
  uint64_t timeUs = static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count());
  const auto& pubKey = signer.getPublicKeyAsHash();

  // sha256 over body || time || sender
  ces::Buffer hashInput;
  hashInput.putBytes(std::span<const uint8_t>(body))
           .put<uint64_t>(timeUs)
           .putBytes(std::span<const uint8_t>(pubKey.data(), pubKey.size()));
  minx::Hash digest = ces::sha256(hashInput.data(), hashInput.size());

  // Sign the digest (verifier sees 32 bytes → no re-hash).
  ces::Signature sig = signer.signData(
    std::span<const uint8_t>(digest.data(), digest.size()));

  // Final wire layout.
  ces::Buffer wire(4 + body.size() + 8 + pubKey.size() + digest.size() + sig.size());
  wire.put<uint32_t>(static_cast<uint32_t>(body.size()))
      .putBytes(std::span<const uint8_t>(body))
      .put<uint64_t>(timeUs)
      .putBytes(std::span<const uint8_t>(pubKey.data(), pubKey.size()))
      .put(digest)
      .put(sig);

  return PutEnvelope{std::move(wire).take()};
}

// Drive a PUT on the given stream. Returns {status, costDebited}.
struct PutResult { uint8_t status = 0xFF; uint64_t cost = 0; };

static PutResult doPut(boost::asio::io_context& ioc,
                       std::shared_ptr<minx::RudpStream> stream,
                       const PutEnvelope& env) {
  struct Run : std::enable_shared_from_this<Run> {
    std::shared_ptr<minx::RudpStream> stream;
    std::array<uint8_t, 1> verb{0x01};
    ces::Bytes wire;
    std::array<uint8_t, 9> resp{};
    std::promise<PutResult> prom;
    void run() {
      auto self = shared_from_this();
      boost::asio::async_write(
        *stream, boost::asio::buffer(verb),
        [self](const boost::system::error_code& ec, std::size_t) {
          if (ec) { self->prom.set_value({0xFF, 0}); return; }
          boost::asio::async_write(
            *self->stream, boost::asio::buffer(self->wire),
            [self](const boost::system::error_code& e2, std::size_t) {
              if (e2) { self->prom.set_value({0xFF, 0}); return; }
              boost::asio::async_read(
                *self->stream, boost::asio::buffer(self->resp),
                [self](const boost::system::error_code& e3, std::size_t) {
                  if (e3) { self->prom.set_value({0xFF, 0}); return; }
                  PutResult r{self->resp[0],
                              ces::Buffer::peek<uint64_t>(self->resp.data() + 1)};
                  self->prom.set_value(r);
                });
            });
        });
    }
  };
  auto r = std::make_shared<Run>();
  r->stream = std::move(stream);
  r->wire = env.wire;
  auto fut = r->prom.get_future();
  boost::asio::post(ioc, [r]() { r->run(); });
  auto st = fut.wait_for(std::chrono::seconds(5));
  if (st != std::future_status::ready) return {0xFF, 0};
  return fut.get();
}

struct GetResult {
  uint8_t status = 0xFF;
  ces::Bytes bytes;
};

static GetResult doGet(boost::asio::io_context& ioc,
                       std::shared_ptr<minx::RudpStream> stream,
                       const std::string& name) {
  struct Run : std::enable_shared_from_this<Run> {
    std::shared_ptr<minx::RudpStream> stream;
    std::array<uint8_t, 1> verb{0x02};
    ces::Bytes nameBuf;
    std::array<uint8_t, 1> statusBuf{};
    std::array<uint8_t, 8> sizeBuf{};
    ces::Bytes body;
    std::promise<GetResult> prom;
    void run() {
      auto self = shared_from_this();
      boost::asio::async_write(
        *stream, boost::asio::buffer(verb),
        [self](const boost::system::error_code& ec, std::size_t) {
          if (ec) { self->prom.set_value({}); return; }
          boost::asio::async_write(
            *self->stream, boost::asio::buffer(self->nameBuf),
            [self](const boost::system::error_code& e2, std::size_t) {
              if (e2) { self->prom.set_value({}); return; }
              boost::asio::async_read(
                *self->stream, boost::asio::buffer(self->statusBuf),
                [self](const boost::system::error_code& e3, std::size_t) {
                  if (e3) { self->prom.set_value({}); return; }
                  if (self->statusBuf[0] != CES_OK) {
                    GetResult r; r.status = self->statusBuf[0];
                    self->prom.set_value(r);
                    return;
                  }
                  boost::asio::async_read(
                    *self->stream,
                    boost::asio::buffer(self->sizeBuf),
                    [self](const boost::system::error_code& e6,
                           std::size_t) {
                      if (e6) { self->prom.set_value({}); return; }
                      uint64_t sz = ces::Buffer::peek<uint64_t>(self->sizeBuf.data());
                      self->body.resize(sz);
                      auto done =
                        [self](const boost::system::error_code& e7,
                               std::size_t) {
                          if (e7) {
                            self->prom.set_value({}); return;
                          }
                          GetResult r;
                          r.status = CES_OK;
                          r.bytes = std::move(self->body);
                          self->prom.set_value(std::move(r));
                        };
                      if (sz == 0) done({}, 0);
                      else
                        boost::asio::async_read(
                          *self->stream,
                          boost::asio::buffer(self->body), done);
                    });
                });
            });
        });
    }
  };
  auto r = std::make_shared<Run>();
  r->stream = std::move(stream);
  ces::Buffer::put<uint16_t>(r->nameBuf, static_cast<uint16_t>(name.size()));
  r->nameBuf.insert(r->nameBuf.end(), name.begin(), name.end());
  auto fut = r->prom.get_future();
  boost::asio::post(ioc, [r]() { r->run(); });
  auto st = fut.wait_for(std::chrono::seconds(5));
  if (st != std::future_status::ready) return {};
  return fut.get();
}

} // namespace

BOOST_AUTO_TEST_CASE(FileCreateStatWithdraw) {
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);

  minx::Hash priv; priv.fill(0xA1);
  ces::KeyPair signer(priv);
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();

  auto sel = peer.select(fx.rpcPort, "/ces/file/1", signer);
  BOOST_REQUIRE_EQUAL(int(sel.status), 0x01);
  BOOST_REQUIRE(sel.stream != nullptr);

  const std::string name = "/p/docs/hello.txt";
  const uint64_t deposit = 1'000'000;
  const uint64_t size = 1024;
  // Upfront burn at CREATE: size × feeFileRent × 900s / 86400s.
  // fixture feeFileRent=1 → upfront = 1024 × 900 / 86400 = 10.
  const uint64_t upfrontBurn = size * 1ull * 900 / 86400;
  const uint64_t postCreateBalance = deposit - upfrontBurn;
  auto c = fileCreate(peer.taskIO(), sel.stream, signer, sel.sessionToken, CES_NONCELESS,
                      size, /*pricePerKb=*/10, deposit,
                      name);
  CES_CHECK_RC_EQ(c.status, CES_OK);

  auto st = fileStat(peer.taskIO(), sel.stream, signer, sel.sessionToken, name);
  CES_CHECK_RC_EQ(st.status, CES_OK);
  BOOST_CHECK_EQUAL(st.fileBalance, postCreateBalance);
  BOOST_CHECK_EQUAL(st.pricePerKb, 10u);
  BOOST_CHECK_EQUAL(st.size, 1024u);
  BOOST_CHECK(std::memcmp(st.ownerPubkey.data(),
                          signer.getPublicKeyAsHash().data(), 32) == 0);

  auto w = fileWithdraw(peer.taskIO(), sel.stream, signer, sel.sessionToken, CES_NONCELESS,
                        postCreateBalance, name);
  CES_CHECK_RC_EQ(w.status, CES_OK);
  BOOST_REQUIRE_EQUAL(w.preamble.size(), 8u);
  BOOST_CHECK_EQUAL(ces::Buffer::peek<uint64_t>(w.preamble.data()), 0u); // balance drained

  auto st2 = fileStat(peer.taskIO(), sel.stream, signer, sel.sessionToken, name);
  CES_CHECK_RC_EQ(st2.status, CES_OK);
  BOOST_CHECK_EQUAL(st2.fileBalance, 0u);
}

// A resent identical L2 file envelope must be deduplicated so its side effect
// runs exactly once. If _l2ValidateDedupAndDebit returns CES_OK on a duplicate
// without debiting while the verb handler still runs its credit, a resent
// DEPOSIT credits the program account with no signer debit (conservation break).
BOOST_AUTO_TEST_CASE(FileDepositResendIsIdempotent) {
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);

  minx::Hash priv; priv.fill(0xD1);
  ces::KeyPair signer(priv);
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();

  auto sel = peer.select(fx.rpcPort, "/ces/file/1", signer);
  BOOST_REQUIRE_EQUAL(int(sel.status), 0x01);
  BOOST_REQUIRE(sel.stream != nullptr);

  const std::string name = "/p/dedup/deposit.txt";
  const uint64_t size = 1024;
  const uint64_t createDeposit = 1'000'000;
  const uint64_t upfrontBurn = size * 1ull * 900 / 86400;  // fixture feeFileRent=1
  auto c = fileCreate(peer.taskIO(), sel.stream, signer, sel.sessionToken,
                      CES_NONCELESS, size, /*pricePerKb=*/0, createDeposit,
                      name);
  CES_REQUIRE_RC_EQ(c.status, CES_OK);
  const uint64_t postCreate = createDeposit - upfrontBurn;

  // Build ONE deposit envelope and drive it TWICE — identical bytes ⇒ identical
  // per-op salt ⇒ identical sigHash ⇒ the second send is a dedup duplicate.
  const uint64_t amount = 500'000;
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint64_t>(pre, amount);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(signer, 0x05, pre, sel.sessionToken);

  auto d1 = driveVerb(peer.taskIO(), sel.stream, 0x05, env, /*respPreambleLen=*/8);
  CES_REQUIRE_RC_EQ(d1.status, CES_OK);
  BOOST_CHECK_EQUAL(ces::Buffer::peek<uint64_t>(d1.preamble.data()),
                    postCreate + amount);

  // Resend the SAME envelope. The dup must reply OK but NOT re-credit.
  auto d2 = driveVerb(peer.taskIO(), sel.stream, 0x05, env, /*respPreambleLen=*/8);
  CES_REQUIRE_RC_EQ(d2.status, CES_OK);
  // Without dedup the resend would re-credit: postCreate + 2*amount.
  BOOST_CHECK_EQUAL(ces::Buffer::peek<uint64_t>(d2.preamble.data()),
                    postCreate + amount);

  // Cross-check via STAT: a single deposit applied.
  auto st = fileStat(peer.taskIO(), sel.stream, signer, sel.sessionToken, name);
  CES_REQUIRE_RC_EQ(st.status, CES_OK);
  BOOST_CHECK_EQUAL(st.fileBalance, postCreate + amount);
}

BOOST_AUTO_TEST_CASE(FileWriteRead) {
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);

  minx::Hash priv; priv.fill(0xA1);
  ces::KeyPair signer(priv);
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();

  auto sel = peer.select(fx.rpcPort, "/ces/file/1", signer);
  BOOST_REQUIRE_EQUAL(int(sel.status), 0x01);

  const std::string name = "/p/notes/alpha.txt";
  // Deposit must cover write_cost = 64 * feeFileWrite. With default
  // fees ~18.3K per byte, 64 bytes = ~1.2M credits. Use 10M headroom.
  auto c = fileCreate(peer.taskIO(), sel.stream, signer, sel.sessionToken, CES_NONCELESS,
                      /*size=*/64, /*pricePerKb=*/0,
                      /*initialDeposit=*/10'000'000,
                      name);
  CES_REQUIRE_RC_EQ(c.status, CES_OK);

  ces::Bytes content(64, 0);
  const std::string msg = "hello from the v2 write path";
  std::memcpy(content.data(), msg.data(), msg.size());

  auto w = ramfileWrite(peer.taskIO(), sel.stream, signer, sel.sessionToken, CES_NONCELESS,
                     /*offset=*/0, content, name);
  CES_REQUIRE_RC_EQ(w.status, CES_OK);

  auto r = ramfileRead(peer.taskIO(), sel.stream, signer, sel.sessionToken, CES_NONCELESS,
                    /*offset=*/0, /*length=*/64, name);
  CES_REQUIRE_RC_EQ(r.status, CES_OK);
  BOOST_CHECK_EQUAL(r.length, 64u);
  BOOST_CHECK_EQUAL_COLLECTIONS(r.bytes.begin(), r.bytes.end(),
                                content.begin(), content.end());
}

BOOST_AUTO_TEST_CASE(FileCrossSignerEconomics) {
  // A creates a file, B deposits, B reads (pays A), A withdraws the
  // accumulated balance. End-to-end credit conservation.
  // Step 3: each peer binds to one signer, so we use two peers.
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });
  PlexTestPeer peerA, peerB;
  BOOST_REQUIRE(peerA.start() != 0);
  BOOST_REQUIRE(peerB.start() != 0);

  minx::Hash privA; privA.fill(0xA2);
  minx::Hash privB; privB.fill(0xB2);
  ces::KeyPair a(privA), b(privB);
  fx.server->_brr(a.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_brr(b.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();

  auto selA = peerA.select(fx.rpcPort, "/ces/file/1", a);
  BOOST_REQUIRE_EQUAL(int(selA.status), 0x01);
  auto selB = peerB.select(fx.rpcPort, "/ces/file/1", b);
  BOOST_REQUIRE_EQUAL(int(selB.status), 0x01);

  const std::string name = "/p/market/thing";
  const uint64_t pricePerKb = 100'000;
  const uint64_t size = 1024;
  const uint64_t upfrontBurn = size * 1ull * 900 / 86400;
  auto c = fileCreate(peerA.taskIO(), selA.stream, a, selA.sessionToken,
                      CES_NONCELESS, size, pricePerKb,
                      /*initialDeposit=*/500'000,
                      name);
  CES_REQUIRE_RC_EQ(c.status, CES_OK);
  uint64_t expectedBalance = 500'000u - upfrontBurn;

  // B deposits 1M — file_balance should bump.
  auto d = fileDeposit(peerB.taskIO(), selB.stream, b, selB.sessionToken,
                       CES_NONCELESS, 1'000'000, name);
  CES_REQUIRE_RC_EQ(d.status, CES_OK);
  expectedBalance += 1'000'000u;
  BOOST_CHECK_EQUAL(ces::Buffer::peek<uint64_t>(d.preamble.data()), expectedBalance);

  // B reads 1024 bytes — pays pricePerKb to the file.
  auto r = ramfileRead(peerB.taskIO(), selB.stream, b, selB.sessionToken,
                    CES_NONCELESS, /*offset=*/0, /*length=*/1024, name);
  CES_REQUIRE_RC_EQ(r.status, CES_OK);
  expectedBalance += pricePerKb;

  // STAT (on B's channel — anyone can stat).
  auto s = fileStat(peerB.taskIO(), selB.stream, b, selB.sessionToken,
                    name);
  CES_REQUIRE_RC_EQ(s.status, CES_OK);
  BOOST_CHECK_EQUAL(s.fileBalance, expectedBalance);

  // A withdraws the full file_balance → bumps A's account.
  auto w = fileWithdraw(peerA.taskIO(), selA.stream, a, selA.sessionToken,
                        CES_NONCELESS, s.fileBalance, name);
  CES_REQUIRE_RC_EQ(w.status, CES_OK);
  BOOST_CHECK_EQUAL(ces::Buffer::peek<uint64_t>(w.preamble.data()), 0u);
}

BOOST_AUTO_TEST_CASE(FileNonOwnerWriteRejected) {
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });
  PlexTestPeer peerA, peerB;
  BOOST_REQUIRE(peerA.start() != 0);
  BOOST_REQUIRE(peerB.start() != 0);

  minx::Hash privA; privA.fill(0xA3);
  minx::Hash privB; privB.fill(0xB3);
  ces::KeyPair a(privA), b(privB);
  fx.server->_brr(a.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_brr(b.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();

  auto selA = peerA.select(fx.rpcPort, "/ces/file/1", a);
  BOOST_REQUIRE_EQUAL(int(selA.status), 0x01);
  auto selB = peerB.select(fx.rpcPort, "/ces/file/1", b);
  BOOST_REQUIRE_EQUAL(int(selB.status), 0x01);

  const std::string name = "/p/mine/only.txt";
  auto c = fileCreate(peerA.taskIO(), selA.stream, a, selA.sessionToken,
                      CES_NONCELESS, /*size=*/16, /*pricePerKb=*/0,
                      /*initialDeposit=*/10'000'000,
                      name);
  CES_REQUIRE_RC_EQ(c.status, CES_OK);

  // B (different bound channel) tries to write — server rejects with
  // NOT_OWNER because the channel's bound pubkey doesn't match the
  // file's owner.
  ces::Bytes content(16, 'B');
  auto w = ramfileWrite(peerB.taskIO(), selB.stream, b, selB.sessionToken,
                     CES_NONCELESS, /*offset=*/0, content, name);
  CES_CHECK_RC_EQ(w.status, CES_ERROR_NOT_OWNER);
}

BOOST_AUTO_TEST_CASE(FileAppendExtendsSize) {
  // CREATE size 16, APPEND 16 more, verify size=32 + read back both
  // halves with distinct bytes.
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);

  minx::Hash priv; priv.fill(0xA5);
  ces::KeyPair signer(priv);
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();

  auto sel = peer.select(fx.rpcPort, "/ces/file/1", signer);
  BOOST_REQUIRE_EQUAL(int(sel.status), 0x01);

  const std::string name = "/p/grow/growing.bin";
  auto c = fileCreate(peer.taskIO(), sel.stream, signer, sel.sessionToken, CES_NONCELESS,
                      /*size=*/16, /*pricePerKb=*/0,
                      /*initialDeposit=*/10'000'000,
                      name);
  CES_REQUIRE_RC_EQ(c.status, CES_OK);

  // WRITE 'A's into the first 16 bytes.
  ces::Bytes first(16, 'A');
  auto w = ramfileWrite(peer.taskIO(), sel.stream, signer, sel.sessionToken, CES_NONCELESS,
                     /*offset=*/0, first, name);
  CES_REQUIRE_RC_EQ(w.status, CES_OK);

  // APPEND 16 'B's.
  ces::Bytes second(16, 'B');
  auto a = fileAppend(peer.taskIO(), sel.stream, signer, sel.sessionToken, CES_NONCELESS,
                      second, name);
  CES_REQUIRE_RC_EQ(a.status, CES_OK);
  BOOST_REQUIRE_EQUAL(a.preamble.size(), 8u + 8u);
  uint64_t respSize = ces::Buffer::peek<uint64_t>(a.preamble.data() + 8);
  BOOST_CHECK_EQUAL(respSize, 32u);

  // READ the full 32 bytes, verify layout.
  auto r = ramfileRead(peer.taskIO(), sel.stream, signer, sel.sessionToken, CES_NONCELESS,
                    /*offset=*/0, /*length=*/32, name);
  CES_REQUIRE_RC_EQ(r.status, CES_OK);
  BOOST_CHECK_EQUAL(r.length, 32u);
  for (size_t i = 0; i < 16; ++i) BOOST_CHECK_EQUAL(r.bytes[i], 'A');
  for (size_t i = 16; i < 32; ++i) BOOST_CHECK_EQUAL(r.bytes[i], 'B');
}

BOOST_AUTO_TEST_CASE(FileResizeGrowAndShrink) {
  // CREATE size 100, RESIZE to 200 (grow sparse), RESIZE to 50
  // (shrink truncates). STAT confirms each size transition.
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);

  minx::Hash priv; priv.fill(0xA6);
  ces::KeyPair signer(priv);
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();

  auto sel = peer.select(fx.rpcPort, "/ces/file/1", signer);
  BOOST_REQUIRE_EQUAL(int(sel.status), 0x01);

  const std::string name = "/p/flex/flex.bin";
  auto c = fileCreate(peer.taskIO(), sel.stream, signer, sel.sessionToken, CES_NONCELESS,
                      /*size=*/100, /*pricePerKb=*/0,
                      /*initialDeposit=*/10'000'000,
                      name);
  CES_REQUIRE_RC_EQ(c.status, CES_OK);

  // Grow to 200.
  auto g = ramfileResize(peer.taskIO(), sel.stream, signer, sel.sessionToken, CES_NONCELESS,
                      200, name);
  CES_REQUIRE_RC_EQ(g.status, CES_OK);
  BOOST_REQUIRE_EQUAL(g.preamble.size(), 8u);
  BOOST_CHECK_EQUAL(ces::Buffer::peek<uint64_t>(g.preamble.data()), 200u);

  auto s1 = fileStat(peer.taskIO(), sel.stream, signer, sel.sessionToken, name);
  CES_REQUIRE_RC_EQ(s1.status, CES_OK);
  BOOST_CHECK_EQUAL(s1.size, 200u);

  // Shrink to 50.
  auto h = ramfileResize(peer.taskIO(), sel.stream, signer, sel.sessionToken, CES_NONCELESS,
                      50, name);
  CES_REQUIRE_RC_EQ(h.status, CES_OK);
  BOOST_CHECK_EQUAL(ces::Buffer::peek<uint64_t>(h.preamble.data()), 50u);

  auto s2 = fileStat(peer.taskIO(), sel.stream, signer, sel.sessionToken, name);
  CES_REQUIRE_RC_EQ(s2.status, CES_OK);
  BOOST_CHECK_EQUAL(s2.size, 50u);
}

BOOST_AUTO_TEST_CASE(FileRentKillsBrokeFile) {
  // With upfront rent enforcement, CREATE requires deposit ≥ 15 min
  // of rent on the reserved bytes. To exercise the lazy rent kill
  // path we CREATE at minimum upfront, immediately WITHDRAW down to
  // a tiny balance, then wait long enough for the accrued rent to
  // eat what's left. The next STAT triggers rent collection and
  // the file dies.
  //
  // size = 1 MB, feeFileRent = 1 (fixture default).
  //   upfront(15 min) = 1 MB × 1 × 900 / 86400 = 10922 credits
  //   — BURNED at CREATE, so deposit=10924 leaves balance=2.
  //   rent per 300 ms ≈ 3 credits → file dies.
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);

  minx::Hash priv; priv.fill(0xA4);
  ces::KeyPair signer(priv);
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();

  auto sel = peer.select(fx.rpcPort, "/ces/file/1", signer);
  BOOST_REQUIRE_EQUAL(int(sel.status), 0x01);

  const std::string name = "/p/dying/breath.txt";
  auto c = fileCreate(peer.taskIO(), sel.stream, signer, sel.sessionToken, CES_NONCELESS,
                      /*size=*/1024 * 1024, /*pricePerKb=*/0,
                      /*initialDeposit=*/10924,
                      name);
  CES_REQUIRE_RC_EQ(c.status, CES_OK);

  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  auto s = fileStat(peer.taskIO(), sel.stream, signer, sel.sessionToken, name);
  CES_CHECK_RC_EQ(s.status, CES_ERROR_FILE_NOT_FOUND);
}

BOOST_AUTO_TEST_CASE(FileCreateRejectsUnderfundedDeposit) {
  // Anti-grief gate. CREATE must require initial_deposit ≥ 15 min of
  // rent on the reserved bytes, else INSUFFICIENT_BALANCE. Without
  // this, someone could CREATE a huge file with a trivial deposit
  // and vanish before the GC debounce window closes.
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);

  minx::Hash priv; priv.fill(0xA7);
  ces::KeyPair signer(priv);
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();

  auto sel = peer.select(fx.rpcPort, "/ces/file/1", signer);
  BOOST_REQUIRE_EQUAL(int(sel.status), 0x01);

  const std::string name = "/p/cheap/grief.bin";
  // 1 MB requires ~10922 upfront; deposit 1 is laughable.
  auto c = fileCreate(peer.taskIO(), sel.stream, signer, sel.sessionToken, CES_NONCELESS,
                      /*size=*/1024 * 1024, /*pricePerKb=*/0,
                      /*initialDeposit=*/1,
                      name);
  CES_CHECK_RC_EQ(c.status, CES_ERROR_INSUFFICIENT_BALANCE);
}

// ---------------------------------------------------------------------------
// Zone ownership (/h/, /f/, /p/)
// ---------------------------------------------------------------------------

// Render a 32-byte pubkey as 64 lowercase hex chars for use in
// /h/<hex>/... paths.
static std::string pubkeyHex64(const minx::Hash& pk) {
  static const char kHex[] = "0123456789abcdef";
  std::string out(64, '\0');
  for (size_t i = 0; i < 32; ++i) {
    out[i * 2]     = kHex[pk[i] >> 4];
    out[i * 2 + 1] = kHex[pk[i] & 0xF];
  }
  return out;
}

BOOST_AUTO_TEST_CASE(FileHomeDirSelfOwnedAllowed) {
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);

  minx::Hash priv; priv.fill(0xC1);
  ces::KeyPair signer(priv);
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();

  auto sel = peer.select(fx.rpcPort, "/ces/file/1", signer);
  BOOST_REQUIRE_EQUAL(int(sel.status), 0x01);

  // Signer writes under their own /h/<hex-of-their-pubkey>/... path.
  const std::string name =
    "/h/" + pubkeyHex64(signer.getPublicKeyAsHash()) + "/mydoc.txt";
  auto c = fileCreate(peer.taskIO(), sel.stream, signer, sel.sessionToken, CES_NONCELESS,
                      /*size=*/16, /*pricePerKb=*/0,
                      /*initialDeposit=*/1'000'000,
                      name);
  CES_CHECK_RC_EQ(c.status, CES_OK);
}

BOOST_AUTO_TEST_CASE(FileHomeDirWrongSignerRejected) {
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);

  minx::Hash privA; privA.fill(0xC2);
  minx::Hash privB; privB.fill(0xC3);
  ces::KeyPair alice(privA);
  ces::KeyPair bob(privB);
  fx.server->_brr(alice.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_brr(bob.getPublicKeyAsHash(),   10'000'000'000);
  fx.server->_drainLogic();

  // Bind the channel to Bob (the trespasser) — server will reject
  // his create under Alice's home dir.
  auto sel = peer.select(fx.rpcPort, "/ces/file/1", bob);
  BOOST_REQUIRE_EQUAL(int(sel.status), 0x01);

  const std::string name =
    "/h/" + pubkeyHex64(alice.getPublicKeyAsHash()) + "/trespass.txt";
  auto c = fileCreate(peer.taskIO(), sel.stream, bob, sel.sessionToken, CES_NONCELESS,
                      /*size=*/16, /*pricePerKb=*/0,
                      /*initialDeposit=*/1'000'000,
                      name);
  CES_CHECK_RC_EQ(c.status, CES_ERROR_NOT_OWNER);
}

BOOST_AUTO_TEST_CASE(FileNamespaceRequiresAsset) {
  // /f/myns/... CREATEs fail when the namespace asset doesn't exist.
  // (We don't exercise the positive case here because the test
  // harness doesn't go through the CES_CREATE_ASSET wire — that's a
  // separate opcode on the main port. The negative path is the
  // security-relevant one; positive /f/ usage is exercised by
  // integration tests elsewhere once cesh learns the verbs.)
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);

  minx::Hash priv; priv.fill(0xC4);
  ces::KeyPair signer(priv);
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();

  auto sel = peer.select(fx.rpcPort, "/ces/file/1", signer);
  BOOST_REQUIRE_EQUAL(int(sel.status), 0x01);

  const std::string name = "/f/unregistered/file.txt";
  auto c = fileCreate(peer.taskIO(), sel.stream, signer, sel.sessionToken, CES_NONCELESS,
                      /*size=*/16, /*pricePerKb=*/0,
                      /*initialDeposit=*/1'000'000,
                      name);
  CES_CHECK_RC_EQ(c.status, CES_ERROR_NOT_OWNER);
}

BOOST_AUTO_TEST_CASE(FileBadZoneRejected) {
  // Paths not under /h/, /f/, or /p/ are rejected at name validation.
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);

  minx::Hash priv; priv.fill(0xC5);
  ces::KeyPair signer(priv);
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();

  auto sel = peer.select(fx.rpcPort, "/ces/file/1", signer);
  BOOST_REQUIRE_EQUAL(int(sel.status), 0x01);

  const std::string name = "/docs/nope.txt";  // missing zone prefix
  auto c = fileCreate(peer.taskIO(), sel.stream, signer, sel.sessionToken, CES_NONCELESS,
                      /*size=*/16, /*pricePerKb=*/0,
                      /*initialDeposit=*/1'000'000,
                      name);
  CES_CHECK_RC_EQ(c.status, CES_ERROR_BAD_NAME);
}

// Regression: writeSidecar used to hand-roll `key = "val"` TOML, which
// corrupted the sidecar when name held quotes or newlines
// (validateCesFileName permits everything except '/' and NUL). It now
// serializes via tomlplusplus, so these round-trip through STAT's re-read.
BOOST_AUTO_TEST_CASE(FileSidecarSurvivesQuotesAndNewlines) {
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);

  minx::Hash priv; priv.fill(0x5C);
  ces::KeyPair signer(priv);
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();

  auto sel = peer.select(fx.rpcPort, "/ces/file/1", signer);
  BOOST_REQUIRE_EQUAL(int(sel.status), 0x01);

  const std::string name = "/p/has\"quote/f.txt";
  auto c = fileCreate(peer.taskIO(), sel.stream, signer, sel.sessionToken,
                      CES_NONCELESS, /*size=*/16, /*pricePerKb=*/0,
                      /*initialDeposit=*/1'000'000, name);
  CES_CHECK_RC_EQ(c.status, CES_OK);

  auto st = fileStat(peer.taskIO(), sel.stream, signer, sel.sessionToken, name);
  CES_CHECK_RC_EQ(st.status, CES_OK);
  BOOST_CHECK_EQUAL(st.size, 16u);
}

// validateCesFileName is the path-traversal / junk gate that runs before
// any disk path is built. Every one of these must be rejected.
BOOST_AUTO_TEST_CASE(FileNameValidationRejectsBadPaths) {
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);

  minx::Hash priv; priv.fill(0xD7);
  ces::KeyPair signer(priv);
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();

  auto sel = peer.select(fx.rpcPort, "/ces/file/1", signer);
  BOOST_REQUIRE_EQUAL(int(sel.status), 0x01);

  std::string nullComp = "/p/a";
  nullComp.push_back('\0');
  nullComp += "b/x";              // embedded NUL inside a component

  const std::vector<std::string> bad = {
    "/p/../etc/passwd",           // parent traversal
    "/p/./here",                  // dot component
    "/p/.hidden/x",               // dotfile component
    "/p//x",                      // empty component
    "/p/x/",                      // trailing slash
    "/x/y",                       // unknown zone
    "/p",                         // no second component
    "/",                          // just root
    "/h/tooshort/x",              // /h/ second is not 64 hex
    "/p/secret.sidecar.toml",     // reserved sidecar suffix — would alias a sidecar
    "/p/d/inner.sidecar.toml",    // reserved suffix in a nested component
    nullComp,                     // NUL byte in a component
  };

  for (const auto& name : bad) {
    auto c = fileCreate(peer.taskIO(), sel.stream, signer, sel.sessionToken,
                        CES_NONCELESS, /*size=*/16, /*pricePerKb=*/0,
                        /*initialDeposit=*/1'000'000, name);
    BOOST_CHECK_MESSAGE(c.status == CES_ERROR_BAD_NAME,
                        "expected BAD_NAME for '" << name << "' got "
                        << int(c.status));
  }
}

BOOST_AUTO_TEST_SUITE_END()
