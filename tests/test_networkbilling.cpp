// ===========================================================================
// NetworkBilling tests
// ===========================================================================
//
// NetworkBilling exercises track() / snapshot() / a tick that walks
// channels and computes deltas. Verifies the bookkeeping layer end-
// to-end against the live CesPlex echo handler, the in-memory
// eviction-on-tick semantics, and rate-driven debiting +
// eviction-on-insufficient-funds (in its own test below).

#define BOOST_TEST_DYN_LINK
#include "test_common.h"

#include <ces/l2/net_multiplexer.h>
#include <ces/buffer.h>
#include <ces/l2/net_billing.h>
#include <ces/l2/net_envelope.h>
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
#include <chrono>
#include <cstring>
#include <future>
#include <memory>
#include <thread>
#include <vector>

namespace {

uint64_t nbNowMicros() {
  return static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count());
}

class NoopMinxListener : public minx::MinxListener {};

// Outbound-only Rudp::Listener — copies the pattern from
// test_cesplex.cpp's PlexTestPeer.
class NbPeerRudpListener : public minx::Rudp::Listener {
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

// Minimal in-process MINX+Rudp client to drive a channel into a CES
// server. Modeled on PlexTestPeer; trimmed to what these tests need.
class NbTestPeer {
public:
  NbTestPeer() = default;
  ~NbTestPeer() { stop(); }

  uint16_t start() {
    minx_ = std::make_unique<minx::Minx>(
      &listener_, minx::MinxConfig{
        .instanceName = "nbpeer",
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
          if (rudp_) rudp_->onPacket(peer, key, payload, nbNowMicros());
        });
      minx_->setExtensionHandler(std::move(stdExt).build());
    }
    port_ = minx_->openSocket(
      boost::asio::ip::address_v6::loopback(), 0, netIO_, taskIO_);
    if (port_ == 0) return 0;
    netGuard_ = std::make_unique<
      boost::asio::executor_work_guard<
        boost::asio::io_context::executor_type>>(netIO_.get_executor());
    taskGuard_ = std::make_unique<
      boost::asio::executor_work_guard<
        boost::asio::io_context::executor_type>>(taskIO_.get_executor());
    netThread_ = std::thread([this]() { netIO_.run(); });
    taskThread_ = std::thread([this]() { taskIO_.run(); });
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

  // Open a channel and run the signed CesPlex bind handshake.
  // Returns the stream on OK, nullptr otherwise. `signer` is the
  // channel principal — billed as the payer, owns per-op sigs.
  std::shared_ptr<minx::RudpStream>
  selectAndOpen(uint16_t targetPort, const std::string& protoName,
                const ces::KeyPair& signer,
                std::chrono::milliseconds timeout =
                  std::chrono::milliseconds(3000)) {
    currentPeer_ = minx::SockAddr(
      boost::asio::ip::address_v6::loopback(), targetPort);
    currentChannel_ = 1;
    auto done = std::make_shared<std::atomic<bool>>(false);
    auto status = std::make_shared<uint8_t>(0xFF);
    auto mu = std::make_shared<std::mutex>();
    auto cv = std::make_shared<std::condition_variable>();
    boost::asio::post(taskIO_,
      [this, protoName, &signer, done, status, mu, cv]() {
      rudp_->tick(nbNowMicros());
      stream_ = std::make_shared<minx::RudpStream>(
        taskIO_.get_executor());
      if (!rudp_->registerChannel(
            currentPeer_, currentChannel_, stream_)) {
        std::lock_guard<std::mutex> lk(*mu);
        done->store(true); cv->notify_all();
        return;
      }
      const uint64_t bindNowUs = nbNowMicros();
      auto bindReq = std::make_shared<minx::Bytes>(
        ces::buildBindRequest(protoName, bindNowUs, signer));
      boost::asio::async_write(
        *stream_, boost::asio::buffer(*bindReq),
        [this, bindReq, done, status, mu, cv]
        (const boost::system::error_code& ec, std::size_t) {
          if (ec) {
            std::lock_guard<std::mutex> lk(*mu);
            done->store(true); cv->notify_all();
            return;
          }
          auto reply = std::make_shared<
            std::array<uint8_t, ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE>>();
          boost::asio::async_read(
            *stream_, boost::asio::buffer(*reply),
            [reply, done, status, mu, cv]
            (const boost::system::error_code& ec2, std::size_t) {
              if (!ec2) *status = (*reply)[0];
              std::lock_guard<std::mutex> lk(*mu);
              done->store(true); cv->notify_all();
            });
        });
    });
    std::unique_lock<std::mutex> lk(*mu);
    cv->wait_for(lk, timeout, [&]() { return done->load(); });
    if (*status == 0x01) return stream_;
    return nullptr;
  }

  // Echo round-trip: write [u64 len][body], read [u64 len][body] back.
  std::string echo(std::shared_ptr<minx::RudpStream> stream,
                   const std::string& msg,
                   std::chrono::milliseconds timeout =
                     std::chrono::milliseconds(3000)) {
    struct State : std::enable_shared_from_this<State> {
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
          [self](const boost::system::error_code& e1, std::size_t) {
            if (e1) { self->prom.set_value({}); return; }
            boost::asio::async_write(
              *self->stream, boost::asio::buffer(self->msg),
              [self](const boost::system::error_code& e2, std::size_t) {
                if (e2) { self->prom.set_value({}); return; }
                boost::asio::async_read(
                  *self->stream, boost::asio::buffer(self->rxLen),
                  [self](const boost::system::error_code& e3, std::size_t) {
                    if (e3) { self->prom.set_value({}); return; }
                    uint64_t rn = ces::Buffer::peek<uint64_t>(self->rxLen.data());
                    self->rxBody.resize(rn);
                    boost::asio::async_read(
                      *self->stream, boost::asio::buffer(self->rxBody),
                      [self](const boost::system::error_code& e4,
                             std::size_t) {
                        if (e4) { self->prom.set_value({}); return; }
                        self->prom.set_value(
                          std::string(self->rxBody.begin(),
                                      self->rxBody.end()));
                      });
                  });
              });
          });
      }
    };
    auto st = std::make_shared<State>();
    st->stream = stream;
    st->msg = msg;
    auto fut = st->prom.get_future();
    boost::asio::post(taskIO_, [st]() { st->run(); });
    if (fut.wait_for(timeout) != std::future_status::ready) return {};
    return fut.get();
  }

  void closeStream() {
    auto strm = stream_;
    if (!strm) return;
    boost::asio::post(taskIO_, [strm]() { strm->close(); });
  }

private:
  void scheduleTick() {
    if (!tickTimer_ || !rudp_) return;
    tickTimer_->expires_after(std::chrono::milliseconds(20));
    tickTimer_->async_wait(
      [this](const boost::system::error_code& ec) {
        if (ec || !rudp_) return;
        rudp_->tick(nbNowMicros());
        scheduleTick();
      });
  }

  NoopMinxListener listener_;
  NbPeerRudpListener rudpListener_;
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
  minx::SockAddr currentPeer_;
  uint32_t currentChannel_ = 0;
  std::shared_ptr<minx::RudpStream> stream_;
};

// Fixture: CesServer on an ephemeral rpc port with the echo handler
// mounted. Re-uses CesPlexFixture's pattern. fs::path is the boost
// alias inherited from test_common.h.

uint16_t pickEphemeralRpcPort_nb() {
  static std::atomic<uint16_t> nextPort{45000};
  return nextPort.fetch_add(1);
}

struct NetBillFixture {
  std::unique_ptr<ces::CesServer> server;
  fs::path tempDir;
  uint16_t rpcPort = 0;
  ces::KeyPair testKey;  // signed-bind principal for these tests

  NetBillFixture() {
    blog::init();
    blog::set_level(blog::info);
    blog::set_level("netbill", blog::debug);

    tempDir = makeUniqueTempDir("netbill_test");

    minx::Hash serverPriv;
    serverPriv.fill(0xC4);

    ces::CesConfig cfg = makeTestConfig(
      tempDir, serverPriv, std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = pickEphemeralRpcPort_nb();
    cfg.cesplexMounts = { {"/ces/test/echo/1", "builtin:echo"} };
    cfg.cesFileStoreMaxBytes = 1ull * 1024 * 1024 * 1024;
    cfg.feeFileRent = 1;

    server = std::make_unique<ces::CesServer>(cfg);
    server->start();
    rpcPort = server->_rpcBoundPort();
    BOOST_REQUIRE_MESSAGE(rpcPort != 0,
      "CesServer failed to bind secondary port");
    BOOST_REQUIRE_MESSAGE(server->_netBilling() != nullptr,
      "NetworkBilling not constructed");

    // Fund the bind signer so feeQuery isn't blocked by zero balance
    // when handlers (none here, but keep consistent) query.
    server->_brr(testKey.getPublicKeyAsHash(), 10'000'000'000);
  }

  ~NetBillFixture() {
    if (server) server->stop(false);
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }
};

} // namespace

BOOST_AUTO_TEST_SUITE(NetworkBillingSuite)

// 1. Plain happy path: open one channel via CesPlex select, run a
//    round-trip, snapshot — entry exists, has the right tag, RUDP
//    metrics show nonzero counters.
BOOST_FIXTURE_TEST_CASE(TracksOneChannelAfterSelect, NetBillFixture) {
  NbTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);

  auto stream = peer.selectAndOpen(rpcPort, "/ces/test/echo/1", testKey);
  BOOST_REQUIRE(stream != nullptr);

  auto reply = peer.echo(stream, std::string("hello-billing"));
  BOOST_REQUIRE_EQUAL(reply, "hello-billing");

  auto rows = server->_netBilling()->snapshot();
  BOOST_REQUIRE_EQUAL(rows.size(), 1u);
  BOOST_CHECK_EQUAL(rows[0].channelId, 1u);
  BOOST_CHECK_EQUAL(rows[0].tag, std::string("plex:/ces/test/echo/1"));
  // Both directions of bytes flowed (select preamble + ack +
  // round-trip body), so cumulative counters must be > 0.
  BOOST_CHECK_GT(rows[0].metrics.bytesSent, 0u);
  BOOST_CHECK_GT(rows[0].metrics.bytesReceived, 0u);

  peer.closeStream();
}

// 2. Tick-driven delta computation: do one round-trip + tick (deltas
//    populate), then a second tick with no intervening traffic
//    (deltas drop to zero, cumulative unchanged). The echo handler is
//    one-shot — it serves a single round-trip and then drops its
//    stream ref — so we can't keep echoing on the same channel.
BOOST_FIXTURE_TEST_CASE(DeltasResetEachTick, NetBillFixture) {
  NbTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  auto stream = peer.selectAndOpen(rpcPort, "/ces/test/echo/1", testKey);
  BOOST_REQUIRE(stream != nullptr);

  BOOST_REQUIRE_EQUAL(peer.echo(stream, std::string(64, 'a')),
                      std::string(64, 'a'));
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  server->_netBilling()->_runTick();
  auto rows1 = server->_netBilling()->snapshot();
  BOOST_REQUIRE_EQUAL(rows1.size(), 1u);
  BOOST_CHECK_GT(rows1[0].deltaBytesSent, 0u);
  BOOST_CHECK_GT(rows1[0].deltaBytesReceived, 0u);
  const uint64_t bsAfterTick1 = rows1[0].metrics.bytesSent;
  const uint64_t brAfterTick1 = rows1[0].metrics.bytesReceived;

  // Second tick without new traffic. Cumulative metrics may grow
  // slightly from idle keep-alive ticks RUDP runs internally, but
  // deltas should be small relative to the first tick's measurement.
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  server->_netBilling()->_runTick();
  auto rows2 = server->_netBilling()->snapshot();
  BOOST_REQUIRE_EQUAL(rows2.size(), 1u);
  BOOST_CHECK_GE(rows2[0].metrics.bytesSent, bsAfterTick1);
  BOOST_CHECK_GE(rows2[0].metrics.bytesReceived, brAfterTick1);
  // The second-tick delta must be strictly smaller than the
  // first-tick delta (no fresh round-trip happened between them).
  BOOST_CHECK_LT(rows2[0].deltaBytesSent, rows1[0].deltaBytesSent);
  BOOST_CHECK_LT(rows2[0].deltaBytesReceived, rows1[0].deltaBytesReceived);

  peer.closeStream();
}

// A reused (peer, channelId) whose stale ChannelBill baseline exceeds a fresh
// channel's smaller counters must not unsigned-underflow the per-tick byte delta
// into a near-2^64 debit. _testSetBaseline forces the stale-high baseline;
// doTick must clamp the delta (bill the fresh counter from zero), not wrap.
BOOST_FIXTURE_TEST_CASE(ReusedChannelDoesNotUnderflowDelta, NetBillFixture) {
  NbTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  auto stream = peer.selectAndOpen(rpcPort, "/ces/test/echo/1", testKey);
  BOOST_REQUIRE(stream != nullptr);
  BOOST_REQUIRE_EQUAL(peer.echo(stream, std::string(64, 'a')),
                      std::string(64, 'a'));
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  server->_netBilling()->_runTick();

  auto rows0 = server->_netBilling()->snapshot();
  BOOST_REQUIRE_EQUAL(rows0.size(), 1u);
  const auto peerAddr = rows0[0].peer;
  const uint32_t cid = rows0[0].channelId;
  const uint64_t cur = rows0[0].metrics.bytesSent;

  // Simulate a reused channelId: stale baseline far above the fresh counter.
  const uint64_t BIG = 1'000'000'000ull;
  server->_netBilling()->_testSetBaseline(peerAddr, cid,
                                          cur + BIG, cur + BIG, BIG);
  server->_netBilling()->_runTick();

  auto rows1 = server->_netBilling()->snapshot();
  BOOST_REQUIRE_EQUAL(rows1.size(), 1u);
  // Pre-fix: cur - (cur+BIG) wraps to ~2^64. Post-fix: clamped to the fresh
  // counter (a few KB). Either way, far below BIG.
  BOOST_CHECK_LT(rows1[0].deltaBytesSent, BIG);
  BOOST_CHECK_LT(rows1[0].deltaBytesReceived, BIG);
  BOOST_CHECK_LT(rows1[0].deltaMemByteSeconds, BIG);

  peer.closeStream();
}

// 4. Eviction-on-tick: stop the test peer (channel disappears on
//    server side via idle GC eventually, but for the test we trigger
//    a tick after closing the stream + giving Rudp a moment to drop
//    its bookkeeping). The bill entry should evict.
//
//    NOTE: idle GC for an actively-touched channel takes 60 s in
//    Rudp's defaults. We can't realistically wait for that. Instead,
//    we use the closeChannel signal: closing the stream from the
//    client side eventually triggers HS_CLOSE on the server, which
//    drops the channel; then the next tick walks the bill map and
//    sees metricsFor() return nullopt → evicts.
BOOST_FIXTURE_TEST_CASE(EvictsAfterChannelDies, NetBillFixture) {
  NbTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  auto stream = peer.selectAndOpen(rpcPort, "/ces/test/echo/1", testKey);
  BOOST_REQUIRE(stream != nullptr);

  // Confirm one tracked channel
  BOOST_CHECK_EQUAL(server->_netBilling()->snapshot().size(), 1u);

  // Close from the client side. close() emits HS_CLOSE → server's
  // RUDP marks channel PEER_CLOSED → drops state.
  peer.closeStream();
  // Drop the local stream ref so the peer's destructor runs cleanly.
  stream.reset();

  // Give the wire a moment to deliver HS_CLOSE.
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  // Trigger a tick on the server's billing — it should evict.
  server->_netBilling()->_runTick();
  auto rows = server->_netBilling()->snapshot();
  BOOST_CHECK_EQUAL(rows.size(), 0u);
}

// 5. Rate-driven debit + insufficient-funds eviction. Open a channel
//    bound to a key whose account has been drained to ~zero, run
//    a tick that incurs a small debit, observe the channel get
//    closed by NetworkBilling because the debit failed.
BOOST_FIXTURE_TEST_CASE(EvictsOnInsufficientFunds, NetBillFixture) {
  // Use a fresh key (NOT testKey, which the fixture funds heavily).
  ces::KeyPair brokeKey;
  // Fund only enough for a single feeQuery — far less than what the
  // tick's bytes/age/mem debit will cost.
  server->_brr(brokeKey.getPublicKeyAsHash(), 100);

  NbTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  auto stream = peer.selectAndOpen(rpcPort, "/ces/test/echo/1", brokeKey);
  BOOST_REQUIRE(stream != nullptr);

  // Confirm tracked + drive a small round-trip so deltas accumulate.
  auto reply = peer.echo(stream, std::string(64, 'x'));
  BOOST_REQUIRE_EQUAL(reply, std::string(64, 'x'));

  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // Trigger a tick — debit will exceed the 100-credit balance, so
  // NetworkBilling closeChannels the channel (the bound payer
  // can't cover the per-tick cost).
  server->_netBilling()->_runTick();

  // Give the closeChannel time to process + fire onClosed.
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  // A second tick walks the bill map; the now-dead channel evicts.
  server->_netBilling()->_runTick();
  auto rows = server->_netBilling()->snapshot();
  BOOST_CHECK_EQUAL(rows.size(), 0u);
}

BOOST_AUTO_TEST_SUITE_END()
