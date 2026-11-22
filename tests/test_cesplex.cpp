// ===========================================================================
// CesPlex end-to-end tests
// ===========================================================================
//
// Exercises the bind handshake on a CES server's secondary
// port. For each test, we stand up a CesServer with a specific
// cesplexMounts config and a MINX/Rudp "client" in-process that opens
// a channel to the server's rpc port and speaks the bind wire
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

#include <ces/cesplex/bind_client.h>
#include <ces/cesplex/mux.h>
#include <ces/cesplex/session.h>
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
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
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
// channel to the server's rpc port and speaks the bind wire
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

// Rudp::Listener for the test peer. Forwards onSend to the local Minx. It
// rejects inbound HS_OPENs, unless a test gives it an acceptor.
class PlexPeerRudpListener : public minx::Rudp::Listener {
public:
  using Acceptor = std::function<std::shared_ptr<minx::Rudp::ChannelHandler>()>;
  void setMinx(minx::Minx* m) { minx_ = m; }
  void setAcceptor(Acceptor a) { acceptor_ = std::move(a); }
  std::shared_ptr<minx::Rudp::ChannelHandler> onAccept(
      const minx::SockAddr&, uint32_t) override {
    return acceptor_ ? acceptor_() : nullptr;
  }
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
  Acceptor acceptor_;
};

class PlexTestPeer {
public:
  PlexTestPeer() = default;
  ~PlexTestPeer() { stop(); }

  // Make the peer accept inbound channels, as a server. Call before start().
  void setAcceptor(PlexPeerRudpListener::Acceptor a) {
    rudpListener_.setAcceptor(std::move(a));
  }

  // Bring the peer up and return its bound port. 0 on failure.
  uint16_t start() {
    minx_ = std::make_unique<minx::Minx>(
      &listener_, minx::MinxConfig{
        .instanceName = "peer",
        .randomXVMsToKeep = 0,
        .randomXInitThreads = 0,
        .trustLoopback = true});

    rudpListener_.setMinx(minx_.get());
    // Room for a few channels to one server: the replay tests hold a bound
    // channel open while they open another one.
    minx::RudpConfig rcfg;
    rcfg.maxChannelsPerPeer = 4;
    rudp_ = std::make_unique<minx::Rudp>(&rudpListener_, rcfg);

    {
      minx::MinxStdExtensions stdExt;
      stdExt.registerExtension(
        minx::Rudp::KEY_V0,
        [this](const minx::SockAddr& peer, uint64_t key,
               const minx::Bytes& payload) {
          packetsIn_.fetch_add(1);
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
    if (tickTimer_) tickTimer_->cancel();
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
    silent_.reset();
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
    // The challenge of the server hello.
    uint64_t challenge = 0;
    // The digest of the bind; per-op sigs sign it.
    ces::BindDigest bindDigest{};
    ces::ServerHello hello;   // the server hello of this channel
    minx::Bytes request;      // the bind request that this channel sent
  };

  // How selectWith builds the bind request. A negative test changes one
  // thing only.
  struct BindOptions {
    uint64_t timeUs = 0;      // the signed client time; 0 = now
    uint32_t channel = 1;     // the RUDP channel id
    // Sign for this changed hello, in place of the hello that came.
    std::function<void(ces::ServerHello&)> changeHello;
    // Send these bytes as the request, as they are (a replay).
    std::optional<minx::Bytes> request;
    // Build the request from the hello that came.
    std::function<minx::Bytes(const ces::ServerHello&)> buildRequest;
  };

  boost::asio::io_context& taskIO() { return taskIO_; }
  minx::Rudp* rudp() { return rudp_.get(); }

  // RUDP packets that this peer got.
  size_t packetsIn() const { return packetsIn_.load(); }

  // Open a channel to (loopback, targetPort) and say nothing on it.
  // Returns false if the channel could not be registered.
  bool openSilent(uint16_t targetPort, uint32_t channel) {
    std::promise<bool> done;
    auto fut = done.get_future();
    boost::asio::post(taskIO_, [this, targetPort, channel, &done]() {
      rudp_->tick(nowMicros());
      silent_ = std::make_shared<minx::RudpStream>(taskIO_.get_executor());
      done.set_value(rudp_->registerChannel(
        minx::SockAddr(boost::asio::ip::address_v6::loopback(), targetPort),
        channel, silent_));
    });
    return fut.get();
  }

  // Write `bytes` on the silent channel.
  void writeSilent(minx::Bytes bytes) {
    std::promise<void> done;
    auto fut = done.get_future();
    auto buf = std::make_shared<minx::Bytes>(std::move(bytes));
    boost::asio::post(taskIO_, [this, buf, &done]() {
      boost::asio::async_write(*silent_, boost::asio::buffer(*buf),
        [buf](const boost::system::error_code&, std::size_t) {});
      done.set_value();
    });
    fut.wait();
  }

  // Whether the silent channel is still open on this side.
  bool silentOpen() {
    std::promise<bool> done;
    auto fut = done.get_future();
    boost::asio::post(taskIO_, [this, &done]() {
      done.set_value(silent_ && silent_->is_open());
    });
    return fut.get();
  }

  // Whether the silent channel is ESTABLISHED (the accept came), and the
  // bytes that it got.
  std::pair<bool, size_t> silentState(uint16_t targetPort, uint32_t channel) {
    std::promise<std::pair<bool, size_t>> done;
    auto fut = done.get_future();
    boost::asio::post(taskIO_, [this, targetPort, channel, &done]() {
      const bool est = rudp_->isEstablished(
        minx::SockAddr(boost::asio::ip::address_v6::loopback(), targetPort),
        channel);
      done.set_value({est, silent_ ? silent_->available() : 0});
    });
    return fut.get();
  }

  // Signed bind handshake. `signer` is the principal pubkey the channel
  // will be bound to; the bind preamble is signed by it. Returns
  // SelectResult with status=OK (0x01), the bound stream, and the
  // challenge on success; status=NACK (0x00) on a clean PROTO_REJECTED
  // reply; status=0xFF on transport/verify failure or timeout.
  SelectResult select(uint16_t targetPort, const std::string& protoName,
                      const ces::KeyPair& signer,
                      std::chrono::milliseconds timeout =
                        std::chrono::milliseconds(3000),
                      uint64_t bindTimeOverrideUs = 0) {
    BindOptions opts;
    opts.timeUs = bindTimeOverrideUs;
    return selectWith(targetPort, protoName, signer, opts, timeout);
  }

  SelectResult selectWith(uint16_t targetPort, const std::string& protoName,
                          const ces::KeyPair& signer, BindOptions opts,
                          std::chrono::milliseconds timeout =
                            std::chrono::milliseconds(3000)) {
    currentPeer_ = minx::SockAddr(
      boost::asio::ip::address_v6::loopback(), targetPort);
    currentChannel_ = opts.channel;

    auto done = std::make_shared<std::atomic<bool>>(false);
    auto result = std::make_shared<SelectResult>();
    auto mu = std::make_shared<std::mutex>();
    auto cv = std::make_shared<std::condition_variable>();

    boost::asio::post(taskIO_,
      [this, protoName, signer, opts, done, result, mu, cv]() {
      // Seed Rudp's clock before registerChannel (avoid idle-GC).
      rudp_->tick(nowMicros());
      stream_ = std::make_shared<minx::RudpStream>(
        taskIO_.get_executor());
      if (!rudp_->registerChannel(
            currentPeer_, currentChannel_, stream_)) {
        finish(done, result, mu, cv, 0xFF, nullptr, 0);
        return;
      }
      auto stream = stream_;
      ces::asyncStartBind(stream, protoName, std::nullopt,
        [this, stream, protoName, signer, opts, done, result, mu, cv]
        (ces::BindError err, ces::ServerHello hello) {
          if (err != ces::BindError::None) {
            finish(done, result, mu, cv, 0xFF, nullptr, 0);
            return;
          }
          ces::ServerHello signFor = hello;
          if (opts.changeHello) opts.changeHello(signFor);
          minx::Bytes req = opts.request ? *opts.request
            : opts.buildRequest ? opts.buildRequest(hello)
            : ces::buildBindRequest(
                protoName, opts.timeUs ? opts.timeUs : nowMicros(), signer,
                signFor);
          {
            std::lock_guard<std::mutex> lk(*mu);
            result->hello = hello;
            result->request = req;
          }
          ces::asyncFinishBind(stream, std::move(req), hello,
            [this, stream, hello, done, result, mu, cv]
            (ces::BindError e, ces::BindDigest digest) {
              {
                std::lock_guard<std::mutex> lk(*mu);
                result->bindDigest = digest;
              }
              const uint8_t status = e == ces::BindError::None     ? 0x01
                                   : e == ces::BindError::Rejected ? 0x00
                                                                   : 0xFF;
              finish(done, result, mu, cv, status,
                     e == ces::BindError::None ? stream : nullptr,
                     e == ces::BindError::None ? hello.challenge : 0);
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
              uint64_t challenge) {
    {
      std::lock_guard<std::mutex> lk(*mu);
      result->status = status;
      result->stream = std::move(stream);
      result->challenge = challenge;
      done->store(true);
    }
    cv->notify_all();
  }

  std::atomic<size_t> packetsIn_{0};
  std::shared_ptr<minx::RudpStream> silent_;   // see openSilent
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
    // These tests check rent at the base price, so pin the utilization
    // rent multiplier to full. RentPriceTests covers the multiplier.
    if (server->fileHandler()) server->fileHandler()->_testPinRentBp(10000);
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

// The peers that the server's rpc Rudp holds, read on the Rudp's thread.
size_t serverRudpPeers(CesServer& s) {
  std::promise<size_t> p;
  auto f = p.get_future();
  boost::asio::post(s._rpcTaskIOExecutor(),
                    [&] { p.set_value(s._rpcRudp()->peerCount()); });
  return f.get();
}

// Wait at most 2 s for the server's rpc Rudp to hold no peer.
bool serverRudpEmpties(CesServer& s) {
  for (int i = 0; i < 200; ++i) {
    if (serverRudpPeers(s) == 0) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return false;
}

// A STAT of a file that does not exist, over `ch`.
uint8_t statMissing(ces::CesPlexChannel& ch) {
  constexpr uint8_t kVerbStat = 0x04;
  const std::string name = "/f/nothing";
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = ch.buildEnvelope(kVerbStat, pre);
  ces::Bytes resp;
  return ch.driveVerb(kVerbStat, env, 0, nullptr, resp);
}

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

// A bind whose signed client time is outside the time window gets a NACK, with
// the true key and challenge. (Fresh binds still succeed — see
// FileSelectAccepts above.)
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

namespace {

// Counts serve() calls. It keeps no stream: a bound channel lives until the
// RUDP idle GC.
struct CountingHandler : ces::CesPlexHandler {
  std::atomic<int> served{0};
  void serve(std::shared_ptr<minx::RudpStream>,
             ces::BoundChannelContext) override {
    served.fetch_add(1);
  }
};

// serve() runs on the server's thread; wait for it to show.
bool waitServed(const CountingHandler& h, int n) {
  for (int i = 0; i < 100 && h.served.load() < n; ++i)
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  return h.served.load() == n;
}

constexpr const char* kCountProto = "/ces/test/count/1";

} // namespace

// A copy of a bind request fails on each other channel, also at the same
// server and in the time window: it signs the challenge of the channel that
// it came from.
BOOST_AUTO_TEST_CASE(BindReplayOnNewChannelIsRejected) {
  CountingHandler counter;
  CesPlexFixture fx({}, { {kCountProto, &counter} });
  PlexTestPeer victim;
  PlexTestPeer attacker;
  BOOST_REQUIRE(victim.start() != 0);
  BOOST_REQUIRE(attacker.start() != 0);
  ces::KeyPair signer;
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();

  const uint64_t tracksBefore = fx.server->_channelMeter()->_trackCalls();
  auto ok = victim.select(fx.rpcPort, kCountProto, signer);
  BOOST_REQUIRE_EQUAL(int(ok.status), 0x01);
  BOOST_REQUIRE(waitServed(counter, 1));

  PlexTestPeer::BindOptions replay;
  replay.request = ok.request;
  auto fromOther = attacker.selectWith(fx.rpcPort, kCountProto, signer, replay);
  BOOST_CHECK_EQUAL(int(fromOther.status), 0x00);
  BOOST_CHECK(fromOther.stream == nullptr);

  replay.channel = 2;
  auto fromSame = victim.selectWith(fx.rpcPort, kCountProto, signer, replay);
  BOOST_CHECK_EQUAL(int(fromSame.status), 0x00);

  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  BOOST_CHECK_EQUAL(counter.served.load(), 1);

  // The server meters (and so bills) the signer's own channel only: the
  // replays never reach track().
  BOOST_CHECK_EQUAL(fx.server->_channelMeter()->_trackCalls() - tracksBefore, 1u);
}

// An open that never speaks on its channel gets the RUDP accept, and nothing
// more: the server sends no hello to an address that has not proven itself
// with a channel packet. An open with the forged address of a victim is such
// an open, so the server cannot be used to flood the victim.
BOOST_AUTO_TEST_CASE(AnOpenThatNeverSpeaksGetsOnlyTheAccept) {
  CountingHandler counter;
  CesPlexFixture fx({}, { {kCountProto, &counter} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  BOOST_REQUIRE(peer.openSilent(fx.rpcPort, 7));
  std::this_thread::sleep_for(std::chrono::seconds(2));
  // The accept came: the channel is ESTABLISHED. And the server sent no
  // byte on it: a server that wrote its hello first would have put 40 bytes
  // in this stream.
  const auto [established, bytes] = peer.silentState(fx.rpcPort, 7);
  BOOST_CHECK(established);
  BOOST_CHECK_EQUAL(bytes, 0u);
  // The accept, and at most a few small RUDP packets. A server that wrote
  // its hello first sends it here too: 12 packets with this peer, which acks
  // it. A forged address acks nothing, so that server would send it again
  // in each pulse until the channel idles out.
  BOOST_CHECK_LE(peer.packetsIn(), 4u);
  BOOST_CHECK_EQUAL(counter.served.load(), 0);
}

// A bind for the key of another server fails, with the true challenge of this
// channel. A party in the middle meets this when it moves a bind from one
// server to another.
BOOST_AUTO_TEST_CASE(BindForAnotherServerIsRejected) {
  CountingHandler counter;
  CesPlexFixture fx({}, { {kCountProto, &counter} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::KeyPair signer;
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();

  const ces::KeyPair otherServer;
  PlexTestPeer::BindOptions o;
  o.changeHello = [&](ces::ServerHello& h) {
    h.serverPubkey = otherServer.getPublicKeyAsHash();
  };
  auto r = peer.selectWith(fx.rpcPort, kCountProto, signer, o);
  BOOST_CHECK_EQUAL(int(r.status), 0x00);

  // The same bind for the true hello works.
  o.changeHello = nullptr;
  o.channel = 2;
  auto ok = peer.selectWith(fx.rpcPort, kCountProto, signer, o);
  BOOST_CHECK_EQUAL(int(ok.status), 0x01);
  BOOST_CHECK(waitServed(counter, 1));
}

// A bind with the right digest and a signature for another challenge gets a
// NACK: the server checks the signature, not only the digest.
BOOST_AUTO_TEST_CASE(BindWithAWrongSignatureIsRejected) {
  CountingHandler counter;
  CesPlexFixture fx({}, { {kCountProto, &counter} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::KeyPair signer;
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();

  PlexTestPeer::BindOptions o;
  o.buildRequest = [&signer](const ces::ServerHello& hello) {
    const std::string name = kCountProto;
    const uint64_t t = nowMicros();
    const auto& pk = signer.getPublicKeyAsHash();
    const std::span<const uint8_t> nameSpan(
      reinterpret_cast<const uint8_t*>(name.data()), name.size());
    const std::span<const uint8_t> pkSpan(pk.data(), pk.size());
    ces::ServerHello other = hello;
    other.challenge += 1;
    auto otherDigest = ces::computeBindRequestDigest(nameSpan, t, pkSpan, other);
    const ces::Signature sig = signer.signData(
      std::span<const uint8_t>(otherDigest.data(), otherDigest.size()));
    // The digest field is for the true hello; the signature is not.
    return ces::buildBindRequestSigned(name, t, pkSpan, hello, sig);
  };
  auto r = peer.selectWith(fx.rpcPort, kCountProto, signer, o);
  BOOST_CHECK_EQUAL(int(r.status), 0x00);
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  BOOST_CHECK_EQUAL(counter.served.load(), 0);
}

// A name length of 0, or above CES_PLEX_MAX_NAME_LEN, ends the channel with
// no reply: the client waits for a hello there, so a NACK would read as one.
BOOST_AUTO_TEST_CASE(ABadNameLengthEndsTheChannelWithNoReply) {
  CountingHandler counter;
  CesPlexFixture fx({}, { {kCountProto, &counter} });
  for (uint16_t len : {uint16_t{0}, uint16_t{ces::CES_PLEX_MAX_NAME_LEN + 1}}) {
    PlexTestPeer peer;
    BOOST_REQUIRE(peer.start() != 0);
    BOOST_REQUIRE(peer.openSilent(fx.rpcPort, 9));
    minx::Bytes prefix(2);
    ces::Buffer::poke<uint16_t>(reinterpret_cast<uint8_t*>(prefix.data()), len);
    peer.writeSilent(prefix);
    for (int i = 0; i < 400 && peer.silentOpen(); ++i)
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    BOOST_CHECK(!peer.silentOpen());
    BOOST_CHECK_EQUAL(peer.silentState(fx.rpcPort, 9).second, 0u);
  }
  BOOST_CHECK_EQUAL(counter.served.load(), 0);
}

// A bind for another challenge fails, with the true server key.
BOOST_AUTO_TEST_CASE(BindWithWrongChallengeIsRejected) {
  CountingHandler counter;
  CesPlexFixture fx({}, { {kCountProto, &counter} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::KeyPair signer;
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();

  PlexTestPeer::BindOptions o;
  o.changeHello = [](ces::ServerHello& h) { h.challenge += 1; };
  auto r = peer.selectWith(fx.rpcPort, kCountProto, signer, o);
  BOOST_CHECK_EQUAL(int(r.status), 0x00);
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  BOOST_CHECK_EQUAL(counter.served.load(), 0);
}

// The hello has the server's key, and each channel gets its own challenge.
BOOST_AUTO_TEST_CASE(EachChannelGetsItsOwnChallenge) {
  CountingHandler counter;
  CesPlexFixture fx({}, { {kCountProto, &counter} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::KeyPair signer;
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();

  PlexTestPeer::BindOptions o;
  auto a = peer.selectWith(fx.rpcPort, kCountProto, signer, o);
  o.channel = 2;
  auto b = peer.selectWith(fx.rpcPort, kCountProto, signer, o);
  BOOST_REQUIRE_EQUAL(int(a.status), 0x01);
  BOOST_REQUIRE_EQUAL(int(b.status), 0x01);
  BOOST_CHECK(a.hello.serverPubkey ==
              fx.server->_serverKeyPair().getPublicKeyAsHash());
  BOOST_CHECK(b.hello.serverPubkey == a.hello.serverPubkey);
  BOOST_CHECK_NE(a.challenge, 0u);
  BOOST_CHECK_NE(b.challenge, 0u);
  BOOST_CHECK_NE(a.challenge, b.challenge);
}

// A client that expects another server key refuses the hello, and signs
// nothing: no bind reaches the server, and the channel closes.
BOOST_AUTO_TEST_CASE(PinnedClientRefusesWrongHello) {
  CountingHandler counter;
  CesPlexFixture fx({}, { {kCountProto, &counter} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::KeyPair signer;
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();
  const minx::SockAddr to(boost::asio::ip::address_v6::loopback(), fx.rpcPort);

  {
    ces::CesPlexChannel ch(peer.taskIO(), peer.rudp());
    ch.setServerPubkey(ces::KeyPair().getPublicKeyAsHash());
    CES_CHECK_RC_EQ(ch.select(to, kCountProto, signer), CES_ERROR_INTERNAL);
  }
  BOOST_CHECK(serverRudpEmpties(*fx.server));
  BOOST_CHECK_EQUAL(counter.served.load(), 0);

  ces::CesPlexChannel ch(peer.taskIO(), peer.rudp());
  ch.setServerPubkey(fx.server->_serverKeyPair().getPublicKeyAsHash());
  CES_CHECK_OK(ch.select(to, kCountProto, signer));
  BOOST_CHECK(waitServed(counter, 1));
}

namespace {

// An endpoint that runs the server side of the bind by hand, and can lie in
// its reply: the reply has a valid signature, but names another challenge, or
// another key, than the hello.
struct LyingEndpoint {
  // None: an honest bind. Challenge, Key: a reply with that field changed.
  // UnknownStatus: a signed reply with a status that is neither OK nor NACK.
  // Nack: a signed NACK. BadNack: a NACK signed over another digest.
  // NoHello: no hello after the name. NoReply: a hello, and no reply.
  enum class Lie { None, Challenge, Key, UnknownStatus, Nack, BadNack,
                   NoHello, NoReply };
  ces::KeyPair key;        // the key in the hello
  ces::KeyPair otherKey;   // signs the reply for Lie::Key
  Lie lie = Lie::None;
  // Send this challenge in the hello, in place of a fresh one: the challenge
  // of a channel at another server.
  std::optional<uint64_t> forceChallenge;
  std::atomic<bool> gotBytes{false};    // a byte of a request came
  std::atomic<bool> gotSigned{false};   // the signed part of a request came
  std::atomic<bool> sawEnd{false};      // the client ended the channel

  struct Session : std::enable_shared_from_this<Session> {
    LyingEndpoint* ep = nullptr;
    std::shared_ptr<minx::RudpStream> stream;
    ces::ServerHello hello;
    minx::Bytes helloBuf;
    std::array<uint8_t, 2> lenBuf{};
    ces::Bytes name;
    std::array<uint8_t, ces::CES_PLEX_BIND_REQ_TAIL_SIZE> tail{};
    minx::Bytes reply;

    // Wait for the end of the channel, and record it.
    void watchEnd() {
      auto self = shared_from_this();
      auto one = std::make_shared<std::array<uint8_t, 1>>();
      boost::asio::async_read(*stream, boost::asio::buffer(*one),
        [self, one](const boost::system::error_code& ec, std::size_t) {
          if (ec) self->ep->sawEnd = true;
        });
    }
    // The client speaks first: the protocol name.
    void start() {
      auto self = shared_from_this();
      boost::asio::async_read(*stream, boost::asio::buffer(lenBuf),
        [self](const boost::system::error_code& ec, std::size_t) {
          if (ec) { self->ep->sawEnd = true; return; }
          self->ep->gotBytes = true;
          self->name.resize(ces::Buffer::peek<uint16_t>(self->lenBuf.data()));
          boost::asio::async_read(*self->stream, boost::asio::buffer(self->name),
            [self](const boost::system::error_code& ec2, std::size_t) {
              if (ec2) { self->ep->sawEnd = true; return; }
              if (self->ep->lie == Lie::NoHello) { self->watchEnd(); return; }
              self->sendHello();
            });
        });
    }
    void sendHello() {
      hello.serverPubkey = ep->key.getPublicKeyAsHash();
      hello.challenge = ep->forceChallenge ? *ep->forceChallenge
                                           : ces::newChallenge();
      helloBuf = ces::buildServerHello(hello);
      auto self = shared_from_this();
      boost::asio::async_write(*stream, boost::asio::buffer(helloBuf),
        [self](const boost::system::error_code& ec, std::size_t) {
          if (ec) return;
          boost::asio::async_read(*self->stream, boost::asio::buffer(self->tail),
            [self](const boost::system::error_code& ec2, std::size_t) {
              if (ec2) { self->ep->sawEnd = true; return; }
              self->ep->gotSigned = true;
              self->answer();
            });
        });
    }
    void answer() {
      if (ep->lie == Lie::NoReply) { watchEnd(); return; }
      std::array<uint8_t, ces::CES_PLEX_SHA256_SIZE> claimed{};
      std::memcpy(claimed.data(),
                  tail.data() + sizeof(uint64_t) + ces::CES_PLEX_PUBKEY_SIZE,
                  claimed.size());
      ces::BindReplyFields f;
      f.status = ep->lie == Lie::UnknownStatus ? uint8_t{0x07}
               : (ep->lie == Lie::Nack || ep->lie == Lie::BadNack)
                   ? ces::CES_PLEX_NACK
                   : ces::CES_PLEX_OK;
      f.serverTimeUs = nowMicros();
      f.challenge = hello.challenge + (ep->lie == Lie::Challenge ? 1 : 0);
      const ces::KeyPair& signer = ep->lie == Lie::Key ? ep->otherKey : ep->key;
      if (ep->lie == Lie::BadNack) claimed.fill(0);
      reply = ces::buildBindReply(
        f, std::span<const uint8_t>(claimed.data(), claimed.size()), signer);
      auto self = shared_from_this();
      boost::asio::async_write(*stream, boost::asio::buffer(reply),
        [self](const boost::system::error_code&, std::size_t) {});
    }
  };

  // Touched only on the thread of the peer that accepts.
  std::vector<std::shared_ptr<Session>> sessions;

  std::shared_ptr<minx::Rudp::ChannelHandler> accept(boost::asio::io_context& io) {
    auto s = std::make_shared<Session>();
    s->ep = this;
    s->stream = std::make_shared<minx::RudpStream>(io.get_executor());
    sessions.push_back(s);
    s->start();
    return s->stream;
  }
};

} // namespace

// A client refuses a bind reply that names another challenge, or another key,
// than its server hello, also when the reply has a valid signature, and a
// reply with an unknown status. It takes a NACK as a refusal only when the
// NACK verifies. The honest run shows that the lie is the only thing wrong.
BOOST_AUTO_TEST_CASE(ClientRefusesAReplyForAnotherHello) {
  using Lie = LyingEndpoint::Lie;
  for (Lie lie : {Lie::None, Lie::Challenge, Lie::Key, Lie::UnknownStatus,
                  Lie::Nack, Lie::BadNack}) {
    LyingEndpoint ep;
    ep.lie = lie;
    PlexTestPeer server;
    server.setAcceptor([&ep, &server] { return ep.accept(server.taskIO()); });
    const uint16_t port = server.start();
    BOOST_REQUIRE(port != 0);
    PlexTestPeer client;
    BOOST_REQUIRE(client.start() != 0);
    const minx::SockAddr to(boost::asio::ip::address_v6::loopback(), port);
    ces::KeyPair signer;
    ces::CesPlexChannel ch(client.taskIO(), client.rudp());
    const uint8_t rc = ch.select(to, kCountProto, signer);
    if (lie == Lie::None) {
      CES_CHECK_OK(rc);
    } else if (lie == Lie::Nack) {
      CES_CHECK_RC_EQ(rc, CES_ERROR_PROTO_REJECTED);
    } else {
      CES_CHECK_RC_EQ(rc, CES_ERROR_INTERNAL);
    }
  }
}

// A client that expects another key signs nothing for the endpoint: it sends
// only the protocol name, and refuses the hello. The same client with no
// expected key sends its signed request there, so the endpoint can see one.
BOOST_AUTO_TEST_CASE(PinnedClientSignsNothingForAnotherKey) {
  for (bool pinned : {true, false}) {
    LyingEndpoint ep;
    PlexTestPeer server;
    server.setAcceptor([&ep, &server] { return ep.accept(server.taskIO()); });
    const uint16_t port = server.start();
    BOOST_REQUIRE(port != 0);
    PlexTestPeer client;
    BOOST_REQUIRE(client.start() != 0);
    const minx::SockAddr to(boost::asio::ip::address_v6::loopback(), port);
    ces::KeyPair signer;
    ces::CesPlexChannel ch(client.taskIO(), client.rudp());
    if (pinned) ch.setServerPubkey(ces::KeyPair().getPublicKeyAsHash());
    const uint8_t rc = ch.select(to, kCountProto, signer);
    if (pinned) {
      CES_CHECK_RC_EQ(rc, CES_ERROR_INTERNAL);
      // The refusal closes the channel, so the endpoint sees its end.
      for (int i = 0; i < 100 && !ep.sawEnd.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      BOOST_CHECK(ep.sawEnd.load());
      BOOST_CHECK(!ep.gotSigned.load());
    } else {
      CES_CHECK_OK(rc);
      BOOST_CHECK(ep.gotSigned.load());
    }
  }
}

// A select whose endpoint sends no hello, or no reply, ends at the connect
// timeout with UNREACHABLE, and closes its channel: the endpoint sees the end.
BOOST_AUTO_TEST_CASE(SelectTimeoutClosesTheChannel) {
  using Lie = LyingEndpoint::Lie;
  for (Lie lie : {Lie::NoHello, Lie::NoReply}) {
    LyingEndpoint ep;
    ep.lie = lie;
    PlexTestPeer server;
    server.setAcceptor([&ep, &server] { return ep.accept(server.taskIO()); });
    const uint16_t port = server.start();
    BOOST_REQUIRE(port != 0);
    PlexTestPeer client;
    BOOST_REQUIRE(client.start() != 0);
    const minx::SockAddr to(boost::asio::ip::address_v6::loopback(), port);
    ces::KeyPair signer;
    ces::CesPlexChannel ch(client.taskIO(), client.rudp());
    CES_CHECK_RC_EQ(ch.select(to, kCountProto, signer), CES_ERROR_UNREACHABLE);
    for (int i = 0; i < 200 && !ep.sawEnd.load(); ++i)
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    BOOST_CHECK(ep.sawEnd.load());
    BOOST_CHECK_EQUAL(ep.gotSigned.load(), lie == Lie::NoReply);
  }
}

// A client with a protocol name that is too long refuses it before it writes:
// the endpoint gets no byte.
BOOST_AUTO_TEST_CASE(AClientRefusesATooLongNameBeforeItWrites) {
  LyingEndpoint ep;
  PlexTestPeer server;
  server.setAcceptor([&ep, &server] { return ep.accept(server.taskIO()); });
  const uint16_t port = server.start();
  BOOST_REQUIRE(port != 0);
  PlexTestPeer client;
  BOOST_REQUIRE(client.start() != 0);
  const minx::SockAddr to(boost::asio::ip::address_v6::loopback(), port);
  ces::KeyPair signer;
  ces::CesPlexChannel ch(client.taskIO(), client.rudp());
  const std::string name(ces::CES_PLEX_MAX_NAME_LEN + 1, 'n');
  CES_CHECK_RC_EQ(ch.select(to, name, signer), CES_ERROR_PROTO_REJECTED);
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  BOOST_CHECK(!ep.gotBytes.load());
}

// Write [u8 verb][envelope] on `stream`, read an error response (the status,
// an empty preamble and the signed trailer), and return its status. 0xFF if
// the stream ends first.
uint8_t sendVerbStatus(boost::asio::io_context& io,
                       std::shared_ptr<minx::RudpStream> stream,
                       uint8_t verb, const minx::Bytes& envelope) {
  auto wire = std::make_shared<minx::Bytes>();
  wire->push_back(static_cast<char>(verb));
  wire->insert(wire->end(), envelope.begin(), envelope.end());
  auto st = std::make_shared<std::array<uint8_t, 1 + ces::CES_PLEX_RESP_TRAILER_SIZE>>();
  auto done = std::make_shared<std::promise<uint8_t>>();
  auto fut = done->get_future();
  boost::asio::post(io, [stream, wire, st, done]() {
    boost::asio::async_write(*stream, boost::asio::buffer(*wire),
      [stream, wire, st, done](const boost::system::error_code& ec, std::size_t) {
        if (ec) { done->set_value(0xFF); return; }
        boost::asio::async_read(*stream, boost::asio::buffer(*st),
          [st, done](const boost::system::error_code& ec2, std::size_t) {
            done->set_value(ec2 ? uint8_t{0xFF} : (*st)[0]);
          });
      });
  });
  if (fut.wait_for(std::chrono::seconds(5)) != std::future_status::ready)
    return 0xFF;
  return fut.get();
}

// A per-op verb that a key signs for one server fails on its channel at
// another server. Here a dishonest endpoint M gives its own channel the
// challenge of the key's channel at the real server S. The key signs a STAT
// for M; that STAT must not run at S.
BOOST_AUTO_TEST_CASE(AVerbSignedForAnotherServerIsRejected) {
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });
  ces::KeyPair signer;
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();

  // The key's channel at S.
  PlexTestPeer peerS;
  BOOST_REQUIRE(peerS.start() != 0);
  auto atS = peerS.select(fx.rpcPort, "/ces/file/1", signer);
  BOOST_REQUIRE_EQUAL(int(atS.status), 0x01);

  // M copies the challenge of that channel into its own hello.
  LyingEndpoint m;
  m.forceChallenge = atS.challenge;
  PlexTestPeer peerM;
  peerM.setAcceptor([&m, &peerM] { return m.accept(peerM.taskIO()); });
  const uint16_t mPort = peerM.start();
  BOOST_REQUIRE(mPort != 0);

  // The production client binds to M and signs a STAT for M.
  PlexTestPeer client;
  BOOST_REQUIRE(client.start() != 0);
  ces::CesPlexChannel ch(client.taskIO(), client.rudp());
  CES_REQUIRE_OK(ch.select(
    minx::SockAddr(boost::asio::ip::address_v6::loopback(), mPort),
    "/ces/file/1", signer));
  constexpr uint8_t kVerbStat = 0x04;
  const std::string name = "/f/nothing";
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  const minx::Bytes env = ch.buildEnvelope(kVerbStat, pre);

  // The control: the same STAT, signed for the key's channel at S, runs
  // there as a STAT of a missing file.
  // [u32 len][u64 salt + preamble][65 sig], as CesPlexChannel builds it.
  ces::Bytes signedPre;
  ces::Buffer::put<uint64_t>(signedPre, 1);
  signedPre.insert(signedPre.end(), pre.begin(), pre.end());
  const ces::Signature ownSig = ces::signPerOp(
    signer, kVerbStat,
    std::span<const uint8_t>(signedPre.data(), signedPre.size()),
    atS.bindDigest);
  ces::Bytes own;
  ces::Buffer::put<uint32_t>(own, static_cast<uint32_t>(signedPre.size()));
  own.insert(own.end(), signedPre.begin(), signedPre.end());
  own.insert(own.end(), ownSig.begin(), ownSig.end());
  BOOST_REQUIRE_EQUAL(
    int(sendVerbStatus(peerS.taskIO(), atS.stream, kVerbStat,
                       minx::Bytes(own.begin(), own.end()))),
    int(CES_ERROR_FILE_NOT_FOUND));

  // M moves the STAT that the key signed for it onto the key's channel at S.
  // S must refuse it: the signature names M.
  const uint8_t status =
    sendVerbStatus(peerS.taskIO(), atS.stream, kVerbStat, env);
  BOOST_CHECK_EQUAL(int(status), int(CES_ERROR_BAD_INPUT));
}

// Two binds that differ only in the server key give two digests, and a
// per-op sig for one fails on the other.
BOOST_AUTO_TEST_CASE(APerOpSigNamesTheServerKey) {
  const std::string name = "/ces/file/1";
  ces::KeyPair signer;
  const auto& pub = signer.getPublicKeyAsHash();
  ces::ServerHello helloA, helloB;
  helloA.serverPubkey.fill(0x22);
  helloB.serverPubkey.fill(0x33);
  helloA.challenge = helloB.challenge = 0x8000000000000001ull;
  auto digestFor = [&](const ces::ServerHello& h) {
    return ces::computeBindRequestDigest(
      std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(name.data()), name.size()),
      1700000000000000ull, std::span<const uint8_t>(pub.data(), pub.size()), h);
  };
  ces::BoundChannelContext atA;
  atA.boundPubkey = signer.getPublicKey();
  atA.bindDigest = digestFor(helloA);
  const ces::Bytes pre{1, 2, 3, 4};
  const std::span<const uint8_t> sp(pre.data(), pre.size());
  BOOST_CHECK(ces::verifyPerOp(atA, 0x04, sp,
                               ces::signPerOp(signer, 0x04, sp, digestFor(helloA))));
  BOOST_CHECK(!ces::verifyPerOp(atA, 0x04, sp,
                                ces::signPerOp(signer, 0x04, sp, digestFor(helloB))));
}

// CES signs a bind digest to the same bytes as cesweb's cessign.js: the same
// constants are in "signatures: the known answers of the C++ suite" in
// cesweb/tests/cessign.test.mjs. Both algorithms are deterministic.
BOOST_AUTO_TEST_CASE(SignaturesMatchCessign) {
  const std::string name = "/ces/lua/1";
  ces::ServerHello hello;
  hello.serverPubkey.fill(0x22);
  hello.challenge = 0x8000000000000001ull;
  struct Case { ces::KeyAlgo algo; const char* priv; const char* pub; const char* sig; };
  const Case cases[] = {
    {ces::KeyAlgo::ED25519, "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
     "fc947730f49eb01427a66e050733294d9e520e545c7a27125a780634e0860a27",
     "00bcc1e29f99b9d73fa943adb28cadb5140f24815aa65adb50d2d53de1a811a0137821e069fed2a1096b56cb95c50736dcc39cbd84ab115f90601289300e811709"},
    {ces::KeyAlgo::SECP256K1, "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
     "ab5d2e79cfd621b1b027ffb24e2453ed7fb571ba9a841ff0e2473466cabd168d",
     "02a2b26927b785d103744d29e93e720dd35ee5661bfe3e8aa211ae05a2bfa95f204bb7d15442c45bca1dd25f6dea60afcb694c9ce964a5dc8b04a41f8443aa5538"},
  };
  for (const auto& c : cases) {
    const ces::KeyPair key(std::string(c.priv), c.algo);
    const auto& pub = key.getPublicKeyAsHash();
    BOOST_CHECK_EQUAL(minx::hashToString(pub), c.pub);
    auto d = ces::computeBindRequestDigest(
      std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(name.data()), name.size()),
      1700000000000000ull, std::span<const uint8_t>(pub.data(), pub.size()),
      hello);
    ces::Signature sig =
      key.signData(std::span<const uint8_t>(d.data(), d.size()));
    std::string hex;
    for (uint8_t b : sig) {
      static const char* k = "0123456789abcdef";
      hex.push_back(k[b >> 4]);
      hex.push_back(k[b & 15]);
    }
    BOOST_CHECK_EQUAL(hex, c.sig);
  }
}

// One known digest. cesweb's tests/cessign.test.mjs and
// tests/webcrypto.test.mjs check the same bytes; the challenge is above 2^53,
// where a JavaScript Number loses bits.
BOOST_AUTO_TEST_CASE(BindDigestKnownAnswer) {
  const std::string name = "/ces/lua/1";
  std::array<uint8_t, 32> clientPub;
  clientPub.fill(0x11);
  ces::ServerHello hello;
  hello.serverPubkey.fill(0x22);
  hello.challenge = 0x8000000000000001ull;
  auto d = ces::computeBindRequestDigest(
    std::span<const uint8_t>(
      reinterpret_cast<const uint8_t*>(name.data()), name.size()),
    1700000000000000ull,
    std::span<const uint8_t>(clientPub.data(), clientPub.size()), hello);
  minx::Hash h;
  std::memcpy(h.data(), d.data(), h.size());
  BOOST_CHECK_EQUAL(minx::hashToString(h),
    "04bcbf72a154ef9775748c52f2ee9a94a4d9234c32f509ea27db123cb36def65");
}

// One known per-op digest: the ATTACH of pid 7 on the bind of
// BindDigestKnownAnswer. cesweb's tests check the same bytes.
BOOST_AUTO_TEST_CASE(PerOpDigestKnownAnswer) {
  ces::BindDigest bind{};
  minx::Hash b;
  minx::stringToHash(b,
    "04bcbf72a154ef9775748c52f2ee9a94a4d9234c32f509ea27db123cb36def65");
  std::memcpy(bind.data(), b.data(), bind.size());
  ces::Bytes pre;
  ces::Buffer::put<uint64_t>(pre, 7);
  auto d = ces::computePerOpDigest(
    0x01, std::span<const uint8_t>(pre.data(), pre.size()), bind);
  minx::Hash h;
  std::memcpy(h.data(), d.data(), h.size());
  BOOST_CHECK_EQUAL(minx::hashToString(h),
    "fcc76fdaffc05370107ae476fa3ac2cb80a156ac8486707468cef58d0bb2922b");
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
// Sig is over sha256(verb || salt || preamble || bind digest).
static ces::Bytes buildSignedEnvelope(
    const ces::KeyPair& signer,
    uint8_t verb,
    const ces::Bytes& preamble,
    const ces::BindDigest& bindDigest) {
  // Match CesPlexClient: prepend an 8-byte per-op salt so repeated ops
  // sign differently (a static counter gives uniqueness across calls).
  static uint64_t opSalt = 1;
  ces::Bytes signedPre;
  ces::Buffer::put<uint64_t>(signedPre, opSalt++);
  signedPre.insert(signedPre.end(), preamble.begin(), preamble.end());
  ces::Signature sig = ces::signPerOp(
    signer, verb,
    std::span<const uint8_t>(signedPre.data(), signedPre.size()),
    bindDigest);
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
                           const ces::BindDigest& bindDigest,
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
  auto env = buildSignedEnvelope(signer, 0x01, pre, bindDigest);
  return driveVerb(ioc, stream, 0x01, env, /*respPreambleLen=*/16);
}

// --- WRITE ---
static RespTail ramfileWrite(boost::asio::io_context& ioc,
                          std::shared_ptr<minx::RudpStream> stream,
                          const ces::KeyPair& signer,
                          const ces::BindDigest& bindDigest,
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
  auto env = buildSignedEnvelope(signer, 0x02, pre, bindDigest);
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
                           const ces::BindDigest& bindDigest,
                           uint32_t reqNonce,
                           uint64_t offset, uint32_t length,
                           const std::string& name) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, reqNonce);
  ces::Buffer::put<uint64_t>(pre, offset);
  ces::Buffer::put<uint32_t>(pre, length);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(signer, 0x03, pre, bindDigest);

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
                           const ces::BindDigest& bindDigest,
                           const std::string& name) {
  // Step 3: STAT is signed like every other verb. Preamble is
  // [u32 reqNonce][u16 name_len][name].
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(signer, 0x04, pre, bindDigest);

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
                            const ces::BindDigest& bindDigest,
                            uint32_t reqNonce, uint64_t amount,
                            const std::string& name) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, reqNonce);
  ces::Buffer::put<uint64_t>(pre, amount);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(signer, 0x05, pre, bindDigest);
  return driveVerb(ioc, stream, 0x05, env, /*respPreambleLen=*/8);
}
static RespTail fileWithdraw(boost::asio::io_context& ioc,
                             std::shared_ptr<minx::RudpStream> stream,
                             const ces::KeyPair& signer,
                             const ces::BindDigest& bindDigest,
                             uint32_t reqNonce, uint64_t amount,
                             const std::string& name) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, reqNonce);
  ces::Buffer::put<uint64_t>(pre, amount);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(signer, 0x06, pre, bindDigest);
  return driveVerb(ioc, stream, 0x06, env, /*respPreambleLen=*/8);
}
static RespTail fileSetPrice(boost::asio::io_context& ioc,
                             std::shared_ptr<minx::RudpStream> stream,
                             const ces::KeyPair& signer,
                             const ces::BindDigest& bindDigest,
                             uint32_t reqNonce, uint64_t price,
                             const std::string& name) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, reqNonce);
  ces::Buffer::put<uint64_t>(pre, price);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(signer, 0x07, pre, bindDigest);
  return driveVerb(ioc, stream, 0x07, env, /*respPreambleLen=*/8);
}
static RespTail fileDelete(boost::asio::io_context& ioc,
                           std::shared_ptr<minx::RudpStream> stream,
                           const ces::KeyPair& signer,
                           const ces::BindDigest& bindDigest,
                           uint32_t reqNonce,
                           const std::string& name) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, reqNonce);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(signer, 0x08, pre, bindDigest);
  return driveVerb(ioc, stream, 0x08, env, /*respPreambleLen=*/8);
}

// --- APPEND ---
// Response preamble: [u64 file_balance][u64 new_size].
static RespTail fileAppend(boost::asio::io_context& ioc,
                           std::shared_ptr<minx::RudpStream> stream,
                           const ces::KeyPair& signer,
                           const ces::BindDigest& bindDigest,
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
  auto env = buildSignedEnvelope(signer, 0x09, pre, bindDigest);
  return driveVerb(ioc, stream, 0x09, env,
                   /*respPreambleLen=*/8 + 8,
                   /*extraBodyToSend=*/content);
}

// --- RESIZE ---
// Response preamble: [u64 new_size].
static RespTail ramfileResize(boost::asio::io_context& ioc,
                           std::shared_ptr<minx::RudpStream> stream,
                           const ces::KeyPair& signer,
                           const ces::BindDigest& bindDigest,
                           uint32_t reqNonce,
                           uint64_t newSize,
                           const std::string& name) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, reqNonce);
  ces::Buffer::put<uint64_t>(pre, newSize);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(signer, 0x0a, pre, bindDigest);
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
  auto c = fileCreate(peer.taskIO(), sel.stream, signer, sel.bindDigest, CES_NONCELESS,
                      size, /*pricePerKb=*/10, deposit,
                      name);
  CES_CHECK_RC_EQ(c.status, CES_OK);

  auto st = fileStat(peer.taskIO(), sel.stream, signer, sel.bindDigest, name);
  CES_CHECK_RC_EQ(st.status, CES_OK);
  BOOST_CHECK_EQUAL(st.fileBalance, postCreateBalance);
  BOOST_CHECK_EQUAL(st.pricePerKb, 10u);
  BOOST_CHECK_EQUAL(st.size, 1024u);
  BOOST_CHECK(std::memcmp(st.ownerPubkey.data(),
                          signer.getPublicKeyAsHash().data(), 32) == 0);

  auto w = fileWithdraw(peer.taskIO(), sel.stream, signer, sel.bindDigest, CES_NONCELESS,
                        postCreateBalance, name);
  CES_CHECK_RC_EQ(w.status, CES_OK);
  BOOST_REQUIRE_EQUAL(w.preamble.size(), 8u);
  BOOST_CHECK_EQUAL(ces::Buffer::peek<uint64_t>(w.preamble.data()), 0u); // balance drained

  auto st2 = fileStat(peer.taskIO(), sel.stream, signer, sel.bindDigest, name);
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
  auto c = fileCreate(peer.taskIO(), sel.stream, signer, sel.bindDigest,
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
  auto env = buildSignedEnvelope(signer, 0x05, pre, sel.bindDigest);

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
  auto st = fileStat(peer.taskIO(), sel.stream, signer, sel.bindDigest, name);
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
  auto c = fileCreate(peer.taskIO(), sel.stream, signer, sel.bindDigest, CES_NONCELESS,
                      /*size=*/64, /*pricePerKb=*/0,
                      /*initialDeposit=*/10'000'000,
                      name);
  CES_REQUIRE_RC_EQ(c.status, CES_OK);

  ces::Bytes content(64, 0);
  const std::string msg = "hello from the v2 write path";
  std::memcpy(content.data(), msg.data(), msg.size());

  auto w = ramfileWrite(peer.taskIO(), sel.stream, signer, sel.bindDigest, CES_NONCELESS,
                     /*offset=*/0, content, name);
  CES_REQUIRE_RC_EQ(w.status, CES_OK);

  auto r = ramfileRead(peer.taskIO(), sel.stream, signer, sel.bindDigest, CES_NONCELESS,
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
  auto c = fileCreate(peerA.taskIO(), selA.stream, a, selA.bindDigest,
                      CES_NONCELESS, size, pricePerKb,
                      /*initialDeposit=*/500'000,
                      name);
  CES_REQUIRE_RC_EQ(c.status, CES_OK);
  uint64_t expectedBalance = 500'000u - upfrontBurn;

  // B deposits 1M — file_balance should bump.
  auto d = fileDeposit(peerB.taskIO(), selB.stream, b, selB.bindDigest,
                       CES_NONCELESS, 1'000'000, name);
  CES_REQUIRE_RC_EQ(d.status, CES_OK);
  expectedBalance += 1'000'000u;
  BOOST_CHECK_EQUAL(ces::Buffer::peek<uint64_t>(d.preamble.data()), expectedBalance);

  // B reads 1024 bytes — pays pricePerKb to the file.
  auto r = ramfileRead(peerB.taskIO(), selB.stream, b, selB.bindDigest,
                    CES_NONCELESS, /*offset=*/0, /*length=*/1024, name);
  CES_REQUIRE_RC_EQ(r.status, CES_OK);
  expectedBalance += pricePerKb;

  // STAT (on B's channel — anyone can stat).
  auto s = fileStat(peerB.taskIO(), selB.stream, b, selB.bindDigest,
                    name);
  CES_REQUIRE_RC_EQ(s.status, CES_OK);
  BOOST_CHECK_EQUAL(s.fileBalance, expectedBalance);

  // A withdraws the full file_balance → bumps A's account.
  auto w = fileWithdraw(peerA.taskIO(), selA.stream, a, selA.bindDigest,
                        CES_NONCELESS, s.fileBalance, name);
  CES_REQUIRE_RC_EQ(w.status, CES_OK);
  BOOST_CHECK_EQUAL(ces::Buffer::peek<uint64_t>(w.preamble.data()), 0u);
}

BOOST_AUTO_TEST_CASE(FileWithdrawBeyondInt64NeverMints) {
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });
  PlexTestPeer peerA, peerB;
  BOOST_REQUIRE(peerA.start() != 0);
  BOOST_REQUIRE(peerB.start() != 0);
  minx::Hash privA; privA.fill(0xA9);
  minx::Hash privB; privB.fill(0xB9);
  ces::KeyPair a(privA), b(privB);
  fx.server->_brr(a.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_brr(b.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();
  auto selA = peerA.select(fx.rpcPort, "/ces/file/1", a);
  BOOST_REQUIRE_EQUAL(int(selA.status), 0x01);
  auto selB = peerB.select(fx.rpcPort, "/ces/file/1", b);
  BOOST_REQUIRE_EQUAL(int(selB.status), 0x01);

  const std::string name = "/p/withdraw/huge";
  auto c = fileCreate(peerA.taskIO(), selA.stream, a, selA.bindDigest,
                      CES_NONCELESS, 1024, 0, /*initialDeposit=*/500'000, name);
  CES_REQUIRE_RC_EQ(c.status, CES_OK);
  auto s0 = fileStat(peerB.taskIO(), selB.stream, b, selB.bindDigest, name);
  CES_REQUIRE_RC_EQ(s0.status, CES_OK);
  const int64_t circBefore = fx.server->_getTotalCredits();

  auto w = fileWithdraw(peerA.taskIO(), selA.stream, a, selA.bindDigest,
                        CES_NONCELESS, ~uint64_t(0) - 999'999, name);
  BOOST_CHECK(w.status != CES_OK);

  auto s1 = fileStat(peerB.taskIO(), selB.stream, b, selB.bindDigest, name);
  CES_REQUIRE_RC_EQ(s1.status, CES_OK);
  BOOST_CHECK_LE(s1.fileBalance, s0.fileBalance);
  BOOST_CHECK_LE(fx.server->_getTotalCredits(), circBefore);
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
  auto c = fileCreate(peerA.taskIO(), selA.stream, a, selA.bindDigest,
                      CES_NONCELESS, /*size=*/16, /*pricePerKb=*/0,
                      /*initialDeposit=*/10'000'000,
                      name);
  CES_REQUIRE_RC_EQ(c.status, CES_OK);

  // B (different bound channel) tries to write — server rejects with
  // NOT_OWNER because the channel's bound pubkey doesn't match the
  // file's owner.
  ces::Bytes content(16, 'B');
  auto w = ramfileWrite(peerB.taskIO(), selB.stream, b, selB.bindDigest,
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
  auto c = fileCreate(peer.taskIO(), sel.stream, signer, sel.bindDigest, CES_NONCELESS,
                      /*size=*/16, /*pricePerKb=*/0,
                      /*initialDeposit=*/10'000'000,
                      name);
  CES_REQUIRE_RC_EQ(c.status, CES_OK);

  // WRITE 'A's into the first 16 bytes.
  ces::Bytes first(16, 'A');
  auto w = ramfileWrite(peer.taskIO(), sel.stream, signer, sel.bindDigest, CES_NONCELESS,
                     /*offset=*/0, first, name);
  CES_REQUIRE_RC_EQ(w.status, CES_OK);

  // APPEND 16 'B's.
  ces::Bytes second(16, 'B');
  auto a = fileAppend(peer.taskIO(), sel.stream, signer, sel.bindDigest, CES_NONCELESS,
                      second, name);
  CES_REQUIRE_RC_EQ(a.status, CES_OK);
  BOOST_REQUIRE_EQUAL(a.preamble.size(), 8u + 8u);
  uint64_t respSize = ces::Buffer::peek<uint64_t>(a.preamble.data() + 8);
  BOOST_CHECK_EQUAL(respSize, 32u);

  // READ the full 32 bytes, verify layout.
  auto r = ramfileRead(peer.taskIO(), sel.stream, signer, sel.bindDigest, CES_NONCELESS,
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
  auto c = fileCreate(peer.taskIO(), sel.stream, signer, sel.bindDigest, CES_NONCELESS,
                      /*size=*/100, /*pricePerKb=*/0,
                      /*initialDeposit=*/10'000'000,
                      name);
  CES_REQUIRE_RC_EQ(c.status, CES_OK);

  // Grow to 200.
  auto g = ramfileResize(peer.taskIO(), sel.stream, signer, sel.bindDigest, CES_NONCELESS,
                      200, name);
  CES_REQUIRE_RC_EQ(g.status, CES_OK);
  BOOST_REQUIRE_EQUAL(g.preamble.size(), 8u);
  BOOST_CHECK_EQUAL(ces::Buffer::peek<uint64_t>(g.preamble.data()), 200u);

  auto s1 = fileStat(peer.taskIO(), sel.stream, signer, sel.bindDigest, name);
  CES_REQUIRE_RC_EQ(s1.status, CES_OK);
  BOOST_CHECK_EQUAL(s1.size, 200u);

  // Shrink to 50.
  auto h = ramfileResize(peer.taskIO(), sel.stream, signer, sel.bindDigest, CES_NONCELESS,
                      50, name);
  CES_REQUIRE_RC_EQ(h.status, CES_OK);
  BOOST_CHECK_EQUAL(ces::Buffer::peek<uint64_t>(h.preamble.data()), 50u);

  auto s2 = fileStat(peer.taskIO(), sel.stream, signer, sel.bindDigest, name);
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
  auto c = fileCreate(peer.taskIO(), sel.stream, signer, sel.bindDigest, CES_NONCELESS,
                      /*size=*/1024 * 1024, /*pricePerKb=*/0,
                      /*initialDeposit=*/10924,
                      name);
  CES_REQUIRE_RC_EQ(c.status, CES_OK);

  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  auto s = fileStat(peer.taskIO(), sel.stream, signer, sel.bindDigest, name);
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
  auto c = fileCreate(peer.taskIO(), sel.stream, signer, sel.bindDigest, CES_NONCELESS,
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
  auto c = fileCreate(peer.taskIO(), sel.stream, signer, sel.bindDigest, CES_NONCELESS,
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
  auto c = fileCreate(peer.taskIO(), sel.stream, bob, sel.bindDigest, CES_NONCELESS,
                      /*size=*/16, /*pricePerKb=*/0,
                      /*initialDeposit=*/1'000'000,
                      name);
  CES_CHECK_RC_EQ(c.status, CES_ERROR_NOT_OWNER);
}

BOOST_AUTO_TEST_CASE(FileNamespaceUnownedRejected) {
  // /f/<name>/ CREATEs fail when nobody owns the name (no key_name). The
  // key_name is the SOLE gate; there is no asset gate. Positive ownership is
  // exercised by FileNamespaceKeyNameGated.
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
  auto c = fileCreate(peer.taskIO(), sel.stream, signer, sel.bindDigest, CES_NONCELESS,
                      /*size=*/16, /*pricePerKb=*/0,
                      /*initialDeposit=*/1'000'000,
                      name);
  CES_CHECK_RC_EQ(c.status, CES_ERROR_NOT_OWNER);
}

BOOST_AUTO_TEST_CASE(FileNamespaceKeyNameGated) {
  // The /f/ gate: whoever owns the key_name owns /f/<name>/, and that is the
  // ONLY gate (no asset). The key_name holder can CREATE there; a non-holder
  // cannot. One peer per channel (the per-peer channel cap).
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });

  minx::Hash privA; privA.fill(0xD1);
  minx::Hash privB; privB.fill(0xD2);
  ces::KeyPair owner(privA);
  ces::KeyPair other(privB);
  fx.server->_brr(owner.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_brr(other.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();

  // owner registers the name "myzone"; other registers "My Zone" (no assets).
  BOOST_REQUIRE(fx.server->_registerKeyName(owner.getPublicKeyAsHash(), "myzone"));
  BOOST_REQUIRE(
      fx.server->_registerKeyName(other.getPublicKeyAsHash(), "My Zone"));

  // The key_name holder CREATEs under /f/myzone/ -- allowed by the name gate.
  {
    PlexTestPeer peer; BOOST_REQUIRE(peer.start() != 0);
    auto sel = peer.select(fx.rpcPort, "/ces/file/1", owner);
    BOOST_REQUIRE_EQUAL(int(sel.status), 0x01);
    auto c = fileCreate(peer.taskIO(), sel.stream, owner, sel.bindDigest,
                        CES_NONCELESS, /*size=*/16, /*pricePerKb=*/0,
                        /*initialDeposit=*/1'000'000, "/f/myzone/hello.txt");
    CES_CHECK_RC_EQ(c.status, CES_OK);
  }
  // A different signer cannot: not the name holder, and no asset gate either.
  {
    PlexTestPeer peer; BOOST_REQUIRE(peer.start() != 0);
    auto sel = peer.select(fx.rpcPort, "/ces/file/1", other);
    BOOST_REQUIRE_EQUAL(int(sel.status), 0x01);
    auto c = fileCreate(peer.taskIO(), sel.stream, other, sel.bindDigest,
                        CES_NONCELESS, /*size=*/16, /*pricePerKb=*/0,
                        /*initialDeposit=*/1'000'000, "/f/myzone/evil.txt");
    CES_CHECK_RC_EQ(c.status, CES_ERROR_NOT_OWNER);
  }
  // The handle is normalized: "My Zone" -> /f/My_Zone/ is writable by other.
  {
    PlexTestPeer peer; BOOST_REQUIRE(peer.start() != 0);
    auto sel = peer.select(fx.rpcPort, "/ces/file/1", other);
    BOOST_REQUIRE_EQUAL(int(sel.status), 0x01);
    auto c = fileCreate(peer.taskIO(), sel.stream, other, sel.bindDigest,
                        CES_NONCELESS, /*size=*/16, /*pricePerKb=*/0,
                        /*initialDeposit=*/1'000'000, "/f/My_Zone/note.txt");
    CES_CHECK_RC_EQ(c.status, CES_OK);
  }
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
  auto c = fileCreate(peer.taskIO(), sel.stream, signer, sel.bindDigest, CES_NONCELESS,
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
  auto c = fileCreate(peer.taskIO(), sel.stream, signer, sel.bindDigest,
                      CES_NONCELESS, /*size=*/16, /*pricePerKb=*/0,
                      /*initialDeposit=*/1'000'000, name);
  CES_CHECK_RC_EQ(c.status, CES_OK);

  auto st = fileStat(peer.taskIO(), sel.stream, signer, sel.bindDigest, name);
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
    auto c = fileCreate(peer.taskIO(), sel.stream, signer, sel.bindDigest,
                        CES_NONCELESS, /*size=*/16, /*pricePerKb=*/0,
                        /*initialDeposit=*/1'000'000, name);
    BOOST_CHECK_MESSAGE(c.status == CES_ERROR_BAD_NAME,
                        "expected BAD_NAME for '" << name << "' got "
                        << int(c.status));
  }
}

// Regression: acceptInbound must reject a duplicate (peer, channelId) - returning
// null and NOT creating a second untracked session over the in-flight one.
BOOST_AUTO_TEST_CASE(AcceptInboundRejectsDuplicateCoords) {
  boost::asio::io_context io;
  ces::CesPlex plex(io, /*host=*/nullptr, /*meter=*/nullptr);

  minx::SockAddr peer(boost::asio::ip::make_address_v6("::1"), 40000);
  auto s1 = plex.acceptInbound(peer, 7);
  BOOST_CHECK(s1 != nullptr);
  BOOST_CHECK_EQUAL(plex._pendingSessionCount(), 1u);

  auto s2 = plex.acceptInbound(peer, 7);      // same coords -> rejected
  BOOST_CHECK(s2 == nullptr);
  BOOST_CHECK_EQUAL(plex._pendingSessionCount(), 1u);

  auto s3 = plex.acceptInbound(peer, 8);      // different channel -> distinct
  BOOST_CHECK(s3 != nullptr);
  BOOST_CHECK_EQUAL(plex._pendingSessionCount(), 2u);

  io.stop();
}

// A channel that the owner closes frees its slot on the server. The server
// holds at most max_channels_per_peer channels for one address. Channels from
// one port that end without HS_CLOSE fill those slots, and the next select
// gets no answer.
BOOST_AUTO_TEST_CASE(ClosedChannelsFreeTheirSlots) {
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::KeyPair signer;
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();
  const minx::SockAddr to(boost::asio::ip::address_v6::loopback(), fx.rpcPort);
  const size_t n = fx.server->_config().rpcRudpMaxChannelsPerPeer + 2;
  for (size_t i = 0; i < n; ++i) {
    ces::CesPlexChannel ch(peer.taskIO(), peer.rudp());
    CES_REQUIRE_OK(ch.select(to, "/ces/file/1", signer));
    CES_REQUIRE_RC_EQ(statMissing(ch), CES_ERROR_FILE_NOT_FOUND);
    ch.close();
  }
  BOOST_CHECK(serverRudpEmpties(*fx.server));
}

// The destructor of a channel sends nothing, so the server keeps the slot.
BOOST_AUTO_TEST_CASE(DestroyingAChannelSendsNothing) {
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::KeyPair signer;
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();
  const minx::SockAddr to(boost::asio::ip::address_v6::loopback(), fx.rpcPort);
  {
    ces::CesPlexChannel ch(peer.taskIO(), peer.rudp());
    CES_REQUIRE_OK(ch.select(to, "/ces/file/1", signer));
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  BOOST_CHECK_EQUAL(serverRudpPeers(*fx.server), 1u);
}

// A client that disconnects sends HS_CLOSE, so the server frees its slot at
// once, before the idle GC.
BOOST_AUTO_TEST_CASE(DisconnectFreesTheServerSlot) {
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });
  ces::KeyPair signer;
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();
  ces::CesPlexClient c;
  CES_REQUIRE_OK(c.connect("localhost", fx.rpcPort, "/ces/file/1", signer));
  BOOST_REQUIRE_EQUAL(serverRudpPeers(*fx.server), 1u);
  c.disconnect();
  BOOST_CHECK(serverRudpEmpties(*fx.server));
}

// A port where no server listens gives UNREACHABLE.
BOOST_AUTO_TEST_CASE(NoServerIsUnreachable) {
  uint16_t port = 0;
  {
    boost::asio::io_context io;
    boost::asio::ip::udp::socket s(
      io, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0));
    port = s.local_endpoint().port();
  }
  ces::KeyPair signer;
  ces::CesPlexClient c;
  CES_CHECK_RC_EQ(c.connect("127.0.0.1", port, "/ces/file/1", signer),
                  CES_ERROR_UNREACHABLE);
}

// A verb on a channel that ended gives CONNECTION_LOST. The next verb opens a
// new channel and signs for it.
BOOST_AUTO_TEST_CASE(VerbOnAnEndedChannelIsConnectionLost) {
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::KeyPair signer;
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();
  const minx::SockAddr to(boost::asio::ip::address_v6::loopback(), fx.rpcPort);
  ces::CesPlexChannel ch(peer.taskIO(), peer.rudp());
  CES_REQUIRE_OK(ch.select(to, "/ces/file/1", signer));
  ch.close();
  CES_CHECK_RC_EQ(statMissing(ch), CES_ERROR_CONNECTION_LOST);
  CES_CHECK_RC_EQ(statMissing(ch), CES_ERROR_FILE_NOT_FOUND);
}

// A verb that cannot open a new channel gives UNREACHABLE, also when the
// envelope tried to open it first.
BOOST_AUTO_TEST_CASE(VerbWithNoServerLeftIsUnreachable) {
  CesPlexFixture fx({ {"/ces/file/1", "builtin:file"} });
  PlexTestPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  ces::KeyPair signer;
  fx.server->_brr(signer.getPublicKeyAsHash(), 10'000'000'000);
  fx.server->_drainLogic();
  const minx::SockAddr to(boost::asio::ip::address_v6::loopback(), fx.rpcPort);
  ces::CesPlexChannel ch(peer.taskIO(), peer.rudp());
  CES_REQUIRE_OK(ch.select(to, "/ces/file/1", signer));
  ch.close();
  CES_CHECK_RC_EQ(statMissing(ch), CES_ERROR_CONNECTION_LOST);
  fx.server->stop(false);
  fx.server.reset();
  CES_CHECK_RC_EQ(statMissing(ch), CES_ERROR_UNREACHABLE);
}

BOOST_AUTO_TEST_SUITE_END()
