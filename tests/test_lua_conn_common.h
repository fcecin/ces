// ===========================================================================
// Shared harness — in-process peer for /ces/lua/1 channel routing tests.
// ===========================================================================
//
// PlexLuaPeer (the in-process bind/attach/byte-pipe peer), LuaConnFixture
// (server + real cesluajitd), and the peer I/O helpers. Included by
// test_lua_conn.cpp (the /ces/lua/1 routing suite) and test_dice_lua.cpp
// (the /s/dice.lua program suite).
//
// Exercises the wire path that lets an external user open a signed,
// bound RUDP channel to a running cesluajitd Lua program.
//
// Wire shape after the bind handshake (the bind itself is covered by
// test_cesplex.cpp):
//
//   Client → Server (ATTACH):
//     [u8 verb=0x01][u32 BE preamble_len=8][preamble][65 sig]
//     preamble = [u64 pid]
//     sig over sha256(verb || preamble || sessionToken)
//
//   Server → Client (ATTACH reply):
//     [u8 status]
//     [u64 conn_id BE]   (only when status == CES_OK)
//     [u64 time_us BE][u64 req_sig_hash BE][32 sha256][65 sig]
//
//   On OK, the channel is in DATA mode — raw byte stream both ways.
//
// Tests use a real cesluajitd child. The "user" side is an in-process
// Minx + Rudp peer that drives a single bound channel.

#pragma once

#include "test_common.h"
#include "test_e2e_common.h"

#include <ces/l2/compute_client.h>
#include <ces/buffer.h>
#include <ces/l2/file_client.h>
#include <ces/cesplex/mux.h>
#include <ces/l2/compute_handler.h>
#include <ces/l2/file_handler.h>
#include <ces/l2/compute_lua_handler.h>
#include <ces/ramfilestore.h>
#include <ces/cesplex/wire.h>
#include <ces/server.h>
#include <ces/types.h>

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

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace ces;

namespace {

uint64_t nowMicros() {
  return static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count());
}

// All BE serialization goes through ces::Buffer (see ces/buffer.h).

// ---------------------------------------------------------------------------
// PlexLuaPeer — outbound-only Minx + Rudp that opens a single channel,
// runs the signed bind handshake, and drives ATTACH + raw byte I/O.
// ---------------------------------------------------------------------------

class NoopMinxListener : public minx::MinxListener {};

class PeerRudpListener : public minx::Rudp::Listener {
public:
  void setMinx(minx::Minx* m) { minx_ = m; }
  void onSend(const minx::SockAddr& peer,
              const minx::Bytes& bytes) override {
    if (!minx_) return;
    try { minx_->sendExtension(peer, bytes); }
    catch (const std::exception&) { /* socket closed during teardown */ }
  }
private:
  minx::Minx* minx_ = nullptr;
};

class PlexLuaPeer {
public:
  PlexLuaPeer() = default;
  ~PlexLuaPeer() { stop(); }

  uint16_t start() {
    minx_ = std::make_unique<minx::Minx>(
      &listener_, minx::MinxConfig{
        .instanceName = "lcp",
        .randomXVMsToKeep = 0,
        .randomXInitThreads = 0,
        .trustLoopback = true});

    rudpListener_.setMinx(minx_.get());
    rudp_ = std::make_unique<minx::Rudp>(&rudpListener_);

    minx::MinxStdExtensions stdExt;
    stdExt.registerExtension(
      minx::Rudp::KEY_V0,
      [this](const minx::SockAddr& peer, uint64_t key,
             const minx::Bytes& payload) {
        if (rudp_) rudp_->onPacket(peer, key, payload, nowMicros());
      });
    minx_->setExtensionHandler(std::move(stdExt).build());

    port_ = minx_->openSocket(
      boost::asio::ip::address_v6::loopback(), 0, netIO_, taskIO_);
    if (port_ == 0) return 0;

    netGuard_ = std::make_unique<WG>(netIO_.get_executor());
    taskGuard_ = std::make_unique<WG>(taskIO_.get_executor());
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

  // Open a channel to (loopback, targetPort), do the signed select for
  // /ces/lua/1, return the bound sessionToken (and the underlying
  // RudpStream via stream()).
  bool bind(uint16_t targetPort, const KeyPair& signer,
            uint64_t& sessionToken,
            std::chrono::milliseconds timeout =
              std::chrono::seconds(3)) {
    currentPeer_ = minx::SockAddr(
      boost::asio::ip::address_v6::loopback(), targetPort);
    currentChannel_ = 1;

    auto done = std::make_shared<std::atomic<bool>>(false);
    auto ok = std::make_shared<std::atomic<bool>>(false);
    auto tok = std::make_shared<std::atomic<uint64_t>>(0);
    auto mu = std::make_shared<std::mutex>();
    auto cv = std::make_shared<std::condition_variable>();

    boost::asio::post(taskIO_, [this, &signer, done, ok, tok, mu, cv]() {
      rudp_->tick(nowMicros());
      stream_ = std::make_shared<minx::RudpStream>(
        taskIO_.get_executor());
      if (!rudp_->registerChannel(
            currentPeer_, currentChannel_, stream_)) {
        finishBind(done, mu, cv);
        return;
      }

      const uint64_t bindNowUs = nowMicros();
      const std::string name = "/ces/lua/1";
      auto bindReq = std::make_shared<minx::Bytes>(
        ces::buildBindRequest(name, bindNowUs, signer));
      boost::asio::async_write(
        *stream_, boost::asio::buffer(*bindReq),
        [this, bindReq, done, ok, tok, mu, cv]
        (const boost::system::error_code& ec, std::size_t) {
          if (ec) { finishBind(done, mu, cv); return; }
          auto reply = std::make_shared<
            std::array<uint8_t, ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE>>();
          boost::asio::async_read(
            *stream_, boost::asio::buffer(*reply),
            [reply, done, ok, tok, mu, cv]
            (const boost::system::error_code& ec2, std::size_t) {
              if (ec2 || (*reply)[0] != ces::CES_PLEX_OK) {
                finishBind(done, mu, cv);
                return;
              }
              // sessionToken is at offset 1 + 8 (time) + 32 (pubkey).
              uint64_t st = ces::Buffer::peek<uint64_t>(reply->data() + 1 + 8 + 32);
              ok->store(true);
              tok->store(st);
              finishBind(done, mu, cv);
            });
        });
    });

    std::unique_lock<std::mutex> lk(*mu);
    if (!cv->wait_for(lk, timeout, [&]() { return done->load(); }))
      return false;
    sessionToken = tok->load();
    return ok->load();
  }

  // Send the ATTACH verb and read the (fixed-shape) reply.
  // Returns the status byte and (on CES_OK) the conn_id.
  struct AttachResult {
    uint8_t status = 0xFF;
    uint64_t connId = 0;
  };

  AttachResult attach(const KeyPair& signer,
                      uint64_t sessionToken,
                      uint64_t pid,
                      std::chrono::milliseconds timeout =
                        std::chrono::seconds(3)) {
    // Build preamble = [u64 pid].
    ces::Bytes preamble;
    ces::Buffer::put<uint64_t>(preamble, pid);

    constexpr uint8_t kVerbAttach = 0x01;
    ces::Signature sig = ces::signPerOp(
      signer, kVerbAttach,
      std::span<const uint8_t>(preamble.data(), preamble.size()),
      sessionToken);

    ces::Bytes wire;
    wire.push_back(kVerbAttach);
    ces::Buffer::put<uint32_t>(wire, static_cast<uint32_t>(preamble.size()));
    wire.insert(wire.end(), preamble.begin(), preamble.end());
    wire.insert(wire.end(), sig.begin(), sig.end());

    auto done = std::make_shared<std::atomic<bool>>(false);
    auto result = std::make_shared<AttachResult>();
    auto mu = std::make_shared<std::mutex>();
    auto cv = std::make_shared<std::condition_variable>();
    auto wireBuf = std::make_shared<ces::Bytes>(std::move(wire));

    boost::asio::post(taskIO_, [this, wireBuf, done, result, mu, cv]() {
      boost::asio::async_write(
        *stream_, boost::asio::buffer(*wireBuf),
        [this, wireBuf, done, result, mu, cv]
        (const boost::system::error_code& ec, std::size_t) {
          if (ec) {
            finishAttach(done, mu, cv);
            return;
          }
          // Read just the 1-byte status first; the trailing shape
          // depends on whether status == CES_OK.
          auto stBuf = std::make_shared<std::array<uint8_t, 1>>();
          boost::asio::async_read(
            *stream_, boost::asio::buffer(*stBuf),
            [this, stBuf, done, result, mu, cv]
            (const boost::system::error_code& ec2, std::size_t) {
              if (ec2) { finishAttach(done, mu, cv); return; }
              uint8_t status = (*stBuf)[0];
              result->status = status;
              // Tail: [u64 time][u64 req_sig_hash][32 sha256][65 sig]
              //       + (8 conn_id only on OK).
              const std::size_t okExtra = (status == CES_OK) ? 8 : 0;
              const std::size_t tailLen = okExtra + 8 + 8 + 32 + 65;
              auto tail = std::make_shared<ces::Bytes>(tailLen);
              boost::asio::async_read(
                *stream_, boost::asio::buffer(*tail),
                [tail, status, done, result, mu, cv]
                (const boost::system::error_code& ec3, std::size_t) {
                  if (ec3) { finishAttach(done, mu, cv); return; }
                  if (status == CES_OK) {
                    result->connId = ces::Buffer::peek<uint64_t>(tail->data());
                  }
                  finishAttach(done, mu, cv);
                });
            });
        });
    });

    std::unique_lock<std::mutex> lk(*mu);
    cv->wait_for(lk, timeout, [&]() { return done->load(); });
    return *result;
  }

  // After ATTACH OK, raw bytes flow both ways. Send + read primitives
  // are exposed here; tests post them to taskIO_.

  std::shared_ptr<minx::RudpStream> stream() const { return stream_; }
  boost::asio::io_context& taskIO() { return taskIO_; }

  // Explicitly close the bound stream from the user side. Emits
  // HS_CLOSE so the server's read loop errors out promptly (instead
  // of waiting for RUDP's 60-second idle GC). Must be called before
  // stop() / destruction; safe to call multiple times.
  void closeStream() {
    auto s = stream_;
    if (!s) return;
    boost::asio::post(taskIO_, [s]() {
      try { s->close(); } catch (...) { /* already closed */ }
    });
  }

private:
  using WG = boost::asio::executor_work_guard<
    boost::asio::io_context::executor_type>;

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

  static void finishBind(std::shared_ptr<std::atomic<bool>> done,
                         std::shared_ptr<std::mutex> mu,
                         std::shared_ptr<std::condition_variable> cv) {
    {
      std::lock_guard<std::mutex> lk(*mu);
      done->store(true);
    }
    cv->notify_all();
  }

  static void finishAttach(std::shared_ptr<std::atomic<bool>> done,
                           std::shared_ptr<std::mutex> mu,
                           std::shared_ptr<std::condition_variable> cv) {
    finishBind(done, mu, cv);
  }

  NoopMinxListener listener_;
  PeerRudpListener rudpListener_;
  std::unique_ptr<minx::Minx> minx_;
  std::unique_ptr<minx::Rudp> rudp_;
  boost::asio::io_context netIO_;
  boost::asio::io_context taskIO_;
  std::unique_ptr<WG> netGuard_;
  std::unique_ptr<WG> taskGuard_;
  std::thread netThread_;
  std::thread taskThread_;
  std::shared_ptr<boost::asio::steady_timer> tickTimer_;
  uint16_t port_ = 0;

  minx::SockAddr currentPeer_;
  uint32_t currentChannel_ = 0;
  std::shared_ptr<minx::RudpStream> stream_;
};

// ---------------------------------------------------------------------------
// LuaConnFixture — server with /ces/file + /ces/compute + /ces/lua mounted,
// plus a real cesluajitd.
// ---------------------------------------------------------------------------

struct LuaConnFixture {
  std::unique_ptr<CesServer> server;
  fs::path tempDir;
  uint16_t serverPort = 0;
  uint16_t rpcPort = 0;
  std::string luajitBin;
  KeyPair ownerKey;
  KeyPair userKey;

  LuaConnFixture() {
    blog::init();
    blog::set_level(blog::fatal);
    blog::set_level("plex", blog::fatal);
    blog::set_level("lua", blog::fatal);

    tempDir = makeUniqueTempDir("lua_conn");

    minx::Hash serverPriv;
    serverPriv.fill(0xCD);

    CesConfig cfg = makeTestConfig(
      tempDir, serverPriv, std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = {
      {"/ces/file/1",    "builtin:file"},
      {"/ces/compute/1", "builtin:compute"},
      {"/ces/lua/1",     "builtin:lua"},
    };
    cfg.cesFileStoreMaxBytes = 16ull * 1024 * 1024;
    cfg.feeFileRent = 1;

    cfg.computeMaxInstances = 4;
    cfg.feeComputeSlotSec = 1;
    luajitBin = ces::e2e::findBinary("cesluajitd");
    cfg.cesComputeChildBinary = luajitBin;
    cfg.cesComputeUser = "";
    cfg.cesComputeWorkDir = (tempDir / "cescompute").string();

    server = std::make_unique<CesServer>(cfg);
    serverPort = server->start(0);
    BOOST_REQUIRE_MESSAGE(serverPort > 0, "server port bind failed");
    rpcPort = server->_rpcBoundPort();
    BOOST_REQUIRE_MESSAGE(rpcPort > 0, "rpc port bind failed");

    server->_brr(ownerKey.getPublicKeyAsHash(), 10'000'000'000);
    server->_brr(userKey.getPublicKeyAsHash(),  10'000'000'000);
    server->_drainLogic();
  }

  ~LuaConnFixture() {
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }

  void uploadScript(const std::string& path,
                    const std::string& source) {
    CesFileClient fc;
    fc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(fc.connect("localhost", rpcPort, ownerKey));
    uint64_t bal = 0, cost = 0;
    CES_REQUIRE_OK(fc.create(
      path, /*size=*/source.size(),
      /*pricePerKb=*/0,
      /*initialDeposit=*/100'000'000ULL,
      bal, cost));
    ces::Bytes content(source.begin(), source.end());
    CES_REQUIRE_OK(fc.write(path, /*offset=*/0, content, bal));
    fc.disconnect();
  }

  uint64_t launchScript(const std::string& path) {
    CesComputeClient cc;
    cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));
    uint64_t instId = 0, startedAt = 0;
    CES_REQUIRE_OK(cc.launch(path, instId, startedAt));
    cc.disconnect();
    return instId;
  }
};

// Async write/read helpers driven on the peer's taskIO.

bool peerWrite(PlexLuaPeer& peer, const ces::Bytes& data,
               std::chrono::milliseconds timeout = std::chrono::seconds(3)) {
  auto done = std::make_shared<std::atomic<bool>>(false);
  auto ok = std::make_shared<std::atomic<bool>>(false);
  auto mu = std::make_shared<std::mutex>();
  auto cv = std::make_shared<std::condition_variable>();
  auto buf = std::make_shared<ces::Bytes>(data);
  auto stream = peer.stream();
  boost::asio::post(peer.taskIO(), [stream, buf, done, ok, mu, cv]() {
    boost::asio::async_write(
      *stream, boost::asio::buffer(*buf),
      [buf, done, ok, mu, cv]
      (const boost::system::error_code& ec, std::size_t) {
        if (!ec) ok->store(true);
        {
          std::lock_guard<std::mutex> lk(*mu);
          done->store(true);
        }
        cv->notify_all();
      });
  });
  std::unique_lock<std::mutex> lk(*mu);
  cv->wait_for(lk, timeout, [&]() { return done->load(); });
  return ok->load();
}

bool peerReadExact(PlexLuaPeer& peer, ces::Bytes& out, std::size_t n,
                   std::chrono::milliseconds timeout = std::chrono::seconds(3)) {
  out.assign(n, 0);
  auto done = std::make_shared<std::atomic<bool>>(false);
  auto ok = std::make_shared<std::atomic<bool>>(false);
  auto mu = std::make_shared<std::mutex>();
  auto cv = std::make_shared<std::condition_variable>();
  auto stream = peer.stream();
  // Buffer pointer is stable for the duration of the wait, since out
  // is not resized while async_read runs.
  boost::asio::post(peer.taskIO(),
    [stream, &out, n, done, ok, mu, cv]() {
      boost::asio::async_read(
        *stream, boost::asio::buffer(out.data(), n),
        [done, ok, mu, cv]
        (const boost::system::error_code& ec, std::size_t) {
          if (!ec) ok->store(true);
          {
            std::lock_guard<std::mutex> lk(*mu);
            done->store(true);
          }
          cv->notify_all();
        });
    });
  std::unique_lock<std::mutex> lk(*mu);
  cv->wait_for(lk, timeout, [&]() { return done->load(); });
  return ok->load();
}

// Read whatever bytes are currently available (one async_read_some), up to
// maxN. Returns the count read (0 on timeout/error). Unlike peerReadExact it
// does not block for a fixed length — used to drive a line-oriented reader
// over a program that emits variable-length text (greeting + command replies).
inline std::size_t peerReadSome(
    PlexLuaPeer& peer, ces::Bytes& out, std::size_t maxN,
    std::chrono::milliseconds timeout = std::chrono::seconds(3)) {
  auto buf = std::make_shared<ces::Bytes>(maxN, 0);
  auto done = std::make_shared<std::atomic<bool>>(false);
  auto got = std::make_shared<std::atomic<std::size_t>>(0);
  auto mu = std::make_shared<std::mutex>();
  auto cv = std::make_shared<std::condition_variable>();
  auto stream = peer.stream();
  boost::asio::post(peer.taskIO(), [stream, buf, maxN, done, got, mu, cv]() {
    stream->async_read_some(
      boost::asio::buffer(buf->data(), maxN),
      [buf, done, got, mu, cv]
      (const boost::system::error_code& ec, std::size_t n) {
        if (!ec) got->store(n);
        {
          std::lock_guard<std::mutex> lk(*mu);
          done->store(true);
        }
        cv->notify_all();
      });
  });
  std::unique_lock<std::mutex> lk(*mu);
  cv->wait_for(lk, timeout, [&]() { return done->load(); });
  std::size_t n = got->load();
  out.assign(buf->begin(), buf->begin() + n);
  return n;
}

// Line-buffered reader over a PlexLuaPeer in DATA mode. Accumulates raw bytes
// and hands back one '\n'-terminated line at a time — the natural grain for a
// line-REPL program like /s/dice.lua.
struct PlexLineReader {
  PlexLuaPeer& peer;
  std::string buf;

  explicit PlexLineReader(PlexLuaPeer& p) : peer(p) {}

  // Next complete line (newline stripped), or "" on timeout.
  std::string nextLine(std::chrono::milliseconds timeout =
                         std::chrono::seconds(5)) {
    using clk = std::chrono::steady_clock;
    const auto deadline = clk::now() + timeout;
    for (;;) {
      auto nl = buf.find('\n');
      if (nl != std::string::npos) {
        std::string line = buf.substr(0, nl);
        buf.erase(0, nl + 1);
        return line;
      }
      if (clk::now() >= deadline) return "";
      ces::Bytes chunk;
      std::size_t n = peerReadSome(peer, chunk, 4096,
                                   std::chrono::milliseconds(500));
      if (n) buf.append(reinterpret_cast<const char*>(chunk.data()), n);
    }
  }

  // Read lines until one contains `needle`; return that line (or "" on
  // timeout). Lets a test skip the greeting and land on the reply it cares
  // about.
  std::string lineContaining(const std::string& needle,
                             std::chrono::milliseconds timeout =
                               std::chrono::seconds(5)) {
    using clk = std::chrono::steady_clock;
    const auto deadline = clk::now() + timeout;
    for (;;) {
      std::string line = nextLine(timeout);
      if (line.find(needle) != std::string::npos) return line;
      if (line.empty() && clk::now() >= deadline) return "";
    }
  }
};

} // namespace
