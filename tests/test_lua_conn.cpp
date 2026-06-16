// ===========================================================================
// builtin:lua — /ces/lua/1 user RUDP connection routing.
// ===========================================================================
//
// Exercises the wire path that lets an external user open a signed,
// bound RUDP channel to a running cesluajitd Lua program.
//
// Wire shape after the bind handshake (the bind itself is covered by
// test_cesplex.cpp):
//
//   Client → Server (ATTACH):
//     [u8 verb=0x01][u32 BE preamble_len=8][preamble][65 sig]
//     preamble = [u64 instance_id]
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

#define BOOST_TEST_DYN_LINK
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
                      uint64_t instanceId,
                      std::chrono::milliseconds timeout =
                        std::chrono::seconds(3)) {
    // Build preamble = [u64 instance_id].
    ces::Bytes preamble;
    ces::Buffer::put<uint64_t>(preamble, instanceId);

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
    wait_net();
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

} // namespace

BOOST_FIXTURE_TEST_SUITE(LuaConnTests, LuaConnFixture)

// ATTACH must fail with CES_ERROR_NOT_LISTENING when the program never
// called ces.conn.set_listener — the per-instance accept gate defaults
// OFF.
BOOST_AUTO_TEST_CASE(AttachRequiresListener) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/silent.lua";
  // No set_listener: just block on ces.client_recv so the process stays
  // alive while we attempt an ATTACH against it.
  const std::string src =
    "while true do\n"
    "  local pfx, msg = ces.client_recv()\n"
    "  if not pfx then break end\n"
    "end\n";
  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  // Let the child reach ces.client_recv (ensures it's running, not
  // that the gate would change — gate stays OFF either way).
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  uint64_t sessionToken = 0;
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, sessionToken));

  auto r = peer.attach(userKey, sessionToken, instId);
  CES_CHECK_RC_EQ(r.status, CES_ERROR_NOT_LISTENING);
}

// Round-trip: program calls set_listener({on_data = echo}) + run().
// User attaches, sends "ping", reads "ping" back from on_data → conn:write.
BOOST_AUTO_TEST_CASE(EchoRoundTrip) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/echo_conn.lua";
  const std::string src =
    "ces.conn.set_listener({\n"
    "  on_data = function(conn, data) conn:write(data) end,\n"
    "})\n"
    "ces.conn.run()\n";
  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  // Give the child time to install set_listener (which sends the
  // TAG_LISTEN_ON IPC frame the supervisor needs to flip
  // acceptsConnections=true).
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  uint64_t sessionToken = 0;
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, sessionToken));

  auto r = peer.attach(userKey, sessionToken, instId);
  CES_REQUIRE_RC_EQ(r.status, CES_OK);
  BOOST_CHECK(r.connId > 0);

  // Channel is now in DATA mode. Send "ping", expect "ping" back.
  const std::string msg = "ping";
  ces::Bytes wire(msg.begin(), msg.end());
  BOOST_REQUIRE(peerWrite(peer, wire));
  ces::Bytes echoed;
  BOOST_REQUIRE(peerReadExact(peer, echoed, msg.size(),
                              std::chrono::seconds(5)));
  std::string got(echoed.begin(), echoed.end());
  BOOST_CHECK_EQUAL(got, msg);
}

// on_open fires with the bound user pubkey on conn.pubkey. Program
// writes "open:" + 32 raw bytes back as soon as on_open lands.
BOOST_AUTO_TEST_CASE(OnOpenFiresWithBoundPubkey) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/open_pk.lua";
  const std::string src =
    "ces.conn.set_listener({\n"
    "  on_open = function(conn) conn:write('open:' .. conn.pubkey) end,\n"
    "})\n"
    "ces.conn.run()\n";
  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  uint64_t sessionToken = 0;
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, sessionToken));
  auto r = peer.attach(userKey, sessionToken, instId);
  CES_REQUIRE_RC_EQ(r.status, CES_OK);

  ces::Bytes got;
  BOOST_REQUIRE(peerReadExact(peer, got, 5 + 32,
                              std::chrono::seconds(5)));
  BOOST_CHECK(std::memcmp(got.data(), "open:", 5) == 0);
  const auto& expectedPk = userKey.getPublicKeyAsHash();
  BOOST_CHECK(std::memcmp(got.data() + 5, expectedPk.data(), 32) == 0);
}

// Bursty bidirectional echo — on_data fires 10 conn:writes per call.
// Without the per-conn write queue, two of those async_writes would
// race on the same RudpStream and the user side would either error or
// see corrupted ordering.
BOOST_AUTO_TEST_CASE(BurstyBidirectionalEcho) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/burst.lua";
  const std::string src =
    "ces.conn.set_listener({\n"
    "  on_data = function(conn, _)\n"
    "    for i = 0, 9 do\n"
    "      conn:write(string.format('c%02d', i))\n"
    "    end\n"
    "  end,\n"
    "})\n"
    "ces.conn.run()\n";
  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  uint64_t sessionToken = 0;
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, sessionToken));
  auto r = peer.attach(userKey, sessionToken, instId);
  CES_REQUIRE_RC_EQ(r.status, CES_OK);

  // One inbound byte triggers ten outbound writes.
  BOOST_REQUIRE(peerWrite(peer, ces::Bytes{'x'}));
  ces::Bytes got;
  BOOST_REQUIRE(peerReadExact(peer, got, 30, std::chrono::seconds(5)));
  std::string s(got.begin(), got.end());
  // Strict ordering: c00..c09 in sequence.
  BOOST_CHECK_EQUAL(s, "c00c01c02c03c04c05c06c07c08c09");
}

// Lua program calls conn:close() inside on_data. The user-side stream
// must die cleanly (any subsequent peerReadExact errors).
BOOST_AUTO_TEST_CASE(ProgramCloseTearsDownUserChannel) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/prog_close.lua";
  const std::string src =
    "ces.conn.set_listener({\n"
    "  on_data = function(conn, _)\n"
    "    conn:write('bye')\n"
    "    conn:close()\n"
    "  end,\n"
    "})\n"
    "ces.conn.run()\n";
  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  uint64_t sessionToken = 0;
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, sessionToken));
  auto r = peer.attach(userKey, sessionToken, instId);
  CES_REQUIRE_RC_EQ(r.status, CES_OK);

  BOOST_REQUIRE(peerWrite(peer, ces::Bytes{'x'}));
  ces::Bytes got;
  BOOST_REQUIRE(peerReadExact(peer, got, 3, std::chrono::seconds(5)));
  BOOST_CHECK_EQUAL(std::string(got.begin(), got.end()), "bye");

  // Subsequent reads must fail — the channel is gone.
  ces::Bytes after;
  BOOST_CHECK(!peerReadExact(peer, after, 1, std::chrono::seconds(2)));
}

// Helper: poll a file's content via the file-handler client until it
// reaches `expectedBytes` (up to `timeout`). Returns the final content.
inline ces::Bytes pollFileContent(
    LuaConnFixture& fx, const std::string& path,
    std::size_t expectedBytes,
    std::chrono::milliseconds timeout = std::chrono::seconds(5)) {
  using clk = std::chrono::steady_clock;
  const auto deadline = clk::now() + timeout;
  CesFileClient fc;
  fc.setServerPubkey(fx.server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(fc.connect("localhost", fx.rpcPort, fx.ownerKey));
  ces::Bytes data;
  while (clk::now() < deadline) {
    CesFileClient::StatInfo info;
    if (fc.stat(path, info) == CES_OK && info.size >= expectedBytes) {
      minx::Hash _h{};
      uint8_t rc = fc.read(path, /*offset=*/0,
                           static_cast<uint32_t>(info.size), data, _h);
      if (rc == CES_OK) {
        fc.disconnect();
        return data;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  fc.disconnect();
  return data;
}

// User-side stream close fires on_close in the program. Program logs
// the event into a side file via ces.file_append; test reads it.
BOOST_AUTO_TEST_CASE(OnCloseFiresOnUserClose) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/uclose.lua";
  const std::string logPath    = "/h/" + ownerHex + "/uclose.log";
  const std::string src =
    "local logp = '" + logPath + "'\n"
    "ces.file_create(logp, 1024, 0, 5000000, 'text/plain')\n"
    "ces.conn.set_listener({\n"
    "  on_close = function(_) ces.file_append(logp, 'closed') end,\n"
    "})\n"
    "ces.conn.run()\n";
  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  std::this_thread::sleep_for(std::chrono::milliseconds(400));

  {
    PlexLuaPeer peer;
    BOOST_REQUIRE(peer.start() != 0);
    uint64_t sessionToken = 0;
    BOOST_REQUIRE(peer.bind(rpcPort, userKey, sessionToken));
    auto r = peer.attach(userKey, sessionToken, instId);
    CES_REQUIRE_RC_EQ(r.status, CES_OK);
    // Explicit close emits HS_CLOSE so the server's dataReadLoop
    // errors out immediately (instead of waiting for RUDP idle GC),
    // which fires computeSendConnClosed → on_close in the program.
    peer.closeStream();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }

  auto data = pollFileContent(*this, logPath,
                              /*expectedBytes=*/1024 + 6);
  // The file is sparse-prefilled with 1024 zero bytes; "closed" is
  // appended past that (offset = original size).
  BOOST_REQUIRE_GE(data.size(), 1024u + 6u);
  std::string tail(data.end() - 6, data.end());
  BOOST_CHECK_EQUAL(tail, "closed");
}

// SIGKILLing the cesluajitd child cascades through the supervisor's
// luaHandlerOnInstanceDying: every routed connection is dropped. The
// user side observes its stream die.
BOOST_AUTO_TEST_CASE(InstanceDyingCascadesToUser) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/dying.lua";
  const std::string src =
    "ces.conn.set_listener({})\n"
    "ces.conn.run()\n";
  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  uint64_t sessionToken = 0;
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, sessionToken));
  auto r = peer.attach(userKey, sessionToken, instId);
  CES_REQUIRE_RC_EQ(r.status, CES_OK);

  // Kill the instance via the compute client (separate channel).
  {
    CesComputeClient cc;
    cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));
    CES_REQUIRE_OK(cc.kill(instId));
    cc.disconnect();
  }

  // The user's stream must error within a reasonable window.
  ces::Bytes after;
  BOOST_CHECK(!peerReadExact(peer, after, 1, std::chrono::seconds(3)));
}

// Two independent ATTACHes from the same user → distinct conn_ids,
// each with its own (instId, connId) routing entry. Both echo
// independently.
BOOST_AUTO_TEST_CASE(MultipleConnsSameUser) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/many.lua";
  const std::string src =
    "ces.conn.set_listener({\n"
    "  on_data = function(conn, data)\n"
    "    conn:write(string.format('%d:%s', conn.id, data))\n"
    "  end,\n"
    "})\n"
    "ces.conn.run()\n";
  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  PlexLuaPeer p1, p2;
  BOOST_REQUIRE(p1.start() != 0);
  BOOST_REQUIRE(p2.start() != 0);
  uint64_t st1 = 0, st2 = 0;
  BOOST_REQUIRE(p1.bind(rpcPort, userKey, st1));
  BOOST_REQUIRE(p2.bind(rpcPort, userKey, st2));
  auto r1 = p1.attach(userKey, st1, instId);
  auto r2 = p2.attach(userKey, st2, instId);
  CES_REQUIRE_RC_EQ(r1.status, CES_OK);
  CES_REQUIRE_RC_EQ(r2.status, CES_OK);
  BOOST_REQUIRE_NE(r1.connId, r2.connId);

  BOOST_REQUIRE(peerWrite(p1, ces::Bytes{'A'}));
  BOOST_REQUIRE(peerWrite(p2, ces::Bytes{'B'}));
  // Reply size = ndigits(connId) + 1 (':') + 1 (data byte).
  auto expectedFor = [](uint64_t connId, char data) {
    return std::to_string(connId) + ":" + data;
  };
  const std::string e1 = expectedFor(r1.connId, 'A');
  const std::string e2 = expectedFor(r2.connId, 'B');
  ces::Bytes g1, g2;
  BOOST_REQUIRE(peerReadExact(p1, g1, e1.size()));
  BOOST_REQUIRE(peerReadExact(p2, g2, e2.size()));
  BOOST_CHECK_EQUAL(std::string(g1.begin(), g1.end()), e1);
  BOOST_CHECK_EQUAL(std::string(g2.begin(), g2.end()), e2);
}

// Two ATTACHes from two different users → conn.pubkey distinct on
// the program side, both echo independently.
BOOST_AUTO_TEST_CASE(MultipleConnsMultipleUsers) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/mu.lua";
  const std::string src =
    "ces.conn.set_listener({\n"
    "  on_data = function(conn, data)\n"
    "    conn:write(conn.pubkey:sub(1, 4) .. ':' .. data)\n"
    "  end,\n"
    "})\n"
    "ces.conn.run()\n";
  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  KeyPair u2;
  server->_brr(u2.getPublicKeyAsHash(), 10'000'000'000);

  PlexLuaPeer p1, p2;
  BOOST_REQUIRE(p1.start() != 0);
  BOOST_REQUIRE(p2.start() != 0);
  uint64_t st1 = 0, st2 = 0;
  BOOST_REQUIRE(p1.bind(rpcPort, userKey, st1));
  BOOST_REQUIRE(p2.bind(rpcPort, u2,      st2));
  CES_REQUIRE_RC_EQ(p1.attach(userKey, st1, instId).status, CES_OK);
  CES_REQUIRE_RC_EQ(p2.attach(u2,      st2, instId).status, CES_OK);

  BOOST_REQUIRE(peerWrite(p1, ces::Bytes{'A'}));
  BOOST_REQUIRE(peerWrite(p2, ces::Bytes{'B'}));
  ces::Bytes g1, g2;
  BOOST_REQUIRE(peerReadExact(p1, g1, 4 + 1 + 1));
  BOOST_REQUIRE(peerReadExact(p2, g2, 4 + 1 + 1));
  // First 4 bytes of p1's reply == first 4 bytes of userKey's pubkey.
  // First 4 bytes of p2's reply == first 4 bytes of u2's pubkey.
  const auto& pk1 = userKey.getPublicKeyAsHash();
  const auto& pk2 = u2.getPublicKeyAsHash();
  BOOST_CHECK(std::memcmp(g1.data(), pk1.data(), 4) == 0);
  BOOST_CHECK_EQUAL(g1[4], ':');
  BOOST_CHECK_EQUAL(g1[5], 'A');
  BOOST_CHECK(std::memcmp(g2.data(), pk2.data(), 4) == 0);
  BOOST_CHECK_EQUAL(g2[4], ':');
  BOOST_CHECK_EQUAL(g2[5], 'B');
}

// ATTACH for an instance_id that isn't registered →
// CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND. Covers both "id was never
// minted" and id=0 (gNextInstanceId starts at 1).
BOOST_AUTO_TEST_CASE(AttachUnknownInstance) {
  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  uint64_t sessionToken = 0;
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, sessionToken));
  auto r = peer.attach(userKey, sessionToken, /*bogus*/ 99999ULL);
  CES_CHECK_RC_EQ(r.status, CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND);
}

// Bad sig on ATTACH → handler silently tears down the channel without
// replying. The user side observes timeout (no reply byte), confirming
// the verifyPerOp path on the server actually rejects forged sigs and
// drops the channel instead of admitting it.
BOOST_AUTO_TEST_CASE(AttachBadSigDropsChannel) {
  PlexLuaPeer peer;
  BOOST_REQUIRE(peer.start() != 0);
  uint64_t sessionToken = 0;
  BOOST_REQUIRE(peer.bind(rpcPort, userKey, sessionToken));

  // Build an ATTACH wire by hand with a deliberately wrong sig (signed
  // with a DIFFERENT key — passes shape checks but won't verify
  // against the channel's bound pubkey).
  KeyPair stranger;
  ces::Bytes preamble;
  ces::Buffer::put<uint64_t>(preamble, /*any id*/ 1ULL);

  constexpr uint8_t kVerbAttach = 0x01;
  ces::Signature badSig = ces::signPerOp(
    stranger, kVerbAttach,
    std::span<const uint8_t>(preamble.data(), preamble.size()),
    sessionToken);

  ces::Bytes wire;
  wire.push_back(kVerbAttach);
  ces::Buffer::put<uint32_t>(wire, static_cast<uint32_t>(preamble.size()));
  wire.insert(wire.end(), preamble.begin(), preamble.end());
  wire.insert(wire.end(), badSig.begin(), badSig.end());

  BOOST_REQUIRE(peerWrite(peer, wire));
  // No reply: the handler tears down silently. Reading any byte
  // within 1 s must fail.
  ces::Bytes out;
  BOOST_CHECK(!peerReadExact(peer, out, 1, std::chrono::seconds(1)));
}

// set_listener(nil) flips the per-instance accept gate OFF. New
// ATTACHes get CES_ERROR_NOT_LISTENING. The existing channel is NOT
// torn down — the user can still write to it and the channel stays
// open — but on_data won't fire (no listener installed), so bytes
// silently disappear at the Lua layer until set_listener is called
// again with a non-nil handler.
BOOST_AUTO_TEST_CASE(SetListenerNilFlipsGateOff) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/toggle.lua";
  const std::string src =
    "ces.conn.set_listener({\n"
    "  on_data = function(conn, data)\n"
    "    if data == 'OFF' then\n"
    "      ces.conn.set_listener(nil)\n"
    "      conn:write('off')\n"
    "    else\n"
    "      conn:write(data)\n"
    "    end\n"
    "  end,\n"
    "})\n"
    "ces.conn.run()\n";
  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  std::this_thread::sleep_for(std::chrono::milliseconds(400));

  // First peer attaches successfully.
  PlexLuaPeer p1;
  BOOST_REQUIRE(p1.start() != 0);
  uint64_t st1 = 0;
  BOOST_REQUIRE(p1.bind(rpcPort, userKey, st1));
  CES_REQUIRE_RC_EQ(p1.attach(userKey, st1, instId).status, CES_OK);

  // Echo works (gate ON).
  BOOST_REQUIRE(peerWrite(p1, ces::Bytes{'h', 'i'}));
  ces::Bytes g1;
  BOOST_REQUIRE(peerReadExact(p1, g1, 2));
  BOOST_CHECK_EQUAL(std::string(g1.begin(), g1.end()), "hi");

  // Tell the program to flip the gate off + ack.
  BOOST_REQUIRE(peerWrite(p1, {'O', 'F', 'F'}));
  ces::Bytes ack;
  BOOST_REQUIRE(peerReadExact(p1, ack, 3));
  BOOST_CHECK_EQUAL(std::string(ack.begin(), ack.end()), "off");

  // New ATTACH must be rejected.
  PlexLuaPeer p2;
  BOOST_REQUIRE(p2.start() != 0);
  uint64_t st2 = 0;
  BOOST_REQUIRE(p2.bind(rpcPort, userKey, st2));
  auto r2 = p2.attach(userKey, st2, instId);
  CES_CHECK_RC_EQ(r2.status, CES_ERROR_NOT_LISTENING);

  // Existing conn is alive but silent — write succeeds, but no
  // callback fires (listener registry slot is nil), so no echo.
  BOOST_REQUIRE(peerWrite(p1, {'!', '!'}));
  ces::Bytes g3;
  BOOST_CHECK(!peerReadExact(p1, g3, 2, std::chrono::seconds(1)));
}

BOOST_AUTO_TEST_SUITE_END()
