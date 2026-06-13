// ===========================================================================
// SYS_RPC end-to-end tests
// ===========================================================================
//
// These tests exercise the full outbound SYS_RPC path: a gateway VM
// program on a CesServer issues the syscall, the dispatcher opens an
// RUDP channel over the server's dedicated rpcMinx_, performs the
// CesPlex select handshake negotiating protocol "/ces/rpc/1", sends
// a signed envelope, receives a response from a MockRpcServer
// running inline in this file (on its own Minx + Rudp +
// io_context + thread), writes the response back into the same
// ramfile asset chain, and schedules a followup.
//
// Wire layout:
//
//   Outbound (CesServer → target):
//     [u16 BE 11]["/ces/rpc/1"]        CesPlex select
//     [u8 status]                       inbound — 0x01 OK / 0x00 NACK
//     [u32 BE body_len][body][137B footer]  signed envelope
//
//   Inbound (target → CesServer):
//     [u32 BE body_len][body][137B footer]  response envelope
//
// CesPlex wraps the rpc protocol identically to any other protocol
// on the secondary port — see include/ces/l2/net_multiplexer.h. A NACK (0x00)
// surfaces to the VM caller as CES_ERROR_PROTO_REJECTED; this is
// the "calling a CES server that doesn't serve rpc" path (CES
// servers are rpc clients, not rpc servers — per the asymmetric
// design).
//
// The mock server is deliberately not a CesServer — it's a bare
// minx::Minx + minx::Rudp + minx::RudpStream stack that implements the
// same wire protocol a (not-yet-existing) content-server binary would
// implement. Each test can plug a different transform
// function into the mock; the default is rot13DoubleTransform (append
// a copy of the request to itself, then ROT13 the lowercase ASCII
// letters). Tests can also override the mock's accepted CesPlex
// protocol name via setAcceptedProtoName to exercise the NACK path.
//
// What the tests verify:
//
//   - Small round-trip: 50-byte request → 100-byte response, single-
//     chunk request/response files.
//   - Large round-trip: 500-byte request → 1000-byte response,
//     multi-chunk files, exercising the response-write path that
//     walks through several chunks.
//   - DisabledWhenNoRpcPort: a CesServer with rpcPort=0 rejects
//     SYS_RPC with CES_ERROR_DISABLED before the dispatcher even
//     tries to reach the wire.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"

#include <ces/cesvm.h>
#include <ces/buffer.h>
#include <ces/ramfilestore.h>
#include <ces/keys.h>
#include <ces/l2/net_envelope.h>
#include <ces/server.h>
#include <ces/util/vmprogram.h>

#include <minx/minx.h>
#include <minx/rudp/rudp.h>
#include <minx/rudp/rudp_stream.h>
#include <minx/stdext.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <thread>
#include <vector>

// ---------------------------------------------------------------------------
// MockRpcServer — in-process RUDP endpoint for testing SYS_RPC
// ---------------------------------------------------------------------------

namespace {

static uint64_t mockNowMicros() {
  return static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count());
}

// Inbound-accepting Rudp::Listener for the MockRpcServer. Forwards
// onSend to the local Minx and delegates onAccept to the parent
// server, which constructs a per-channel Session+RudpStream.
class MockRpcServer;
class MockRpcRudpListener : public minx::Rudp::Listener {
public:
  void setMinx(minx::Minx* m) { minx_ = m; }
  void setOwner(MockRpcServer* o) { owner_ = o; }
  void onSend(const minx::SockAddr& peer,
              const minx::Bytes& bytes) override {
    if (!minx_) return;
    try {
      minx_->sendExtension(peer, bytes);
    } catch (const std::exception&) {
      // Socket already closed during teardown.
    }
  }
  std::shared_ptr<minx::Rudp::ChannelHandler>
  onAccept(const minx::SockAddr& peer, uint32_t channelId) override;
private:
  minx::Minx* minx_ = nullptr;
  MockRpcServer* owner_ = nullptr;
};

class MockRpcServer {
public:
  // Transform: takes the verified request body, returns the bytes to
  // send back as the response body.
  using Transform =
    std::function<ces::Bytes(const ces::Bytes&)>;

  explicit MockRpcServer(Transform transform)
    : transform_(std::move(transform)) {}

  ~MockRpcServer() { stop(); }

  // Which CesPlex protocol name this mock will accept on the select
  // handshake. Default "/ces/rpc/1" matches RpcSession (the outbound
  // side of SYS_RPC). Tests can set this to something else to
  // exercise the NACK path and verify the outbound side surfaces
  // CES_ERROR_PROTO_REJECTED.
  void setAcceptedProtoName(std::string name) {
    acceptedProtoName_ = std::move(name);
  }

  // Starts the mock server on an ephemeral port. Returns the bound
  // port on success, 0 on failure.
  uint16_t start() {
    minx_ = std::make_unique<minx::Minx>(
      &listener_, minx::MinxConfig{
        .instanceName = "mock",
        .randomXVMsToKeep = 0,
        .trustLoopback = true});

    rudpListener_.setMinx(minx_.get());
    rudpListener_.setOwner(this);
    rudp_ = std::make_unique<minx::Rudp>(&rudpListener_);

    {
      minx::MinxStdExtensions stdExt;
      stdExt.registerExtension(
        minx::Rudp::KEY_V0,
        [this](const minx::SockAddr& peer, uint64_t key,
               const minx::Bytes& payload) {
          if (rudp_) rudp_->onPacket(peer, key, payload, mockNowMicros());
        });
      minx_->setExtensionHandler(std::move(stdExt).build());
    }

    port_ = minx_->openSocket(
      boost::asio::ip::address_v6::loopback(), 0,  // 0 = ephemeral
      netIO_, taskIO_);
    if (port_ == 0) return 0;

    netThread_ = std::thread([this]() { netIO_.run(); });
    taskThread_ = std::thread([this]() { taskIO_.run(); });

    // Schedule the Rudp tick pulse.
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
    netIO_.stop();
    taskIO_.stop();
    if (netThread_.joinable()) netThread_.join();
    if (taskThread_.joinable()) taskThread_.join();
    sessions_.clear();
    tickTimer_.reset();
    rudp_.reset();
    minx_.reset();
    rudpListener_.setMinx(nullptr);
    rudpListener_.setOwner(nullptr);
    port_ = 0;
  }

  uint16_t port() const { return port_; }

private:
  // One inbound call. Wire shape:
  //   1. Read signed bind preamble (u16 name_len + name + 137-byte
  //      tail with time/pubkey/sha256/sig).
  //   2. Send signed bind reply (status + 84-byte body + 32 sha256 +
  //      65 sig). Mock signs with its own keypair.
  //   3. Read [u32 body_len][body bytes] (no per-rpc envelope).
  //   4. Apply transform_ to body, write [u32 len][body] back.
  struct Session : std::enable_shared_from_this<Session> {
    MockRpcServer& parent;
    minx::SockAddr peer;
    uint32_t channelId;
    std::shared_ptr<minx::RudpStream> stream;
    // Bind preamble = u16 name_len + name + 137-byte tail.
    std::array<uint8_t, 2> bindLenBuf{};
    ces::Bytes bindNameBuf;
    std::array<uint8_t, 8 + 32 + 32 + 65> bindTailBuf{};
    // Stash for the bind reply.
    std::array<uint8_t, ces::CES_PLEX_SHA256_SIZE> clientDigest{};
    minx::Bytes bindReplyBuf;
    // Then [u32 body_len][body], no per-rpc envelope.
    std::array<uint8_t, 4> lenBuf{};
    ces::Bytes bodyBuf;

    Session(MockRpcServer& p, const minx::SockAddr& pr, uint32_t ch,
            std::shared_ptr<minx::RudpStream> s)
      : parent(p), peer(pr), channelId(ch), stream(std::move(s)) {}

    void start() {
      readBindNameLen();
    }

    void readBindNameLen() {
      auto self = shared_from_this();
      boost::asio::async_read(
        *stream, boost::asio::buffer(bindLenBuf),
        [self](const boost::system::error_code& ec, std::size_t) {
          if (ec) { self->finish(); return; }
          const uint16_t nameLen =
            ces::Buffer::peek<uint16_t>(self->bindLenBuf.data());
          if (nameLen == 0 || nameLen > 256) {
            self->sendBindNackAndFinish();
            return;
          }
          self->bindNameBuf.resize(nameLen);
          self->readBindName();
        });
    }

    void readBindName() {
      auto self = shared_from_this();
      boost::asio::async_read(
        *stream, boost::asio::buffer(bindNameBuf),
        [self](const boost::system::error_code& ec, std::size_t) {
          if (ec) { self->finish(); return; }
          self->readBindTail();
        });
    }

    void readBindTail() {
      auto self = shared_from_this();
      boost::asio::async_read(
        *stream, boost::asio::buffer(bindTailBuf),
        [self](const boost::system::error_code& ec, std::size_t) {
          if (ec) { self->finish(); return; }
          // Tail = [u64 time_us][32 pubkey][32 sha256][65 sig].
          uint64_t clientTimeUs =
            ces::Buffer::peek<uint64_t>(self->bindTailBuf.data());
          // We don't verify the client's bind sig in this mock —
          // SYS_RPC tests aren't about server-side bind validation;
          // they're about the post-bind body round-trip.
          // We DO need to echo the client's sha256 in our reply so
          // the client's verify passes.
          std::memcpy(self->clientDigest.data(),
                      self->bindTailBuf.data() + 8 + 32,
                      ces::CES_PLEX_SHA256_SIZE);
          const std::string name(
            reinterpret_cast<const char*>(self->bindNameBuf.data()),
            self->bindNameBuf.size());
          if (name == self->parent.acceptedProtoName_) {
            self->sendBindOk();
          } else {
            self->sendBindNackAndFinish();
          }
        });
    }

    void sendBindOk() {
      ces::BindReplyFields fields;
      fields.status = ces::CES_PLEX_OK;
      fields.serverTimeUs = mockNowMicros();
      fields.channelSessionToken = 0;  // mock doesn't care
      fields.serverProtoVersion = ces::CES_PLEX_PROTO_VERSION_V1;
      bindReplyBuf = ces::buildBindReply(
        fields,
        std::span<const uint8_t>(clientDigest.data(), clientDigest.size()),
        parent.serverKey_);
      auto self = shared_from_this();
      boost::asio::async_write(
        *stream, boost::asio::buffer(bindReplyBuf),
        [self](const boost::system::error_code& ec, std::size_t) {
          if (ec) { self->finish(); return; }
          self->readBodyLen();
        });
    }

    void sendBindNackAndFinish() {
      ces::BindReplyFields fields;
      fields.status = ces::CES_PLEX_NACK;
      fields.serverTimeUs = mockNowMicros();
      fields.serverProtoVersion = ces::CES_PLEX_PROTO_VERSION_V1;
      bindReplyBuf = ces::buildBindReply(
        fields,
        std::span<const uint8_t>(clientDigest.data(), clientDigest.size()),
        parent.serverKey_);
      auto self = shared_from_this();
      boost::asio::async_write(
        *stream, boost::asio::buffer(bindReplyBuf),
        [self](const boost::system::error_code&, std::size_t) {
          self->finish();
        });
    }

    void readBodyLen() {
      auto self = shared_from_this();
      boost::asio::async_read(
        *stream, boost::asio::buffer(lenBuf),
        [self](const boost::system::error_code& ec, std::size_t) {
          if (ec) { self->finish(); return; }
          uint32_t len = ces::Buffer::peek<uint32_t>(self->lenBuf.data());
          self->bodyBuf.resize(len);
          if (len == 0) { self->dispatch(); return; }
          self->readBody();
        });
    }

    void readBody() {
      auto self = shared_from_this();
      boost::asio::async_read(
        *stream, boost::asio::buffer(bodyBuf),
        [self](const boost::system::error_code& ec, std::size_t) {
          if (ec) { self->finish(); return; }
          self->dispatch();
        });
    }

    void dispatch() {
      ces::Bytes response = parent.transform_(bodyBuf);
      sendResponse(std::move(response));
    }

    void sendResponse(ces::Bytes body) {
      auto out = std::make_shared<ces::Bytes>();
      out->reserve(4 + body.size());
      ces::Buffer::put<uint32_t>(*out, static_cast<uint32_t>(body.size()));
      out->insert(out->end(), body.begin(), body.end());

      auto self = shared_from_this();
      boost::asio::async_write(
        *stream, boost::asio::buffer(*out),
        [self, out](const boost::system::error_code&, std::size_t) {
          self->finish();
        });
    }

    void finish() {
      // Drop without close(): close() emits HS_CLOSE immediately
      // and races ahead of in-flight reliable response bytes that
      // are still in the local send buffer. Letting the destructor
      // detach keeps the channel alive long enough for the peer to
      // drain its read; idle GC reclaims it eventually.
      stream.reset();
      parent.sessions_.erase(std::make_pair(peer, channelId));
    }
  };

public:
  // Called by MockRpcRudpListener::onAccept on a fresh inbound
  // HS_OPEN. Builds the per-channel RudpStream + Session and
  // returns the stream as the channel handler.
  std::shared_ptr<minx::Rudp::ChannelHandler>
  acceptInbound(const minx::SockAddr& peer, uint32_t channelId) {
    auto stream = std::make_shared<minx::RudpStream>(
      taskIO_.get_executor());
    auto session = std::make_shared<Session>(
      *this, peer, channelId, stream);
    sessions_[std::make_pair(peer, channelId)] = session;
    session->start();
    return stream;
  }

private:

  void scheduleTick() {
    if (!tickTimer_ || !rudp_) return;
    tickTimer_->expires_after(std::chrono::milliseconds(20));
    auto timer = tickTimer_;
    timer->async_wait(
      [this, timer](const boost::system::error_code& ec) {
        if (ec || !rudp_) return;
        rudp_->tick(mockNowMicros());
        scheduleTick();
      });
  }

  Transform transform_;
  std::string acceptedProtoName_ = "/ces/rpc/1";
  // Server keypair, used to sign Step-3 bind replies. The mock has
  // no inherent identity; tests don't validate the mock's pubkey.
  ces::KeyPair serverKey_;
  minx::MinxListener listener_;  // no-op defaults
  MockRpcRudpListener rudpListener_;
  std::unique_ptr<minx::Minx> minx_;
  std::unique_ptr<minx::Rudp> rudp_;
  boost::asio::io_context netIO_;
  boost::asio::io_context taskIO_;
  std::thread netThread_;
  std::thread taskThread_;
  std::shared_ptr<boost::asio::steady_timer> tickTimer_;
  std::map<std::pair<minx::SockAddr, uint32_t>,
           std::shared_ptr<Session>> sessions_;
  uint16_t port_ = 0;
};

inline std::shared_ptr<minx::Rudp::ChannelHandler>
MockRpcRudpListener::onAccept(const minx::SockAddr& peer,
                              uint32_t channelId) {
  if (!owner_) return nullptr;
  return owner_->acceptInbound(peer, channelId);
}

// ---------------------------------------------------------------------------
// Transform functions
// ---------------------------------------------------------------------------

// Produces (input || input) with all lowercase/uppercase ASCII letters
// ROT13-rotated. Response is exactly 2× the input length. Dead-simple
// deterministic transform — the test compares byte-exact.
ces::Bytes rot13DoubleTransform(const ces::Bytes& in) {
  ces::Bytes out;
  out.reserve(in.size() * 2);
  out.insert(out.end(), in.begin(), in.end());
  out.insert(out.end(), in.begin(), in.end());
  for (auto& b : out) {
    if (b >= 'a' && b <= 'z') {
      b = static_cast<uint8_t>('a' + (b - 'a' + 13) % 26);
    } else if (b >= 'A' && b <= 'Z') {
      b = static_cast<uint8_t>('A' + (b - 'A' + 13) % 26);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Test fixture: CesServer with rpcPort configured + MockRpcServer
// ---------------------------------------------------------------------------

struct SysRpcFixture {
  std::unique_ptr<CesServer> server;
  std::unique_ptr<CesClient> client;
  fs::path tempDir;
  KeyPair clientKey;
  uint16_t serverPort = 0;

  std::unique_ptr<MockRpcServer> mock;
  uint16_t mockPort = 0;

  SysRpcFixture() : SysRpcFixture(nullptr) {}

protected:
  // Subclass-accessible ctor that lets a test override CesConfig fields
  // (rpcMaxPending, rpcMaxResponseBytes, ...) before the server is built.
  explicit SysRpcFixture(std::function<void(CesConfig&)> cfgMod) {
    blog::init();
    blog::set_level(blog::info);
    blog::set_level("minx", blog::info);

    tempDir = makeUniqueTempDir("ces_sysrpc_test");

    minx::Hash serverPriv;
    serverPriv.fill(0xEE);

    CesConfig cfg =
      makeTestConfig(tempDir, serverPriv, std::numeric_limits<uint64_t>::max());
    // Configure the dedicated RPC port. 0 would skip the second Minx
    // construction entirely — we want the full bridge spun up.
    // OS-allocated rpc port: rpcAutoPort makes openSocket(0) pick a
    // guaranteed-free port. The SYS_RPC target is the mock server's own
    // (also OS-allocated) port, so this fixture never needs the number.
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;

    if (cfgMod) cfgMod(cfg);

    server = std::make_unique<CesServer>(cfg);
    serverPort = server->start(0);
    BOOST_REQUIRE_MESSAGE(serverPort > 0, "Server failed to bind");

    boost::asio::ip::udp::endpoint serverEp(
      boost::asio::ip::address_v6::loopback(), serverPort);
    client = std::make_unique<CesClient>(serverEp, false);
    client->start(0);
    client->setKey(clientKey);
    BOOST_REQUIRE(client->connect());

    server->_brr(clientKey.getPublicKeyAsHash(), 10'000'000'000);
    wait_net();

    // Start the mock server.
    mock = std::make_unique<MockRpcServer>(&rot13DoubleTransform);
    mockPort = mock->start();
    BOOST_REQUIRE_MESSAGE(mockPort > 0, "Mock RPC server failed to bind");
  }

  ~SysRpcFixture() {
    if (mock) mock->stop();
    if (client) client->stop();
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }

  HashPrefix getMyId() { return Account::getMapKey(clientKey.getPublicKeyAsHash()); }

  // Swap in a different transform for the next call. The existing
  // mock server is stopped and a fresh one started on a new port.
  void restartMockWith(MockRpcServer::Transform t) {
    if (mock) mock->stop();
    mock = std::make_unique<MockRpcServer>(std::move(t));
    mockPort = mock->start();
    BOOST_REQUIRE(mockPort > 0);
  }
};

// ---------------------------------------------------------------------------
// Helpers shared by multiple tests. These live in the top-level
// anonymous namespace (not nested inside any BOOST suite) so the
// flow-control and inbound-probe suites can reach them too.
// ---------------------------------------------------------------------------

// Compose the VM input buffer the gateway program expects.
// Layout (72 bytes, 9 cells):
//   [0..2)   port (u16 LE) — the destination mock server port
//   [2..8)   padding
//   [8..40)  file head key (32 bytes)
//   [40..72) followup key (32 bytes)
ces::Bytes buildGatewayInput(uint16_t port,
                                         const minx::Hash& fileKey,
                                         const minx::Hash& followupKey) {
  ces::Bytes input(72, 0);
  // Port is little-endian (matches VM cell layout).
  ces::Buffer::pokeLE<uint16_t>(input.data(), port);
  std::memcpy(input.data() + 8, fileKey.data(), 32);
  std::memcpy(input.data() + 40, followupKey.data(), 32);
  return input;
}

// Build the gateway VM program bytecode. Reads (port, fileKey,
// followupKey) from its input buffer, writes the literal host
// "::1" into a scratch region, and issues sysRpc.
AssetData buildGatewayProgram() {
  VmProgram pgm;

  // Input layout in cells:
  //   CESVM_IO_INPUT + 0 = cell holding port (u16 in low bits)
  //   CESVM_IO_INPUT + 1..4 = file head key (32 bytes)
  //   CESVM_IO_INPUT + 5..8 = followup key (32 bytes)
  //
  // Working cells we pick for the syscall:
  //   cell 16 = port (copied from input cell 0)
  //   cell 20..23 = file head key (copied from input cells 1..4)
  //   cell 24..27 = followup key (copied from input cells 5..8)
  //   cell 32 = host string "::1" (3 bytes, fits in one cell)

  pgm.copy(16, CESVM_IO_INPUT + 0, 1);
  pgm.copy(20, CESVM_IO_INPUT + 1, 4);
  pgm.copy(24, CESVM_IO_INPUT + 5, 4);

  // Write "::1" into cell 32. writeBytesToIo takes the destination
  // cell index and an ASCII byte buffer.
  const uint8_t host[3] = {':', ':', '1'};
  pgm.writeBytesToIo(32, host, 3);

  // Fire SYS_RPC. hostCell=Imm(32), hostLen=Imm(3), port=Ref(16)
  // so the opcode dereferences cell 16 for the actual u16 value.
  pgm.sysRpc({
    .hostCell = Imm(32),
    .hostLen  = Imm(3),
    .port     = Ref(16),
    .fileHead = Imm(20),
    .followup = Imm(24),
    .budget   = Imm(1'000'000),
    .tag      = Imm(0),
  });
  pgm.term();

  return pgm.buildBootBlock();
}

// Trivial followup program that terminates immediately. The tests
// don't need the followup to do anything; they poll the file head
// directly to observe the response. The gateway program still has
// to name a valid followup asset, though, so the dispatcher has
// something to schedule.
AssetData buildNoopFollowup() {
  VmProgram pgm;
  pgm.term();
  return pgm.buildBootBlock();
}

// Non-aborting variant of buildGatewayProgram. Uses OP_HOSTV (via
// pgm.hostv) instead of the typed sysRpc wrapper so the caller can
// observe the queue-time status in S() rather than having a nonzero
// S() hard-abort the VM run. Pairs with the flow-control tests that
// expect queueRpc to reject a call synchronously.
AssetData buildObservableGatewayProgram() {
  VmProgram pgm;

  // Same input layout as buildGatewayProgram.
  pgm.copy(16, CESVM_IO_INPUT + 0, 1);
  pgm.copy(20, CESVM_IO_INPUT + 1, 4);
  pgm.copy(24, CESVM_IO_INPUT + 5, 4);

  const uint8_t host[3] = {':', ':', '1'};
  pgm.writeBytesToIo(32, host, 3);

  pgm.hostv(SYS_RPC, {
    Imm(32),          // hostCell
    Imm(3),           // hostLen
    Ref(16),          // port (dereferences input cell 0)
    Imm(20),          // fileHead
    Imm(24),          // followup
    Imm(1'000'000),   // budget
    Imm(0),           // tag
  });

  // Copy S into output[0] so the caller can inspect the queue-time
  // error code (CES_ERROR_QUEUE_FULL, CES_ERROR_INSUFFICIENT_PAYMENT,
  // CES_OK if queued cleanly, etc.).
  pgm.set(Imm(CESVM_IO_OUTPUT_LEN), Imm(1));
  pgm.stb(Imm(CESVM_IO_OUTPUT * 8), Ref(CESVM_CELL_S));
  pgm.term();

  return pgm.buildBootBlock();
}

// Transform that sleeps before replying. Used by the TimeoutAsync
// test: the CesServer's per-session timer should fire while the mock
// is still asleep, delivering CES_ERROR_TIMEOUT.
ces::Bytes slowTransform(const ces::Bytes& in) {
  std::this_thread::sleep_for(std::chrono::seconds(3));
  return in;
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(SysRpcTests, SysRpcFixture)

// ---------------------------------------------------------------------------
// SmallRpc: 50-byte request → 100-byte response (single chunk each)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(SmallRpc_Rot13Double) {
  // Deploy the gateway + followup programs as account-owned assets.
  minx::Hash gatewayKey; gatewayKey.fill(0); gatewayKey[0] = 0xC0;
  AssetData gatewayPgm = buildGatewayProgram();
  uint8_t rc = client->createAsset(gatewayKey, gatewayPgm, 1);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  minx::Hash followupKey; followupKey.fill(0); followupKey[0] = 0xC1;
  AssetData followupPgm = buildNoopFollowup();
  rc = client->createAsset(followupKey, followupPgm, 1);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Pre-allocate a file with room for request (50) + response (100).
  // Request capacity == response capacity: 100 bytes = 1 chunk. The
  // test writes a 50-byte request first, then the dispatcher
  // overwrites with a 100-byte response.
  minx::Hash fileKey; fileKey.fill(0); fileKey[0] = 0xC2;
  ces::Bytes requestBody(50);
  for (size_t i = 0; i < 50; ++i)
    requestBody[i] = static_cast<uint8_t>('a' + (i % 26));

  rc = ramfilePut(*client, fileKey, requestBody.data(), requestBody.size(), 1);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Fire the gateway VM program.
  ces::Bytes input =
    buildGatewayInput(mockPort, fileKey, followupKey);
  uint64_t vmError = 0;
  uint64_t budgetUsed = 0;
  ces::Bytes output;
  rc = client->runAsset(gatewayKey, 10'000'000, input,
                         vmError, budgetUsed, output);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_REQUIRE_EQUAL(vmError, CESVM_OK);

  // Poll the file for the response. The dispatcher writes the
  // response asynchronously on rpcTaskIO_ → posts back to the
  // logic strand → walks the chain → touches the head.
  ces::Bytes expected = rot13DoubleTransform(requestBody);
  BOOST_REQUIRE_EQUAL(expected.size(), 100u);

  ces::Bytes got;
  RamfileHeader hdr;
  bool matched = false;
  for (int i = 0; i < 60; ++i) {  // up to ~6 seconds
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    got.clear();
    rc = ramfileGet(*client, fileKey, got, &hdr, nullptr);
    if (rc != CES_OK) continue;
    if (got == expected) { matched = true; break; }
  }

  BOOST_CHECK_MESSAGE(matched, "Response did not match expected. "
                      "got.size()=" << got.size()
                      << " expected.size()=" << expected.size());
}

// ---------------------------------------------------------------------------
// LargeRpc: 500-byte request → 1000-byte response (multi-chunk)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(LargeRpc_Rot13Double) {
  // Deploy programs.
  minx::Hash gatewayKey; gatewayKey.fill(0); gatewayKey[0] = 0xD0;
  AssetData gatewayPgm = buildGatewayProgram();
  uint8_t rc = client->createAsset(gatewayKey, gatewayPgm, 1);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  minx::Hash followupKey; followupKey.fill(0); followupKey[0] = 0xD1;
  AssetData followupPgm = buildNoopFollowup();
  rc = client->createAsset(followupKey, followupPgm, 1);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Pre-allocate a file with capacity for the response (1000 bytes),
  // then write the 500-byte request body into it. The ramfileResize +
  // ramfileWrite composition (split-capacity-from-size model) gives us
  // "1000 bytes of chunks, first 500 bytes of content."
  minx::Hash fileKey; fileKey.fill(0); fileKey[0] = 0xD2;
  ces::Bytes requestBody(500);
  for (size_t i = 0; i < 500; ++i)
    requestBody[i] = static_cast<uint8_t>('A' + (i % 26));

  // Start with an empty file, grow capacity to 1000, then shrink
  // declared size to 500 and write the request bytes.
  rc = ramfilePut(*client, fileKey, nullptr, 0, 1);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  std::vector<minx::Hash> keys;
  rc = ramfileScan(*client, fileKey, keys);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  rc = ramfileResize(*client, keys, 1000, 1);   // allocate chunks
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  rc = ramfileResize(*client, keys, 500, 1);    // shrink declared size
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  rc = ramfileWrite(*client, keys, 0, requestBody.data(), requestBody.size());
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Fire the gateway VM program.
  ces::Bytes input =
    buildGatewayInput(mockPort, fileKey, followupKey);
  uint64_t vmError = 0;
  uint64_t budgetUsed = 0;
  ces::Bytes output;
  rc = client->runAsset(gatewayKey, 10'000'000, input,
                         vmError, budgetUsed, output);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_REQUIRE_EQUAL(vmError, CESVM_OK);

  // Poll for the response. The expected body is 1000 bytes
  // (2 × 500 request, ROT13'd).
  ces::Bytes expected = rot13DoubleTransform(requestBody);
  BOOST_REQUIRE_EQUAL(expected.size(), 1000u);

  ces::Bytes got;
  RamfileHeader hdr;
  bool matched = false;
  for (int i = 0; i < 100; ++i) {  // up to ~10 seconds
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    got.clear();
    rc = ramfileGet(*client, fileKey, got, &hdr, nullptr);
    if (rc != CES_OK) continue;
    if (got == expected) { matched = true; break; }
  }

  BOOST_CHECK_MESSAGE(matched, "Response did not match expected. "
                      "got.size()=" << got.size()
                      << " expected.size()=" << expected.size());
}

BOOST_AUTO_TEST_SUITE_END()

// ---------------------------------------------------------------------------
// Flow-control tests. Each uses a thin subclass of SysRpcFixture
// that tweaks one CesConfig knob before server construction.
// ---------------------------------------------------------------------------

struct QueueFullFixture : SysRpcFixture {
  QueueFullFixture() : SysRpcFixture(
    [](CesConfig& c) { c.rpcMaxPending = 0; }) {}
};

struct TinyRequestCapFixture : SysRpcFixture {
  TinyRequestCapFixture() : SysRpcFixture(
    [](CesConfig& c) { c.rpcMaxRequestBytes = 32; }) {}
};

struct TinyResponseCapFixture : SysRpcFixture {
  TinyResponseCapFixture() : SysRpcFixture(
    [](CesConfig& c) { c.rpcMaxResponseBytes = 50; }) {}
};

struct ShortTimeoutFixture : SysRpcFixture {
  ShortTimeoutFixture() : SysRpcFixture(
    [](CesConfig& c) { c.rpcResponseTimeoutMs = 200; }) {}
};

BOOST_AUTO_TEST_SUITE(SysRpcFlowControlTests)

// Deploys the observable gateway + noop followup, sends the input,
// returns output[0]. Centralizes the boilerplate that the four flow-
// control tests share.
static uint8_t runObservableGateway(CesClient& client,
                                     uint16_t destPort,
                                     const minx::Hash& gatewayKey,
                                     const minx::Hash& followupKey,
                                     const minx::Hash& fileKey) {
  AssetData gatewayPgm = buildObservableGatewayProgram();
  uint8_t rc = client.createAsset(gatewayKey, gatewayPgm, 1);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  AssetData followupPgm = buildNoopFollowup();
  rc = client.createAsset(followupKey, followupPgm, 1);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  ces::Bytes input =
    buildGatewayInput(destPort, fileKey, followupKey);
  uint64_t vmError = 0;
  uint64_t budgetUsed = 0;
  ces::Bytes output;
  rc = client.runAsset(gatewayKey, 10'000'000, input,
                        vmError, budgetUsed, output);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_REQUIRE_EQUAL(vmError, CESVM_OK);
  BOOST_REQUIRE(!output.empty());
  return output[0];
}

// rpcMaxPending=0 → every queueRpc call is rejected before touching
// the asset store. No mock involvement; the S() should be
// CES_ERROR_QUEUE_FULL.
BOOST_FIXTURE_TEST_CASE(QueueFullRejectsSynchronously, QueueFullFixture) {
  minx::Hash gatewayKey; gatewayKey.fill(0); gatewayKey[0] = 0xA0;
  minx::Hash followupKey; followupKey.fill(0); followupKey[0] = 0xA1;
  minx::Hash fileKey; fileKey.fill(0); fileKey[0] = 0xA2;

  ces::Bytes requestBody(50, 0x41);
  uint8_t rc = ramfilePut(*client, fileKey,
                        requestBody.data(), requestBody.size(), 1);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  uint8_t s = runObservableGateway(*client, mockPort,
                                    gatewayKey, followupKey, fileKey);
  BOOST_CHECK_EQUAL((int)s, (int)CES_ERROR_QUEUE_FULL);
}

// rpcMaxRequestBytes=32 with a 100-byte request file → queueRpc should
// reject at the readFileChunkBytes cap before any wire I/O.
BOOST_FIXTURE_TEST_CASE(RequestTooBigRejectsSynchronously,
                        TinyRequestCapFixture) {
  minx::Hash gatewayKey; gatewayKey.fill(0); gatewayKey[0] = 0xB0;
  minx::Hash followupKey; followupKey.fill(0); followupKey[0] = 0xB1;
  minx::Hash fileKey; fileKey.fill(0); fileKey[0] = 0xB2;

  // 100 bytes > rpcMaxRequestBytes (32). Written as a single chunk.
  ces::Bytes requestBody(100, 0x41);
  uint8_t rc = ramfilePut(*client, fileKey,
                        requestBody.data(), requestBody.size(), 1);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  uint8_t s = runObservableGateway(*client, mockPort,
                                    gatewayKey, followupKey, fileKey);
  BOOST_CHECK_EQUAL((int)s, (int)CES_ERROR_INSUFFICIENT_PAYMENT);
}

// rpcMaxResponseBytes=50 with a mock that sends 200 bytes (rot13Double
// of a 100-byte request). The queue-time S() is CES_OK; the failure
// surfaces asynchronously in completeRpc's status code, observable via
// the test-hook completion observer.
BOOST_FIXTURE_TEST_CASE(ResponseTooBigFailsAsync,
                        TinyResponseCapFixture) {
  // _rpcCompletionObserver fires on logicStrand_. Capture status via
  // a promise so the test can block until completion lands.
  std::promise<uint8_t> doneP;
  auto doneF = doneP.get_future();
  server->_rpcCompletionObserver =
    [&doneP](uint8_t status) mutable {
      try { doneP.set_value(status); } catch (...) { /* already set */ }
    };

  minx::Hash gatewayKey; gatewayKey.fill(0); gatewayKey[0] = 0xC0;
  AssetData gatewayPgm = buildGatewayProgram();
  uint8_t rc = client->createAsset(gatewayKey, gatewayPgm, 1);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  minx::Hash followupKey; followupKey.fill(0); followupKey[0] = 0xC1;
  rc = client->createAsset(followupKey, buildNoopFollowup(), 1);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  minx::Hash fileKey; fileKey.fill(0); fileKey[0] = 0xC2;
  // 100-byte request → 200-byte response from rot13Double, exceeds
  // the rpcMaxResponseBytes=50 cap.
  ces::Bytes requestBody(100, 'a');
  rc = ramfilePut(*client, fileKey,
                requestBody.data(), requestBody.size(), 1);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  ces::Bytes input =
    buildGatewayInput(mockPort, fileKey, followupKey);
  uint64_t vmError = 0;
  uint64_t budgetUsed = 0;
  ces::Bytes output;
  rc = client->runAsset(gatewayKey, 10'000'000, input,
                         vmError, budgetUsed, output);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_REQUIRE_EQUAL(vmError, CESVM_OK);

  // Wait for the async completion to land.
  auto waitRes = doneF.wait_for(std::chrono::seconds(10));
  BOOST_REQUIRE_MESSAGE(waitRes == std::future_status::ready,
                        "completion observer never fired");
  uint8_t status = doneF.get();
  BOOST_CHECK_EQUAL((int)status, (int)CES_ERROR_INTERNAL);
}

// rpcResponseTimeoutMs=200 with a mock that sleeps 3 seconds. The
// RpcSession's asio timer fires first and delivers CES_ERROR_TIMEOUT
// into completeRpc.
BOOST_FIXTURE_TEST_CASE(ShortTimeoutFailsAsync, ShortTimeoutFixture) {
  // Swap the mock for one with the blocking transform.
  restartMockWith(&slowTransform);

  std::promise<uint8_t> doneP;
  auto doneF = doneP.get_future();
  server->_rpcCompletionObserver =
    [&doneP](uint8_t status) mutable {
      try { doneP.set_value(status); } catch (...) { /* already set */ }
    };

  minx::Hash gatewayKey; gatewayKey.fill(0); gatewayKey[0] = 0xD0;
  uint8_t rc = client->createAsset(
    gatewayKey, buildGatewayProgram(), 1);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  minx::Hash followupKey; followupKey.fill(0); followupKey[0] = 0xD1;
  rc = client->createAsset(followupKey, buildNoopFollowup(), 1);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  minx::Hash fileKey; fileKey.fill(0); fileKey[0] = 0xD2;
  ces::Bytes requestBody(20, 'x');
  rc = ramfilePut(*client, fileKey,
                requestBody.data(), requestBody.size(), 1);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  ces::Bytes input =
    buildGatewayInput(mockPort, fileKey, followupKey);
  uint64_t vmError = 0;
  uint64_t budgetUsed = 0;
  ces::Bytes output;
  rc = client->runAsset(gatewayKey, 10'000'000, input,
                         vmError, budgetUsed, output);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_REQUIRE_EQUAL(vmError, CESVM_OK);

  // 200ms timeout + some slack. Observer must fire well before the
  // mock's 3-second transform returns.
  auto waitRes = doneF.wait_for(std::chrono::seconds(5));
  BOOST_REQUIRE_MESSAGE(waitRes == std::future_status::ready,
                        "completion observer never fired");
  uint8_t status = doneF.get();
  BOOST_CHECK_EQUAL((int)status, (int)CES_ERROR_TIMEOUT);
}

BOOST_AUTO_TEST_SUITE_END()

// ---------------------------------------------------------------------------
// A separate suite with its own fixture — uses a CesServer that has
// rpcPort == 0 to verify SYS_RPC returns CES_ERROR_DISABLED.
// ---------------------------------------------------------------------------

struct NoRpcPortFixture {
  std::unique_ptr<CesServer> server;
  std::unique_ptr<CesClient> client;
  fs::path tempDir;
  KeyPair clientKey;
  uint16_t serverPort = 0;

  NoRpcPortFixture() {
    blog::init();
    tempDir = makeUniqueTempDir("ces_norpc_test");

    minx::Hash serverPriv;
    serverPriv.fill(0xEE);

    CesConfig cfg = makeTestConfig(
      tempDir, serverPriv, std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;  // SYS_RPC disabled on this server

    server = std::make_unique<CesServer>(cfg);
    serverPort = server->start(0);
    BOOST_REQUIRE(serverPort > 0);

    boost::asio::ip::udp::endpoint serverEp(
      boost::asio::ip::address_v6::loopback(), serverPort);
    client = std::make_unique<CesClient>(serverEp, false);
    client->start(0);
    client->setKey(clientKey);
    BOOST_REQUIRE(client->connect());

    server->_brr(clientKey.getPublicKeyAsHash(), 10'000'000'000);
    wait_net();
  }

  ~NoRpcPortFixture() {
    if (client) client->stop();
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }
};

BOOST_FIXTURE_TEST_SUITE(SysRpcDisabledTests, NoRpcPortFixture)

BOOST_AUTO_TEST_CASE(DisabledWhenNoRpcPort) {
  // Deploy a gateway program that calls SYS_RPC. It should return
  // with S() set to CES_ERROR_DISABLED without hitting the wire
  // (there is no wire — rpcRudp_ is null on this server). We use
  // the non-aborting OP_HOSTV (via pgm.hostv) instead of the typed
  // sysRpc wrapper, because sysRpc uses OP_HOSTXV which promotes
  // a nonzero S to CESVM_ABORT — that's the right semantics for
  // production (failed queue is a hard stop) but it would hide
  // the specific error code from this test.
  minx::Hash gatewayKey; gatewayKey.fill(0); gatewayKey[0] = 0xE0;

  VmProgram pgm;
  const uint8_t host[3] = {':', ':', '1'};
  pgm.writeBytesToIo(32, host, 3);

  // Fake keys — they don't exist as assets, but the dispatcher
  // should fail with CES_ERROR_DISABLED before ever looking them up.
  minx::Hash fakeKey{};
  fakeKey[0] = 0xFE;
  pgm.writeBytesToIo(20, fakeKey.data(), 32);  // file head
  pgm.writeBytesToIo(24, fakeKey.data(), 32);  // followup

  pgm.hostv(SYS_RPC, {
    Imm(32),          // hostCell
    Imm(3),           // hostLen
    Imm(55000),       // port
    Imm(20),          // fileHead
    Imm(24),          // followup
    Imm(1'000'000),   // budget
    Imm(0),           // tag
  });

  // After the syscall, io[S] holds the error code. Copy S to the
  // first byte of the output slot for the test to observe.
  pgm.set(Imm(CESVM_IO_OUTPUT_LEN), Imm(1));
  pgm.stb(Imm(CESVM_IO_OUTPUT * 8), Ref(CESVM_CELL_S));
  pgm.term();

  AssetData code = pgm.buildBootBlock();
  uint8_t rc = client->createAsset(gatewayKey, code, 1);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  uint64_t vmError = 0;
  uint64_t budgetUsed = 0;
  ces::Bytes output;
  rc = client->runAsset(gatewayKey, 10'000'000, {},
                         vmError, budgetUsed, output);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_REQUIRE_EQUAL(vmError, CESVM_OK);
  BOOST_REQUIRE(!output.empty());
  BOOST_CHECK_EQUAL(output[0], CES_ERROR_DISABLED);
}

BOOST_AUTO_TEST_SUITE_END()

// ---------------------------------------------------------------------------
// Inbound RPC is intentionally disabled; CES is rpc-client-only. A CesServer
// with rpcPort != 0 must still reject inbound RUDP handshakes at the
// Accept predicate — no session state, no logging. This test spins up a
// minimal RUDP client probe and asserts its push() never reaches
// ESTABLISHED on the server side.
// ---------------------------------------------------------------------------

namespace {

// Minimal RUDP client stack — Minx + Rudp + io_context + thread, with
// just enough wiring to drive a push() toward a CesServer's rpcPort.
// No inbound sessions, no streams; we only care whether the handshake
// completes (it must not).
class InboundProbeClient {
public:
  InboundProbeClient() = default;
  ~InboundProbeClient() { stop(); }

  uint16_t start() {
    minx_ = std::make_unique<minx::Minx>(
      &listener_, minx::MinxConfig{
        .instanceName = "probe",
        .randomXVMsToKeep = 0,
        .trustLoopback = true});
    rudpListener_.setMinx(minx_.get());
    rudp_ = std::make_unique<minx::Rudp>(&rudpListener_);
    minx::MinxStdExtensions stdExt;
    stdExt.registerExtension(
      minx::Rudp::KEY_V0,
      [this](const minx::SockAddr& peer, uint64_t key,
             const minx::Bytes& payload) {
        if (rudp_) rudp_->onPacket(peer, key, payload, mockNowMicros());
      });
    minx_->setExtensionHandler(std::move(stdExt).build());

    port_ = minx_->openSocket(
      boost::asio::ip::address_v6::loopback(), 0, netIO_, taskIO_);
    if (port_ == 0) return 0;

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
    netIO_.stop();
    taskIO_.stop();
    if (netThread_.joinable()) netThread_.join();
    if (taskThread_.joinable()) taskThread_.join();
    tickTimer_.reset();
    rudp_.reset();
    minx_.reset();
    rudpListener_.setMinx(nullptr);
    port_ = 0;
  }

  // Register a stub channel handler on (peer, channelId) and post a
  // reliable message. Returns true iff both registerChannel and push
  // succeeded. The probe doesn't care what the handler does — it
  // just needs the channel state to exist so RUDP fires HS_OPEN
  // toward the server. The new RUDP API requires registerChannel
  // before push().
  bool pushSync(const minx::SockAddr& peer, uint32_t channelId,
                const minx::Bytes& msg) {
    struct StubHandler : public minx::Rudp::ChannelHandler {};
    std::promise<bool> p;
    auto f = p.get_future();
    boost::asio::post(taskIO_, [this, &peer, channelId, &msg, &p]() {
      // Seed the clock before registerChannel — see CesFileClient
      // for the rationale (avoid immediate idle-GC).
      rudp_->tick(mockNowMicros());
      auto handler = std::make_shared<StubHandler>();
      if (!rudp_->registerChannel(peer, channelId, handler)) {
        p.set_value(false);
        return;
      }
      p.set_value(rudp_->push(peer, channelId, msg, /*reliable=*/true));
    });
    return f.get();
  }

  // Same serialized-access pattern for isEstablished. Rudp lookups
  // touch the internal peer/channel map; do them on taskIO_ so we
  // don't race with tick() or inbound packet handling.
  bool isEstablishedSync(const minx::SockAddr& peer, uint32_t channelId) {
    std::promise<bool> p;
    auto f = p.get_future();
    boost::asio::post(taskIO_, [this, &peer, channelId, &p]() {
      p.set_value(rudp_->isEstablished(peer, channelId));
    });
    return f.get();
  }

private:
  void scheduleTick() {
    if (!tickTimer_ || !rudp_) return;
    tickTimer_->expires_after(std::chrono::milliseconds(20));
    auto timer = tickTimer_;
    timer->async_wait(
      [this, timer](const boost::system::error_code& ec) {
        if (ec || !rudp_) return;
        rudp_->tick(mockNowMicros());
        scheduleTick();
      });
  }

  minx::MinxListener listener_;
  // Outbound-only Rudp::Listener: forwards onSend, rejects inbound.
  class ProbeRudpListener : public minx::Rudp::Listener {
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
  ProbeRudpListener rudpListener_;
  std::unique_ptr<minx::Minx> minx_;
  std::unique_ptr<minx::Rudp> rudp_;
  boost::asio::io_context netIO_;
  boost::asio::io_context taskIO_;
  std::thread netThread_;
  std::thread taskThread_;
  std::shared_ptr<boost::asio::steady_timer> tickTimer_;
  uint16_t port_ = 0;
};

// Fresh fixture specifically for the inbound test. We deliberately do
// NOT reuse SysRpcFixture — that fixture also starts a MockRpcServer
// (unneeded here) and a CES client (also unneeded). Simpler setup:
// just a CesServer with rpcPort bound on loopback.
struct InboundProbeFixture {
  std::unique_ptr<CesServer> server;
  fs::path tempDir;
  uint16_t serverPort = 0;

  InboundProbeFixture() {
    blog::init();
    blog::set_level(blog::info);
    blog::set_level("minx", blog::info);

    tempDir = makeUniqueTempDir("ces_inbound_probe");

    minx::Hash serverPriv;
    serverPriv.fill(0xEF);

    CesConfig cfg = makeTestConfig(
      tempDir, serverPriv, std::numeric_limits<uint64_t>::max());
    // OS-allocated rpc port; read back via _rpcBoundPort() in the tests.
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;

    server = std::make_unique<CesServer>(cfg);
    serverPort = server->start(0);
    BOOST_REQUIRE(serverPort > 0);
  }

  ~InboundProbeFixture() {
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }
};

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(SysRpcInboundDisabledTests, InboundProbeFixture)

BOOST_AUTO_TEST_CASE(InboundHandshakeRejected) {
  // The server's RPC socket is bound — this is a running RPC listener
  // that accepts OUTBOUND calls. We send an inbound OPEN at it via a
  // bare RUDP probe. The server's ChannelAccept predicate returns
  // false, so the handshake silently dies: the probe keeps retrying
  // until its handshakeMaxRetries are exhausted and isEstablished
  // stays false the entire time.
  const uint16_t rpcPort = server->_rpcBoundPort();
  BOOST_REQUIRE_MESSAGE(rpcPort > 0,
                        "server did not bind its RPC port");

  InboundProbeClient probe;
  BOOST_REQUIRE(probe.start() > 0);

  minx::SockAddr serverAddr(
    boost::asio::ip::address_v6::loopback(), rpcPort);
  const uint32_t channelId = 0xDEADBEEF;
  minx::Bytes payload;
  payload.push_back('x');

  // push() may succeed (it only fails on MAX_MESSAGE_SIZE / per-peer
  // cap / send-buffer-full — none of those apply here). What we care
  // about is that the channel never reaches ESTABLISHED.
  BOOST_REQUIRE(probe.pushSync(serverAddr, channelId, payload));

  // Give both sides time to exchange handshake packets. RUDP's default
  // handshakeRetryInterval is 200 ms × 3 retries = 600 ms. We wait
  // longer than that to be sure retries have been exhausted.
  for (int i = 0; i < 20; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    if (probe.isEstablishedSync(serverAddr, channelId)) break;
  }

  BOOST_CHECK_MESSAGE(
    !probe.isEstablishedSync(serverAddr, channelId),
    "Inbound RUDP channel was accepted — inbound RPC must be off");

  probe.stop();
}

BOOST_AUTO_TEST_SUITE_END()
