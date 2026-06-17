// dial.cpp — implementation of `cesh dial <instance_id>`.
//
// Single self-contained translation unit. We don't reuse
// CesComputeClient because (a) it's hardcoded to /ces/compute/1, (b) it
// has a verb-driven request/response loop while dial flips into raw
// byte-pump mode after ATTACH, and (c) factoring a shared CesPlex
// client base would balloon scope. The ~80 LOC of bind boilerplate
// duplicated below is the price.

#include "dial.h"

#include <ces/cesplex/wire.h>
#include <ces/buffer.h>
#include <ces/types.h>

#include <minx/blog.h>
#include <minx/minx.h>
#include <minx/rudp/rudp.h>
#include <minx/rudp/rudp_stream.h>
#include <minx/stdext.h>
#include <minx/types.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/udp.hpp>

#include <unistd.h>           // STDIN_FILENO, STDOUT_FILENO, ::write
#include <errno.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <sstream>
#include <cstdio>
#include <cstring>
#include <functional>
#include <future>
#include <iostream>
#include <memory>
#include <random>
#include <span>
#include <string>
#include <thread>
#include <vector>

LOG_MODULE("cesh");

namespace ces {

namespace {

constexpr const char* kLuaProto = "/ces/lua/1";
constexpr uint8_t kVerbAttach = 0x01;

// Per-call timeouts. Long enough to absorb LAN+WAN jitter, short
// enough that a hung server gives the user back the prompt.
constexpr auto kBindTimeout    = std::chrono::seconds(10);
constexpr auto kAttachTimeout  = std::chrono::seconds(10);

uint64_t nowMicros() {
  return static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count());
}

// --extsign control-channel helpers: line-based on fd 0/1, read byte-by-byte so
// we never consume past the newline into the raw byte pipe that follows.
bool hexToBytes(const std::string& hex, uint8_t* out, size_t n) {
  if (hex.size() != n * 2) return false;
  auto hv = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i < n; i++) {
    int hi = hv(hex[2 * i]), lo = hv(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return true;
}

std::string readControlLine() {
  std::string s;
  char c;
  for (;;) {
    ssize_t r = ::read(STDIN_FILENO, &c, 1);
    if (r <= 0) return s;             // EOF/error: caller treats short line as error
    if (c == '\n') break;
    if (c != '\r') s.push_back(c);
  }
  return s;
}

void writeControlLine(const std::string& s) {
  std::string o = s + "\n";
  ssize_t w = ::write(STDOUT_FILENO, o.data(), o.size());
  (void)w;
}

// All BE serialization goes through ces::Buffer (see ces/buffer.h).

class NoopListener : public minx::MinxListener {};

// Outbound-only Rudp::Listener — forwards onSend to the local Minx,
// no inbound channel acceptance.
class DialRudpListener : public minx::Rudp::Listener {
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

// Resolve host:rpcPort → SockAddr (v6, IPv4-mapped if needed).
bool resolvePeer(const std::string& host, uint16_t port,
                 minx::SockAddr& out, std::string& err) {
  boost::asio::io_context ioc;
  boost::asio::ip::udp::resolver res(ioc);
  boost::system::error_code ec;
  auto results = res.resolve(host, std::to_string(port), ec);
  if (ec || results.empty()) {
    err = "resolve(" + host + "): " +
          (ec ? ec.message() : std::string("no results"));
    return false;
  }
  auto addr = results.begin()->endpoint().address();
  if (addr.is_v4()) {
    addr = boost::asio::ip::make_address_v6(
      boost::asio::ip::v4_mapped, addr.to_v4());
  }
  out = minx::SockAddr(addr, port);
  return true;
}

// Synchronous dial driver. Owns minx, rudp, two io_contexts, two
// threads. Lifetime bounded by runDial(). Not thread-safe — only the
// runDial() main thread touches public methods; everything inside
// runs on netIO_ or taskIO_.
class Dialer {
public:
  using WorkGuard = boost::asio::executor_work_guard<
    boost::asio::io_context::executor_type>;

  ~Dialer() { stop(); }

  // Spin up the network stack and open the local UDP socket.
  // Returns empty string on success, error message on failure.
  std::string start(const minx::SockAddr& peer) {
    peer_ = peer;

    minx::MinxConfig mc{};
    mc.instanceName = "cesh-dial";
    mc.randomXVMsToKeep = 0;
    mc.randomXInitThreads = 0;
    mc.trustLoopback = true;
    minx_ = std::make_unique<minx::Minx>(&listener_, mc);

    minx::RudpConfig rcfg{};
    rcfg.maxChannelsPerPeer = 2;
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
    if (boundPort_ == 0) return "failed to open local UDP socket";

    netGuard_ = std::make_unique<WorkGuard>(netIO_.get_executor());
    taskGuard_ = std::make_unique<WorkGuard>(taskIO_.get_executor());
    netThread_ = std::thread([this]() { netIO_.run(); });
    taskThread_ = std::thread([this]() { taskIO_.run(); });

    tickTimer_ = std::make_shared<boost::asio::steady_timer>(taskIO_);
    boost::asio::post(taskIO_, [this]() { scheduleTick(); });

    std::mt19937 rng(std::random_device{}());
    channel_ = 0;
    while (channel_ == 0) channel_ = rng();

    return "";
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

  // Bind handshake on /ces/lua/1. On success, fills sessionToken and
  // serverPubkey. Returns empty string on success, error message
  // otherwise. `expected` (if non-null) hard-checks the reply pubkey;
  // otherwise we TOFU-accept and write the captured pubkey out.
  std::string bind(const KeyPair& signer,
                   const minx::Hash* expected,
                   uint64_t& sessionToken,
                   minx::Hash& serverPubkey) {
    auto run = std::make_shared<std::promise<std::string>>();
    auto fut = run->get_future();
    auto tokenOut = std::make_shared<uint64_t>(0);
    auto pubkeyOut = std::make_shared<minx::Hash>();
    boost::asio::post(taskIO_, [this, &signer, expected,
                                tokenOut, pubkeyOut, run]() {
      rudp_->tick(nowMicros());
      stream_ = std::make_shared<minx::RudpStream>(
        taskIO_.get_executor());
      if (!rudp_->registerChannel(peer_, channel_, stream_)) {
        run->set_value("rudp registerChannel failed");
        return;
      }

      const uint64_t bindNowUs = nowMicros();
      const std::string name = kLuaProto;
      auto bindReq = std::make_shared<minx::Bytes>(
        ces::buildBindRequest(name, bindNowUs, signer));
      const auto& pkArr = signer.getPublicKeyAsHash();
      auto clientDigest = std::make_shared<
        std::array<uint8_t, ces::CES_PLEX_SHA256_SIZE>>(
          ces::computeBindRequestDigest(
            std::span<const uint8_t>(
              reinterpret_cast<const uint8_t*>(name.data()),
              name.size()),
            bindNowUs,
            std::span<const uint8_t>(pkArr.data(), pkArr.size())));

      boost::asio::async_write(
        *stream_, boost::asio::buffer(*bindReq),
        [this, bindReq, clientDigest, expected,
         tokenOut, pubkeyOut, run]
        (const boost::system::error_code& ec, std::size_t) {
          if (ec) { run->set_value("bind write: " + ec.message()); return; }
          auto reply = std::make_shared<
            std::array<uint8_t, ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE>>();
          boost::asio::async_read(
            *stream_, boost::asio::buffer(*reply),
            [reply, clientDigest, expected,
             tokenOut, pubkeyOut, run]
            (const boost::system::error_code& ec2, std::size_t) {
              if (ec2) {
                run->set_value("bind read: " + ec2.message()); return;
              }
              auto r = ces::parseBindReply(
                std::span<const uint8_t,
                          ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE>(
                  reply->data(), reply->size()));
              if (r.status != ces::CES_PLEX_OK) {
                run->set_value("bind NACK from server");
                return;
              }
              if (!ces::verifyBindReply(
                    r,
                    std::span<const uint8_t>(
                      clientDigest->data(), clientDigest->size()))) {
                run->set_value("bind reply digest/sig verify failed");
                return;
              }
              if (expected && std::memcmp(expected->data(),
                                          r.serverPubkey.data(),
                                          expected->size()) != 0) {
                run->set_value("bind reply pubkey != expected");
                return;
              }
              std::memcpy(pubkeyOut->data(), r.serverPubkey.data(),
                          pubkeyOut->size());
              *tokenOut = r.channelSessionToken;
              run->set_value("");
            });
        });
    });
    if (fut.wait_for(kBindTimeout) != std::future_status::ready)
      return "bind handshake timeout";
    std::string err = fut.get();
    if (err.empty()) {
      sessionToken = *tokenOut;
      serverPubkey = *pubkeyOut;
    }
    return err;
  }

  // ATTACH verb. Fills outStatus + outConnId. Returns empty string on
  // wire success (status itself may be a CES_ERROR_*); error message
  // on transport failure (write/read errored, no reply, etc.).
  std::string attach(const KeyPair& signer,
                     uint64_t sessionToken,
                     uint64_t instanceId,
                     uint8_t& outStatus,
                     uint64_t& outConnId) {
    ces::Bytes preamble;
    ces::Buffer::put<uint64_t>(preamble, instanceId);

    Signature sig = ces::signPerOp(
      signer, kVerbAttach,
      std::span<const uint8_t>(preamble.data(), preamble.size()),
      sessionToken);

    // Wire shape: [u8 verb][u32 BE preamble_len][preamble][65 sig].
    const size_t totalSize = ces::CES_PLEX_VERB_SIZE
                             + ces::CES_PLEX_PREAMBLE_LEN_SIZE
                             + preamble.size() + sig.size();
    minx::Bytes wire(totalSize);
    minx::Buffer buf(wire);
    buf.put<uint8_t>(kVerbAttach);
    buf.put<uint32_t>(static_cast<uint32_t>(preamble.size()));
    buf.put(std::span<const uint8_t>(preamble.data(), preamble.size()));
    buf.put(sig);

    auto run = std::make_shared<std::promise<std::string>>();
    auto fut = run->get_future();
    auto wireBuf = std::make_shared<minx::Bytes>(std::move(wire));
    auto strm = stream_;
    // Outputs are written by handlers on taskIO_ and copied to the
    // caller's refs only once the future is ready — never through the
    // stack refs, so a late handler can't poke a freed frame on timeout.
    auto statusOut = std::make_shared<uint8_t>(0xFF);
    auto connIdOut = std::make_shared<uint64_t>(0);

    boost::asio::post(taskIO_,
      [strm, wireBuf, statusOut, connIdOut, run]() {
        boost::asio::async_write(
          *strm, boost::asio::buffer(*wireBuf),
          [strm, wireBuf, statusOut, connIdOut, run]
          (const boost::system::error_code& ec, std::size_t) {
            if (ec) {
              run->set_value("attach write: " + ec.message()); return;
            }
            auto stBuf = std::make_shared<std::array<uint8_t, 1>>();
            boost::asio::async_read(
              *strm, boost::asio::buffer(*stBuf),
              [strm, stBuf, statusOut, connIdOut, run]
              (const boost::system::error_code& ec2, std::size_t) {
                if (ec2) {
                  run->set_value("attach read status: " + ec2.message());
                  return;
                }
                uint8_t status = (*stBuf)[0];
                *statusOut = status;
                const std::size_t okExtra =
                  (status == CES_OK) ? sizeof(uint64_t) : 0;
                const std::size_t tailLen =
                  okExtra + ces::CES_PLEX_RESP_TRAILER_SIZE;
                auto tail = std::make_shared<ces::Bytes>(tailLen);
                boost::asio::async_read(
                  *strm, boost::asio::buffer(*tail),
                  [tail, status, connIdOut, run]
                  (const boost::system::error_code& ec3, std::size_t) {
                    if (ec3) {
                      run->set_value("attach read tail: " + ec3.message());
                      return;
                    }
                    if (status == CES_OK) {
                      *connIdOut = ces::Buffer::peek<uint64_t>(tail->data());
                    }
                    run->set_value("");
                  });
              });
          });
      });
    if (fut.wait_for(kAttachTimeout) != std::future_status::ready)
      return "attach timeout";
    std::string err = fut.get();
    if (err.empty()) {
      outStatus = *statusOut;
      outConnId = *connIdOut;
    }
    return err;
  }

  // External-signing bind: same handshake as bind(), but the request was signed
  // elsewhere (no private key here). `pubkey` is the 32-byte client key; `sig`
  // is over computeBindRequestDigest(kLuaProto, timeUs, pubkey).
  std::string bindExt(std::span<const uint8_t> pubkey, uint64_t timeUs,
                      const Signature& sig, const minx::Hash* expected,
                      uint64_t& sessionToken, minx::Hash& serverPubkey) {
    const std::string name = kLuaProto;
    auto bindReq = std::make_shared<minx::Bytes>(
      ces::buildBindRequestSigned(name, timeUs, pubkey, sig));
    auto clientDigest = std::make_shared<
      std::array<uint8_t, ces::CES_PLEX_SHA256_SIZE>>(
        ces::computeBindRequestDigest(
          std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(name.data()), name.size()),
          timeUs, pubkey));
    auto run = std::make_shared<std::promise<std::string>>();
    auto fut = run->get_future();
    auto tokenOut = std::make_shared<uint64_t>(0);
    auto pubkeyOut = std::make_shared<minx::Hash>();
    boost::asio::post(taskIO_, [this, bindReq, clientDigest, expected,
                                tokenOut, pubkeyOut, run]() {
      rudp_->tick(nowMicros());
      stream_ = std::make_shared<minx::RudpStream>(taskIO_.get_executor());
      if (!rudp_->registerChannel(peer_, channel_, stream_)) {
        run->set_value("rudp registerChannel failed"); return;
      }
      boost::asio::async_write(
        *stream_, boost::asio::buffer(*bindReq),
        [this, bindReq, clientDigest, expected, tokenOut, pubkeyOut, run]
        (const boost::system::error_code& ec, std::size_t) {
          if (ec) { run->set_value("bind write: " + ec.message()); return; }
          auto reply = std::make_shared<
            std::array<uint8_t, ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE>>();
          boost::asio::async_read(
            *stream_, boost::asio::buffer(*reply),
            [reply, clientDigest, expected, tokenOut, pubkeyOut, run]
            (const boost::system::error_code& ec2, std::size_t) {
              if (ec2) { run->set_value("bind read: " + ec2.message()); return; }
              auto r = ces::parseBindReply(
                std::span<const uint8_t, ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE>(
                  reply->data(), reply->size()));
              if (r.status != ces::CES_PLEX_OK) {
                run->set_value("bind NACK from server"); return;
              }
              if (!ces::verifyBindReply(r, std::span<const uint8_t>(
                    clientDigest->data(), clientDigest->size()))) {
                run->set_value("bind reply digest/sig verify failed"); return;
              }
              if (expected && std::memcmp(expected->data(),
                    r.serverPubkey.data(), expected->size()) != 0) {
                run->set_value("bind reply pubkey != expected"); return;
              }
              std::memcpy(pubkeyOut->data(), r.serverPubkey.data(),
                          pubkeyOut->size());
              *tokenOut = r.channelSessionToken;
              run->set_value("");
            });
        });
    });
    if (fut.wait_for(kBindTimeout) != std::future_status::ready)
      return "bind handshake timeout";
    std::string err = fut.get();
    if (err.empty()) { sessionToken = *tokenOut; serverPubkey = *pubkeyOut; }
    return err;
  }

  // External-signing ATTACH: same as attach(), but `sig` was produced elsewhere
  // over computePerOpDigest(kVerbAttach, preamble=instanceId, sessionToken).
  std::string attachExt(const Signature& sig, uint64_t instanceId,
                        uint8_t& outStatus, uint64_t& outConnId) {
    ces::Bytes preamble;
    ces::Buffer::put<uint64_t>(preamble, instanceId);
    const size_t totalSize = ces::CES_PLEX_VERB_SIZE
                             + ces::CES_PLEX_PREAMBLE_LEN_SIZE
                             + preamble.size() + sig.size();
    minx::Bytes wire(totalSize);
    minx::Buffer buf(wire);
    buf.put<uint8_t>(kVerbAttach);
    buf.put<uint32_t>(static_cast<uint32_t>(preamble.size()));
    buf.put(std::span<const uint8_t>(preamble.data(), preamble.size()));
    buf.put(sig);

    auto run = std::make_shared<std::promise<std::string>>();
    auto fut = run->get_future();
    auto wireBuf = std::make_shared<minx::Bytes>(std::move(wire));
    auto strm = stream_;
    auto statusOut = std::make_shared<uint8_t>(0xFF);
    auto connIdOut = std::make_shared<uint64_t>(0);
    boost::asio::post(taskIO_, [strm, wireBuf, statusOut, connIdOut, run]() {
      boost::asio::async_write(
        *strm, boost::asio::buffer(*wireBuf),
        [strm, wireBuf, statusOut, connIdOut, run]
        (const boost::system::error_code& ec, std::size_t) {
          if (ec) { run->set_value("attach write: " + ec.message()); return; }
          auto stBuf = std::make_shared<std::array<uint8_t, 1>>();
          boost::asio::async_read(
            *strm, boost::asio::buffer(*stBuf),
            [strm, stBuf, statusOut, connIdOut, run]
            (const boost::system::error_code& ec2, std::size_t) {
              if (ec2) { run->set_value("attach read status: " + ec2.message()); return; }
              uint8_t status = (*stBuf)[0];
              *statusOut = status;
              const std::size_t okExtra = (status == CES_OK) ? sizeof(uint64_t) : 0;
              const std::size_t tailLen = okExtra + ces::CES_PLEX_RESP_TRAILER_SIZE;
              auto tail = std::make_shared<ces::Bytes>(tailLen);
              boost::asio::async_read(
                *strm, boost::asio::buffer(*tail),
                [tail, status, connIdOut, run]
                (const boost::system::error_code& ec3, std::size_t) {
                  if (ec3) { run->set_value("attach read tail: " + ec3.message()); return; }
                  if (status == CES_OK)
                    *connIdOut = ces::Buffer::peek<uint64_t>(tail->data());
                  run->set_value("");
                });
            });
        });
    });
    if (fut.wait_for(kAttachTimeout) != std::future_status::ready)
      return "attach timeout";
    std::string err = fut.get();
    if (err.empty()) { outStatus = *statusOut; outConnId = *connIdOut; }
    return err;
  }

  // Drive the data pump until the channel closes (EOF) or a signal
  // arrives. Returns the exit code (0 / 130 / 143). All operations
  // run on taskIO_; the calling thread blocks on a promise.
  int runDataPump() {
    auto exitCode = std::make_shared<std::promise<int>>();
    auto exitFut = exitCode->get_future();
    auto exitSet = std::make_shared<std::atomic<bool>>(false);

    auto stdinFd = std::make_shared<
      boost::asio::posix::stream_descriptor>(taskIO_, STDIN_FILENO);
    auto signals = std::make_shared<boost::asio::signal_set>(
      taskIO_, SIGINT, SIGTERM);

    auto setExit = [exitCode, exitSet](int code) {
      bool expected = false;
      if (exitSet->compare_exchange_strong(expected, true))
        exitCode->set_value(code);
    };

    auto strm = stream_;

    // The two recursive pump callbacks are owned here by shared_ptr and
    // re-armed through weak_ptrs. taskIO_ keeps running until the Dialer
    // is destroyed (well after this frame returns on exit), so a late
    // continuation must not re-enter a callback whose frame is gone:
    // lock() yields null once this frame drops the last strong ref.

    // ---- channel → stdout pump ----
    auto chanBuf = std::make_shared<std::array<uint8_t, 4096>>();
    auto readChan = std::make_shared<std::function<void()>>();
    std::weak_ptr<std::function<void()>> readChanW = readChan;
    *readChan = [strm, chanBuf, readChanW, stdinFd, signals, setExit]() {
      strm->async_read_some(
        boost::asio::buffer(*chanBuf),
        [strm, chanBuf, readChanW, stdinFd, signals, setExit]
        (const boost::system::error_code& ec, std::size_t n) {
          if (ec) {
            // Channel closed by any party. Cancel stdin reader and
            // signal handler so taskIO_ can drain.
            boost::system::error_code cec;
            stdinFd->cancel(cec);
            signals->cancel(cec);
            setExit(0);
            return;
          }
          if (n > 0) {
            // Blocking write to stdout — io thread is the only writer.
            // EINTR-resume; any other write error means stdout is gone,
            // which we treat as terminal.
            const uint8_t* p = chanBuf->data();
            std::size_t left = n;
            while (left > 0) {
              ssize_t w = ::write(STDOUT_FILENO, p, left);
              if (w < 0) {
                if (errno == EINTR) continue;
                // Tear down: stdout died, no point in keeping the
                // channel up.
                boost::system::error_code cec;
                strm->close();
                stdinFd->cancel(cec);
                signals->cancel(cec);
                setExit(1);
                return;
              }
              p += w; left -= static_cast<std::size_t>(w);
            }
          }
          if (auto self = readChanW.lock()) (*self)();
        });
    };

    // ---- stdin → channel pump ----
    auto stdinBuf = std::make_shared<std::array<uint8_t, 4096>>();
    auto readStdin = std::make_shared<std::function<void()>>();
    std::weak_ptr<std::function<void()>> readStdinW = readStdin;
    *readStdin = [strm, stdinFd, stdinBuf, readStdinW]() {
      stdinFd->async_read_some(
        boost::asio::buffer(*stdinBuf),
        [strm, stdinBuf, readStdinW]
        (const boost::system::error_code& ec, std::size_t n) {
          if (ec) {
            // EOF (boost::asio::error::eof) or cancel. Half-close: stop
            // reading stdin, leave the channel up so the program can
            // drain replies. Don't close the stream here.
            return;
          }
          if (n == 0) {
            if (auto self = readStdinW.lock()) (*self)();
            return;
          }
          auto out = std::make_shared<minx::Bytes>(
            stdinBuf->begin(), stdinBuf->begin() + n);
          boost::asio::async_write(
            *strm, boost::asio::buffer(*out),
            [readStdinW, out]
            (const boost::system::error_code& wec, std::size_t) {
              if (wec) {
                // Channel write failed — channel reader will pick up
                // the close on its next async_read_some.
                return;
              }
              if (auto self = readStdinW.lock()) (*self)();
            });
        });
    };

    // ---- signal handler ----
    signals->async_wait(
      [setExit, strm, stdinFd]
      (const boost::system::error_code& ec, int signo) {
        if (ec) return;
        // Active close → channel reader will see eof and tear down.
        // exitCode reflects the signal.
        boost::system::error_code cec;
        strm->close();
        stdinFd->cancel(cec);
        int code = (signo == SIGTERM) ? 143 : 130;
        setExit(code);
      });

    boost::asio::post(taskIO_, [readStdin, readChan]() {
      (*readStdin)();
      (*readChan)();
    });

    int code = exitFut.get();

    // Best-effort flush of stdout. Channel reader has already drained
    // up to its eof; nothing else owes us bytes.
    boost::system::error_code cec;
    stdinFd->cancel(cec);
    signals->cancel(cec);
    return code;
  }

private:
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

  NoopListener listener_;
  DialRudpListener rudpListener_;
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
};

// Map ATTACH status → cesh exit code per spec.
int exitCodeForAttachStatus(uint8_t s) {
  switch (s) {
    case CES_OK:                                 return 0;
    case CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND:   return 2;
    case CES_ERROR_NOT_LISTENING:                return 3;
    case CES_ERROR_PROTO_REJECTED:               return 5;
    default:                                     return 1;
  }
}

const char* attachErrorName(uint8_t s) {
  switch (s) {
    case CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND: return "instance not found";
    case CES_ERROR_NOT_LISTENING:              return "instance not listening";
    case CES_ERROR_PROTO_REJECTED:             return "protocol rejected";
    case CES_ERROR_BAD_NAME:                   return "bad name";
    default:                                   return "attach failed";
  }
}

} // namespace

int runDial(const DialArgs& args) {
  if (args.rpcPort == 0) {
    std::cerr << "Error: --rpc-port is required for `cesh dial`.\n";
    return 1;
  }

  // Unbuffered stdio. We use ::write to STDOUT_FILENO directly anyway,
  // but flip the FILE* layer too in case a fallback path uses it.
  std::setvbuf(stdin,  nullptr, _IONBF, 0);
  std::setvbuf(stdout, nullptr, _IONBF, 0);

  minx::SockAddr peer;
  std::string err;
  if (!resolvePeer(args.serverHost, args.rpcPort, peer, err)) {
    std::cerr << "Error: " << err << "\n";
    return 1;
  }

  Dialer dialer;
  if (auto e = dialer.start(peer); !e.empty()) {
    std::cerr << "Error: " << e << "\n";
    return 1;
  }

  uint64_t sessionToken = 0;
  minx::Hash serverPk{};
  const minx::Hash* expected =
    args.expectedServerPk.has_value() ? &*args.expectedServerPk : nullptr;

  // --extsign: the signatures come from a tunneler (cesweb) over a stdio
  // control handshake; no private key here. Bind, hand back the session token
  // so the far side can sign ATTACH over it, then ATTACH and fall into the same
  // raw byte pipe. Control I/O is on fd 0/1 and strictly precedes the pump.
  if (args.extSign) {
    minx::Hash clientPub{};
    if (!hexToBytes(args.clientPubkeyHex, clientPub.data(), clientPub.size())) {
      writeControlLine("ERR bad --pubkey"); return 1;
    }
    std::string bindLine = readControlLine();      // "BIND <timeUs> <sigHex>"
    uint64_t timeUs = 0; std::string bindSigHex;
    { std::istringstream is(bindLine); std::string tag;
      if (!(is >> tag >> timeUs >> bindSigHex) || tag != "BIND") {
        writeControlLine("ERR expected BIND"); return 1; } }
    Signature bindSig{};
    if (!hexToBytes(bindSigHex, bindSig.data(), bindSig.size())) {
      writeControlLine("ERR bad bind sig"); return 1;
    }
    if (auto e = dialer.bindExt(
          std::span<const uint8_t>(clientPub.data(), clientPub.size()),
          timeUs, bindSig, expected, sessionToken, serverPk); !e.empty()) {
      writeControlLine("ERR bind: " + e); return 4;
    }
    writeControlLine("TOKEN " + std::to_string(sessionToken));

    std::string attLine = readControlLine();       // "ATTACH <sigHex>"
    std::string attSigHex;
    { std::istringstream is(attLine); std::string tag;
      if (!(is >> tag >> attSigHex) || tag != "ATTACH") {
        writeControlLine("ERR expected ATTACH"); return 1; } }
    Signature attSig{};
    if (!hexToBytes(attSigHex, attSig.data(), attSig.size())) {
      writeControlLine("ERR bad attach sig"); return 1;
    }
    uint8_t st = 0xFF; uint64_t cid = 0;
    if (auto e = dialer.attachExt(attSig, args.instanceId, st, cid); !e.empty()) {
      writeControlLine("ERR attach: " + e); return 5;
    }
    if (st != CES_OK) {
      writeControlLine(std::string("ERR ") + attachErrorName(st));
      return exitCodeForAttachStatus(st);
    }
    writeControlLine("READY");
    return dialer.runDataPump();
  }

  if (auto e = dialer.bind(args.signerKey, expected,
                           sessionToken, serverPk);
      !e.empty()) {
    std::cerr << "Error: bind: " << e << "\n";
    return 4;
  }
  if (!expected && args.verbose) {
    std::cerr << "TOFU server pubkey: "
              << minx::hashToString(serverPk) << "\n";
  }

  uint8_t attachStatus = 0xFF;
  uint64_t connId = 0;
  if (auto e = dialer.attach(args.signerKey, sessionToken,
                             args.instanceId, attachStatus, connId);
      !e.empty()) {
    std::cerr << "Error: attach: " << e << "\n";
    return 5;
  }
  if (attachStatus != CES_OK) {
    std::cerr << "Error: " << attachErrorName(attachStatus)
              << " (attach status=" << int(attachStatus) << ")\n";
    return exitCodeForAttachStatus(attachStatus);
  }
  if (args.verbose) {
    std::cerr << "ATTACH ok conn_id=" << connId << "\n";
  }

  return dialer.runDataPump();
}

} // namespace ces
