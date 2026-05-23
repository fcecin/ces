// compute_lua_handler.cpp - builtin:lua handler.
//
// Mounts /ces/lua/1. Routes a user's signed-bound RUDP channel to a
// running cesluajitd Lua program by handling a one-shot ATTACH verb
// and from then on shoveling raw bytes both ways via the supervisor's
// IPC primitives.
//
// Lifecycle: luaHandlerBind(server) at start, luaHandlerBind(nullptr)
// at stop. Instance-death cascade tears down all that instance's
// routed connections; explicit Lua close, user-side close, billing
// eviction, and RUDP idle GC each reach the same per-connection
// teardown via the read-loop's error path.

#include <ces/l2/compute_lua_handler.h>
#include <ces/buffer.h>

#include <ces/l2/net_multiplexer.h>
#include <ces/l2/compute_handler.h>
#include <ces/ramfilestore.h>          // ces::sha256
#include <ces/keys.h>
#include <ces/l2/net_envelope.h>
#include <ces/server.h>
#include <ces/types.h>

#include <minx/blog.h>
#include <minx/rudp/rudp_stream.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

LOG_MODULE("lua");

namespace ces {

namespace {

// ATTACH verb code. Single-verb protocol; once ATTACH succeeds the
// channel is in DATA mode.
constexpr uint8_t kVerbAttach = 0x01;

// CONN_CLOSED reason codes pushed to the child. Best-effort; the
// program treats any nonzero value as "unexpected end."
constexpr uint8_t kCloseReasonNormal     = 0x00;  // peer-closed cleanly
constexpr uint8_t kCloseReasonInternal   = 0x01;  // server bookkeeping issue
constexpr uint8_t kCloseReasonInstance   = 0x02;  // instance dying
constexpr uint8_t kCloseReasonProgram    = 0x03;  // Lua called conn:close()

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

std::atomic<CesServer*> gServer{nullptr};

struct ConnCtx : std::enable_shared_from_this<ConnCtx> {
  std::shared_ptr<minx::RudpStream> stream;
  BoundChannelContext bound;
  uint64_t instanceId = 0;
  uint64_t connId = 0;
  bool attached = false;
  bool closed = false;
  // Per-read scratch. RUDP's MAX_MESSAGE_SIZE is 1241 B per reliable
  // message, so even a small buffer drains the wire efficiently.
  std::array<uint8_t, 8 * 1024> readBuf{};
  // Outbound write serialization. RudpStream forbids overlapping
  // async_writes; the child can fire conn:write() bursts that arrive
  // back-to-back as TAG_CONN_DATA_OUT frames. We queue them here and
  // kick the next one only after the previous async_write completes.
  std::deque<std::shared_ptr<ces::Bytes>> writeQueue;
  bool writing = false;
};

// Keyed by (instance_id, conn_id). All access on rpcTaskIO_.
using ConnKey = std::pair<uint64_t, uint64_t>;
std::map<ConnKey, std::shared_ptr<ConnCtx>> gConns;

// ---------------------------------------------------------------------------
// Wire helpers (response envelope mirrors file/compute: server-signed)
// ---------------------------------------------------------------------------

uint64_t nowMicros() {
  return static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count());
}

// Build the full response wire bytes, server-signed:
//   [u8 status][preamble][u64 time_us][u64 req_sig_hash]
//   [u8 sha256[32]][u8 sig[65]]
// sha256 input: status || verb || preamble || time_us || req_sig_hash.
minx::Bytes buildResponseEnvelope(
    CesServer* server,
    uint8_t verb,
    uint8_t status,
    std::span<const uint8_t> preamble,
    uint64_t reqSigHash) {
  // [status][preamble][time_us][reqSigHash][sha256][sig]
  const size_t total = 1 + preamble.size() + 8 + 8 + 32 + 65;
  minx::Bytes out(total);
  minx::Buffer buf(out);
  buf.put<uint8_t>(status);
  buf.put(preamble);
  uint64_t timeUs = nowMicros();
  buf.put<uint64_t>(timeUs);
  buf.put<uint64_t>(reqSigHash);

  // Compute the digest over a parallel pre-sized buffer.
  const size_t hashSize = 1 + 1 + preamble.size() + 8 + 8;
  minx::Bytes hashIn(hashSize);
  minx::Buffer hbuf(hashIn);
  hbuf.put<uint8_t>(status);
  hbuf.put<uint8_t>(verb);
  hbuf.put(preamble);
  hbuf.put<uint64_t>(timeUs);
  hbuf.put<uint64_t>(reqSigHash);
  minx::Hash digest = ces::sha256(
    reinterpret_cast<const uint8_t*>(hashIn.data()), hashIn.size());
  buf.put(digest);

  ces::Signature sig = server->_serverKeyPair().signData(
    std::span<const uint8_t>(digest.data(), digest.size()));
  buf.put(sig);
  return out;
}

// ---------------------------------------------------------------------------
// Per-connection lifecycle helpers
// ---------------------------------------------------------------------------

void dataReadLoop(std::shared_ptr<ConnCtx> ctx);

// Tear down a connection from the server side. Drops the routing
// entry, sends CONN_CLOSED to the child, asks RUDP for a graceful
// close on the channel. Safe to call multiple times — second call is
// a no-op once `closed`.
void teardownConn(std::shared_ptr<ConnCtx> ctx, uint8_t reason,
                   bool notifyChild) {
  if (ctx->closed) return;
  ctx->closed = true;
  if (ctx->attached && notifyChild) {
    computeSendConnClosed(ctx->instanceId, ctx->connId, reason);
  }
  if (ctx->attached) {
    gConns.erase({ctx->instanceId, ctx->connId});
  }
  // Graceful close. shutdown() lets any in-flight async_write (e.g.
  // the program's final "bye\n") drain into Rudp's sendBuf, then
  // fires HS_CLOSE within kRudpStreamCloseTimeout. The user's dial
  // sees a clean EOF instead of waiting on idle GC (60s).
  if (ctx->stream) {
    ctx->stream->shutdown(kRudpStreamCloseTimeout);
    ctx->stream.reset();
  }
}

// Drain the per-conn writeQueue onto the stream, one async_write at
// a time. RudpStream forbids overlapping writes, so we serialize even
// though every call lands on the same strand.
void kickConnWrite(std::shared_ptr<ConnCtx> ctx) {
  if (ctx->writing || ctx->writeQueue.empty()
      || ctx->closed || !ctx->stream) {
    return;
  }
  ctx->writing = true;
  auto head = ctx->writeQueue.front();
  auto stream = ctx->stream;
  boost::asio::async_write(
    *stream, boost::asio::buffer(*head),
    [ctx, head](const boost::system::error_code& ec, std::size_t) {
      ctx->writing = false;
      if (!ctx->writeQueue.empty()) ctx->writeQueue.pop_front();
      if (ec) {
        // Stream broke. dataReadLoop on the same stream will see it
        // (or already has). Idempotent teardown.
        teardownConn(ctx, kCloseReasonInternal, ctx->attached);
        return;
      }
      kickConnWrite(ctx);
    });
}

// Send the ATTACH reply (signed by server). On OK, hands off to
// DATA mode. On error, drops the connection.
void sendAttachReply(std::shared_ptr<ConnCtx> ctx, uint8_t status,
                      uint64_t reqSigHash) {
  CesServer* server = gServer.load();
  if (!server) {
    teardownConn(ctx, kCloseReasonInternal, false);
    return;
  }
  minx::Bytes preamble;
  if (status == CES_OK) {
    ces::Buffer::put<uint64_t>(preamble, ctx->connId);
  }
  auto env = std::make_shared<minx::Bytes>(
    buildResponseEnvelope(
      server, kVerbAttach, status,
      std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(preamble.data()), preamble.size()),
      reqSigHash));
  auto stream = ctx->stream;
  // ATTACH-reply is always the first write on a fresh ConnCtx — no
  // other writes can have been queued before it. So we can wire the
  // OK→dataReadLoop hand-off directly here without competing with the
  // generic kickConnWrite path.
  ctx->writing = true;
  boost::asio::async_write(
    *stream, boost::asio::buffer(*env),
    [ctx, env, status](const boost::system::error_code& ec,
                        std::size_t) {
      ctx->writing = false;
      if (ec || status != CES_OK) {
        // On write failure or non-OK status, drop. Notify the child
        // only if we got far enough to register the conn.
        teardownConn(ctx, kCloseReasonInternal, ctx->attached);
        return;
      }
      // OK and write succeeded — channel is in DATA mode.
      kickConnWrite(ctx);  // drain anything the child sent meanwhile
      dataReadLoop(ctx);
    });
}

// Read the per-op envelope for the ATTACH verb:
//   [u8 verb=0x01][u32 preamble_len][preamble][65 sig]
// preamble = [u16 name_len][source_name].
void readAttachVerb(std::shared_ptr<ConnCtx> ctx) {
  auto stream = ctx->stream;
  auto verbBuf = std::make_shared<std::array<uint8_t, 1>>();
  boost::asio::async_read(
    *stream, boost::asio::buffer(*verbBuf),
    [ctx, verbBuf](const boost::system::error_code& ec, std::size_t) {
      if (ec) {
        teardownConn(ctx, kCloseReasonInternal, false);
        return;
      }
      uint8_t verb = (*verbBuf)[0];
      if (verb != kVerbAttach) {
        LOGDEBUG << "builtin:lua bad first verb"
                 << VAR(int(verb));
        teardownConn(ctx, kCloseReasonInternal, false);
        return;
      }
      auto lenBuf = std::make_shared<std::array<uint8_t, 4>>();
      boost::asio::async_read(
        *ctx->stream, boost::asio::buffer(*lenBuf),
        [ctx, lenBuf](const boost::system::error_code& e2, std::size_t) {
          if (e2) {
            teardownConn(ctx, kCloseReasonInternal, false);
            return;
          }
          uint32_t preLen = ces::Buffer::peek<uint32_t>(
            std::span<const uint8_t>(*lenBuf), 0);
          if (preLen != 8) {
            // ATTACH preamble is exactly [u64 instance_id]. Anything
            // else is a wire-format mismatch (likely an old client).
            teardownConn(ctx, kCloseReasonInternal, false);
            return;
          }
          auto preBuf = std::make_shared<ces::Bytes>(preLen);
          boost::asio::async_read(
            *ctx->stream, boost::asio::buffer(*preBuf),
            [ctx, preBuf](const boost::system::error_code& e3,
                          std::size_t) {
              if (e3) {
                teardownConn(ctx, kCloseReasonInternal, false);
                return;
              }
              auto sigBuf = std::make_shared<std::array<uint8_t, 65>>();
              boost::asio::async_read(
                *ctx->stream, boost::asio::buffer(*sigBuf),
                [ctx, preBuf, sigBuf]
                (const boost::system::error_code& e4, std::size_t) {
                  if (e4) {
                    teardownConn(ctx, kCloseReasonInternal, false);
                    return;
                  }
                  // Verify per-op sig against the bound pubkey.
                  if (!ces::verifyPerOp(
                        ctx->bound, kVerbAttach,
                        std::span<const uint8_t>(
                          preBuf->data(), preBuf->size()),
                        *sigBuf)) {
                    LOGDEBUG << "builtin:lua ATTACH sig verify FAILED";
                    teardownConn(ctx, kCloseReasonInternal, false);
                    return;
                  }
                  // Decode preamble: [u64 instance_id]. ATTACH is a
                  // one-shot verb on a fresh channel — no nonce needed,
                  // sig dedup handles the trivial replay case.
                  uint64_t instId = ces::Buffer::peek<uint64_t>(
                    std::span<const uint8_t>(*preBuf), 0);
                  uint64_t sigHash = ces::sigDedupHash(*sigBuf);

                  if (!computeInstanceExists(instId)) {
                    sendAttachReply(
                      ctx, CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND,
                      sigHash);
                    return;
                  }
                  if (!computeInstanceAcceptsConnections(instId)) {
                    sendAttachReply(
                      ctx, CES_ERROR_NOT_LISTENING, sigHash);
                    return;
                  }
                  // Allocate conn_id + register routing + tell child.
                  std::array<uint8_t, 32> userPk{};
                  std::memcpy(userPk.data(),
                              ctx->bound.boundPubkey.getHash().data(),
                              32);
                  uint64_t connId = computeOpenConnection(instId, userPk);
                  if (connId == 0) {
                    sendAttachReply(
                      ctx, CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND,
                      sigHash);
                    return;
                  }
                  ctx->instanceId = instId;
                  ctx->connId = connId;
                  ctx->attached = true;
                  gConns.emplace(ConnKey{instId, connId}, ctx);
                  LOGDEBUG << "builtin:lua attached"
                           << VAR(instId) << VAR(connId);
                  sendAttachReply(ctx, CES_OK, sigHash);
                });
            });
        });
    });
}

// DATA mode read loop. Reads bytes from the stream and forwards them
// to the child via the supervisor's IPC. On error (channel closed by
// any party), tears down the connection.
void dataReadLoop(std::shared_ptr<ConnCtx> ctx) {
  if (ctx->closed || !ctx->stream) return;
  auto stream = ctx->stream;
  stream->async_read_some(
    boost::asio::buffer(ctx->readBuf),
    [ctx](const boost::system::error_code& ec, std::size_t n) {
      if (ec) {
        // Stream ended. Notify the child and clean up. Reason
        // depends on which closeReason RUDP attached, if any.
        uint8_t reason = kCloseReasonNormal;
        if (ctx->stream) {
          auto cr = ctx->stream->getCloseReason();
          if (cr && *cr != minx::Rudp::CloseReason::PEER_CLOSED) {
            reason = kCloseReasonInternal;
          }
        }
        teardownConn(ctx, reason, true);
        return;
      }
      if (n > 0) {
        computeSendConnDataIn(ctx->instanceId, ctx->connId,
                               ctx->readBuf.data(), n);
      }
      dataReadLoop(ctx);
    });
}

// ---------------------------------------------------------------------------
// CesPlex handler class
// ---------------------------------------------------------------------------

class LuaHandler : public CesPlexHandler {
public:
  void serve(std::shared_ptr<minx::RudpStream> stream,
             BoundChannelContext bound) override {
    if (!gServer.load()) {
      LOGWARNING << "builtin:lua invoked with no bound CesServer";
      return;
    }
    auto ctx = std::make_shared<ConnCtx>();
    ctx->stream = std::move(stream);
    ctx->bound = std::move(bound);
    readAttachVerb(ctx);
  }
};

LuaHandler gLuaHandler;

} // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void luaHandlerBind(CesServer* server) {
  if (server == nullptr) {
    // Tear down all known conns. We don't notify the children — the
    // compute supervisor's own teardown will do that via
    // luaHandlerOnInstanceDying as it kills each instance.
    for (auto& [_, ctx] : gConns) {
      ctx->closed = true;
      if (ctx->stream) {
        ctx->stream->shutdown(kRudpStreamCloseTimeout);
        ctx->stream.reset();
      }
    }
    gConns.clear();
    gServer.store(nullptr);
    return;
  }
  gServer.store(server);
}

void luaHandlerHandleConnDataOut(uint64_t instId, uint64_t connId,
                                  const uint8_t* data, size_t len) {
  auto it = gConns.find({instId, connId});
  if (it == gConns.end()) return;
  auto ctx = it->second;
  if (ctx->closed || !ctx->stream || len == 0) return;
  ctx->writeQueue.push_back(
    std::make_shared<ces::Bytes>(data, data + len));
  kickConnWrite(ctx);
}

void luaHandlerHandleConnClose(uint64_t instId, uint64_t connId) {
  auto it = gConns.find({instId, connId});
  if (it == gConns.end()) return;
  auto ctx = it->second;
  // Program asked us to close. Don't echo the CONN_CLOSED back to it.
  teardownConn(ctx, kCloseReasonProgram, /*notifyChild=*/false);
}

void luaHandlerOnInstanceDying(uint64_t instId) {
  // Tear down every connection routed to this instance. We don't
  // notify the child (it's about to die anyway).
  for (auto it = gConns.begin(); it != gConns.end(); ) {
    if (it->first.first != instId) { ++it; continue; }
    auto ctx = it->second;
    ctx->closed = true;
    if (ctx->stream) {
      ctx->stream->shutdown(kRudpStreamCloseTimeout);
      ctx->stream.reset();
    }
    it = gConns.erase(it);
  }
}

} // namespace ces

// Static registration.
REGISTER_CESPLEX_BUILTIN("lua", ::ces::gLuaHandler, LuaHandler)

// TU anchor — net_multiplexer.cpp references this via its anchor array.
extern "C" { int compute_lua_handler_anchor = 1; }
