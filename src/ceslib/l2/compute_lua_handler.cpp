// compute_lua_handler.cpp - builtin:lua handler (per-server object). See header.
//
// Mounts /ces/lua/1. Routes a user's signed-bound RUDP channel to a running
// cesluajitd Lua program by handling a one-shot ATTACH verb and from then on
// shoveling raw bytes both ways via the supervisor's IPC primitives.
//
// One LuaHandler per CesServer; no process-global state. Instance-death
// cascade tears down all that instance's routed connections; explicit Lua
// close, user-side close, billing eviction, and RUDP idle GC each reach the
// same per-connection teardown via the read-loop's error path.

#include <ces/l2/compute_lua_handler.h>
#include <ces/buffer.h>

#include <ces/cesplex/mux.h>
#include <ces/l2/compute_handler.h>
#include <ces/ramfilestore.h>          // ces::sha256
#include <ces/keys.h>
#include <ces/cesplex/wire.h>
#include <ces/server.h>
#include <ces/types.h>

#include <minx/blog.h>
#include <minx/rudp/rudp_stream.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <cstring>
#include <deque>
#include <memory>
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

}  // namespace

struct LuaConnCtx : std::enable_shared_from_this<LuaConnCtx> {
  std::shared_ptr<minx::RudpStream> stream;
  BoundChannelContext bound;
  uint64_t pid = 0;
  uint64_t connId = 0;
  bool attached = false;
  bool closed = false;
  std::array<uint8_t, 8 * 1024> readBuf{};
  // Outbound write serialization. RudpStream forbids overlapping
  // async_writes; the child can fire conn:write() bursts that arrive
  // back-to-back. Queue them and kick the next only after the previous
  // async_write completes.
  std::deque<std::shared_ptr<ces::Bytes>> writeQueue;
  bool writing = false;
};

// ---------------------------------------------------------------------------
// LuaHandler
// ---------------------------------------------------------------------------

LuaHandler::LuaHandler(CesServer* server) : server_(server) {}

LuaHandler::~LuaHandler() { stop(); }

// Tear down a connection from the server side. Drops the routing entry,
// sends CONN_CLOSED to the child, asks RUDP for a graceful close. Safe to
// call multiple times -- a second call is a no-op once `closed`.
void LuaHandler::teardownConn(std::shared_ptr<LuaConnCtx> ctx, uint8_t reason,
                              bool notifyChild) {
  if (ctx->closed) return;
  ctx->closed = true;
  if (ctx->attached && notifyChild) {
    if (ComputeHandler* h = server_->computeHandler())
      h->sendConnClosed(ctx->pid, ctx->connId, reason);
  }
  if (ctx->attached) {
    conns_.erase({ctx->pid, ctx->connId});
  }
  // Graceful close so the user's dial sees a clean EOF instead of idle GC.
  if (ctx->stream) {
    ctx->stream->shutdown(kRudpStreamCloseTimeout);
    ctx->stream.reset();
  }
}

// Drain the per-conn writeQueue onto the stream, one async_write at a time.
void LuaHandler::kickConnWrite(std::shared_ptr<LuaConnCtx> ctx) {
  if (ctx->writing || ctx->writeQueue.empty()
      || ctx->closed || !ctx->stream) {
    return;
  }
  ctx->writing = true;
  auto head = ctx->writeQueue.front();
  auto stream = ctx->stream;
  boost::asio::async_write(
    *stream, boost::asio::buffer(*head),
    [this, ctx, head](const boost::system::error_code& ec, std::size_t) {
      ctx->writing = false;
      if (!ctx->writeQueue.empty()) ctx->writeQueue.pop_front();
      if (ec) {
        teardownConn(ctx, kCloseReasonInternal, ctx->attached);
        return;
      }
      kickConnWrite(ctx);
    });
}

// Send the ATTACH reply (signed by server). On OK, hands off to DATA mode.
void LuaHandler::sendAttachReply(std::shared_ptr<LuaConnCtx> ctx,
                                 uint8_t status, uint64_t reqSigHash) {
  minx::Bytes preamble;
  if (status == CES_OK) {
    ces::Buffer::put<uint64_t>(preamble, ctx->connId);
  }
  auto env = std::make_shared<ces::Bytes>(
    buildPerOpResponse(
      server_->_serverKeyPair(), kVerbAttach, status,
      std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(preamble.data()), preamble.size()),
      reqSigHash));
  auto stream = ctx->stream;
  // ATTACH-reply is always the first write on a fresh ctx -- no other writes
  // can have been queued before it, so wire the OK->dataReadLoop hand-off
  // directly here without competing with the generic kickConnWrite path.
  ctx->writing = true;
  boost::asio::async_write(
    *stream, boost::asio::buffer(*env),
    [this, ctx, env, status](const boost::system::error_code& ec,
                             std::size_t) {
      ctx->writing = false;
      if (ec || status != CES_OK) {
        teardownConn(ctx, kCloseReasonInternal, ctx->attached);
        return;
      }
      kickConnWrite(ctx);   // drain anything the child sent meanwhile
      dataReadLoop(ctx);
    });
}

// Read the per-op envelope for the ATTACH verb:
//   [u8 verb=0x01][u32 preamble_len][preamble][65 sig], preamble = [u64 pid].
void LuaHandler::readAttachVerb(std::shared_ptr<LuaConnCtx> ctx) {
  auto stream = ctx->stream;
  auto verbBuf = std::make_shared<std::array<uint8_t, 1>>();
  boost::asio::async_read(
    *stream, boost::asio::buffer(*verbBuf),
    [this, ctx, verbBuf](const boost::system::error_code& ec, std::size_t) {
      if (ec) { teardownConn(ctx, kCloseReasonInternal, false); return; }
      uint8_t verb = (*verbBuf)[0];
      if (verb != kVerbAttach) {
        LOGDEBUG << "builtin:lua bad first verb" << VAR(int(verb));
        teardownConn(ctx, kCloseReasonInternal, false);
        return;
      }
      auto lenBuf = std::make_shared<std::array<uint8_t, 4>>();
      boost::asio::async_read(
        *ctx->stream, boost::asio::buffer(*lenBuf),
        [this, ctx, lenBuf](const boost::system::error_code& e2, std::size_t) {
          if (e2) { teardownConn(ctx, kCloseReasonInternal, false); return; }
          uint32_t preLen = ces::Buffer::peek<uint32_t>(
            std::span<const uint8_t>(*lenBuf), 0);
          if (preLen != 8) {
            teardownConn(ctx, kCloseReasonInternal, false);
            return;
          }
          auto preBuf = std::make_shared<ces::Bytes>(preLen);
          boost::asio::async_read(
            *ctx->stream, boost::asio::buffer(*preBuf),
            [this, ctx, preBuf](const boost::system::error_code& e3,
                                std::size_t) {
              if (e3) { teardownConn(ctx, kCloseReasonInternal, false); return; }
              auto sigBuf = std::make_shared<std::array<uint8_t, 65>>();
              boost::asio::async_read(
                *ctx->stream, boost::asio::buffer(*sigBuf),
                [this, ctx, preBuf, sigBuf]
                (const boost::system::error_code& e4, std::size_t) {
                  if (e4) {
                    teardownConn(ctx, kCloseReasonInternal, false);
                    return;
                  }
                  if (!ces::verifyPerOp(
                        ctx->bound, kVerbAttach,
                        std::span<const uint8_t>(
                          preBuf->data(), preBuf->size()),
                        *sigBuf)) {
                    LOGDEBUG << "builtin:lua ATTACH sig verify FAILED";
                    teardownConn(ctx, kCloseReasonInternal, false);
                    return;
                  }
                  uint64_t pid = ces::Buffer::peek<uint64_t>(
                    std::span<const uint8_t>(*preBuf), 0);
                  uint64_t sigHash = ces::sigDedupHash(*sigBuf);

                  ComputeHandler* ch = server_->computeHandler();
                  if (!ch || !ch->instanceExists(pid)) {
                    sendAttachReply(
                      ctx, CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND, sigHash);
                    return;
                  }
                  if (!ch->instanceAcceptsConnections(pid)) {
                    sendAttachReply(ctx, CES_ERROR_NOT_LISTENING, sigHash);
                    return;
                  }
                  std::array<uint8_t, 32> userPk{};
                  std::memcpy(userPk.data(),
                              ctx->bound.boundPubkey.getHash().data(), 32);
                  uint64_t connId = ch->openConnection(pid, userPk);
                  if (connId == 0) {
                    sendAttachReply(
                      ctx, CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND, sigHash);
                    return;
                  }
                  ctx->pid = pid;
                  ctx->connId = connId;
                  ctx->attached = true;
                  conns_.emplace(ConnKey{pid, connId}, ctx);
                  LOGDEBUG << "builtin:lua attached"
                           << VAR(pid) << VAR(connId);
                  sendAttachReply(ctx, CES_OK, sigHash);
                });
            });
        });
    });
}

// DATA mode read loop: read bytes from the stream, forward to the child via
// the supervisor's IPC. On error (channel closed by any party), tear down.
void LuaHandler::dataReadLoop(std::shared_ptr<LuaConnCtx> ctx) {
  if (ctx->closed || !ctx->stream) return;
  auto stream = ctx->stream;
  stream->async_read_some(
    boost::asio::buffer(ctx->readBuf),
    [this, ctx](const boost::system::error_code& ec, std::size_t n) {
      if (ec) {
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
        if (ComputeHandler* h = server_->computeHandler())
          h->sendConnDataIn(ctx->pid, ctx->connId, ctx->readBuf.data(), n);
      }
      dataReadLoop(ctx);
    });
}

void LuaHandler::serve(std::shared_ptr<minx::RudpStream> stream,
                       BoundChannelContext bound) {
  auto ctx = std::make_shared<LuaConnCtx>();
  ctx->stream = std::move(stream);
  ctx->bound = std::move(bound);
  readAttachVerb(ctx);
}

void LuaHandler::stop() {
  // Tear down all known conns. We don't notify the children -- the compute
  // supervisor's own teardown does that via onInstanceDying as it kills each.
  for (auto& [_, ctx] : conns_) {
    ctx->closed = true;
    if (ctx->stream) {
      ctx->stream->shutdown(kRudpStreamCloseTimeout);
      ctx->stream.reset();
    }
  }
  conns_.clear();
}

void LuaHandler::handleConnDataOut(uint64_t pid, uint64_t connId,
                                   const uint8_t* data, std::size_t len) {
  auto it = conns_.find({pid, connId});
  if (it == conns_.end()) return;
  auto ctx = it->second;
  if (ctx->closed || !ctx->stream || len == 0) return;
  ctx->writeQueue.push_back(std::make_shared<ces::Bytes>(data, data + len));
  kickConnWrite(ctx);
}

void LuaHandler::handleConnClose(uint64_t pid, uint64_t connId) {
  auto it = conns_.find({pid, connId});
  if (it == conns_.end()) return;
  // Program asked us to close. Don't echo CONN_CLOSED back to it.
  teardownConn(it->second, kCloseReasonProgram, /*notifyChild=*/false);
}

void LuaHandler::onInstanceDying(uint64_t pid) {
  // Tear down every connection routed to this instance. Don't notify the
  // child (it's about to die anyway).
  for (auto it = conns_.begin(); it != conns_.end(); ) {
    if (it->first.first != pid) { ++it; continue; }
    auto ctx = it->second;
    ctx->closed = true;
    if (ctx->stream) {
      ctx->stream->shutdown(kRudpStreamCloseTimeout);
      ctx->stream.reset();
    }
    it = conns_.erase(it);
  }
}

} // namespace ces
