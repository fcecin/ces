// compute_lua_handler.h - builtin:lua: per-server channel-routing handler.
//
// Mounts /ces/lua/1. Routes a user's signed-bound RUDP channel to a running
// cesluajitd instance via a one-shot ATTACH verb, then shovels raw bytes both
// ways through the compute supervisor's IPC.
//
// One LuaHandler OBJECT per CesServer (owned by the server). No process-global
// state. Lifecycle: the server constructs a LuaHandler(this), mounts it into
// its CesPlex, and drops it (after stop()) on shutdown.

#pragma once

#include <ces/cesplex/mux.h>   // CesPlexHandler, BoundChannelContext
#include <minx/rudp/rudp_stream.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <utility>

namespace ces {

class CesServer;
struct LuaConnCtx;   // per-connection state, defined in the .cpp

class LuaHandler : public CesPlexHandler {
public:
  explicit LuaHandler(CesServer* server);
  ~LuaHandler();

  LuaHandler(const LuaHandler&) = delete;
  LuaHandler& operator=(const LuaHandler&) = delete;

  // CesPlexHandler: a freshly-bound /ces/lua/1 channel. Reads the one-shot
  // ATTACH verb, then enters raw-byte DATA mode into the target instance.
  void serve(std::shared_ptr<minx::RudpStream> stream,
             BoundChannelContext bound) override;

  // Tear down all routed connections. Call on shutdown before CesPlex /
  // rpcRudp_ go away.
  void stop();

  // Cross-handler dispatchers, called by the compute supervisor when a child
  // writes bytes back / closes a conn from the program side, or an instance
  // dies. Reached via server->luaHandler().
  void handleConnDataOut(uint64_t pid, uint64_t connId,
                         const uint8_t* data, std::size_t len);
  void handleConnClose(uint64_t pid, uint64_t connId);
  void onInstanceDying(uint64_t pid);

private:
  using ConnKey = std::pair<uint64_t, uint64_t>;   // (pid, conn_id)

  void teardownConn(std::shared_ptr<LuaConnCtx> ctx, uint8_t reason,
                    bool notifyChild);
  void kickConnWrite(std::shared_ptr<LuaConnCtx> ctx);
  void sendAttachReply(std::shared_ptr<LuaConnCtx> ctx, uint8_t status,
                       uint64_t reqSigHash);
  void readAttachVerb(std::shared_ptr<LuaConnCtx> ctx);
  void dataReadLoop(std::shared_ptr<LuaConnCtx> ctx);

  CesServer* server_;
  std::map<ConnKey, std::shared_ptr<LuaConnCtx>> conns_;
};

} // namespace ces
