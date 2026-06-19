// compute_lua_handler.h - builtin:lua handler lifecycle API
//
// The lua handler is a compiled-in CesPlex handler registered as
// "lua" in the global builtin registry, mounted at /ces/lua/1. Its
// job is to route a user's RUDP channel to a running cesluajitd
// instance: the user binds, sends a one-shot ATTACH verb naming the
// target pid, and from then on the channel is a raw byte
// stream into and out of the program.
//
// Lifecycle: CesServer::start() calls luaHandlerBind(this) after
// CesPlex is constructed, and luaHandlerBind(nullptr) on shutdown
// before CesPlex is torn down.

#pragma once

#include <cstddef>
#include <cstdint>

namespace ces {

class CesServer;

// Bind/unbind the builtin:lua handler to a CesServer.
void luaHandlerBind(CesServer* server);

// Cross-handler dispatchers. The compute supervisor calls these
// when it sees CONN_DATA_OUT or CONN_CLOSE frames coming FROM the
// child process (Lua program writing bytes back to the user, or
// closing a connection from the program side). The lua handler
// looks up the (pid, conn_id) pair in its routing table
// and pushes bytes / closes the appropriate RudpStream.
//
// Also called when an instance dies (any reason) to tear down all
// of that instance's connections.
void luaHandlerHandleConnDataOut(uint64_t pid, uint64_t connId,
                                  const uint8_t* data, size_t len);
void luaHandlerHandleConnClose(uint64_t pid, uint64_t connId);
void luaHandlerOnInstanceDying(uint64_t pid);

} // namespace ces
