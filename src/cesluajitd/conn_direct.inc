// ---------------------------------------------------------------------------
// Direct transport (/ces/luarpc/1) plumbing for the unified ces.conn API: the
// conn write/close ops, the bridge-event dispatcher, and outbound connect().
// These feed the SAME listener + run loop as the relay; the only program-
// visible mark of the transport is conn.source == 1. conn write/close hop to
// the endpoint strand; conn.pubkey is the authenticated pubkey of the peer.
// ---------------------------------------------------------------------------
constexpr const char* kRegLuaRpcConns    = "ces.conn.direct.live";  // [native] = conn

// conn:write(bytes) → true | false (false if the conn is already closed).
int lua_ces_luarpc_conn_write(lua_State* L) {
  luaL_checktype(L, 1, LUA_TTABLE);
  size_t n = 0;
  const char* s = luaL_checklstring(L, 2, &n);
  lua_getfield(L, 1, "closed");
  bool closed = lua_toboolean(L, -1);
  lua_pop(L, 1);
  if (closed) { lua_pushboolean(L, 0); return 1; }
  lua_getfield(L, 1, "__sid");
  uint64_t id = static_cast<uint64_t>(lua_tonumber(L, -1));
  lua_pop(L, 1);
  luarpc_conn_write(id, std::string(s, n));
  lua_pushboolean(L, 1);
  return 1;
}

// conn:close() — graceful close. Idempotent.
int lua_ces_luarpc_conn_close(lua_State* L) {
  luaL_checktype(L, 1, LUA_TTABLE);
  lua_getfield(L, 1, "__sid");
  uint64_t id = static_cast<uint64_t>(lua_tonumber(L, -1));
  lua_pop(L, 1);
  lua_pushboolean(L, 1);
  lua_setfield(L, 1, "closed");
  // Drop it from the live registry now. The peer-close path does this in
  // dispatch, but a program-initiated close sets closing=true on the endpoint
  // side, which suppresses the Closed event — so without this the conn table
  // would leak in kRegLuaRpcConns forever.
  lua_getfield(L, LUA_REGISTRYINDEX, kRegLuaRpcConns);
  if (lua_istable(L, -1)) {
    lua_pushnumber(L, static_cast<lua_Number>(id));
    lua_pushnil(L);
    lua_rawset(L, -3);
  }
  lua_pop(L, 1);
  luarpc_conn_close(id);
  return 0;
}

// Build a direct conn table {id=host uid, source=1, __sid=native, pubkey(32B),
// closed, write, close}, key the live table by the native id, and leave it on
// the stack top. Same shape as the relay builder; only source and the transport
// the write/close route to differ.
void make_luarpc_conn(lua_State* L, uint64_t id, const uint8_t* peer) {
  lua_newtable(L);
  lua_pushnumber(L, static_cast<lua_Number>(g_conn_uid_next++));
  lua_setfield(L, -2, "id");
  lua_pushinteger(L, CONN_SOURCE_DIRECT);
  lua_setfield(L, -2, "source");
  lua_pushnumber(L, static_cast<lua_Number>(id));   // native routing id
  lua_setfield(L, -2, "__sid");
  lua_pushlstring(L, reinterpret_cast<const char*>(peer), 32);
  lua_setfield(L, -2, "pubkey");
  lua_pushboolean(L, 0);
  lua_setfield(L, -2, "closed");
  lua_pushcfunction(L, guarded<lua_ces_luarpc_conn_write>);
  lua_setfield(L, -2, "write");
  lua_pushcfunction(L, guarded<lua_ces_luarpc_conn_close>);
  lua_setfield(L, -2, "close");
  lua_getfield(L, LUA_REGISTRYINDEX, kRegLuaRpcConns);
  if (lua_istable(L, -1)) {
    lua_pushnumber(L, static_cast<lua_Number>(id));
    lua_pushvalue(L, -3);  // the conn table
    lua_rawset(L, -3);
  }
  lua_pop(L, 1);  // live table
}

// Push live-conn[id] (or nil) onto the stack.
void push_luarpc_conn(lua_State* L, uint64_t id) {
  lua_getfield(L, LUA_REGISTRYINDEX, kRegLuaRpcConns);
  if (!lua_istable(L, -1)) { lua_pop(L, 1); lua_pushnil(L); return; }
  lua_pushnumber(L, static_cast<lua_Number>(id));
  lua_rawget(L, -2);
  lua_remove(L, -2);  // drop live table, leave conn-or-nil on top
}

// Drop a direct conn from the live-conns registry (after on_close, or when a
// close event has no handler to run).
void remove_luarpc_conn(lua_State* L, uint64_t id) {
  lua_getfield(L, LUA_REGISTRYINDEX, kRegLuaRpcConns);
  if (lua_istable(L, -1)) {
    lua_pushnumber(L, static_cast<lua_Number>(id));
    lua_pushnil(L);
    lua_rawset(L, -3);
  }
  lua_pop(L, 1);
}

// Direct-transport twin of setup_handler_co: prepares coroutine `co` to run the
// listener callback for bridge event `e`. Same contract (pushes [cb, conn,
// (data)], returns arg count or -1).
int setup_luarpc_handler_co(lua_State* mainL, lua_State* co,
                            const LuaRpcEvent& e) {
  lua_getfield(mainL, LUA_REGISTRYINDEX, kRegListenerTable);
  if (!lua_istable(mainL, -1)) { lua_pop(mainL, 1); return -1; }

  if (e.type == LuaRpcEvent::Type::Opened) {
    make_luarpc_conn(mainL, e.connId, e.peer.data());  // [listener, conn]
    lua_getfield(mainL, -2, "on_open");                 // [listener, conn, cb]
    if (!lua_isfunction(mainL, -1)) { lua_pop(mainL, 3); return -1; }
    lua_xmove(mainL, co, 1);                            // cb   -> co
    lua_xmove(mainL, co, 1);                            // conn -> co
    lua_pop(mainL, 1);
    return 1;
  }

  const char* cbname =
    (e.type == LuaRpcEvent::Type::Data) ? "on_data" : "on_close";
  lua_getfield(mainL, -1, cbname);                      // [listener, cb]
  bool hasCb = lua_isfunction(mainL, -1);
  push_luarpc_conn(mainL, e.connId);                    // [listener, cb, conn]
  if (lua_isnil(mainL, -1)) { lua_pop(mainL, 3); return -1; }
  if (e.type == LuaRpcEvent::Type::Closed) {
    lua_pushboolean(mainL, 1);
    lua_setfield(mainL, -2, "closed");
  }
  if (!hasCb) { lua_pop(mainL, 3); return -1; }
  lua_pushvalue(mainL, -2);                             // dup cb
  lua_xmove(mainL, co, 1);                              // cb   -> co
  lua_xmove(mainL, co, 1);                              // conn -> co
  lua_pop(mainL, 2);
  if (e.type == LuaRpcEvent::Type::Data) {
    lua_pushlstring(co, e.bytes.data(), e.bytes.size());
    return 2;
  }
  return 1;
}

// Direct-transport twin of conn_advance.
static void luarpc_advance(lua_State* mainL, uint64_t id) {
  auto it = g_luarpc_exec.find(id);
  if (it == g_luarpc_exec.end()) return;
  LuaRpcExec& ce = it->second;
  if (ce.busy || ce.pending.empty()) return;
  LuaRpcEvent e = std::move(ce.pending.front());
  ce.pending.pop_front();
  bool isClose = (e.type == LuaRpcEvent::Type::Closed);

  lua_State* co = lua_newthread(mainL);
  int ref = luaL_ref(mainL, LUA_REGISTRYINDEX);
  int nargs = setup_luarpc_handler_co(mainL, co, e);
  if (nargs < 0) {
    luaL_unref(mainL, LUA_REGISTRYINDEX, ref);
    if (isClose) { remove_luarpc_conn(mainL, id); g_luarpc_exec.erase(id); return; }
    g_luarpc_advance.push_back(id);
    return;
  }
  g_coro_refs[co] = ref;
  ce.busy = true;
  g_handler_co[co] = HandlerCo{id, isClose, true};
  resume_coro(mainL, co, nargs);
}

// Direct-transport twin of drain_conn_advance.
static void drain_luarpc_advance(lua_State* mainL) {
  while (!g_luarpc_advance.empty()) {
    uint64_t id = g_luarpc_advance.front();
    g_luarpc_advance.pop_front();
    luarpc_advance(mainL, id);
  }
}

// Resume coroutines whose ces.conn.connect finished (endpoint thread delivered
// the result). Conn construction touches Lua state, so it happens here on the
// run-loop thread, not on the endpoint thread.
static void drain_connect_done(lua_State* mainL) {
  for (;;) {
    ConnectDelivery d;
    {
      std::lock_guard<std::mutex> lk(g_luarpc_mx);
      if (g_connect_done.empty()) break;
      d = std::move(g_connect_done.front());
      g_connect_done.pop_front();
    }
    if (!g_parked.erase(d.co)) continue;   // already resumed (future timeout)
    int n;
    if (d.res.status != ces::CES_OK) {
      lua_checkstack(d.co, 2);
      lua_pushnil(d.co);
      lua_pushstring(d.co, d.res.status == ces::CES_ERROR_PROTO_REJECTED
                             ? "bind rejected or wrong peer"
                             : "connect failed (network)");
      n = 2;
    } else {
      lua_checkstack(d.co, 2);
      make_luarpc_conn(d.co, d.res.connId, d.res.peer.data());
      n = 1;
    }
    resume_coro(mainL, d.co, n);
  }
}

// Resume coroutines whose offloaded blocking call (a worker-pool job) finished.
// The worker delivered a "deliver" closure that pushes the Lua results here, on
// the run-loop thread.
static void drain_offload_done(lua_State* mainL) {
  for (;;) {
    OffloadDone d;
    {
      std::lock_guard<std::mutex> lk(g_offload_mx);
      if (g_offload_done.empty()) break;
      d = std::move(g_offload_done.front());
      g_offload_done.pop_front();
    }
    if (!g_parked.erase(d.co)) continue;
    lua_checkstack(d.co, LUA_MINSTACK);
    int n = d.deliver(d.co);
    resume_coro(mainL, d.co, n);
  }
}

// Route one bridge event into its conn's serialized queue and request dispatch;
// the handler runs (as a coroutine) in luarpc_advance, drained by the run loop.
void dispatch_luarpc_event(lua_State* L, LuaRpcEvent e) {
  uint64_t id = e.connId;
  g_luarpc_exec[id].pending.push_back(std::move(e));
  g_luarpc_advance.push_back(id);
  (void)L;
}

// ces.conn.connect(addr, server_pubkey(32) [, timeout_ms]) → conn | nil, err.
// Dials a remote (or this) lua host's /ces/luarpc/1 out the instance's OWN rpc
// socket — the only outbound path (the relay is inbound-only: the server brings
// users in, it is not a generic egress proxy). From a coroutine it yields; on
// success returns a source=1 conn whose inbound data flows to the unified
// listener's on_data like any other. Optional timeout_ms bounds the bind
// handshake at the source (default 15000); a dead peer fails in ~timeout_ms
// rather than waiting on RUDP idle-GC. (Listen + run are unified — see
// ces.conn.set_listener / ces.run.)
int lua_ces_conn_connect(lua_State* L) {
  size_t alen = 0;
  const char* addr = luaL_checklstring(L, 1, &alen);
  size_t plen = 0;
  const char* spk = luaL_checklstring(L, 2, &plen);
  if (plen != 32) {
    lua_pushnil(L);
    lua_pushstring(L, "server pubkey must be 32 bytes");
    return 2;
  }
  int timeoutMs = static_cast<int>(luaL_optinteger(L, 3, 15000));
  if (timeoutMs < 0) timeoutMs = 0;   // 0 = no bind timeout (RUDP idle-GC only)
  luarpc_ensure_endpoint();   // lazy-open the port for dialing
  if (!g_luarpc_io || !g_luarpc_rudp || !g_luarpc_signer) {
    lua_pushnil(L);
    lua_pushstring(L,
      "networking permanently disabled (this instance has no rpc port)");
    return 2;
  }
  minx::SockAddr peer;
  try {
    auto ep = ces::Resolver::resolveUdp(std::string(addr, alen));
    auto a = ep.address();
    if (a.is_v4()) {
      a = boost::asio::ip::make_address_v6(
            boost::asio::ip::v4_mapped, a.to_v4());
    }
    peer = minx::SockAddr(a, ep.port());
  } catch (const std::exception&) {
    lua_pushnil(L);
    lua_pushstring(L, "address resolve failed");
    return 2;
  }
  std::array<uint8_t, 32> expectPk{};
  std::memcpy(expectPk.data(), spk, 32);

  // From a coroutine: park and let the endpoint's io thread drive the bind,
  // then resume on completion via g_connect_done. The loop never freezes; the
  // bind is bounded at the source by timeoutMs (see luarpc_do_connect).
  if (io_yieldable(L)) {
    lua_State* co = L;
    g_parked.insert(co);
    boost::asio::post(*g_luarpc_io, [peer, expectPk, co, timeoutMs]() {
      luarpc_do_connect(peer, expectPk, [co](LuaRpcConnectResult res) {
        {
          std::lock_guard<std::mutex> lk(g_luarpc_mx);
          g_connect_done.push_back(ConnectDelivery{co, std::move(res)});
        }
        if (g_luarpc_wakefd >= 0) {
          uint64_t one = 1;
          ssize_t w = ::write(g_luarpc_wakefd, &one, sizeof(one));
          (void)w;
        }
      }, timeoutMs);
    });
    return lua_yield(L, 0);
  }

  // Main chunk (cannot yield): block on the round-trip -- the degenerate case.
  auto pr = std::make_shared<std::promise<LuaRpcConnectResult>>();
  auto fut = pr->get_future();
  boost::asio::post(*g_luarpc_io, [peer, expectPk, pr, timeoutMs]() {
    luarpc_do_connect(peer, expectPk,
      [pr](LuaRpcConnectResult res) { pr->set_value(std::move(res)); },
      timeoutMs);
  });
  if (fut.wait_for(std::chrono::seconds(15)) != std::future_status::ready) {
    lua_pushnil(L);
    lua_pushstring(L, "connect timeout");
    return 2;
  }
  LuaRpcConnectResult res = fut.get();
  if (res.status != ces::CES_OK) {
    lua_pushnil(L);
    lua_pushstring(L, res.status == ces::CES_ERROR_INTERNAL
                        ? "connect failed (network)"
                        : "bind rejected or wrong peer");
    return 2;
  }
  make_luarpc_conn(L, res.connId, res.peer.data());
  return 1;
}

// ces.rpc_port() → the UDP port this instance hosts /ces/luarpc/1 on (0 if it
// got none). A serving program advertises (host, this port) so peers can dial.
int lua_ces_rpc_port(lua_State* L) {
  lua_pushnumber(L, static_cast<lua_Number>(g_rpc_port));
  return 1;
}

