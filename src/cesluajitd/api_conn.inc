// ---------------------------------------------------------------------------
// ces.conn — /ces/lua/1 connection routing.
// ---------------------------------------------------------------------------
//
// Programs that want to accept user RUDP connections call
// ces.conn.set_listener({on_open, on_data, on_close}) to flip the
// server-side accept gate ON, then ces.conn.run() to enter the event
// loop. The runtime dispatches per-connection events to the matching
// callback. conn objects (Lua tables) provide :write(s) / :close()
// and read-only .id / .pubkey fields.
//
// No coroutines, no yielding — callback-driven for v1. Programs that
// need byte-streaming semantics keep their own per-conn state across
// callback invocations.
//
// The accept gate is one bool per instance, server-side. The listener
// table is held in the Lua registry; passing nil to set_listener
// flips the gate OFF (existing connections continue to work).

// Registry keys. kRegListenerTable is the SINGLE listener shared by BOTH
// transports — relay /ces/lua/1 and direct /ces/luarpc/1. Each transport keeps
// its OWN live-conn table keyed by its native conn id (relay: the supervisor's
// per-instance nextConnId; direct: this endpoint's g_luarpc_next_id) purely for
// inbound routing. Those two native spaces are independent and overlap, so they
// are NEVER the program-facing identity — see g_conn_uid_next.
constexpr const char* kRegListenerTable = "ces.conn.listener";
// Registry table service(string) -> handler fn, set by ces.peer.listen and
// read by drain_peer to dispatch an inbound /ces/peer/1 message.
constexpr const char* kRegPeerListeners = "ces.peer.listeners";
constexpr const char* kRegConnsTable    = "ces.conn.relay.live";  // [native] = conn

// Program-facing conn.id: ONE monotonic id owned entirely by this host, handed
// out at open for EITHER transport, so it is unique across both — a program can
// key its own state by conn.id with zero collisions. The native routing id is
// kept privately in conn.__sid. conn.source (below) still reports the origin.
// Lua-thread-only (the dispatchers and connect all run on the Lua thread).
uint64_t g_conn_uid_next = 1;

// conn.source — informational origin only, NOT identity and NOT used to route.
constexpr int CONN_SOURCE_RELAY  = 0;  // /ces/lua/1, server-relayed over the UDS
constexpr int CONN_SOURCE_DIRECT = 1;  // /ces/luarpc/1, this instance's own rpc port

// Per-conn close-reason byte (matches kCloseReason* in handler).
constexpr uint8_t CONN_CLOSE_NORMAL   = 0x00;
constexpr uint8_t CONN_CLOSE_INTERNAL = 0x01;
constexpr uint8_t CONN_CLOSE_INSTANCE = 0x02;
constexpr uint8_t CONN_CLOSE_PROGRAM  = 0x03;

// Push the registry-stored conn table for `conn_id` onto the stack,
// or nil if not present. Always pushes one value.
void push_conn_table(lua_State* L, uint64_t conn_id) {
  lua_getfield(L, LUA_REGISTRYINDEX, kRegConnsTable);
  if (!lua_istable(L, -1)) {
    lua_pop(L, 1);
    lua_pushnil(L);
    return;
  }
  // Use double-as-int key (LuaJIT 5.1 has no native u64 in tables;
  // double is exact for u64 < 2^53, our nextConnId starts at 1 and
  // grows monotonically per instance — well below 2^53).
  lua_pushnumber(L, static_cast<lua_Number>(conn_id));
  lua_rawget(L, -2);
  // Stack: [conns_table, conn_or_nil]. Remove conns_table.
  lua_remove(L, -2);
}

// Send TAG_CONN_DATA_OUT for (conn_id, bytes). Returns true on
// IPC write success.
bool send_conn_data_out(uint64_t conn_id,
                         const uint8_t* data, size_t len) {
  std::vector<uint8_t> body;
  body.reserve(sizeof(uint64_t) + sizeof(uint32_t) + len);
  put_u64(body, conn_id);
  put_u32(body, static_cast<uint32_t>(len));
  if (len > 0)
    body.insert(body.end(), data, data + len);
  return write_frame(TAG_CONN_DATA_OUT, 0, body.data(), body.size());
}

// Send TAG_CONN_CLOSE for conn_id.
bool send_conn_close(uint64_t conn_id) {
  std::vector<uint8_t> body;
  body.reserve(sizeof(uint64_t));
  put_u64(body, conn_id);
  return write_frame(TAG_CONN_CLOSE, 0, body.data(), body.size());
}

// conn:write(s) — Lua method on a conn table.
// Returns true on success, nil + err on failure.
int lua_ces_conn_write(lua_State* L) {
  if (!lua_istable(L, 1)) {
    lua_pushnil(L); lua_pushstring(L, "expected conn table"); return 2;
  }
  // Reject if marked closed.
  lua_getfield(L, 1, "closed");
  bool closed = lua_toboolean(L, -1);
  lua_pop(L, 1);
  if (closed) {
    lua_pushnil(L); lua_pushstring(L, "closed"); return 2;
  }
  lua_getfield(L, 1, "__sid");
  if (!lua_isnumber(L, -1)) {
    lua_pop(L, 1);
    lua_pushnil(L); lua_pushstring(L, "missing routing id"); return 2;
  }
  uint64_t id = static_cast<uint64_t>(lua_tonumber(L, -1));
  lua_pop(L, 1);

  size_t n = 0;
  const char* s = luaL_checklstring(L, 2, &n);
  if (n > 1024 * 1024) {
    lua_pushnil(L);
    lua_pushstring(L, "payload too large (max 1 MB per write)");
    return 2;
  }
  if (!send_conn_data_out(id, reinterpret_cast<const uint8_t*>(s), n)) {
    lua_pushnil(L); lua_pushstring(L, "ipc write failed"); return 2;
  }
  lua_pushboolean(L, 1);
  return 1;
}

// conn:close() — Lua method on a conn table.
int lua_ces_conn_close(lua_State* L) {
  if (!lua_istable(L, 1)) {
    lua_pushnil(L); lua_pushstring(L, "expected conn table"); return 2;
  }
  lua_getfield(L, 1, "closed");
  bool already = lua_toboolean(L, -1);
  lua_pop(L, 1);
  if (already) {
    lua_pushboolean(L, 1);
    return 1;
  }
  lua_getfield(L, 1, "__sid");
  uint64_t id = static_cast<uint64_t>(lua_tonumber(L, -1));
  lua_pop(L, 1);
  send_conn_close(id);
  // Mark closed locally + drop from g_conns_table. Note: the host
  // does not echo back CONN_CLOSED for program-side close (saves
  // an unnecessary IPC round-trip).
  lua_pushboolean(L, 1);
  lua_setfield(L, 1, "closed");
  lua_getfield(L, LUA_REGISTRYINDEX, kRegConnsTable);
  if (lua_istable(L, -1)) {
    lua_pushnumber(L, static_cast<lua_Number>(id));
    lua_pushnil(L);
    lua_rawset(L, -3);
  }
  lua_pop(L, 1);
  lua_pushboolean(L, 1);
  return 1;
}

// ces.conn.set_listener(table_or_nil) — the ONE accept gate for both transports.
// Non-nil: stores the listener, sends TAG_LISTEN_ON (relay accept gate), flips
// the direct accept gate on, and lazy-opens this instance's /ces/luarpc/1
// endpoint (a no-op if it got no rpc port). Inbound conns from EITHER transport
// fan into the same on_open/on_data/on_close; tell them apart, if you must, by
// conn.source. nil: clears the listener and closes both gates (existing conns in
// either live table keep working).
int lua_ces_conn_set_listener(lua_State* L) {
  if (lua_isnil(L, 1)) {
    lua_pushnil(L);
    lua_setfield(L, LUA_REGISTRYINDEX, kRegListenerTable);
    g_luarpc_listening.store(false, std::memory_order_relaxed);   // direct gate off
    if (!write_frame(TAG_LISTEN_OFF, 0, nullptr, 0)) {            // relay gate off
      lua_pushnil(L); lua_pushstring(L, "ipc write failed"); return 2;
    }
    lua_pushboolean(L, 1);
    return 1;
  }
  if (!lua_istable(L, 1)) {
    return luaL_error(L, "ces.conn.set_listener: expected table or nil");
  }
  // Stash the listener table in the registry — both dispatchers read it.
  lua_pushvalue(L, 1);
  lua_setfield(L, LUA_REGISTRYINDEX, kRegListenerTable);
  // Make sure the relay live-conns table exists.
  lua_getfield(L, LUA_REGISTRYINDEX, kRegConnsTable);
  if (!lua_istable(L, -1)) {
    lua_pop(L, 1);
    lua_newtable(L);
    lua_setfield(L, LUA_REGISTRYINDEX, kRegConnsTable);
  } else {
    lua_pop(L, 1);
  }
  // Direct transport: flip the gate on + open the endpoint (no-op if no port).
  g_luarpc_listening.store(true, std::memory_order_relaxed);
  luarpc_ensure_endpoint();
  // Relay transport: tell the supervisor to start accepting ATTACHes.
  if (!write_frame(TAG_LISTEN_ON, 0, nullptr, 0)) {
    lua_pushnil(L); lua_pushstring(L, "ipc write failed"); return 2;
  }
  lua_pushboolean(L, 1);
  return 1;
}

// Build a fresh relay conn table for native id `conn_id` + `pubkey`. The
// program-facing conn.id is a fresh host uid (unique across transports); the
// native id goes in conn.__sid for routing and keys kRegConnsTable[conn_id] (so
// later DATA_IN / CLOSED frames, which carry the native id, find it). Leaves the
// conn table on the stack top, ready to pass to a Lua callback.
void make_and_register_conn(lua_State* L, uint64_t conn_id,
                             const uint8_t* pubkey) {
  lua_newtable(L);
  lua_pushnumber(L, static_cast<lua_Number>(g_conn_uid_next++));
  lua_setfield(L, -2, "id");
  lua_pushinteger(L, CONN_SOURCE_RELAY);
  lua_setfield(L, -2, "source");
  lua_pushnumber(L, static_cast<lua_Number>(conn_id));   // native routing id
  lua_setfield(L, -2, "__sid");
  lua_pushlstring(L, reinterpret_cast<const char*>(pubkey), 32);
  lua_setfield(L, -2, "pubkey");
  lua_pushboolean(L, 0);
  lua_setfield(L, -2, "closed");
  lua_pushcfunction(L, guarded<lua_ces_conn_write>);
  lua_setfield(L, -2, "write");
  lua_pushcfunction(L, guarded<lua_ces_conn_close>);
  lua_setfield(L, -2, "close");
  // Register in the live-conns table, keyed by the native id (the wire id the
  // dispatcher will look up on later DATA_IN / CLOSED frames).
  lua_getfield(L, LUA_REGISTRYINDEX, kRegConnsTable);
  if (lua_istable(L, -1)) {
    lua_pushnumber(L, static_cast<lua_Number>(conn_id));
    lua_pushvalue(L, -3); // copy of the conn table
    lua_rawset(L, -3);
  }
  lua_pop(L, 1);
  // Stack-top: the conn table.
}

// Drop a relay conn from the live-conns registry (after on_close completes, or
// when a CLOSED frame has no handler to run).
void remove_conn(lua_State* L, uint64_t id) {
  lua_getfield(L, LUA_REGISTRYINDEX, kRegConnsTable);
  if (lua_istable(L, -1)) {
    lua_pushnumber(L, static_cast<lua_Number>(id));
    lua_pushnil(L);
    lua_rawset(L, -3);
  }
  lua_pop(L, 1);
}

// Prepare coroutine `co` to run the listener callback for frame `f`: pushes
// [callback, conn, (data)] onto co and returns the arg count (1 or 2), or -1 if
// there is nothing to run (no listener, no callback, or the conn is gone). For
// OPEN the conn is created+registered here (even when on_open is absent, so the
// callback still finds it); for CLOSE the conn is marked closed before the
// callback. Stack-neutral on mainL.
int setup_handler_co(lua_State* mainL, lua_State* co, const Frame& f) {
  if (f.body.size() < sizeof(uint64_t)) return -1;
  uint64_t id = get_u64(f.body.data());
  constexpr size_t dataHdr = sizeof(uint64_t) + sizeof(uint32_t);

  // Per-tag frame validation up front.
  if (f.tag == TAG_CONN_OPENED &&
      f.body.size() < sizeof(uint64_t) + WIRE_KEY_LEN) return -1;
  if (f.tag == TAG_CONN_DATA_IN) {
    if (f.body.size() < dataHdr) return -1;
    uint32_t dlen = get_u32(f.body.data() + sizeof(uint64_t));
    if (f.body.size() < dataHdr + dlen) return -1;
  }
  if (f.tag == TAG_CONN_CLOSED &&
      f.body.size() < sizeof(uint64_t) + sizeof(uint8_t)) return -1;

  lua_getfield(mainL, LUA_REGISTRYINDEX, kRegListenerTable);
  if (!lua_istable(mainL, -1)) { lua_pop(mainL, 1); return -1; }

  const char* cbname = (f.tag == TAG_CONN_OPENED)  ? "on_open"
                     : (f.tag == TAG_CONN_DATA_IN) ? "on_data"
                                                   : "on_close";

  if (f.tag == TAG_CONN_OPENED) {
    const uint8_t* pk = f.body.data() + sizeof(uint64_t);
    make_and_register_conn(mainL, id, pk);    // mainL: [listener, conn]
    lua_getfield(mainL, -2, cbname);           // [listener, conn, cb]
    if (!lua_isfunction(mainL, -1)) { lua_pop(mainL, 3); return -1; }
    lua_xmove(mainL, co, 1);                   // cb   -> co ; mainL: [listener, conn]
    lua_xmove(mainL, co, 1);                   // conn -> co ; mainL: [listener]
    lua_pop(mainL, 1);
    return 1;
  }

  // DATA_IN / CLOSED: the conn must already exist.
  lua_getfield(mainL, -1, cbname);             // [listener, cb]
  bool hasCb = lua_isfunction(mainL, -1);
  push_conn_table(mainL, id);                  // [listener, cb, conn] (conn or nil)
  if (lua_isnil(mainL, -1)) { lua_pop(mainL, 3); return -1; }
  if (f.tag == TAG_CONN_CLOSED) {
    lua_pushboolean(mainL, 1);
    lua_setfield(mainL, -2, "closed");         // close before callback: no write/close
  }
  if (!hasCb) { lua_pop(mainL, 3); return -1; }
  lua_pushvalue(mainL, -2);                    // [listener, cb, conn, cb]
  lua_xmove(mainL, co, 1);                     // cb   -> co ; mainL: [listener, cb, conn]
  lua_xmove(mainL, co, 1);                     // conn -> co ; mainL: [listener, cb]
  lua_pop(mainL, 2);
  if (f.tag == TAG_CONN_DATA_IN) {
    uint32_t dlen = get_u32(f.body.data() + sizeof(uint64_t));
    lua_pushlstring(co, reinterpret_cast<const char*>(f.body.data() + dataHdr),
                    dlen);
    return 2;
  }
  return 1;
}

// Start the next pending frame for conn `id` as a fresh handler coroutine, if
// one is not already live. A frame with nothing to run (no callback / conn
// gone) is skipped; a CLOSED frame so skipped still tears the conn down. Called
// when a frame arrives and when a handler finishes (re-queued via g_conn_advance
// so the resume chain stays flat, never recursive).
static void conn_advance(lua_State* mainL, uint64_t id) {
  auto it = g_conn_exec.find(id);
  if (it == g_conn_exec.end()) return;
  ConnExec& ce = it->second;
  if (ce.busy || ce.pending.empty()) return;
  Frame f = std::move(ce.pending.front());
  ce.pending.pop_front();
  bool isClose = (f.tag == TAG_CONN_CLOSED);

  lua_State* co = lua_newthread(mainL);
  int ref = luaL_ref(mainL, LUA_REGISTRYINDEX);
  int nargs = setup_handler_co(mainL, co, f);
  if (nargs < 0) {
    luaL_unref(mainL, LUA_REGISTRYINDEX, ref);  // nothing to run; drop the thread
    if (isClose) { remove_conn(mainL, id); g_conn_exec.erase(id); return; }
    g_conn_advance.push_back(id);                // try the next pending frame
    return;
  }
  g_coro_refs[co] = ref;
  ce.busy = true;
  g_handler_co[co] = HandlerCo{id, isClose, false};
  resume_coro(mainL, co, nargs);
}

// Route one inbound CONN_* frame into its conn's serialized queue and request a
// dispatch. The handler runs (as a coroutine) in conn_advance, drained by the
// run loop. Always returns true; framing/socket errors are handled by the
// caller's read path.
bool dispatch_conn_frame(lua_State* L, Frame f) {
  if (f.body.size() < sizeof(uint64_t)) return true;
  uint64_t id = get_u64(f.body.data());
  g_conn_exec[id].pending.push_back(std::move(f));
  g_conn_advance.push_back(id);
  (void)L;
  return true;
}

// Drain conns with a ready frame. Flat: a handler that finishes synchronously
// re-queues its conn via resume_coro, so this while-loop (not C recursion)
// walks a burst. Runs only from the run loop.
static void drain_conn_advance(lua_State* mainL) {
  while (!g_conn_advance.empty()) {
    uint64_t id = g_conn_advance.front();
    g_conn_advance.pop_front();
    conn_advance(mainL, id);
  }
}

// Forward decl — the unified loop below dispatches luarpc bridge events whose
// handler (dispatch_luarpc_event) is defined later in this file.
void dispatch_luarpc_event(lua_State* L, LuaRpcEvent e);

