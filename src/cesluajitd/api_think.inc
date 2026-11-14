// ---------------------------------------------------------------------------
// ces.think(prompt [, on_piece]) -> reply, charged | nil, rc, partial
//
// builtin:think for this program, as a host call. The server bills the
// file's program account (ces.program_pubkey()); the child names no payer.
// The reply streams in as TAG_THINK_PIECE frames under the call's corr_id.
// They collect in g_think_calls, and on_piece (when given) runs once for each
// piece, in order. In a coroutine the call yields until the reply ends, and
// on_piece runs from the run loop. In the main chunk the call blocks, and
// on_piece runs inside that wait. on_piece cannot yield: a host call in it
// blocks. An error in on_piece is logged and drops it for the rest of the
// call. rc is a CES status (see ces.err).
// ---------------------------------------------------------------------------

constexpr size_t kThinkPromptMax = 16u * 1024u * 1024u;   // IPC sanity cap

struct ThinkCall {
  std::string text;      // the reply so far
  int cb = LUA_NOREF;    // registry ref of on_piece
};
std::map<uint16_t, ThinkCall> g_think_calls;   // corr_id -> call (Lua thread)

// Add each queued piece to its call and run the call's on_piece. `L` must be
// a running state: the main thread in the run loop, or the main chunk in its
// own blocking wait.
void drain_think(lua_State* L) {
  while (!g_think_q.empty()) {
    Frame f = std::move(g_think_q.front());
    g_think_q.pop_front();
    auto it = g_think_calls.find(f.corr_id);
    if (it == g_think_calls.end()) continue;
    const char* b = reinterpret_cast<const char*>(f.body.data());
    it->second.text.append(b, f.body.size());
    int cb = it->second.cb;
    if (cb == LUA_NOREF) continue;
    lua_rawgeti(L, LUA_REGISTRYINDEX, cb);
    lua_pushlstring(L, b, f.body.size());
    if (lua_pcall(L, 1, 0, 0) != 0) {
      const char* m = lua_tostring(L, -1);
      host_log(3, std::string("ces.think on_piece: ") + (m ? m : "error"));
      lua_pop(L, 1);
      auto again = g_think_calls.find(f.corr_id);   // on_piece may call ces.think
      if (again != g_think_calls.end() && again->second.cb == cb) {
        luaL_unref(L, LUA_REGISTRYINDEX, cb);
        again->second.cb = LUA_NOREF;
      }
    }
  }
}

// End a call: push its results from the API reply [u8 status][u64 charged].
int think_finish(lua_State* L, uint16_t corr, const Frame& reply) {
  ThinkCall call;
  auto it = g_think_calls.find(corr);
  if (it != g_think_calls.end()) {
    call = std::move(it->second);
    g_think_calls.erase(it);
  }
  if (call.cb != LUA_NOREF) luaL_unref(L, LUA_REGISTRYINDEX, call.cb);
  uint8_t st = reply.body.empty() ? uint8_t(ces::CES_ERROR_INTERNAL)
                                  : reply.body[0];
  if (st == ces::CES_OK && reply.body.size() < 1 + sizeof(uint64_t))
    st = ces::CES_ERROR_INTERNAL;
  if (st != ces::CES_OK) {
    lua_pushnil(L);
    lua_pushinteger(L, st);
    lua_pushlstring(L, call.text.data(), call.text.size());
    return 3;
  }
  lua_pushlstring(L, call.text.data(), call.text.size());
  lua_pushnumber(L, static_cast<lua_Number>(get_u64(reply.body.data() + 1)));
  return 2;
}

// The main chunk's wait: read frames until this call's reply, and run
// on_piece for each piece as it lands.
bool think_wait(lua_State* L, uint16_t corr, Frame& out) {
  for (;;) {
    for (auto it = g_reply_q.begin(); it != g_reply_q.end(); ++it) {
      if (it->corr_id == corr) {
        out = std::move(*it);
        g_reply_q.erase(it);
        drain_think(L);
        return true;
      }
    }
    Frame f;
    if (!read_frame(f)) return false;
    if (f.tag == TAG_API_REPLY && f.corr_id == corr) {
      out = std::move(f);
      drain_think(L);
      return true;
    }
    route_to_queue(std::move(f));
    drain_think(L);
  }
}

int lua_ces_think(lua_State* L) {
  size_t plen = 0;
  const char* p = luaL_checklstring(L, 1, &plen);
  if (plen == 0 || plen > kThinkPromptMax) {
    lua_pushnil(L);
    lua_pushstring(L, plen == 0 ? "prompt must not be empty" : "prompt too large");
    return 2;
  }
  int cb = LUA_NOREF;
  if (!lua_isnoneornil(L, 2)) {
    luaL_checktype(L, 2, LUA_TFUNCTION);
    lua_pushvalue(L, 2);
    cb = luaL_ref(L, LUA_REGISTRYINDEX);
  }
  std::vector<uint8_t> args;
  args.reserve(sizeof(uint32_t) + plen);
  put_u32(args, static_cast<uint32_t>(plen));
  put_bytes(args, p, plen);
  uint16_t corr = send_api_call(METHOD_THINK, args);
  if (corr == 0) {
    if (cb != LUA_NOREF) luaL_unref(L, LUA_REGISTRYINDEX, cb);
    return push_ipc_fail(L);
  }
  g_think_calls[corr] = ThinkCall{{}, cb};
  IoDecoder decode = [corr](lua_State* co, const Frame& r) {
    return think_finish(co, corr, r);
  };
  if (io_yieldable(L)) {
    g_io_waiters[corr] = IoWaiter{L, std::move(decode)};
    g_parked.insert(L);
    return lua_yield(L, 0);
  }
  Frame reply;
  if (!think_wait(L, corr, reply)) {
    auto it = g_think_calls.find(corr);
    if (it != g_think_calls.end()) {
      if (it->second.cb != LUA_NOREF)
        luaL_unref(L, LUA_REGISTRYINDEX, it->second.cb);
      g_think_calls.erase(it);
    }
    return push_ipc_fail(L);
  }
  return decode(L, reply);
}
