// ---------------------------------------------------------------------------
// ces.chan — CSP message channel (Hoare; same model as Go's chan). The struct +
// scheduler glue (g_chan_waiters, drain_chan_timeouts) live up by the timers.
//   ch = ces.chan()
//   ch:send(v)                -- enqueue v (any Lua value); never blocks;
//                                returns false if the channel is closed (drop)
//   v = ch:recv([timeout_ms]) -- next value, else nil,"timeout" / nil,"closed".
//                                default 10000ms; recv from a coroutine; a
//                                queued value wins immediately (no park)
//   ch:close()                -- wake parked recv-ers (nil,"closed"); later sends drop
// ---------------------------------------------------------------------------
static const char* kChanMT = "ces.chan.mt";

static Channel* check_chan(lua_State* L, int idx) {
  void* ud = luaL_checkudata(L, idx, kChanMT);
  Channel* ch = ud ? *static_cast<Channel**>(ud) : nullptr;
  if (!ch) { luaL_error(L, "invalid channel"); }
  return ch;
}

int lua_chan_new(lua_State* L) {
  Channel** ud = static_cast<Channel**>(lua_newuserdata(L, sizeof(Channel*)));
  *ud = new Channel();
  luaL_getmetatable(L, kChanMT);
  lua_setmetatable(L, -2);
  return 1;
}

int lua_chan_send(lua_State* L) {
  Channel* ch = check_chan(L, 1);
  if (ch->closed) { lua_pushboolean(L, 0); return 1; }   // dropped
  // Hand directly to the oldest parked recv-er, if one is still waiting.
  while (!ch->recvers.empty()) {
    lua_State* co = ch->recvers.front();
    ch->recvers.pop_front();
    if (g_parked.erase(co)) {
      g_chan_waiters.erase(co);
      lua_checkstack(co, 1);
      lua_pushvalue(L, 2);                 // the value
      lua_xmove(L, co, 1);                 // -> co's stack
      g_ready.push_back({co, 1});          // resumed in drain_ready with it
      lua_pushboolean(L, 1);
      return 1;
    }
    // co was already woken (timed out): drop it, try the next recv-er
  }
  // No waiter: enqueue. A registry ref keeps the value alive until recv/gc.
  lua_pushvalue(L, 2);
  ch->queue.push_back(luaL_ref(L, LUA_REGISTRYINDEX));
  lua_pushboolean(L, 1);
  return 1;
}

int lua_chan_recv(lua_State* L) {
  Channel* ch = check_chan(L, 1);
  int timeoutMs = static_cast<int>(luaL_optinteger(L, 2, 10000));
  // A queued value wins immediately -- even on a closed channel, drain first.
  if (!ch->queue.empty()) {
    int ref = ch->queue.front();
    ch->queue.pop_front();
    lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
    luaL_unref(L, LUA_REGISTRYINDEX, ref);
    return 1;
  }
  if (ch->closed) { lua_pushnil(L); lua_pushstring(L, "closed"); return 2; }
  // Empty + open: park with a timeout backstop. The main chunk can't yield, and
  // timeout<=0 is a non-blocking poll -- both return an immediate "timeout".
  if (!io_yieldable(L) || timeoutMs <= 0) {
    lua_pushnil(L); lua_pushstring(L, "timeout"); return 2;
  }
  g_parked.insert(L);
  ch->recvers.push_back(L);
  g_chan_waiters[L] = ChanWaiter{
    ch, timer_now_us() + static_cast<uint64_t>(timeoutMs) * 1000ULL};
  return lua_yield(L, 0);
}

int lua_chan_close(lua_State* L) {
  Channel* ch = check_chan(L, 1);
  ch->closed = true;
  while (!ch->recvers.empty()) {
    lua_State* co = ch->recvers.front();
    ch->recvers.pop_front();
    if (g_parked.erase(co)) {
      g_chan_waiters.erase(co);
      lua_checkstack(co, 2);
      lua_pushnil(co);
      lua_pushstring(co, "closed");
      g_ready.push_back({co, 2});
    }
  }
  return 0;
}

// __gc: release the refs of any never-received values, then free the Channel.
// No recv-er can be parked here -- a parked recv-er holds the userdata alive.
int lua_chan_gc(lua_State* L) {
  void* ud = lua_touserdata(L, 1);
  if (!ud) return 0;
  Channel* ch = *static_cast<Channel**>(ud);
  if (!ch) return 0;
  for (int ref : ch->queue) luaL_unref(L, LUA_REGISTRYINDEX, ref);
  delete ch;
  *static_cast<Channel**>(ud) = nullptr;
  return 0;
}

