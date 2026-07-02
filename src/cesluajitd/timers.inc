// ---------------------------------------------------------------------------
// Periodic timers — ces.every(ms, fn). The run loop fires due callbacks and
// uses the nearest deadline as its poll timeout, so a program can do periodic
// work (gossip rounds, liveness, republish) without an external driver. All on
// the Lua thread, like the conn dispatchers.
// ---------------------------------------------------------------------------
struct LuaTimer {
  uint64_t next_us;
  uint64_t interval_us;
  int ref;              // registry ref to the Lua cb (ces.every), or LUA_NOREF
  lua_State* resume_co; // coroutine to resume (ces.sleep), or nullptr
  bool active;
  lua_State* busy_co = nullptr;  // periodic tick coroutine in flight, or nullptr.
                                 // Skip-if-busy: never lap a still-parked tick.
};
std::vector<LuaTimer> g_timers;

// Cooperative scheduler. spawn() runs a function as a coroutine; sleep() (and,
// later, yielding I/O) suspends a coroutine so the run loop services everyone
// else. All the hard part lives here in C++ -- the Lua side just calls
// blocking-looking functions and never sees a coroutine. Coroutines are resumed
// ONLY from the run loop, and a primitive yields from leaf Lua, so there is no
// cross-C-boundary yield (LuaJIT's one constraint stays satisfied).
struct ReadyCoro { lua_State* co; int nargs; };
std::deque<ReadyCoro>     g_ready;      // coroutines to resume now (g_coro_refs above)

// ces.chan — CSP message channel. Carries whole Lua VALUES (held as registry
// refs while queued), not bytes: send a table, recv that table. recv parks the
// caller with a timeout backstop (default 10s) so a channel can never introduce
// an unbounded wait -- the property the rest of the async surface guarantees.
// send never blocks (unbounded) and drops on a closed channel. Cleanup: queued
// values are unref'd at close or __gc; a parked recv-er can't pin a channel past
// its timeout, so abandoned channels GC cleanly.
struct Channel {
  std::deque<int>        queue;     // registry refs of sent values (FIFO)
  std::deque<lua_State*> recvers;   // coroutines parked in recv (FIFO)
  bool                   closed = false;
};
struct ChanWaiter { Channel* ch; uint64_t deadline_us; };
std::map<lua_State*, ChanWaiter> g_chan_waiters;  // co parked on recv -> chan+deadline

static void chan_remove_recver(Channel* ch, lua_State* co) {
  for (auto it = ch->recvers.begin(); it != ch->recvers.end(); ++it)
    if (*it == co) { ch->recvers.erase(it); return; }
}

static uint64_t timer_now_us() {
  return static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count());
}

// Poll timeout (ms) until the next due timer; -1 if no active timers.
static int next_timer_timeout_ms() {
  uint64_t next = std::numeric_limits<uint64_t>::max();
  bool any = false;
  for (auto& t : g_timers) {
    if (t.active) { any = true; if (t.next_us < next) next = t.next_us; }
  }
  for (auto& kv : g_chan_waiters) {   // a parked recv must wake on its timeout
    any = true;
    if (kv.second.deadline_us < next) next = kv.second.deadline_us;
  }
  if (!any) return -1;
  uint64_t now = timer_now_us();
  if (next <= now) return 0;
  uint64_t ms = (next - now) / 1000;
  if (ms > 1000000) ms = 1000000;     // cap a single sleep at ~1000s
  return static_cast<int>(ms) + 1;     // round up so we never wake early
}

static void fire_due_timers(lua_State* L) {
  if (g_timers.empty()) return;
  uint64_t now = timer_now_us();
  // Index-based: a callback may register more timers (vector may reallocate),
  // so never hold a reference across the pcall.
  for (size_t i = 0; i < g_timers.size(); ++i) {
    if (!g_timers[i].active || g_timers[i].next_us > now) continue;
    if (g_timers[i].resume_co) {
      // One-shot sleep timer: mark the coroutine ready (the run loop resumes it).
      g_ready.push_back({g_timers[i].resume_co, 0});
      g_timers[i].active = false;
      continue;
    }
    int ref = g_timers[i].ref;
    // Periodic ces.every: run the callback in its OWN coroutine (like a conn
    // handler) so a blocking-looking call inside it parks instead of freezing
    // the VM -- while a tick waits on the network, inbound conns still get
    // serviced. Skip the fire if the previous tick is still parked (busy_co):
    // queueing periodic fires would build an unbounded backlog; a poke wants
    // "fire if free, else skip".
    if (!g_timers[i].busy_co) {
      lua_rawgeti(L, LUA_REGISTRYINDEX, ref);             // L: [cb]
      if (lua_isfunction(L, -1)) {
        lua_State* co = lua_newthread(L);                  // L: [cb, co]
        g_coro_refs[co] = luaL_ref(L, LUA_REGISTRYINDEX);  // pop+ref co; L: [cb]
        lua_xmove(L, co, 1);                                // cb -> co; co: [cb]
        g_timers[i].busy_co = co;
        resume_coro(L, co, 0);                               // cb() runs; finishes or parks
      } else {
        lua_pop(L, 1);
      }
    }
    // Re-index (vector may have grown; resume_coro re-entered Lua); advance the
    // grid whether the tick fired or was skipped, so a long tick never
    // busy-spins. A callback may have cancelled this timer.
    if (i < g_timers.size() && g_timers[i].ref == ref && g_timers[i].active) {
      g_timers[i].next_us += g_timers[i].interval_us;
      if (g_timers[i].next_us <= now)
        g_timers[i].next_us = now + g_timers[i].interval_us;  // skip missed
    }
  }
  // Reap dead entries (fired one-shot sleeps, cancelled ces.every) so a program
  // that sleeps in a loop does not grow g_timers without bound. Inactive timers
  // already released their ref; nothing else references them.
  g_timers.erase(
    std::remove_if(g_timers.begin(), g_timers.end(),
                   [](const LuaTimer& t) { return !t.active; }),
    g_timers.end());
}

// Wake recv-ers whose timeout elapsed: deliver (nil, "timeout") to each, unless
// a send/close already woke it (g_parked guards the double-resume). Snapshot
// first -- resuming a coroutine may itself recv/send and mutate g_chan_waiters.
static void drain_chan_timeouts(lua_State* mainL) {
  if (g_chan_waiters.empty()) return;
  uint64_t now = timer_now_us();
  std::vector<lua_State*> due;
  for (auto& kv : g_chan_waiters)
    if (kv.second.deadline_us <= now) due.push_back(kv.first);
  for (lua_State* co : due) {
    auto it = g_chan_waiters.find(co);
    if (it == g_chan_waiters.end()) continue;
    Channel* ch = it->second.ch;
    g_chan_waiters.erase(it);
    if (!g_parked.erase(co)) continue;          // already woken by send/close
    chan_remove_recver(ch, co);
    lua_checkstack(co, 2);
    lua_pushnil(co);
    lua_pushstring(co, "timeout");
    resume_coro(mainL, co, 2);
  }
}

// ces.every(ms, fn) -> id. Calls fn() every ms from the run loop. Returns a
// timer id usable with ces.cancel.
int lua_ces_every(lua_State* L) {
  lua_Number ms = luaL_checknumber(L, 1);
  luaL_checktype(L, 2, LUA_TFUNCTION);
  if (ms < 1) ms = 1;
  lua_pushvalue(L, 2);
  int ref = luaL_ref(L, LUA_REGISTRYINDEX);
  uint64_t iv = static_cast<uint64_t>(ms * 1000.0);
  g_timers.push_back({timer_now_us() + iv, iv, ref, nullptr, true});
  lua_pushinteger(L, ref);
  return 1;
}

// ces.cancel(id) — stop a timer created by ces.every.
int lua_ces_cancel(lua_State* L) {
  int ref = static_cast<int>(luaL_checkinteger(L, 1));
  for (auto& t : g_timers) {
    if (t.ref == ref && t.active && t.resume_co == nullptr) {
      t.active = false;
      luaL_unref(L, LUA_REGISTRYINDEX, t.ref);
      break;
    }
  }
  return 0;
}

// ces.spawn(fn) - run fn as a concurrent behavior (coroutine). Returns at once;
// fn starts on the next run-loop turn. Other behaviors keep running while this
// one waits on a timeout-bounded call.
int lua_ces_spawn(lua_State* L) {
  luaL_checktype(L, 1, LUA_TFUNCTION);
  lua_State* co = lua_newthread(L);            // pushes the new thread on L
  int ref = luaL_ref(L, LUA_REGISTRYINDEX);    // pop + ref it (registry is global)
  g_coro_refs[co] = ref;
  lua_pushvalue(L, 1);                          // copy fn to top of L
  lua_xmove(L, co, 1);                          // move fn onto co; co stack = [fn]
  g_ready.push_back({co, 0});                   // resume with 0 args -> calls fn()
  return 0;
}

// ces.gossip.send(msg, budget [, dest]) — flood a message across the server
// mesh. One-way: the home server originates it and pays the flood out of its
// own peer reserves. dest is a 32-byte server pubkey, or nil/absent to
// broadcast to everyone.
int lua_ces_gossip_send(lua_State* L) {
  size_t mlen = 0;
  const char* m = luaL_checklstring(L, 1, &mlen);
  // The CesGossip wire caps the payload at 1024 bytes; reject oversize here so
  // the message can't deliver locally yet get truncated + sig-rejected on peers.
  if (mlen > 1024)
    return luaL_error(L, "ces.gossip.send: msg exceeds 1024 bytes");
  lua_Number budget = luaL_checknumber(L, 2);
  if (budget < 0) budget = 0;
  uint8_t zero[32] = {0};
  const uint8_t* dest = zero;
  if (!lua_isnoneornil(L, 3)) {
    size_t dlen = 0;
    const char* d = luaL_checklstring(L, 3, &dlen);
    if (dlen != 32)
      return luaL_error(L, "ces.gossip.send: dest must be a 32-byte key");
    dest = reinterpret_cast<const uint8_t*>(d);
  }
  // Body: [u64 budget BE][32 dest][u32 len BE][msg].
  std::vector<uint8_t> body;
  put_u64(body, static_cast<uint64_t>(budget));
  body.insert(body.end(), dest, dest + 32);
  put_u32(body, static_cast<uint32_t>(mlen));
  body.insert(body.end(), m, m + mlen);
  write_frame(TAG_GOSSIP_OUT, 0, body.data(), body.size());
  return 0;
}

// ces.peer.send(peer_pubkey, service, bytes) - fire a targeted message to a
// peer's same-service extension over the /ces/peer/1 mesh. Free (unmetered,
// server-to-server), fire-and-forget. No-op if there is no live link to peer.
int lua_ces_peer_send(lua_State* L) {
  size_t klen = 0;
  const char* k = luaL_checklstring(L, 1, &klen);
  if (klen != 32)
    return luaL_error(L, "ces.peer.send: peer must be a 32-byte key");
  size_t slen = 0;
  const char* s = luaL_checklstring(L, 2, &slen);
  if (slen == 0 || slen > 0xFFFF)
    return luaL_error(L, "ces.peer.send: service must be 1..65535 bytes");
  size_t plen = 0;
  const char* p = luaL_checklstring(L, 3, &plen);
  // Body: [32 peer][u16 service_len][service][payload].
  std::vector<uint8_t> body;
  body.insert(body.end(), k, k + 32);
  put_u16(body, static_cast<uint16_t>(slen));
  body.insert(body.end(), s, s + slen);
  body.insert(body.end(), p, p + plen);
  write_frame(TAG_PEER_MSG_OUT, 0, body.data(), body.size());
  return 0;
}

// ces.peer.listen(service, fn) - register fn(from_pubkey, bytes) as the handler
// for inbound mesh messages tagged `service`. fn nil unregisters. Tells the
// server this instance owns `service` so it routes inbound messages here.
int lua_ces_peer_listen(lua_State* L) {
  size_t slen = 0;
  const char* s = luaL_checklstring(L, 1, &slen);
  if (slen == 0 || slen > 0xFFFF)
    return luaL_error(L, "ces.peer.listen: service must be 1..65535 bytes");
  if (!lua_isnoneornil(L, 2) && !lua_isfunction(L, 2))
    return luaL_error(L, "ces.peer.listen: handler must be a function or nil");
  // Ensure the service -> fn registry table exists.
  lua_getfield(L, LUA_REGISTRYINDEX, kRegPeerListeners);
  if (!lua_istable(L, -1)) {
    lua_pop(L, 1);
    lua_newtable(L);
    lua_pushvalue(L, -1);
    lua_setfield(L, LUA_REGISTRYINDEX, kRegPeerListeners);
  }
  lua_pushlstring(L, s, slen);
  if (lua_isnoneornil(L, 2)) lua_pushnil(L); else lua_pushvalue(L, 2);
  lua_settable(L, -3);   // tbl[service] = fn (or nil)
  lua_pop(L, 1);
  // Body: [u16 service_len][service]. The server reads a length-prefixed
  // service (matching TAG_PEER_MSG_OUT's framing).
  std::vector<uint8_t> body;
  put_u16(body, static_cast<uint16_t>(slen));
  body.insert(body.end(), s, s + slen);
  if (!write_frame(TAG_PEER_LISTEN, 0, body.data(), body.size())) {
    lua_pushnil(L); lua_pushstring(L, "ipc write failed"); return 2;
  }
  lua_pushboolean(L, 1);
  return 1;
}


// ces.sleep(ms) - looks blocking, isn't: suspends THIS behavior for ms while
// the run loop services the rest. Only valid inside spawn() (a coroutine), not
// in the main chunk or an event handler (those run on the host thread and
// cannot yield); calling it there is a clean error, not a crash.
int lua_ces_sleep(lua_State* L) {
  if (lua_pushthread(L)) {                      // 1 == this IS the main thread
    lua_pop(L, 1);
    return luaL_error(L, "ces.sleep: only inside spawn()");
  }
  lua_pop(L, 1);
  lua_Number ms = luaL_checknumber(L, 1);
  if (ms < 0) ms = 0;
  uint64_t iv = static_cast<uint64_t>(ms * 1000.0);
  g_timers.push_back({timer_now_us() + iv, 0, LUA_NOREF, L, true});
  return lua_yield(L, 0);
}

