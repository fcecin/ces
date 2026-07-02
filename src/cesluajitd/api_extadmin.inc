// ---------------------------------------------------------------------------
// ces.extension_admin{} — the extension management contract. The program registers
// callbacks; the host (ExtensionManager via the compute supervisor) invokes
// them over IPC when the program runs as a /s/ extension. Registration ships
// the host a manifest + capability bits + the command menu + config defaults in
// one REGISTER frame; status/command requests round-trip via EXT_REQ/EXT_REP;
// config edits arrive one-way via EXT_CONFIG.
// ---------------------------------------------------------------------------
int  g_ext_status_ref  = LUA_NOREF;
int  g_ext_command_ref = LUA_NOREF;
int  g_ext_config_ref  = LUA_NOREF;
bool g_ext_registered  = false;

std::string ext_str_field(lua_State* L, int tbl, const char* key) {
  lua_getfield(L, tbl, key);
  std::string s;
  if (lua_isstring(L, -1)) {
    size_t n = 0; const char* p = lua_tolstring(L, -1, &n); s.assign(p, n);
  }
  lua_pop(L, 1);
  return s;
}

// Parse "key = value" lines (# comments, trimmed) into a fresh Lua table left on
// the stack. Mirrors cesdk's conf.lua so on_config receives a string->string map.
void push_config_table(lua_State* L, const uint8_t* data, size_t len) {
  lua_newtable(L);
  std::string s(reinterpret_cast<const char*>(data), len);
  auto trim = [](std::string x) {
    size_t a = x.find_first_not_of(" \t\r");
    if (a == std::string::npos) return std::string();
    size_t b = x.find_last_not_of(" \t\r");
    return x.substr(a, b - a + 1);
  };
  size_t pos = 0;
  while (pos <= s.size()) {
    size_t nl = s.find('\n', pos);
    std::string line = s.substr(pos, nl == std::string::npos ? s.size() - pos : nl - pos);
    pos = (nl == std::string::npos) ? s.size() + 1 : nl + 1;
    size_t hash = line.find('#');
    if (hash != std::string::npos) line = line.substr(0, hash);
    size_t eq = line.find('=');
    if (eq == std::string::npos) continue;
    std::string k = trim(line.substr(0, eq));
    if (k.empty()) continue;
    std::string v = trim(line.substr(eq + 1));
    lua_pushlstring(L, v.data(), v.size());
    lua_setfield(L, -2, k.c_str());
  }
}

// Serialize a {k=v} table (string->string) as [u16 count]([lp k][lp v])*.
void ext_serialize_status(lua_State* L, int tbl, std::vector<uint8_t>& out) {
  std::vector<uint8_t> pairs;
  uint16_t count = 0;
  lua_pushnil(L);
  while (lua_next(L, tbl) != 0) {
    if (lua_type(L, -2) == LUA_TSTRING) {           // only string keys (lua_next-safe)
      size_t kn = 0, vn = 0;
      const char* k = lua_tolstring(L, -2, &kn);
      const char* v = lua_tolstring(L, -1, &vn);    // string or number; nil otherwise
      if (k && v) { put_name(pairs, k, kn); put_name(pairs, v, vn); count++; }
    }
    lua_pop(L, 1);
  }
  put_u16(out, count);
  put_bytes(out, pairs.data(), pairs.size());
}

// Read the program's CES_MANIFEST global — a STATIC table the cesdk bundler
// emits from project.lua (a hand-written /s/ program declares it directly) — and
// report it to the host. Called once when the program enters its run loop. It's
// data, not a call, so `--manifest` can harvest it without running the program.
void send_manifest_from_global(lua_State* L) {
  lua_getglobal(L, "CES_MANIFEST");
  if (lua_istable(L, -1)) {
    int t = lua_gettop(L);
    std::string name    = ext_str_field(L, t, "name");
    std::string version = ext_str_field(L, t, "version");
    std::string desc    = ext_str_field(L, t, "description");
    std::vector<uint8_t> body;
    put_name(body, name.data(), name.size());
    put_name(body, version.data(), version.size());
    put_name(body, desc.data(), desc.size());
    write_frame(TAG_EXT_MANIFEST, 0, body.data(), body.size());
  }
  lua_pop(L, 1);
}

// ces.extension_admin{ status=, commands=, on_command=, config_defaults=,
// on_config= }. The spec arrives at stack index 2 (index 1 is the
// ces.extension_admin table itself, via __call). NO metadata here: name/version/
// description are declared via ces.manifest{} (bundler-generated), not here —
// this call registers the admin contract only.
int lua_ces_extension_admin(lua_State* L) {
  luaL_checktype(L, 2, LUA_TTABLE);
  std::vector<uint8_t> body;
  body.push_back(0);                                // caps placeholder
  uint8_t caps = 0;

  lua_getfield(L, 2, "status");
  if (lua_isfunction(L, -1)) {
    if (g_ext_status_ref != LUA_NOREF) luaL_unref(L, LUA_REGISTRYINDEX, g_ext_status_ref);
    g_ext_status_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    caps |= EXT_CAP_STATUS;
  } else lua_pop(L, 1);

  std::vector<uint8_t> cmds;
  uint16_t cmdCount = 0;
  lua_getfield(L, 2, "commands");
  if (lua_istable(L, -1)) {
    int n = static_cast<int>(lua_objlen(L, -1));
    for (int i = 1; i <= n; i++) {
      lua_rawgeti(L, -1, i);
      if (lua_istable(L, -1)) {
        int c = lua_gettop(L);
        std::string id = ext_str_field(L, c, "id");
        std::string label = ext_str_field(L, c, "label");
        if (!id.empty()) {
          put_name(cmds, id.data(), id.size());
          put_name(cmds, label.data(), label.size());
          cmdCount++;
        }
      }
      lua_pop(L, 1);
    }
  }
  lua_pop(L, 1);
  put_u16(body, cmdCount);
  put_bytes(body, cmds.data(), cmds.size());
  if (cmdCount > 0) caps |= EXT_CAP_COMMANDS;

  lua_getfield(L, 2, "on_command");
  if (lua_isfunction(L, -1)) {
    if (g_ext_command_ref != LUA_NOREF) luaL_unref(L, LUA_REGISTRYINDEX, g_ext_command_ref);
    g_ext_command_ref = luaL_ref(L, LUA_REGISTRYINDEX);
  } else lua_pop(L, 1);

  std::string defaults;
  lua_getfield(L, 2, "config_defaults");
  if (lua_isfunction(L, -1)) {
    if (lua_pcall(L, 0, 1, 0) == 0 && lua_isstring(L, -1)) {
      size_t n = 0; const char* p = lua_tolstring(L, -1, &n); defaults.assign(p, n);
    }
    lua_pop(L, 1);
    caps |= EXT_CAP_CONFIG_DEFAULTS;
  } else if (lua_isstring(L, -1)) {
    size_t n = 0; const char* p = lua_tolstring(L, -1, &n); defaults.assign(p, n);
    lua_pop(L, 1);
    caps |= EXT_CAP_CONFIG_DEFAULTS;
  } else lua_pop(L, 1);
  if (defaults.size() > 65535) defaults.resize(65535);
  put_name(body, defaults.data(), defaults.size());

  lua_getfield(L, 2, "on_config");
  if (lua_isfunction(L, -1)) {
    if (g_ext_config_ref != LUA_NOREF) luaL_unref(L, LUA_REGISTRYINDEX, g_ext_config_ref);
    g_ext_config_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    caps |= EXT_CAP_ON_CONFIG;
  } else lua_pop(L, 1);

  body[0] = caps;
  write_frame(TAG_EXT_REGISTER, 0, body.data(), body.size());
  g_ext_registered = true;
  return 0;
}

// ces.extension_admin.disable_self() — the program-initiated Disable (kills this
// instance; the /s/ file stays).
int lua_ces_extension_admin_disable_self(lua_State* L) {
  (void)L;
  write_frame(TAG_EXT_DISABLE_SELF, 0, nullptr, 0);
  return 0;
}

// Host -> program: EXT_CONFIG (one-way on_config) or EXT_REQ (status/command,
// answered with EXT_REP echoing the corr_id). Returns false on a fatal socket
// write error so the run loop can exit.
bool dispatch_ext_frame(lua_State* L, Frame f) {
  if (f.tag == TAG_EXT_CONFIG) {
    if (g_ext_config_ref == LUA_NOREF) return true;
    lua_rawgeti(L, LUA_REGISTRYINDEX, g_ext_config_ref);
    push_config_table(L, f.body.data(), f.body.size());
    if (lua_pcall(L, 1, 0, 0) != 0) {
      host_log(3, std::string("ces.extension_admin on_config: ") + lua_err_str(L));
      lua_pop(L, 1);
    }
    return true;
  }
  if (f.tag != TAG_EXT_REQ || f.body.empty()) return true;
  uint8_t kind = f.body[0];
  std::vector<uint8_t> rep;
  if (kind == EXT_REQ_STATUS) {
    if (g_ext_status_ref == LUA_NOREF) {
      rep.push_back(STATUS_INTERNAL);
    } else {
      lua_rawgeti(L, LUA_REGISTRYINDEX, g_ext_status_ref);
      if (lua_pcall(L, 0, 1, 0) != 0) {
        host_log(3, std::string("ces.extension_admin status: ") + lua_err_str(L));
        lua_pop(L, 1);
        rep.push_back(STATUS_INTERNAL);
      } else {
        rep.push_back(STATUS_OK);
        if (lua_istable(L, -1)) ext_serialize_status(L, lua_gettop(L), rep);
        else put_u16(rep, 0);
        lua_pop(L, 1);
      }
    }
  } else if (kind == EXT_REQ_COMMAND) {
    if (g_ext_command_ref == LUA_NOREF) {
      rep.push_back(STATUS_INTERNAL);
    } else {
      const uint8_t* p = f.body.data() + 1;
      size_t left = f.body.size() - 1;
      if (left < 2) { rep.push_back(STATUS_INTERNAL); }
      else {
        uint16_t idlen = (uint16_t(p[0]) << 8) | uint16_t(p[1]);
        p += 2; left -= 2;
        if (left < idlen) { rep.push_back(STATUS_INTERNAL); }
        else {
          std::string id(reinterpret_cast<const char*>(p), idlen);
          const uint8_t* arg = p + idlen;
          size_t arglen = left - idlen;
          lua_rawgeti(L, LUA_REGISTRYINDEX, g_ext_command_ref);
          lua_pushlstring(L, id.data(), id.size());
          lua_pushlstring(L, reinterpret_cast<const char*>(arg), arglen);
          if (lua_pcall(L, 2, 1, 0) != 0) {
            host_log(3, std::string("ces.extension_admin on_command: ") + lua_err_str(L));
            lua_pop(L, 1);
            rep.push_back(STATUS_INTERNAL);
          } else {
            rep.push_back(STATUS_OK);
            if (lua_isstring(L, -1)) {
              size_t rn = 0; const char* r = lua_tolstring(L, -1, &rn);
              put_bytes(rep, r, rn);
            }
            lua_pop(L, 1);
          }
        }
      }
    }
  } else {
    rep.push_back(STATUS_INTERNAL);
  }
  write_frame(TAG_EXT_REP, f.corr_id, rep.data(), rep.size());
  return true;
}

// Resume one coroutine with `nargs` results already on its stack. A coroutine
// that yields again parks (its waker re-readies it); one that finishes or errors
// is unreferenced.
static void resume_coro(lua_State* mainL, lua_State* co, int nargs) {
  int r = lua_resume(co, nargs);
  if (r == LUA_YIELD) return;                  // parked again; nothing to do
  if (r != 0)
    host_log(3, std::string("scheduled task: ") + lua_err_str(co));
  auto it = g_coro_refs.find(co);
  if (it != g_coro_refs.end()) {
    luaL_unref(mainL, LUA_REGISTRYINDEX, it->second);
    g_coro_refs.erase(it);
  }
  // If this was a periodic-timer tick, free the timer so its next fire can run
  // (skip-if-busy lifts here). Matched by coroutine pointer, not the registry
  // ref, so a cancelled-and-reused ref can't clear the wrong timer.
  for (auto& t : g_timers) {
    if (t.busy_co == co) { t.busy_co = nullptr; break; }
  }
  // If this was a conn handler coroutine, free the conn so its next queued
  // frame can run -- or, for on_close, tear the conn down now that it is done.
  auto h = g_handler_co.find(co);
  if (h != g_handler_co.end()) {
    uint64_t id = h->second.id;
    bool isClose = h->second.isClose, isLuarpc = h->second.isLuarpc;
    g_handler_co.erase(h);
    if (isLuarpc) {
      auto le = g_luarpc_exec.find(id);
      if (le != g_luarpc_exec.end()) {
        le->second.busy = false;
        if (isClose) { remove_luarpc_conn(mainL, id); g_luarpc_exec.erase(id); }
        else g_luarpc_advance.push_back(id);
      }
    } else {
      auto ce = g_conn_exec.find(id);
      if (ce != g_conn_exec.end()) {
        ce->second.busy = false;
        if (isClose) { remove_conn(mainL, id); g_conn_exec.erase(id); }
        else g_conn_advance.push_back(id);
      }
    }
  }
}

// Dispatch each pending inbound gossip as its own handler coroutine (like
// ces.spawn), if the program defined a global on_gossip. Frame body:
//   [32 author][32 sender][32 msgId][32 dest][u32 len][msg]
// The handler runs on_gossip(msg, {author, sender, msgid, dest}); frames are
// independent, so unlike conn there is no per-key ordering to preserve. No
// on_gossip => the program just doesn't receive gossip.
static void drain_gossip(lua_State* mainL) {
  constexpr size_t H = 4 * WIRE_KEY_LEN + sizeof(uint32_t);
  while (!g_gossip_q.empty()) {
    Frame f = std::move(g_gossip_q.front());
    g_gossip_q.pop_front();
    if (f.body.size() < H) continue;
    uint32_t mlen = get_u32(f.body.data() + 4 * WIRE_KEY_LEN);
    if (f.body.size() < H + mlen) continue;

    lua_getglobal(mainL, "on_gossip");
    if (!lua_isfunction(mainL, -1)) { lua_pop(mainL, 1); continue; }

    lua_State* co = lua_newthread(mainL);            // mainL: [handler, co]
    int ref = luaL_ref(mainL, LUA_REGISTRYINDEX);    // pop co, ref it; mainL: [handler]
    g_coro_refs[co] = ref;
    lua_xmove(mainL, co, 1);                          // handler -> co; co: [handler]

    const uint8_t* b = f.body.data();
    lua_pushlstring(co, reinterpret_cast<const char*>(b + H), mlen);  // arg1: msg
    lua_createtable(co, 0, 4);                                        // arg2: meta
    lua_pushlstring(co, reinterpret_cast<const char*>(b + 0 * WIRE_KEY_LEN),
                    WIRE_KEY_LEN); lua_setfield(co, -2, "author");
    lua_pushlstring(co, reinterpret_cast<const char*>(b + 1 * WIRE_KEY_LEN),
                    WIRE_KEY_LEN); lua_setfield(co, -2, "sender");
    lua_pushlstring(co, reinterpret_cast<const char*>(b + 2 * WIRE_KEY_LEN),
                    WIRE_KEY_LEN); lua_setfield(co, -2, "msgid");
    lua_pushlstring(co, reinterpret_cast<const char*>(b + 3 * WIRE_KEY_LEN),
                    WIRE_KEY_LEN); lua_setfield(co, -2, "dest");
    g_ready.push_back({co, 2});
  }
}

// Inbound /ces/peer/1 mesh message: [32 from][u16 service_len][service]
// [u32 len][payload]. Dispatch the per-service handler registered via
// ces.peer.listen(service, fn) as fn(from_pubkey, payload) in a coroutine.
static void drain_peer(lua_State* mainL) {
  while (!g_peer_q.empty()) {
    Frame f = std::move(g_peer_q.front());
    g_peer_q.pop_front();
    if (f.body.size() < WIRE_KEY_LEN + sizeof(uint16_t)) continue;
    const uint8_t* b = f.body.data();
    uint16_t slen = get_u16(b + WIRE_KEY_LEN);
    size_t svcOff = WIRE_KEY_LEN + sizeof(uint16_t);
    size_t lenOff = svcOff + slen;
    if (f.body.size() < lenOff + sizeof(uint32_t)) continue;
    uint32_t plen = get_u32(b + lenOff);
    size_t payOff = lenOff + sizeof(uint32_t);
    if (f.body.size() < payOff + plen) continue;
    std::string service(reinterpret_cast<const char*>(b + svcOff), slen);

    lua_getfield(mainL, LUA_REGISTRYINDEX, kRegPeerListeners);  // [tbl?]
    if (!lua_istable(mainL, -1)) { lua_pop(mainL, 1); continue; }
    lua_getfield(mainL, -1, service.c_str());                   // [tbl, fn?]
    if (!lua_isfunction(mainL, -1)) { lua_pop(mainL, 2); continue; }
    lua_remove(mainL, -2);                                       // [fn]

    lua_State* co = lua_newthread(mainL);            // [fn, co]
    int ref = luaL_ref(mainL, LUA_REGISTRYINDEX);    // pop co; [fn]
    g_coro_refs[co] = ref;
    lua_xmove(mainL, co, 1);                          // fn -> co; co: [fn]
    lua_pushlstring(co, reinterpret_cast<const char*>(b), WIRE_KEY_LEN); // from
    lua_pushlstring(co, reinterpret_cast<const char*>(b + payOff), plen); // payload
    g_ready.push_back({co, 2});
  }
}

// Resume every ready coroutine (spawn starts, sleep wakeups). Spawns made while
// draining are picked up in the same pass, so a burst of spawns all start before
// the loop blocks again.
static void drain_ready(lua_State* mainL) {
  while (!g_ready.empty()) {
    ReadyCoro rc = g_ready.front();
    g_ready.pop_front();
    resume_coro(mainL, rc.co, rc.nargs);
  }
}

// Resume coroutines whose host reply has arrived. Runs ONLY from the run loop:
// a reply read by a nested blocking wait_for_reply just waits in g_io_ready
// until control returns here, so there is no nested resume. The decoder pushes
// the call's Lua results onto the coroutine, then we resume it with that many
// values -- mirroring how a normal verb returns. lua_checkstack guards the push;
// a true allocation failure there kills this (RLIMIT_AS-bounded) child, which is
// the intended out-of-memory behavior and cannot harm the host.
static void drain_io_completions(lua_State* mainL) {
  while (!g_io_ready.empty()) {
    Frame f = std::move(g_io_ready.front());
    g_io_ready.pop_front();
    auto it = g_io_waiters.find(f.corr_id);
    if (it == g_io_waiters.end()) continue;
    lua_State* co = it->second.co;
    IoDecoder decode = std::move(it->second.decode);
    g_io_waiters.erase(it);
    if (!g_parked.erase(co)) continue;         // already resumed by another waker
    int n;
    if (f.body.empty()) {
      lua_checkstack(co, 2);
      lua_pushnil(co);
      lua_pushstring(co, "ipc_failure");
      n = 2;
    } else {
      lua_checkstack(co, LUA_MINSTACK);
      n = decode(co, f);
    }
    resume_coro(mainL, co, n);
  }
}

// The UNIFIED event loop — ces.run() (= ces.conn.run).
// Consumes the program: blocks OUTSIDE Lua on every event source at once —
// the host IPC socket (/ces/lua/1 conn frames + client DELIVER) AND the
// luarpc bridge (peer conns on our own rpc port) — and re-enters Lua to
// dispatch each. Calling it is what turns a program into a server. Returns
// only when the IPC socket dies. Pre-luarpc programs that call ces.conn.run
// behave exactly as before (the bridge half just stays empty).
int lua_ces_run(lua_State* L) {
  static bool manifest_sent = false;
  if (!manifest_sent) { manifest_sent = true; send_manifest_from_global(L); }
  // Ensure the wakeup eventfd exists before the loop blocks: worker pools and
  // ces.conn.connect nudge it on completion to wake the poll. Without it, an
  // offloaded call from an otherwise-idle program would park forever (the poll
  // has no other event to wake on). luarpc_ensure_endpoint also creates it, but
  // a program using only main-port verbs (ces.ping/remote_*) never goes there.
  if (g_luarpc_wakefd < 0)
    g_luarpc_wakefd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
  for (;;) {
    // Drain everything already queued. CONN_* frames may have been parked by
    // an API call's wait_for_reply; luarpc events are queued by the endpoint
    // threads.
    while (!g_conn_q.empty()) {
      Frame qf = std::move(g_conn_q.front());
      g_conn_q.pop_front();
      if (!dispatch_conn_frame(L, std::move(qf))) return 0;
    }
    for (;;) {
      LuaRpcEvent e;
      {
        std::lock_guard<std::mutex> lk(g_luarpc_mx);
        if (g_luarpc_inq.empty()) break;
        e = std::move(g_luarpc_inq.front());
        g_luarpc_inq.pop_front();
      }
      dispatch_luarpc_event(L, std::move(e));
    }

    // Drain channel-usage the endpoint's meter queued and report it to the
    // parent (one-way TAG_NET_USAGE). Only this (IPC) thread may write g_sock_fd.
    for (;;) {
      NetUsageRecord r;
      {
        std::lock_guard<std::mutex> lk(g_net_usage_mx);
        if (g_net_usage_q.empty()) break;
        r = g_net_usage_q.front();
        g_net_usage_q.pop_front();
      }
      std::vector<uint8_t> nb;
      put_bytes(nb, r.payer.data(), r.payer.size());
      put_u64(nb, r.usage.bytesSent);
      put_u64(nb, r.usage.bytesReceived);
      put_u64(nb, r.usage.memByteSeconds);
      put_u64(nb, r.usage.ageSeconds);
      write_frame(TAG_NET_USAGE, 0, nb.data(), nb.size());
    }

    // Fire due periodic timers (ces.every) + sleep wakeups, resume coroutines
    // whose host reply arrived, dispatch ready conn handlers, then run every
    // ready coroutine before blocking.
    fire_due_timers(L);
    drain_chan_timeouts(L);
    drain_io_completions(L);
    drain_connect_done(L);
    drain_offload_done(L);
    drain_conn_advance(L);
    drain_luarpc_advance(L);
    drain_gossip(L);
    drain_peer(L);
    drain_ready(L);

    // Block until the next event on either source, or the next timer deadline.
    // Don't block if a coroutine became ready in the meantime.
    pollfd pfds[2];
    pfds[0].fd = g_sock_fd;
    pfds[0].events = POLLIN;
    pfds[0].revents = 0;
    int nfds = 1;
    if (g_luarpc_wakefd >= 0) {
      pfds[1].fd = g_luarpc_wakefd;
      pfds[1].events = POLLIN;
      pfds[1].revents = 0;
      nfds = 2;
    }
    bool workPending = !g_ready.empty() || !g_conn_advance.empty() ||
                       !g_luarpc_advance.empty();
    int pr = ::poll(pfds, nfds, workPending ? 0 : next_timer_timeout_ms());
    if (pr < 0) {
      if (errno == EINTR) continue;
      return 0;
    }

    // Bridge nudge → clear the eventfd; the next loop drains g_luarpc_inq.
    if (nfds == 2 && (pfds[1].revents & POLLIN)) {
      uint64_t v;
      ssize_t r = ::read(g_luarpc_wakefd, &v, sizeof(v));
      (void)r;
    }
    // IPC frame ready → read + dispatch/route.
    if (pfds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) return 0;
    if (pfds[0].revents & POLLIN) {
      Frame f;
      if (!read_frame(f)) return 0;
      if (f.tag == TAG_CONN_OPENED || f.tag == TAG_CONN_DATA_IN ||
          f.tag == TAG_CONN_CLOSED) {
        if (!dispatch_conn_frame(L, std::move(f))) return 0;
      } else if (f.tag == TAG_EXT_REQ || f.tag == TAG_EXT_CONFIG) {
        if (!dispatch_ext_frame(L, std::move(f))) return 0;
      } else {
        route_to_queue(std::move(f));   // DELIVER → g_inbox, API_REPLY → reply_q
      }
    }
  }
}

