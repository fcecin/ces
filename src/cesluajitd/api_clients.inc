// ---------------------------------------------------------------------------
// ces.file_client / ces.compute_client — OUTBOUND clients of remote (or this)
// CES servers' /ces/file/1 and /ces/compute/1 handlers. Distinct from the
// LOCAL owner-authority ces.file_* (in-process, billed to the source file):
// these dial a server as the program's OWN identity over the instance's
// reserved rpc-port endpoint (firewall-correct), reusing the SAME C++ verb
// codec (CesFileClient / CesComputeClient) cesh uses — one source of truth.
//
// A handle is a Lua table {id, <verb methods>, close}. The C++ channel+client
// live in a registry keyed by id (Lua-thread-only). Verb methods block the Lua
// thread on the round-trip (the endpoint strand is separate). close() destroys
// the channel ON the endpoint strand (its RudpStream is touched there).
// ---------------------------------------------------------------------------

// inflight: an offloaded verb is running on a worker thread (set/cleared only on
// the Lua thread). At most one in flight per handle — a second verb on a busy
// handle errors instead of racing a second worker on the same client. closePending:
// close() was called while inflight; the close is deferred to completion so the
// worker's raw client pointer can't be freed under it. Together these stop a
// program from corrupting the host by sharing a handle across coroutines.
struct LuaFileClientEntry {
  std::unique_ptr<ces::CesPlexChannel> ch;
  std::unique_ptr<ces::CesFileClient> fc;
  bool inflight = false;
  bool closePending = false;
};
struct LuaComputeClientEntry {
  std::unique_ptr<ces::CesPlexChannel> ch;
  std::unique_ptr<ces::CesComputeClient> cc;
  bool inflight = false;
  bool closePending = false;
};
std::map<uint64_t, LuaFileClientEntry>    g_file_clients;     // Lua-thread-only
std::map<uint64_t, LuaComputeClientEntry> g_compute_clients;  // Lua-thread-only
uint64_t g_client_next_id = 1;

uint64_t client_handle_id(lua_State* L, int idx) {
  lua_getfield(L, idx, "id");
  uint64_t id = static_cast<uint64_t>(lua_tonumber(L, -1));
  lua_pop(L, 1);
  return id;
}
uint64_t client_arg_u64(lua_State* L, int idx) {
  return static_cast<uint64_t>(luaL_checknumber(L, idx));
}
int client_push_closed(lua_State* L) {
  lua_pushnil(L);
  lua_pushstring(L, "client closed");
  return 2;
}
int client_push_err(lua_State* L, uint8_t rc) {
  lua_pushnil(L);
  lua_pushinteger(L, rc);
  return 2;
}

// Lazy-open the endpoint, resolve addr, build + bind a CesPlexChannel for
// `proto`, signed by the program key. Null + err on any failure.
// Resolve + bind a CesPlexChannel for `proto`. The caller MUST have called
// luarpc_ensure_endpoint() first (on the Lua thread) — this is safe to run on a
// worker thread (the offload path) precisely because it does not touch the lazy
// endpoint setup, only the already-built g_luarpc_io/rudp/signer.
std::unique_ptr<ces::CesPlexChannel> client_open_channel(
    const std::string& addr, const uint8_t* pk, const char* proto,
    std::string& err) {
  if (!g_luarpc_io || !g_luarpc_rudp || !g_luarpc_signer) {
    err = "networking disabled: instance has no rpc port";
    return nullptr;
  }
  minx::SockAddr peer;
  try {
    auto ep = ces::Resolver::resolveUdp(addr);
    auto a = ep.address();
    if (a.is_v4())
      a = boost::asio::ip::make_address_v6(boost::asio::ip::v4_mapped,
                                           a.to_v4());
    peer = minx::SockAddr(a, ep.port());
  } catch (const std::exception&) {
    err = "address resolve failed";
    return nullptr;
  }
  auto ch = std::make_unique<ces::CesPlexChannel>(*g_luarpc_io, g_luarpc_rudp);
  if (pk) {
    minx::Hash h{};
    std::memcpy(h.data(), pk, 32);
    ch->setServerPubkey(h);
  }
  uint8_t rc = ch->select(peer, proto, *g_luarpc_signer);
  if (rc != ces::CES_OK) {
    err = "bind rejected (rc=" + std::to_string(static_cast<int>(rc)) + ")";
    // Destroy the half-open channel on the endpoint strand (its RudpStream is
    // touched there), not here on the Lua thread.
    boost::asio::post(*g_luarpc_io, [c = std::move(ch)]() { (void)c; });
    return nullptr;
  }
  return ch;
}

// Read the (addr, optional server_pubkey) args common to both constructors.
// Returns false + leaves (nil, err) on the stack on a bad pubkey.
bool client_read_dial_args(lua_State* L, std::string& addr,
                           const uint8_t** pk, uint8_t pkbuf[32]) {
  size_t alen = 0;
  const char* a = luaL_checklstring(L, 1, &alen);
  addr.assign(a, alen);
  *pk = nullptr;
  if (!lua_isnoneornil(L, 2)) {
    size_t plen = 0;
    const char* p = luaL_checklstring(L, 2, &plen);
    if (plen != 32) {
      lua_pushnil(L);
      lua_pushstring(L, "server pubkey must be 32 bytes");
      return false;
    }
    std::memcpy(pkbuf, p, 32);
    *pk = pkbuf;
  }
  return true;
}

LuaFileClientEntry* file_entry(uint64_t id) {
  auto it = g_file_clients.find(id);
  return it == g_file_clients.end() ? nullptr : &it->second;
}
LuaComputeClientEntry* compute_entry(uint64_t id) {
  auto it = g_compute_clients.find(id);
  return it == g_compute_clients.end() ? nullptr : &it->second;
}

// Destroy a registry entry's channel/client on the endpoint strand (its
// RudpStream is touched there). Generic over the two entry maps.
template <typename Map>
void client_close(Map& reg, uint64_t id) {
  auto it = reg.find(id);
  if (it == reg.end()) return;
  auto entry = std::move(it->second);
  reg.erase(it);
  if (g_luarpc_io)
    boost::asio::post(*g_luarpc_io, [e = std::move(entry)]() { (void)e; });
  // else: no endpoint → entry destroyed here (harmless; can't really happen).
}

// Run a verb-client round-trip. The handle is arg 1; its entry + arg parse
// happen on the Lua thread BEFORE this (the registry is Lua-thread-only), and
// `job` captures the raw client pointer + by-value args. From a coroutine the
// blocking call is offloaded to the worker pool and the coroutine yields;
// otherwise it runs inline (main-chunk degenerate case).
//
// The raw pointer the worker holds stays valid because this serializes per
// handle: at most one offloaded verb in flight per handle (a second verb on a
// busy handle returns "busy", never a second worker on the same client), and a
// close() that arrives while a verb is in flight is DEFERRED (closePending) to
// completion. So a program sharing a handle across coroutines can never free the
// client under a worker or run two workers on one client. inflight/closePending
// are touched only on the Lua thread (here + the deliver + close).
template <typename Map>
int client_call(lua_State* L, Map& reg, OffloadJob job) {
  uint64_t id = client_handle_id(L, 1);
  auto it = reg.find(id);
  if (it == reg.end()) return client_push_closed(L);
  if (io_yieldable(L)) {
    if (it->second.inflight) {
      lua_pushnil(L);
      lua_pushstring(L, "busy");
      return 2;
    }
    it->second.inflight = true;
    g_parked.insert(L);
    g_pool_client.ensure(g_client_pool_size);
    g_pool_client.submit(L, [job = std::move(job), &reg, id]() -> OffloadDeliver {
      OffloadDeliver d = job();                       // worker: the blocking verb
      return [d = std::move(d), &reg, id](lua_State* L) -> int {
        auto it = reg.find(id);                        // Lua thread (at resume)
        if (it != reg.end()) {
          it->second.inflight = false;
          if (it->second.closePending) client_close(reg, id);  // deferred close
        }
        return d(L);                                   // verb results (no client ref)
      };
    });
    return lua_yield(L, 0);
  }
  OffloadDeliver deliver = job();
  return deliver(L);
}

// ---- ces.file_client verbs ----

int lua_fc_create(lua_State* L) {
  auto* e = file_entry(client_handle_id(L, 1));
  if (!e) return client_push_closed(L);
  size_t nlen = 0; const char* name = luaL_checklstring(L, 2, &nlen);
  uint64_t size = client_arg_u64(L, 3);
  uint64_t price = client_arg_u64(L, 4);
  uint64_t deposit = client_arg_u64(L, 5);
  ces::CesFileClient* fc = e->fc.get();
  return client_call(L, g_file_clients, [fc, nm = std::string(name, nlen), size, price,
                         deposit]() -> OffloadDeliver {
    uint64_t fb = 0, cost = 0;
    uint8_t rc = fc->create(nm, size, price, deposit, fb, cost);
    if (rc != ces::CES_OK)
      return [rc](lua_State* L) { return client_push_err(L, rc); };
    return [fb, cost](lua_State* L) -> int {
      lua_pushnumber(L, static_cast<lua_Number>(fb));
      lua_pushnumber(L, static_cast<lua_Number>(cost));
      return 2;
    };
  });
}

int lua_fc_write(lua_State* L) {
  auto* e = file_entry(client_handle_id(L, 1));
  if (!e) return client_push_closed(L);
  size_t nlen = 0; const char* name = luaL_checklstring(L, 2, &nlen);
  uint64_t offset = client_arg_u64(L, 3);
  size_t blen = 0; const char* b = luaL_checklstring(L, 4, &blen);
  if (blen == 0 || blen > (1024 * 1024)) {
    lua_pushnil(L); lua_pushstring(L, "data must be 1..1048576 bytes"); return 2;
  }
  ces::Bytes content(reinterpret_cast<const uint8_t*>(b),
                     reinterpret_cast<const uint8_t*>(b) + blen);
  ces::CesFileClient* fc = e->fc.get();
  return client_call(L, g_file_clients, [fc, nm = std::string(name, nlen), offset,
                         content]() -> OffloadDeliver {
    uint64_t fb = 0;
    uint8_t rc = fc->write(nm, offset, content, fb);
    if (rc != ces::CES_OK)
      return [rc](lua_State* L) { return client_push_err(L, rc); };
    return [fb](lua_State* L) -> int {
      lua_pushnumber(L, static_cast<lua_Number>(fb)); return 1;
    };
  });
}

int lua_fc_read(lua_State* L) {
  auto* e = file_entry(client_handle_id(L, 1));
  if (!e) return client_push_closed(L);
  size_t nlen = 0; const char* name = luaL_checklstring(L, 2, &nlen);
  uint64_t offset = client_arg_u64(L, 3);
  uint64_t length64 = client_arg_u64(L, 4);
  if (length64 == 0 || length64 > (1024 * 1024)) {
    lua_pushnil(L); lua_pushstring(L, "length must be 1..1048576 bytes"); return 2;
  }
  uint32_t length = static_cast<uint32_t>(length64);
  ces::CesFileClient* fc = e->fc.get();
  return client_call(L, g_file_clients, [fc, nm = std::string(name, nlen), offset,
                         length]() -> OffloadDeliver {
    ces::Bytes content;
    minx::Hash rangeHash{};
    uint8_t rc = fc->read(nm, offset, length, content, rangeHash);
    if (rc != ces::CES_OK)
      return [rc](lua_State* L) { return client_push_err(L, rc); };
    return [content, rangeHash](lua_State* L) -> int {
      lua_pushlstring(L, reinterpret_cast<const char*>(content.data()),
                      content.size());
      lua_pushlstring(L, reinterpret_cast<const char*>(rangeHash.data()),
                      rangeHash.size());
      return 2;
    };
  });
}

int lua_fc_append(lua_State* L) {
  auto* e = file_entry(client_handle_id(L, 1));
  if (!e) return client_push_closed(L);
  size_t nlen = 0; const char* name = luaL_checklstring(L, 2, &nlen);
  size_t blen = 0; const char* b = luaL_checklstring(L, 3, &blen);
  if (blen == 0 || blen > (1024 * 1024)) {
    lua_pushnil(L); lua_pushstring(L, "data must be 1..1048576 bytes"); return 2;
  }
  ces::Bytes content(reinterpret_cast<const uint8_t*>(b),
                     reinterpret_cast<const uint8_t*>(b) + blen);
  ces::CesFileClient* fc = e->fc.get();
  return client_call(L, g_file_clients, [fc, nm = std::string(name, nlen),
                         content]() -> OffloadDeliver {
    uint64_t fb = 0, newSize = 0;
    uint8_t rc = fc->append(nm, content, fb, newSize);
    if (rc != ces::CES_OK)
      return [rc](lua_State* L) { return client_push_err(L, rc); };
    return [fb, newSize](lua_State* L) -> int {
      lua_pushnumber(L, static_cast<lua_Number>(fb));
      lua_pushnumber(L, static_cast<lua_Number>(newSize));
      return 2;
    };
  });
}

int lua_fc_resize(lua_State* L) {
  auto* e = file_entry(client_handle_id(L, 1));
  if (!e) return client_push_closed(L);
  size_t nlen = 0; const char* name = luaL_checklstring(L, 2, &nlen);
  uint64_t newSize = client_arg_u64(L, 3);
  ces::CesFileClient* fc = e->fc.get();
  return client_call(L, g_file_clients, [fc, nm = std::string(name, nlen),
                         newSize]() -> OffloadDeliver {
    uint64_t outSize = 0;
    uint8_t rc = fc->resize(nm, newSize, outSize);
    if (rc != ces::CES_OK)
      return [rc](lua_State* L) { return client_push_err(L, rc); };
    return [outSize](lua_State* L) -> int {
      lua_pushnumber(L, static_cast<lua_Number>(outSize)); return 1;
    };
  });
}

int lua_fc_deposit(lua_State* L) {
  auto* e = file_entry(client_handle_id(L, 1));
  if (!e) return client_push_closed(L);
  size_t nlen = 0; const char* name = luaL_checklstring(L, 2, &nlen);
  uint64_t amount = client_arg_u64(L, 3);
  ces::CesFileClient* fc = e->fc.get();
  return client_call(L, g_file_clients, [fc, nm = std::string(name, nlen),
                         amount]() -> OffloadDeliver {
    uint64_t fb = 0;
    uint8_t rc = fc->deposit(nm, amount, fb);
    if (rc != ces::CES_OK)
      return [rc](lua_State* L) { return client_push_err(L, rc); };
    return [fb](lua_State* L) -> int {
      lua_pushnumber(L, static_cast<lua_Number>(fb)); return 1;
    };
  });
}

int lua_fc_withdraw(lua_State* L) {
  auto* e = file_entry(client_handle_id(L, 1));
  if (!e) return client_push_closed(L);
  size_t nlen = 0; const char* name = luaL_checklstring(L, 2, &nlen);
  uint64_t amount = client_arg_u64(L, 3);
  ces::CesFileClient* fc = e->fc.get();
  return client_call(L, g_file_clients, [fc, nm = std::string(name, nlen),
                         amount]() -> OffloadDeliver {
    uint64_t fb = 0;
    uint8_t rc = fc->withdraw(nm, amount, fb);
    if (rc != ces::CES_OK)
      return [rc](lua_State* L) { return client_push_err(L, rc); };
    return [fb](lua_State* L) -> int {
      lua_pushnumber(L, static_cast<lua_Number>(fb)); return 1;
    };
  });
}

int lua_fc_set_price(lua_State* L) {
  auto* e = file_entry(client_handle_id(L, 1));
  if (!e) return client_push_closed(L);
  size_t nlen = 0; const char* name = luaL_checklstring(L, 2, &nlen);
  uint64_t newPrice = client_arg_u64(L, 3);
  ces::CesFileClient* fc = e->fc.get();
  return client_call(L, g_file_clients, [fc, nm = std::string(name, nlen),
                         newPrice]() -> OffloadDeliver {
    uint64_t outPrice = 0;
    uint8_t rc = fc->setPrice(nm, newPrice, outPrice);
    if (rc != ces::CES_OK)
      return [rc](lua_State* L) { return client_push_err(L, rc); };
    return [outPrice](lua_State* L) -> int {
      lua_pushnumber(L, static_cast<lua_Number>(outPrice)); return 1;
    };
  });
}

int lua_fc_delete(lua_State* L) {
  auto* e = file_entry(client_handle_id(L, 1));
  if (!e) return client_push_closed(L);
  size_t nlen = 0; const char* name = luaL_checklstring(L, 2, &nlen);
  ces::CesFileClient* fc = e->fc.get();
  return client_call(L, g_file_clients, [fc, nm = std::string(name, nlen)]() -> OffloadDeliver {
    uint64_t refunded = 0;
    uint8_t rc = fc->deleteFile(nm, refunded);
    if (rc != ces::CES_OK)
      return [rc](lua_State* L) { return client_push_err(L, rc); };
    return [refunded](lua_State* L) -> int {
      lua_pushnumber(L, static_cast<lua_Number>(refunded)); return 1;
    };
  });
}

int lua_fc_stat(lua_State* L) {
  auto* e = file_entry(client_handle_id(L, 1));
  if (!e) return client_push_closed(L);
  size_t nlen = 0; const char* name = luaL_checklstring(L, 2, &nlen);
  ces::CesFileClient* fc = e->fc.get();
  return client_call(L, g_file_clients, [fc, nm = std::string(name, nlen)]() -> OffloadDeliver {
    ces::CesFileClient::StatInfo info;
    uint8_t rc = fc->stat(nm, info);
    if (rc != ces::CES_OK)
      return [rc](lua_State* L) { return client_push_err(L, rc); };
    return [info](lua_State* L) -> int {
      lua_newtable(L);
      lua_pushlstring(L, reinterpret_cast<const char*>(info.ownerPubkey.data()),
                      info.ownerPubkey.size());
      lua_setfield(L, -2, "owner_pubkey");
      lua_pushnumber(L, static_cast<lua_Number>(info.fileBalance));
      lua_setfield(L, -2, "file_balance");
      lua_pushnumber(L, static_cast<lua_Number>(info.pricePerKb));
      lua_setfield(L, -2, "price_per_kb");
      lua_pushnumber(L, static_cast<lua_Number>(info.size));
      lua_setfield(L, -2, "size");
      lua_pushnumber(L, static_cast<lua_Number>(info.createdUs));
      lua_setfield(L, -2, "created_us");
      lua_pushnumber(L, static_cast<lua_Number>(info.modifiedUs));
      lua_setfield(L, -2, "modified_us");
      return 1;
    };
  });
}

int lua_fc_close(lua_State* L) {
  uint64_t id = client_handle_id(L, 1);
  auto it = g_file_clients.find(id);
  if (it == g_file_clients.end()) return 0;
  if (it->second.inflight) { it->second.closePending = true; return 0; }  // defer
  client_close(g_file_clients, id);
  return 0;
}

void push_file_handle(lua_State* L, uint64_t id) {
  lua_newtable(L);
  lua_pushnumber(L, static_cast<lua_Number>(id)); lua_setfield(L, -2, "id");
  lua_pushcfunction(L, guarded<lua_fc_create>);    lua_setfield(L, -2, "create");
  lua_pushcfunction(L, guarded<lua_fc_write>);     lua_setfield(L, -2, "write");
  lua_pushcfunction(L, guarded<lua_fc_read>);      lua_setfield(L, -2, "read");
  lua_pushcfunction(L, guarded<lua_fc_append>);    lua_setfield(L, -2, "append");
  lua_pushcfunction(L, guarded<lua_fc_resize>);    lua_setfield(L, -2, "resize");
  lua_pushcfunction(L, guarded<lua_fc_deposit>);   lua_setfield(L, -2, "deposit");
  lua_pushcfunction(L, guarded<lua_fc_withdraw>);  lua_setfield(L, -2, "withdraw");
  lua_pushcfunction(L, guarded<lua_fc_set_price>); lua_setfield(L, -2, "set_price");
  lua_pushcfunction(L, guarded<lua_fc_delete>);    lua_setfield(L, -2, "delete");
  lua_pushcfunction(L, guarded<lua_fc_stat>);      lua_setfield(L, -2, "stat");
  lua_pushcfunction(L, guarded<lua_fc_close>);     lua_setfield(L, -2, "close");
}

// Dial `proto` and build a verb-client handle. The blocking bind (ch->select)
// is offloaded to the client pool from a coroutine, so dialing never freezes
// the loop; from the main chunk it binds inline. `makeHandle` registers the
// bound channel and pushes the Lua handle — it always runs on the Lua thread
// (inline, or in the deliver). The half-open channel on a bind failure is
// destroyed inside client_open_channel on the endpoint strand.
using ChannelHandleFn =
  std::function<int(lua_State*, std::unique_ptr<ces::CesPlexChannel>)>;
int client_dial(lua_State* L, const std::string& addr, const uint8_t* pk,
                const char* proto, ChannelHandleFn makeHandle) {
  luarpc_ensure_endpoint();   // Lua thread: lazy endpoint setup (idempotent)
  if (!g_luarpc_io || !g_luarpc_rudp || !g_luarpc_signer) {
    lua_pushnil(L);
    lua_pushstring(L, "networking disabled: instance has no rpc port");
    return 2;
  }
  std::array<uint8_t, 32> pkbuf{};
  bool hasPk = (pk != nullptr);
  if (hasPk) std::memcpy(pkbuf.data(), pk, 32);
  std::string protoStr(proto);

  if (io_yieldable(L)) {
    lua_State* co = L;
    g_parked.insert(co);
    g_pool_client.ensure(g_client_pool_size);
    g_pool_client.submit(co, [addr, pkbuf, hasPk, protoStr, makeHandle]()
                                -> OffloadDeliver {
      std::string err;
      auto ch = client_open_channel(addr, hasPk ? pkbuf.data() : nullptr,
                                    protoStr.c_str(), err);
      if (!ch)
        return [err](lua_State* L) {
          lua_pushnil(L); lua_pushlstring(L, err.data(), err.size()); return 2;
        };
      auto holder =
        std::make_shared<std::unique_ptr<ces::CesPlexChannel>>(std::move(ch));
      return [holder, makeHandle](lua_State* L) -> int {
        return makeHandle(L, std::move(*holder));
      };
    });
    return lua_yield(L, 0);
  }

  std::string err;
  auto ch = client_open_channel(addr, pk, proto, err);
  if (!ch) { lua_pushnil(L); lua_pushstring(L, err.c_str()); return 2; }
  return makeHandle(L, std::move(ch));
}

int lua_ces_file_client(lua_State* L) {
  std::string addr; const uint8_t* pk = nullptr; uint8_t pkbuf[32];
  if (!client_read_dial_args(L, addr, &pk, pkbuf)) return 2;
  return client_dial(L, addr, pk, "/ces/file/1",
    [](lua_State* L, std::unique_ptr<ces::CesPlexChannel> ch) -> int {
      auto fc = std::make_unique<ces::CesFileClient>();
      fc->attach(*ch);
      uint64_t id = g_client_next_id++;
      auto& e = g_file_clients[id];
      e.ch = std::move(ch);
      e.fc = std::move(fc);
      push_file_handle(L, id);
      return 1;
    });
}

// ---- ces.compute_client verbs ----

void push_instance_info(lua_State* L,
                        const ces::CesComputeClient::InstanceInfo& info) {
  lua_newtable(L);
  lua_pushnumber(L, static_cast<lua_Number>(info.pid));
  lua_setfield(L, -2, "pid");
  lua_pushlstring(L, info.sourceName.data(), info.sourceName.size());
  lua_setfield(L, -2, "source_name");
  lua_pushnumber(L, static_cast<lua_Number>(info.startedAtUs));
  lua_setfield(L, -2, "started_at_us");
  lua_pushnumber(L, static_cast<lua_Number>(info.fileBalance));
  lua_setfield(L, -2, "file_balance");
  lua_pushnumber(L, static_cast<lua_Number>(info.cpuBasisPoints));
  lua_setfield(L, -2, "cpu_basis_points");
  lua_pushnumber(L, static_cast<lua_Number>(info.rssBytes));
  lua_setfield(L, -2, "rss_bytes");
  lua_pushnumber(L, static_cast<lua_Number>(info.clientPort));
  lua_setfield(L, -2, "client_port");
  lua_pushnumber(L, static_cast<lua_Number>(info.rpcPort));
  lua_setfield(L, -2, "rpc_port");
  lua_pushlstring(L, reinterpret_cast<const char*>(info.programPubkey.data()),
                  info.programPubkey.size());
  lua_setfield(L, -2, "program_pubkey");
}

int lua_cc_launch(lua_State* L) {
  auto* e = compute_entry(client_handle_id(L, 1));
  if (!e) return client_push_closed(L);
  size_t nlen = 0; const char* name = luaL_checklstring(L, 2, &nlen);
  ces::CesComputeClient* cc = e->cc.get();
  return client_call(L, g_compute_clients, [cc, nm = std::string(name, nlen)]() -> OffloadDeliver {
    uint64_t id = 0, startedAt = 0;
    uint8_t rc = cc->launch(nm, id, startedAt);
    if (rc != ces::CES_OK)
      return [rc](lua_State* L) { return client_push_err(L, rc); };
    return [id, startedAt](lua_State* L) -> int {
      lua_pushnumber(L, static_cast<lua_Number>(id));
      lua_pushnumber(L, static_cast<lua_Number>(startedAt));
      return 2;
    };
  });
}

int lua_cc_kill(lua_State* L) {
  auto* e = compute_entry(client_handle_id(L, 1));
  if (!e) return client_push_closed(L);
  uint64_t id = client_arg_u64(L, 2);
  ces::CesComputeClient* cc = e->cc.get();
  return client_call(L, g_compute_clients, [cc, id]() -> OffloadDeliver {
    uint8_t rc = cc->kill(id);
    if (rc != ces::CES_OK)
      return [rc](lua_State* L) { return client_push_err(L, rc); };
    return [](lua_State* L) -> int { lua_pushboolean(L, 1); return 1; };
  });
}

int lua_cc_stat(lua_State* L) {
  auto* e = compute_entry(client_handle_id(L, 1));
  if (!e) return client_push_closed(L);
  uint64_t id = client_arg_u64(L, 2);
  ces::CesComputeClient* cc = e->cc.get();
  return client_call(L, g_compute_clients, [cc, id]() -> OffloadDeliver {
    ces::CesComputeClient::InstanceInfo info;
    uint8_t rc = cc->stat(id, info);
    if (rc != ces::CES_OK)
      return [rc](lua_State* L) { return client_push_err(L, rc); };
    return [info](lua_State* L) -> int { push_instance_info(L, info); return 1; };
  });
}

int lua_cc_list(lua_State* L) {
  auto* e = compute_entry(client_handle_id(L, 1));
  if (!e) return client_push_closed(L);
  ces::CesComputeClient* cc = e->cc.get();
  return client_call(L, g_compute_clients, [cc]() -> OffloadDeliver {
    std::vector<ces::CesComputeClient::InstanceInfo> infos;
    uint8_t rc = cc->list(infos);
    if (rc != ces::CES_OK)
      return [rc](lua_State* L) { return client_push_err(L, rc); };
    return [infos](lua_State* L) -> int {
      lua_newtable(L);
      for (size_t i = 0; i < infos.size(); ++i) {
        push_instance_info(L, infos[i]);
        lua_rawseti(L, -2, static_cast<int>(i + 1));
      }
      return 1;
    };
  });
}

int lua_cc_instances(lua_State* L) {
  auto* e = compute_entry(client_handle_id(L, 1));
  if (!e) return client_push_closed(L);
  size_t plen = 0; const char* path = luaL_checklstring(L, 2, &plen);
  ces::CesComputeClient* cc = e->cc.get();
  return client_call(L, g_compute_clients, [cc, p = std::string(path, plen)]() -> OffloadDeliver {
    std::vector<ces::CesComputeClient::InstanceInfo> infos;
    uint8_t rc = cc->instances(p, infos);
    if (rc != ces::CES_OK)
      return [rc](lua_State* L) { return client_push_err(L, rc); };
    return [infos](lua_State* L) -> int {
      lua_newtable(L);
      for (size_t i = 0; i < infos.size(); ++i) {
        push_instance_info(L, infos[i]);
        lua_rawseti(L, -2, static_cast<int>(i + 1));
      }
      return 1;
    };
  });
}

int lua_cc_close(lua_State* L) {
  uint64_t id = client_handle_id(L, 1);
  auto it = g_compute_clients.find(id);
  if (it == g_compute_clients.end()) return 0;
  if (it->second.inflight) { it->second.closePending = true; return 0; }  // defer
  client_close(g_compute_clients, id);
  return 0;
}

void push_compute_handle(lua_State* L, uint64_t id) {
  lua_newtable(L);
  lua_pushnumber(L, static_cast<lua_Number>(id)); lua_setfield(L, -2, "id");
  lua_pushcfunction(L, guarded<lua_cc_launch>);    lua_setfield(L, -2, "launch");
  lua_pushcfunction(L, guarded<lua_cc_kill>);      lua_setfield(L, -2, "kill");
  lua_pushcfunction(L, guarded<lua_cc_stat>);      lua_setfield(L, -2, "stat");
  lua_pushcfunction(L, guarded<lua_cc_list>);      lua_setfield(L, -2, "list");
  lua_pushcfunction(L, guarded<lua_cc_instances>); lua_setfield(L, -2, "instances");
  lua_pushcfunction(L, guarded<lua_cc_close>);     lua_setfield(L, -2, "close");
}

int lua_ces_compute_client(lua_State* L) {
  std::string addr; const uint8_t* pk = nullptr; uint8_t pkbuf[32];
  if (!client_read_dial_args(L, addr, &pk, pkbuf)) return 2;
  return client_dial(L, addr, pk, "/ces/compute/1",
    [](lua_State* L, std::unique_ptr<ces::CesPlexChannel> ch) -> int {
      auto cc = std::make_unique<ces::CesComputeClient>();
      cc->attach(*ch);
      uint64_t id = g_client_next_id++;
      auto& e = g_compute_clients[id];
      e.ch = std::move(ch);
      e.cc = std::move(cc);
      push_compute_handle(L, id);
      return 1;
    });
}

// ces.err — CES error names → codes, for legible error checks.
void install_ces_err_table(lua_State* L) {
  lua_newtable(L);
  const struct { const char* name; int code; } kErrs[] = {
    {"OK", ces::CES_OK},
    {"ORIGIN_NOT_FOUND", ces::CES_ERROR_ORIGIN_NOT_FOUND},
    {"WRONG_NONCE", ces::CES_ERROR_WRONG_NONCE},
    {"INSUFFICIENT_BALANCE", ces::CES_ERROR_INSUFFICIENT_BALANCE},
    {"INSUFFICIENT_BALANCE_WITH_CREATE",
     ces::CES_ERROR_INSUFFICIENT_BALANCE_WITH_CREATE},
    {"INVALID_TARGET_ACCOUNT", ces::CES_ERROR_INVALID_TARGET_ACCOUNT},
    {"WRONG_TARGET_ACCOUNT", ces::CES_ERROR_WRONG_TARGET_ACCOUNT},
    {"WRONG_PAYMENT_AMOUNT", ces::CES_ERROR_WRONG_PAYMENT_AMOUNT},
    {"ASSET_EXISTS", ces::CES_ERROR_ASSET_EXISTS},
    {"ASSET_NOT_FOUND", ces::CES_ERROR_ASSET_NOT_FOUND},
    {"NOT_OWNER", ces::CES_ERROR_NOT_OWNER},
    {"NOT_FOR_SALE", ces::CES_ERROR_NOT_FOR_SALE},
    {"INSUFFICIENT_PAYMENT", ces::CES_ERROR_INSUFFICIENT_PAYMENT},
    {"TIMEOUT", ces::CES_ERROR_TIMEOUT},
    {"INTERNAL", ces::CES_ERROR_INTERNAL},
    {"TARGET_NOT_FOUND", ces::CES_ERROR_TARGET_NOT_FOUND},
    {"UNKNOWN_PEER", ces::CES_ERROR_UNKNOWN_PEER},
    {"QUEUE_FULL", ces::CES_ERROR_QUEUE_FULL},
    {"VM_FAILED", ces::CES_ERROR_VM_FAILED},
    {"DISABLED", ces::CES_ERROR_DISABLED},
    {"ALLOWANCE_EXCEEDED", ces::CES_ERROR_ALLOWANCE_EXCEEDED},
    {"PROTO_REJECTED", ces::CES_ERROR_PROTO_REJECTED},
    {"FILE_NOT_FOUND", ces::CES_ERROR_FILE_NOT_FOUND},
    {"FILE_EXISTS", ces::CES_ERROR_FILE_EXISTS},
    {"BAD_NAME", ces::CES_ERROR_BAD_NAME},
    {"PATH_CONFLICT", ces::CES_ERROR_PATH_CONFLICT},
    {"STORE_FULL", ces::CES_ERROR_STORE_FULL},
    {"COMPUTE_DISABLED", ces::CES_ERROR_COMPUTE_DISABLED},
    {"COMPUTE_NO_FILE_HANDLER", ces::CES_ERROR_COMPUTE_NO_FILE_HANDLER},
    {"COMPUTE_FUND_TOO_LOW", ces::CES_ERROR_COMPUTE_FUND_TOO_LOW},
    {"COMPUTE_INSTANCE_NOT_FOUND", ces::CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND},
    {"COMPUTE_MAX_INSTANCES", ces::CES_ERROR_COMPUTE_MAX_INSTANCES},
    {"NOT_LISTENING", ces::CES_ERROR_NOT_LISTENING},
    {"IMMUTABLE", ces::CES_ERROR_IMMUTABLE},
    {"BAD_INPUT", ces::CES_ERROR_BAD_INPUT},
  };
  for (const auto& e : kErrs) {
    lua_pushinteger(L, e.code);
    lua_setfield(L, -2, e.name);
  }
  lua_setfield(L, -2, "err");   // ces.err = {...}  (ces table is at -2)
}

void install_ces_api(lua_State* L) {
  lua_newtable(L);
  lua_pushcfunction(L, guarded<lua_ces_now>);           lua_setfield(L, -2, "now");
  lua_pushcfunction(L, guarded<lua_ces_sha256>);        lua_setfield(L, -2, "sha256");
  lua_pushcfunction(L, guarded<lua_ces_log>);           lua_setfield(L, -2, "log");
  lua_pushcfunction(L, guarded<lua_ces_sign>);          lua_setfield(L, -2, "sign");
  lua_pushcfunction(L, guarded<lua_ces_verify>);        lua_setfield(L, -2, "verify");
  lua_pushcfunction(L, guarded<lua_ces_server_sign>);   lua_setfield(L, -2, "serverSign");
  lua_pushcfunction(L, guarded<lua_ces_server_verify>); lua_setfield(L, -2, "serverVerify");
  lua_pushcfunction(L, guarded<lua_ces_every>);         lua_setfield(L, -2, "every");
  lua_pushcfunction(L, guarded<lua_ces_cancel>);        lua_setfield(L, -2, "cancel");
  lua_pushcfunction(L, guarded<lua_ces_spawn>);         lua_setfield(L, -2, "spawn");
  lua_pushcfunction(L, guarded<lua_ces_sleep>);         lua_setfield(L, -2, "sleep");
  lua_pushcfunction(L, guarded<lua_chan_new>);          lua_setfield(L, -2, "chan");
  // ces.chan metatable (methods + __gc), created once.
  luaL_newmetatable(L, kChanMT);
  lua_pushvalue(L, -1); lua_setfield(L, -2, "__index");
  lua_pushcfunction(L, guarded<lua_chan_send>);  lua_setfield(L, -2, "send");
  lua_pushcfunction(L, guarded<lua_chan_recv>);  lua_setfield(L, -2, "recv");
  lua_pushcfunction(L, guarded<lua_chan_close>); lua_setfield(L, -2, "close");
  lua_pushcfunction(L, lua_chan_gc);             lua_setfield(L, -2, "__gc");
  lua_pop(L, 1);
  lua_pushcfunction(L, guarded<lua_ces_client_recv>);   lua_setfield(L, -2, "client_recv");
  lua_pushcfunction(L, guarded<lua_ces_client_send>);   lua_setfield(L, -2, "client_send");
  lua_pushcfunction(L, guarded<lua_ces_prog_prefix>);   lua_setfield(L, -2, "prog_prefix");
  lua_pushcfunction(L, guarded<lua_ces_owner_pubkey>);  lua_setfield(L, -2, "owner_pubkey");
  lua_pushcfunction(L, guarded<lua_ces_program_pubkey>);lua_setfield(L, -2, "program_pubkey");
  lua_pushcfunction(L, guarded<lua_ces_rpc_port>);      lua_setfield(L, -2, "rpc_port");
  lua_pushcfunction(L, guarded<lua_ces_start_time>);    lua_setfield(L, -2, "start_time");
  lua_pushcfunction(L, guarded<lua_ces_transfer>);      lua_setfield(L, -2, "transfer");
  lua_pushcfunction(L, guarded<lua_ces_random_bytes>);  lua_setfield(L, -2, "random_bytes");
  lua_pushcfunction(L, guarded<lua_ces_account_read>);  lua_setfield(L, -2, "account_read");
  lua_pushcfunction(L, guarded<lua_ces_peers>);         lua_setfield(L, -2, "peers");
  // Peering CONTROL is operator-only: present solely for privileged (/s/)
  // programs. The supervisor enforces the same gate, so the boundary holds even
  // if the sandbox were bypassed.
  if (g_privileged) {
    lua_pushcfunction(L, guarded<lua_ces_add_peer>);        lua_setfield(L, -2, "add_peer");
    lua_pushcfunction(L, guarded<lua_ces_remove_peer>);     lua_setfield(L, -2, "remove_peer");
    lua_pushcfunction(L, guarded<lua_ces_grief_peer>);      lua_setfield(L, -2, "grief_peer");
    lua_pushcfunction(L, guarded<lua_ces_ban_peer>);        lua_setfield(L, -2, "ban_peer");
    lua_pushcfunction(L, guarded<lua_ces_set_peer_target>); lua_setfield(L, -2, "set_peer_target");
    lua_pushcfunction(L, guarded<lua_ces_peer_target>);     lua_setfield(L, -2, "peer_target");
  }
  lua_pushcfunction(L, guarded<lua_ces_ping>);          lua_setfield(L, -2, "ping");
  lua_pushcfunction(L, guarded<lua_ces_peer_info>);     lua_setfield(L, -2, "peer_info");
  lua_pushcfunction(L, guarded<lua_ces_authentic_asset_create>);
  lua_setfield(L, -2, "authentic_asset_create");
  lua_pushcfunction(L, guarded<lua_ces_bucket_new>);    lua_setfield(L, -2, "bucket_new");
  lua_pushcfunction(L, guarded<lua_ces_file_create>);   lua_setfield(L, -2, "file_create");
  lua_pushcfunction(L, guarded<lua_ces_file_write>);    lua_setfield(L, -2, "file_write");
  lua_pushcfunction(L, guarded<lua_ces_file_read>);     lua_setfield(L, -2, "file_read");
  lua_pushcfunction(L, guarded<lua_ces_file_stat>);     lua_setfield(L, -2, "file_stat");
  lua_pushcfunction(L, guarded<lua_ces_file_deposit>);  lua_setfield(L, -2, "file_deposit");
  lua_pushcfunction(L, guarded<lua_ces_file_withdraw>); lua_setfield(L, -2, "file_withdraw");
  lua_pushcfunction(L, guarded<lua_ces_file_set_price>);lua_setfield(L, -2, "file_set_price");
  lua_pushcfunction(L, guarded<lua_ces_file_delete>);   lua_setfield(L, -2, "file_delete");
  lua_pushcfunction(L, guarded<lua_ces_file_append>);   lua_setfield(L, -2, "file_append");
  lua_pushcfunction(L, guarded<lua_ces_file_resize>);   lua_setfield(L, -2, "file_resize");
  lua_pushcfunction(L, guarded<lua_ces_store>);         lua_setfield(L, -2, "store");
  lua_pushcfunction(L, guarded<lua_ces_file_client>);   lua_setfield(L, -2, "file_client");
  lua_pushcfunction(L, guarded<lua_ces_compute_client>);lua_setfield(L, -2, "compute_client");
  lua_pushcfunction(L, guarded<lua_ces_remote_account_read>);
  lua_setfield(L, -2, "remote_account_read");
  lua_pushcfunction(L, guarded<lua_ces_remote_transfer>);
  lua_setfield(L, -2, "remote_transfer");
  lua_pushcfunction(L, guarded<lua_ces_remote_cross_transfer>);
  lua_setfield(L, -2, "remote_cross_transfer");
  lua_pushcfunction(L, guarded<lua_ces_cross_transfer>);
  lua_setfield(L, -2, "cross_transfer");
  lua_pushcfunction(L, guarded<lua_ces_request_funds>);
  lua_setfield(L, -2, "request_funds");

  // ces.conn — the UNIFIED connection API: one listener + run loop + conn shape
  // over BOTH transports (relay /ces/lua/1, server-relayed; direct /ces/luarpc/1
  // on this instance's own port). connect() dials out the direct transport.
  // Inbound conns from either fan into one set of callbacks; tell them apart, if
  // you must, by conn.source (0 = relay, 1 = direct).
  lua_newtable(L);
  lua_pushcfunction(L, guarded<lua_ces_conn_set_listener>);
  lua_setfield(L, -2, "set_listener");
  lua_pushcfunction(L, guarded<lua_ces_run>);
  lua_setfield(L, -2, "run");
  lua_pushcfunction(L, guarded<lua_ces_conn_connect>);
  lua_setfield(L, -2, "connect");
  lua_setfield(L, -2, "conn");

  // ces.gossip — flood/route messaging over the server mesh. send(msg, budget
  // [, dest]) originates a flood; inbound is delivered by calling the program's
  // global on_gossip(msg, {author,sender,msgid,dest}) if it defined one. A node
  // delivers its own originated gossip to its own programs too, so local
  // extensions stay in step with the swarm.
  lua_newtable(L);
  lua_pushcfunction(L, guarded<lua_ces_gossip_send>);
  lua_setfield(L, -2, "send");
  lua_setfield(L, -2, "gossip");

  // ces.peer.send(peer_pubkey, service, bytes) fires a targeted, free message
  // over the /ces/peer/1 mesh to a peer server's same-service extension;
  // ces.peer.listen(service, fn) registers fn(from_pubkey, bytes) for inbound.
  lua_newtable(L);
  lua_pushcfunction(L, guarded<lua_ces_peer_send>);
  lua_setfield(L, -2, "send");
  lua_pushcfunction(L, guarded<lua_ces_peer_listen>);
  lua_setfield(L, -2, "listen");
  lua_setfield(L, -2, "peer");

  // Direct-transport live-conn registry (the relay's is created lazily in
  // set_listener).
  lua_newtable(L);
  lua_setfield(L, LUA_REGISTRYINDEX, kRegLuaRpcConns);

  // ces.run() — the unified event loop (ces.conn.run aliases it).
  lua_pushcfunction(L, guarded<lua_ces_run>);
  lua_setfield(L, -2, "run");

  // ces.err — error names → codes.
  install_ces_err_table(L);

  // ces.extension_admin — a callable table: ces.extension_admin{...} registers
  // the admin contract (via __call); ces.extension_admin.disable_self() turns
  // this instance off.
  lua_newtable(L);
  lua_pushcfunction(L, guarded<lua_ces_extension_admin_disable_self>);
  lua_setfield(L, -2, "disable_self");
  lua_newtable(L);                                  // metatable
  lua_pushcfunction(L, guarded<lua_ces_extension_admin>);
  lua_setfield(L, -2, "__call");
  lua_setmetatable(L, -2);
  lua_setfield(L, -2, "extension_admin");

  lua_setglobal(L, "ces");
}

// `cesluajitd --manifest <file>`: harvest a program's CES_MANIFEST WITHOUT
// running it as a service. Loads the file in a no-op sandbox — a stub `ces` whose
// every index/call yields itself, so ces.run()/ces.transfer()/... do nothing —
// runs it under a tight instruction budget, then reads the static CES_MANIFEST
// global. CES_MANIFEST is the program's first statement, so it's set even if
// later code aborts. No source-text parsing: the real Lua loader evaluates the
// actual table. Prints name/version/description on three lines.
void probe_budget_hook(lua_State* L, lua_Debug*) {
  luaL_error(L, "manifest probe budget exceeded");
}
int probe_manifest(const char* path) {
  std::FILE* fp = std::fopen(path, "rb");
  if (!fp) return 1;
  std::string src;
  char rbuf[4096];
  size_t n;
  while ((n = std::fread(rbuf, 1, sizeof(rbuf), fp)) > 0) src.append(rbuf, n);
  std::fclose(fp);
  if (!src.empty() && static_cast<unsigned char>(src[0]) == 0x1b) return 1;  // no bytecode

  lua_State* L = luaL_newstate();
  if (!L) return 1;
  load_safe_libs(L);
  luaL_dostring(L,                                  // universal no-op `ces` stub
    "local s; s = setmetatable({}, {__index=function() return s end,"
    " __call=function() return s end}); ces = s");
  lua_sethook(L, probe_budget_hook, LUA_MASKCOUNT, 2000000);

  std::string name, version, desc;
  if (luaL_loadbufferx(L, src.data(), src.size(), "=probe", "t") == 0)
    lua_pcall(L, 0, 0, 0);                          // errors ignored; CES_MANIFEST set first
  lua_sethook(L, nullptr, 0, 0);
  lua_getglobal(L, "CES_MANIFEST");
  if (lua_istable(L, -1)) {
    int t = lua_gettop(L);
    name    = ext_str_field(L, t, "name");
    version = ext_str_field(L, t, "version");
    desc    = ext_str_field(L, t, "description");
  }
  lua_close(L);
  std::printf("%s\n%s\n%s\n", name.c_str(), version.c_str(), desc.c_str());
  return 0;
}

