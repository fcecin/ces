// ---------------------------------------------------------------------------
// Blocking-call offload pools. The network verbs below wrap synchronous C++
// (CesClient / CesPlexChannel), which would freeze the event loop if run on the
// Lua thread from a coroutine. Instead a worker thread runs the blocking call,
// the coroutine parks, and the run loop resumes it when the worker reports back
// — the same park/yield/resume contract the IPC path uses, just woken by a
// worker instead of a reply frame. Two pools (see the verb sites):
//   g_pool_main   — 1 worker, the main-port CesClient (reused + re-pointed,
//                   sharing the single leased outbound port).
//   g_pool_client — N workers, the endpoint verb-clients (independent channels).
// A saturated pool does NOT block the loop: the coroutine just stays parked
// until a worker frees. Main-chunk callers (cannot yield) still block inline.
// ---------------------------------------------------------------------------

// A worker runs the job and returns a "deliver" closure that, on the run-loop
// thread, pushes the call's Lua results and returns the count.
using OffloadDeliver = std::function<int(lua_State*)>;
using OffloadJob     = std::function<OffloadDeliver()>;

struct OffloadDone { lua_State* co; OffloadDeliver deliver; };
std::deque<OffloadDone> g_offload_done;   // workers push, run() drains
std::mutex              g_offload_mx;

// Worker → run loop: queue the result and nudge run()'s poll (the eventfd is
// the endpoint's, reused here purely as a wakeup).
void offload_complete(lua_State* co, OffloadDeliver deliver) {
  {
    std::lock_guard<std::mutex> lk(g_offload_mx);
    g_offload_done.push_back(OffloadDone{co, std::move(deliver)});
  }
  if (g_luarpc_wakefd >= 0) {
    uint64_t one = 1;
    ssize_t w = ::write(g_luarpc_wakefd, &one, sizeof(one));
    (void)w;
  }
}

struct WorkerPool {
  std::vector<std::thread> threads;
  std::deque<std::pair<lua_State*, OffloadJob>> q;
  std::mutex mx;
  std::condition_variable cv;
  bool stop = false;

  void ensure(int n) {
    if (!threads.empty()) return;   // lazy: started on first use
    for (int i = 0; i < n; i++) threads.emplace_back([this]() { run(); });
  }
  void run() {
    for (;;) {
      std::pair<lua_State*, OffloadJob> item;
      {
        std::unique_lock<std::mutex> lk(mx);
        cv.wait(lk, [this]() { return stop || !q.empty(); });
        if (stop && q.empty()) return;
        item = std::move(q.front());
        q.pop_front();
      }
      OffloadDeliver deliver;
      // A thrown job surfaces its reason to the program via the deliver (which
      // runs on the Lua thread) -- never host_log from here: a worker must not
      // write the IPC socket (it would race the main thread's frames).
      try {
        deliver = item.second();
      } catch (const std::exception& e) {
        std::string msg = e.what();
        deliver = [msg](lua_State* L) {
          lua_pushnil(L); lua_pushstring(L, msg.c_str()); return 2;
        };
      } catch (...) {
        deliver = [](lua_State* L) {
          lua_pushnil(L); lua_pushstring(L, "internal"); return 2;
        };
      }
      offload_complete(item.first, std::move(deliver));
    }
  }
  void submit(lua_State* co, OffloadJob job) {
    {
      std::lock_guard<std::mutex> lk(mx);
      q.push_back({co, std::move(job)});
    }
    cv.notify_one();
  }
  void shutdown() {
    { std::lock_guard<std::mutex> lk(mx); stop = true; }
    cv.notify_all();
    for (auto& t : threads) if (t.joinable()) t.join();
    threads.clear();
  }
};

WorkerPool g_pool_main;             // #4: main-port CesClient
WorkerPool g_pool_client;           // #3: endpoint verb-clients
// #3 worker count: operator knob (compute_client_pool_size), passed in via
// argv on spawn. Read once at startup; clamped to a sane range. The single
// pool-main worker (#4) is fixed at 1 (port-constrained), not configurable.
int g_client_pool_size = 4;

// The reused, re-pointable main-port client — one per g_pool_main worker (the
// pool has exactly one). Created lazily, bound once to the instance's leased
// outbound port. Re-points to `ep` and resets tries/retry on EVERY call: the
// client persists across jobs, so its config must not leak between verbs (e.g.
// a prior ces.ping's tries=1 must not weaken a later transfer). Null if the
// port bind fails. Touched ONLY on the pool-main worker thread.
ces::CesClient* poolMainClient(const boost::asio::ip::udp::endpoint& ep,
                               int tries, int retryMs) {
  // g_pool_main is one worker by design: the reused client is held thread_local
  // and binds the single g_program_port (bindable once), so a second worker
  // would only get a client whose start() fails on the taken port. Assert one
  // caller thread so a future ensure(>1) on this pool trips loudly in debug.
  static std::atomic<std::thread::id> owner{std::thread::id{}};
  std::thread::id self = std::this_thread::get_id(), none{};
  owner.compare_exchange_strong(none, self);
  assert(owner.load() == self && "poolMainClient: g_pool_main must be 1 worker");
  static thread_local std::unique_ptr<ces::CesClient> c;
  if (!c) {
    boost::asio::ip::udp::endpoint seed(
      boost::asio::ip::address_v6::loopback(), 0);
    c = std::make_unique<ces::CesClient>(seed, /*useDataset=*/false,
                                         luaClientConfig());
    if (!c->start(g_program_port)) { c.reset(); return nullptr; }
  }
  c->setRemoteEndpoint(ep);
  c->setTries(tries);
  c->setRetryIntervalMs(retryMs);
  return c.get();
}

// Optional timeout_ms at Lua arg `argn` → the reused client's per-try reply
// wait (default 3000, CesClient's own default). For single-try verbs (queries)
// this is the whole wait; transfers apply it per retry.
int optRetryMs(lua_State* L, int argn) {
  int t = static_cast<int>(luaL_optinteger(L, argn, 0));
  return t > 0 ? t : 3000;
}

// ces.remote_account_read(addr:string, account_pubkey:string(32) [, timeout_ms])
//   → balance, nonce, last_xfer_dest(8B), last_xfer_amount, last_xfer_time
//     | nil, err
//
// Resolves `addr` ("ip:port" or "host:port") and queries that account on
// the remote server via the child's own CesClient. Unsigned query — needs
// no key. Blocks the Lua VM for the round-trip (sync).
int lua_ces_remote_account_read(lua_State* L) {
  if (g_program_port == 0) {
    lua_pushnil(L);
    lua_pushstring(L, "networking permanently disabled (this instance has no compute port)");
    return 2;
  }
  size_t addr_len = 0;
  const char* addr = luaL_checklstring(L, 1, &addr_len);
  size_t pk_len = 0;
  const char* pk = luaL_checklstring(L, 2, &pk_len);
  if (pk_len != 32) {
    lua_pushnil(L);
    lua_pushstring(L, "account pubkey must be 32 bytes");
    return 2;
  }
  boost::asio::ip::udp::endpoint ep;
  try {
    ep = ces::Resolver::resolveUdp(std::string(addr, addr_len));
  } catch (const std::exception&) {
    lua_pushnil(L);
    lua_pushstring(L, "address resolve failed");
    return 2;
  }
  ces::Hash pubkey{};
  std::memcpy(pubkey.data(), pk, 32);
  ces::HashPrefix mapKey = ces::Account::getMapKey(pubkey);
  int retryMs = optRetryMs(L, 3);   // optional timeout_ms (arg 3)

  if (io_yieldable(L)) {
    lua_State* co = L;
    g_parked.insert(co);
    g_pool_main.ensure(1);
    g_pool_main.submit(co, [ep, mapKey, retryMs]() -> OffloadDeliver {
      ces::CesClient* c = poolMainClient(ep, 1, retryMs);
      auto fail = [](lua_State* L) {
        lua_pushnil(L); lua_pushinteger(L, STATUS_INTERNAL); return 2;
      };
      if (!c) return fail;
      if (!c->connect()) return fail;
      int64_t bal = 0; uint32_t nonce = 0; ces::HashPrefix ld{};
      uint64_t la = 0; uint32_t lt = 0;
      uint8_t rc = c->queryAccount(mapKey, bal, nonce, ld, la, lt);
      if (rc != ces::CES_OK)
        return [rc](lua_State* L) {
          lua_pushnil(L); lua_pushinteger(L, rc); return 2;
        };
      return [bal, nonce, ld, la, lt](lua_State* L) -> int {
        lua_pushnumber(L, static_cast<lua_Number>(bal));
        lua_pushnumber(L, static_cast<lua_Number>(nonce));
        lua_pushlstring(L, reinterpret_cast<const char*>(ld.data()), ld.size());
        lua_pushnumber(L, static_cast<lua_Number>(la));
        lua_pushnumber(L, static_cast<lua_Number>(lt));
        return 5;
      };
    });
    return lua_yield(L, 0);
  }

  int64_t balance = 0;
  uint32_t nonce = 0;
  ces::HashPrefix lastDest{};
  uint64_t lastAmt = 0;
  uint32_t lastTime = 0;
  uint8_t rc;
  try {
    ces::CesClient client(ep, /*useDataset=*/false, luaClientConfig());
    client.setTries(1);
    client.setRetryIntervalMs(retryMs);
    if (!client.start(g_program_port) || !client.connect()) {
      lua_pushnil(L);
      lua_pushinteger(L, STATUS_INTERNAL);
      return 2;
    }
    rc = client.queryAccount(mapKey, balance, nonce, lastDest, lastAmt, lastTime);
    client.disconnect();
    client.stop();
  } catch (const std::exception& e) {
    host_log(3, std::string("ces.remote_account_read: ") + e.what());
    lua_pushnil(L);
    lua_pushinteger(L, STATUS_INTERNAL);
    return 2;
  }
  if (rc != ces::CES_OK) {
    lua_pushnil(L);
    lua_pushinteger(L, rc);
    return 2;
  }
  lua_pushnumber(L, static_cast<lua_Number>(balance));
  lua_pushnumber(L, static_cast<lua_Number>(nonce));
  lua_pushlstring(L, reinterpret_cast<const char*>(lastDest.data()),
                  lastDest.size());
  lua_pushnumber(L, static_cast<lua_Number>(lastAmt));
  lua_pushnumber(L, static_cast<lua_Number>(lastTime));
  return 5;
}

// ces.ping(addr [, timeout_ms]) → {pubkey(32), rpc_port, min_difficulty} | nil, err
//
// Free MINX GetInfo handshake to a remote server: learns its public key and
// the rpc port that reaches its CesPlex handlers (file/compute/luarpc). A P2P
// node turns a peer's main address (from ces.peers) into the rpc endpoint where
// the peer's DHT instance can be discovered and dialed. Ticketless, so it works
// even against a no-PoW-engine peer.
//
// Optional timeout_ms overrides the single-try reply wait (the CesClient
// default is 3000); a crawler with many hosts can lower it so a dead host fails
// in well under the default 3s. Omitted/<=0 keeps the default.
int lua_ces_ping(lua_State* L) {
  if (g_program_port == 0) {
    lua_pushnil(L);
    lua_pushstring(L, "networking permanently disabled (no compute port)");
    return 2;
  }
  size_t alen = 0;
  const char* addr = luaL_checklstring(L, 1, &alen);
  int timeoutMs = static_cast<int>(luaL_optinteger(L, 2, 0));
  boost::asio::ip::udp::endpoint ep;
  try {
    ep = ces::Resolver::resolveUdp(std::string(addr, alen));
  } catch (const std::exception&) {
    lua_pushnil(L);
    lua_pushstring(L, "address resolve failed");
    return 2;
  }
  // Builds the {pubkey, rpc_port, min_difficulty} result table.
  auto deliverInfo = [](minx::Hash key, uint16_t rpc, uint8_t md) {
    return [key, rpc, md](lua_State* L) -> int {
      lua_newtable(L);
      lua_pushlstring(L, reinterpret_cast<const char*>(key.data()), 32);
      lua_setfield(L, -2, "pubkey");
      lua_pushnumber(L, static_cast<lua_Number>(rpc));
      lua_setfield(L, -2, "rpc_port");
      lua_pushnumber(L, static_cast<lua_Number>(md));
      lua_setfield(L, -2, "min_difficulty");
      return 1;
    };
  };
  auto deliverErr = [](const char* msg) {
    std::string m(msg);
    return [m](lua_State* L) -> int {
      lua_pushnil(L);
      lua_pushlstring(L, m.data(), m.size());
      return 2;
    };
  };

  // From a coroutine: offload the round-trip to the single main-port worker
  // (reused re-pointable client) and yield. Otherwise block inline.
  if (io_yieldable(L)) {
    lua_State* co = L;
    g_parked.insert(co);
    g_pool_main.ensure(1);
    int retryMs = timeoutMs > 0 ? timeoutMs : 3000;
    g_pool_main.submit(co, [ep, retryMs, deliverInfo, deliverErr]()
                              -> OffloadDeliver {
      ces::CesClient* c = poolMainClient(ep, 1, retryMs);
      if (!c) return deliverErr("networking disabled");
      if (!c->connect()) return deliverErr("unreachable");
      return deliverInfo(c->getServerKey(), c->getServerRpcPort(),
                         c->getMinDifficulty());
    });
    return lua_yield(L, 0);
  }

  minx::Hash serverKey;
  uint16_t rpcPort = 0;
  uint8_t minDiff = 0;
  try {
    ces::CesClient client(ep, /*useDataset=*/false, luaClientConfig());
    client.setTries(1);  // fast-fail: a departed peer must not freeze the loop
    if (timeoutMs > 0) client.setRetryIntervalMs(timeoutMs);
    if (!client.start(g_program_port) || !client.connect()) {
      lua_pushnil(L);
      lua_pushstring(L, "unreachable");
      return 2;
    }
    serverKey = client.getServerKey();
    rpcPort = client.getServerRpcPort();
    minDiff = client.getMinDifficulty();
    client.disconnect();
    client.stop();
  } catch (const std::exception& e) {
    host_log(3, std::string("ces.ping: ") + e.what());
    lua_pushnil(L);
    lua_pushstring(L, "ping failed");
    return 2;
  }
  return deliverInfo(serverKey, rpcPort, minDiff)(L);
}

// ces.peer_info(addr, index [, timeout_ms]) -> {count, found, pubkey(32)|nil, address|nil}
//   | nil, err. One slot of a remote server's public peer table (unsigned,
//   unpaid CES_QUERY_PEER_INFO): the total count and the peer at index.
int lua_ces_peer_info(lua_State* L) {
  if (g_program_port == 0) {
    lua_pushnil(L);
    lua_pushstring(L, "networking permanently disabled (this instance has no compute port)");
    return 2;
  }
  size_t addr_len = 0;
  const char* addr = luaL_checklstring(L, 1, &addr_len);
  lua_Number idx_n = luaL_checknumber(L, 2);
  if (idx_n < 0 || idx_n > 65535) {
    lua_pushnil(L);
    lua_pushstring(L, "index must be 0..65535");
    return 2;
  }
  uint16_t index = static_cast<uint16_t>(idx_n);
  boost::asio::ip::udp::endpoint ep;
  try {
    ep = ces::Resolver::resolveUdp(std::string(addr, addr_len));
  } catch (const std::exception&) {
    lua_pushnil(L);
    lua_pushstring(L, "address resolve failed");
    return 2;
  }

  int retryMs = optRetryMs(L, 3);   // optional timeout_ms (arg 3)

  if (io_yieldable(L)) {
    lua_State* co = L;
    g_parked.insert(co);
    g_pool_main.ensure(1);
    g_pool_main.submit(co, [ep, index, retryMs]() -> OffloadDeliver {
      ces::CesClient* c = poolMainClient(ep, 1, retryMs);
      auto err = [](const char* m) {
        std::string s(m);
        return [s](lua_State* L) {
          lua_pushnil(L); lua_pushlstring(L, s.data(), s.size()); return 2;
        };
      };
      if (!c) return err("networking disabled");
      if (!c->connect()) return err("unreachable");
      uint16_t count = 0; bool found = false; ces::Hash pk{}; std::string paddr;
      uint8_t rc = c->queryPeerInfo(index, count, found, pk, paddr);
      if (rc != ces::CES_OK)
        return [rc](lua_State* L) {
          lua_pushnil(L); lua_pushinteger(L, rc); return 2;
        };
      return [count, found, pk, paddr](lua_State* L) -> int {
        lua_newtable(L);
        lua_pushnumber(L, static_cast<lua_Number>(count));
        lua_setfield(L, -2, "count");
        lua_pushboolean(L, found ? 1 : 0);
        lua_setfield(L, -2, "found");
        if (found) {
          lua_pushlstring(L, reinterpret_cast<const char*>(pk.data()), 32);
          lua_setfield(L, -2, "pubkey");
          lua_pushlstring(L, paddr.data(), paddr.size());
          lua_setfield(L, -2, "address");
        }
        return 1;
      };
    });
    return lua_yield(L, 0);
  }

  uint16_t count = 0;
  bool found = false;
  ces::Hash pubkey{};
  std::string paddr;
  uint8_t rc;
  try {
    ces::CesClient client(ep, /*useDataset=*/false, luaClientConfig());
    client.setTries(1);  // fast-fail: a slow crawler must not block on a dead host
    client.setRetryIntervalMs(retryMs);
    if (!client.start(g_program_port) || !client.connect()) {
      lua_pushnil(L);
      lua_pushstring(L, "unreachable");
      return 2;
    }
    rc = client.queryPeerInfo(index, count, found, pubkey, paddr);
    client.disconnect();
    client.stop();
  } catch (const std::exception& e) {
    host_log(3, std::string("ces.peer_info: ") + e.what());
    lua_pushnil(L);
    lua_pushstring(L, "peer_info failed");
    return 2;
  }
  if (rc != ces::CES_OK) {
    lua_pushnil(L);
    lua_pushinteger(L, rc);
    return 2;
  }
  lua_newtable(L);
  lua_pushnumber(L, static_cast<lua_Number>(count));
  lua_setfield(L, -2, "count");
  lua_pushboolean(L, found ? 1 : 0);
  lua_setfield(L, -2, "found");
  if (found) {
    lua_pushlstring(L, reinterpret_cast<const char*>(pubkey.data()), 32);
    lua_setfield(L, -2, "pubkey");
    lua_pushlstring(L, paddr.data(), paddr.size());
    lua_setfield(L, -2, "address");
  }
  return 1;
}

// ces.remote_transfer(addr:string, dest_pubkey:string(32), amount:number [, timeout_ms])
//   → true, new_origin_balance | nil, err
//
// Resolves `addr` and signs a transfer from the program's own account on
// that remote server with the program's private key. Open transfer: creates
// the destination account if it does not exist there yet (safe mode, which
// rejects a missing target, is for humans who mistype an address — a program
// paying out to a fresh account wants it created, like the local ces.transfer).
int lua_ces_remote_transfer(lua_State* L) {
  if (g_program_port == 0) {
    lua_pushnil(L);
    lua_pushstring(L, "networking permanently disabled (this instance has no compute port)");
    return 2;
  }
  size_t addr_len = 0;
  const char* addr = luaL_checklstring(L, 1, &addr_len);
  size_t pk_len = 0;
  const char* pk = luaL_checklstring(L, 2, &pk_len);
  if (pk_len != 32) {
    lua_pushnil(L);
    lua_pushstring(L, "dest pubkey must be 32 bytes");
    return 2;
  }
  lua_Number amt_n = luaL_checknumber(L, 3);
  if (amt_n < 0 || amt_n > 9.2233720368547e18) {
    lua_pushnil(L);
    lua_pushstring(L, "amount out of range");
    return 2;
  }
  uint64_t amount = static_cast<uint64_t>(amt_n);
  boost::asio::ip::udp::endpoint ep;
  try {
    ep = ces::Resolver::resolveUdp(std::string(addr, addr_len));
  } catch (const std::exception&) {
    lua_pushnil(L);
    lua_pushstring(L, "address resolve failed");
    return 2;
  }
  ces::Hash priv{};
  std::memcpy(priv.data(), g_program_privkey, 32);
  ces::KeyPair kp(priv, ces::KeyAlgo::ED25519);
  ces::Hash dest{};
  std::memcpy(dest.data(), pk, 32);
  int retryMs = optRetryMs(L, 4);   // optional timeout_ms (arg 4)

  if (io_yieldable(L)) {
    lua_State* co = L;
    g_parked.insert(co);
    g_pool_main.ensure(1);
    g_pool_main.submit(co, [ep, kp, dest, amount, retryMs]() -> OffloadDeliver {
      ces::CesClient* c = poolMainClient(ep, 3, retryMs);
      auto fail = [](lua_State* L) {
        lua_pushnil(L); lua_pushinteger(L, STATUS_INTERNAL); return 2;
      };
      if (!c) return fail;
      c->setKey(kp);
      if (!c->connect()) return fail;
      int64_t newBal = 0;
      uint8_t rc = c->openTransfer(dest, amount, newBal);
      if (rc != ces::CES_OK)
        return [rc](lua_State* L) {
          lua_pushnil(L); lua_pushinteger(L, rc); return 2;
        };
      return [newBal](lua_State* L) -> int {
        lua_pushboolean(L, 1);
        lua_pushnumber(L, static_cast<lua_Number>(newBal));
        return 2;
      };
    });
    return lua_yield(L, 0);
  }

  int64_t newBal = 0;
  uint8_t rc;
  try {
    ces::CesClient client(ep, /*useDataset=*/false, luaClientConfig());
    client.setKey(kp);
    client.setRetryIntervalMs(retryMs);
    if (!client.start(g_program_port) || !client.connect()) {
      lua_pushnil(L);
      lua_pushinteger(L, STATUS_INTERNAL);
      return 2;
    }
    rc = client.openTransfer(dest, amount, newBal);
    client.disconnect();
    client.stop();
  } catch (const std::exception& e) {
    host_log(3, std::string("ces.remote_transfer: ") + e.what());
    lua_pushnil(L);
    lua_pushinteger(L, STATUS_INTERNAL);
    return 2;
  }
  if (rc != ces::CES_OK) {
    lua_pushnil(L);
    lua_pushinteger(L, rc);
    return 2;
  }
  lua_pushboolean(L, 1);
  lua_pushnumber(L, static_cast<lua_Number>(newBal));
  return 2;
}

// ces.remote_cross_transfer(addr:string, dest_pubkey:string(32),
//                           amount:number, dest_server:string [, timeout_ms])
//   → true, new_origin_balance | nil, err
//
// Asks the remote server at `addr` to cross-transfer the program's funds
// held THERE to `dest_pubkey` on `dest_server` (a peer of `addr`). Signed
// with the program's private key — the remote server is the cross originator.
int lua_ces_remote_cross_transfer(lua_State* L) {
  if (g_program_port == 0) {
    lua_pushnil(L);
    lua_pushstring(L, "networking permanently disabled (this instance has no compute port)");
    return 2;
  }
  size_t addr_len = 0;
  const char* addr = luaL_checklstring(L, 1, &addr_len);
  size_t pk_len = 0;
  const char* pk = luaL_checklstring(L, 2, &pk_len);
  if (pk_len != 32) {
    lua_pushnil(L);
    lua_pushstring(L, "dest pubkey must be 32 bytes");
    return 2;
  }
  lua_Number amt_n = luaL_checknumber(L, 3);
  if (amt_n < 0 || amt_n > 9.2233720368547e18) {
    lua_pushnil(L);
    lua_pushstring(L, "amount out of range");
    return 2;
  }
  uint64_t amount = static_cast<uint64_t>(amt_n);
  size_t dsrv_len = 0;
  const char* dsrv = luaL_checklstring(L, 4, &dsrv_len);

  boost::asio::ip::udp::endpoint ep;
  try {
    ep = ces::Resolver::resolveUdp(std::string(addr, addr_len));
  } catch (const std::exception&) {
    lua_pushnil(L);
    lua_pushstring(L, "address resolve failed");
    return 2;
  }
  ces::Hash priv{};
  std::memcpy(priv.data(), g_program_privkey, 32);
  ces::KeyPair kp(priv, ces::KeyAlgo::ED25519);
  ces::Hash dest{};
  std::memcpy(dest.data(), pk, 32);
  std::string dsrvStr(dsrv, dsrv_len);
  int retryMs = optRetryMs(L, 5);   // optional timeout_ms (arg 5)

  if (io_yieldable(L)) {
    lua_State* co = L;
    g_parked.insert(co);
    g_pool_main.ensure(1);
    g_pool_main.submit(co, [ep, kp, dest, amount, dsrvStr, retryMs]()
                              -> OffloadDeliver {
      ces::CesClient* c = poolMainClient(ep, 3, retryMs);
      auto fail = [](lua_State* L) {
        lua_pushnil(L); lua_pushinteger(L, STATUS_INTERNAL); return 2;
      };
      if (!c) return fail;
      c->setKey(kp);
      if (!c->connect()) return fail;
      int64_t newBal = 0;
      uint8_t rc = c->crossTransfer(dest, amount, dsrvStr, newBal);
      if (rc != ces::CES_OK)
        return [rc](lua_State* L) {
          lua_pushnil(L); lua_pushinteger(L, rc); return 2;
        };
      return [newBal](lua_State* L) -> int {
        lua_pushboolean(L, 1);
        lua_pushnumber(L, static_cast<lua_Number>(newBal));
        return 2;
      };
    });
    return lua_yield(L, 0);
  }

  int64_t newBal = 0;
  uint8_t rc;
  try {
    ces::CesClient client(ep, /*useDataset=*/false, luaClientConfig());
    client.setKey(kp);
    client.setRetryIntervalMs(retryMs);
    if (!client.start(g_program_port) || !client.connect()) {
      lua_pushnil(L);
      lua_pushinteger(L, STATUS_INTERNAL);
      return 2;
    }
    rc = client.crossTransfer(dest, amount, std::string(dsrv, dsrv_len), newBal);
    client.disconnect();
    client.stop();
  } catch (const std::exception& e) {
    host_log(3, std::string("ces.remote_cross_transfer: ") + e.what());
    lua_pushnil(L);
    lua_pushinteger(L, STATUS_INTERNAL);
    return 2;
  }
  if (rc != ces::CES_OK) {
    lua_pushnil(L);
    lua_pushinteger(L, rc);
    return 2;
  }
  lua_pushboolean(L, 1);
  lua_pushnumber(L, static_cast<lua_Number>(newBal));
  return 2;
}

// ces.cross_transfer(dest_pubkey:string(32), amount:number, dest_server:string)
//   → true, new_origin_balance | nil, err_code
//
// Asks THIS server (home) to cross-transfer the program's funds here to
// `dest_pubkey` on peer `dest_server`. Server-mediated (home is the
// originator); no key needed — runs under owner/program authority like
// ces.transfer.
int lua_ces_cross_transfer(lua_State* L) {
  size_t pk_len = 0;
  const char* pk = luaL_checklstring(L, 1, &pk_len);
  if (pk_len != 32) {
    lua_pushnil(L);
    lua_pushstring(L, "dest pubkey must be 32 bytes");
    return 2;
  }
  lua_Number amt_n = luaL_checknumber(L, 2);
  if (amt_n < 0 || amt_n > 9.2233720368547e18) {
    lua_pushnil(L);
    lua_pushstring(L, "amount out of range");
    return 2;
  }
  uint64_t amount = static_cast<uint64_t>(amt_n);
  size_t dsrv_len = 0;
  const char* dsrv = luaL_checklstring(L, 3, &dsrv_len);
  if (dsrv_len == 0 || dsrv_len > 255) {
    lua_pushnil(L);
    lua_pushstring(L, "dest_server length out of range");
    return 2;
  }

  std::vector<uint8_t> args;
  args.reserve(WIRE_KEY_LEN + sizeof(uint64_t) + 1 + dsrv_len);
  put_bytes(args, pk, 32);
  put_u64(args, amount);
  args.push_back(static_cast<uint8_t>(dsrv_len));
  put_bytes(args, dsrv, dsrv_len);

  return io_call(L, METHOD_CROSS_TRANSFER, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) {
    lua_pushnil(L);
    lua_pushinteger(L, st);
    return 2;
  }
  if (reply.body.size() < sizeof(uint8_t) + sizeof(uint64_t))
    return push_file_err(L, STATUS_INTERNAL);
  uint64_t newBal = get_u64(reply.body.data() + 1);
  lua_pushboolean(L, 1);
  lua_pushnumber(L, static_cast<lua_Number>(newBal));
  return 2;
  });
}

// ces.request_funds(addr:string, amount:number) → granted:number | nil, err
//
// Petition the SERVER to fund THIS program's key at remote `addr` with up to
// `amount` credits — a server-signed regular transfer AT the remote (origin = the
// server's reserve there), gated by the operator's GLOBAL funding budget (off by
// default). Returns the CONFIRMED granted amount (0..amount). A 0 is NOT an error
// — budget exhausted/off, or the remote transfer failed; the caller backs off and
// retries. The program holds no budget and no authority; it only asks.
int lua_ces_request_funds(lua_State* L) {
  size_t addr_len = 0;
  const char* addr = luaL_checklstring(L, 1, &addr_len);
  if (addr_len == 0 || addr_len > 255) {
    lua_pushnil(L);
    lua_pushstring(L, "addr length out of range");
    return 2;
  }
  lua_Number amt_n = luaL_checknumber(L, 2);
  if (amt_n < 0 || amt_n > 9.2233720368547e18) {
    lua_pushnil(L);
    lua_pushstring(L, "amount out of range");
    return 2;
  }
  uint64_t amount = static_cast<uint64_t>(amt_n);

  std::vector<uint8_t> args;
  args.reserve(sizeof(uint64_t) + 1 + addr_len);
  put_u64(args, amount);
  args.push_back(static_cast<uint8_t>(addr_len));
  put_bytes(args, addr, addr_len);

  return io_call(L, METHOD_REQUEST_FUNDS, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) {
    lua_pushnil(L);
    lua_pushinteger(L, st);
    return 2;
  }
  if (reply.body.size() < sizeof(uint8_t) + sizeof(uint64_t))
    return push_file_err(L, STATUS_INTERNAL);
  uint64_t granted = get_u64(reply.body.data() + 1);
  lua_pushnumber(L, static_cast<lua_Number>(granted));
  return 1;
  });
}

// ces.authentic_asset_create(asset_id, recipient_pubkey, payload, days)
//   → true | nil, err_code
//
// Mints an IMMUTABLE asset whose first 32 bytes are this program's
// identity hash sha256(source_bytes || source_path), looked up from
// the source file's sidecar. The remaining 178 bytes hold the
// caller-supplied payload (zero-padded if shorter). The asset's
// owner is `recipient_pubkey`. Asset rent is paid by the program's
// owner account (whoever owns the source file).
//
// Args:
//   asset_id          : string(32)  - 32-byte asset key
//   recipient_pubkey  : string(32)  - 32-byte ed25519/secp pubkey of new owner
//   payload           : string(<=178) - opaque user bytes
//   days              : integer (1..8191)
int lua_ces_authentic_asset_create(lua_State* L) {
  size_t aid_len = 0;
  const char* aid = luaL_checklstring(L, 1, &aid_len);
  if (aid_len != 32) {
    lua_pushnil(L);
    lua_pushstring(L, "asset_id must be 32 bytes");
    return 2;
  }
  size_t rcpt_len = 0;
  const char* rcpt = luaL_checklstring(L, 2, &rcpt_len);
  if (rcpt_len != 32) {
    lua_pushnil(L);
    lua_pushstring(L, "recipient_pubkey must be 32 bytes");
    return 2;
  }
  size_t pl_len = 0;
  const char* pl = luaL_checklstring(L, 3, &pl_len);
  if (pl_len > 178) {
    lua_pushnil(L);
    lua_pushstring(L, "payload exceeds 178 bytes");
    return 2;
  }
  lua_Integer days_i = luaL_checkinteger(L, 4);
  if (days_i < 1 || days_i > 8191) {
    lua_pushnil(L);
    lua_pushstring(L, "days must be in [1, 8191]");
    return 2;
  }

  std::vector<uint8_t> args;
  args.reserve(WIRE_KEY_LEN + WIRE_KEY_LEN + sizeof(uint16_t) + pl_len);
  put_bytes(args, aid, 32);
  put_bytes(args, rcpt, 32);
  put_u16(args, static_cast<uint16_t>(days_i));
  if (pl_len > 0)
    put_bytes(args, pl, pl_len);

  return io_call(L, METHOD_AUTHENTIC_ASSET_CREATE, args,
    [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) {
    lua_pushnil(L);
    lua_pushinteger(L, st);
    return 2;
  }
  lua_pushboolean(L, 1);
  return 1;
  });
}

// ces.random_bytes(n:integer) → string(n) | nil, err
//
// Crypto-grade randomness from the host's CryptoPP AutoSeededRandomPool.
// Bounded to n ∈ [1, 256] per call; programs needing more should call
// repeatedly. Used by dice for the coin flip.
int lua_ces_random_bytes(lua_State* L) {
  lua_Integer n = luaL_checkinteger(L, 1);
  if (n < 1 || n > 256) {
    lua_pushnil(L);
    lua_pushstring(L, "n must be in [1, 256]");
    return 2;
  }
  std::vector<uint8_t> args;
  put_u16(args, static_cast<uint16_t>(n));
  return io_call(L, METHOD_RANDOM_BYTES, args,
    [n](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) return push_file_err(L, st);
  if (reply.body.size() < sizeof(uint8_t) + size_t(n))
    return push_file_err(L, STATUS_INTERNAL);
  lua_pushlstring(L,
    reinterpret_cast<const char*>(reply.body.data() + 1),
    static_cast<size_t>(n));
  return 1;
  });
}

// ces.account_read(pubkey:string(32))
//   → table {balance, nonce, last_xfer_dest, last_xfer_amount,
//            last_xfer_time} | nil, err_code
//
// Read-only account query. Mirrors the wire's
// CES_UNSIGNED_QUERY_ACCOUNT verb — no fee, no nonce. Account fields
// for a missing account come back as zeros (an honest "no state").
// Used by dice to verify a player's most recent transfer is the bet.
int lua_ces_account_read(lua_State* L) {
  size_t pk_len = 0;
  const char* pk = luaL_checklstring(L, 1, &pk_len);
  if (pk_len != 32) {
    lua_pushnil(L);
    lua_pushstring(L, "pubkey must be 32 bytes");
    return 2;
  }
  std::vector<uint8_t> args;
  put_bytes(args, pk, 32);
  return io_call(L, METHOD_ACCOUNT_READ, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) return push_file_err(L, st);
  // Tail: [i64 BE balance][u32 BE nonce][8B last_xfer_dest]
  //       [u64 BE last_xfer_amount][u32 BE last_xfer_time]
  constexpr size_t TAIL = sizeof(uint64_t) + sizeof(uint32_t)
                          + WIRE_PREFIX_LEN + sizeof(uint64_t)
                          + sizeof(uint32_t);
  if (reply.body.size() < sizeof(uint8_t) + TAIL)
    return push_file_err(L, STATUS_INTERNAL);
  const uint8_t* p = reply.body.data() + 1;
  uint64_t balU = get_u64(p); p += 8;
  uint32_t nonce = get_u32(p); p += 4;
  const uint8_t* lastDest = p; p += 8;
  uint64_t lastAmt = get_u64(p); p += 8;
  uint32_t lastTime = get_u32(p); p += 4;

  // Reinterpret bal as signed via union-cast for payment-account
  // negative balances. Lua numbers are doubles, so we project to
  // double; payment-account magnitudes are well within precision.
  int64_t balS;
  std::memcpy(&balS, &balU, sizeof(int64_t));

  lua_newtable(L);
  lua_pushnumber(L, static_cast<lua_Number>(balS));
  lua_setfield(L, -2, "balance");
  lua_pushnumber(L, static_cast<lua_Number>(nonce));
  lua_setfield(L, -2, "nonce");
  lua_pushlstring(L, reinterpret_cast<const char*>(lastDest), 8);
  lua_setfield(L, -2, "last_xfer_dest");
  lua_pushnumber(L, static_cast<lua_Number>(lastAmt));
  lua_setfield(L, -2, "last_xfer_amount");
  lua_pushnumber(L, static_cast<lua_Number>(lastTime));
  lua_setfield(L, -2, "last_xfer_time");
  return 1;
  });
}

// ces.peers() → array of {pubkey(32), address, reachable, verified,
//   outbound, inbound}. The local server's peer table snapshot (the same
//   data the public CES_QUERY_PEER_INFO opcode exposes). This is the P2P
//   overlay's bootstrap topology: a Lua node discovers its server's peers,
//   then dials their instances over /ces/luarpc/1.
int lua_ces_peers(lua_State* L) {
  std::vector<uint8_t> args;  // no arguments
  return io_call(L, METHOD_PEERS, args, [](lua_State* L, const Frame& reply) -> int {
  if (reply.body.empty() || reply.body[0] != STATUS_OK)
    return push_file_err(L, reply.body.empty() ? STATUS_INTERNAL : reply.body[0]);
  const uint8_t* p = reply.body.data() + 1;
  const uint8_t* end = reply.body.data() + reply.body.size();
  if (p + 2 > end) return push_file_err(L, STATUS_INTERNAL);
  uint16_t count = get_u16(p); p += 2;
  lua_newtable(L);
  for (uint16_t i = 0; i < count; ++i) {
    if (p + 32 + 2 > end) break;
    const uint8_t* ckey = p; p += 32;
    uint16_t alen = get_u16(p); p += 2;
    if (p + size_t(alen) + 1 + 2 + 16 > end) break;  // addr,flags,rpc,powIn,powOut
    const char* addr = reinterpret_cast<const char*>(p); p += alen;
    uint8_t flags = *p; p += 1;
    uint16_t rpcPort = get_u16(p); p += 2;
    uint64_t powIn = get_u64(p); p += 8;
    uint64_t powOut = get_u64(p); p += 8;
    lua_newtable(L);
    lua_pushlstring(L, reinterpret_cast<const char*>(ckey), 32);
    lua_setfield(L, -2, "pubkey");
    lua_pushlstring(L, addr, alen);
    lua_setfield(L, -2, "address");
    lua_pushboolean(L, (flags & 0x01) ? 1 : 0); lua_setfield(L, -2, "reachable");
    lua_pushboolean(L, (flags & 0x02) ? 1 : 0); lua_setfield(L, -2, "verified");
    lua_pushboolean(L, (flags & 0x04) ? 1 : 0); lua_setfield(L, -2, "outbound");
    lua_pushboolean(L, (flags & 0x08) ? 1 : 0); lua_setfield(L, -2, "inbound");
    lua_pushnumber(L, static_cast<lua_Number>(rpcPort));
    lua_setfield(L, -2, "rpc_port");
    lua_pushnumber(L, static_cast<lua_Number>(powIn));
    lua_setfield(L, -2, "inbound_pow");
    lua_pushnumber(L, static_cast<lua_Number>(powOut));
    lua_setfield(L, -2, "outbound_pow");
    lua_rawseti(L, -2, i + 1);
  }
  return 1;
  });
}

// Peering control (privileged: registered only for /s/ programs, and the
// supervisor enforces the same gate). These let an operator-deployed extension
// run the node's peering policy from Lua -- e.g. an autopeering agent that
// learns the network from gossip and decides who to befriend.

// ces.add_peer(pubkey(32), address) -> true | nil,err. Establish an outbound
// peering; the peer miner then probes it (and mines a reserve if the target>0).
int lua_ces_add_peer(lua_State* L) {
  size_t pk_len = 0;
  const char* pk = luaL_checklstring(L, 1, &pk_len);
  if (pk_len != 32) {
    lua_pushnil(L); lua_pushstring(L, "peer pubkey must be 32 bytes"); return 2;
  }
  size_t addr_len = 0;
  const char* addr = luaL_checklstring(L, 2, &addr_len);
  if (addr_len == 0 || addr_len > 256) {
    lua_pushnil(L); lua_pushstring(L, "address must be 1..256 bytes"); return 2;
  }
  std::vector<uint8_t> args;
  put_bytes(args, pk, 32);
  put_bytes(args, addr, addr_len);
  return io_call(L, METHOD_PEER_ADD, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body.empty() ? STATUS_INTERNAL : reply.body[0];
  if (st != STATUS_OK) { lua_pushnil(L); lua_pushinteger(L, st); return 2; }
  lua_pushboolean(L, 1);
  return 1;
  });
}

// ces.remove_peer(pubkey(32)) -> removed(bool) | nil,err.
int lua_ces_remove_peer(lua_State* L) {
  size_t pk_len = 0;
  const char* pk = luaL_checklstring(L, 1, &pk_len);
  if (pk_len != 32) {
    lua_pushnil(L); lua_pushstring(L, "peer pubkey must be 32 bytes"); return 2;
  }
  std::vector<uint8_t> args;
  put_bytes(args, pk, 32);
  return io_call(L, METHOD_PEER_REMOVE, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body.empty() ? STATUS_INTERNAL : reply.body[0];
  if (st != STATUS_OK) { lua_pushnil(L); lua_pushinteger(L, st); return 2; }
  lua_pushboolean(L, reply.body.size() >= 2 && reply.body[1] != 0);
  return 1;
  });
}

// ces.grief_peer(pubkey(32) [, amount]) -> true | nil,err. Raise a peer's grief in
// the C++ peer table by `amount` (default 1 = confidence in the offense); the C++
// side bans the peer once grief crosses the threshold and decays it otherwise.
int lua_ces_grief_peer(lua_State* L) {
  size_t pk_len = 0;
  const char* pk = luaL_checklstring(L, 1, &pk_len);
  if (pk_len != 32) {
    lua_pushnil(L); lua_pushstring(L, "peer pubkey must be 32 bytes"); return 2;
  }
  lua_Integer amt = luaL_optinteger(L, 2, 1);
  if (amt < 1) amt = 1;
  if (amt > 0xFFFFFFFF) amt = 0xFFFFFFFF;
  std::vector<uint8_t> args;
  put_bytes(args, pk, 32);
  put_u32(args, static_cast<uint32_t>(amt));
  return io_call(L, METHOD_PEER_GRIEF, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body.empty() ? STATUS_INTERNAL : reply.body[0];
  if (st != STATUS_OK) { lua_pushnil(L); lua_pushinteger(L, st); return 2; }
  lua_pushboolean(L, 1);
  return 1;
  });
}

// ces.ban_peer(pubkey(32)) -> true | nil,err. Ban a peer immediately on conclusive
// evidence (bypasses the accumulating grief counter), e.g. a params hash an honest
// peer cannot produce. For uncertain evidence use ces.grief_peer instead.
int lua_ces_ban_peer(lua_State* L) {
  size_t pk_len = 0;
  const char* pk = luaL_checklstring(L, 1, &pk_len);
  if (pk_len != 32) {
    lua_pushnil(L); lua_pushstring(L, "peer pubkey must be 32 bytes"); return 2;
  }
  std::vector<uint8_t> args;
  put_bytes(args, pk, 32);
  return io_call(L, METHOD_PEER_BAN, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body.empty() ? STATUS_INTERNAL : reply.body[0];
  if (st != STATUS_OK) { lua_pushnil(L); lua_pushinteger(L, st); return 2; }
  lua_pushboolean(L, 1);
  return 1;
  });
}

// ces.serverSign(bytes) -> sig(65) | nil,err. Sign `bytes` with the SERVER key for a
// privileged /s/ extension. The server private key never enters the sandbox: the host
// (CES core) applies the reserved domain tag, hashes SHA256(tag || bytes), signs, and
// returns only the signature. Denied (nil) for a non-/s/ program. Pairs with
// ces.serverVerify. Used by formation to make a relayed attestation attributable to
// the member's server identity.
int lua_ces_server_sign(lua_State* L) {
  size_t n = 0;
  const char* s = luaL_checklstring(L, 1, &n);
  std::vector<uint8_t> args;
  put_bytes(args, s, n);
  return io_call(L, METHOD_SERVER_SIGN, args, [](lua_State* L, const Frame& reply) -> int {
    uint8_t st = reply.body.empty() ? STATUS_INTERNAL : reply.body[0];
    if (st != STATUS_OK) { lua_pushnil(L); lua_pushinteger(L, st); return 2; }
    if (reply.body.size() != 1 + ces::SIG_SIZE) {
      lua_pushnil(L); lua_pushstring(L, "internal"); return 2;
    }
    lua_pushlstring(L, reinterpret_cast<const char*>(reply.body.data() + 1),
                    ces::SIG_SIZE);
    return 1;
  });
}

// ces.set_peer_target(units) -> true | nil,err. The reserve the peer miner
// aims to accumulate on each peer, in raw internal units (PRICE_UNIT = 1 full
// credit = 100000000 units; the value is stored unscaled). 0 = never mine,
// just keep peers fresh.
int lua_ces_set_peer_target(lua_State* L) {
  lua_Number n = luaL_checknumber(L, 1);
  if (n < 0 || n > 9.2233720368547e18) {
    lua_pushnil(L); lua_pushstring(L, "target out of range"); return 2;
  }
  std::vector<uint8_t> args;
  put_u64(args, static_cast<uint64_t>(n));
  return io_call(L, METHOD_PEER_TARGET_SET, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body.empty() ? STATUS_INTERNAL : reply.body[0];
  if (st != STATUS_OK) { lua_pushnil(L); lua_pushinteger(L, st); return 2; }
  lua_pushboolean(L, 1);
  return 1;
  });
}

// ces.peer_target() -> units(number) | nil,err. Raw internal units (see
// ces.set_peer_target; PRICE_UNIT = 100000000 units per full credit).
int lua_ces_peer_target(lua_State* L) {
  std::vector<uint8_t> args;  // no arguments
  return io_call(L, METHOD_PEER_TARGET_GET, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body.empty() ? STATUS_INTERNAL : reply.body[0];
  if (st != STATUS_OK) { lua_pushnil(L); lua_pushinteger(L, st); return 2; }
  if (reply.body.size() < 1 + sizeof(uint64_t))
    return push_file_err(L, STATUS_INTERNAL);
  uint64_t target = get_u64(reply.body.data() + 1);
  lua_pushnumber(L, static_cast<lua_Number>(target));
  return 1;
  });
}

