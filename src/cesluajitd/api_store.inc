// ---------------------------------------------------------------------------
// ces.store: persistent key-value store (a logkv-backed kv-file).
// ---------------------------------------------------------------------------
//
// ces.store(path) returns a handle bound to a kv-file path; its methods
// (:create / :put / :get / :erase / :keys / :deposit) ride the same in-process
// file path as ces.file_*, with kv verbs. Each key is a self-renting cell: a
// deposit funds the key's rent balance, the daily rent sweep charges and evicts
// it at balance 0, and a read returns only the stored bytes. The handle holds
// no host-side state, so a fresh handle for the same path sees the same data.

// Pull the bound path out of the handle table at stack slot 1 (the `self` in
// db:method(...)). Returns false (handle left on stack cleaned) on a bad table.
bool store_path_arg(lua_State* L, std::string& out) {
  if (lua_type(L, 1) != LUA_TTABLE) return false;
  lua_getfield(L, 1, "path");
  size_t n = 0;
  const char* p = lua_tolstring(L, -1, &n);
  if (!p || n == 0) { lua_pop(L, 1); return false; }
  out.assign(p, n);
  lua_pop(L, 1);
  return true;
}

// db:create(initial_deposit [, price_per_kb]) → true, file_balance | nil, err
int lua_ces_store_create(lua_State* L) {
  std::string path;
  if (!store_path_arg(L, path)) {
    lua_pushnil(L); lua_pushstring(L, "bad store handle"); return 2;
  }
  lua_Number dep_n = luaL_optnumber(L, 2, 0);
  lua_Number ppk_n = luaL_optnumber(L, 3, 0);
  if (dep_n < 0 || ppk_n < 0) {
    lua_pushnil(L); lua_pushstring(L, "bad args"); return 2;
  }
  std::vector<uint8_t> args;
  put_u64(args, uint64_t(ppk_n));
  put_u64(args, uint64_t(dep_n));
  put_name(args, path.data(), path.size());
  return io_call(L, METHOD_KV_CREATE, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) return push_file_err(L, st);
  if (reply.body.size() < 9) return push_file_err(L, STATUS_INTERNAL);
  uint64_t fb = get_u64(reply.body.data() + 1);
  lua_pushboolean(L, 1);
  lua_pushnumber(L, double(fb));
  return 2;
  });
}

// db:put(key, value [, deposit]) → true, cell_balance, new_size | nil, err
//   `deposit` seeds/tops the key's rent balance (credits keeping it alive). A
//   key with balance 0 is evicted on the next daily rent sweep, so a record you
//   want to persist must be funded (here or via db:deposit).
int lua_ces_store_put(lua_State* L) {
  std::string path;
  if (!store_path_arg(L, path)) {
    lua_pushnil(L); lua_pushstring(L, "bad store handle"); return 2;
  }
  size_t klen = 0, vlen = 0;
  const char* key = luaL_checklstring(L, 2, &klen);
  const char* val = luaL_checklstring(L, 3, &vlen);
  lua_Number dep_n = luaL_optnumber(L, 4, 0);
  if (klen == 0 || klen > 256 || vlen == 0 || vlen > (1024 * 1024) || dep_n < 0) {
    lua_pushnil(L); lua_pushstring(L, "bad args"); return 2;
  }
  std::vector<uint8_t> args;
  put_u64(args, uint64_t(dep_n));            // [u64 deposit]
  put_name(args, key, klen);                 // [u16 keylen][key]
  put_u32(args, uint32_t(vlen));             // [u32 vallen][value]
  put_bytes(args, val, vlen);
  put_name(args, path.data(), path.size());  // [u16 namelen][name]
  return io_call(L, METHOD_KV_PUT, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) return push_file_err(L, st);
  if (reply.body.size() < 17) return push_file_err(L, STATUS_INTERNAL);
  uint64_t fb = get_u64(reply.body.data() + 1);
  uint64_t sz = get_u64(reply.body.data() + 9);
  lua_pushboolean(L, 1);
  lua_pushnumber(L, double(fb));
  lua_pushnumber(L, double(sz));
  return 3;
  });
}

// db:get(key) → value | nil [, err]
//   Missing key returns a single nil (no error). A real error returns
//   (nil, err_code), so a caller distinguishes the two by the 2nd value.
int lua_ces_store_get(lua_State* L) {
  std::string path;
  if (!store_path_arg(L, path)) {
    lua_pushnil(L); lua_pushstring(L, "bad store handle"); return 2;
  }
  size_t klen = 0;
  const char* key = luaL_checklstring(L, 2, &klen);
  if (klen == 0 || klen > 256) {
    lua_pushnil(L); lua_pushstring(L, "bad args"); return 2;
  }
  std::vector<uint8_t> args;
  put_name(args, key, klen);
  put_name(args, path.data(), path.size());
  return io_call(L, METHOD_KV_GET, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) return push_file_err(L, st);
  // Tail: [u8 found][u32 vallen][value]
  if (reply.body.size() < 1 + 1 + sizeof(uint32_t))
    return push_file_err(L, STATUS_INTERNAL);
  uint8_t found = reply.body[1];
  if (!found) { lua_pushnil(L); return 1; }
  uint32_t vlen = get_u32(reply.body.data() + 2);
  if (reply.body.size() < 6 + size_t(vlen))
    return push_file_err(L, STATUS_INTERNAL);
  lua_pushlstring(L, reinterpret_cast<const char*>(reply.body.data() + 6), vlen);
  return 1;
  });
}

// db:erase(key) → true | nil, err   (erasing a missing key still returns true)
int lua_ces_store_erase(lua_State* L) {
  std::string path;
  if (!store_path_arg(L, path)) {
    lua_pushnil(L); lua_pushstring(L, "bad store handle"); return 2;
  }
  size_t klen = 0;
  const char* key = luaL_checklstring(L, 2, &klen);
  if (klen == 0 || klen > 256) {
    lua_pushnil(L); lua_pushstring(L, "bad args"); return 2;
  }
  std::vector<uint8_t> args;
  put_name(args, key, klen);
  put_name(args, path.data(), path.size());
  return io_call(L, METHOD_KV_ERASE, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) return push_file_err(L, st);
  lua_pushboolean(L, 1);
  return 1;
  });
}

// db:keys() → { key, key, ... } | nil, err
//   The array of every key currently stored. (Values are fetched per-key with
//   :get — the iterate op carries keys only, which is what set reconciliation
//   needs.)
int lua_ces_store_keys(lua_State* L) {
  std::string path;
  if (!store_path_arg(L, path)) {
    lua_pushnil(L); lua_pushstring(L, "bad store handle"); return 2;
  }
  std::vector<uint8_t> args;
  put_name(args, path.data(), path.size());
  return io_call(L, METHOD_KV_ITER, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) return push_file_err(L, st);
  if (reply.body.size() < 1 + sizeof(uint32_t))
    return push_file_err(L, STATUS_INTERNAL);
  uint32_t cnt = get_u32(reply.body.data() + 1);
  const uint8_t* p   = reply.body.data() + 5;
  const uint8_t* end = reply.body.data() + reply.body.size();
  lua_newtable(L);
  for (uint32_t i = 0; i < cnt; ++i) {
    if (p + 2 > end) return push_file_err(L, STATUS_INTERNAL);
    uint16_t kl = get_u16(p); p += 2;
    if (p + kl > end) return push_file_err(L, STATUS_INTERNAL);
    lua_pushlstring(L, reinterpret_cast<const char*>(p), kl); p += kl;
    lua_rawseti(L, -2, int(i) + 1);
  }
  return 1;
  });
}

// db:range(lo, hi [, max_bytes]) → entries, effective_hi | nil, err
//   Ordered scan of [lo, hi): entries is an array of { key=, value= } sorted
//   ascending by key. lo/hi may be "" for start/end of store. If effective_hi
//   == hi the whole range was delivered; otherwise effective_hi is the next
//   undelivered key and the caller continues with db:range(effective_hi, hi).
//   Bounded by max_bytes (clamped server-side); always returns at least one
//   in-range entry so a scan cannot stall.
int lua_ces_store_range(lua_State* L) {
  std::string path;
  if (!store_path_arg(L, path)) {
    lua_pushnil(L); lua_pushstring(L, "bad store handle"); return 2;
  }
  size_t lolen = 0, hilen = 0;
  const char* lo = luaL_optlstring(L, 2, "", &lolen);
  const char* hi = luaL_optlstring(L, 3, "", &hilen);
  lua_Number max_n = luaL_optnumber(L, 4, 0);
  if (lolen > 256 || hilen > 256 || max_n < 0) {
    lua_pushnil(L); lua_pushstring(L, "bad args"); return 2;
  }
  std::vector<uint8_t> args;
  put_u16(args, static_cast<uint16_t>(lolen)); put_bytes(args, lo, lolen);
  put_u16(args, static_cast<uint16_t>(hilen)); put_bytes(args, hi, hilen);
  put_u64(args, uint64_t(max_n));
  put_name(args, path.data(), path.size());
  return io_call(L, METHOD_KV_RANGE, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) return push_file_err(L, st);
  const uint8_t* p   = reply.body.data() + 1;
  const uint8_t* end = reply.body.data() + reply.body.size();
  // [u16 endLen][end][u32 count]( [u16 klen][key][u32 vlen][value] )*
  if (p + 2 > end) return push_file_err(L, STATUS_INTERNAL);
  uint16_t endLen = get_u16(p); p += 2;
  if (p + endLen > end) return push_file_err(L, STATUS_INTERNAL);
  const uint8_t* effHi = p; p += endLen;
  if (p + 4 > end) return push_file_err(L, STATUS_INTERNAL);
  uint32_t cnt = get_u32(p); p += 4;
  lua_newtable(L);                              // entries
  for (uint32_t i = 0; i < cnt; ++i) {
    if (p + 2 > end) return push_file_err(L, STATUS_INTERNAL);
    uint16_t kl = get_u16(p); p += 2;
    if (p + kl + 4 > end) return push_file_err(L, STATUS_INTERNAL);
    const uint8_t* k = p; p += kl;
    uint32_t vl = get_u32(p); p += 4;
    if (p + vl > end) return push_file_err(L, STATUS_INTERNAL);
    const uint8_t* v = p; p += vl;
    lua_newtable(L);
    lua_pushlstring(L, reinterpret_cast<const char*>(k), kl); lua_setfield(L, -2, "key");
    lua_pushlstring(L, reinterpret_cast<const char*>(v), vl); lua_setfield(L, -2, "value");
    lua_rawseti(L, -2, int(i) + 1);
  }
  lua_pushlstring(L, reinterpret_cast<const char*>(effHi), endLen);  // effective_hi
  return 2;
  });
}

// db:deposit(key, amount) → cell_balance | nil, err
//   Add `amount` to an existing key's rent balance: the funding that keeps the
//   record alive against the rent sweep. Any caller may fund any key.
int lua_ces_store_deposit(lua_State* L) {
  std::string path;
  if (!store_path_arg(L, path)) {
    lua_pushnil(L); lua_pushstring(L, "bad store handle"); return 2;
  }
  size_t klen = 0;
  const char* key = luaL_checklstring(L, 2, &klen);
  lua_Number amt_n = luaL_checknumber(L, 3);
  if (klen == 0 || klen > 256 || amt_n <= 0) {
    lua_pushnil(L); lua_pushstring(L, "bad args"); return 2;
  }
  std::vector<uint8_t> args;
  put_u64(args, uint64_t(amt_n));            // [u64 amount]
  put_name(args, key, klen);                 // [u16 keylen][key]
  put_name(args, path.data(), path.size());  // [u16 namelen][name]
  return io_call(L, METHOD_KV_DEPOSIT, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) return push_file_err(L, st);
  if (reply.body.size() < 9) return push_file_err(L, STATUS_INTERNAL);
  uint64_t bal = get_u64(reply.body.data() + 1);
  lua_pushnumber(L, double(bal));
  return 1;
  });
}

// ces.store(path) → handle { path, create, put, get, erase, keys, range, deposit }
int lua_ces_store(lua_State* L) {
  size_t plen = 0;
  const char* path = luaL_checklstring(L, 1, &plen);
  if (plen == 0 || plen > 1024) {
    lua_pushnil(L); lua_pushstring(L, "bad path"); return 2;
  }
  lua_newtable(L);
  lua_pushlstring(L, path, plen);                       lua_setfield(L, -2, "path");
  lua_pushcfunction(L, guarded<lua_ces_store_create>);  lua_setfield(L, -2, "create");
  lua_pushcfunction(L, guarded<lua_ces_store_put>);     lua_setfield(L, -2, "put");
  lua_pushcfunction(L, guarded<lua_ces_store_get>);     lua_setfield(L, -2, "get");
  lua_pushcfunction(L, guarded<lua_ces_store_erase>);   lua_setfield(L, -2, "erase");
  lua_pushcfunction(L, guarded<lua_ces_store_keys>);    lua_setfield(L, -2, "keys");
  lua_pushcfunction(L, guarded<lua_ces_store_range>);   lua_setfield(L, -2, "range");
  lua_pushcfunction(L, guarded<lua_ces_store_deposit>); lua_setfield(L, -2, "deposit");
  return 1;
}

