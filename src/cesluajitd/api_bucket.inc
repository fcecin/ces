// ---------------------------------------------------------------------------
// ces.bucket_* - per-instance rotating cache (TTL-bounded forgetting).
//
// Backed by minx::BucketCache on the host. Two rotating buckets with
// auto-flip at ttl_secs: an entry is guaranteed present for at least
// ttl_secs and at most 2x ttl_secs before being aged out. Capacity is
// enforced by REFUSAL, not eviction: when the active bucket is full,
// put returns false instead of clearing entries, so the ttl_secs
// retention floor holds regardless of load. Programs that need
// replay-protection state (dice.lua's per-deposit marker, etc.) use
// this so they don't have to keep "all deposits for all eternity."
//
// Surface:
//   local b = ces.bucket_new(ttl_secs, max_entries, max_entry_bytes)
//   local ok = b:put(key, value) -- true if stored; false if bucket full
//   local v = b:get(key)         -- string, or nil if missing
//
// `key` and `value` are arbitrary bytes (Lua's lstring carries length).
// Each instance can create multiple buckets; they all die together
// when the instance is killed.
// ---------------------------------------------------------------------------

// Internal: pull `id` (u32 bucket handle) from a bucket-self table.
static uint32_t bucket_self_id(lua_State* L, int idx) {
  lua_getfield(L, idx, "id");
  uint32_t id = static_cast<uint32_t>(lua_tonumber(L, -1));
  lua_pop(L, 1);
  return id;
}

int lua_ces_bucket_put(lua_State* L) {
  luaL_checktype(L, 1, LUA_TTABLE);
  uint32_t id = bucket_self_id(L, 1);
  size_t klen = 0, vlen = 0;
  const char* k = luaL_checklstring(L, 2, &klen);
  const char* v = luaL_checklstring(L, 3, &vlen);
  if (klen > 65535) {
    lua_pushnil(L);
    lua_pushstring(L, "key too long");
    return 2;
  }
  std::vector<uint8_t> args;
  put_u32(args, id);
  put_u16(args, static_cast<uint16_t>(klen));
  put_bytes(args, k, klen);
  put_u32(args, static_cast<uint32_t>(vlen));
  put_bytes(args, v, vlen);
  return io_call(L, METHOD_BUCKET_PUT, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st == STATUS_BUCKET_FULL) { lua_pushboolean(L, 0); return 1; }
  if (st != STATUS_OK) return push_file_err(L, st);
  lua_pushboolean(L, 1);
  return 1;
  });
}

int lua_ces_bucket_get(lua_State* L) {
  luaL_checktype(L, 1, LUA_TTABLE);
  uint32_t id = bucket_self_id(L, 1);
  size_t klen = 0;
  const char* k = luaL_checklstring(L, 2, &klen);
  if (klen > 65535) {
    lua_pushnil(L);
    lua_pushstring(L, "key too long");
    return 2;
  }
  std::vector<uint8_t> args;
  put_u32(args, id);
  put_u16(args, static_cast<uint16_t>(klen));
  put_bytes(args, k, klen);
  return io_call(L, METHOD_BUCKET_GET, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) return push_file_err(L, st);
  // Tail: [u8 found_flag][u32 BE vlen][v]
  if (reply.body.size() < 2) return push_file_err(L, STATUS_INTERNAL);
  uint8_t found = reply.body[1];
  if (!found) {
    lua_pushnil(L);
    return 1;
  }
  if (reply.body.size() < sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint32_t))
    return push_file_err(L, STATUS_INTERNAL);
  uint32_t vlen = get_u32(reply.body.data() + 2);
  if (reply.body.size() < sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint32_t)
                            + vlen)
    return push_file_err(L, STATUS_INTERNAL);
  lua_pushlstring(L,
    reinterpret_cast<const char*>(reply.body.data() + 6), vlen);
  return 1;
  });
}

// ces.bucket_new(ttl_secs, max_entries, max_entry_bytes)
//   → bucket | nil, err
//
// Pre-declares the bucket's worst-case footprint
// (max_entries × max_entry_bytes), which the host bills against on
// every supervisor tick — see feeBucketByteSec in CesConfig. Per-put
// klen+vlen is capped at max_entry_bytes; oversize values reject.
//
// Reasonable defaults for replay-protection caches:
//   ces.bucket_new(7200, 100000, 64)
// = 2 hours TTL, up to 100k entries, 64 bytes per entry.
int lua_ces_bucket_new(lua_State* L) {
  lua_Integer ttl     = luaL_checkinteger(L, 1);
  lua_Integer maxE    = luaL_checkinteger(L, 2);
  lua_Integer maxB    = luaL_checkinteger(L, 3);
  if (ttl < 1 || ttl > 86400 * 30) {
    lua_pushnil(L);
    lua_pushstring(L, "ttl_secs must be in [1, 30 days]");
    return 2;
  }
  if (maxE < 1 || maxE > 1000000) {
    lua_pushnil(L);
    lua_pushstring(L, "max_entries must be in [1, 1M]");
    return 2;
  }
  if (maxB < 1 || maxB > 65536) {
    lua_pushnil(L);
    lua_pushstring(L, "max_entry_bytes must be in [1, 64K]");
    return 2;
  }
  std::vector<uint8_t> args;
  put_u32(args, static_cast<uint32_t>(ttl));
  put_u32(args, static_cast<uint32_t>(maxE));
  put_u32(args, static_cast<uint32_t>(maxB));
  return io_call(L, METHOD_BUCKET_NEW, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) return push_file_err(L, st);
  if (reply.body.size() < sizeof(uint8_t) + sizeof(uint32_t))
    return push_file_err(L, STATUS_INTERNAL);
  uint32_t id = get_u32(reply.body.data() + 1);
  // Build the bucket-self Lua table.
  lua_newtable(L);
  lua_pushnumber(L, static_cast<lua_Number>(id));
  lua_setfield(L, -2, "id");
  lua_pushcfunction(L, guarded<lua_ces_bucket_put>);
  lua_setfield(L, -2, "put");
  lua_pushcfunction(L, guarded<lua_ces_bucket_get>);
  lua_setfield(L, -2, "get");
  return 1;
  });
}

// ces.file_stat(name) → table | nil, err_code
int lua_ces_file_stat(lua_State* L) {
  size_t nlen = 0;
  const char* name = luaL_checklstring(L, 1, &nlen);
  std::vector<uint8_t> args;
  put_name(args, name, nlen);
  return io_call(L, METHOD_FILE_STAT, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) return push_file_err(L, st);
  // Tail: [32B owner][u64 fb][u64 ppk][u64 size]
  //       [u64 createdUs][u64 modifiedUs]
  const uint8_t* p = reply.body.data() + 1;
  size_t rem = reply.body.size() - 1;
  if (rem < WIRE_KEY_LEN + sizeof(uint64_t) * 5)
    return push_file_err(L, STATUS_INTERNAL);
  const uint8_t* owner = p; p += 32;
  uint64_t fb = get_u64(p); p += 8;
  uint64_t ppk = get_u64(p); p += 8;
  uint64_t sz = get_u64(p); p += 8;
  uint64_t crUs = get_u64(p); p += 8;
  uint64_t mdUs = get_u64(p); p += 8;
  lua_newtable(L);
  lua_pushlstring(L, reinterpret_cast<const char*>(owner), 32);
  lua_setfield(L, -2, "owner_pubkey");
  lua_pushnumber(L, double(fb));   lua_setfield(L, -2, "file_balance");
  lua_pushnumber(L, double(ppk));  lua_setfield(L, -2, "price_per_kb");
  lua_pushnumber(L, double(sz));   lua_setfield(L, -2, "size");
  lua_pushnumber(L, double(crUs)); lua_setfield(L, -2, "created_us");
  lua_pushnumber(L, double(mdUs)); lua_setfield(L, -2, "modified_us");
  return 1;
  });
}

// ces.file_read(name, offset, length) → data | nil, err_code
int lua_ces_file_read(lua_State* L) {
  size_t nlen = 0;
  const char* name = luaL_checklstring(L, 1, &nlen);
  lua_Number off_n = luaL_checknumber(L, 2);
  lua_Number len_n = luaL_checknumber(L, 3);
  if (off_n < 0 || len_n <= 0 || len_n > (1024 * 1024)) {
    lua_pushnil(L); lua_pushstring(L, "bad args"); return 2;
  }
  std::vector<uint8_t> args;
  put_u64(args, uint64_t(off_n));
  put_u32(args, uint32_t(len_n));
  put_name(args, name, nlen);
  return io_call(L, METHOD_FILE_READ, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) return push_file_err(L, st);
  constexpr size_t kHdr = sizeof(uint8_t) + sizeof(uint32_t);  // status + len
  if (reply.body.size() < kHdr) return push_file_err(L, STATUS_INTERNAL);
  uint32_t dlen = get_u32(reply.body.data() + sizeof(uint8_t));
  if (reply.body.size() < kHdr + size_t(dlen))
    return push_file_err(L, STATUS_INTERNAL);
  lua_pushlstring(L, reinterpret_cast<const char*>(reply.body.data() + kHdr),
                  dlen);
  return 1;
  });
}

// ces.file_write(name, offset, data) → true, file_balance | nil, err_code
int lua_ces_file_write(lua_State* L) {
  size_t nlen = 0, dlen = 0;
  const char* name = luaL_checklstring(L, 1, &nlen);
  lua_Number off_n = luaL_checknumber(L, 2);
  const char* data = luaL_checklstring(L, 3, &dlen);
  if (off_n < 0 || dlen == 0 || dlen > (1024 * 1024)) {
    lua_pushnil(L); lua_pushstring(L, "bad args"); return 2;
  }
  std::vector<uint8_t> args;
  put_u64(args, uint64_t(off_n));
  put_name(args, name, nlen);
  put_u32(args, uint32_t(dlen));
  put_bytes(args, data, dlen);
  return io_call(L, METHOD_FILE_WRITE, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) return push_file_err(L, st);
  if (reply.body.size() < 9) return push_file_err(L, STATUS_INTERNAL);
  uint64_t fb = get_u64(reply.body.data() + 1);
  lua_pushboolean(L, 1);
  lua_pushnumber(L, double(fb));
  return 2;
  });
}

// ces.file_append(name, data) → true, file_balance, new_size | nil, err_code
int lua_ces_file_append(lua_State* L) {
  size_t nlen = 0, dlen = 0;
  const char* name = luaL_checklstring(L, 1, &nlen);
  const char* data = luaL_checklstring(L, 2, &dlen);
  if (dlen == 0 || dlen > (1024 * 1024)) {
    lua_pushnil(L); lua_pushstring(L, "bad args"); return 2;
  }
  std::vector<uint8_t> args;
  put_name(args, name, nlen);
  put_u32(args, uint32_t(dlen));
  put_bytes(args, data, dlen);
  return io_call(L, METHOD_FILE_APPEND, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) return push_file_err(L, st);
  if (reply.body.size() < 17) return push_file_err(L, STATUS_INTERNAL);
  uint64_t fb = get_u64(reply.body.data() + 1);
  uint64_t ns = get_u64(reply.body.data() + 9);
  lua_pushboolean(L, 1);
  lua_pushnumber(L, double(fb));
  lua_pushnumber(L, double(ns));
  return 3;
  });
}

// ces.file_create(name, size, price_per_kb, initial_deposit)
//   → true, file_balance | nil, err_code
int lua_ces_file_create(lua_State* L) {
  size_t nlen = 0;
  const char* name = luaL_checklstring(L, 1, &nlen);
  lua_Number sz_n = luaL_checknumber(L, 2);
  lua_Number ppk_n = luaL_optnumber(L, 3, 0);
  lua_Number dep_n = luaL_optnumber(L, 4, 0);
  if (sz_n <= 0 || ppk_n < 0 || dep_n < 0) {
    lua_pushnil(L); lua_pushstring(L, "bad args"); return 2;
  }
  std::vector<uint8_t> args;
  put_u64(args, uint64_t(sz_n));
  put_u64(args, uint64_t(ppk_n));
  put_u64(args, uint64_t(dep_n));
  put_name(args, name, nlen);
  return io_call(L, METHOD_FILE_CREATE, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) return push_file_err(L, st);
  if (reply.body.size() < 9) return push_file_err(L, STATUS_INTERNAL);
  uint64_t fb = get_u64(reply.body.data() + 1);
  lua_pushboolean(L, 1);
  lua_pushnumber(L, double(fb));
  return 2;
  });
}

// ces.file_deposit(name, amount) → true, file_balance | nil, err_code
int lua_ces_file_deposit(lua_State* L) {
  size_t nlen = 0;
  const char* name = luaL_checklstring(L, 1, &nlen);
  lua_Number amt_n = luaL_checknumber(L, 2);
  if (amt_n < 0) { lua_pushnil(L); lua_pushstring(L, "bad args"); return 2; }
  std::vector<uint8_t> args;
  put_u64(args, uint64_t(amt_n));
  put_name(args, name, nlen);
  return io_call(L, METHOD_FILE_DEPOSIT, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) return push_file_err(L, st);
  if (reply.body.size() < 9) return push_file_err(L, STATUS_INTERNAL);
  uint64_t fb = get_u64(reply.body.data() + 1);
  lua_pushboolean(L, 1);
  lua_pushnumber(L, double(fb));
  return 2;
  });
}

// ces.file_withdraw(name, amount) → true, file_balance | nil, err_code
int lua_ces_file_withdraw(lua_State* L) {
  size_t nlen = 0;
  const char* name = luaL_checklstring(L, 1, &nlen);
  lua_Number amt_n = luaL_checknumber(L, 2);
  if (amt_n < 0) { lua_pushnil(L); lua_pushstring(L, "bad args"); return 2; }
  std::vector<uint8_t> args;
  put_u64(args, uint64_t(amt_n));
  put_name(args, name, nlen);
  return io_call(L, METHOD_FILE_WITHDRAW, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) return push_file_err(L, st);
  if (reply.body.size() < 9) return push_file_err(L, STATUS_INTERNAL);
  uint64_t fb = get_u64(reply.body.data() + 1);
  lua_pushboolean(L, 1);
  lua_pushnumber(L, double(fb));
  return 2;
  });
}

// ces.file_set_price(name, price_per_kb) → true, new_price | nil, err_code
int lua_ces_file_set_price(lua_State* L) {
  size_t nlen = 0;
  const char* name = luaL_checklstring(L, 1, &nlen);
  lua_Number ppk_n = luaL_checknumber(L, 2);
  if (ppk_n < 0) { lua_pushnil(L); lua_pushstring(L, "bad args"); return 2; }
  std::vector<uint8_t> args;
  put_u64(args, uint64_t(ppk_n));
  put_name(args, name, nlen);
  return io_call(L, METHOD_FILE_SET_PRICE, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) return push_file_err(L, st);
  if (reply.body.size() < 9) return push_file_err(L, STATUS_INTERNAL);
  uint64_t p = get_u64(reply.body.data() + 1);
  lua_pushboolean(L, 1);
  lua_pushnumber(L, double(p));
  return 2;
  });
}

// ces.file_delete(name) → true, refunded | nil, err_code
int lua_ces_file_delete(lua_State* L) {
  size_t nlen = 0;
  const char* name = luaL_checklstring(L, 1, &nlen);
  std::vector<uint8_t> args;
  put_name(args, name, nlen);
  return io_call(L, METHOD_FILE_DELETE, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) return push_file_err(L, st);
  if (reply.body.size() < 9) return push_file_err(L, STATUS_INTERNAL);
  uint64_t r = get_u64(reply.body.data() + 1);
  lua_pushboolean(L, 1);
  lua_pushnumber(L, double(r));
  return 2;
  });
}

// ces.file_resize(name, new_size) → true, file_balance, new_size | nil, err_code
int lua_ces_file_resize(lua_State* L) {
  size_t nlen = 0;
  const char* name = luaL_checklstring(L, 1, &nlen);
  lua_Number sz_n = luaL_checknumber(L, 2);
  if (sz_n <= 0) { lua_pushnil(L); lua_pushstring(L, "bad args"); return 2; }
  std::vector<uint8_t> args;
  put_u64(args, uint64_t(sz_n));
  put_name(args, name, nlen);
  return io_call(L, METHOD_FILE_RESIZE, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) return push_file_err(L, st);
  if (reply.body.size() < 17) return push_file_err(L, STATUS_INTERNAL);
  uint64_t fb = get_u64(reply.body.data() + 1);
  uint64_t ns = get_u64(reply.body.data() + 9);
  lua_pushboolean(L, 1);
  lua_pushnumber(L, double(fb));
  lua_pushnumber(L, double(ns));
  return 3;
  });
}

