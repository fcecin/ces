// ---------------------------------------------------------------------------
// ces.file_* — file-storage bindings. Each call routes through the
// host's fileHandlerExec, which enforces full owner semantics 1:1
// with `cesh file`. No feeQuery charged (no network signed-op).
// ---------------------------------------------------------------------------

// BE serialization helpers — local to cesluajitd by design.
//
// The rest of the CES codebase uses `ces::Buffer::put<T>` / `peek<T>`
// (see include/ces/buffer.h) which delegates to logkv::serializer.
// cesluajitd is deliberately minimal — no ceslib, no boost link
// dependency, no MINX/logkv include paths plumbed through CMake — so
// it carries its own byte-shifting. Same wire shape as the canonical
// helpers; just self-contained for the small binary.
void put_u16(std::vector<uint8_t>& o, uint16_t v) {
  o.push_back(uint8_t((v >> 8) & 0xFF));
  o.push_back(uint8_t( v       & 0xFF));
}
void put_u32(std::vector<uint8_t>& o, uint32_t v) {
  o.push_back(uint8_t((v >> 24) & 0xFF));
  o.push_back(uint8_t((v >> 16) & 0xFF));
  o.push_back(uint8_t((v >>  8) & 0xFF));
  o.push_back(uint8_t( v        & 0xFF));
}
void put_u64(std::vector<uint8_t>& o, uint64_t v) {
  for (int i = 7; i >= 0; --i)
    o.push_back(uint8_t((v >> (i * 8)) & 0xFF));
}
void put_bytes(std::vector<uint8_t>& o, const void* p, size_t n) {
  const uint8_t* b = static_cast<const uint8_t*>(p);
  o.insert(o.end(), b, b + n);
}
// Append [u16 BE name_len][name] to buffer. Caller ensures name
// length fits u16.
void put_name(std::vector<uint8_t>& o, const char* name, size_t nlen) {
  put_u16(o, static_cast<uint16_t>(nlen));
  put_bytes(o, name, nlen);
}

uint16_t get_u16(const uint8_t* p) {
  return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
}
uint32_t get_u32(const uint8_t* p) {
  return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16)
       | (uint32_t(p[2]) <<  8) |  uint32_t(p[3]);
}
uint64_t get_u64(const uint8_t* p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
  return v;
}

// Build + send a TAG_API_CALL; returns its corr_id, or 0 on write failure.
// corr_id 0 is reserved for one-way frames, so the counter skips it on wrap.
uint16_t send_api_call(uint16_t method, const std::vector<uint8_t>& args) {
  std::vector<uint8_t> body;
  body.reserve(sizeof(uint16_t) + args.size());
  put_u16(body, method);
  body.insert(body.end(), args.begin(), args.end());
  uint16_t corr;
  do { corr = g_next_corr_id++; } while (corr == 0);
  if (!write_frame(TAG_API_CALL, corr, body.data(), body.size())) return 0;
  return corr;
}

// On API error, pushes (nil, err_code). On IPC failure, (nil,
// "ipc_failure"). Caller returns the number this returns.
int push_file_err(lua_State* L, int status) {
  lua_pushnil(L);
  lua_pushinteger(L, status);
  return 2;
}
int push_ipc_fail(lua_State* L) {
  lua_pushnil(L);
  lua_pushstring(L, "ipc_failure");
  return 2;
}

// True if the current call can suspend. Only a coroutine yields; the main
// thread (the main chunk, and any handler dispatched on it) cannot. Same guard
// ces.sleep uses.
bool io_yieldable(lua_State* L) {
  int isMain = lua_pushthread(L);
  lua_pop(L, 1);
  return isMain == 0;
}

// The host round-trip shared by every ces.* verb below. From a coroutine it
// parks (no thread blocked) and resumes when the reply lands; from the main
// thread it blocks in wait_for_reply -- the correct degenerate case, since
// nothing else is running there. `decode` turns the reply body into the call's
// Lua return values and runs either here (blocking path) or in the run loop at
// resume (yield path), never spanning the yield. A reply with an empty body is
// an IPC failure, handled here so decoders only ever see a real body.
int io_call(lua_State* L, uint16_t method,
            const std::vector<uint8_t>& args, IoDecoder decode) {
  uint16_t corr = send_api_call(method, args);
  if (corr == 0) return push_ipc_fail(L);
  if (io_yieldable(L)) {
    g_io_waiters[corr] = IoWaiter{L, std::move(decode)};
    g_parked.insert(L);
    return lua_yield(L, 0);
  }
  Frame reply;
  if (!wait_for_reply(corr, reply) || reply.body.empty()) return push_ipc_fail(L);
  return decode(L, reply);
}

// ces.transfer(target_pubkey:string(32), amount:number)
//   → true, new_origin_balance | nil, err_code
//
// Sends `amount` credits from the program's owner account to the
// target. /s/ programs run with owner = server (auto-topped to
// near-INT64_MAX every boot), so dice / payouts / etc. just work.
// Programs in /h/ or /f/ pull from their owner's account exactly the
// same way file ops do — i.e. the program acts under the owner's
// authority.
int lua_ces_transfer(lua_State* L) {
  size_t pk_len = 0;
  const char* pk = luaL_checklstring(L, 1, &pk_len);
  if (pk_len != 32) {
    lua_pushnil(L);
    lua_pushstring(L, "target pubkey must be 32 bytes");
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
  args.reserve(WIRE_KEY_LEN + sizeof(uint64_t));
  put_bytes(args, pk, 32);
  put_u64(args, amount);

  return io_call(L, METHOD_TRANSFER, args, [](lua_State* L, const Frame& reply) -> int {
  uint8_t st = reply.body[0];
  if (st != STATUS_OK) {
    lua_pushnil(L);
    lua_pushinteger(L, st);
    return 2;
  }
  // Tail: [u64 BE new_origin_balance]
  if (reply.body.size() < sizeof(uint8_t) + sizeof(uint64_t))
    return push_file_err(L, STATUS_INTERNAL);
  uint64_t newBal = get_u64(reply.body.data() + 1);
  lua_pushboolean(L, 1);
  lua_pushnumber(L, static_cast<lua_Number>(newBal));
  return 2;
  });
}

// Minx config for a single outbound round-trip from this compute instance.
// CesClient's default is server-sized: a Minx with DEFAULT_RECV_BUFFERS_SIZE
// (16384) x 2KB recv buffers = ~32MB allocated up front. Constructing that per
// call inside a child capped by RLIMIT_AS throws std::bad_alloc. A client doing
// one blocking request needs only a small recv ring and none of the server's
// PoW/spam machinery, so size it for what it is.
minx::MinxConfig luaClientConfig() {
  minx::MinxConfig c{"luacl"};
  c.recvBuffersSize    = 256;   // one round-trip, not a server's inbound backlog
  c.spamSampleRate     = 0;     // a client does not spam-score its own replies
  c.randomXVMsToKeep   = 0;     // ping/query/transfer never verify PoW
  c.randomXInitThreads = 0;
  c.trustLoopback      = true;
  return c;
}

