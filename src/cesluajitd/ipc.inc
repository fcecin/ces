// ---------------------------------------------------------------------------
// IPC frame I/O over the host's Unix socket.
// ---------------------------------------------------------------------------

constexpr uint8_t  TAG_BOOTSTRAP   = 0x00;
constexpr uint8_t  TAG_DELIVER     = 0x01;
constexpr uint8_t  TAG_API_CALL    = 0x02;
constexpr uint8_t  TAG_API_REPLY   = 0x03;
// /ces/lua/1 connection routing tags. Mirror compute_handler.cpp.
constexpr uint8_t  TAG_CONN_OPENED   = 0x04;  // server → child
constexpr uint8_t  TAG_CONN_DATA_IN  = 0x05;  // server → child
constexpr uint8_t  TAG_CONN_CLOSED   = 0x06;  // server → child
constexpr uint8_t  TAG_CONN_DATA_OUT = 0x07;  // child → server
constexpr uint8_t  TAG_CONN_CLOSE    = 0x08;  // child → server
constexpr uint8_t  TAG_LISTEN_ON     = 0x09;  // child → server
constexpr uint8_t  TAG_LISTEN_OFF    = 0x0a;  // child → server
constexpr uint8_t  TAG_LOG           = 0x0b;  // child → server (ces.log, one-way)
constexpr uint8_t  TAG_HOST_LOG      = 0x0c;  // child → server (host C++, one-way)
constexpr uint8_t  TAG_NET_USAGE     = 0x15;  // child -> server (channel usage, one-way)

// Extension contract (ces.extension_admin{}). REGISTER/REP/DISABLE_SELF flow child →
// server; REQ/CONFIG flow server → child. EXT_REQ carries a corr_id the child
// echoes in EXT_REP so the server can match the reply.
constexpr uint8_t  TAG_EXT_REGISTER     = 0x0d;  // child → server
constexpr uint8_t  TAG_EXT_REQ          = 0x0e;  // server → child (status/command)
constexpr uint8_t  TAG_EXT_REP          = 0x0f;  // child → server (reply)
constexpr uint8_t  TAG_EXT_CONFIG       = 0x10;  // server → child (on_config, one-way)
constexpr uint8_t  TAG_EXT_DISABLE_SELF = 0x11;  // child → server
constexpr uint8_t  TAG_EXT_MANIFEST     = 0x12;  // child → server (ces.manifest, one-way)

constexpr uint8_t  TAG_GOSSIP_IN        = 0x13;  // server → child (a flooded message)
constexpr uint8_t  TAG_GOSSIP_OUT       = 0x14;  // child → server (ces.gossip.send)

// Peer-mesh messaging (must match compute_handler kIpcTagPeer*). Targeted,
// free, service-tagged messages over /ces/peer/1 between same-named extensions.
constexpr uint8_t  TAG_PEER_MSG_IN      = 0x16;  // server → child (mesh message)
constexpr uint8_t  TAG_PEER_MSG_OUT     = 0x17;  // child → server (ces.peer.send)
constexpr uint8_t  TAG_PEER_LISTEN      = 0x18;  // child → server (ces.peer.listen)

constexpr uint8_t  EXT_REQ_STATUS  = 0x00;
constexpr uint8_t  EXT_REQ_COMMAND = 0x01;

constexpr uint8_t  EXT_CAP_STATUS          = 0x01;
constexpr uint8_t  EXT_CAP_COMMANDS        = 0x02;
constexpr uint8_t  EXT_CAP_CONFIG_DEFAULTS = 0x04;
constexpr uint8_t  EXT_CAP_ON_CONFIG       = 0x08;

constexpr uint16_t METHOD_CLIENT_SEND      = 0x0001;
constexpr uint16_t METHOD_FILE_CREATE      = 0x0100;
constexpr uint16_t METHOD_FILE_WRITE       = 0x0101;
constexpr uint16_t METHOD_FILE_READ        = 0x0102;
constexpr uint16_t METHOD_FILE_STAT        = 0x0103;
constexpr uint16_t METHOD_FILE_DEPOSIT     = 0x0104;
constexpr uint16_t METHOD_FILE_WITHDRAW    = 0x0105;
constexpr uint16_t METHOD_FILE_SET_PRICE   = 0x0106;
constexpr uint16_t METHOD_FILE_DELETE      = 0x0107;
constexpr uint16_t METHOD_FILE_APPEND      = 0x0108;
constexpr uint16_t METHOD_FILE_RESIZE      = 0x0109;
constexpr uint16_t METHOD_KV_CREATE        = 0x010a;
constexpr uint16_t METHOD_KV_PUT           = 0x010b;
constexpr uint16_t METHOD_KV_GET           = 0x010c;
constexpr uint16_t METHOD_KV_ERASE         = 0x010d;
constexpr uint16_t METHOD_KV_ITER          = 0x010e;
constexpr uint16_t METHOD_KV_DEPOSIT       = 0x010f;
constexpr uint16_t METHOD_KV_RANGE         = 0x0110;
constexpr uint16_t METHOD_TRANSFER         = 0x0200;
constexpr uint16_t METHOD_CROSS_TRANSFER   = 0x0201;
constexpr uint16_t METHOD_RANDOM_BYTES     = 0x0202;
constexpr uint16_t METHOD_ACCOUNT_READ     = 0x0203;
constexpr uint16_t METHOD_BUCKET_NEW       = 0x0210;
constexpr uint16_t METHOD_BUCKET_PUT       = 0x0211;
constexpr uint16_t METHOD_BUCKET_GET       = 0x0212;
constexpr uint16_t METHOD_AUTHENTIC_ASSET_CREATE = 0x0220;
constexpr uint16_t METHOD_PEERS            = 0x0230;
constexpr uint16_t METHOD_PEER_ADD         = 0x0231;
constexpr uint16_t METHOD_PEER_REMOVE      = 0x0232;
constexpr uint16_t METHOD_PEER_TARGET_SET  = 0x0233;
constexpr uint16_t METHOD_PEER_TARGET_GET  = 0x0234;
constexpr uint16_t METHOD_REQUEST_FUNDS    = 0x0235;
constexpr uint16_t METHOD_PEER_GRIEF       = 0x0236;
constexpr uint16_t METHOD_PEER_BAN         = 0x0237;
constexpr uint16_t METHOD_SERVER_SIGN      = 0x0238;

constexpr uint8_t STATUS_OK               = 0x00;
constexpr uint8_t STATUS_NOT_CONNECTED    = 0x01;
constexpr uint8_t STATUS_INSUFFICIENT_BAL = 0x02;
constexpr uint8_t STATUS_BUCKET_FULL      = 0x04;
constexpr uint8_t STATUS_INTERNAL         = 0xFF;

// Byte widths of fixed wire fields shared with the host. This TU has no
// ces includes, so these mirror ces::KEY_SIZE / the sha256 digest / the
// 8-byte HashPrefix by value.
constexpr size_t WIRE_KEY_LEN    = 32;   // pubkey / sha256 / asset id
constexpr size_t WIRE_PREFIX_LEN = 8;    // account / program hash prefix

struct Frame {
  uint8_t  tag;
  uint16_t corr_id;
  std::vector<uint8_t> body;
};

int g_sock_fd = -1;              // host IPC socket
std::deque<Frame> g_inbox;       // pending DELIVER frames
std::deque<Frame> g_reply_q;     // pending API_REPLY frames
std::deque<Frame> g_conn_q;      // pending CONN_* frames (drained by run())
std::deque<Frame> g_gossip_q;    // pending GOSSIP_IN frames (drained by run())
std::deque<Frame> g_peer_q;      // pending PEER_MSG_IN frames (drained by run())

// Cooperative I/O scheduler state (single-threaded: only the IPC thread that
// runs run()/the main chunk touches these). A coroutine that calls a host
// round-trip from inside the event loop parks here instead of spinning in
// wait_for_reply: the verb sends its TAG_API_CALL, records itself by corr_id,
// and yields; the run loop resumes it when the matching TAG_API_REPLY lands.
// Main-chunk / non-coroutine callers cannot yield and keep blocking.
using IoDecoder = std::function<int(lua_State*, const Frame&)>;
struct IoWaiter { lua_State* co; IoDecoder decode; };
std::set<lua_State*>         g_parked;      // coroutines suspended on a host call
std::map<uint16_t, IoWaiter> g_io_waiters;  // corr_id -> parked coroutine + decoder
std::deque<Frame>            g_io_ready;     // arrived replies for parked coroutines

// Per-conn handler dispatch. Each inbound conn event (relay CONN_* frame or
// direct /ces/luarpc/1 event) runs its listener callback (on_open/on_data/
// on_close) in its OWN coroutine so the callback can make blocking-looking host
// calls that transparently yield -- identically on both transports, as the
// unified ces.conn API promises. Ordering within a conn is preserved: at most
// ONE handler coroutine is live per conn; while it is parked, later events for
// that conn wait in `pending` and run in arrival order. Different conns
// interleave freely. The relay and direct id spaces are separate, so each
// transport keeps its own exec/advance state (isLuarpc tells resume_coro which).
struct ConnExec { std::deque<Frame> pending; bool busy = false; };
struct HandlerCo { uint64_t id; bool isClose; bool isLuarpc; };
std::map<uint64_t, ConnExec>    g_conn_exec;     // relay conn id -> serialized state
std::map<lua_State*, HandlerCo> g_handler_co;    // handler coroutine -> its conn
std::deque<uint64_t>            g_conn_advance;   // relay conns with an event ready
std::map<lua_State*, int>       g_coro_refs;     // coroutine -> registry ref (keeps it alive)
static void resume_coro(lua_State* mainL, lua_State* co, int nargs);
static void conn_advance(lua_State* mainL, uint64_t id);
static void luarpc_advance(lua_State* mainL, uint64_t id);
static void drain_luarpc_advance(lua_State* mainL);
static void drain_connect_done(lua_State* mainL);
static void drain_offload_done(lua_State* mainL);
void remove_luarpc_conn(lua_State* L, uint64_t id);
void put_u16(std::vector<uint8_t>& o, uint16_t v);
int io_call(lua_State* L, uint16_t method,
            const std::vector<uint8_t>& args, IoDecoder decode);

// Blocking read of exactly n bytes from g_sock_fd. Returns true on
// success, false on EOF/error.
bool read_exact(void* out, size_t n) {
  uint8_t* p = static_cast<uint8_t*>(out);
  while (n > 0) {
    ssize_t r = ::read(g_sock_fd, p, n);
    if (r == 0) return false;
    if (r < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    p += r;
    n -= static_cast<size_t>(r);
  }
  return true;
}

bool write_exact(const void* in, size_t n) {
  const uint8_t* p = static_cast<const uint8_t*>(in);
  while (n > 0) {
    ssize_t w = ::write(g_sock_fd, p, n);
    if (w < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    p += w;
    n -= static_cast<size_t>(w);
  }
  return true;
}

// Read the next raw frame from the socket. Returns true on
// success; `out` contains tag + corr_id + body.
bool read_frame(Frame& out) {
  uint8_t lenbe[4];
  if (!read_exact(lenbe, 4)) return false;
  uint32_t len = (uint32_t(lenbe[0]) << 24) | (uint32_t(lenbe[1]) << 16)
               | (uint32_t(lenbe[2]) << 8)  |  uint32_t(lenbe[3]);
  if (len < 3) return false; // must at least have tag + corr_id
  if (len > (64u * 1024u * 1024u)) return false; // sanity cap
  std::vector<uint8_t> hdrbody(len);
  if (!read_exact(hdrbody.data(), len)) return false;
  out.tag = hdrbody[0];
  out.corr_id = (uint16_t(hdrbody[1]) << 8) | uint16_t(hdrbody[2]);
  out.body.assign(hdrbody.begin() + 3, hdrbody.end());
  return true;
}

bool write_frame(uint8_t tag, uint16_t corr_id,
                 const uint8_t* body, size_t body_len) {
  uint32_t len = static_cast<uint32_t>(
      sizeof(uint8_t) + sizeof(uint16_t) + body_len);   // tag + corr + body
  uint8_t hdr[7];
  hdr[0] = uint8_t((len >> 24) & 0xFF);
  hdr[1] = uint8_t((len >> 16) & 0xFF);
  hdr[2] = uint8_t((len >>  8) & 0xFF);
  hdr[3] = uint8_t((len      ) & 0xFF);
  hdr[4] = tag;
  hdr[5] = uint8_t((corr_id >> 8) & 0xFF);
  hdr[6] = uint8_t( corr_id       & 0xFF);
  if (!write_exact(hdr, 7)) return false;
  if (body_len > 0 && !write_exact(body, body_len)) return false;
  return true;
}

// Structured log line from the C++ host side of this instance (not the Lua
// program). Rides the same one-way IPC the Lua ces.log uses, but on its own tag
// so the server attributes it to the host, not the program. level: 0 trace,
// 1 debug, 2 info, 3 warning, 4 error. Call only from the run-loop thread (where
// every ces.* C function runs), matching ces.log's threading.
void host_log(uint8_t level, const std::string& msg) {
  std::vector<uint8_t> body;
  body.reserve(1 + msg.size());
  body.push_back(level);
  body.insert(body.end(), msg.begin(), msg.end());
  write_frame(TAG_HOST_LOG, 0, body.data(), body.size());
}

// Safe-stringify the Lua error value on top of `s`'s stack, for host_log.
std::string lua_err_str(lua_State* s) {
  const char* m = lua_tostring(s, -1);
  return m ? std::string(m) : std::string("(non-string error)");
}

// Exception firewall wrapped around EVERY native function exposed to Lua. A
// std::exception thrown inside a native -- std::bad_alloc under the child's
// RLIMIT_AS, a CryptoPP/Boost.System throw, a length_error from a bad size --
// must never unwind into LuaJIT as a foreign "C++ exception": uncaught above a
// pcall it can take down the run-loop thread. Catch it here and re-raise as an
// ordinary Lua error the program's pcall can handle, logging it host-side.
//
// Only std::exception is caught, deliberately: LuaJIT's OWN error propagation
// (luaL_error/lua_error, e.g. from a luaL_check* arg failure inside the wrapped
// function) is a foreign exception class, not std::exception, so it passes
// straight through this handler untouched -- preserving real Lua error messages.
// A blanket catch(...) here would swallow that and break Lua error handling.
template <lua_CFunction Fn>
int guarded(lua_State* L) {
  try {
    return Fn(L);
  } catch (const std::exception& e) {
    // host_log allocates; never let a failure there mask the original fault.
    try { host_log(4, std::string("uncaught native exception: ") + e.what()); }
    catch (...) {}
    return luaL_error(L, "internal error");
  }
}

// Try to read one frame without blocking. Returns 1 on success,
// 0 if no frame available right now, -1 on socket error/EOF.
int try_read_frame_nonblocking(Frame& out) {
  pollfd pfd{};
  pfd.fd = g_sock_fd;
  pfd.events = POLLIN;
  int pr = ::poll(&pfd, 1, 0);
  if (pr < 0) {
    if (errno == EINTR) return 0;
    return -1;
  }
  if (pr == 0) return 0;
  if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) return -1;
  return read_frame(out) ? 1 : -1;
}

// Stash a frame into the queue that matches its tag. CONN_* frames
// arriving while the program is blocked on an API call go to g_conn_q;
// ces.conn.run() drains it before reading new frames so the listener
// callbacks never silently miss a connection event.
void route_to_queue(Frame f) {
  if (f.tag == TAG_DELIVER) g_inbox.push_back(std::move(f));
  else if (f.tag == TAG_API_REPLY) {
    if (g_io_waiters.find(f.corr_id) != g_io_waiters.end())
      g_io_ready.push_back(std::move(f));   // a parked coroutine awaits this reply
    else
      g_reply_q.push_back(std::move(f));    // a blocking wait_for_reply (or stale)
  }
  else if (f.tag == TAG_CONN_OPENED || f.tag == TAG_CONN_DATA_IN ||
           f.tag == TAG_CONN_CLOSED) g_conn_q.push_back(std::move(f));
  else if (f.tag == TAG_GOSSIP_IN) g_gossip_q.push_back(std::move(f));
  else if (f.tag == TAG_PEER_MSG_IN) g_peer_q.push_back(std::move(f));
  // Ignore other tags (BOOTSTRAP is only at startup).
}

// Absorb any currently-available frames into the per-tag queues.
// Returns false on fatal socket error (caller should exit).
bool drain_socket_nonblocking() {
  for (;;) {
    Frame f;
    int r = try_read_frame_nonblocking(f);
    if (r == 0) return true;
    if (r < 0) return false;
    route_to_queue(std::move(f));
  }
}

// Blocking wait for the next API reply with the given corr_id.
// Stashes other-tag frames in their per-tag queues so the rest of the
// runtime (ces.client_recv, ces.conn.run) can drain them later.
// Returns false on socket error.
bool wait_for_reply(uint16_t corr_id, Frame& out) {
  // Check already-queued replies first.
  for (auto it = g_reply_q.begin(); it != g_reply_q.end(); ++it) {
    if (it->corr_id == corr_id) {
      out = std::move(*it);
      g_reply_q.erase(it);
      return true;
    }
  }
  for (;;) {
    Frame f;
    if (!read_frame(f)) return false;
    if (f.tag == TAG_API_REPLY && f.corr_id == corr_id) {
      out = std::move(f);
      return true;
    }
    route_to_queue(std::move(f));
  }
}

