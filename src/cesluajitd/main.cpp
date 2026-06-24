// cesluajitd — LuaJIT-hosted compute child for /ces/compute/1.
//
// Replaces cescompmockd as the default compute runtime. One
// process per running program instance; the program's Lua source
// arrives in the IPC bootstrap frame from the host. The child
// enters a Lua event loop that can react to inbound client
// messages (ces.client_recv) and push replies back
// (ces.client_send).
//
// The child is deliberately minimal:
//   * No filesystem API. No os, io, debug, package, require,
//     loadfile, dofile, load, loadstring, ffi (no runtime code/bytecode
//     loading — bytecode is unverified in LuaJIT and an escape vector).
//   * Outbound CesClient (ces.remote_account_read / ces.remote_transfer)
//     reaches other CES servers; no inbound network beyond client↔program
//     messaging.
//   * Lua stays in memory, with RLIMIT_AS as a hard ceiling.
//
// Invocation: cesluajitd <ipc_socket_path> [drop_to_user]
//
// When drop_to_user is given and the process is running as root,
// it drops privileges before any Lua code runs.
//
// IPC wire format (both directions):
//
//   [u32 BE length][u8 tag][u16 BE corr_id][body]
//
// where `length` covers everything after itself.
//
// Tags:
//   0x00  H→C  Bootstrap    body = Lua source bytes
//   0x01  H→C  Deliver      body = [8B sender_pfx][payload bytes]
//   0x02  C→H  API call     body = [u16 BE method_id][args...]
//   0x03  H→C  API reply    body = [u8 status][status-specific]
//
// Method IDs (C→H):
//   0x0001  CLIENT_SEND    args = [8B target_pfx][u16 BE len][bytes]
//
// API reply status:
//   0x00 ok
//   0x01 target client is not connected
//   0x02 insufficient balance (out of scope in v1; reserved)
//   0xFF internal / malformed
//
// The IPC channel is full-duplex Unix stream. The child runs a
// single-threaded Lua; within Lua, ces.* calls are synchronous
// (write request, drain frames until we see the matching reply).
// Inbound deliver frames that arrive while we're waiting for a
// reply are buffered into the in-process inbox for the next
// ces.client_recv.

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <deque>
#include <limits>
#include <map>
#include <functional>
#include <set>
#include <thread>
#include <future>
#include <memory>
#include <mutex>
#include <random>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <string>
#include <sys/resource.h>
#include <malloc.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

extern "C" {
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <luajit.h>
}

#include <ces/account.h>
#include <ces/cesplex/endpoint.h>
#include <ces/cesplex/session.h>
#include <ces/client.h>
#include <ces/keys.h>
#include <ces/l2/compute_client.h>
#include <ces/l2/file_client.h>
#include <ces/protocol.h>
#include <ces/types.h>
#include <ces/util/resolver.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

// ---------------------------------------------------------------------------
// Minimal SHA-256 for ces.sha256. Self-contained, tiny, no crypto
// strength claim needed (Lua programs that want real integrity
// already have CES signatures on the wire).
//
// Based on the canonical public-domain reference implementation.
// ~120 lines. Kept here so cesluajitd has no dependency on ceslib
// (keeps its binary small and independently debuggable).
// ---------------------------------------------------------------------------

namespace {

struct Sha256Ctx {
  uint32_t h[8];
  uint64_t len_bits;
  uint8_t  buf[64];
  size_t   buflen;
};

constexpr uint32_t sha256_k[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

void sha256_init(Sha256Ctx& c) {
  c.h[0]=0x6a09e667; c.h[1]=0xbb67ae85; c.h[2]=0x3c6ef372; c.h[3]=0xa54ff53a;
  c.h[4]=0x510e527f; c.h[5]=0x9b05688c; c.h[6]=0x1f83d9ab; c.h[7]=0x5be0cd19;
  c.len_bits = 0;
  c.buflen = 0;
}

void sha256_compress(Sha256Ctx& c, const uint8_t* block) {
  uint32_t w[64];
  for (int i = 0; i < 16; ++i) {
    w[i] = (uint32_t(block[i*4]) << 24) | (uint32_t(block[i*4+1]) << 16)
         | (uint32_t(block[i*4+2]) << 8) | uint32_t(block[i*4+3]);
  }
  for (int i = 16; i < 64; ++i) {
    uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
    uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19)  ^ (w[i-2] >> 10);
    w[i] = w[i-16] + s0 + w[i-7] + s1;
  }
  uint32_t a=c.h[0],b=c.h[1],ch=c.h[2],d=c.h[3],e=c.h[4],f=c.h[5],g=c.h[6],hh=c.h[7];
  for (int i = 0; i < 64; ++i) {
    uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
    uint32_t Ch = (e & f) ^ (~e & g);
    uint32_t t1 = hh + S1 + Ch + sha256_k[i] + w[i];
    uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
    uint32_t Mj = (a & b) ^ (a & ch) ^ (b & ch);
    uint32_t t2 = S0 + Mj;
    hh=g; g=f; f=e; e=d+t1; d=ch; ch=b; b=a; a=t1+t2;
  }
  c.h[0]+=a; c.h[1]+=b; c.h[2]+=ch; c.h[3]+=d;
  c.h[4]+=e; c.h[5]+=f; c.h[6]+=g;  c.h[7]+=hh;
}

void sha256_update(Sha256Ctx& c, const uint8_t* data, size_t len) {
  c.len_bits += uint64_t(len) * 8;
  while (len > 0) {
    size_t take = std::min(size_t(64) - c.buflen, len);
    std::memcpy(c.buf + c.buflen, data, take);
    c.buflen += take;
    data += take;
    len -= take;
    if (c.buflen == 64) { sha256_compress(c, c.buf); c.buflen = 0; }
  }
}

void sha256_final(Sha256Ctx& c, uint8_t out[32]) {
  uint64_t total = c.len_bits;
  uint8_t pad = 0x80;
  sha256_update(c, &pad, 1);
  uint8_t zero = 0;
  while (c.buflen != 56) sha256_update(c, &zero, 1);
  uint8_t tail[8];
  for (int i = 0; i < 8; ++i)
    tail[i] = uint8_t((total >> ((7 - i) * 8)) & 0xFF);
  sha256_update(c, tail, 8);
  for (int i = 0; i < 8; ++i) {
    out[i*4+0] = uint8_t((c.h[i] >> 24) & 0xFF);
    out[i*4+1] = uint8_t((c.h[i] >> 16) & 0xFF);
    out[i*4+2] = uint8_t((c.h[i] >> 8) & 0xFF);
    out[i*4+3] = uint8_t(c.h[i] & 0xFF);
  }
}

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
constexpr uint8_t  TAG_NET_USAGE     = 0x0c;  // child -> server (one-way)

// Extension contract (ces.extension_admin{}). REGISTER/REP/DISABLE_SELF flow child →
// server; REQ/CONFIG flow server → child. EXT_REQ carries a corr_id the child
// echoes in EXT_REP so the server can match the reply.
constexpr uint8_t  TAG_EXT_REGISTER     = 0x0d;  // child → server
constexpr uint8_t  TAG_EXT_REQ          = 0x0e;  // server → child (status/command)
constexpr uint8_t  TAG_EXT_REP          = 0x0f;  // child → server (reply)
constexpr uint8_t  TAG_EXT_CONFIG       = 0x10;  // server → child (on_config, one-way)
constexpr uint8_t  TAG_EXT_DISABLE_SELF = 0x11;  // child → server
constexpr uint8_t  TAG_EXT_MANIFEST     = 0x12;  // child → server (ces.manifest, one-way)

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

// ---------------------------------------------------------------------------
// Startup: unix socket connect, uid drop, rlimits, Lua locking.
// ---------------------------------------------------------------------------

int connect_unix_socket(const char* path) {
  int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) { std::perror("cesluajitd: socket"); return -1; }
  sockaddr_un a{};
  a.sun_family = AF_UNIX;
  if (std::strlen(path) >= sizeof(a.sun_path)) {
    std::fprintf(stderr, "cesluajitd: socket path too long\n");
    ::close(fd);
    return -1;
  }
  std::strncpy(a.sun_path, path, sizeof(a.sun_path) - 1);
  if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) < 0) {
    std::perror("cesluajitd: connect");
    ::close(fd);
    return -1;
  }
  return fd;
}

// If running as root AND user_name is non-empty, drop to that
// account (gid first, then uid). Non-fatal if we're already not
// root; fatal if the drop is requested and any step fails.
bool drop_privileges_if_root(const char* user_name) {
  if (::geteuid() != 0) return true; // already non-root, nothing to do
  if (user_name == nullptr || user_name[0] == '\0') {
    host_log(4, "running as root with no drop-to-user configured; refusing");
    return false;
  }
  struct passwd* pw = ::getpwnam(user_name);
  if (!pw) {
    host_log(4, std::string("unknown drop-to-user '") + user_name + "'");
    return false;
  }
  if (::setgroups(0, nullptr) < 0) {
    host_log(4, std::string("setgroups: ") + std::strerror(errno));
    return false;
  }
  if (::setgid(pw->pw_gid) < 0) {
    host_log(4, std::string("setgid: ") + std::strerror(errno));
    return false;
  }
  if (::setuid(pw->pw_uid) < 0) {
    host_log(4, std::string("setuid: ") + std::strerror(errno));
    return false;
  }
  if (::geteuid() == 0 || ::getegid() == 0) {
    host_log(4, "privilege drop didn't stick");
    return false;
  }
  return true;
}

void apply_rlimits(size_t mem_max_bytes) {
  // Cap glibc's per-thread malloc arenas. Each new thread otherwise gets its
  // own 64 MB virtual arena, and the transient CesClient behind the outbound
  // networking APIs (ces.ping / ces.remote_*) spawns IO threads per call --
  // a few of those reserve enough address space to trip RLIMIT_AS and throw
  // std::bad_alloc. Two arenas is plenty for a mostly single-threaded VM and
  // keeps outbound networking inside the documented mem ceiling.
  mallopt(M_ARENA_MAX, 2);
  // Hard ceilings that cannot be raised from inside Lua. RLIMIT_AS is
  // the merciless memory cap (from the server's compute_process_mem_max):
  // the kernel denies any allocation past it, so a runaway or malicious
  // program can never OOM the host. No RLIMIT_CPU — CPU is billed via
  // file_balance depletion, not capped; throttling a paying process
  // would be pointless.
  rlimit r{};
  r.rlim_cur = r.rlim_max = mem_max_bytes;
  ::setrlimit(RLIMIT_AS, &r);
  // Descriptor ceiling: stdio, the host UDS, and the outbound CesClient's
  // socket plus asio internals (epoll / eventfd / timerfd). Bounded, but
  // above the original no-network ceiling.
  r.rlim_cur = r.rlim_max = 64;
  ::setrlimit(RLIMIT_NOFILE, &r);
}

// ---------------------------------------------------------------------------
// Sandbox: load ONLY the safe standard libraries (default-deny).
// ---------------------------------------------------------------------------
//
// Rather than open everything (luaL_openlibs) and remove the dangerous
// libraries afterward, open only the safe subset — base, string, table,
// math, bit — so os / io / debug / package / ffi / jit are never present
// at all, regardless of any removal list. None of the loaded libraries
// expose a filesystem, process, or memory-unsafe surface. A text program
// can only reach what's here plus the ces.* bindings; it cannot fabricate
// access to unbound C (no ffi, no pointers), and bytecode never reaches
// the VM (main()'s program loader is text-only).

void load_safe_libs(lua_State* L) {
  // Open ONLY the safe computation libraries. luaL_openlibs is never
  // called, so os, io, debug, package, ffi, and jit are never present in
  // the VM at all — there is no removal list to get wrong for those. What
  // remains is a pure computation surface: numbers, strings, tables, bit
  // ops, plus the ces.* host bindings installed separately.
  static const luaL_Reg kSafeLibs[] = {
    { "",       luaopen_base },   // also brings coroutine.* (in-VM, benign)
    { "table",  luaopen_table },
    { "string", luaopen_string },
    { "math",   luaopen_math },
    { "bit",    luaopen_bit },
    { nullptr,  nullptr }
  };
  for (const luaL_Reg* lib = kSafeLibs; lib->func; ++lib) {
    lua_pushcfunction(L, lib->func);
    lua_pushstring(L, lib->name);
    lua_call(L, 1, 0);
  }

  // The base library brings code loaders, environment reflection, GC
  // control, and print; remove all of them. After this there is no way
  // for program text to load code/bytecode, reach another stack frame's
  // environment, drive the collector, or write to stdout (which goes
  // nowhere for the daemon child anyway).
  static const char* const kRemoveGlobals[] = {
    "load", "loadstring", "dofile", "loadfile", // code / bytecode loaders
    "getfenv", "setfenv",                       // environment reflection
    "collectgarbage", "gcinfo",                 // GC control / mem info leak
    "newproxy",                                 // userdata fabrication
    "print",                                    // stdout goes nowhere here
    nullptr
  };
  for (int i = 0; kRemoveGlobals[i] != nullptr; ++i) {
    lua_pushnil(L);
    lua_setglobal(L, kRemoveGlobals[i]);
  }

  // string.dump serializes a function to BYTECODE. Nothing here can load
  // it back (the loaders are gone, and main()'s program loader is
  // text-only), but remove it anyway: the program surface deals in text,
  // never bytecode, in either direction.
  lua_getglobal(L, "string");
  if (lua_istable(L, -1)) {
    lua_pushnil(L);
    lua_setfield(L, -2, "dump");
  }
  lua_pop(L, 1);
}

// ---------------------------------------------------------------------------
// ces.* bindings
// ---------------------------------------------------------------------------

// Per-instance source program prefix, supplied by bootstrap env.
// Sent as part of outbound CES_APP_COMPUTE_MSG so the remote CES
// client can demux by prog_pfx.
uint8_t g_prog_prefix[8] = {0,0,0,0,0,0,0,0};
// Per-instance owner pubkey, supplied by bootstrap. Surfaced via
// ces.owner_pubkey() — programs use it (e.g. to know the house
// pubkey for /s/ programs running under the server's identity).
uint8_t g_owner_pubkey[32] = {0};
// Per-instance program-account pubkey, supplied by bootstrap. Surfaced
// via ces.program_pubkey() — the account ces.transfer spends from, which
// programs advertise as their receive address so deposits and payouts
// share one pool.
uint8_t g_program_pubkey[32] = {0};
uint8_t g_program_privkey[32] = {0};
// Per-instance birth wall-clock microseconds, supplied by bootstrap.
// Surfaced via ces.start_time(). Programs use it as a replay-
// protection anchor: any payment with lastXferTime ≤ start_time/1e6
// cannot have been a fresh deposit aimed at THIS instance.
uint64_t g_start_time_us = 0;
// UDP port the server statically assigned this instance for its
// outbound CES client, supplied by bootstrap. The client binds it so
// every outbound op leaves from a known, firewall-configured source
// port. 0 = no compute port range configured → this instance has no
// network: the outbound remote_* verbs fail with "networking disabled"
// rather than binding an unreachable ephemeral port.
uint16_t g_program_port = 0;
// The static UDP port reserved for this instance's inbound CesPlex host
// (/ces/luarpc/1). 0 = none → the instance hosts nothing.
uint16_t g_rpc_port = 0;
// Whether this instance runs privileged, decided once by the server (source in
// the /s/ zone) and delivered in the bootstrap. The host trusts this verdict;
// it never re-derives privilege. Gates operator-only API such as ces.log.
bool g_privileged = false;

// ---------------------------------------------------------------------------
// /ces/luarpc/1 — the protocol this lua host SERVES (and, later, dials) on
// its rpc port. A raw, opaque byte pipe: whatever bytes arrive are handed to
// the program; whatever bytes the program writes are sent. No host framing,
// batching, or buffering — any grammar lives in Lua.
//
// The endpoint runs on its own single strand; the Lua VM runs on main. The
// bridge below crosses that boundary: inbound (endpoint → Lua) via a
// mutex+condvar event queue drained by ces.conn.run(); outbound (Lua →
// endpoint) via asio::post onto the endpoint strand, where the per-conn
// RudpStreams live. Blocking here is fine — the compute child is sandboxed
// and metered, so a stalled strand has no global consequence.
//
// All per-conn stream state (g_luarpc_conns, g_luarpc_next_id) is touched
// ONLY on the endpoint strand: the handler runs there, and the Lua-side
// write/close hop there via post. So no lock guards them. Only the inbound
// event queue is cross-thread (mutex+condvar); the accept gate is atomic.
// ---------------------------------------------------------------------------
namespace {

struct LuaRpcEvent {
  enum class Type { Opened, Data, Closed } type;
  uint64_t connId = 0;
  std::array<uint8_t, 32> peer{};   // Opened
  std::string bytes;                // Data
};

std::mutex               g_luarpc_mx;
std::deque<LuaRpcEvent>  g_luarpc_inq;     // endpoint pushes, run() drains
int                      g_luarpc_wakefd = -1;  // eventfd; nudges run()'s poll

// Per-conn serialized handler dispatch for direct (/ces/luarpc/1) conns -- the
// direct-transport twin of g_conn_exec/g_conn_advance (see their comment). Kept
// separate because the direct id space (g_luarpc_next_id) is independent of the
// relay's.
struct LuaRpcExec { std::deque<LuaRpcEvent> pending; bool busy = false; };
std::map<uint64_t, LuaRpcExec> g_luarpc_exec;     // direct conn id -> serialized state
std::deque<uint64_t>           g_luarpc_advance;  // direct conns with an event ready

// Accept gate: set by ces.conn.set_listener (Lua), read by serve()
// (endpoint). No listener → close-on-connect.
std::atomic<bool> g_luarpc_listening{false};

// The endpoint's task strand, armed in main once the endpoint is up. Null
// until then (and forever if this instance got no rpc port).
boost::asio::io_context* g_luarpc_io = nullptr;

struct LuaRpcConn {
  std::shared_ptr<minx::RudpStream> stream;
  std::deque<std::string> writeQ;   // RudpStream forbids overlapping writes,
  bool writing = false;             //   so we serialize: one in flight.
  bool closing = false;
  std::array<uint8_t, 4096> readBuf{};
};
std::map<uint64_t, std::shared_ptr<LuaRpcConn>> g_luarpc_conns;  // strand-only
uint64_t g_luarpc_next_id = 1;                                   // strand-only

// Per-channel resource usage the endpoint's ChannelMeter reports (endpoint
// strand); the run() loop drains it into a one-way TAG_NET_USAGE frame to the
// parent (IPC thread; only it may touch g_sock_fd). Each report carries the
// channel's bound payer prefix. Inbound channels carry the remote caller's
// prefix; outbound channels are tracked under this instance's OWN program prefix
// (see luarpc_do_connect). The parent prices the usage and routes the bill by
// payer: own prefix -> source file_balance, anyone else -> that caller.
struct NetUsageRecord {
  ces::HashPrefix   payer{};
  ces::CesPlexUsage usage{};
};
std::mutex                  g_net_usage_mx;
std::deque<NetUsageRecord>  g_net_usage_q;

void luarpc_push(LuaRpcEvent e) {
  {
    std::lock_guard<std::mutex> lk(g_luarpc_mx);
    g_luarpc_inq.push_back(std::move(e));
  }
  // Nudge the unified run() poll on the Lua thread. The endpoint threads
  // can't call into the single-threaded Lua VM, so they queue + wake; run()
  // re-enters Lua to dispatch.
  if (g_luarpc_wakefd >= 0) {
    uint64_t one = 1;
    ssize_t w = ::write(g_luarpc_wakefd, &one, sizeof(one));
    (void)w;
  }
}

// Endpoint strand: drain a conn's writeQ, one async_write at a time.
void luarpc_drain_writes(uint64_t id, std::shared_ptr<LuaRpcConn> c) {
  if (c->writing || c->closing || c->writeQ.empty()) return;
  c->writing = true;
  auto buf = std::make_shared<std::string>(std::move(c->writeQ.front()));
  c->writeQ.pop_front();
  boost::asio::async_write(*c->stream, boost::asio::buffer(*buf),
    [id, c, buf](const boost::system::error_code& ec, std::size_t) {
      c->writing = false;
      if (ec) {
        if (!c->closing) luarpc_push({LuaRpcEvent::Type::Closed, id, {}, {}});
        g_luarpc_conns.erase(id);
        return;
      }
      luarpc_drain_writes(id, c);
    });
}

// Endpoint strand: read whatever arrives → push Data → repeat. A read error
// (peer close / reset) → push Closed + drop the conn.
void luarpc_start_read(uint64_t id, std::shared_ptr<LuaRpcConn> c) {
  c->stream->async_read_some(
    boost::asio::buffer(c->readBuf.data(), c->readBuf.size()),
    [id, c](const boost::system::error_code& ec, std::size_t n) {
      if (ec) {
        if (!c->closing) luarpc_push({LuaRpcEvent::Type::Closed, id, {}, {}});
        g_luarpc_conns.erase(id);
        return;
      }
      LuaRpcEvent e{LuaRpcEvent::Type::Data, id, {}, {}};
      e.bytes.assign(reinterpret_cast<const char*>(c->readBuf.data()), n);
      luarpc_push(std::move(e));
      luarpc_start_read(id, c);
    });
}

// Called from Lua → hop to the endpoint strand to enqueue + send.
void luarpc_conn_write(uint64_t id, std::string bytes) {
  if (!g_luarpc_io) return;
  boost::asio::post(*g_luarpc_io,
    [id, bytes = std::move(bytes)]() mutable {
      auto it = g_luarpc_conns.find(id);
      if (it == g_luarpc_conns.end() || it->second->closing) return;
      it->second->writeQ.push_back(std::move(bytes));
      luarpc_drain_writes(id, it->second);
    });
}

// Called from Lua → hop to the strand to gracefully close.
void luarpc_conn_close(uint64_t id) {
  if (!g_luarpc_io) return;
  boost::asio::post(*g_luarpc_io, [id]() {
    auto it = g_luarpc_conns.find(id);
    if (it == g_luarpc_conns.end()) return;
    it->second->closing = true;
    it->second->stream->shutdown(ces::kRudpStreamCloseTimeout);
    // The read completion (error after shutdown) erases the conn.
  });
}

// Outbound dialing rides the SAME endpoint Rudp/socket as serving (the user's
// "religiously the same socket"). Armed in main alongside g_luarpc_io.
minx::Rudp*                   g_luarpc_rudp = nullptr;
ces::ChannelMeter*            g_luarpc_meter = nullptr;  // = endpoint->meter()
std::shared_ptr<ces::KeyPair> g_luarpc_signer;   // the program's keypair

struct LuaRpcConnectResult {
  uint8_t status = ces::CES_ERROR_INTERNAL;
  uint64_t connId = 0;
  std::array<uint8_t, 32> peer{};
};

// A finished ces.conn.connect awaiting its coroutine's resume. The endpoint
// thread pushes (under g_luarpc_mx) + nudges g_luarpc_wakefd; the run loop
// drains, builds the conn on the coroutine, and resumes it. The blocking
// (main-chunk) connect path keeps its own promise instead.
struct ConnectDelivery { lua_State* co; LuaRpcConnectResult res; };
std::deque<ConnectDelivery> g_connect_done;

// Endpoint strand: open an OUTBOUND /ces/luarpc/1 channel to `peer`, drive the
// client bind (signed by the program key), verify the reply AND that the
// server pubkey matches `expectPk` (the program knows who it dialed), and on
// success register the bound stream as a raw conn + start pumping. Reports via
// `pr`. Mirrors CesPlexClient::doSelect, but on the endpoint's own Rudp.
void luarpc_do_connect(minx::SockAddr peer, std::array<uint8_t, 32> expectPk,
                       std::function<void(LuaRpcConnectResult)> done,
                       int timeoutMs) {
  if (!g_luarpc_rudp || !g_luarpc_signer || !g_luarpc_io) {
    done({ces::CES_ERROR_INTERNAL, 0, {}});
    return;
  }
  // Seed Rudp's clock so the fresh channel isn't idle-GC'd on the next tick.
  g_luarpc_rudp->tick(ces::getMicrosSinceEpoch());
  std::random_device rd;
  uint32_t channel = static_cast<uint32_t>(rd());
  auto stream = std::make_shared<minx::RudpStream>(g_luarpc_io->get_executor());
  if (!g_luarpc_rudp->registerChannel(peer, channel, stream)) {
    done({ces::CES_ERROR_INTERNAL, 0, {}});
    return;
  }

  // Bind-handshake timeout, bounded AT THE SOURCE: if no reply within
  // timeoutMs, close the half-open stream so the pending read fails with ec ->
  // done(error), the clean "connect failed" path. Cancelled the instant the
  // bind resolves (so it never closes a now-live conn). Beats waiting on RUDP
  // idle-GC (~60s), and there is no racing coroutine-side timer to leave an
  // orphaned conn behind: a timeout fails before the conn is ever registered.
  auto timer = std::make_shared<boost::asio::steady_timer>(*g_luarpc_io);
  if (timeoutMs > 0) {
    timer->expires_after(std::chrono::milliseconds(timeoutMs));
    timer->async_wait([stream](const boost::system::error_code& tec) {
      if (tec) return;   // cancelled: the bind already resolved
      try { stream->close(); } catch (...) {}
    });
  }

  static const std::string kProto = "/ces/luarpc/1";
  const uint64_t bindNowUs = ces::getMicrosSinceEpoch();
  auto bindReq = std::make_shared<minx::Bytes>(
    ces::buildBindRequest(kProto, bindNowUs, *g_luarpc_signer));
  const auto& pkArr = g_luarpc_signer->getPublicKeyAsHash();
  auto clientDigest =
    std::make_shared<std::array<uint8_t, ces::CES_PLEX_SHA256_SIZE>>(
      ces::computeBindRequestDigest(
        std::span<const uint8_t>(
          reinterpret_cast<const uint8_t*>(kProto.data()), kProto.size()),
        bindNowUs,
        std::span<const uint8_t>(pkArr.data(), pkArr.size())));

  boost::asio::async_write(*stream, boost::asio::buffer(*bindReq),
    [stream, bindReq, clientDigest, done, expectPk, peer, channel, timer]
    (const boost::system::error_code& ec, std::size_t) {
      if (ec) { timer->cancel(); done({ces::CES_ERROR_INTERNAL, 0, {}}); return; }
      auto reply = std::make_shared<
        std::array<uint8_t, ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE>>();
      boost::asio::async_read(*stream, boost::asio::buffer(*reply),
        [stream, reply, clientDigest, done, expectPk, peer, channel, timer]
        (const boost::system::error_code& ec2, std::size_t) {
          timer->cancel();   // bind resolved (ok or fail): disarm the timeout
          if (ec2) { done({ces::CES_ERROR_INTERNAL, 0, {}}); return; }
          ces::ParsedBindReply r = ces::parseBindReply(
            std::span<const uint8_t, ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE>(
              reply->data(), reply->size()));
          const bool ok =
            r.status == ces::CES_PLEX_OK &&
            ces::verifyBindReply(r, std::span<const uint8_t>(
              clientDigest->data(), clientDigest->size())) &&
            std::memcmp(r.serverPubkey.data(), expectPk.data(), 32) == 0;
          if (!ok) {
            done({ces::CES_ERROR_PROTO_REJECTED, 0, {}});
            return;
          }
          uint64_t id = g_luarpc_next_id++;
          auto c = std::make_shared<LuaRpcConn>();
          c->stream = stream;
          g_luarpc_conns[id] = c;
          // Meter this OUTBOUND channel so the instance pays its own server
          // (file_balance) for dialing out. Track it under this instance's own
          // program prefix: the parent recognizes that as "the instance itself"
          // and routes the bill to file_balance (vs an inbound caller's prefix).
          if (g_luarpc_meter) {
            ces::HashPrefix self{};
            std::memcpy(self.data(), g_program_pubkey, self.size());
            g_luarpc_meter->track(peer, channel, "luarpc:out", self);
          }
          LuaRpcConnectResult res{ces::CES_OK, id, {}};
          std::memcpy(res.peer.data(), r.serverPubkey.data(), 32);
          luarpc_start_read(id, c);
          done(res);
        });
    });
}

// One serve() per inbound /ces/luarpc/1 channel, on the endpoint strand. No
// Lua listener → close-on-connect (drop the stream). Else register the conn,
// announce it (on_open), and start pumping bytes.
class LuaRpcHandler : public ces::CesPlexHandler {
public:
  void serve(std::shared_ptr<minx::RudpStream> stream,
             ces::BoundChannelContext bound) override {
    if (!g_luarpc_listening.load(std::memory_order_relaxed)) {
      (void)stream;   // dropped on return → channel closes
      return;
    }
    uint64_t id = g_luarpc_next_id++;
    auto c = std::make_shared<LuaRpcConn>();
    c->stream = std::move(stream);
    LuaRpcEvent opened{LuaRpcEvent::Type::Opened, id, {}, {}};
    const ces::Hash& pk = bound.boundPubkey.getHash();
    std::memcpy(opened.peer.data(), pk.data(), opened.peer.size());
    g_luarpc_conns[id] = c;
    luarpc_push(std::move(opened));
    luarpc_start_read(id, c);
  }
};
LuaRpcHandler g_luaRpcHandler;

// CesPlexHost for this lua host's rpc endpoint: signs bind replies + per-op
// responses with the program's own keypair. Usage is reported up to the parent
// server, which prices it and bills the caller (inbound) or this instance's
// file_balance (outbound).
class LuaHostPlexHost : public ces::CesPlexHost {
public:
  explicit LuaHostPlexHost(const ces::KeyPair& key) : key_(key) {}
  const ces::KeyPair& cesplexSigningKey() const override { return key_; }
  void cesplexReportUsage(const ces::HashPrefix& payer,
                          const minx::SockAddr& /*peer*/,
                          uint32_t /*channelId*/,
                          const ces::CesPlexUsage& usage) override {
    // Endpoint strand: must NOT touch g_sock_fd. Queue the (payer, usage) and
    // nudge; run() emits the TAG_NET_USAGE frame on the IPC thread. The parent
    // decides who pays from the payer prefix.
    {
      std::lock_guard<std::mutex> lk(g_net_usage_mx);
      g_net_usage_q.push_back(NetUsageRecord{payer, usage});
    }
    if (g_luarpc_wakefd >= 0) {
      uint64_t one = 1;
      ssize_t w = ::write(g_luarpc_wakefd, &one, sizeof(one));
      (void)w;
    }
  }
private:
  ces::KeyPair key_;
};

// The endpoint is opened LAZILY — the first time the program touches luarpc
// (set_listener or connect). A program that never speaks luarpc opens no
// socket and spawns no endpoint threads. Once up, it stays for the instance's
// life. No-op if already up or if this instance got no rpc port.
std::unique_ptr<LuaHostPlexHost>      g_luarpc_host;
std::unique_ptr<ces::CesPlexEndpoint> g_luarpc_endpoint;

void luarpc_ensure_endpoint() {
  if (g_luarpc_endpoint || g_rpc_port == 0) return;
  try {
    ces::Hash priv{};
    std::memcpy(priv.data(), g_program_privkey, 32);
    g_luarpc_signer =
        std::make_shared<ces::KeyPair>(priv, ces::KeyAlgo::ED25519);
    g_luarpc_host = std::make_unique<LuaHostPlexHost>(*g_luarpc_signer);

    // The eventfd the endpoint threads nudge so the unified run() poll wakes.
    // Created before the endpoint so it exists before any thread can push.
    if (g_luarpc_wakefd < 0)
      g_luarpc_wakefd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);

    minx::MinxConfig minxCfg{};
    minxCfg.instanceName = "luarpc";
    minxCfg.randomXVMsToKeep = 0;
    minxCfg.randomXInitThreads = 0;
    // No PoW engine + spam disabled → dialable without tickets, mirroring the
    // server's own rpc port. (Anti-spam posture for a public luarpc port is a
    // deliberate decision still owed — see the compute closure design doc.)
    minxCfg.spamThreshold = std::numeric_limits<uint16_t>::max();
    minxCfg.spamSampleRate = 512;
    minxCfg.trustLoopback = true;

    minx::RudpConfig rudpCfg{};
    rudpCfg.baseTickInterval = std::chrono::milliseconds(1);
    // The endpoint is a full server+client: it serves /ces/luarpc/1 AND dials
    // out (luarpc + file + compute), so one program may hold several channels
    // to the SAME peer at once (e.g. a file client then a compute client to
    // one server). The Rudp default of 1 channel/peer is far too low; match
    // CesPlexClient's headroom.
    rudpCfg.maxChannelsPerPeer = 8;

    g_luarpc_endpoint = std::make_unique<ces::CesPlexEndpoint>(
        g_rpc_port, g_luarpc_host.get(),
        std::map<std::string, std::string>{
            {"/ces/luarpc/1", "builtin:luarpc"}},
        std::move(minxCfg), std::move(rudpCfg));
    g_luarpc_io = &g_luarpc_endpoint->io();
    g_luarpc_rudp = g_luarpc_endpoint->rudp();
    g_luarpc_meter = g_luarpc_endpoint->meter();
  } catch (const std::exception& e) {
    host_log(3, std::string("rpc endpoint setup failed: ") + e.what());
    g_luarpc_endpoint.reset();
    g_luarpc_host.reset();
    g_luarpc_signer.reset();
  }
}
}  // namespace
REGISTER_CESPLEX_BUILTIN("luarpc", g_luaRpcHandler, LuaRpcHandler)
uint16_t g_next_corr_id = 1;

int lua_ces_now(lua_State* L) {
  auto us = std::chrono::duration_cast<std::chrono::microseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
  lua_pushnumber(L, static_cast<lua_Number>(us));
  return 1;
}

int lua_ces_sha256(lua_State* L) {
  size_t n = 0;
  const char* s = luaL_checklstring(L, 1, &n);
  Sha256Ctx c{};
  sha256_init(c);
  sha256_update(c, reinterpret_cast<const uint8_t*>(s), n);
  uint8_t digest[32];
  sha256_final(c, digest);
  lua_pushlstring(L, reinterpret_cast<const char*>(digest), 32);
  return 1;
}

// ces.log([level,] msg) - operator instrumentation, registered ONLY for
// privileged (/s/) programs (see install_ces_api). The application picks the
// level ("trace"|"debug"|"info"|"warn"|"error", default "info"); the operator
// picks what's visible via blog's "compute" module level. Fire-and-forget over
// a one-way IPC frame; the host (builtin:compute) logs it through blog under
// "compute", tagged with the instance + program prefix (added host-side, not
// trusted from here). Never reaches user programs. Capped so a program can't
// emit huge log lines.
// Level byte: 0=trace 1=debug 2=info 3=warn 4=error (mirrors the compute side).
static uint8_t log_level_from_name(lua_State* L, const char* name) {
  if (std::strcmp(name, "trace") == 0) return 0;
  if (std::strcmp(name, "debug") == 0) return 1;
  if (std::strcmp(name, "info")  == 0) return 2;
  if (std::strcmp(name, "warn")  == 0 || std::strcmp(name, "warning") == 0) return 3;
  if (std::strcmp(name, "error") == 0) return 4;
  return static_cast<uint8_t>(luaL_error(L, "ces.log: invalid level '%s'", name));
}

int lua_ces_log(lua_State* L) {
  if (!g_privileged) return 0;  // no-op for non-/s/ instances (also gated server-side)
  uint8_t level = 2;  // info
  size_t n = 0;
  const char* s;
  if (lua_gettop(L) >= 2) {
    level = log_level_from_name(L, luaL_checkstring(L, 1));
    s = luaL_checklstring(L, 2, &n);
  } else {
    s = luaL_checklstring(L, 1, &n);
  }
  if (n > 4096) n = 4096;
  std::vector<uint8_t> body;
  body.reserve(1 + n);
  body.push_back(level);
  body.insert(body.end(), s, s + n);
  write_frame(TAG_LOG, 0, body.data(), body.size());
  return 0;
}

// ces.sign(bytes) -> sig(65 bytes). Signs with this instance's program key.
// The private key never enters the sandbox: signing happens here in the host
// and only the signature comes back. Decorator byte + 64-byte signature.
int lua_ces_sign(lua_State* L) {
  size_t n = 0;
  const char* s = luaL_checklstring(L, 1, &n);
  ces::Hash priv{};
  std::memcpy(priv.data(), g_program_privkey, 32);
  ces::KeyPair kp(priv, ces::KeyAlgo::ED25519);
  ces::Signature sig = kp.signData(s, n);
  lua_pushlstring(L, reinterpret_cast<const char*>(sig.data()), sig.size());
  return 1;
}

// ces.verify(pubkey(32), bytes, sig(65)) -> bool. Verifies any party's
// signature over bytes; the signature's decorator byte selects the algorithm.
int lua_ces_verify(lua_State* L) {
  size_t pkn = 0, dn = 0, sn = 0;
  const char* pk = luaL_checklstring(L, 1, &pkn);
  const char* data = luaL_checklstring(L, 2, &dn);
  const char* sigs = luaL_checklstring(L, 3, &sn);
  if (pkn != 32 || sn != ces::SIG_SIZE) {
    lua_pushboolean(L, 0);
    return 1;
  }
  ces::Hash pkh{};
  std::memcpy(pkh.data(), pk, 32);
  ces::PublicKey pub(pkh);
  ces::Signature sig{};
  std::memcpy(sig.data(), sigs, ces::SIG_SIZE);
  bool ok = false;
  try {
    ok = pub.verifySignature(data, dn, sig);
  } catch (...) {
    // A malformed pubkey or signature must verify as false, never throw
    // through LuaJIT.
    ok = false;
  }
  lua_pushboolean(L, ok ? 1 : 0);
  return 1;
}

// ces.client_recv([nowait]) → (sender_pfx:string(8), payload:string) | nil
//
// Default: BLOCKING. Drains the socket first (so any currently-
// queued deliver frames come out), then if the inbox is still
// empty blocks on read() until either a deliver frame arrives
// or the host closes the pipe (which means the supervisor is
// about to SIGKILL us; we return nil and the top-level loop
// exits).
//
// Pass any truthy arg (e.g. `true`) to request non-blocking mode:
// returns nil immediately if no message is queued.
int lua_ces_client_recv(lua_State* L) {
  bool nowait = lua_toboolean(L, 1);
  auto pop_if_available = [L]() -> int {
    if (g_inbox.empty()) return 0;
    Frame f = std::move(g_inbox.front());
    g_inbox.pop_front();
    if (f.body.size() < 8) return 0;
    lua_pushlstring(L, reinterpret_cast<const char*>(f.body.data()), 8);
    lua_pushlstring(L, reinterpret_cast<const char*>(f.body.data() + 8),
                       f.body.size() - 8);
    return 2;
  };
  if (!drain_socket_nonblocking()) return 0;
  if (int r = pop_if_available()) return r;
  if (nowait) return 0;

  // Blocking path: read frames until a deliver arrives (or socket
  // dies). Replies we don't expect get buffered; non-deliver frames
  // (which shouldn't happen) get dropped.
  for (;;) {
    Frame f;
    if (!read_frame(f)) return 0; // socket dead
    if (f.tag == TAG_DELIVER) {
      g_inbox.push_back(std::move(f));
      return pop_if_available();
    }
    if (f.tag == TAG_API_REPLY) {
      route_to_queue(std::move(f));   // diverts a parked coroutine's reply to g_io_ready
      continue;
    }
    // Anything else: ignore and keep waiting.
  }
}

// ces.client_send(target_pfx:string(8), bytes:string) → true | nil, err
int lua_ces_client_send(lua_State* L) {
  size_t pfx_len = 0, bytes_len = 0;
  const char* pfx = luaL_checklstring(L, 1, &pfx_len);
  const char* bytes = luaL_checklstring(L, 2, &bytes_len);
  if (pfx_len != 8) {
    lua_pushnil(L);
    lua_pushstring(L, "prefix must be 8 bytes");
    return 2;
  }
  if (bytes_len > 1024) {
    lua_pushnil(L);
    lua_pushstring(L, "payload too large (max 1024)");
    return 2;
  }
  // send_api_call prepends the u16 method; args = [8B target_pfx][u16 BE len][bytes].
  std::vector<uint8_t> args;
  args.reserve(WIRE_PREFIX_LEN + sizeof(uint16_t) + bytes_len);
  args.insert(args.end(), reinterpret_cast<const uint8_t*>(pfx),
              reinterpret_cast<const uint8_t*>(pfx) + 8);
  put_u16(args, static_cast<uint16_t>(bytes_len));
  args.insert(args.end(), reinterpret_cast<const uint8_t*>(bytes),
              reinterpret_cast<const uint8_t*>(bytes) + bytes_len);

  // Through io_call so it yields from a coroutine instead of freezing the VM on
  // the host round-trip (the only request/response verb that still blocked).
  return io_call(L, METHOD_CLIENT_SEND, args,
                 [](lua_State* L, const Frame& reply) -> int {
    uint8_t status = reply.body[0];
    if (status == STATUS_OK) { lua_pushboolean(L, 1); return 1; }
    lua_pushnil(L);
    switch (status) {
      case STATUS_NOT_CONNECTED:    lua_pushstring(L, "not_connected"); break;
      case STATUS_INSUFFICIENT_BAL: lua_pushstring(L, "insufficient_balance"); break;
      default:                      lua_pushstring(L, "internal"); break;
    }
    return 2;
  });
}

// ces.prog_prefix() → string(8) — convenience so scripts can log
// or key state by their own identity.
int lua_ces_prog_prefix(lua_State* L) {
  lua_pushlstring(L, reinterpret_cast<const char*>(g_prog_prefix), 8);
  return 1;
}

// ces.owner_pubkey() → string(32) — the source file's owner pubkey.
// /s/ programs see the server's pubkey here (their "house key").
int lua_ces_owner_pubkey(lua_State* L) {
  lua_pushlstring(L, reinterpret_cast<const char*>(g_owner_pubkey), 32);
  return 1;
}

// ces.program_pubkey() → string(32) — the file's dedicated program
// account: the pool ces.transfer spends from, and the address a program
// should advertise to receive funds (a game's "house", a service's
// wallet) so deposits and payouts share one pool.
int lua_ces_program_pubkey(lua_State* L) {
  lua_pushlstring(L, reinterpret_cast<const char*>(g_program_pubkey), 32);
  return 1;
}

// ces.start_time() → number — this instance's birth time in
// microseconds since epoch. Stable for the instance's life. Programs
// use it as a freshness anchor: a payment whose lastXferTime is
// ≤ start_time / 1e6 (seconds) cannot have been a fresh deposit
// aimed at THIS instance, so it should not count as a bet.
int lua_ces_start_time(lua_State* L) {
  lua_pushnumber(L, static_cast<lua_Number>(g_start_time_us));
  return 1;
}

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
    if (p + size_t(alen) + 1 + 2 > end) break;
    const char* addr = reinterpret_cast<const char*>(p); p += alen;
    uint8_t flags = *p; p += 1;
    uint16_t rpcPort = get_u16(p); p += 2;
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

// ---------------------------------------------------------------------------
// ces.conn — /ces/lua/1 connection routing.
// ---------------------------------------------------------------------------
//
// Programs that want to accept user RUDP connections call
// ces.conn.set_listener({on_open, on_data, on_close}) to flip the
// server-side accept gate ON, then ces.conn.run() to enter the event
// loop. The runtime dispatches per-connection events to the matching
// callback. conn objects (Lua tables) provide :write(s) / :close()
// and read-only .id / .pubkey fields.
//
// No coroutines, no yielding — callback-driven for v1. Programs that
// need byte-streaming semantics keep their own per-conn state across
// callback invocations.
//
// The accept gate is one bool per instance, server-side. The listener
// table is held in the Lua registry; passing nil to set_listener
// flips the gate OFF (existing connections continue to work).

// Registry keys. kRegListenerTable is the SINGLE listener shared by BOTH
// transports — relay /ces/lua/1 and direct /ces/luarpc/1. Each transport keeps
// its OWN live-conn table keyed by its native conn id (relay: the supervisor's
// per-instance nextConnId; direct: this endpoint's g_luarpc_next_id) purely for
// inbound routing. Those two native spaces are independent and overlap, so they
// are NEVER the program-facing identity — see g_conn_uid_next.
constexpr const char* kRegListenerTable = "ces.conn.listener";
constexpr const char* kRegConnsTable    = "ces.conn.relay.live";  // [native] = conn

// Program-facing conn.id: ONE monotonic id owned entirely by this host, handed
// out at open for EITHER transport, so it is unique across both — a program can
// key its own state by conn.id with zero collisions. The native routing id is
// kept privately in conn.__sid. conn.source (below) still reports the origin.
// Lua-thread-only (the dispatchers and connect all run on the Lua thread).
uint64_t g_conn_uid_next = 1;

// conn.source — informational origin only, NOT identity and NOT used to route.
constexpr int CONN_SOURCE_RELAY  = 0;  // /ces/lua/1, server-relayed over the UDS
constexpr int CONN_SOURCE_DIRECT = 1;  // /ces/luarpc/1, this instance's own rpc port

// Per-conn close-reason byte (matches kCloseReason* in handler).
constexpr uint8_t CONN_CLOSE_NORMAL   = 0x00;
constexpr uint8_t CONN_CLOSE_INTERNAL = 0x01;
constexpr uint8_t CONN_CLOSE_INSTANCE = 0x02;
constexpr uint8_t CONN_CLOSE_PROGRAM  = 0x03;

// Push the registry-stored conn table for `conn_id` onto the stack,
// or nil if not present. Always pushes one value.
void push_conn_table(lua_State* L, uint64_t conn_id) {
  lua_getfield(L, LUA_REGISTRYINDEX, kRegConnsTable);
  if (!lua_istable(L, -1)) {
    lua_pop(L, 1);
    lua_pushnil(L);
    return;
  }
  // Use double-as-int key (LuaJIT 5.1 has no native u64 in tables;
  // double is exact for u64 < 2^53, our nextConnId starts at 1 and
  // grows monotonically per instance — well below 2^53).
  lua_pushnumber(L, static_cast<lua_Number>(conn_id));
  lua_rawget(L, -2);
  // Stack: [conns_table, conn_or_nil]. Remove conns_table.
  lua_remove(L, -2);
}

// Send TAG_CONN_DATA_OUT for (conn_id, bytes). Returns true on
// IPC write success.
bool send_conn_data_out(uint64_t conn_id,
                         const uint8_t* data, size_t len) {
  std::vector<uint8_t> body;
  body.reserve(sizeof(uint64_t) + sizeof(uint32_t) + len);
  put_u64(body, conn_id);
  put_u32(body, static_cast<uint32_t>(len));
  if (len > 0)
    body.insert(body.end(), data, data + len);
  return write_frame(TAG_CONN_DATA_OUT, 0, body.data(), body.size());
}

// Send TAG_CONN_CLOSE for conn_id.
bool send_conn_close(uint64_t conn_id) {
  std::vector<uint8_t> body;
  body.reserve(sizeof(uint64_t));
  put_u64(body, conn_id);
  return write_frame(TAG_CONN_CLOSE, 0, body.data(), body.size());
}

// conn:write(s) — Lua method on a conn table.
// Returns true on success, nil + err on failure.
int lua_ces_conn_write(lua_State* L) {
  if (!lua_istable(L, 1)) {
    lua_pushnil(L); lua_pushstring(L, "expected conn table"); return 2;
  }
  // Reject if marked closed.
  lua_getfield(L, 1, "closed");
  bool closed = lua_toboolean(L, -1);
  lua_pop(L, 1);
  if (closed) {
    lua_pushnil(L); lua_pushstring(L, "closed"); return 2;
  }
  lua_getfield(L, 1, "__sid");
  if (!lua_isnumber(L, -1)) {
    lua_pop(L, 1);
    lua_pushnil(L); lua_pushstring(L, "missing routing id"); return 2;
  }
  uint64_t id = static_cast<uint64_t>(lua_tonumber(L, -1));
  lua_pop(L, 1);

  size_t n = 0;
  const char* s = luaL_checklstring(L, 2, &n);
  if (n > 1024 * 1024) {
    lua_pushnil(L);
    lua_pushstring(L, "payload too large (max 1 MB per write)");
    return 2;
  }
  if (!send_conn_data_out(id, reinterpret_cast<const uint8_t*>(s), n)) {
    lua_pushnil(L); lua_pushstring(L, "ipc write failed"); return 2;
  }
  lua_pushboolean(L, 1);
  return 1;
}

// conn:close() — Lua method on a conn table.
int lua_ces_conn_close(lua_State* L) {
  if (!lua_istable(L, 1)) {
    lua_pushnil(L); lua_pushstring(L, "expected conn table"); return 2;
  }
  lua_getfield(L, 1, "closed");
  bool already = lua_toboolean(L, -1);
  lua_pop(L, 1);
  if (already) {
    lua_pushboolean(L, 1);
    return 1;
  }
  lua_getfield(L, 1, "__sid");
  uint64_t id = static_cast<uint64_t>(lua_tonumber(L, -1));
  lua_pop(L, 1);
  send_conn_close(id);
  // Mark closed locally + drop from g_conns_table. Note: the host
  // does not echo back CONN_CLOSED for program-side close (saves
  // an unnecessary IPC round-trip).
  lua_pushboolean(L, 1);
  lua_setfield(L, 1, "closed");
  lua_getfield(L, LUA_REGISTRYINDEX, kRegConnsTable);
  if (lua_istable(L, -1)) {
    lua_pushnumber(L, static_cast<lua_Number>(id));
    lua_pushnil(L);
    lua_rawset(L, -3);
  }
  lua_pop(L, 1);
  lua_pushboolean(L, 1);
  return 1;
}

// ces.conn.set_listener(table_or_nil) — the ONE accept gate for both transports.
// Non-nil: stores the listener, sends TAG_LISTEN_ON (relay accept gate), flips
// the direct accept gate on, and lazy-opens this instance's /ces/luarpc/1
// endpoint (a no-op if it got no rpc port). Inbound conns from EITHER transport
// fan into the same on_open/on_data/on_close; tell them apart, if you must, by
// conn.source. nil: clears the listener and closes both gates (existing conns in
// either live table keep working).
int lua_ces_conn_set_listener(lua_State* L) {
  if (lua_isnil(L, 1)) {
    lua_pushnil(L);
    lua_setfield(L, LUA_REGISTRYINDEX, kRegListenerTable);
    g_luarpc_listening.store(false, std::memory_order_relaxed);   // direct gate off
    if (!write_frame(TAG_LISTEN_OFF, 0, nullptr, 0)) {            // relay gate off
      lua_pushnil(L); lua_pushstring(L, "ipc write failed"); return 2;
    }
    lua_pushboolean(L, 1);
    return 1;
  }
  if (!lua_istable(L, 1)) {
    return luaL_error(L, "ces.conn.set_listener: expected table or nil");
  }
  // Stash the listener table in the registry — both dispatchers read it.
  lua_pushvalue(L, 1);
  lua_setfield(L, LUA_REGISTRYINDEX, kRegListenerTable);
  // Make sure the relay live-conns table exists.
  lua_getfield(L, LUA_REGISTRYINDEX, kRegConnsTable);
  if (!lua_istable(L, -1)) {
    lua_pop(L, 1);
    lua_newtable(L);
    lua_setfield(L, LUA_REGISTRYINDEX, kRegConnsTable);
  } else {
    lua_pop(L, 1);
  }
  // Direct transport: flip the gate on + open the endpoint (no-op if no port).
  g_luarpc_listening.store(true, std::memory_order_relaxed);
  luarpc_ensure_endpoint();
  // Relay transport: tell the supervisor to start accepting ATTACHes.
  if (!write_frame(TAG_LISTEN_ON, 0, nullptr, 0)) {
    lua_pushnil(L); lua_pushstring(L, "ipc write failed"); return 2;
  }
  lua_pushboolean(L, 1);
  return 1;
}

// Build a fresh relay conn table for native id `conn_id` + `pubkey`. The
// program-facing conn.id is a fresh host uid (unique across transports); the
// native id goes in conn.__sid for routing and keys kRegConnsTable[conn_id] (so
// later DATA_IN / CLOSED frames, which carry the native id, find it). Leaves the
// conn table on the stack top, ready to pass to a Lua callback.
void make_and_register_conn(lua_State* L, uint64_t conn_id,
                             const uint8_t* pubkey) {
  lua_newtable(L);
  lua_pushnumber(L, static_cast<lua_Number>(g_conn_uid_next++));
  lua_setfield(L, -2, "id");
  lua_pushinteger(L, CONN_SOURCE_RELAY);
  lua_setfield(L, -2, "source");
  lua_pushnumber(L, static_cast<lua_Number>(conn_id));   // native routing id
  lua_setfield(L, -2, "__sid");
  lua_pushlstring(L, reinterpret_cast<const char*>(pubkey), 32);
  lua_setfield(L, -2, "pubkey");
  lua_pushboolean(L, 0);
  lua_setfield(L, -2, "closed");
  lua_pushcfunction(L, guarded<lua_ces_conn_write>);
  lua_setfield(L, -2, "write");
  lua_pushcfunction(L, guarded<lua_ces_conn_close>);
  lua_setfield(L, -2, "close");
  // Register in the live-conns table, keyed by the native id (the wire id the
  // dispatcher will look up on later DATA_IN / CLOSED frames).
  lua_getfield(L, LUA_REGISTRYINDEX, kRegConnsTable);
  if (lua_istable(L, -1)) {
    lua_pushnumber(L, static_cast<lua_Number>(conn_id));
    lua_pushvalue(L, -3); // copy of the conn table
    lua_rawset(L, -3);
  }
  lua_pop(L, 1);
  // Stack-top: the conn table.
}

// Drop a relay conn from the live-conns registry (after on_close completes, or
// when a CLOSED frame has no handler to run).
void remove_conn(lua_State* L, uint64_t id) {
  lua_getfield(L, LUA_REGISTRYINDEX, kRegConnsTable);
  if (lua_istable(L, -1)) {
    lua_pushnumber(L, static_cast<lua_Number>(id));
    lua_pushnil(L);
    lua_rawset(L, -3);
  }
  lua_pop(L, 1);
}

// Prepare coroutine `co` to run the listener callback for frame `f`: pushes
// [callback, conn, (data)] onto co and returns the arg count (1 or 2), or -1 if
// there is nothing to run (no listener, no callback, or the conn is gone). For
// OPEN the conn is created+registered here (even when on_open is absent, so the
// callback still finds it); for CLOSE the conn is marked closed before the
// callback. Stack-neutral on mainL.
int setup_handler_co(lua_State* mainL, lua_State* co, const Frame& f) {
  if (f.body.size() < sizeof(uint64_t)) return -1;
  uint64_t id = get_u64(f.body.data());
  constexpr size_t dataHdr = sizeof(uint64_t) + sizeof(uint32_t);

  // Per-tag frame validation up front.
  if (f.tag == TAG_CONN_OPENED &&
      f.body.size() < sizeof(uint64_t) + WIRE_KEY_LEN) return -1;
  if (f.tag == TAG_CONN_DATA_IN) {
    if (f.body.size() < dataHdr) return -1;
    uint32_t dlen = get_u32(f.body.data() + sizeof(uint64_t));
    if (f.body.size() < dataHdr + dlen) return -1;
  }
  if (f.tag == TAG_CONN_CLOSED &&
      f.body.size() < sizeof(uint64_t) + sizeof(uint8_t)) return -1;

  lua_getfield(mainL, LUA_REGISTRYINDEX, kRegListenerTable);
  if (!lua_istable(mainL, -1)) { lua_pop(mainL, 1); return -1; }

  const char* cbname = (f.tag == TAG_CONN_OPENED)  ? "on_open"
                     : (f.tag == TAG_CONN_DATA_IN) ? "on_data"
                                                   : "on_close";

  if (f.tag == TAG_CONN_OPENED) {
    const uint8_t* pk = f.body.data() + sizeof(uint64_t);
    make_and_register_conn(mainL, id, pk);    // mainL: [listener, conn]
    lua_getfield(mainL, -2, cbname);           // [listener, conn, cb]
    if (!lua_isfunction(mainL, -1)) { lua_pop(mainL, 3); return -1; }
    lua_xmove(mainL, co, 1);                   // cb   -> co ; mainL: [listener, conn]
    lua_xmove(mainL, co, 1);                   // conn -> co ; mainL: [listener]
    lua_pop(mainL, 1);
    return 1;
  }

  // DATA_IN / CLOSED: the conn must already exist.
  lua_getfield(mainL, -1, cbname);             // [listener, cb]
  bool hasCb = lua_isfunction(mainL, -1);
  push_conn_table(mainL, id);                  // [listener, cb, conn] (conn or nil)
  if (lua_isnil(mainL, -1)) { lua_pop(mainL, 3); return -1; }
  if (f.tag == TAG_CONN_CLOSED) {
    lua_pushboolean(mainL, 1);
    lua_setfield(mainL, -2, "closed");         // close before callback: no write/close
  }
  if (!hasCb) { lua_pop(mainL, 3); return -1; }
  lua_pushvalue(mainL, -2);                    // [listener, cb, conn, cb]
  lua_xmove(mainL, co, 1);                     // cb   -> co ; mainL: [listener, cb, conn]
  lua_xmove(mainL, co, 1);                     // conn -> co ; mainL: [listener, cb]
  lua_pop(mainL, 2);
  if (f.tag == TAG_CONN_DATA_IN) {
    uint32_t dlen = get_u32(f.body.data() + sizeof(uint64_t));
    lua_pushlstring(co, reinterpret_cast<const char*>(f.body.data() + dataHdr),
                    dlen);
    return 2;
  }
  return 1;
}

// Start the next pending frame for conn `id` as a fresh handler coroutine, if
// one is not already live. A frame with nothing to run (no callback / conn
// gone) is skipped; a CLOSED frame so skipped still tears the conn down. Called
// when a frame arrives and when a handler finishes (re-queued via g_conn_advance
// so the resume chain stays flat, never recursive).
static void conn_advance(lua_State* mainL, uint64_t id) {
  auto it = g_conn_exec.find(id);
  if (it == g_conn_exec.end()) return;
  ConnExec& ce = it->second;
  if (ce.busy || ce.pending.empty()) return;
  Frame f = std::move(ce.pending.front());
  ce.pending.pop_front();
  bool isClose = (f.tag == TAG_CONN_CLOSED);

  lua_State* co = lua_newthread(mainL);
  int ref = luaL_ref(mainL, LUA_REGISTRYINDEX);
  int nargs = setup_handler_co(mainL, co, f);
  if (nargs < 0) {
    luaL_unref(mainL, LUA_REGISTRYINDEX, ref);  // nothing to run; drop the thread
    if (isClose) { remove_conn(mainL, id); g_conn_exec.erase(id); return; }
    g_conn_advance.push_back(id);                // try the next pending frame
    return;
  }
  g_coro_refs[co] = ref;
  ce.busy = true;
  g_handler_co[co] = HandlerCo{id, isClose, false};
  resume_coro(mainL, co, nargs);
}

// Route one inbound CONN_* frame into its conn's serialized queue and request a
// dispatch. The handler runs (as a coroutine) in conn_advance, drained by the
// run loop. Always returns true; framing/socket errors are handled by the
// caller's read path.
bool dispatch_conn_frame(lua_State* L, Frame f) {
  if (f.body.size() < sizeof(uint64_t)) return true;
  uint64_t id = get_u64(f.body.data());
  g_conn_exec[id].pending.push_back(std::move(f));
  g_conn_advance.push_back(id);
  (void)L;
  return true;
}

// Drain conns with a ready frame. Flat: a handler that finishes synchronously
// re-queues its conn via resume_coro, so this while-loop (not C recursion)
// walks a burst. Runs only from the run loop.
static void drain_conn_advance(lua_State* mainL) {
  while (!g_conn_advance.empty()) {
    uint64_t id = g_conn_advance.front();
    g_conn_advance.pop_front();
    conn_advance(mainL, id);
  }
}

// Forward decl — the unified loop below dispatches luarpc bridge events whose
// handler (dispatch_luarpc_event) is defined later in this file.
void dispatch_luarpc_event(lua_State* L, LuaRpcEvent e);

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

// ---------------------------------------------------------------------------
// Direct transport (/ces/luarpc/1) plumbing for the unified ces.conn API: the
// conn write/close ops, the bridge-event dispatcher, and outbound connect().
// These feed the SAME listener + run loop as the relay; the only program-
// visible mark of the transport is conn.source == 1. conn write/close hop to
// the endpoint strand; conn.pubkey is the authenticated pubkey of the peer.
// ---------------------------------------------------------------------------
constexpr const char* kRegLuaRpcConns    = "ces.conn.direct.live";  // [native] = conn

// conn:write(bytes) → true | false (false if the conn is already closed).
int lua_ces_luarpc_conn_write(lua_State* L) {
  luaL_checktype(L, 1, LUA_TTABLE);
  size_t n = 0;
  const char* s = luaL_checklstring(L, 2, &n);
  lua_getfield(L, 1, "closed");
  bool closed = lua_toboolean(L, -1);
  lua_pop(L, 1);
  if (closed) { lua_pushboolean(L, 0); return 1; }
  lua_getfield(L, 1, "__sid");
  uint64_t id = static_cast<uint64_t>(lua_tonumber(L, -1));
  lua_pop(L, 1);
  luarpc_conn_write(id, std::string(s, n));
  lua_pushboolean(L, 1);
  return 1;
}

// conn:close() — graceful close. Idempotent.
int lua_ces_luarpc_conn_close(lua_State* L) {
  luaL_checktype(L, 1, LUA_TTABLE);
  lua_getfield(L, 1, "__sid");
  uint64_t id = static_cast<uint64_t>(lua_tonumber(L, -1));
  lua_pop(L, 1);
  lua_pushboolean(L, 1);
  lua_setfield(L, 1, "closed");
  // Drop it from the live registry now. The peer-close path does this in
  // dispatch, but a program-initiated close sets closing=true on the endpoint
  // side, which suppresses the Closed event — so without this the conn table
  // would leak in kRegLuaRpcConns forever.
  lua_getfield(L, LUA_REGISTRYINDEX, kRegLuaRpcConns);
  if (lua_istable(L, -1)) {
    lua_pushnumber(L, static_cast<lua_Number>(id));
    lua_pushnil(L);
    lua_rawset(L, -3);
  }
  lua_pop(L, 1);
  luarpc_conn_close(id);
  return 0;
}

// Build a direct conn table {id=host uid, source=1, __sid=native, pubkey(32B),
// closed, write, close}, key the live table by the native id, and leave it on
// the stack top. Same shape as the relay builder; only source and the transport
// the write/close route to differ.
void make_luarpc_conn(lua_State* L, uint64_t id, const uint8_t* peer) {
  lua_newtable(L);
  lua_pushnumber(L, static_cast<lua_Number>(g_conn_uid_next++));
  lua_setfield(L, -2, "id");
  lua_pushinteger(L, CONN_SOURCE_DIRECT);
  lua_setfield(L, -2, "source");
  lua_pushnumber(L, static_cast<lua_Number>(id));   // native routing id
  lua_setfield(L, -2, "__sid");
  lua_pushlstring(L, reinterpret_cast<const char*>(peer), 32);
  lua_setfield(L, -2, "pubkey");
  lua_pushboolean(L, 0);
  lua_setfield(L, -2, "closed");
  lua_pushcfunction(L, guarded<lua_ces_luarpc_conn_write>);
  lua_setfield(L, -2, "write");
  lua_pushcfunction(L, guarded<lua_ces_luarpc_conn_close>);
  lua_setfield(L, -2, "close");
  lua_getfield(L, LUA_REGISTRYINDEX, kRegLuaRpcConns);
  if (lua_istable(L, -1)) {
    lua_pushnumber(L, static_cast<lua_Number>(id));
    lua_pushvalue(L, -3);  // the conn table
    lua_rawset(L, -3);
  }
  lua_pop(L, 1);  // live table
}

// Push live-conn[id] (or nil) onto the stack.
void push_luarpc_conn(lua_State* L, uint64_t id) {
  lua_getfield(L, LUA_REGISTRYINDEX, kRegLuaRpcConns);
  if (!lua_istable(L, -1)) { lua_pop(L, 1); lua_pushnil(L); return; }
  lua_pushnumber(L, static_cast<lua_Number>(id));
  lua_rawget(L, -2);
  lua_remove(L, -2);  // drop live table, leave conn-or-nil on top
}

// Drop a direct conn from the live-conns registry (after on_close, or when a
// close event has no handler to run).
void remove_luarpc_conn(lua_State* L, uint64_t id) {
  lua_getfield(L, LUA_REGISTRYINDEX, kRegLuaRpcConns);
  if (lua_istable(L, -1)) {
    lua_pushnumber(L, static_cast<lua_Number>(id));
    lua_pushnil(L);
    lua_rawset(L, -3);
  }
  lua_pop(L, 1);
}

// Direct-transport twin of setup_handler_co: prepares coroutine `co` to run the
// listener callback for bridge event `e`. Same contract (pushes [cb, conn,
// (data)], returns arg count or -1).
int setup_luarpc_handler_co(lua_State* mainL, lua_State* co,
                            const LuaRpcEvent& e) {
  lua_getfield(mainL, LUA_REGISTRYINDEX, kRegListenerTable);
  if (!lua_istable(mainL, -1)) { lua_pop(mainL, 1); return -1; }

  if (e.type == LuaRpcEvent::Type::Opened) {
    make_luarpc_conn(mainL, e.connId, e.peer.data());  // [listener, conn]
    lua_getfield(mainL, -2, "on_open");                 // [listener, conn, cb]
    if (!lua_isfunction(mainL, -1)) { lua_pop(mainL, 3); return -1; }
    lua_xmove(mainL, co, 1);                            // cb   -> co
    lua_xmove(mainL, co, 1);                            // conn -> co
    lua_pop(mainL, 1);
    return 1;
  }

  const char* cbname =
    (e.type == LuaRpcEvent::Type::Data) ? "on_data" : "on_close";
  lua_getfield(mainL, -1, cbname);                      // [listener, cb]
  bool hasCb = lua_isfunction(mainL, -1);
  push_luarpc_conn(mainL, e.connId);                    // [listener, cb, conn]
  if (lua_isnil(mainL, -1)) { lua_pop(mainL, 3); return -1; }
  if (e.type == LuaRpcEvent::Type::Closed) {
    lua_pushboolean(mainL, 1);
    lua_setfield(mainL, -2, "closed");
  }
  if (!hasCb) { lua_pop(mainL, 3); return -1; }
  lua_pushvalue(mainL, -2);                             // dup cb
  lua_xmove(mainL, co, 1);                              // cb   -> co
  lua_xmove(mainL, co, 1);                              // conn -> co
  lua_pop(mainL, 2);
  if (e.type == LuaRpcEvent::Type::Data) {
    lua_pushlstring(co, e.bytes.data(), e.bytes.size());
    return 2;
  }
  return 1;
}

// Direct-transport twin of conn_advance.
static void luarpc_advance(lua_State* mainL, uint64_t id) {
  auto it = g_luarpc_exec.find(id);
  if (it == g_luarpc_exec.end()) return;
  LuaRpcExec& ce = it->second;
  if (ce.busy || ce.pending.empty()) return;
  LuaRpcEvent e = std::move(ce.pending.front());
  ce.pending.pop_front();
  bool isClose = (e.type == LuaRpcEvent::Type::Closed);

  lua_State* co = lua_newthread(mainL);
  int ref = luaL_ref(mainL, LUA_REGISTRYINDEX);
  int nargs = setup_luarpc_handler_co(mainL, co, e);
  if (nargs < 0) {
    luaL_unref(mainL, LUA_REGISTRYINDEX, ref);
    if (isClose) { remove_luarpc_conn(mainL, id); g_luarpc_exec.erase(id); return; }
    g_luarpc_advance.push_back(id);
    return;
  }
  g_coro_refs[co] = ref;
  ce.busy = true;
  g_handler_co[co] = HandlerCo{id, isClose, true};
  resume_coro(mainL, co, nargs);
}

// Direct-transport twin of drain_conn_advance.
static void drain_luarpc_advance(lua_State* mainL) {
  while (!g_luarpc_advance.empty()) {
    uint64_t id = g_luarpc_advance.front();
    g_luarpc_advance.pop_front();
    luarpc_advance(mainL, id);
  }
}

// Resume coroutines whose ces.conn.connect finished (endpoint thread delivered
// the result). Conn construction touches Lua state, so it happens here on the
// run-loop thread, not on the endpoint thread.
static void drain_connect_done(lua_State* mainL) {
  for (;;) {
    ConnectDelivery d;
    {
      std::lock_guard<std::mutex> lk(g_luarpc_mx);
      if (g_connect_done.empty()) break;
      d = std::move(g_connect_done.front());
      g_connect_done.pop_front();
    }
    if (!g_parked.erase(d.co)) continue;   // already resumed (future timeout)
    int n;
    if (d.res.status != ces::CES_OK) {
      lua_checkstack(d.co, 2);
      lua_pushnil(d.co);
      lua_pushstring(d.co, d.res.status == ces::CES_ERROR_PROTO_REJECTED
                             ? "bind rejected or wrong peer"
                             : "connect failed (network)");
      n = 2;
    } else {
      lua_checkstack(d.co, 2);
      make_luarpc_conn(d.co, d.res.connId, d.res.peer.data());
      n = 1;
    }
    resume_coro(mainL, d.co, n);
  }
}

// Resume coroutines whose offloaded blocking call (a worker-pool job) finished.
// The worker delivered a "deliver" closure that pushes the Lua results here, on
// the run-loop thread.
static void drain_offload_done(lua_State* mainL) {
  for (;;) {
    OffloadDone d;
    {
      std::lock_guard<std::mutex> lk(g_offload_mx);
      if (g_offload_done.empty()) break;
      d = std::move(g_offload_done.front());
      g_offload_done.pop_front();
    }
    if (!g_parked.erase(d.co)) continue;
    lua_checkstack(d.co, LUA_MINSTACK);
    int n = d.deliver(d.co);
    resume_coro(mainL, d.co, n);
  }
}

// Route one bridge event into its conn's serialized queue and request dispatch;
// the handler runs (as a coroutine) in luarpc_advance, drained by the run loop.
void dispatch_luarpc_event(lua_State* L, LuaRpcEvent e) {
  uint64_t id = e.connId;
  g_luarpc_exec[id].pending.push_back(std::move(e));
  g_luarpc_advance.push_back(id);
  (void)L;
}

// ces.conn.connect(addr, server_pubkey(32) [, timeout_ms]) → conn | nil, err.
// Dials a remote (or this) lua host's /ces/luarpc/1 out the instance's OWN rpc
// socket — the only outbound path (the relay is inbound-only: the server brings
// users in, it is not a generic egress proxy). From a coroutine it yields; on
// success returns a source=1 conn whose inbound data flows to the unified
// listener's on_data like any other. Optional timeout_ms bounds the bind
// handshake at the source (default 15000); a dead peer fails in ~timeout_ms
// rather than waiting on RUDP idle-GC. (Listen + run are unified — see
// ces.conn.set_listener / ces.run.)
int lua_ces_conn_connect(lua_State* L) {
  size_t alen = 0;
  const char* addr = luaL_checklstring(L, 1, &alen);
  size_t plen = 0;
  const char* spk = luaL_checklstring(L, 2, &plen);
  if (plen != 32) {
    lua_pushnil(L);
    lua_pushstring(L, "server pubkey must be 32 bytes");
    return 2;
  }
  int timeoutMs = static_cast<int>(luaL_optinteger(L, 3, 15000));
  if (timeoutMs < 0) timeoutMs = 0;   // 0 = no bind timeout (RUDP idle-GC only)
  luarpc_ensure_endpoint();   // lazy-open the port for dialing
  if (!g_luarpc_io || !g_luarpc_rudp || !g_luarpc_signer) {
    lua_pushnil(L);
    lua_pushstring(L,
      "networking permanently disabled (this instance has no rpc port)");
    return 2;
  }
  minx::SockAddr peer;
  try {
    auto ep = ces::Resolver::resolveUdp(std::string(addr, alen));
    auto a = ep.address();
    if (a.is_v4()) {
      a = boost::asio::ip::make_address_v6(
            boost::asio::ip::v4_mapped, a.to_v4());
    }
    peer = minx::SockAddr(a, ep.port());
  } catch (const std::exception&) {
    lua_pushnil(L);
    lua_pushstring(L, "address resolve failed");
    return 2;
  }
  std::array<uint8_t, 32> expectPk{};
  std::memcpy(expectPk.data(), spk, 32);

  // From a coroutine: park and let the endpoint's io thread drive the bind,
  // then resume on completion via g_connect_done. The loop never freezes; the
  // bind is bounded at the source by timeoutMs (see luarpc_do_connect).
  if (io_yieldable(L)) {
    lua_State* co = L;
    g_parked.insert(co);
    boost::asio::post(*g_luarpc_io, [peer, expectPk, co, timeoutMs]() {
      luarpc_do_connect(peer, expectPk, [co](LuaRpcConnectResult res) {
        {
          std::lock_guard<std::mutex> lk(g_luarpc_mx);
          g_connect_done.push_back(ConnectDelivery{co, std::move(res)});
        }
        if (g_luarpc_wakefd >= 0) {
          uint64_t one = 1;
          ssize_t w = ::write(g_luarpc_wakefd, &one, sizeof(one));
          (void)w;
        }
      }, timeoutMs);
    });
    return lua_yield(L, 0);
  }

  // Main chunk (cannot yield): block on the round-trip -- the degenerate case.
  auto pr = std::make_shared<std::promise<LuaRpcConnectResult>>();
  auto fut = pr->get_future();
  boost::asio::post(*g_luarpc_io, [peer, expectPk, pr, timeoutMs]() {
    luarpc_do_connect(peer, expectPk,
      [pr](LuaRpcConnectResult res) { pr->set_value(std::move(res)); },
      timeoutMs);
  });
  if (fut.wait_for(std::chrono::seconds(15)) != std::future_status::ready) {
    lua_pushnil(L);
    lua_pushstring(L, "connect timeout");
    return 2;
  }
  LuaRpcConnectResult res = fut.get();
  if (res.status != ces::CES_OK) {
    lua_pushnil(L);
    lua_pushstring(L, res.status == ces::CES_ERROR_INTERNAL
                        ? "connect failed (network)"
                        : "bind rejected or wrong peer");
    return 2;
  }
  make_luarpc_conn(L, res.connId, res.peer.data());
  return 1;
}

// ces.rpc_port() → the UDP port this instance hosts /ces/luarpc/1 on (0 if it
// got none). A serving program advertises (host, this port) so peers can dial.
int lua_ces_rpc_port(lua_State* L) {
  lua_pushnumber(L, static_cast<lua_Number>(g_rpc_port));
  return 1;
}

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

} // namespace

// ---------------------------------------------------------------------------
// Entry point.
// ---------------------------------------------------------------------------

int main(int argc, char** argv) {
  if (argc >= 3 && std::strcmp(argv[1], "--manifest") == 0)
    return probe_manifest(argv[2]);
  if (argc < 2) {
    std::fprintf(stderr,
                 "usage: %s <ipc-socket-path> [drop-to-user] [mem-max-bytes]\n",
                 argc > 0 ? argv[0] : "cesluajitd");
    return 2;
  }
  const char* sock_path = argv[1];
  const char* drop_user = argc >= 3 ? argv[2] : "";
  // argv[3]: address-space ceiling in bytes (RLIMIT_AS), from the
  // server's compute_process_mem_max. Absent/unparsable → 256 MB.
  size_t mem_max_bytes = 256ULL * 1024ULL * 1024ULL;
  if (argc >= 4) {
    char* end = nullptr;
    unsigned long long v = std::strtoull(argv[3], &end, 10);
    if (end != argv[3] && v > 0) mem_max_bytes = static_cast<size_t>(v);
  }
  // argv[4]: #3 verb-client worker-pool size, from the server's
  // compute_client_pool_size. Absent/unparsable → keep the default; clamp to
  // [1, 64] so a bad value can neither disable offload nor spawn a thread storm.
  if (argc >= 5) {
    char* end = nullptr;
    long v = std::strtol(argv[4], &end, 10);
    if (end != argv[4] && v >= 1 && v <= 64) g_client_pool_size = static_cast<int>(v);
  }

  g_sock_fd = connect_unix_socket(sock_path);
  if (g_sock_fd < 0) return 1;

  if (!drop_privileges_if_root(drop_user)) return 1;
  apply_rlimits(mem_max_bytes);

  // Read bootstrap frame. Body layout (must match
  // compute_handler.cpp::sendBootstrapFrame):
  //   [8B prog_prefix][32B owner_pubkey][32B program_pubkey]
  //   [32B program_privkey][8B start_time_us BE][u32 BE src_len][src bytes]
  Frame bs;
  if (!read_frame(bs) || bs.tag != TAG_BOOTSTRAP) {
    host_log(4, "bad bootstrap frame");
    return 1;
  }
  // Field offsets within the bootstrap body (must match
  // compute_handler.cpp::sendBootstrapFrame).
  constexpr size_t kOffPrefix  = 0;
  constexpr size_t kOffOwner   = kOffPrefix  + WIRE_PREFIX_LEN;
  constexpr size_t kOffProgram = kOffOwner   + WIRE_KEY_LEN;
  constexpr size_t kOffPrivkey = kOffProgram + WIRE_KEY_LEN;
  constexpr size_t kOffPort    = kOffPrivkey + WIRE_KEY_LEN;
  constexpr size_t kOffRpcPort = kOffPort    + sizeof(uint16_t);
  constexpr size_t kOffPriv    = kOffRpcPort + sizeof(uint16_t);
  constexpr size_t kOffStart   = kOffPriv    + 1;
  constexpr size_t kOffSrcLen  = kOffStart   + sizeof(uint64_t);
  constexpr size_t BS_HEADER   = kOffSrcLen  + sizeof(uint32_t);
  if (bs.body.size() < BS_HEADER) {
    host_log(4, "bootstrap too short");
    return 1;
  }
  std::memcpy(g_prog_prefix,     bs.body.data() + kOffPrefix,  WIRE_PREFIX_LEN);
  std::memcpy(g_owner_pubkey,    bs.body.data() + kOffOwner,   WIRE_KEY_LEN);
  std::memcpy(g_program_pubkey,  bs.body.data() + kOffProgram, WIRE_KEY_LEN);
  std::memcpy(g_program_privkey, bs.body.data() + kOffPrivkey, WIRE_KEY_LEN);
  g_program_port  = get_u16(bs.body.data() + kOffPort);
  g_rpc_port      = get_u16(bs.body.data() + kOffRpcPort);
  g_privileged    = bs.body[kOffPriv] != 0;
  g_start_time_us = get_u64(bs.body.data() + kOffStart);
  uint32_t src_len = get_u32(bs.body.data() + kOffSrcLen);
  if (bs.body.size() < BS_HEADER + src_len) {
    host_log(4, "bootstrap truncated");
    return 1;
  }
  const char* src =
    reinterpret_cast<const char*>(bs.body.data() + BS_HEADER);

  // Programs are Lua TEXT only. LuaJIT's loader treats a leading ESC
  // (0x1B) as a precompiled-bytecode chunk, and LuaJIT bytecode is
  // UNVERIFIED — crafted bytecode is a sandbox-escape vector that bypasses
  // the language-level safety entirely. A remote-supplied source must
  // never reach the bytecode path: reject a bytecode marker here, and load
  // with the explicit text-only mode below.
  if (src_len > 0 && static_cast<unsigned char>(src[0]) == 0x1b) {
    host_log(4, "refusing bytecode program (text only)");
    return 1;
  }

  lua_State* L = luaL_newstate();
  if (!L) {
    host_log(4, "luaL_newstate failed");
    return 1;
  }
  load_safe_libs(L);
  install_ces_api(L);

  // The /ces/luarpc/1 endpoint opens LAZILY — on the program's first
  // ces.luarpc.set_listener() or .connect() (see luarpc_ensure_endpoint). A
  // program that never speaks luarpc opens no socket and spawns no threads.

  // "t" = text only: a second barrier that refuses bytecode even if the
  // leading-byte guard above is bypassed.
  if (luaL_loadbufferx(L, src, src_len, "=program", "t") != 0) {
    host_log(4, std::string("load failed: ") + lua_err_str(L));
    lua_close(L);
    return 1;
  }
  if (lua_pcall(L, 0, 0, 0) != 0) {
    host_log(4, std::string("run failed: ") + lua_err_str(L));
    lua_close(L);
    return 1;
  }
  g_pool_main.shutdown();
  g_pool_client.shutdown();
  if (g_luarpc_wakefd >= 0) { ::close(g_luarpc_wakefd); g_luarpc_wakefd = -1; }
  lua_close(L);
  return 0;
}
