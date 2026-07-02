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

#include "sha256.h"  // cesluajitd-local: SHA-256 for ces.sha256

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

namespace cesluajitd {

#include "ipc.inc"
#include "startup.inc"
#include "sandbox.inc"
#include "api_core.inc"
#include "api_file.inc"
#include "offload_net.inc"
#include "api_bucket.inc"
#include "api_store.inc"
#include "api_conn.inc"
#include "timers.inc"
#include "api_chan.inc"
#include "api_extadmin.inc"
#include "conn_direct.inc"
#include "api_clients.inc"
}  // namespace cesluajitd

// The entry point lives in the global namespace; bring in the cesluajitd
// helpers it calls (load_safe_libs, connect_unix_socket, run, ...).
using namespace cesluajitd;

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
  int rc = 0;
  if (lua_pcall(L, 0, 0, 0) != 0) {
    host_log(4, std::string("run failed: ") + lua_err_str(L));
    rc = 1;
  }
  g_pool_main.shutdown();
  g_pool_client.shutdown();
  // Tear down the lazily-opened /ces/luarpc/1 endpoint and its host HERE, while the
  // asio runtime and Boost.Log are still alive. As file-scope globals they would
  // otherwise be destroyed at static-destruction time, where ~CesPlexEndpoint ->
  // ~ChannelMeter logs through an already-destroyed Boost.Log core and SEGVs on exit
  // (static destruction order fiasco). reset() is a no-op if the endpoint never opened.
  g_luarpc_meter = nullptr;
  g_luarpc_endpoint.reset();
  g_luarpc_host.reset();
  if (g_luarpc_wakefd >= 0) { ::close(g_luarpc_wakefd); g_luarpc_wakefd = -1; }
  lua_close(L);
  return rc;
}
