// compute_handler.cpp - builtin:compute CesPlex handler.
//
// See the header for the bind-prereq list.
//
// One child process per running instance (default cesluajitd, a sandboxed
// LuaJIT VM; cescompmockd is the no-Lua test stub), connected via a named
// Unix domain socket. The supervisor ticks periodically, samples the child's
// /proc CPU + RSS, debits slot/cpu/rss/bucket fees from the source file's
// file_balance via fileHandlerDebitBalance, and SIGKILLs the instance when a
// debit would delete the source file. A 15-minute upfront slot+rss fee is
// debited at LAUNCH to prevent create-and-abandon on the scheduler.
//
// Verbs (wire format mirrors builtin:file — preamble-first, signed
// envelope binding to sha256(verb || preamble), server-signed
// response):
//   0x01 LAUNCH  (owner): u16 path_len, path
//     resp: u64 instance_id, u64 started_at_us
//   0x02 KILL    (owner): u64 instance_id
//     resp: (empty)
//   0x03 LIST    (any, scoped to signer's own): (no preamble beyond reqNonce)
//     resp: u32 count, [u64 id, u16 path_len, path,
//                       u64 started_at_us, u64 file_balance,
//                       u32 cpu_bp, u64 rss_bytes,
//                       u16 client_port, u16 rpc_port]*
//   0x04 STAT    (any): u64 instance_id
//     resp: u64 instance_id, u64 started_at_us, u64 file_balance,
//           u32 cpu_bp, u64 rss_bytes, u16 client_port, u16 rpc_port,
//           u16 path_len, path
//   0x05 INSTANCES (any): u16 path_len, path
//     resp: u32 count, [u64 id, u64 started_at_us, u32 cpu_bp,
//                       u64 rss_bytes, u16 client_port, u16 rpc_port]*
//
// Inspectability: STAT (by id) and INSTANCES (by source path) are public
// to any signer and expose a live instance's leased ports, so anyone can
// discover a running service and dial it — relayed via the server's own
// rpc port (/ces/lua/1) or direct to the instance's own host port
// (/ces/luarpc/1). A port reads 0 when the instance got no lease. Only
// LAUNCH/KILL stay owner-gated (they mutate); LIST is scoped to the
// signer's own instances. file_balance is funding info on a public
// ledger (already readable via the file handler), so it rides along.
//
// The signed-request loop (verb read, envelope verify, server-signed
// response) is the shared cesPlexServe engine in cesplex/mux.h.

#include <ces/cesplex/mux.h>
#include <ces/cesplex/session.h>
#include <ces/l2/compute_handler.h>
#include <ces/l2/file_handler.h>
#include <ces/buffer.h>
#include <ces/ramfilestore.h>
#include <ces/keys.h>
#include <ces/server.h>
#include <ces/types.h>

#include <minx/blog.h>
#include <minx/bucketcache.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <span>
#include <sstream>
#include <string>
#include <vector>

LOG_MODULE("plex");

namespace ces {

namespace {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

constexpr uint8_t kVerbLaunch    = 0x01;
constexpr uint8_t kVerbKill      = 0x02;
constexpr uint8_t kVerbList      = 0x03;
constexpr uint8_t kVerbStat      = 0x04;
constexpr uint8_t kVerbInstances = 0x05;

constexpr uint16_t kMaxNameLen = 512;   // matches file handler
constexpr uint16_t kAppPayloadMax = 1024;

// Supervisor cadence is taken from cfg.computeTickIntervalMs (60 s
// default in production). One tick does procfs sampling + slot-fee
// debit through the source file's sidecar — each of those is
// measurable in microseconds per instance, so 60 s gives us decent
// eviction responsiveness with near-zero steady-state overhead.
// Tests override the cadence down to 1 s so CPU/RSS assertions
// don't need a full-minute wait.

// LAUNCH-time burn against create-and-abandon churn. At LAUNCH the
// source file_balance is debited feeComputeSlotSec × kUpfrontSeconds
// — a commitment fee, not a runtime credit. Billing starts at
// t=0 as usual.
constexpr uint64_t kUpfrontSeconds = 15 * 60;

// Socket-accept timeout for the cesluad-style handshake (ms). If the
// child fails to connect back within this window we SIGKILL it and
// return CES_ERROR_INTERNAL.
constexpr int kAcceptTimeoutMs = 2000;

// IPC tags (mirror cesluajitd/main.cpp).
constexpr uint8_t kIpcTagBootstrap = 0x00;
constexpr uint8_t kIpcTagDeliver   = 0x01;
constexpr uint8_t kIpcTagApiCall   = 0x02;
constexpr uint8_t kIpcTagApiReply  = 0x03;
// /ces/lua/1 connection routing tags. Server↔child for forwarding
// bytes between Lua programs and external users.
constexpr uint8_t kIpcTagConnOpened   = 0x04;  // server → child
constexpr uint8_t kIpcTagConnDataIn   = 0x05;  // server → child
constexpr uint8_t kIpcTagConnClosed   = 0x06;  // server → child
constexpr uint8_t kIpcTagConnDataOut  = 0x07;  // child → server
constexpr uint8_t kIpcTagConnClose    = 0x08;  // child → server
constexpr uint8_t kIpcTagListenOn     = 0x09;  // child → server
constexpr uint8_t kIpcTagListenOff    = 0x0a;  // child → server

constexpr uint16_t kApiMethodClientSend = 0x0001;
constexpr uint16_t kApiMethodFileCreate   = 0x0100;
constexpr uint16_t kApiMethodFileWrite    = 0x0101;
constexpr uint16_t kApiMethodFileRead     = 0x0102;
constexpr uint16_t kApiMethodFileStat     = 0x0103;
constexpr uint16_t kApiMethodFileDeposit  = 0x0104;
constexpr uint16_t kApiMethodFileWithdraw = 0x0105;
constexpr uint16_t kApiMethodFileSetPrice = 0x0106;
constexpr uint16_t kApiMethodFileDelete   = 0x0107;
constexpr uint16_t kApiMethodFileAppend   = 0x0108;
constexpr uint16_t kApiMethodFileResize   = 0x0109;
// Ledger / RNG bindings exposed to the Lua sandbox:
//   TRANSFER     — program-initiated transfer from owner's account.
//                  /s/ programs see the server's account, which is
//                  bottomless by boot top-up.
//   RANDOM_BYTES — crypto-grade RNG, n ≤ 256.
//   ACCOUNT_READ — unsigned account query, no fee.
constexpr uint16_t kApiMethodTransfer     = 0x0200;
constexpr uint16_t kApiMethodCrossTransfer = 0x0201;
constexpr uint16_t kApiMethodRandomBytes  = 0x0202;
constexpr uint16_t kApiMethodAccountRead  = 0x0203;
// Per-instance rotating bucket cache (minx::BucketCache wrapper):
//   BUCKET_NEW — allocate a bucket with TTL + size cap; returns u32 id
//   BUCKET_PUT — set k → v in the bucket
//   BUCKET_GET — read v for k, or "missing" status
// Used by Lua programs that need replay-protection tables with
// guaranteed forgetting (e.g. dice.lua's per-user last-consumed
// transfer time). Capacity is billed on the supervisor tick via
// feeBucketByteSec (see committedBytes below).
constexpr uint16_t kApiMethodBucketNew    = 0x0210;
constexpr uint16_t kApiMethodBucketPut    = 0x0211;
constexpr uint16_t kApiMethodBucketGet    = 0x0212;

// ces.authentic_asset_create(asset_id, recipient_pubkey, payload, days).
// Mints an IMMUTABLE asset whose first 32 bytes are the program's
// identity hash sha256(source_file_bytes || source_file_path), looked
// up from the source file's sidecar (computed lazily on first call,
// cached until the file is content-modified). User payload occupies
// the remaining 178 bytes of asset content. The new asset is owned
// by `recipient_pubkey` (may differ from the program's owner — the
// typical case is "program mints loot to a player"). Asset rent is
// paid by the program's owner account.
constexpr uint16_t kApiMethodAuthenticAssetCreate = 0x0220;
constexpr uint16_t kApiMethodPeers        = 0x0230;

// Authentic-asset content layout (a compute-SDK concept, opaque to the
// server): first 32 bytes are the program-identity hash
// sha256(source_bytes || source_path); the rest is the user payload. The
// handler assembles the full AssetData and hands raw bytes to createAssetAsync.
constexpr size_t AUTHENTIC_ASSET_HASH_SIZE = 32;
constexpr size_t AUTHENTIC_ASSET_PAYLOAD_SIZE =
  std::tuple_size_v<AssetData> - AUTHENTIC_ASSET_HASH_SIZE;

// File-verb codes mirror file_handler.cpp. Exposed to
// fileHandlerExec via FileExecReq.verb.
constexpr uint8_t kFileVerbCreate   = 0x01;
constexpr uint8_t kFileVerbWrite    = 0x02;
constexpr uint8_t kFileVerbRead     = 0x03;
constexpr uint8_t kFileVerbStat     = 0x04;
constexpr uint8_t kFileVerbDeposit  = 0x05;
constexpr uint8_t kFileVerbWithdraw = 0x06;
constexpr uint8_t kFileVerbSetPrice = 0x07;
constexpr uint8_t kFileVerbDelete   = 0x08;
constexpr uint8_t kFileVerbAppend   = 0x09;
constexpr uint8_t kFileVerbResize   = 0x0a;

constexpr uint8_t kApiStatusOk            = 0x00;
constexpr uint8_t kApiStatusNotConnected  = 0x01;
constexpr uint8_t kApiStatusInsufficient  = 0x02;
constexpr uint8_t kApiStatusInternal      = 0xFF;

constexpr uint32_t kIpcMaxFrameLen = 2 * 1024 * 1024;   // 2 MB safety cap

// Per-instance cap on queued outbound IPC frames before a best-effort
// DELIVER (incoming CES_APP_COMPUTE_MSG) is dropped instead of enqueued.
// CES_APP_COMPUTE_MSG is a lossy lane by contract — an undeliverable
// message is dropped silently — so shedding it when the child is behind
// is correct, and it bounds server memory against a remote flood aimed at
// a slow or non-reading program. Correctness-critical frames (API replies,
// conn routing, bootstrap) ignore this cap; they are flow-controlled by
// other means (request/response, RUDP windowing, one-shot).
constexpr size_t kMaxDeliverBacklog = 1024;

} // namespace
// Forward decls into the lua handler — defined in compute_lua_handler.cpp.
// The compute supervisor calls these when CONN_DATA_OUT / CONN_CLOSE
// frames arrive from the child, and when an instance is dying (so the
// lua handler can tear down all its routed connections before the
// Instance is dropped).
void luaHandlerHandleConnDataOut(uint64_t instId, uint64_t connId,
                                  const uint8_t* data, size_t len);
void luaHandlerHandleConnClose(uint64_t instId, uint64_t connId);
void luaHandlerOnInstanceDying(uint64_t instId);
namespace {

// All BE serialization goes through ces::Buffer (see ces/buffer.h).

// ---------------------------------------------------------------------------
// Global handler state — accessed only from rpcTaskIO_ (the CesPlex /
// handler strand). APPLICATION messages posted from taskIO_ hop onto
// rpcTaskIO_ before touching any of this.
// ---------------------------------------------------------------------------

std::atomic<CesServer*> gServer{nullptr};

using UnixSocket = boost::asio::local::stream_protocol::socket;
using UnixAcceptor = boost::asio::local::stream_protocol::acceptor;

struct Instance : std::enable_shared_from_this<Instance> {
  uint64_t id = 0;
  std::string sourceName;
  std::array<uint8_t, 32> ownerPk{};
  // Program account pubkey from the source file's sidecar.
  std::array<uint8_t, 32> programPubkey{};
  // Program account ed25519 private half, copied to the child at bootstrap
  // so it can sign its own remote ops.
  std::array<uint8_t, 32> programPrivkey{};
  std::array<uint8_t, 8> progPrefix{};  // first 8B of sha256(sourceName)
  pid_t pid = -1;
  // UDP port the server statically assigned this instance for its
  // outbound CES client, from the configured compute port range. 0 =
  // no range configured (instance has no network). Handed to the child
  // in the bootstrap frame; freed back to the pool on death.
  uint16_t clientPort = 0;
  // UDP port the server reserved for this instance's inbound CesPlex host
  // (/ces/luarpc/1), from the same range. 0 = none. Independent of
  // clientPort; freed back to the pool on death.
  uint16_t rpcPort = 0;
  uint64_t startedAtUs = 0;
  uint64_t lastTickUs = 0;              // supervisor's last-charged wall time
  uint64_t upfrontDeposit = 0;
  // CPU + RSS monitoring. Sampled each supervisor tick from
  // /proc/<pid>/stat + /proc/<pid>/statm. CPU is in basis points of
  // one core: 10000 = 100% of a single CPU; sustained ≥10000 on a
  // multi-core box means this (single-threaded Lua) child is fully
  // saturating its core. cpuBasisPoints reflects usage between the
  // last two samples, not cumulative since launch.
  uint64_t lastCpuTicks = 0;            // utime+stime at last sample (clock ticks)
  uint64_t lastSampleUs = 0;            // wall-clock at last sample
  uint32_t cpuBasisPoints = 0;          // 0..10000, of one core
  uint64_t rssBytes = 0;                // resident pages × page size, last sample
  std::string socketPath;
  // Async-I/O endpoint to the child. Wraps the accepted fd as an
  // asio::local::stream_protocol::socket. All reads and writes run
  // on rpcTaskIO_.
  std::shared_ptr<UnixSocket> peer;
  // Outbound frame queue. Kept serial: when empty and caller wants
  // to write, we start async_write of the new head; completion pops
  // head and, if the queue is non-empty, starts the next write.
  // Lets bootstrap + deliver + api-reply interleave safely from
  // different call sites without torn frames.
  std::deque<std::shared_ptr<ces::Bytes>> outbox;
  bool writing = false;
  // Inbound-frame read state.
  std::array<uint8_t, 4> rxLenBuf{};
  ces::Bytes rxBodyBuf;

  // /ces/lua/1 connection state. The accept gate (default closed) is
  // flipped by the child via TAG_LISTEN_ON / TAG_LISTEN_OFF. The
  // routing table for active connections is owned by the lua handler
  // (compute_lua_handler.cpp), keyed by (instId, connId); the
  // supervisor calls into it via forward-declared dispatchers when
  // CONN_DATA_OUT / CONN_CLOSE frames arrive from the child.
  bool acceptsConnections = false;
  uint64_t nextConnId = 1;

  // Per-instance rotating bucket caches, surfaced to Lua as
  // ces.bucket_new(ttl_secs, max_entries, max_entry_bytes).
  // Caches die with the instance — the bucket map clears when the
  // Instance is destroyed. BucketCache itself is thread-safe
  // (internal mutex), so reads/writes from the rpcTaskIO_ strand
  // are fine without extra locks.
  //
  // committedBytes is the worst-case footprint pre-declared at
  // bucket_new time: max_entries × max_entry_bytes. It's what the
  // supervisor bills against, so the program pays a predictable
  // capacity rent regardless of actual fill. Per-entry size is
  // capped at put time against max_entry_bytes (key + value sum).
  struct LuaBucket {
    std::shared_ptr<BucketCache<std::string, std::string>> cache;
    uint32_t maxEntries = 0;
    uint32_t maxEntryBytes = 0;     // klen + vlen cap per entry
    uint64_t committedBytes = 0;    // maxEntries × maxEntryBytes
  };
  std::map<uint32_t, LuaBucket> buckets;
  uint32_t nextBucketId = 1;
};

// Instance registry. Keyed by instance_id (the only identity). The
// path → ids and prefix → ids indexes are multi-valued: a source path
// may have N concurrent instances (one cesh compute launch ⇒ one new
// id), and prog_pfx is content-addressed from the path so all sibling
// instances on this server share it. APPLICATION routing broadcasts
// to every matching instance; file-deletion kills every matching
// instance.
std::map<uint64_t, std::shared_ptr<Instance>> gInstances;
std::map<std::array<uint8_t, 8>, std::set<uint64_t>> gByPrefix;
std::map<std::string, std::set<uint64_t>> gByName;
uint64_t gNextInstanceId = 1;

// In-flight LAUNCH reservations: launches admitted past the cap check
// whose instance isn't in gInstances yet (the child is still connecting
// back — async, up to kAcceptTimeoutMs). Counted against the cap so
// concurrent launches can't overshoot computeMaxInstances. Strand-only
// (rpcTaskIO_); no atomic needed.
uint64_t gPendingLaunches = 0;

// RAII reservation token: ++gPendingLaunches on construct, -- on
// destruct. Held (via shared_ptr) across the async LAUNCH chain and
// released once the instance lands in gInstances or the launch fails.
struct LaunchSlot {
  LaunchSlot() { ++gPendingLaunches; }
  ~LaunchSlot() { if (gPendingLaunches > 0) --gPendingLaunches; }
  LaunchSlot(const LaunchSlot&) = delete;
  LaunchSlot& operator=(const LaunchSlot&) = delete;
};

// Launch slots spoken for = registered instances + in-flight launches.
// The LAUNCH cap is checked against this, never gInstances alone.
inline std::size_t launchSlotsInUse() {
  return gInstances.size() + static_cast<std::size_t>(gPendingLaunches);
}

// L2 compute program port allocator. Each running instance gets one UDP
// port for its child's outbound CES client, claimed from the configured
// range [computePortBase, computePortBase + computePortCount - 1]. The
// server owns the whole lifecycle — no child picks its own port — so a
// firewalled L2 host can open exactly this range. Strand-only
// (rpcTaskIO_), like gInstances; no lock.
std::set<uint16_t> gUsedComputePorts;

// Claim the lowest free port in the configured range. Returns false if
// the range is configured (base != 0) but fully spoken for. With base
// == 0 there is no range: returns true with out = 0, which the child
// reads as "no network" — its outbound remote_* verbs fail cleanly
// rather than binding an unreachable ephemeral port.
bool allocateComputePort(const CesConfig& cfg, uint16_t& out) {
  if (cfg.computePortBase == 0) { out = 0; return true; }
  uint32_t base = cfg.computePortBase;
  uint32_t end = base + cfg.computePortCount;   // exclusive
  for (uint32_t p = base; p < end && p <= 0xFFFF; ++p) {
    uint16_t port = static_cast<uint16_t>(p);
    if (gUsedComputePorts.insert(port).second) { out = port; return true; }
  }
  return false;
}

void releaseComputePort(uint16_t port) {
  if (port != 0) gUsedComputePorts.erase(port);
}

// RAII reservation for a claimed compute port — mirrors LaunchSlot.
// Holds the port across the async launch chain and returns it to the
// pool on destruction unless commit()ted. A failed launch drops the
// lease and frees the port; on success the port is committed to the
// Instance, and killInstanceById frees it when the instance dies.
struct PortLease {
  uint16_t port = 0;
  bool committed = false;
  explicit PortLease(uint16_t p) : port(p) {}
  ~PortLease() { if (!committed) releaseComputePort(port); }
  void commit() { committed = true; }
  PortLease(const PortLease&) = delete;
  PortLease& operator=(const PortLease&) = delete;
};

// Supervisor tick timer. Lives on rpcTaskIO_'s strand.
std::shared_ptr<boost::asio::steady_timer> gTickTimer;
std::atomic<bool> gTickRunning{false};

// True iff we've registered our deletion callback with the file
// handler. Registration is one-shot per process — fileHandler has no
// unregister. Repeat binds reuse the same callback, which reads
// gServer atomically.
std::atomic<bool> gDeletionCallbackInstalled{false};

// ---------------------------------------------------------------------------
// Unix socket / process helpers
// ---------------------------------------------------------------------------

std::filesystem::path resolveWorkDir(const CesConfig& cfg) {
  if (!cfg.cesComputeWorkDir.empty()) return cfg.cesComputeWorkDir;
  return std::filesystem::path(cfg.dataDir.string()) / "cescompute";
}

std::filesystem::path instanceSocketPath(const CesConfig& cfg, uint64_t id) {
  return resolveWorkDir(cfg) / (std::to_string(id) + ".sock");
}

// Compute 8B prefix = first 8 bytes of sha256(name).
std::array<uint8_t, 8> progPrefixOf(const std::string& name) {
  minx::Hash h = ces::sha256(
    reinterpret_cast<const uint8_t*>(name.data()), name.size());
  std::array<uint8_t, 8> pf{};
  std::memcpy(pf.data(), h.data(), 8);
  return pf;
}

// Create + bind + listen on a Unix socket at `path`. Returns fd or
// -errno.
int createListenSocket(const std::string& path) {
  // Clean up any stale socket file; we own this path.
  std::error_code ec;
  std::filesystem::remove(path, ec);

  int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return -errno;
  sockaddr_un a{};
  a.sun_family = AF_UNIX;
  if (path.size() >= sizeof(a.sun_path)) { ::close(fd); return -ENAMETOOLONG; }
  std::memcpy(a.sun_path, path.data(), path.size());
  if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) < 0) {
    int e = errno; ::close(fd); return -e;
  }
  if (::listen(fd, 1) < 0) {
    int e = errno; ::close(fd); return -e;
  }
  return fd;
}

// fork+exec the configured child binary. argv[1] is the IPC socket
// path; argv[2] (optional) is the non-root user to drop to if the
// server is running as root. Returns pid > 0 on success, -errno
// on failure.
pid_t spawnChild(const std::string& binary,
                 const std::string& sockPath,
                 const std::string& dropUser,
                 uint64_t memMaxBytes) {
  // Build argv strings before fork — only async-signal-safe work may run
  // between fork and exec. dropUser is passed positionally ("" when no
  // drop is requested) so memMax lands at a fixed argv slot.
  std::string memMaxStr = std::to_string(memMaxBytes);
  pid_t pid = ::fork();
  if (pid < 0) return -errno;
  if (pid == 0) {
    // Child. Close stdin; leave stdout/stderr for the runtime's
    // panic messages (which should only ever fire on host bugs).
    ::close(STDIN_FILENO);
    const char* arg0 = binary.c_str();
    const char* arg1 = sockPath.c_str();
    const char* arg2 = dropUser.c_str();   // "" = no privilege drop
    const char* arg3 = memMaxStr.c_str();  // RLIMIT_AS ceiling, bytes
    ::execlp(arg0, arg0, arg1, arg2, arg3, nullptr);
    std::_Exit(127);
  }
  return pid;
}

// SIGKILL + reap the pid. Best-effort — returns true on success, but
// callers shouldn't branch on it: a reaped child is a reaped child.
bool killAndReap(pid_t pid) {
  if (pid <= 0) return true;
  ::kill(pid, SIGKILL);
  // Non-blocking reap loop. The child is dead or dying; WNOHANG
  // shouldn't wait, but run a short retry in case of SIGKILL delivery
  // latency.
  for (int i = 0; i < 50; ++i) {
    int status = 0;
    pid_t r = ::waitpid(pid, &status, WNOHANG);
    if (r == pid || r < 0) return true;
    // Not reaped yet.
    ::usleep(1000);
  }
  return false;
}

// ---------------------------------------------------------------------------
// CPU + RSS sampling from /proc
// ---------------------------------------------------------------------------
//
// /proc/<pid>/stat — many space-separated fields; field 2 is the comm
//   in parens and may itself contain spaces/parens. Safe parse: split
//   AFTER the last ')'. utime (field 14) and stime (field 15) become
//   the 12th + 13th tokens of that tail.
// /proc/<pid>/statm — 7 space-separated page counts; field 2 is
//   "resident" (the RSS in pages).

struct ProcSample {
  uint64_t ticks = 0;   // utime + stime, in clock ticks
  uint64_t rssBytes = 0;
};

bool readProcSample(pid_t pid, ProcSample& out) {
  {
    std::string path = "/proc/" + std::to_string(pid) + "/stat";
    std::ifstream f(path);
    if (!f) return false;
    std::string line;
    if (!std::getline(f, line)) return false;
    auto rp = line.rfind(')');
    if (rp == std::string::npos || rp + 2 >= line.size()) return false;
    std::istringstream ss(line.substr(rp + 2));
    std::vector<std::string> toks;
    std::string t;
    while (ss >> t) toks.push_back(t);
    // Indices 11 + 12 correspond to utime (14th field) + stime (15th field).
    if (toks.size() < 13) return false;
    uint64_t utime = 0, stime = 0;
    try {
      utime = std::stoull(toks[11]);
      stime = std::stoull(toks[12]);
    } catch (...) {
      return false;
    }
    out.ticks = utime + stime;
  }
  {
    std::string path = "/proc/" + std::to_string(pid) + "/statm";
    std::ifstream f(path);
    if (!f) return false;
    uint64_t sizePages = 0, residentPages = 0;
    if (!(f >> sizePages >> residentPages)) return false;
    long ps = ::sysconf(_SC_PAGESIZE);
    if (ps <= 0) ps = 4096;
    out.rssBytes = residentPages * static_cast<uint64_t>(ps);
  }
  return true;
}

// Sample the instance's process and refresh cpuBasisPoints + rssBytes.
// Stale state is kept on failure (process may have gone; the zombie
// reap path is responsible for teardown). CPU basis points are the
// mean over the interval since last sample — so a busy-loop Lua will
// pin at ~10000 (= 100% of one core).
void sampleInstanceProc(Instance& inst, uint64_t nowUs) {
  if (inst.pid <= 0) return;
  ProcSample s;
  if (!readProcSample(inst.pid, s)) return;
  uint64_t deltaUs = (nowUs > inst.lastSampleUs)
    ? (nowUs - inst.lastSampleUs) : 0;
  uint64_t deltaTicks = (s.ticks >= inst.lastCpuTicks)
    ? (s.ticks - inst.lastCpuTicks) : 0;
  long tps = ::sysconf(_SC_CLK_TCK);
  if (tps <= 0) tps = 100;
  uint32_t bp = 0;
  if (deltaUs > 0) {
    // bp = deltaTicks * 10000 * 1e6 / (tps * deltaUs)
    // 128-bit to avoid overflow on longer intervals.
    __uint128_t num =
      static_cast<__uint128_t>(deltaTicks) * 10000ull * 1'000'000ull;
    __uint128_t den =
      static_cast<__uint128_t>(tps) * deltaUs;
    __uint128_t q = (den > 0) ? (num / den) : 0;
    uint64_t bp64 = (q > 10000) ? 10000 : static_cast<uint64_t>(q);
    bp = static_cast<uint32_t>(bp64);
  }
  inst.cpuBasisPoints = bp;
  inst.rssBytes = s.rssBytes;
  inst.lastCpuTicks = s.ticks;
  inst.lastSampleUs = nowUs;
}

// Tear down per-instance resources (sockets, socket file). Does not
// manipulate gInstances / gByPrefix / gByName — caller handles the
// registry.
void teardownInstance(Instance& inst) {
  if (inst.peer) {
    boost::system::error_code ec;
    inst.peer->close(ec);
    inst.peer.reset();
  }
  if (!inst.socketPath.empty()) {
    std::error_code ec;
    std::filesystem::remove(inst.socketPath, ec);
  }
}

// Kill an instance by id, remove from registries, clean up resources.
// No fee refund on kill: the upfront slot-fee paid for a commitment the
// host already honored by running.
void killInstanceById(uint64_t id) {
  auto it = gInstances.find(id);
  if (it == gInstances.end()) return;
  auto inst = it->second;
  // Tear down any /ces/lua/1 connections routed to this instance
  // before we drop the registry entry, so the lua handler can
  // still find it (and so the bytes-and-onClosed cascade fires
  // while the supervisor is still in a coherent state).
  luaHandlerOnInstanceDying(id);
  killAndReap(inst->pid);
  teardownInstance(*inst);
  releaseComputePort(inst->clientPort);
  releaseComputePort(inst->rpcPort);
  gInstances.erase(it);
  if (auto pit = gByPrefix.find(inst->progPrefix); pit != gByPrefix.end()) {
    pit->second.erase(id);
    if (pit->second.empty()) gByPrefix.erase(pit);
  }
  if (auto nit = gByName.find(inst->sourceName); nit != gByName.end()) {
    nit->second.erase(id);
    if (nit->second.empty()) gByName.erase(nit);
  }
  LOGDEBUG << "builtin:compute instance terminated"
           << VAR(id) << SVAR(inst->sourceName);
}

// ---------------------------------------------------------------------------
// IPC framing helpers (host ↔ cesluajitd)
// ---------------------------------------------------------------------------
//
// Frame layout (both directions):
//   [u32 BE length][u8 tag][u16 BE corr_id][body]
//
// `length` covers tag + corr_id + body. Frames that arrive with a
// malformed length or that miss the pipe cause the instance to be
// killed — we treat IPC errors as terminal.

// Forward decls for the async reader + dispatcher.
void startIpcReader(std::shared_ptr<Instance> inst);
void handleChildFrame(std::shared_ptr<Instance> inst);
void handleChildApiCall(std::shared_ptr<Instance> inst,
                        uint16_t corr_id,
                        const uint8_t* body, size_t bodyLen);

// Build a framed outbound message. Caller fills tag, corr_id, body
// bytes; this returns the full wire packet with the length prefix.
std::shared_ptr<ces::Bytes> makeFrame(
    uint8_t tag, uint16_t corr_id,
    const uint8_t* body, size_t body_len) {
  uint32_t len = static_cast<uint32_t>(
      sizeof(uint8_t) + sizeof(uint16_t) + body_len);   // tag + corr + body
  ces::Buffer buf(sizeof(uint32_t) + len);              // length prefix + frame
  buf.put<uint32_t>(len)
     .put<uint8_t>(tag)
     .put<uint16_t>(corr_id);
  if (body_len > 0) {
    buf.putBytes(std::span<const uint8_t>(body, body_len));
  }
  return std::make_shared<ces::Bytes>(std::move(buf).take());
}

// Forward decl: after a write completes, this tries to kick the
// next one if the outbox has more.
void kickOutboundIfIdle(std::shared_ptr<Instance> inst);

// Enqueue a pre-framed packet for async_write. If the outbox was
// idle, kicks off the next write.
void enqueueOutbound(std::shared_ptr<Instance> inst,
                     std::shared_ptr<ces::Bytes> frame) {
  if (!inst->peer) return;
  inst->outbox.push_back(std::move(frame));
  kickOutboundIfIdle(inst);
}

void kickOutboundIfIdle(std::shared_ptr<Instance> inst) {
  if (!inst->peer) return;
  if (inst->writing) return;
  if (inst->outbox.empty()) return;
  inst->writing = true;
  auto head = inst->outbox.front();
  boost::asio::async_write(
    *inst->peer, boost::asio::buffer(*head),
    [inst, head](const boost::system::error_code& ec, std::size_t) {
      inst->writing = false;
      if (!inst->outbox.empty()) inst->outbox.pop_front();
      if (ec) {
        LOGDEBUG << "builtin:compute ipc write failed"
                 << VAR(inst->id) << SVAR(ec.message());
        killInstanceById(inst->id);
        return;
      }
      kickOutboundIfIdle(inst);
    });
}

// Send a TAG_DELIVER frame to the child.
// Body = [8B sender_pfx][payload bytes].
void sendDeliverFrame(std::shared_ptr<Instance> inst,
                      const std::array<uint8_t, 8>& senderPfx,
                      const uint8_t* payload, size_t payloadLen) {
  // Best-effort lane: if the child is already deep behind on its outbound
  // queue, drop this message rather than grow the server's memory without
  // bound. A program that wants every message must keep draining.
  if (inst->peer && inst->outbox.size() >= kMaxDeliverBacklog) {
    LOGDEBUG << "builtin:compute deliver dropped (outbox full)"
             << VAR(inst->id) << VAR(inst->outbox.size());
    return;
  }
  ces::Bytes body;
  body.reserve(sizeof(senderPfx) + payloadLen);
  body.insert(body.end(), senderPfx.begin(), senderPfx.end());
  if (payloadLen > 0)
    body.insert(body.end(), payload, payload + payloadLen);
  enqueueOutbound(inst, makeFrame(kIpcTagDeliver, 0,
                                  body.data(), body.size()));
}

// Send a TAG_API_REPLY frame to the child. Reply body is a 1-byte
// status code optionally followed by a method-specific payload.
void sendApiReply(std::shared_ptr<Instance> inst,
                  uint16_t corr_id, uint8_t status) {
  uint8_t body = status;
  enqueueOutbound(inst, makeFrame(kIpcTagApiReply, corr_id, &body, 1));
}

void sendApiReplyWithBody(std::shared_ptr<Instance> inst,
                          uint16_t corr_id, uint8_t status,
                          const ces::Bytes& tail) {
  ces::Bytes body;
  body.reserve(sizeof(uint8_t) + tail.size());
  body.push_back(status);
  body.insert(body.end(), tail.begin(), tail.end());
  enqueueOutbound(inst,
    makeFrame(kIpcTagApiReply, corr_id, body.data(), body.size()));
}

// Send the bootstrap frame at LAUNCH time. Body layout:
//   [8B prog_prefix][32B owner_pubkey][32B program_pubkey]
//   [32B program_privkey][2B client_port BE][2B rpc_port BE]
//   [1B privileged][8B start_time_us BE][u32 BE src_len][src bytes]
// - privileged: 1 for an operator /s/ program (server-deployed, runs under the
//   server identity), 0 otherwise. Gates operator-only API like ces.log so an
//   untrusted user program can't reach it.
// - prog_prefix: first 8B of sha256(source path); used as the
//   "prog_pfx" field on outbound CES_APP_COMPUTE_MSG packets so the
//   remote CES client can demux by program.
// - owner_pubkey: full 32B pubkey of the source file's owner.
//   Programs surface it via ces.owner_pubkey().
// - program_pubkey: full 32B pubkey of the file's dedicated program
//   account — the pool ces.transfer spends from. Programs surface it
//   via ces.program_pubkey() and advertise it as their receive address
//   (e.g. a game's "house"), so deposits and payouts share one pool.
// - program_privkey: the program account's ed25519 private half, so the
//   program can sign its own remote ops.
// - start_time_us: this instance's birth wall-clock micros (same
//   value as inst->startedAtUs). Programs use it as a freshness
//   anchor for replay protection — a payment whose lastXferTime is
//   ≤ this couldn't have been intended for this program-instance.
// - client_port: the UDP port the server reserved for this instance's
//   outbound CES client (0 = no range → the instance has no network).
//   The child binds its client to this port so it sends from a known,
//   firewall-configurable source port.
// - rpc_port: the UDP port the server reserved for this instance's inbound
//   CesPlex host (/ces/luarpc/1). 0 = none → the instance hosts nothing.
//   Independent of client_port: an instance may get one, both, or neither.
void sendBootstrapFrame(std::shared_ptr<Instance> inst,
                        const uint8_t* src, size_t srcLen) {
  ces::Bytes body;
  body.reserve(sizeof(inst->progPrefix) + sizeof(inst->ownerPk)
               + sizeof(inst->programPubkey) + sizeof(inst->programPrivkey)
               + sizeof(uint16_t) + sizeof(uint16_t) + 1 + sizeof(uint64_t)
               + sizeof(uint32_t) + srcLen);
  body.insert(body.end(),
              inst->progPrefix.begin(), inst->progPrefix.end());
  body.insert(body.end(),
              inst->ownerPk.begin(), inst->ownerPk.end());
  body.insert(body.end(),
              inst->programPubkey.begin(), inst->programPubkey.end());
  body.insert(body.end(),
              inst->programPrivkey.begin(), inst->programPrivkey.end());
  ces::Buffer::put<uint16_t>(body, inst->clientPort);
  ces::Buffer::put<uint16_t>(body, inst->rpcPort);
  body.push_back(isServerZone(inst->sourceName) ? 1 : 0);
  ces::Buffer::put<uint64_t>(body, inst->startedAtUs);
  ces::Buffer::put<uint32_t>(body, static_cast<uint32_t>(srcLen));
  if (srcLen > 0)
    body.insert(body.end(), src, src + srcLen);
  enqueueOutbound(inst, makeFrame(kIpcTagBootstrap, 0,
                                  body.data(), body.size()));
}

// Async-read one frame from the child. On success, dispatches and
// re-arms itself for the next frame.
void startIpcReader(std::shared_ptr<Instance> inst) {
  if (!inst->peer) return;
  boost::asio::async_read(
    *inst->peer, boost::asio::buffer(inst->rxLenBuf),
    [inst](const boost::system::error_code& ec, std::size_t) {
      if (ec) {
        // Child closed its end. Reap and clean up.
        killInstanceById(inst->id);
        return;
      }
      uint32_t len = ces::Buffer::peek<uint32_t>(inst->rxLenBuf.data());
      if (len < 3 || len > kIpcMaxFrameLen) {
        LOGDEBUG << "builtin:compute ipc bad frame len"
                 << VAR(inst->id) << VAR(len);
        killInstanceById(inst->id);
        return;
      }
      inst->rxBodyBuf.assign(len, 0);
      boost::asio::async_read(
        *inst->peer, boost::asio::buffer(inst->rxBodyBuf),
        [inst](const boost::system::error_code& ec2, std::size_t) {
          if (ec2) {
            killInstanceById(inst->id);
            return;
          }
          handleChildFrame(inst);
          if (gInstances.count(inst->id))
            startIpcReader(inst);
        });
    });
}

// (Cross-handler dispatchers for the lua handler are forward-declared
// at the top of this file, near the IPC tag constants, so they're
// visible to both handleChildFrame and killInstanceById.)

void handleChildFrame(std::shared_ptr<Instance> inst) {
  const auto& body = inst->rxBodyBuf;
  if (body.size() < 3) return;
  uint8_t tag = body[0];
  uint16_t corr = ces::Buffer::peek<uint16_t>(body.data() + 1);
  // /ces/lua/1 routing tags. Don't carry corr_id semantics — corr
  // is reserved zero by the child.
  if (tag == kIpcTagListenOn || tag == kIpcTagListenOff) {
    inst->acceptsConnections = (tag == kIpcTagListenOn);
    LOGDEBUG << "builtin:compute listener gate"
             << VAR(inst->id) << VAR(inst->acceptsConnections);
    return;
  }
  // `body` still carries the [u8 tag][u16 corr_id] frame header; the
  // routing payload begins after it.
  constexpr size_t kIpcHdr = sizeof(uint8_t) + sizeof(uint16_t);
  if (tag == kIpcTagConnDataOut) {
    // Payload: [u64 conn_id][u32 BE len][len bytes]
    constexpr size_t kConnIdOff = kIpcHdr;
    constexpr size_t kLenOff    = kConnIdOff + sizeof(uint64_t);
    constexpr size_t kDataOff   = kLenOff + sizeof(uint32_t);
    if (body.size() < kDataOff) return;
    uint64_t connId = ces::Buffer::peek<uint64_t>(body.data() + kConnIdOff);
    uint32_t dlen  = ces::Buffer::peek<uint32_t>(body.data() + kLenOff);
    if (body.size() < kDataOff + dlen) return;
    luaHandlerHandleConnDataOut(inst->id, connId,
                                 body.data() + kDataOff, dlen);
    return;
  }
  if (tag == kIpcTagConnClose) {
    if (body.size() < kIpcHdr + sizeof(uint64_t)) return;
    uint64_t connId = ces::Buffer::peek<uint64_t>(body.data() + kIpcHdr);
    luaHandlerHandleConnClose(inst->id, connId);
    return;
  }
  if (tag != kIpcTagApiCall) {
    // Child is only supposed to send API_CALL or one of the lua
    // routing tags above. Anything else is a protocol error.
    LOGDEBUG << "builtin:compute unexpected child tag"
             << VAR(inst->id) << VAR(int(tag));
    killInstanceById(inst->id);
    return;
  }
  if (body.size() < 5) {
    sendApiReply(inst, corr, kApiStatusInternal);
    return;
  }
  handleChildApiCall(inst, corr, body.data() + 3, body.size() - 3);
}

void handleChildApiCall(std::shared_ptr<Instance> inst,
                        uint16_t corr_id,
                        const uint8_t* args, size_t argsLen) {
  if (argsLen < 2) { sendApiReply(inst, corr_id, kApiStatusInternal); return; }
  uint16_t method = ces::Buffer::peek<uint16_t>(args);
  const uint8_t* mbody = args + 2;
  size_t mlen = argsLen - 2;
  if (method == kApiMethodClientSend) {
    // Body: [8B target_pfx][u16 BE len][bytes]
    if (mlen < sizeof(uint64_t) + sizeof(uint16_t)) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }
    HashPrefix target{};
    std::memcpy(target.data(), mbody, 8);
    uint16_t plen = ces::Buffer::peek<uint16_t>(mbody + 8);
    if (plen > kAppPayloadMax) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }
    if (mlen < size_t(sizeof(uint64_t) + sizeof(uint16_t) + plen)) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }
    const uint8_t* payload = mbody + 10;
    // Build the CES_APP_COMPUTE_MSG packet. Wire format (app-data,
    // after MINX strips its opcode byte):
    //   [1B flags=0][8B prog_pfx][2B len BE][N payload]
    minx::Bytes pkt;
    ces::Buffer::put<uint8_t>(pkt, 0); // flags
    pkt.insert(pkt.end(),
               inst->progPrefix.begin(), inst->progPrefix.end());
    ces::Buffer::put<uint16_t>(pkt, plen);
    pkt.insert(pkt.end(),
               reinterpret_cast<const char*>(payload),
               reinterpret_cast<const char*>(payload) + plen);
    CesServer* server = gServer.load();
    bool ok = server && server->send(target, CES_APP_COMPUTE_MSG, pkt);
    sendApiReply(inst, corr_id,
                 ok ? kApiStatusOk : kApiStatusNotConnected);
    return;
  }

  // ---- ces.transfer(target_pubkey, amount). Origin is the file's
  // dedicated PROGRAM account (ces.program_pubkey()), NOT the owner —
  // the program spends its own bankroll, not the deployer's wallet. This
  // is what makes a deposit-funded game like /s/dice net-zero: bets are
  // transferred into the program account and winnings are paid back out
  // of it. (File-store ops are the ones billed to the owner's authority;
  // transfers are not.) On /s/ the boot reconcile auto-tops the program
  // account; off /s/ the deployer funds it with `cesh file deposit`.
  // Reply: [u8 status][u64 BE new_origin_balance].
  if (method == kApiMethodTransfer) {
    if (mlen < ces::KEY_SIZE + sizeof(uint64_t)) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }
    minx::Hash dest{};
    std::memcpy(dest.data(), mbody, 32);
    uint64_t amount = ces::Buffer::peek<uint64_t>(mbody + 32);
    CesServer* server = gServer.load();
    if (!server) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }
    // Origin = the file's program account.
    minx::Hash origin{};
    std::memcpy(origin.data(), inst->programPubkey.data(), 32);
    auto inst_cap = inst;
    server->_l2Transfer(origin, dest, amount,
      [inst_cap, corr_id](uint8_t rc, int64_t newBal) {
        ces::Bytes tail;
        ces::Buffer::put<uint64_t>(tail, static_cast<uint64_t>(
          newBal < 0 ? 0 : newBal));
        sendApiReplyWithBody(inst_cap, corr_id, rc, tail);
      },
      inst->peer->get_executor());
    return;
  }

  // ---- ces.cross_transfer(dest_pubkey, amount, dest_server). The home
  // server is the cross-transfer originator: debit the program's account
  // here, settle `amount` to `dest` on peer `dest_server`. Origin = the
  // program account, same as ces.transfer.
  // Args: [32B dest][u64 amount][u8 srv_len][srv]. Reply: [u8 status][u64 BE bal].
  if (method == kApiMethodCrossTransfer) {
    if (mlen < ces::KEY_SIZE + sizeof(uint64_t) + 1) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }
    uint8_t srvLen = mbody[ces::KEY_SIZE + sizeof(uint64_t)];
    if (srvLen == 0 ||
        mlen < ces::KEY_SIZE + sizeof(uint64_t) + 1 + srvLen) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }
    minx::Hash dest{};
    std::memcpy(dest.data(), mbody, 32);
    uint64_t amount = ces::Buffer::peek<uint64_t>(mbody + 32);
    std::string destServer(
      reinterpret_cast<const char*>(mbody + ces::KEY_SIZE + sizeof(uint64_t) + 1),
      srvLen);
    CesServer* server = gServer.load();
    if (!server) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }
    minx::Hash origin{};
    std::memcpy(origin.data(), inst->programPubkey.data(), 32);
    auto inst_cap = inst;
    server->_l2CrossTransfer(origin, dest, amount, destServer,
      [inst_cap, corr_id](uint8_t rc, int64_t newBal) {
        ces::Bytes tail;
        ces::Buffer::put<uint64_t>(tail, static_cast<uint64_t>(
          newBal < 0 ? 0 : newBal));
        sendApiReplyWithBody(inst_cap, corr_id, rc, tail);
      },
      inst->peer->get_executor());
    return;
  }

  // ---- ces.random_bytes(n). Pulls n ≤ 256 bytes from the host's
  // thread-local AutoSeededRandomPool (CryptoPP). Synchronous — no
  // strand hop.
  // Reply: [u8 status][n bytes].
  if (method == kApiMethodRandomBytes) {
    if (mlen < 2) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }
    uint16_t n = ces::Buffer::peek<uint16_t>(mbody);
    if (n == 0 || n > 256) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }
    ces::Bytes tail(n);
    ces::getThreadLocalPRNG().GenerateBlock(
      reinterpret_cast<CryptoPP::byte*>(tail.data()), n);
    sendApiReplyWithBody(inst, corr_id, kApiStatusOk, tail);
    return;
  }

  // ---- ces.bucket_new(ttl_secs, max_entries, max_entry_bytes).
  // Per-instance rotating cache; entries last between ttl_secs and
  // 2×ttl_secs. Worst-case footprint = max_entries × max_entry_bytes
  // is what the supervisor bills against (predictable capacity rent),
  // not actual fill — so a program declares its budget upfront.
  //   Args: [u32 BE ttl_secs][u32 BE max_entries][u32 BE max_entry_bytes]
  //   Reply: [u8 status][u32 BE bucket_id]
  if (method == kApiMethodBucketNew) {
    if (mlen < sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t)) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }
    uint32_t ttl  = ces::Buffer::peek<uint32_t>(mbody);
    uint32_t maxE = ces::Buffer::peek<uint32_t>(mbody + 4);
    uint32_t maxB = ces::Buffer::peek<uint32_t>(mbody + 8);
    if (ttl == 0 || maxE == 0 || maxB == 0 ||
        maxE > 1'000'000 || maxB > 65'536) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }
    uint32_t id = inst->nextBucketId++;
    Instance::LuaBucket lb;
    lb.cache = std::make_shared<BucketCache<std::string, std::string>>(
      maxE, static_cast<int64_t>(ttl));
    lb.maxEntries = maxE;
    lb.maxEntryBytes = maxB;
    lb.committedBytes =
      static_cast<uint64_t>(maxE) * static_cast<uint64_t>(maxB);
    inst->buckets[id] = std::move(lb);
    ces::Bytes tail;
    ces::Buffer::put<uint32_t>(tail, id);
    sendApiReplyWithBody(inst, corr_id, kApiStatusOk, tail);
    return;
  }

  // ---- ces.bucket_put(handle, key, value).
  // klen + vlen must fit in the bucket's declared max_entry_bytes
  // (the per-entry budget the program committed to at bucket_new).
  //   Args: [u32 BE bucket_id][u16 BE klen][k][u32 BE vlen][v]
  //   Reply: [u8 status]
  if (method == kApiMethodBucketPut) {
    if (mlen < sizeof(uint32_t) + sizeof(uint16_t)) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }
    uint32_t id = ces::Buffer::peek<uint32_t>(mbody);
    size_t off = 4;
    uint16_t klen = ces::Buffer::peek<uint16_t>(mbody + off); off += 2;
    if (off + klen + 4 > mlen) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }
    std::string key(reinterpret_cast<const char*>(mbody + off), klen);
    off += klen;
    uint32_t vlen = ces::Buffer::peek<uint32_t>(mbody + off); off += 4;
    if (off + vlen > mlen) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }
    auto it = inst->buckets.find(id);
    if (it == inst->buckets.end()) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }
    if (klen + vlen > it->second.maxEntryBytes) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }
    std::string val(reinterpret_cast<const char*>(mbody + off), vlen);
    it->second.cache->put(key, val);
    sendApiReply(inst, corr_id, kApiStatusOk);
    return;
  }

  // ---- ces.bucket_get(handle, key).
  //   Args: [u32 BE bucket_id][u16 BE klen][k]
  //   Reply: [u8 status][u8 found_flag][u32 BE vlen][v]
  // status is OK whether found or not; the found_flag distinguishes.
  // Internal status only on malformed args / bad handle.
  if (method == kApiMethodBucketGet) {
    if (mlen < sizeof(uint32_t) + sizeof(uint16_t)) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }
    uint32_t id = ces::Buffer::peek<uint32_t>(mbody);
    size_t off = 4;
    uint16_t klen = ces::Buffer::peek<uint16_t>(mbody + off); off += 2;
    if (off + klen > mlen) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }
    std::string key(reinterpret_cast<const char*>(mbody + off), klen);
    auto it = inst->buckets.find(id);
    if (it == inst->buckets.end()) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }
    auto v = it->second.cache->get(key);
    ces::Bytes tail;
    if (v.has_value()) {
      tail.push_back(1);
      ces::Buffer::put<uint32_t>(tail, static_cast<uint32_t>(v->size()));
      tail.insert(tail.end(), v->begin(), v->end());
    } else {
      tail.push_back(0);
    }
    sendApiReplyWithBody(inst, corr_id, kApiStatusOk, tail);
    return;
  }

  // ---- ces.account_read(pubkey). Read-only ledger access. No fee.
  // Reply: [u8 status][i64 BE balance][u32 BE nonce]
  //        [8B last_xfer_dest][u64 BE last_xfer_amount]
  //        [u32 BE last_xfer_time].
  if (method == kApiMethodAccountRead) {
    if (mlen < 32) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }
    minx::Hash key{};
    std::memcpy(key.data(), mbody, 32);
    CesServer* server = gServer.load();
    if (!server) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }
    auto inst_cap = inst;
    server->_l2QueryAccount(key,
      [inst_cap, corr_id](int64_t bal, uint32_t nonce,
                          HashPrefix lastDest, uint64_t lastAmount,
                          uint32_t lastTime) {
        ces::Bytes tail;
        // Cast int64 → uint64 bit-pattern preserves sign for the
        // child's 8-byte read. Account balances on the wire are
        // signed (payment accounts); ces.account_read on the Lua
        // side returns a Lua number, which is float-double — fine
        // for everyday balances, may lose precision past 2^53. The
        // dice game's bet sizes are far below that.
        ces::Buffer::put<uint64_t>(tail, static_cast<uint64_t>(bal));
        ces::Buffer::put<uint32_t>(tail, nonce);
        tail.insert(tail.end(), lastDest.begin(), lastDest.end());
        ces::Buffer::put<uint64_t>(tail, lastAmount);
        ces::Buffer::put<uint32_t>(tail, lastTime);
        sendApiReplyWithBody(inst_cap, corr_id, kApiStatusOk, tail);
      },
      inst->peer->get_executor());
    return;
  }

  // ---- ces.peers() → the server's peer-table snapshot.
  //   Request: (no args)
  //   Reply body (after the u8 status): [u16 count] then per peer
  //     [32B ckey][u16 addr_len][addr][u8 flags][u16 rpc_port]
  //     flags: bit0 reachable, bit1 verified, bit2 outbound, bit3 inbound
  //   Same data as the public CES_QUERY_PEER_INFO opcode; _peerSnapshot()
  //   locks the peer-table mutex internally, so it is safe off logicStrand_.
  if (method == kApiMethodPeers) {
    CesServer* server = gServer.load();
    if (!server) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }
    auto peers = server->_peerSnapshot();
    ces::Bytes body;
    ces::Buffer::put<uint16_t>(body, static_cast<uint16_t>(peers.size()));
    for (const auto& p : peers) {
      body.insert(body.end(), p.ckey.begin(), p.ckey.end());
      ces::Buffer::put<uint16_t>(
        body, static_cast<uint16_t>(p.declaredAddress.size()));
      body.insert(body.end(), p.declaredAddress.begin(),
                  p.declaredAddress.end());
      uint8_t flags = 0;
      if (p.reachable) flags |= 0x01;
      if (p.verified)  flags |= 0x02;
      if (p.outbound)  flags |= 0x04;
      if (p.inbound)   flags |= 0x08;
      body.push_back(flags);
      ces::Buffer::put<uint16_t>(body, p.rpcPort);
    }
    sendApiReplyWithBody(inst, corr_id, kApiStatusOk, body);
    return;
  }

  // ---- ces.authentic_asset_create(asset_id, recipient_pubkey,
  //                                  payload, days).
  //   Request: [32B asset_id][32B recipient_pubkey][u16 BE days][payload <= 178B]
  //   Reply:   [u8 status]      (CES_OK or error_code_t)
  if (method == kApiMethodAuthenticAssetCreate) {
    constexpr size_t kAuthHeaderLen =
        sizeof(minx::Hash) + ces::KEY_SIZE + sizeof(uint16_t);
    if (mlen < kAuthHeaderLen) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }
    minx::Hash assetId{};
    std::memcpy(assetId.data(), mbody, 32);
    minx::Hash recipient{};
    std::memcpy(recipient.data(), mbody + 32, 32);
    uint16_t days = ces::Buffer::peek<uint16_t>(mbody + 64);
    const uint8_t* payload = mbody + kAuthHeaderLen;
    size_t payloadLen = mlen - kAuthHeaderLen;
    if (payloadLen > AUTHENTIC_ASSET_PAYLOAD_SIZE) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }

    CesServer* server = gServer.load();
    if (!server) {
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
    }

    // Lookup (or compute on first use) the program-identity hash
    // from the source file's sidecar. Done synchronously here on
    // rpcTaskIO_ — it's a single sha256 of a small file (Lua
    // source). After the first hit it's cached in the sidecar.
    std::array<uint8_t, AUTHENTIC_ASSET_HASH_SIZE> progHash{};
    if (!fileHandlerGetProgramHash(inst->sourceName, progHash)) {
      sendApiReply(inst, corr_id, CES_ERROR_INTERNAL); return;
    }

    // Assemble the 210-byte content: [32B programHash][payload, zero-padded].
    AssetData content{};
    std::memcpy(content.data(), progHash.data(), AUTHENTIC_ASSET_HASH_SIZE);
    if (payloadLen > 0)
      std::memcpy(content.data() + AUTHENTIC_ASSET_HASH_SIZE, payload, payloadLen);

    // IMMUTABLE; not private, not asset-owned. createAsset adds the
    // standard 1-day grace and re-derives the flags from this balance.
    uint16_t balance = assetBalance(days, /*priv=*/false, /*aowned=*/false,
                                    /*immutable=*/true);

    // Origin = the file's program account.
    minx::Hash origin{};
    std::memcpy(origin.data(), inst->programPubkey.data(), 32);
    HashPrefix recipientPrefix = ces::Account::getMapKey(recipient);

    auto inst_cap = inst;
    server->createAssetAsync(
      origin, recipientPrefix, assetId, content, balance,
      [inst_cap, corr_id](uint8_t rc) {
        sendApiReply(inst_cap, corr_id, rc);
      },
      inst->peer->get_executor());
    return;
  }

  // ---- File verbs. Reply tail formats are verb-specific (see each
  // case); reply status is a raw error_code_t (CES_OK = 0x00 on
  // success; any non-zero is a file-handler error, e.g.
  // FILE_NOT_FOUND=0x16, NOT_OWNER=0x0a, INSUFFICIENT_BALANCE=0x03,
  // BAD_NAME=0x18). The Lua side exposes this as the first return
  // value of ces.file_*.

  // Helper: parse [u16 BE name_len][name] starting at mbody+start.
  // Returns true with outName populated, false on malformed.
  auto parseName = [](const uint8_t* mbody, size_t mlen, size_t& off,
                      std::string& outName) -> bool {
    if (off + 2 > mlen) return false;
    uint16_t nl = ces::Buffer::peek<uint16_t>(mbody + off);
    off += 2;
    if (nl == 0 || off + nl > mlen) return false;
    outName.assign(reinterpret_cast<const char*>(mbody + off), nl);
    off += nl;
    return true;
  };

  CesServer* server = gServer.load();
  if (!server) {
    sendApiReply(inst, corr_id, kApiStatusInternal); return;
  }
  auto cbEx = inst->peer->get_executor();

  FileExecReq req{};
  req.ownerPubkey = inst->ownerPk;
  req.sourceName = inst->sourceName;

  size_t off = 0;
  switch (method) {
    case kApiMethodFileStat: {
      if (!parseName(mbody, mlen, off, req.name)) {
        sendApiReply(inst, corr_id, kApiStatusInternal); return;
      }
      req.verb = kFileVerbStat;
      break;
    }
    case kApiMethodFileRead: {
      if (mlen < sizeof(uint64_t) + sizeof(uint32_t)) {
        sendApiReply(inst, corr_id, kApiStatusInternal); return;
      }
      req.offset = ces::Buffer::peek<uint64_t>(mbody + off); off += 8;
      req.length = ces::Buffer::peek<uint32_t>(mbody + off); off += 4;
      if (!parseName(mbody, mlen, off, req.name)) {
        sendApiReply(inst, corr_id, kApiStatusInternal); return;
      }
      req.verb = kFileVerbRead;
      break;
    }
    case kApiMethodFileWrite: {
      if (mlen < 8) {
        sendApiReply(inst, corr_id, kApiStatusInternal); return;
      }
      req.offset = ces::Buffer::peek<uint64_t>(mbody + off); off += 8;
      if (!parseName(mbody, mlen, off, req.name)) {
        sendApiReply(inst, corr_id, kApiStatusInternal); return;
      }
      if (off + 4 > mlen) {
        sendApiReply(inst, corr_id, kApiStatusInternal); return;
      }
      uint32_t blen = ces::Buffer::peek<uint32_t>(mbody + off); off += 4;
      if (off + blen > mlen) {
        sendApiReply(inst, corr_id, kApiStatusInternal); return;
      }
      req.body.assign(mbody + off, mbody + off + blen);
      off += blen;
      req.verb = kFileVerbWrite;
      break;
    }
    case kApiMethodFileAppend: {
      if (!parseName(mbody, mlen, off, req.name)) {
        sendApiReply(inst, corr_id, kApiStatusInternal); return;
      }
      if (off + 4 > mlen) {
        sendApiReply(inst, corr_id, kApiStatusInternal); return;
      }
      uint32_t blen = ces::Buffer::peek<uint32_t>(mbody + off); off += 4;
      if (off + blen > mlen) {
        sendApiReply(inst, corr_id, kApiStatusInternal); return;
      }
      req.body.assign(mbody + off, mbody + off + blen);
      off += blen;
      req.verb = kFileVerbAppend;
      break;
    }
    case kApiMethodFileCreate: {
      if (mlen < sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint64_t)) {
        sendApiReply(inst, corr_id, kApiStatusInternal); return;
      }
      req.size           = ces::Buffer::peek<uint64_t>(mbody + off); off += 8;
      req.pricePerKb     = ces::Buffer::peek<uint64_t>(mbody + off); off += 8;
      req.initialDeposit = ces::Buffer::peek<uint64_t>(mbody + off); off += 8;
      if (!parseName(mbody, mlen, off, req.name)) {
        sendApiReply(inst, corr_id, kApiStatusInternal); return;
      }
      req.verb = kFileVerbCreate;
      break;
    }
    case kApiMethodFileDeposit:
    case kApiMethodFileWithdraw: {
      if (mlen < 8) {
        sendApiReply(inst, corr_id, kApiStatusInternal); return;
      }
      req.amount = ces::Buffer::peek<uint64_t>(mbody + off); off += 8;
      if (!parseName(mbody, mlen, off, req.name)) {
        sendApiReply(inst, corr_id, kApiStatusInternal); return;
      }
      req.verb = (method == kApiMethodFileDeposit)
        ? kFileVerbDeposit : kFileVerbWithdraw;
      break;
    }
    case kApiMethodFileSetPrice: {
      if (mlen < 8) {
        sendApiReply(inst, corr_id, kApiStatusInternal); return;
      }
      req.pricePerKb = ces::Buffer::peek<uint64_t>(mbody + off); off += 8;
      if (!parseName(mbody, mlen, off, req.name)) {
        sendApiReply(inst, corr_id, kApiStatusInternal); return;
      }
      req.verb = kFileVerbSetPrice;
      break;
    }
    case kApiMethodFileDelete: {
      if (!parseName(mbody, mlen, off, req.name)) {
        sendApiReply(inst, corr_id, kApiStatusInternal); return;
      }
      req.verb = kFileVerbDelete;
      break;
    }
    case kApiMethodFileResize: {
      if (mlen < 8) {
        sendApiReply(inst, corr_id, kApiStatusInternal); return;
      }
      req.size = ces::Buffer::peek<uint64_t>(mbody + off); off += 8;
      if (!parseName(mbody, mlen, off, req.name)) {
        sendApiReply(inst, corr_id, kApiStatusInternal); return;
      }
      req.verb = kFileVerbResize;
      break;
    }
    default:
      sendApiReply(inst, corr_id, kApiStatusInternal); return;
  }

  // Dispatch to the in-process file primitive. Callback builds the
  // method-specific reply tail (only on OK) and sends API_REPLY.
  uint16_t saved_method = method;
  auto inst_cap = inst;
  fileHandlerExec(req,
    [inst_cap, corr_id, saved_method](FileExecResp resp) {
      if (resp.status != CES_OK) {
        sendApiReply(inst_cap, corr_id, resp.status);
        return;
      }
      ces::Bytes tail;
      switch (saved_method) {
        case kApiMethodFileStat: {
          tail.insert(tail.end(),
            resp.ownerPubkey.begin(), resp.ownerPubkey.end());
          ces::Buffer::put<uint64_t>(tail, resp.fileBalance);
          ces::Buffer::put<uint64_t>(tail, resp.pricePerKb);
          ces::Buffer::put<uint64_t>(tail, resp.size);
          ces::Buffer::put<uint64_t>(tail, resp.createdUs);
          ces::Buffer::put<uint64_t>(tail, resp.modifiedUs);
          break;
        }
        case kApiMethodFileRead: {
          ces::Buffer::put<uint32_t>(tail, static_cast<uint32_t>(resp.data.size()));
          tail.insert(tail.end(), resp.data.begin(), resp.data.end());
          break;
        }
        case kApiMethodFileCreate:
        case kApiMethodFileWrite:
        case kApiMethodFileDeposit:
        case kApiMethodFileWithdraw: {
          ces::Buffer::put<uint64_t>(tail, resp.fileBalance);
          break;
        }
        case kApiMethodFileSetPrice: {
          ces::Buffer::put<uint64_t>(tail, resp.pricePerKb);
          break;
        }
        case kApiMethodFileDelete: {
          ces::Buffer::put<uint64_t>(tail, resp.refunded);
          break;
        }
        case kApiMethodFileAppend:
        case kApiMethodFileResize: {
          ces::Buffer::put<uint64_t>(tail, resp.fileBalance);
          ces::Buffer::put<uint64_t>(tail, resp.size);
          break;
        }
        default: break;
      }
      sendApiReplyWithBody(inst_cap, corr_id, resp.status, tail);
    }, cbEx);
}

// Read the Lua source from disk for a source-file path (e.g.
// /h/<hex>/echo.lua). Returns empty vector on any failure. The
// handler is the caller; it already validated that the file exists
// via fileHandlerReadOwnerAndBalance.
ces::Bytes readSourceBytes(const CesConfig& cfg,
                                     const std::string& name) {
  auto p = std::filesystem::path(cfg.cesFileStoreDir) /
           name.substr(1);   // name is "/h/..."; drop the leading /
  std::ifstream f(p, std::ios::binary);
  if (!f) return {};
  ces::Bytes out(
    (std::istreambuf_iterator<char>(f)),
    std::istreambuf_iterator<char>());
  return out;
}

// ---------------------------------------------------------------------------
// Verb dispatch — the signed-request loop lives in the CesPlex framework
// (cesPlexServe / CesPlexRequest, see cesplex/mux.h). ReqCtx aliases
// the framework request so the dispatchers below need no changes; the
// thin senders forward to its respond/error helpers.
// ---------------------------------------------------------------------------

using ReqCtx = ces::CesPlexRequest;

// The CesPlex bus is host-generic (it knows only CesPlexHost). builtin:compute
// is a CES core feature, so its host is always the CesServer — recover the
// concrete server for the ledger-facing calls below.
inline CesServer* reqServer(const std::shared_ptr<ReqCtx>& ctx) {
  return static_cast<CesServer*>(ctx->host);
}

inline void sendResponseAndLoop(std::shared_ptr<ReqCtx> ctx, uint8_t status,
                                ces::Bytes preamble) {
  ctx->respond(status, std::move(preamble));
}
inline void sendErrorAndLoop(std::shared_ptr<ReqCtx> ctx, uint8_t status) {
  ctx->error(status);
}

// Verb dispatch forward decls.
void dispatchLaunch    (std::shared_ptr<ReqCtx> ctx, ces::Bytes pre);
void dispatchKill      (std::shared_ptr<ReqCtx> ctx, ces::Bytes pre);
void dispatchList      (std::shared_ptr<ReqCtx> ctx, ces::Bytes pre);
void dispatchStat      (std::shared_ptr<ReqCtx> ctx, ces::Bytes pre);
void dispatchInstances (std::shared_ptr<ReqCtx> ctx, ces::Bytes pre);

// ---------------------------------------------------------------------------
// Helper: compute slot-fee window in credits.
// ---------------------------------------------------------------------------

uint64_t slotFeePerSec(const CesConfig& cfg) {
  int64_t s = cfg.feeComputeSlotSec;
  if (s <= 0) {
    // Derive: rent on a nominal 1 KB file per second.
    // feeFileRent is credits per (byte × day). Seconds-per-day = 86400.
    // result = feeFileRent * 1024 / 86400, floored to >= 1.
    int64_t rent = cfg.feeFileRent;
    if (rent <= 0) rent = 1;
    int64_t v = (rent * 1024) / 86'400;
    if (v < 1) v = 1;
    return static_cast<uint64_t>(v);
  }
  return static_cast<uint64_t>(s);
}

// ---------------------------------------------------------------------------
// LAUNCH
// ---------------------------------------------------------------------------

// In-flight LAUNCH accept state. Held by shared_ptr so the async_accept
// completion and the deadline timer share one `finished` guard —
// whichever fires first wins, the other no-ops. Everything runs on
// rpcTaskIO_, so the bool needs no atomic.
struct LaunchAccept {
  std::shared_ptr<Instance> inst;
  std::shared_ptr<UnixAcceptor> acceptor;
  std::shared_ptr<UnixSocket> peer;
  std::shared_ptr<boost::asio::steady_timer> timer;
  ces::Bytes src;
  std::function<void(uint64_t)> done;
  uint64_t now = 0;
  uint64_t upfront = 0;
  bool finished = false;
  std::shared_ptr<LaunchSlot> slot;
  std::shared_ptr<PortLease> portLease;
  std::shared_ptr<PortLease> rpcPortLease;
};

// Strand-only (rpcTaskIO_). Allocate a fresh instance, spawn the child
// binary, and asynchronously await its connect-back on the per-instance
// Unix socket. On success: register in gInstances, send the bootstrap
// frame, arm the IPC reader, invoke `done(id)`. On any failure:
// `done(0)` after tearing down whatever was allocated.
//
// The connect-back is awaited via async_accept bounded by a
// kAcceptTimeoutMs timer — it must NEVER block rpcTaskIO_, which also
// drives every other CesPlex channel, ChannelMeter, and the
// supervisor. (The old synchronous poll()-accept stalled all of them
// for up to kAcceptTimeoutMs on every launch.)
//
// Caller has already validated source-file existence + ownership and
// (if applicable) debited the upfront commitment fee from file_balance.
// `upfront` is recorded on the Instance for visibility, not debited
// here. `now` is the instance's birth wall-clock and the start of its
// first billing tick.
void allocateAndSpawnInstance(
    CesServer* server, const std::string& name,
    const std::array<uint8_t, 32>& ownerPk,
    uint64_t upfront, uint64_t now,
    std::shared_ptr<LaunchSlot> slot,
    std::shared_ptr<PortLease> portLease,
    std::shared_ptr<PortLease> rpcPortLease,
    std::function<void(uint64_t id)> done) {
  const auto& cfg = server->_config();

  auto workDir = resolveWorkDir(cfg);
  std::error_code ec;
  std::filesystem::create_directories(workDir, ec);

  // Read the source's program-account keypair from its sidecar.
  std::array<uint8_t, 32> programPubkey{};
  std::array<uint8_t, 32> programPrivkey{};
  fileHandlerReadProgramPubkey(name, programPubkey);
  fileHandlerReadProgramPrivkey(name, programPrivkey);

  uint64_t id = gNextInstanceId++;
  auto inst = std::make_shared<Instance>();
  inst->id = id;
  inst->sourceName = name;
  inst->ownerPk = ownerPk;
  inst->programPubkey = programPubkey;
  inst->programPrivkey = programPrivkey;
  inst->progPrefix = progPrefixOf(name);
  inst->socketPath = instanceSocketPath(cfg, id).string();
  inst->upfrontDeposit = upfront;

  int lfd = createListenSocket(inst->socketPath);
  if (lfd < 0) {
    LOGWARNING << "builtin:compute socket create failed" << VAR(lfd);
    done(0);
    return;
  }

  // Slurp the Lua source before spawning — if the source file is gone
  // or unreadable on disk, fail cleanly rather than after spawning a
  // child with nothing to run.
  auto srcBytes = readSourceBytes(cfg, name);
  if (srcBytes.empty()) {
    LOGWARNING << "builtin:compute source read failed" << SVAR(name);
    ::close(lfd);
    teardownInstance(*inst);
    done(0);
    return;
  }

  pid_t pid = spawnChild(cfg.cesComputeChildBinary,
                         inst->socketPath,
                         cfg.cesComputeUser,
                         cfg.computeProcessMemMax);
  if (pid <= 0) {
    LOGWARNING << "builtin:compute spawn failed"
               << VAR(pid) << SVAR(cfg.cesComputeChildBinary);
    ::close(lfd);
    teardownInstance(*inst);
    done(0);
    return;
  }
  inst->pid = pid;

  auto io = server->_rpcTaskIOExecutor();
  auto st = std::make_shared<LaunchAccept>();
  st->inst = inst;
  st->acceptor = std::make_shared<UnixAcceptor>(io);
  st->peer = std::make_shared<UnixSocket>(io);
  st->timer = std::make_shared<boost::asio::steady_timer>(io);
  st->src = std::move(srcBytes);
  st->done = std::move(done);
  st->now = now;
  st->upfront = upfront;
  st->slot = std::move(slot);
  st->portLease = std::move(portLease);
  st->rpcPortLease = std::move(rpcPortLease);

  // Adopt the listen fd into the acceptor — it now owns + closes it.
  boost::system::error_code aec;
  st->acceptor->assign(boost::asio::local::stream_protocol(), lfd, aec);
  if (aec) {
    LOGWARNING << "builtin:compute acceptor assign failed"
               << SVAR(aec.message());
    ::close(lfd);
    killAndReap(pid);
    teardownInstance(*inst);
    st->done(0);
    return;
  }

  // Deadline: the child must connect back within kAcceptTimeoutMs. On
  // expiry, abort the accept, reap the child, tear the instance down.
  st->timer->expires_after(std::chrono::milliseconds(kAcceptTimeoutMs));
  st->timer->async_wait([st](const boost::system::error_code& tec) {
    if (tec || st->finished) return;
    st->finished = true;
    boost::system::error_code ig;
    st->acceptor->close(ig);
    LOGWARNING << "builtin:compute accept timed out" << VAR(st->inst->id);
    killAndReap(st->inst->pid);
    teardownInstance(*st->inst);
    st->done(0);
  });

  // Async accept the child's connect-back. Never blocks the strand.
  st->acceptor->async_accept(
    *st->peer,
    [st](const boost::system::error_code& cec) {
      if (st->finished) return;
      st->finished = true;
      boost::system::error_code ig;
      st->timer->cancel(ig);
      st->acceptor->close(ig);
      auto inst = st->inst;
      if (cec) {
        LOGWARNING << "builtin:compute accept failed" << SVAR(cec.message());
        killAndReap(inst->pid);
        teardownInstance(*inst);
        st->done(0);
        return;
      }
      // Handler unbound mid-launch (server shutting down): don't register
      // a zombie into gInstances after teardown ran.
      if (gServer.load() == nullptr) {
        killAndReap(inst->pid);
        teardownInstance(*inst);
        st->done(0);
        return;
      }
      inst->peer = st->peer;
      inst->startedAtUs = st->now;
      inst->lastTickUs = st->now;
      inst->lastSampleUs = st->now;
      inst->lastCpuTicks = 0;

      // Commit the reserved port to the instance: killInstanceById now
      // owns freeing it, so the lease must not also free it on drop.
      inst->clientPort = st->portLease->port;
      st->portLease->commit();
      inst->rpcPort = st->rpcPortLease->port;
      st->rpcPortLease->commit();

      gInstances[inst->id] = inst;
      gByPrefix[inst->progPrefix].insert(inst->id);
      gByName[inst->sourceName].insert(inst->id);
      // Registered in gInstances now — drop the launch-slot reservation
      // so it isn't double-counted against the cap.
      st->slot.reset();

      // Bootstrap the child with its Lua source + identity (incl. the
      // assigned client port), then arm the IPC reader loop.
      sendBootstrapFrame(inst, st->src.data(), st->src.size());
      startIpcReader(inst);

      LOGINFO << "builtin:compute launched"
              << VAR(inst->id) << SVAR(inst->sourceName)
              << VAR(inst->pid) << VAR(st->upfront);
      st->done(inst->id);
    });
}

void dispatchLaunch(std::shared_ptr<ReqCtx> ctx, ces::Bytes pre) {
  if (pre.size() < 2) {
    sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
  }
  uint16_t nameLen = ces::Buffer::peek<uint16_t>(pre.data());
  if (nameLen == 0 || nameLen > kMaxNameLen || pre.size() < sizeof(uint16_t) + nameLen) {
    sendErrorAndLoop(ctx, CES_ERROR_BAD_NAME); return;
  }
  std::string name(reinterpret_cast<const char*>(pre.data() + 2), nameLen);

  const auto& cfg = reqServer(ctx)->_config();

  // Check instance cap against registered + in-flight launches. LAUNCH
  // always mints a fresh id; multiple instances of the same source path
  // are allowed up to the cap.
  if (launchSlotsInUse() >= cfg.computeMaxInstances) {
    sendErrorAndLoop(ctx, CES_ERROR_COMPUTE_MAX_INSTANCES); return;
  }

  // Source-file owner + balance check via the file handler.
  std::array<uint8_t, 32> ownerPk{};
  uint64_t fileBalance = 0;
  if (!fileHandlerReadOwnerAndBalance(name, ownerPk, fileBalance)) {
    sendErrorAndLoop(ctx, CES_ERROR_FILE_NOT_FOUND); return;
  }
  if (std::memcmp(ownerPk.data(), ctx->bound.boundPubkey.getHash().data(), 32) != 0) {
    sendErrorAndLoop(ctx, CES_ERROR_NOT_OWNER); return;
  }
  // /s/ programs are operator-deployed and unmetered: supervisor billing
  // no-ops on them (their file_balance is decorative), so the LAUNCH-time
  // upfront commitment must be waived too. Otherwise a /s/ program -- the
  // "ships standard" model (dht, dice) -- cannot be launched via the explicit
  // verb at all, only via the internal builtin-app path.
  const bool serverZone = isServerZone(name);

  // Discounted slot rate for the upfront commitment (LAUNCH-time price).
  uint64_t slot = reqServer(ctx)->discountFee(
    FeeKind::ComputeSlot, slotFeePerSec(cfg));
  uint64_t upfront = serverZone ? 0 : slot * kUpfrontSeconds;

  if (!serverZone && fileBalance < upfront) {
    sendErrorAndLoop(ctx, CES_ERROR_COMPUTE_FUND_TOO_LOW); return;
  }

  // Compute dedup hash + signer for the _l2 call.
  const ces::PublicKey& signer = ctx->bound.boundPubkey;

  // Claim the child's outbound-client port from the configured range,
  // best-effort. An exhausted (or zero) range leaves clientPort 0; the
  // instance still launches — it stays reachable via the server's own rpc
  // port (/ces/lua/1 ATTACH relay), so compute_port_count == 0 is a valid
  // config. Only the child's OUTBOUND remote_* verbs go dark, and they
  // error permanently on port 0.
  uint16_t clientPort = 0;
  allocateComputePort(cfg, clientPort);
  auto portLease = std::make_shared<PortLease>(clientPort);

  // Second best-effort lease: the child's inbound CesPlex host port
  // (/ces/luarpc/1). Independent of clientPort — exhaustion here leaves
  // rpcPort 0 (the instance hosts nothing) without failing the launch.
  uint16_t rpcPort = 0;
  allocateComputePort(cfg, rpcPort);
  auto rpcPortLease = std::make_shared<PortLease>(rpcPort);

  // Reserve a launch slot now and hold it across the async validate +
  // spawn chain (released when the instance registers or the launch
  // fails). Race-free: nothing else runs on this strand between the cap
  // check above and here, so the reservation reflects that decision.
  auto launchSlot = std::make_shared<LaunchSlot>();

  auto after = [ctx, name, upfront, ownerPk, launchSlot, portLease, rpcPortLease](
                   uint8_t rc, bool /*duplicate*/) mutable {
    if (rc != CES_OK) { sendErrorAndLoop(ctx, rc); return; }
    // LAUNCH passes reqNonce=0 (opted out of dedup) so `duplicate` is never
    // true here; each call independently mints + charges a fresh instance.

    // Debit the 15-min upfront from the source file's file_balance.
    // This is a commitment the host honors by starting + monitoring
    // the instance; no refund on KILL.
    if (!fileHandlerDebitBalance(name, upfront)) {
      sendErrorAndLoop(ctx, CES_ERROR_COMPUTE_FUND_TOO_LOW); return;
    }

    uint64_t now = getMicrosSinceEpoch();
    allocateAndSpawnInstance(
      reqServer(ctx), name, ownerPk, upfront, now, std::move(launchSlot),
      std::move(portLease), std::move(rpcPortLease),
      [ctx, now](uint64_t id) {
        if (id == 0) {
          sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
        }
        ces::Bytes resp;
        ces::Buffer::put<uint64_t>(resp, id);
        ces::Buffer::put<uint64_t>(resp, now);
        sendResponseAndLoop(ctx, CES_OK, std::move(resp));
      });
  };

  // LAUNCH is non-idempotent (each call mints a fresh instance), and the
  // NONCELESS sig-dedup can't survive a channel reselect anyway, so opt
  // out of it: pass reqNonce=0 ("no dedup, no nonce ordering") instead of
  // the wire CES_NONCELESS. Every LAUNCH is then independently
  // fee-validated and spawns — a same-name relaunch is a real second
  // instance, charged, not a dedup-skipped freebie that still spawns.
  reqServer(ctx)->_l2ValidateDedupAndDebit(
    signer, static_cast<int64_t>(reqServer(ctx)->discountFee(FeeKind::Query, cfg.feeQuery)),
    /*reqNonce=*/0, getMicrosSinceEpoch(), ctx->reqSigHash,
    std::move(after), ctx->stream->get_executor());
}

// ---------------------------------------------------------------------------
// KILL
// ---------------------------------------------------------------------------

void dispatchKill(std::shared_ptr<ReqCtx> ctx, ces::Bytes pre) {
  // Wire: [u64 instance_id]. Truncated preamble = caller wire-format bug,
  // not a server failure → BAD_INPUT.
  if (pre.size() < 8) { sendErrorAndLoop(ctx, CES_ERROR_BAD_INPUT); return; }
  uint64_t id = ces::Buffer::peek<uint64_t>(pre.data());

  auto it = gInstances.find(id);
  if (it == gInstances.end()) {
    sendErrorAndLoop(ctx, CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND); return;
  }
  if (std::memcmp(it->second->ownerPk.data(), ctx->bound.boundPubkey.getHash().data(), 32) != 0) {
    sendErrorAndLoop(ctx, CES_ERROR_NOT_OWNER); return;
  }

  const auto& cfg = reqServer(ctx)->_config();
  const ces::PublicKey& signer = ctx->bound.boundPubkey;

  auto after = [ctx, id](uint8_t rc, bool duplicate) {
    if (rc != CES_OK) { sendErrorAndLoop(ctx, rc); return; }
    // Duplicate (resent envelope): the kill already committed; don't re-run it
    // (idempotent anyway), just reply OK so the wire shape matches.
    if (duplicate) { sendResponseAndLoop(ctx, CES_OK, {}); return; }
    killInstanceById(id);
    sendResponseAndLoop(ctx, CES_OK, {});
  };

  reqServer(ctx)->_l2ValidateDedupAndDebit(
    signer, static_cast<int64_t>(reqServer(ctx)->discountFee(FeeKind::Query, cfg.feeQuery)),
    ctx->reqNonce, getMicrosSinceEpoch(), ctx->reqSigHash,
    std::move(after), ctx->stream->get_executor());
}

// ---------------------------------------------------------------------------
// LIST
// ---------------------------------------------------------------------------

void dispatchList(std::shared_ptr<ReqCtx> ctx, ces::Bytes /* pre */) {
  const auto& cfg = reqServer(ctx)->_config();
  const ces::PublicKey& signer = ctx->bound.boundPubkey;

  auto after = [ctx](uint8_t rc, bool /*duplicate*/) {
    if (rc != CES_OK) { sendErrorAndLoop(ctx, rc); return; }
    // Read-only: a duplicate just re-reads current state — correct, no skip.
    ces::Bytes resp;
    uint32_t countOff = resp.size();
    ces::Buffer::put<uint32_t>(resp, 0); // placeholder
    uint32_t count = 0;
    for (auto& [id, inst] : gInstances) {
      if (std::memcmp(inst->ownerPk.data(),
                      ctx->bound.boundPubkey.getHash().data(), 32) != 0) continue;
      ces::Buffer::put<uint64_t>(resp, inst->id);
      ces::Buffer::put<uint16_t>(resp, static_cast<uint16_t>(inst->sourceName.size()));
      resp.insert(resp.end(),
                  reinterpret_cast<const uint8_t*>(inst->sourceName.data()),
                  reinterpret_cast<const uint8_t*>(inst->sourceName.data())
                    + inst->sourceName.size());
      ces::Buffer::put<uint64_t>(resp, inst->startedAtUs);
      // file_balance as of now — a convenience for clients. We read
      // it via the file handler (rent-roll included). If the file
      // was deleted out from under us, report 0.
      std::array<uint8_t, 32> opk{};
      uint64_t bal = 0;
      fileHandlerReadOwnerAndBalance(inst->sourceName, opk, bal);
      ces::Buffer::put<uint64_t>(resp, bal);
      // CPU basis points + RSS bytes from last supervisor sample.
      ces::Buffer::put<uint32_t>(resp, inst->cpuBasisPoints);
      ces::Buffer::put<uint64_t>(resp, inst->rssBytes);
      // Leased ports (0 = none): outbound CES-client, inbound luarpc host.
      ces::Buffer::put<uint16_t>(resp, inst->clientPort);
      ces::Buffer::put<uint16_t>(resp, inst->rpcPort);
      resp.insert(resp.end(), inst->programPubkey.begin(), inst->programPubkey.end());
      count++;
    }
    // Patch count.
    ces::Buffer::poke<uint32_t>(resp.data() + countOff, count);
    sendResponseAndLoop(ctx, CES_OK, std::move(resp));
  };

  reqServer(ctx)->_l2ValidateDedupAndDebit(
    signer, static_cast<int64_t>(reqServer(ctx)->discountFee(FeeKind::Query, cfg.feeQuery)),
    ctx->reqNonce, getMicrosSinceEpoch(), ctx->reqSigHash,
    std::move(after), ctx->stream->get_executor());
}

// ---------------------------------------------------------------------------
// STAT
// ---------------------------------------------------------------------------

void dispatchStat(std::shared_ptr<ReqCtx> ctx, ces::Bytes pre) {
  // Wire: [u64 instance_id]. ID is the only identity — a path can refer
  // to N instances, so name-keyed STAT is not well-defined (use INSTANCES).
  // Public: any signer may inspect a live instance — its uptime, last
  // cpu/rss sample, and leased ports — so a running service is discoverable
  // and dialable by anyone. Only LAUNCH/KILL stay owner-gated.
  if (pre.size() < 8) { sendErrorAndLoop(ctx, CES_ERROR_BAD_INPUT); return; }
  uint64_t instanceId = ces::Buffer::peek<uint64_t>(pre.data());

  auto it = gInstances.find(instanceId);
  if (it == gInstances.end()) {
    sendErrorAndLoop(ctx, CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND); return;
  }
  std::string name = it->second->sourceName;

  // file_balance is best-effort: read the sidecar (which also rolls rent),
  // but a missing source file (instance about to be reaped) is not fatal
  // to inspection — report the live instance with balance 0.
  std::array<uint8_t, 32> ownerPk{};
  uint64_t fileBalance = 0;
  fileHandlerReadOwnerAndBalance(name, ownerPk, fileBalance);

  const auto& cfg = reqServer(ctx)->_config();
  const ces::PublicKey& signer = ctx->bound.boundPubkey;

  auto after = [ctx, name, fileBalance, instanceId](uint8_t rc,
                                                    bool /*duplicate*/) {
    if (rc != CES_OK) { sendErrorAndLoop(ctx, rc); return; }
    // Read-only: a duplicate just re-reads current state — correct, no skip.
    auto it = gInstances.find(instanceId);
    if (it == gInstances.end()) {
      sendErrorAndLoop(ctx, CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND); return;
    }
    auto& inst = *it->second;
    ces::Bytes resp;
    ces::Buffer::put<uint64_t>(resp, inst.id);
    ces::Buffer::put<uint64_t>(resp, inst.startedAtUs);
    ces::Buffer::put<uint64_t>(resp, fileBalance);
    ces::Buffer::put<uint32_t>(resp, inst.cpuBasisPoints);
    ces::Buffer::put<uint64_t>(resp, inst.rssBytes);
    // Leased ports (0 = none): outbound CES-client, inbound luarpc host.
    ces::Buffer::put<uint16_t>(resp, inst.clientPort);
    ces::Buffer::put<uint16_t>(resp, inst.rpcPort);
    resp.insert(resp.end(), inst.programPubkey.begin(), inst.programPubkey.end());
    ces::Buffer::put<uint16_t>(resp, static_cast<uint16_t>(name.size()));
    resp.insert(resp.end(),
                reinterpret_cast<const uint8_t*>(name.data()),
                reinterpret_cast<const uint8_t*>(name.data())
                  + name.size());
    sendResponseAndLoop(ctx, CES_OK, std::move(resp));
  };

  // STAT is public to any signer: allow a signer with no account here to read
  // for free (cross-server discovery).
  reqServer(ctx)->_l2ValidateDedupAndDebit(
    signer, static_cast<int64_t>(reqServer(ctx)->discountFee(FeeKind::Query, cfg.feeQuery)),
    ctx->reqNonce, getMicrosSinceEpoch(), ctx->reqSigHash,
    std::move(after), ctx->stream->get_executor(), /*allowMissingOrigin=*/true);
}

// ---------------------------------------------------------------------------
// INSTANCES — public discovery: list ids for a given source path
// ---------------------------------------------------------------------------
//
// Wire in:    [u16 path_len][path]
// Wire out:   [u32 count][u64 id, u64 started_at_us, u32 cpu_bp,
//                         u64 rss_bytes, u16 client_port, u16 rpc_port]*
//
// No owner check, no file-existence check, no path validation beyond
// the length cap. The path is just a key into gByName; absent → empty
// list. Same per-op fee as STAT/LIST so signers can't free-flood the
// lookup, but anyone with a credited account can ask. Each entry carries
// the instance's leased ports so a single call discovers a service AND
// where to dial it (the source path is the query key, so it isn't echoed
// per entry).
void dispatchInstances(std::shared_ptr<ReqCtx> ctx,
                       ces::Bytes pre) {
  if (pre.size() < 2) { sendErrorAndLoop(ctx, CES_ERROR_BAD_INPUT); return; }
  uint16_t nameLen = ces::Buffer::peek<uint16_t>(pre.data());
  if (nameLen == 0 || nameLen > kMaxNameLen ||
      pre.size() < sizeof(uint16_t) + nameLen) {
    sendErrorAndLoop(ctx, CES_ERROR_BAD_NAME); return;
  }
  std::string name(reinterpret_cast<const char*>(pre.data() + 2), nameLen);

  const auto& cfg = reqServer(ctx)->_config();
  const ces::PublicKey& signer = ctx->bound.boundPubkey;

  auto after = [ctx, name](uint8_t rc, bool /*duplicate*/) {
    if (rc != CES_OK) { sendErrorAndLoop(ctx, rc); return; }
    // Read-only: a duplicate just re-reads current state — correct, no skip.
    ces::Bytes resp;
    uint32_t countOff = resp.size();
    ces::Buffer::put<uint32_t>(resp, 0); // placeholder, patched below
    uint32_t count = 0;
    auto it = gByName.find(name);
    if (it != gByName.end()) {
      // std::set ⇒ ascending iteration; clients shouldn't depend on
      // the order. Two clients querying the same path back-to-back
      // see the same list as long as no LAUNCH/KILL hit in between.
      for (uint64_t id : it->second) {
        auto iit = gInstances.find(id);
        if (iit == gInstances.end()) continue;  // index/registry skew
        auto& inst = *iit->second;
        ces::Buffer::put<uint64_t>(resp, inst.id);
        ces::Buffer::put<uint64_t>(resp, inst.startedAtUs);
        ces::Buffer::put<uint32_t>(resp, inst.cpuBasisPoints);
        ces::Buffer::put<uint64_t>(resp, inst.rssBytes);
        ces::Buffer::put<uint16_t>(resp, inst.clientPort);
        ces::Buffer::put<uint16_t>(resp, inst.rpcPort);
        resp.insert(resp.end(), inst.programPubkey.begin(), inst.programPubkey.end());
        count++;
      }
    }
    ces::Buffer::poke<uint32_t>(resp.data() + countOff, count);
    sendResponseAndLoop(ctx, CES_OK, std::move(resp));
  };

  // INSTANCES is public to any signer: allow a signer with no account here
  // (a peer's P2P node discovering us) to read for free.
  reqServer(ctx)->_l2ValidateDedupAndDebit(
    signer, static_cast<int64_t>(reqServer(ctx)->discountFee(FeeKind::Query, cfg.feeQuery)),
    ctx->reqNonce, getMicrosSinceEpoch(), ctx->reqSigHash,
    std::move(after), ctx->stream->get_executor(), /*allowMissingOrigin=*/true);
}

// ---------------------------------------------------------------------------
// Supervisor tick — per-second slot-fee debit + SIGKILL on exhaustion.
// ---------------------------------------------------------------------------

void supervisorTick() {
  CesServer* server = gServer.load();
  if (!server) return;
  const auto& cfg = server->_config();
  uint64_t now = getMicrosSinceEpoch();

  // Discounted rates for this tick. The metrics pulse refreshes the
  // FeeKind multipliers from l2cpu (slot/cpu) and l2mem (rss/bucket),
  // so the supervisor pays "today's price" — no lock-in across ticks.
  uint64_t slot       = server->discountFee(FeeKind::ComputeSlot,
                                            slotFeePerSec(cfg));
  uint64_t rssRate    = server->discountFee(FeeKind::ComputeRss,
    static_cast<uint64_t>(cfg.feeComputeRssByteDay > 0
                            ? cfg.feeComputeRssByteDay : 0));
  uint64_t cpuRate    = server->discountFee(FeeKind::ComputeCpu,
    static_cast<uint64_t>(cfg.feeComputeCpuSec > 0
                            ? cfg.feeComputeCpuSec : 0));
  uint64_t bucketRate = server->discountFee(FeeKind::BucketByteSec,
    static_cast<uint64_t>(cfg.feeBucketByteSec > 0
                            ? cfg.feeBucketByteSec : 0));

  std::vector<uint64_t> toKill;
  for (auto& [id, inst] : gInstances) {
    // One tick: procfs sample (CPU delta + RSS) + compound debit.
    // Runs at cfg.computeTickIntervalMs cadence (default 60 s).
    sampleInstanceProc(*inst, now);
    if (now <= inst->lastTickUs) continue;   // still in prepaid window
    uint64_t elapsedUs = now - inst->lastTickUs;

    // Slot: flat overhead. debit = slot * elapsed_sec.
    __uint128_t slotDebit =
      static_cast<__uint128_t>(slot) * elapsedUs / 1'000'000ull;

    // RAM: byte-day → debit = rssBytes * rate * elapsed_sec / 86400.
    __uint128_t rssDebit = 0;
    if (rssRate > 0 && inst->rssBytes > 0) {
      rssDebit = static_cast<__uint128_t>(inst->rssBytes)
               * static_cast<__uint128_t>(rssRate)
               * static_cast<__uint128_t>(elapsedUs)
               / (static_cast<__uint128_t>(86400ull) * 1'000'000ull);
    }

    // CPU: core-second. debit = cpuBp * rate * elapsed_sec / 10000.
    __uint128_t cpuDebit = 0;
    if (cpuRate > 0 && inst->cpuBasisPoints > 0) {
      cpuDebit = static_cast<__uint128_t>(inst->cpuBasisPoints)
               * static_cast<__uint128_t>(cpuRate)
               * static_cast<__uint128_t>(elapsedUs)
               / (static_cast<__uint128_t>(10000ull) * 1'000'000ull);
    }

    // Bucket capacity rent: sum committedBytes across all of this
    // instance's buckets, debit at the per-byte-second rate.
    // committedBytes is the worst-case footprint declared at
    // bucket_new (max_entries × max_entry_bytes) — predictable,
    // not sampled.
    __uint128_t bucketDebit = 0;
    if (bucketRate > 0 && !inst->buckets.empty()) {
      uint64_t totalBytes = 0;
      for (auto& [_bid, lb] : inst->buckets) totalBytes += lb.committedBytes;
      if (totalBytes > 0) {
        bucketDebit = static_cast<__uint128_t>(totalBytes)
                    * static_cast<__uint128_t>(bucketRate)
                    * static_cast<__uint128_t>(elapsedUs)
                    / 1'000'000ull;
      }
    }

    __uint128_t total = slotDebit + rssDebit + cpuDebit + bucketDebit;
    // Clamp to uint64 max (reaching it would mean a misconfigured rate, not
    // real usage).
    uint64_t debit = (total > static_cast<__uint128_t>(UINT64_MAX))
      ? UINT64_MAX : static_cast<uint64_t>(total);
    if (debit == 0) continue;
    if (!fileHandlerDebitBalance(inst->sourceName, debit)) {
      toKill.push_back(id);
    } else {
      inst->lastTickUs = now;
    }

    // Reap zombies: if the child exited on its own, drop the
    // instance. No restart — owner re-LAUNCHes manually.
    int status = 0;
    pid_t r = ::waitpid(inst->pid, &status, WNOHANG);
    if (r == inst->pid) {
      LOGDEBUG << "builtin:compute child exited"
               << VAR(id) << VAR(status);
      toKill.push_back(id);
    }
  }
  for (uint64_t id : toKill) killInstanceById(id);
}

void scheduleNextTick() {
  if (!gTickTimer) return;
  if (!gTickRunning.load()) return;
  CesServer* server = gServer.load();
  uint32_t ms = (server && server->_config().computeTickIntervalMs > 0)
    ? server->_config().computeTickIntervalMs : 60000u;
  gTickTimer->expires_after(std::chrono::milliseconds(ms));
  gTickTimer->async_wait([](const boost::system::error_code& ec) {
    if (ec) return;
    supervisorTick();
    scheduleNextTick();
  });
}

// ---------------------------------------------------------------------------
// File-deletion interlock: any file handler delete path fires our
// callback. If the deleted file has a running instance, kill it.
// ---------------------------------------------------------------------------

void onFileDeleted(const std::string& name) {
  // Runs on whatever thread drove the deletion — typically rpcTaskIO_,
  // but we don't assume. Hop onto rpcTaskIO_ so we can touch the
  // instance registry without taking a lock.
  CesServer* server = gServer.load();
  if (!server) return;
  auto io = server->_rpcTaskIOExecutor();
  if (!io) return;
  boost::asio::post(io, [name]() {
    auto it = gByName.find(name);
    if (it == gByName.end()) return;
    // Snapshot ids — killInstanceById mutates gByName.
    std::vector<uint64_t> ids(it->second.begin(), it->second.end());
    for (uint64_t id : ids) killInstanceById(id);
  });
}

// ---------------------------------------------------------------------------
// ComputeHandler class + registration
// ---------------------------------------------------------------------------

class ComputeHandler : public CesPlexHandler {
public:
  void serve(std::shared_ptr<minx::RudpStream> stream,
             BoundChannelContext bound) override {
    CesServer* server = gServer.load();
    if (!server) {
      LOGWARNING << "builtin:compute invoked with no bound CesServer";
      return;
    }
    CesPlexProtocol proto;
    // accepts() also gates "still bound?" — false on unbind stops the loop.
    proto.accepts = [](uint8_t verb) {
      return gServer.load() != nullptr &&
             verb >= kVerbLaunch && verb <= kVerbInstances;
    };
    proto.dispatch = [](std::shared_ptr<ReqCtx> ctx, ces::Bytes pre) {
      switch (ctx->verb) {
        case kVerbLaunch:    dispatchLaunch   (ctx, std::move(pre)); break;
        case kVerbKill:      dispatchKill     (ctx, std::move(pre)); break;
        case kVerbList:      dispatchList     (ctx, std::move(pre)); break;
        case kVerbStat:      dispatchStat     (ctx, std::move(pre)); break;
        case kVerbInstances: dispatchInstances(ctx, std::move(pre)); break;
        default:             ctx->error(CES_ERROR_BAD_INPUT); break;
      }
    };
    cesPlexServe(std::move(stream), std::move(bound), server,
                 std::move(proto));
  }
};

ComputeHandler gComputeHandler;

} // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

uint8_t computeHandlerBind(CesServer* server) {
  if (server == nullptr) {
    // Teardown. SIGKILL every instance and cancel the tick.
    gTickRunning.store(false);
    if (gTickTimer) {
      boost::system::error_code ec;
      gTickTimer->cancel(ec);
    }
    // Kill all instances. Iterate over a snapshot since
    // killInstanceById erases.
    std::vector<uint64_t> ids;
    ids.reserve(gInstances.size());
    for (auto& [id, _] : gInstances) ids.push_back(id);
    for (uint64_t id : ids) killInstanceById(id);
    gTickTimer.reset();
    gServer.store(nullptr);
    return CES_OK;
  }

  const auto& cfg = server->_config();

  if (cfg.computeMaxInstances == 0)
    return CES_ERROR_COMPUTE_DISABLED;

  // File handler must be registered.
  if (findCesPlexBuiltin("file") == nullptr) {
    LOGERROR << "builtin:compute: requires builtin:file; refusing to bind";
    return CES_ERROR_COMPUTE_NO_FILE_HANDLER;
  }

  // Create the workdir eagerly — if we can't, bail now.
  auto workDir = resolveWorkDir(cfg);
  std::error_code ec;
  std::filesystem::create_directories(workDir, ec);
  if (ec) {
    LOGERROR << "builtin:compute: workdir unusable"
             << SVAR(workDir.string());
    return CES_ERROR_INTERNAL;
  }

  gServer.store(server);

  // One-shot deletion callback registration.
  if (!gDeletionCallbackInstalled.exchange(true)) {
    fileHandlerRegisterDeletionCallback(
      [](const std::string& name) { onFileDeleted(name); });
  }

  // Start supervisor timer on rpcTaskIO_.
  auto io = server->_rpcTaskIOExecutor();
  if (!io) {
    LOGERROR << "builtin:compute: rpcTaskIO not available";
    gServer.store(nullptr);
    return CES_ERROR_INTERNAL;
  }
  gTickTimer = std::make_shared<boost::asio::steady_timer>(io);
  gTickRunning.store(true);
  scheduleNextTick();

  LOGINFO << "builtin:compute bound"
          << VAR(cfg.computeMaxInstances)
          << SVAR(cfg.cesComputeChildBinary)
          << SVAR(workDir.string());
  return CES_OK;
}

uint8_t computeHandlerLaunchInternal(const std::string& name) {
  CesServer* server = gServer.load();
  if (!server) return CES_ERROR_COMPUTE_DISABLED;
  const auto& cfg = server->_config();
  if (cfg.computeMaxInstances == 0) return CES_ERROR_COMPUTE_DISABLED;
  if (launchSlotsInUse() >= cfg.computeMaxInstances) {
    return CES_ERROR_COMPUTE_MAX_INSTANCES;
  }
  uint16_t clientPort = 0;
  allocateComputePort(cfg, clientPort);   // best-effort; 0 = local-only
  auto portLease = std::make_shared<PortLease>(clientPort);
  uint16_t rpcPort = 0;
  allocateComputePort(cfg, rpcPort);   // best-effort 2nd port (/ces/luarpc/1 host)
  auto rpcPortLease = std::make_shared<PortLease>(rpcPort);

  // Source file must exist; ownership must be the server. /s/-zone
  // requirement is enforced at deploy time by
  // fileHandlerEnsureServerFile, so we don't double-check the path
  // shape here.
  std::array<uint8_t, 32> ownerPk{};
  uint64_t fileBalance = 0;
  if (!fileHandlerReadOwnerAndBalance(name, ownerPk, fileBalance)) {
    return CES_ERROR_FILE_NOT_FOUND;
  }
  std::array<uint8_t, 32> serverPk{};
  std::memcpy(serverPk.data(),
              server->_serverKeyPair().getPublicKeyAsHash().data(), 32);
  if (ownerPk != serverPk) {
    LOGWARNING << "builtin:compute internal launch: source not owned by server"
               << SVAR(name);
    return CES_ERROR_NOT_OWNER;
  }

  // /s/ files are unmetered → no upfront fee, no rent debit. Pass
  // upfront=0 so the Instance's bookkeeping field is honest about
  // what was committed.
  //
  // The spawn awaits the child's connect-back asynchronously; success
  // or failure is logged from the callback. CES_OK here means
  // "validated + spawn started," not "child connected."
  uint64_t now = getMicrosSinceEpoch();
  allocateAndSpawnInstance(server, name, ownerPk, 0, now,
    std::make_shared<LaunchSlot>(), std::move(portLease), std::move(rpcPortLease),
    [name](uint64_t id) {
      if (id == 0) {
        LOGWARNING << "builtin:compute internal launch spawn failed"
                   << SVAR(name);
      }
    });
  return CES_OK;
}

void computeHandlerOnApplicationMsg(
    const uint8_t* data, std::size_t len,
    const std::array<uint8_t, 8>& senderPfx) {
  if (gServer.load() == nullptr) return;
  // Wire shape (op byte already stripped by CesServer::incomingApplication):
  //   [1B flags][8B prog_pfx][2B len BE][N payload]
  if (len < sizeof(uint8_t) + sizeof(uint64_t) + sizeof(uint16_t)) return;
  if (data[0] != 0) return; // flags must be 0 in v1
  std::array<uint8_t, 8> pfx{};
  std::memcpy(pfx.data(), data + 1, 8);
  uint16_t payloadLen = ces::Buffer::peek<uint16_t>(data + 9);
  if (payloadLen > kAppPayloadMax) return;
  if (len < static_cast<size_t>(11 + payloadLen)) return;

  auto it = gByPrefix.find(pfx);
  if (it == gByPrefix.end()) return; // no local instance for this prefix; drop
  // Broadcast to every local instance sharing this content-addressed
  // prefix. Sibling instances see sibling traffic — same as if they
  // were on different servers in the swarm.
  for (uint64_t id : it->second) {
    auto inst = gInstances.find(id);
    if (inst == gInstances.end()) continue;
    sendDeliverFrame(inst->second, senderPfx, data + 11, payloadLen);
  }
}

bool _computeTestReadProcSample(int pid,
                                uint64_t& outTicks,
                                uint64_t& outRssBytes) {
  ProcSample s;
  if (!readProcSample(static_cast<pid_t>(pid), s)) return false;
  outTicks = s.ticks;
  outRssBytes = s.rssBytes;
  return true;
}

void _computeTestForceTick() {
  CesServer* server = gServer.load();
  if (!server) return;
  auto ex = server->_rpcTaskIOExecutor();
  if (!ex) return;
  // Post a blocking supervisorTick onto the CesPlex strand and wait
  // for it to finish, so the caller sees side effects synchronously.
  std::mutex m;
  std::condition_variable cv;
  bool done = false;
  boost::asio::post(ex, [&]() {
    supervisorTick();
    std::lock_guard lk(m);
    done = true;
    cv.notify_all();
  });
  std::unique_lock lk(m);
  cv.wait(lk, [&]{ return done; });
}

size_t _computeTestFloodDeliver(uint64_t instanceId, size_t count) {
  CesServer* server = gServer.load();
  if (!server) return 0;
  auto ex = server->_rpcTaskIOExecutor();
  if (!ex) return 0;
  // Push `count` best-effort DELIVER frames at the instance back-to-back
  // inside a SINGLE strand task. Because the task never yields, no
  // async_write completion runs between pushes — nothing drains — so the
  // outbox depth read at the end is the exact saturation point: the cap
  // (kMaxDeliverBacklog) when the flood guard is in place, or `count` when
  // it is not. Deterministic, with no socket-buffer or timing dependence.
  std::mutex m;
  std::condition_variable cv;
  bool done = false;
  size_t depth = 0;
  boost::asio::post(ex, [&]() {
    auto it = gInstances.find(instanceId);
    if (it != gInstances.end()) {
      std::array<uint8_t, 8> sender{};
      std::array<uint8_t, 16> payload{};
      for (size_t i = 0; i < count; ++i)
        sendDeliverFrame(it->second, sender, payload.data(), payload.size());
      depth = it->second->outbox.size();
    }
    std::lock_guard lk(m);
    done = true;
    cv.notify_all();
  });
  std::unique_lock lk(m);
  cv.wait(lk, [&]{ return done; });
  return depth;
}

uint16_t _computeTestInstanceClientPort(uint64_t instanceId) {
  CesServer* server = gServer.load();
  if (!server) return 0;
  auto ex = server->_rpcTaskIOExecutor();
  if (!ex) return 0;
  std::mutex m;
  std::condition_variable cv;
  bool done = false;
  uint16_t port = 0;
  boost::asio::post(ex, [&]() {
    auto it = gInstances.find(instanceId);
    if (it != gInstances.end()) port = it->second->clientPort;
    std::lock_guard lk(m);
    done = true;
    cv.notify_all();
  });
  std::unique_lock lk(m);
  cv.wait(lk, [&]{ return done; });
  return port;
}

uint16_t _computeTestInstanceRpcPort(uint64_t instanceId) {
  CesServer* server = gServer.load();
  if (!server) return 0;
  auto ex = server->_rpcTaskIOExecutor();
  if (!ex) return 0;
  std::mutex m;
  std::condition_variable cv;
  bool done = false;
  uint16_t port = 0;
  boost::asio::post(ex, [&]() {
    auto it = gInstances.find(instanceId);
    if (it != gInstances.end()) port = it->second->rpcPort;
    std::lock_guard lk(m);
    done = true;
    cv.notify_all();
  });
  std::unique_lock lk(m);
  cv.wait(lk, [&]{ return done; });
  return port;
}

// ---------------------------------------------------------------------------
// /ces/lua/1 cross-handler primitives — the lua handler calls into
// these from rpcTaskIO_'s strand. See include/ces/l2/compute_handler.h.
// ---------------------------------------------------------------------------

bool computeInstanceExists(uint64_t instanceId) {
  return gInstances.find(instanceId) != gInstances.end();
}

std::vector<ComputeInstanceStat> computeHandlerSnapshot() {
  std::vector<ComputeInstanceStat> out;
  CesServer* server = gServer.load();
  if (!server) return out;
  auto ex = server->_rpcTaskIOExecutor();
  if (!ex) return out;
  uint64_t nowUs = getMicrosSinceEpoch();
  std::mutex m;
  std::condition_variable cv;
  bool done = false;
  boost::asio::post(ex, [&]() {
    out.reserve(gInstances.size());
    for (auto& [id, inst] : gInstances) {
      ComputeInstanceStat s;
      s.id = inst->id;
      s.source = inst->sourceName;
      s.cpuBasisPoints = inst->cpuBasisPoints;
      s.rssBytes = inst->rssBytes;
      s.uptimeSecs = (inst->startedAtUs && nowUs > inst->startedAtUs)
                       ? (nowUs - inst->startedAtUs) / 1000000ULL
                       : 0;
      s.clientPort = inst->clientPort;
      s.rpcPort = inst->rpcPort;
      out.push_back(std::move(s));
    }
    std::lock_guard lk(m);
    done = true;
    cv.notify_all();
  });
  std::unique_lock lk(m);
  cv.wait(lk, [&] { return done; });
  return out;
}

bool computeInstanceAcceptsConnections(uint64_t instanceId) {
  auto it = gInstances.find(instanceId);
  if (it == gInstances.end()) return false;
  return it->second->acceptsConnections;
}

uint64_t computeOpenConnection(uint64_t instanceId,
                                const std::array<uint8_t, 32>& userPubkey) {
  auto it = gInstances.find(instanceId);
  if (it == gInstances.end()) return 0;
  auto inst = it->second;
  uint64_t connId = inst->nextConnId++;
  // Body: [u64 conn_id BE][32B user_pubkey].
  ces::Bytes body;
  body.reserve(sizeof(uint64_t) + sizeof(userPubkey));
  ces::Buffer::put<uint64_t>(body, connId);
  body.insert(body.end(), userPubkey.begin(), userPubkey.end());
  enqueueOutbound(inst, makeFrame(kIpcTagConnOpened, 0,
                                   body.data(), body.size()));
  return connId;
}

void computeSendConnDataIn(uint64_t instanceId, uint64_t connId,
                            const uint8_t* data, std::size_t len) {
  auto it = gInstances.find(instanceId);
  if (it == gInstances.end()) return;
  // Body: [u64 conn_id BE][u32 BE len][len bytes].
  ces::Bytes body;
  body.reserve(sizeof(uint64_t) + sizeof(uint32_t) + len);
  ces::Buffer::put<uint64_t>(body, connId);
  ces::Buffer::put<uint32_t>(body, static_cast<uint32_t>(len));
  if (len > 0) body.insert(body.end(), data, data + len);
  enqueueOutbound(it->second, makeFrame(kIpcTagConnDataIn, 0,
                                         body.data(), body.size()));
}

void computeSendConnClosed(uint64_t instanceId, uint64_t connId,
                            uint8_t reason) {
  auto it = gInstances.find(instanceId);
  if (it == gInstances.end()) return;
  // Body: [u64 conn_id BE][u8 reason].
  ces::Bytes body;
  body.reserve(sizeof(uint64_t) + sizeof(uint8_t));
  ces::Buffer::put<uint64_t>(body, connId);
  body.push_back(reason);
  enqueueOutbound(it->second, makeFrame(kIpcTagConnClosed, 0,
                                         body.data(), body.size()));
}

} // namespace ces

// ---------------------------------------------------------------------------
// Static registration: map protocol name "compute" → gComputeHandler.
// ---------------------------------------------------------------------------

REGISTER_CESPLEX_BUILTIN("compute", ::ces::gComputeHandler, ComputeHandler)

// TU anchor — cesplex/mux.cpp references this via its anchor array.
extern "C" { int compute_handler_anchor = 1; }
