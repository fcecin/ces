#pragma once

#include <boost/filesystem/path.hpp>
#include <ces/types.h>
#include <chrono>
#include <map>
#include <minx/minx.h>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <ces/account.h>
#include <ces/accounts.h>
#include <ces/asset.h>
#include <ces/assets.h>
#include <ces/cesvm.h>
#include <ces/client.h>
#include <ces/clientasync.h>
#include <ces/feemult.h>
#include <ces/keys.h>
#include <ces/util/metrics.h>
#include <ces/cesplex/meter.h>
#include <ces/l2/ledger_txn.h>
#include <functional>
#include <ces/cesplex/mux.h>   // CesPlexHost (CesServer implements it)
#include <ces/protocol.h>
#include <minx/bucketcache.h>
#include <minx/rudp/rudp.h>

using namespace minx;

namespace ces {

// Forward declaration — defined in ces/cesplex/mux.h. CesServer holds
// a unique_ptr to one; the full type is only needed in server.cpp.
class CesPlex;

constexpr uint64_t BASE_FEE_ACCOUNT = 6'400'000;
// Asset rent tracks the RAM size ratio: Account is 64 B, Asset is
// 256 B, so feeAsset = 4x feeAccount.
constexpr uint64_t BASE_FEE_ASSET = 25'600'000;
constexpr uint64_t BASE_FEE_TRANSACTION = 320'000;
// Query fee covers dedup + state write. The network share is billed
// separately (feeNetByte*) and the bind contract removed the per-op
// envelope verify, leaving this well below feeTx.
constexpr uint64_t BASE_FEE_QUERY = 20'000;
constexpr uint64_t BASE_FEE_VM_MULT = 50;

struct CesConfig {

  boost::filesystem::path dataDir;
  minx::Hash serverPrivKey;
  KeyAlgo serverKeyAlgo = KeyAlgo::ED25519;
  std::string version;

  uint64_t minAcc = 0;
  uint64_t maxAcc = 0;
  uint8_t minDiff = 0;
  uint64_t spendSlotSize = 0;
  uint64_t minProveWorkTimestamp = 0;

  uint64_t minAsset = 0;
  uint64_t maxAsset = 0;

  int taskThreads = 1;
  uint64_t flushValue = 10000;
  uint64_t maxLogBytes = 100ULL * 1024 * 1024 * 1024; // 100 GB
  size_t accountStoreBufferSize = 1 << 19;
  size_t assetStoreBufferSize = 1 << 19;

  uint64_t feeAccount = BASE_FEE_ACCOUNT;
  uint64_t feeAsset = BASE_FEE_ASSET;
  uint64_t feeTx = BASE_FEE_TRANSACTION;
  uint64_t feeQuery = BASE_FEE_QUERY;
  uint64_t feeVmMult = BASE_FEE_VM_MULT;

  // Fee-discount system (see feemult.h). When true, the metrics pulse
  // refreshes a per-FeeKind multiplier from the relevant gauge bp; idle
  // server → fees subsidized → full free; saturated → full price. When
  // false, every multiplier is pinned to 10000 (full price always).
  // Tests set this false to keep static-fee assertions.
  bool feeDiscountEnabled = true;

  size_t recvBuffersSize = MinxConfig::DEFAULT_RECV_BUFFERS_SIZE;

  uint64_t getFeeError() const { return feeQuery; }

  // Server identity (optional, e.g. "myserver.example.com:53830")
  // Used in PoW appData to declare this server's address to peers.
  // If empty, falls back to ":port".
  std::string serverName;

  // Peering
  struct PeerConfig {
    std::string pubKeyHex; // 64-char hex
    std::string address;   // host:port
  };
  uint64_t peerTarget = 0;       // credit target on each peer (0 = no peering)
  // Inbound PoW reciprocation, basis points: outbound PoW we mine per inbound
  // PoW received. 0 = off. 10000 = 1:1. Outbound peers ignore it (use peerTarget).
  uint64_t peerPowInboundReciprocationBps = 0;
  int peerMinerIntervalSecs = 60;   // seconds between miner cycles (lower for testing)
  std::vector<PeerConfig> peers;
  int settlementMaxRetries = CesClientAsync::DEFAULT_MAX_RETRIES;

  // Presence cache: max tracked client addresses for push (send()).
  size_t presenceCacheSize = 250000;

  // Autoexec key pattern: assets whose key matches this pattern
  // are parsed as signed CesRunAsset packets and executed on server boot.
  // Key layout: [8 zero bytes][8 AUTOEXEC_MAGIC bytes][8 account prefix][8 random]
  static constexpr uint64_t AUTOEXEC_KEY_MAGIC = 0xCE5C40E70000ULL;

  // Scheduled runAsset (cron) settings
  size_t maxScheduledEntries = 1000000;
  static constexpr uint64_t CRON_TICK_INTERVAL_MS = 100; // 10 Hz
  static constexpr uint64_t CRON_TICK_DEADLINE_MS = 100; // max realtime per tick

  // Cesco admin console (Unix domain socket). Empty = disabled.
  std::string adminSocket;

  // Web dashboard — an HTTP admin UI embedded in the server, bound to
  // loopback only. There is NO authentication: reach it by SSH-tunneling
  // to the host. 0 = disabled (default). The bind address is loopback by
  // design (127.0.0.1); an operator who fronts it with their own auth
  // proxy can repoint it, and gets a warning if it isn't a loopback IP.
  uint16_t webPort = 0;
  std::string webBind = "127.0.0.1";

  // Dedicated MINX/RUDP port for the SYS_RPC syscall. This is a SECOND
  // Minx instance bound to a separate UDP port, held
  // inside CesServer for deployment convenience. It carries no CES
  // protocol traffic — only outbound (initially) RUDP streams.
  //
  //   0 = disabled (default). Minx is not constructed, no socket is
  //       bound, SYS_RPC returns CES_ERROR_DISABLED.
  //
  // When nonzero, CesServer::start() binds a second Minx on this UDP
  // port with a no-op listener. Inbound RUDP handshakes are rejected
  // at Rudp's ChannelAccept predicate (outbound only). Operators can
  // open or close this port independently from the CES protocol port
  // via firewall rules.
  uint16_t rpcPort = 0;

  // Test-only: when true AND rpcPort == 0, the rpc Minx socket is
  // bound on an OS-allocated free port instead of being treated as
  // "disabled." Production callers leave this false; tests set it
  // so they don't have to negotiate port collisions.
  bool rpcAutoPort = false;

  // --- SYS_RPC outbound flow control ---
  // Backpressure against buggy VM programs and slow peers. rpcMaxPending
  // caps concurrent in-flight outbound calls; queueRpc returns
  // CES_ERROR_QUEUE_FULL past this. rpcMaxRequestBytes /
  // rpcMaxResponseBytes cap the envelope body size in either direction.
  // rpcResponseTimeoutMs arms an asio timer per session.
  uint32_t rpcMaxPending       = 1000;
  size_t   rpcMaxRequestBytes  = 64 * 1024;
  size_t   rpcMaxResponseBytes = 64 * 1024;
  uint32_t rpcResponseTimeoutMs = 30000;

  // Per-channel RUDP pacing advertised in the handshake. The effective
  // bucket is min(local, peer) per parameter. Defaults mean "unlimited"
  // (matches current behavior); operators who run adversarial SYS_RPC
  // workloads can clamp. 0xFFFFFFFFu == minx::RudpConfig::PER_CHANNEL_UNLIMITED.
  uint32_t rpcRudpBytesPerSecond = 0xFFFFFFFFu;
  uint32_t rpcRudpBurstBytes     = 0xFFFFFFFFu;

  // RUDP transport caps on the rpc_port. CES ships an opinion on
  // channels (default 2 — lets cesh hold a long-lived stream while
  // doing other ops in parallel) and stays passthrough on the two
  // reorder buffers (-1 = keep the minx::RudpConfig library default,
  // currently 1 MB / 1024 messages).
  size_t  rpcRudpMaxChannelsPerPeer         = 2;
  int64_t rpcRudpMaxReorderBytesPerChannel  = -1;
  int64_t rpcRudpMaxReorderMsgsPerChannel   = -1;

  // rpc_port RUDP channel idle GC, in seconds: a channel with no traffic for
  // this long is dropped. 60 suits request/reply, but is too short for a
  // long-lived interactive channel (a `cesh dial` terminal where a human
  // pauses between commands) — raise it on terminal-serving boxes.
  uint32_t rpcRudpChannelIdleSecs           = 60;

  // --- File storage feature (CesPlex builtin:file, v2) ---
  // Master switch + hard capacity cap. The feature is entirely
  // disabled when 0 — fileHandlerBind is skipped, startup reconcile
  // is skipped, any inbound /ces/file/* channel's handler sees no
  // bound CesServer and drops. A positive value is a hard ceiling
  // on store-wide total_bytes: CREATE is rejected with
  // CES_ERROR_STORE_FULL when the new file's size would push past
  // the cap. WRITE cannot extend files (size fixed at CREATE), so
  // CREATE is the single gate the cap enforces at.
  uint64_t cesFileStoreMaxBytes = 0;
  // Directory where bytes + sidecars live. Empty means
  // "<dataDir>/cesplex_files/". Operators can repoint for
  // bigger / faster / separately-provisioned storage.
  std::string cesFileStoreDir;
  // Read-only catalog of installable extensions (single .lua files). The
  // Extensions page lists these as available; Install copies one into /s/.
  // Empty disables the catalog (already-installed /s/ extensions still show).
  std::string cesExtensionsDir;
  // Extension funding budget: the GLOBAL rate (raw credit units per day, summed
  // over all extensions and all remotes) the server will grant to /s/ programs
  // that petition via ces.request_funds. 0 (default) = funding off: a program
  // can spend NOTHING at remotes until the operator opens a budget. The server
  // enforces this; it never lives in Lua. See local/extension_funding.md.
  uint64_t extFundingPerDay = 0;
  // Three fee knobs mapping to the three physical costs of file
  // storage:
  //   feeFileRent  = retention (byte sitting on disk over time)
  //   feeFileWrite = networking + SSD write (per-KB, one-shot)
  //   feeFileRead  = networking + SSD read  (per-KB, one-shot)
  //
  // Defaults (resolved in CesServer ctor, zero means "derive"):
  //   feeFileRent  = feeAsset / 100 / 256 (disk 100x cheaper than
  //                   asset-cell RAM; the asset pays for its full
  //                   256 B cell, so per-byte-day of RAM is
  //                   feeAsset/256 and disk is /100 of that)
  //   feeFileWrite = 10 * feeFileRent   (writing a KB ~= 10 days
  //                                        of rent on 1 byte of that
  //                                        KB — real I/O)
  //   feeFileRead  = feeFileRent        (reading is ~rent-equivalent;
  //                                        cheaper than write, no wear)
  //
  // Write/read charges are ceil(bytes/1024) × fee. At defaults
  // feeAsset=25.6M → feeFileRent=1000, feeFileWrite=10000; a 1 MB
  // WRITE = 1024 × 10000 ≈ 10.2 M credits. CREATE has no per-byte
  // cost — sparse allocation. Rent starts accruing, covered by the
  // signer's initial_deposit landing in file_balance.
  int64_t feeFileRent   = 0;   // credits per (byte × day) — retention
  int64_t feeFileWrite  = 0;   // credits per KB — WRITE I/O
  int64_t feeFileRead   = 0;   // credits per KB — READ I/O

  // --- RUDP-tier pricing. The server's own price per resource dimension
  //     the CesPlex bus measures, applied live each ChannelMeter tick in
  //     cesplexReportUsage — the bus reports raw counts, the server prices
  //     them here. The bus never carries these on the wire; pricing is the
  //     host's private concern, not part of the bind contract.
  //
  //   feeNetChannelSec    - per-second "channel is open" rate.
  //                         Pays for the supervisor + memory baseline
  //                         of holding a RUDP channel.
  //   feeNetMemByteDay    - per (byte x day) of RUDP buffer state
  //                         (reorder + send + ack caches).
  //   feeNetByteSent      - per byte sent server to client.
  //   feeNetByteReceived  - per byte received client to server.
  //
  // Defaults: 0 (observability only); non-zero values bill per channel
  // via ChannelMeter.
  uint64_t feeNetChannelSec   = 0;
  uint64_t feeNetMemByteDay   = 0;
  uint64_t feeNetByteSent     = 0;
  uint64_t feeNetByteReceived = 0;

  // --- Compute feature (CesPlex builtin:compute) ---
  //
  // Master switch + hard caps for the L2 compute feature. The feature
  // is entirely disabled when
  // computeMaxInstances == 0 — the compute handler refuses to bind,
  // inbound /ces/compute/1 selects NACK, and the cesluad child binary
  // is never spawned.
  //
  // Bind-time prerequisites (all must hold for bind to succeed):
  //   1. computeMaxInstances > 0
  //   2. builtin:file is also registered in the CesPlex registry
  //      (compute uses the file handler's internals for owner-
  //      authority file ops on behalf of running programs).
  //   3. computeUser exists on the host system (a dedicated
  //      unprivileged uid each cesluad child drops to).
  uint32_t computeMaxInstances    = 0;   // 0 = feature OFF
  // computeMaxInstances is the whole admission story. It caps concurrent
  // child processes; worst-casing every instance at one saturated core +
  // computeProcessMemMax of RAM, it statically bounds both resources —
  // RAM = instances × mem-cap, CPU = instances cores. Size it to the host
  // (min of cores × factor and RAM ÷ mem-cap). No runtime load sampling:
  // measuring CPU load without chasing instant peaks or reinventing a load
  // monitor isn't worth it; a static process cap is simpler and safe.
  //
  // Per-process memory ceiling, enforced merciless + instant by the
  // child's RLIMIT_AS: the kernel denies any allocation past it, so a
  // runaway or malicious program can never OOM the host (OOM is an
  // instant, machine-wide attack vector the 60 s billing tick can't react
  // to in time). The program controls its own footprint, and instances ×
  // this value is the hard global bound on total L2-compute memory.
  //
  // No per-process CPU cap — CPU is a flow, billed (feeComputeCpuSec) and
  // shared by the scheduler; the process cap above is the CPU bound. No
  // pids cap — the sandbox exposes no fork/exec, so a child is one process.
  uint64_t computeProcessMemMax   = 268435456; // 256 MB
  // Worker threads each Lua child uses for OUTBOUND verb-client calls
  // (ces.file_client / ces.compute_client): how many such round-trips can be in
  // flight concurrently before further ones queue. Bounds the child's blocking
  // pool; the main-port client pool (ces.ping / ces.remote_*) is fixed at 1
  // (one leased outbound port). Passed to the child on spawn; clamped [1, 64].
  uint32_t computeClientPoolSize  = 4;
  // Fee knobs for compute — credits per unit time / per byte.
  // Every non-zero on a tick is accumulated against the source file's
  // file_balance. 0 = "derive default" at bind time. The four knobs:
  //
  //   feeComputeSlotSec    — flat "slot is occupied" overhead, per
  //                          wall-clock second (pays for supervisor
  //                          state + the per-tick sidecar rewrite).
  //   feeComputeCpuSec     — full-core-second cost. Billed as
  //                          cpu_bp × feeComputeCpuSec / 10000 × sec.
  //                          A 100%-of-one-core second pays the full
  //                          amount; 25% pays a quarter, etc.
  //   feeComputeRssByteDay — RAM residency, credits per byte per day.
  //                          Billed as rss_bytes × rate × sec / 86400.
  //   feeComputeNetByte    — reserved for outbound APPLICATION bytes
  //                          (not yet wired).
  //
  // Defaults:
  //   feeComputeSlotSec    = feeAsset / 86400, floor 1
  //                          Tracking a running instance costs far
  //                          more than a single 64 B account — it's
  //                          a child process, a unix-domain socket,
  //                          a task_struct, supervisor bookkeeping.
  //                          "One asset-day of fixed overhead" is
  //                          the conservative minimum. ~296/sec.
  //   feeComputeRssByteDay = feeAsset / 256, floor 1
  //                          "RAM is RAM" — same per-byte-day as the
  //                          full asset cell. 100K/byte-day at stock.
  //   feeComputeCpuSec     = 5_000_000, floor 1
  //                          Full-core-second cost. 100× cheaper than
  //                          a busy VM (feeVmMult=50 × ~10M ops/sec
  //                          ≈ 500M/sec of wall-clock). At 10000 bp
  //                          (full core) × 1 sec = 5M; at 500 bp
  //                          (5% usage) × 1 sec = 250K.
  //
  // Orientation: a 1 MB idle service at stock fees pays roughly
  // ~72M (RAM) + ~18K (slot) per 60 s tick ≈ 104.9B/day
  // (≈ 4100 assets/day), dominated by RAM residency.
  int64_t feeComputeCpuSec     = 0;
  int64_t feeComputeRssByteDay = 0;
  int64_t feeComputeNetByte    = 0;
  int64_t feeComputeSlotSec    = 0;   // 0 = derive at bind
  // Per-byte-second rate billed for ces.bucket_new() committed
  // capacity (max_entries × max_entry_bytes per bucket, summed across
  // all of an instance's buckets). Charged on the same supervisor
  // tick that bills slot/cpu/rss, against the source file's
  // file_balance. /s/ files are exempt (fileHandlerDebitBalance is a
  // no-op there). 0 = derive at bind from feeComputeRssByteDay /
  // 86400 — same per-byte basis as RSS, but on a per-second cadence
  // because the buckets are an explicit standing capacity rather
  // than a sampled measurement. Use a small positive value if
  // feeComputeRssByteDay is too tuned-down to derive a non-zero rate.
  int64_t feeBucketByteSec     = 0;
  // Supervisor tick cadence in milliseconds. One tick does: /proc
  // sample (CPU delta + RSS) + accrued slot-fee debit + source-file
  // sidecar rewrite. 60 s is the production default — rare enough
  // that the sidecar rewrite is nearly free per instance, while
  // procfs sampling stays cheap and balance-drift stays bounded.
  // Tests override this to a short interval so they don't wait a
  // full minute for the first sample.
  uint32_t computeTickIntervalMs = 60000;
  // Per-instance scratch / IPC socket directory. Empty means
  // "<dataDir>/cescompute/". Operators can repoint for faster /
  // separately-provisioned storage.
  std::string cesComputeWorkDir;
  // Unix user that cesluad child processes drop to. Must exist on the
  // host. Bind fails if the user can't be resolved.
  std::string cesComputeUser = "cesluad";
  // Path to the compute child binary. The CES CLI (src/ces/main.cpp)
  // auto-discovers `cesluajitd` next to /proc/self/exe when this is
  // empty, with bare-name PATH fallback — operators with the typical
  // sibling-binaries install don't need to set anything. Tests and
  // other in-process consumers (which don't go through main.cpp) get
  // the literal default `"cesluajitd"` and rely on PATH or override
  // explicitly. Absolute path → used directly. The original
  // `cescompmockd` stub is still built and kept for regression
  // testing of the plumbing itself (LAUNCH / KILL / inbox delivery)
  // without pulling Lua into the mix.
  std::string cesComputeChildBinary = "cesluajitd";

  // L2 compute program UDP port range: [computePortBase, computePortBase
  // + computePortCount - 1]. Each launched child binds its outbound CES
  // client to a port the server allocates statically from this range. The
  // child never picks its own (ephemeral) port: a firewalled L2 host opens
  // only known ports, and an OS-assigned egress port is neither reachable
  // nor configurable. The server owns the whole lifecycle — it tracks
  // which ports are free, assigns one at LAUNCH, hands it to the child in
  // the bootstrap frame, and frees it when the instance dies. Port
  // allocation is best-effort: a spent range leaves the instance with port
  // 0 (local-only), but the LAUNCH still succeeds — the instance stays
  // reachable via the server's own rpc port (/ces/lua/1 relay).
  //
  // Base and count are independent of computeMaxInstances on purpose:
  // ports and instance slots are orthogonal resources. Size the range to
  // your firewall opening; a count below computeMaxInstances simply means
  // the instances past the range run local-only (no outbound network).
  //
  // computePortBase == 0 = no range: instances launch local-only — their
  // outbound network verbs (ces.remote_transfer / remote_account_read /
  // remote_cross_transfer) fail cleanly with "networking disabled" rather
  // than binding an unreachable ephemeral port. When set, open [base,
  // base + count - 1]/udp at the firewall to match.
  uint16_t computePortBase  = 0;
  uint16_t computePortCount = 0;

  // --- /s/ extensions ---
  // Each name in `extensions` is the basename of a Lua program the
  // operator dropped into <storeDir>/s/ (e.g. "dice" → /s/dice.lua).
  // /s/ is operator-controlled at the disk level — fileHandler's
  // startup reconcile auto-generates sidecars for any files the
  // operator placed there. At boot, CesServer::launchExtensions
  // calls computeHandlerLaunchInternal("/s/<name>.lua") for each
  // entry: source missing → WRN, skip; otherwise one cesluajitd
  // instance is launched.
  // Requires: rpcPort > 0, cesplex builtin:file mounted with
  // cesFileStoreMaxBytes > 0, builtin:compute mounted with
  // computeMaxInstances > 0. If prereqs are missing the autolaunch
  // is skipped with a warning; the server otherwise runs fine.
  std::set<std::string> extensions;

  // --- CesPlex protocol mounts ---
  // The L2 bus (CesPlex) runs on the secondary port (rpcPort). Every
  // inbound RUDP channel does a protocol-select handshake; the table
  // below says which protocol names are mounted, and which handler
  // each name resolves to.
  //
  // Key: protocol name (e.g. "/ces/file/1").
  // Value: target — "builtin:<name>" to bind to a statically-linked
  //   handler registered in the CesPlex registry.
  //
  // Empty map = CesPlex has no bindings; every inbound select is
  // NACK'd. This is the right default for a pure ledger deployment.
  std::map<std::string, std::string> cesplexMounts;
};

// No-op MinxListener for the dedicated RPC Minx (see rpcPort above).
// All MinxListener methods fall through to their empty defaults; this
// subclass exists only so the second Minx has an owner for its
// listener pointer.
class CesRpcListener : public minx::MinxListener {};

class CesServer;

// Rudp::Listener for the rpc port. Owns the back-pointer to CesServer
// for onSend (forward to rpcMinx_) and onAccept (delegate to CesPlex
// for inbound channel handler factory).
class CesRpcRudpListener : public minx::Rudp::Listener {
public:
  explicit CesRpcRudpListener(CesServer* owner) : owner_(owner) {}
  void onSend(const minx::SockAddr& peer, const minx::Bytes& bytes) override;
  std::shared_ptr<minx::Rudp::ChannelHandler> onAccept(
      const minx::SockAddr& peer, uint32_t channelId) override;
private:
  CesServer* owner_;
};

class CesServer : public minx::MinxListener, public CesPlexHost {
  friend class CesRpcRudpListener;
  friend struct ServerLedgerTxn;   // L2 verb ledger transaction (server.cpp)
public:
  using ActiveAccount = Accounts::ActiveAccount;
  using ActiveAsset = Assets::ActiveAsset;

  CesServer(const CesConfig& config);
  virtual ~CesServer();

  uint16_t start(uint16_t serverPort = DEFAULT_PORT);
  void createPoWEngine(bool fullMem = true);
  bool isPoWEngineReady();
  void startPeerMiner();
  void stop(bool flushEvents = true);

  void pause();
  void resume();

  uint64_t getTxCount();

  virtual bool isConnected(const SockAddr& addr);
  virtual bool delegateProveWork(const SockAddr& addr,
                                 const MinxProveWork& msg);
  virtual void incomingInit(const SockAddr& addr, const MinxInit& msg);
  virtual void incomingMessage(const SockAddr& addr, const MinxMessage& msg);
  virtual void incomingGetInfo(const SockAddr& addr, const MinxGetInfo& msg);
  virtual void incomingInfo(const SockAddr& addr, const MinxInfo& msg);
  virtual void incomingProveWork(const SockAddr& addr, const MinxProveWork& msg,
                                 const int difficulty);
  virtual void incomingApplication(const SockAddr& addr, const uint8_t code,
                                   const minx::Bytes& data);

  // Send an unsolicited APPLICATION message to a connected client.
  // Looks up the client's address in the presence cache.
  // Returns true if the client was found and the message was sent.
  bool send(const HashPrefix& clientId, const minx::Bytes& data);

  // Like send() but with an explicit APPLICATION opcode byte.
  // Used by builtin:compute to push CES_APP_COMPUTE_MSG (0x81) to
  // program clients — the default overload sends as
  // MINX_APPLICATION_DEFAULT, which wouldn't route back to the
  // compute inbox on the receiving side.
  bool send(const HashPrefix& clientId, uint8_t code, const minx::Bytes& data);

  // Schedule a delayed runAsset. time_us=0 or past means next tick.
  // Cost is deducted from caller upfront. Returns CES_ERROR_QUEUE_FULL if
  // the scheduled-run queue is at capacity, CES_OK otherwise.
  // `allowance` is the per-run caller-debit cap the future run will see;
  // UINT64_MAX = no enforcement (the autoexec / cron-from-API default).
  uint8_t scheduleRun(const HashPrefix& callerPrefix, const minx::Hash& assetId,
                      uint64_t budget, uint64_t allowance,
                      const ces::Bytes& input,
                      uint64_t time_us, bool prepaid = false);

  uint8_t crossTransfer(const minx::Hash& originKey,
                        const minx::Hash& destKey, uint64_t amount,
                        const std::string& destServer,
                        uint32_t providedNonce,
                        int64_t& outOriginBalance,
                        int64_t txFee = -1, int64_t errFee = -1);

  enum class TransferMode : uint8_t {
    Safe = 0,       // fail if dest not found
    Open = 1,       // auto-create dest if not found
    Payment = 2     // create payment account (negative balance)
  };

  uint8_t transfer(const minx::Hash& originKey, const minx::Hash& destKey,
                   uint64_t amount, TransferMode mode,
                   uint8_t paymentDays,
                   uint32_t providedNonce, int64_t& outOriginBalance,
                   int64_t txFee = -1, int64_t rentFee = -1,
                   int64_t errFee = -1);

  uint8_t bulkTransfer(const minx::Hash& originKey,
                       const std::vector<BulkTransferItem>& items,
                       uint32_t providedNonce, int64_t& outOriginBalance,
                       uint8_t& outSuccessfulCount, int64_t txFee = -1,
                       int64_t rentFee = -1, int64_t errFee = -1);

  uint8_t queryAccount(const minx::Hash& originKey, const HashPrefix& queryId,
                       uint8_t items, uint32_t providedNonce,
                       int64_t& outOriginBalance,
                       std::vector<AccountEntry>& outResults,
                       int64_t queryFee = -1, int64_t errFee = -1);

  void unsignedQueryAccount(const HashPrefix& queryId, int64_t& outBalance,
                            uint32_t& outNonce, HashPrefix& outLastXferDest,
                            uint64_t& outLastXferAmount,
                            uint32_t& outLastXferTime);

  uint8_t createAsset(const minx::Hash& originKey, const HashPrefix& ownerId,
                      const minx::Hash& assetId, const AssetData& content,
                      uint16_t balance, uint32_t providedNonce,
                      int64_t rentFee = -1, int64_t errFee = -1);

  uint8_t updateAsset(const minx::Hash& originKey, const minx::Hash& assetId,
                      const HashPrefix& newOwnerId, const AssetData& content,
                      uint32_t price, uint32_t providedNonce,
                      int64_t updateFee = -1, int64_t errFee = -1);

  uint8_t updateAssetMeta(const minx::Hash& originKey,
                          const minx::Hash& assetId,
                          const HashPrefix& newOwnerId, uint32_t price,
                          uint32_t providedNonce, int64_t updateFee = -1,
                          int64_t errFee = -1);

  uint8_t updateAssetFast(const minx::Hash& originKey,
                          const minx::Hash& assetId, const AssetData& content,
                          uint32_t providedNonce, int64_t fastUpdateFee = -1,
                          int64_t errFee = -1);

  uint8_t fundAsset(const minx::Hash& originKey, const minx::Hash& assetId,
                    uint16_t balance, uint32_t providedNonce,
                    int64_t fundFee = -1, int64_t rentFee = -1,
                    int64_t errFee = -1);

  uint8_t buyAsset(const minx::Hash& originKey, const minx::Hash& assetId,
                   uint64_t priceLimit, uint32_t providedNonce,
                   int64_t buyFee = -1, int64_t errFee = -1);

  uint8_t giveAsset(const minx::Hash& originKey, const minx::Hash& assetId,
                    const HashPrefix& newOwnerId, uint32_t providedNonce,
                    int64_t giveFee = -1, int64_t errFee = -1);

  uint8_t queryAsset(const minx::Hash& originKey, const minx::Hash& assetId,
                     uint8_t items, uint32_t providedNonce,
                     std::vector<AssetEntry>& outResults, int64_t queryFee = -1,
                     int64_t errFee = -1);

  uint8_t queryServerInfo(const minx::Hash& originKey, uint32_t providedNonce,
                          int64_t& outOriginBalance,
                          std::vector<ServerInfoEntry>& outEntries,
                          int64_t queryFee = -1, int64_t errFee = -1);

  void unsignedQueryAsset(const minx::Hash& assetId, HashPrefix& outOwner,
                          AssetData& outContent, uint16_t& outBalance,
                          uint32_t& outPrice);

  void liveSnapshot(std::function<void(bool ok, std::string msg)> cb = {});

  void _brr(const minx::Hash& accountKey, int64_t amount);
  void _burn(const minx::Hash& accountKey, int64_t amount);
  // Operator wallet send: transfer `amount` from the server's own (bottomless)
  // account to `destKey`, creating dest if missing. Debits the server exactly
  // and credits dest — net totalCredits unchanged. Returns false if the server
  // balance can't cover it (a guard against driving its account negative).
  bool _walletSend(const minx::Hash& destKey, uint64_t amount);
  void _save();

  // Credits in circulation: the raw account tally minus the server's own
  // bottomless account, which is counted like any other account and
  // subtracted here so the core ledger class stays unaware of it.
  int64_t circulatingCredits() {
    return accounts_.getTotalCredits() -
           accounts_.get(serverKeyPair_.getPublicKeyAsHash()).balance();
  }
  int64_t _getTotalCredits() { return circulatingCredits(); }

  void _runDailyMaintenance();

  // Test hooks for peer table. Production code reaches peer state through
  // the peer miner loop (probe + writeback). Tests that only care about
  // cross-transfer behavior — not reachability detection itself — use
  // these to skip the miner and set up a reachable outbound peer directly.
  void _markPeerReachable(const minx::Hash& ckey, const std::string& address);
  bool _isPeerReachable(const minx::Hash& ckey);

  // Test hook: post runAutoexec() onto logicStrand_ and block until done.
  // Production callers go through the one-shot boot post in start().
  void _runAutoexecSync();

  // Test hook: fire a scheduled (cron) VM run synchronously — build a
  // ScheduledRun, post it onto logicStrand_, and block until it completes.
  // Bypasses the cron timer so crash-recovery tests can drive the cron path
  // deterministically. Returns executeScheduledRun's result.
  bool _executeScheduledRunSync(const HashPrefix& callerPrefix,
                                const minx::Hash& assetId, uint64_t budget,
                                uint64_t allowance, const ces::Bytes& input);

  // Test hook: number of pending scheduled (cron) runs. Used to assert that a
  // VM abort rolls back a SYS_SCHEDULE enqueue.
  size_t _scheduledRunCount() const { return scheduledRuns_.size(); }

  // Test hook: prime the presence cache (both directions) with a
  // (pubkey prefix, addr) pair. Normally presence is populated by
  // the server's signed-op dispatch; tests that just want to
  // receive unsolicited APPLICATION pushes (e.g. from a running
  // compute program) can bypass authentication with this.
  void _primePresence(const HashPrefix& prefix, const minx::SockAddr& addr);

  // Test hook: observe the UDP port the SYS_RPC Minx instance ended up
  // bound to. Non-zero after start() when cfg_.rpcPort was non-zero.
  uint16_t _rpcBoundPort() const { return rpcBoundPort_; }

  // ChannelMeter accessor — used by cesco for the `netbill`
  // command and by tests. Returns nullptr when the rpc port is
  // disabled (no rpcRudp_, no ChannelMeter).
  ChannelMeter* _channelMeter() { return channelMeter_.get(); }

  // ---------------------------------------------------------------------------
  // Dashboard / admin surface (web dashboard, cesco)
  // ---------------------------------------------------------------------------
  // Read-only, lock-free getters (atomics / set-once boot state).
  uint16_t _boundPort() const { return boundPort_; }
  uint16_t getTps() const { return tpsCurrent_.load(); }

  // Ledger-derived stats. The account/asset stores are logicStrand-only,
  // so these hop onto the strand and block the caller on a future. The
  // caller MUST NOT be the logic strand (the web/cesco threads aren't).
  struct AdminStats {
    int64_t  circulating = 0;  // credits in circulation (server-self excluded)
    uint64_t accounts = 0;
    uint64_t assets = 0;
    uint64_t txCount = 0;
  };
  AdminStats _adminStats();

  // Read-only account lookup (strand-hopped). `exists` distinguishes a
  // missing account from a zero-balance one.
  struct AdminAccount {
    bool exists = false;
    // The 8-byte map-key prefix is occupied, but by a DIFFERENT full key (the
    // stored 24-byte keyTail doesn't match the queried one) — a prefix
    // collision. The queried account does NOT exist; creating it would clash.
    bool prefixTaken = false;
    int64_t balance = 0;
    uint32_t nonce = 0;
    HashPrefix lastXferDest{};
    uint64_t lastXferAmount = 0;
    uint32_t lastXferTime = 0;
  };
  AdminAccount _adminQueryAccount(const minx::Hash& accountKey);

  // Read-only asset lookup (strand-hopped). Returns the raw 16-bit balance
  // word (days + flag bits); the dashboard masks/labels it.
  struct AdminAsset {
    bool exists = false;
    HashPrefix owner{};
    uint16_t balance = 0;
    uint32_t price = 0;
    AssetData content{};
  };
  AdminAsset _adminQueryAsset(const minx::Hash& assetId);

  // L2 file STAT for the dashboard's file lookup. Public/unsigned (no signer).
  // `enabled` is false when the file feature is off; `found` false when the
  // path has no file. Rolls rent forward like a real STAT (a rent-dead file
  // reports not-found).
  struct FileStat {
    bool enabled = false;
    bool found = false;
    std::array<uint8_t, 32> ownerPubkey{};
    uint64_t fileBalance = 0;
    uint64_t size = 0;
    uint64_t pricePerKb = 0;
    uint64_t createdUs = 0;
    uint64_t modifiedUs = 0;
  };
  FileStat _fileStat(const std::string& path);

  // Peer table, flattened for display. `inbound` is derived (the peer has
  // submitted PoW to us); `outbound` means we mine/settle to them.
  struct PeerInfo {
    minx::Hash ckey{};
    std::string declaredAddress;
    std::string resolvedIP;
    bool outbound = false;
    bool inbound = false;
    bool reachable = false;
    bool verified = false;
    int64_t ourBalanceThere = -1;
    uint64_t totalInboundPoW = 0;
    uint64_t totalOutboundPoW = 0;
    uint64_t lastInboundTime = 0;
    uint64_t lastCheckTime = 0;
    uint32_t pingFailures = 0;
    uint16_t rpcPort = 0;   // peer's CesPlex rpc port (0 = not yet probed)
  };
  std::vector<PeerInfo> _peerSnapshot();
  // Vostro balances: for each peer pubkey, the balance of THAT peer's account on
  // THIS server (what we owe them) — the other half of the nostro/vostro pair
  // (PeerInfo.ourBalanceThere is our reserve on them, what they owe us). Lives in
  // the ledger, not the peer table, so it's looked up on logicStrand_. Aligned
  // with `keys`; a peer with no local account reads 0.
  std::vector<int64_t> _peerVostroBalances(const std::vector<minx::Hash>& keys);

  // Add (or upgrade an existing entry to) an outbound peer — one we mine to
  // peerTarget and can cross-transfer through. Persists immediately so it
  // survives restart even if the miner hasn't ticked yet.
  void _addOutboundPeer(const minx::Hash& ckey, const std::string& address);
  // Remove a peer entirely. Returns true if an entry was erased.
  bool _removePeer(const minx::Hash& ckey);

  // Test seams: drive the inbound-PoW peer-table path (inboundCredit > 0) and set
  // the verified flag, so the address-claim policy (a verified address is sticky
  // against an unsigned inbound claim; unverified entries are freely overwritten)
  // can be unit-tested without real PoW + a live signed server-info exchange.
  void _upsertPeerForTest(const minx::Hash& ckey, const std::string& address,
                          uint64_t inboundCredit) {
    upsertPeer(ckey, address, inboundCredit);
  }
  bool _setPeerVerifiedForTest(const minx::Hash& ckey, bool v) {
    std::lock_guard<std::mutex> lock(peerTableMutex_);
    for (auto& p : peerTable_)
      if (p.ckey == ckey) { p.verified = v; return true; }
    return false;
  }

  // Runtime peer-credit target. Reading/writing goes through an atomic the
  // miner consults each cycle; setting it >0 starts the miner if it wasn't
  // already running (e.g. a server that booted with target 0). Note: this
  // is runtime-only — it does not rewrite the TOML, so it resets on restart.
  uint64_t _peerTarget() const { return peerTarget_.load(); }
  void _setPeerTarget(uint64_t target);
  bool _peerMinerRunning() const { return peerMinerRunning_.load(); }
  // Peer miner heartbeat for the dashboard: unix seconds of the last completed
  // cycle (0 = never), and a cumulative cycle count.
  uint64_t _peerMinerLastCycle() const { return lastPeerMinerCycle_.load(); }
  uint64_t _peerMinerCycles() const { return peerMinerCycles_.load(); }
  // What the miner is doing RIGHT NOW: `mining` is true only while actually
  // computing a PoW solution (not merely looping/probing). When true, `peer`
  // and `difficulty` say where and at what target difficulty.
  struct PeerMinerActivity {
    bool mining = false;
    std::string peer;
    uint8_t difficulty = 0;
    uint64_t startSecs = 0;   // unix secs this solve began (0 = not mining)
    double hashRate = 0.0;    // smoothed H/s from completed solves (0 = unknown)
  };
  PeerMinerActivity _peerMinerActivity() const {
    std::lock_guard<std::mutex> lock(peerMinerActivityMutex_);
    return {peerMinerMining_, peerMinerMiningPeer_, peerMinerMiningDiff_,
            peerMinerMiningStartSecs_, peerMinerHashRate_};
  }

  // Export the current effective server config (knobs, with the LIVE runtime
  // peer target) as a TOML config file written to <data_dir>/ces.toml — the
  // resolution to the "config is a boot snapshot but the dashboard mutates it"
  // paradox: change values live, then export and feed the file back on the
  // next boot. Deliberately excludes the peer table (own peerdata.toml) and
  // the hello banner (own hello.txt), which already persist themselves.
  // Returns the absolute path written, or empty string on failure.
  std::string _exportConfig(std::string* errReason = nullptr);

  // Set a runtime-editable config knob live (mutated on logicStrand_, where it
  // is read; the export reads cfg_ so the change persists on the next export).
  // Supported keys: fee_account, fee_asset, fee_tx, fee_query, fee_vm_mult,
  // fee_discount_enabled (0/1). Returns false for an unknown/non-editable key.
  bool _setConfigKnob(const std::string& key, uint64_t value);

  // Inspect a remote server by address. Runs a blocking CesClient handshake
  // on the CALLER's thread (never the logic strand) — discovers the peer's
  // pubkey + min-difficulty + reachability for free off the MINX handshake.
  // If `fetchPaidInfo` and we already hold a balance there, also pulls the
  // paid CES_QUERY_SERVER_INFO KV map (empty otherwise). This is how the
  // dashboard discovers a server before adding it as a peer.
  struct RemoteServerInfo {
    bool reachable = false;
    minx::Hash serverKey{};
    uint8_t minDifficulty = 0;
    std::vector<ServerInfoEntry> entries;  // paid KV info, may be empty
  };
  RemoteServerInfo _inspectRemoteServer(const std::string& address,
                                        bool fetchPaidInfo);

  // Mine `count` solutions on a remote server (our key is the beneficiary) —
  // the way to bootstrap a reserve balance on a server before peering with
  // it. Blocking, on the caller's thread; reuses the same path as the peer
  // miner. RandomX makes this slow, so callers run it off the I/O thread.
  struct RemoteMineResult {
    bool ok = false;
    uint64_t credit = 0;
    int status = 0;
    std::string error;
  };
  RemoteMineResult _mineRemoteServer(const std::string& address, int count);

  // Operator "hello" banner — a UTF-8 string served in CES_QUERY_SERVER_INFO
  // as the "hello" field. Capped at HELLO_MAX_BYTES of UTF-8, trimmed on a
  // codepoint boundary (never mid-sequence). Seeded at boot from
  // <dataDir>/hello.txt if present; the only other way it changes is the
  // dashboard's save (_setHello, which also rewrites the file).
  static constexpr size_t HELLO_MAX_BYTES = 160;
  std::string _getHello();
  // Normalize `raw` (strip trailing newlines, cap to HELLO_MAX_BYTES on a
  // codepoint boundary), write it to <dataDir>/hello.txt (creating the file
  // if absent), set it as the served hello, and return the normalized value.
  std::string _setHello(const std::string& raw);
  // Read <dataDir>/hello.txt and return its normalized contents (for the
  // dashboard's "load" button). Does NOT change the served hello; `existed`
  // reports whether the file was present.
  std::string _loadHelloFile(bool& existed);

  // ---- L2 handler support ----

  // ChannelMeter per-tick debit. Looks up the account
  // by `payerPfx`; if it exists AND has at least `amount` credits,
  // debits and calls cb(true). Otherwise leaves the account alone
  // and calls cb(false) — the caller (ChannelMeter) responds by
  // closing the channel.
  //
  // No nonce, no dedup — billing is server-authoritative and the
  // tick's idempotency comes from "we already advanced the gauges
  // and stored the new lastBilledAt". Posts to logicStrand, callback
  // hops to cbExecutor.
  void _l2DebitNetworkBill(
      const HashPrefix& payerPfx,
      int64_t amount,
      std::function<void(bool ok)> cb,
      boost::asio::any_io_executor cbExecutor);

  // Asset-ownership check — looks up the asset at `assetId` and
  // returns whether it exists AND its owner prefix matches the
  // signer's pubkey prefix. Used by the file handler's /f/ zone
  // to gate CREATE. Read-only ledger access. Posts to logicStrand,
  // callback hops to cbExecutor.
  void _l2CheckAssetOwner(
      const minx::Hash& assetId,
      const ces::PublicKey& signer,
      std::function<void(bool isOwner)> cb,
      boost::asio::any_io_executor cbExecutor);

  // ---------------------------------------------------------------------------
  // Program-account primitives
  // ---------------------------------------------------------------------------
  //
  // Files in the L2 file store carry an associated "program account":
  // a regular ledger Account in accountStore_, identified by a 32B
  // ed25519 public key. This is the unified balance pool that compute
  // supervision, Lua-side ces.transfer / ces.authentic_asset_create, and
  // file handler fee collection all debit. Inbound transfers (anyone →
  // this account) work normally; the program can also sign outbound ops
  // with the account's private key (held in the sidecar).
  //
  // The keypair is allocated once at file CREATE and stored in the
  // sidecar (program_pubkey / program_privkey). All running instances of
  // the same source file share the same program account.

  // Atomically debit `amount` from the program account at `pubkey`
  // on logicStrand_. If the account doesn't exist or balance <
  // amount, calls cb(false, currentBalance) and the account is
  // unchanged. On success calls cb(true, newBalance). Used by
  // every server-mediated outbound flow (compute supervisor,
  // Lua transfers, file fee collection).
  void _l2DebitProgramAccount(
      const minx::Hash& pubkey,
      int64_t amount,
      std::function<void(bool ok, int64_t newBalance)> cb,
      boost::asio::any_io_executor cbExecutor);

  // SYNC-BLOCKING variants of program-account ops.
  //
  // The caller's thread is blocked on a std::future while the work
  // runs on logicStrand_. The strand sets the promise and returns;
  // the caller wakes up. **Caller MUST NOT be running on
  // logicStrand_** (would deadlock).
  //
  // Sync helper for callers that are not yet async (file handler
  // CREDIT/DEBIT, compute supervisor tick). Slated for removal once
  // those callers go fully async.
  struct ProgramAccountDebitResult {
    bool ok;
    int64_t newBalance;
  };
  ProgramAccountDebitResult _l2DebitProgramAccountSync(
      const minx::Hash& pubkey, int64_t amount);
  void _l2CreditProgramAccountSync(
      const minx::Hash& pubkey, int64_t amount);
  // Read-only balance query. Returns the account's balance, or 0 if
  // the account doesn't exist (collected by daily maintenance).
  int64_t _l2ProgramAccountBalanceSync(const minx::Hash& pubkey);

  // The L2 verb primitive: run `fn` as one atomic logicStrand_ task with a
  // LedgerTxn over the account/asset stores (dedup + debit + credit + reads).
  // Blocks until the task completes. The caller must not be on logicStrand_
  // (would deadlock); a verb makes at most one of these per request.
  void _l2Transact(const std::function<void(LedgerTxn&)>& fn);

  // Program-initiated transfer. Origin is the program's owner pubkey
  // (the program acts as its owner — same model as fileHandlerExec).
  // Mode = Open (auto-creates destination), CES_NONCELESS, standard
  // tx + rent fees out of origin's balance. Wraps transfer() onto
  // logicStrand_, hops back to cbExecutor with the result code and
  // origin's post-call balance.
  void _l2Transfer(
      const minx::Hash& originKey,
      const minx::Hash& destKey,
      uint64_t amount,
      std::function<void(uint8_t rc, int64_t newOriginBalance)> cb,
      boost::asio::any_io_executor cbExecutor);

  // Program-initiated cross-transfer (home server is the originator).
  // Wraps crossTransfer() onto logicStrand_ — debits origin here, credits
  // the vostro for `destServer`, settles to destKey on that peer. Hops back
  // to cbExecutor with the result code and origin's post-call balance.
  void _l2CrossTransfer(
      const minx::Hash& originKey,
      const minx::Hash& destKey,
      uint64_t amount,
      const std::string& destServer,
      std::function<void(uint8_t rc, int64_t newOriginBalance)> cb,
      boost::asio::any_io_executor cbExecutor);

  // Off-strand asset creation for in-process callers (e.g. L2 service
  // handlers running on rpcTaskIO_). Hops onto logicStrand_, runs the
  // generic createAsset (origin pays/authorizes; ownerId controls the
  // result; balance carries days + flag bits; NONCELESS), then posts
  // the result code to cbExecutor. The caller supplies the full
  // 210-byte content — the server attaches no meaning to its bytes.
  void createAssetAsync(
      const minx::Hash& originKey,
      const HashPrefix& ownerId,
      const minx::Hash& assetId,
      const AssetData& content,
      uint16_t balance,
      std::function<void(uint8_t rc)> cb,
      boost::asio::any_io_executor cbExecutor);

  // Unsigned account query. Reads balance + nonce + lastXfer* on
  // logicStrand_, hops back to cbExecutor with the fields. Used by
  // ces.account_read in cesluajitd; identical semantics to
  // unsignedQueryAccount but async-and-thread-hopped.
  void _l2QueryAccount(
      const minx::Hash& accountKey,
      std::function<void(int64_t balance, uint32_t nonce,
                         HashPrefix lastXferDest,
                         uint64_t lastXferAmount,
                         uint32_t lastXferTime)> cb,
      boost::asio::any_io_executor cbExecutor);

  // ---- Extension funding rate gate (see local/extension_funding.md). A token
  // bucket refilling at cfg_.extFundingPerDay raw units/day, capped at one day's
  // worth. The grant is the only thing bounding what /s/ programs spend at remotes
  // (the server account is bottomless), so it lives here, never in Lua.
  // extFundingGrant RESERVES up to `requested` (returns what it could reserve);
  // the caller does the remote transfer and either keeps it or extFundingRefunds
  // on failure. Thread-safe (own mutex) — called off logicStrand_.
  uint64_t extFundingGrant(uint64_t requested);
  void     extFundingRefund(uint64_t amount);
  uint64_t extFundingRemaining();              // live available, for the gauge
  uint64_t extFundingPerDay() const {          // live rate (boot value, or last set)
    std::lock_guard<std::mutex> lk(extFundingMu_); return extFundingRatePerDay_;
  }
  void     extFundingSetPerDay(uint64_t perDay);   // operator sets the rate

  // CesConfig accessor — the file handler needs the resolved
  // feeFile / fileMaxBytes / cesplexFileDir after start() has
  // defaulted them.
  const CesConfig& _config() const { return cfg_; }

  // Server keypair accessor — L2 handlers (file handler) sign
  // their responses with the server's key so clients can store
  // receipts that prove "the server committed this state at this
  // time." Cost covered by per-op fees.
  const ces::KeyPair& _serverKeyPair() const { return serverKeyPair_; }

  // CesPlexHost — CesServer hosts the L2 bus on its rpc port. It signs
  // bind replies / responses with its own key and prices the per-channel
  // resource usage the bus measures.
  const ces::KeyPair& cesplexSigningKey() const override {
    return serverKeyPair_;
  }
  // The bus measures; the server prices. Charges `payer` for this tick's
  // resource usage at the live discounted feeNet* rates and closes the
  // channel if the payer can't cover it. Defined in server.cpp.
  void cesplexReportUsage(const HashPrefix& payer,
                          const minx::SockAddr& peer, uint32_t channelId,
                          const CesPlexUsage& usage) override;

  // Price a CesPlexUsage tick at the live discounted feeNet* rates -> credits
  // (0 = free). Shared by cesplexReportUsage and the compute handler's
  // per-instance-endpoint billing.
  uint64_t priceNetUsage(const CesPlexUsage& usage) const;

  // Debit a pre-priced net bill to `payerPfx` on logicStrand_, no close callback
  // (the per-instance endpoint owns its channel). Used by the compute handler to
  // bill a child's INBOUND luarpc usage to the caller. Pair with priceNetUsage.
  void debitNetworkBill(const HashPrefix& payerPfx, uint64_t amount);

  // The rpcTaskIO executor — L2 handlers that need to post work onto
  // the CesPlex / handler strand (e.g. the compute supervisor tick,
  // file-deletion interlocks) fetch the executor through this hook.
  // Returns a default-constructed executor if the rpc port isn't up
  // (no secondary Minx running); handlers should check with .target()
  // or equality-against-default before posting.
  boost::asio::any_io_executor _rpcTaskIOExecutor() {
    if (!rpcMinx_) return boost::asio::any_io_executor{};
    return rpcTaskIO_.get_executor();
  }

  // Test hook: if set, fires on logicStrand_ at the end of completeRpc
  // with the status code that would be handed to the followup VM
  // program's input. Lets tests observe async failures (timeout,
  // oversized response) without depending on a followup's side effects.
  std::function<void(uint8_t status)> _rpcCompletionObserver;

private:
  bool doSnapshot(const char* reason); // strand-only
  void _brrInner(const minx::Hash& accountKey, int64_t amount);
  void _burnInner(const minx::Hash& accountKey, int64_t amount);

  // Context describing how an individual VM run wires its host lambdas.
  // Two code paths use this: the CES_RUN_ASSET handler (undo-log + deferred
  // side effects) and the scheduled run handler (direct mutations, stubs).
  struct VmHostSetup {
    HashPrefix callerPrefix;
    HashPrefix programOwnerPrefix;

    // Hook called before mutating an account. Empty = no undo tracking.
    std::function<void(const HashPrefix&)> saveAccountFn;
    // Hook called before mutating an asset. Empty = no undo tracking.
    std::function<void(const minx::Hash&)> saveAssetFn;

    // Deferred side effects. Empty = side effect is discarded.
    std::function<void(const std::string&, uint16_t,
                       const uint8_t*, size_t)> sendUdpFn;
    // Invoked by VmHost::crossTransfer *after* it has pre-validated the peer,
    // checked settlement backpressure, and debited the caller + credited the
    // peer vostro via the undo log. executeVmRun buffers the dispatch and
    // fires it on commit, so an aborted VM cleanly rolls everything back. Both
    // run paths (wire and cron) go through executeVmRun, so both are atomic.
    // `peerKey` is the resolved peer public key (the settlement client key).
    std::function<void(const minx::Hash& dest, uint64_t amount,
                       const std::string& server,
                       const minx::Hash& peerKey)> crossTransferFn;

    // Invoked by SYS_SCHEDULE. Enqueues a future VM run paid by `callerPrefix`
    // and returns the schedule rc (CES_OK / QUEUE_FULL). executeVmRun records
    // the enqueue in the undo log so a VM abort rolls it back — an aborted run
    // must not leave a live scheduled run behind. Empty = syscall disabled.
    std::function<uint8_t(const minx::Hash& assetId, uint64_t budget,
                          uint64_t allowance, const ces::Bytes& input,
                          uint64_t time_us)> scheduleFn;

    // true = real signature verification; false = always return false.
    bool enableVerifySig = false;

    // Per-run cap on caller-account debits inside the VM (transfers, asset
    // purchases, protocol fees). UINT64_MAX = no enforcement. Both run paths
    // forward a per-run cap: the wire field on CES_RUN_ASSET, or the scheduled
    // run's carried-over allowance.
    uint64_t allowance = std::numeric_limits<uint64_t>::max();
  };

  // Production CesVMHost implementation. Defined in server.cpp; both VM
  // run paths (CES_RUN_ASSET dispatch and executeScheduledRun) construct
  // one inline as `VmHost vmHost(*this, setup);`, then assign callerKey /
  // selfAssetKey / programOwner / input before calling vm.execute().
  class VmHost;

  // CES_RUN_ASSET dispatch. Invoked on logicStrand_ after dispatchSigned
  // has verified the wire signature. Materializes the program asset,
  // opens an undo-log + deferred-effects context, runs the VM, and
  // commits or reverts. Factored out of the incomingMessage switch to
  // keep that function readable.
  void handleRunAsset(const CesRunAsset& req, const HashPrefix& originPrefix,
                      const SockAddr& addr, const MinxMessage& msg);

  // NONCELESS resolution, shared by the two time-boxed escape-hatch ops
  // (CES_OPEN_TRANSFER and CES_RUN_ASSET). Validates the dedup time window +
  // replay, then resolves the server-assigned nonce into `outNonce`. A non-
  // NONCELESS reqNonce short-circuits to Proceed with outNonce = reqNonce.
  // Callers map the verdict to their own reply shape.
  //
  // Dedup is CHECK-ONLY here: on Proceed it returns the op's sig-hash in
  // `outSigHash` (0 for non-NONCELESS), and the caller must `recordDedup` it
  // ONLY after the op commits a ledger event. This keys dedup on the committed
  // event, not the request — a failed op records nothing and stays retryable.
  enum class NoncelessResult { Proceed, Stale, Duplicate };
  NoncelessResult resolveNonceless(uint64_t time, const Signature& sig,
                                   const HashPrefix& originPrefix,
                                   uint32_t reqNonce, uint32_t& outNonce,
                                   uint64_t& outSigHash);

  // The neutral VM-execution transaction core. Both run paths (CES_RUN_ASSET
  // dispatch and executeScheduledRun) call this with the gas budget already
  // debited from the caller. It owns the undo log, the deferred side effects,
  // VM execution, commit-or-revert, the refund of unused budget, and the
  // durability flush — so a scheduled run is atomic exactly like a wire run.
  // Each caller keeps only what genuinely differs: gas reservation (nonce vs
  // prepaid), program-not-found policy, and the after-step (signed reply vs
  // schedule followup).
  struct VmRunRequest {
    HashPrefix callerPrefix;
    minx::Hash callerKey;          // full pubkey, preloaded into VM io
    minx::Hash selfAssetKey;       // the program's own asset key
    HashPrefix programOwnerPrefix;
    ces::Bytes code;               // program bytecode
    ces::Bytes input;
    uint64_t   budget = 0;         // already debited from the caller
    uint64_t   allowance = std::numeric_limits<uint64_t>::max();
    uint64_t   gasMult = 0;        // discounted (wire) or raw (cron)
    bool       enableVerifySig = false;
  };
  struct VmRunResult {
    uint8_t    rcode = 0;
    uint64_t   vmError = 0;
    uint64_t   budgetUsed = 0;
    uint64_t   allowanceUsed = 0;
    ces::Bytes output;
  };
  VmRunResult executeVmRun(const VmRunRequest& req);

  CesConfig cfg_;

  std::unique_ptr<minx::Minx> minx_;
  IOContext netIO_, taskIO_;
  std::thread netIOThread_;
  std::vector<std::thread> taskIOThreads_;

  // Second Minx instance, bound to a dedicated UDP port for the SYS_RPC
  // syscall. Only constructed if cfg_.rpcPort != 0 — otherwise rpcMinx_
  // stays null and the whole RPC path is disabled. The listener is a
  // value member (always present, always no-op) so we don't need a
  // conditional pointer owning it. IO contexts and threads are likewise
  // always present but only `run()` when the second Minx is active.
  CesRpcListener rpcListener_;
  // Rudp::Listener for rpcRudp_ — value member (always present), bound
  // to the Rudp at construction. Forwards onSend to rpcMinx_ and
  // onAccept to cesplex_ when the latter is alive.
  CesRpcRudpListener rpcRudpListener_{this};
  std::unique_ptr<minx::Minx> rpcMinx_;
  IOContext rpcNetIO_, rpcTaskIO_;
  std::thread rpcNetIOThread_;
  std::thread rpcTaskIOThread_;
  uint16_t rpcBoundPort_ = 0;

  // RUDP transport layered on rpcMinx_'s EXTENSION lane. Drives
  // outbound SYS_RPC calls (inbound handshakes are accepted at the
  // Rudp level but drop at the session demux when no session is
  // registered for the (peer, channel_id) pair). All Rudp access is
  // serialized on rpcTaskIO_'s single thread: the extension handler
  // (which calls Rudp::onPacket), the tick timer (which calls
  // Rudp::tick), and any push() initiated by an RpcSession. Only
  // constructed when cfg_.rpcPort != 0 — otherwise stays null.
  std::unique_ptr<minx::Rudp> rpcRudp_;
  std::shared_ptr<boost::asio::steady_timer> rpcTickTimer_;

  // RUDP-tier billing. Constructed alongside rpcRudp_ when rpc_port is
  // enabled. Bills per-channel byte/memory/age deltas against the bound
  // payer each tick; runs observability-only (delta tracking, no debits
  // or evictions) when the feeNet* rates are 0, the default.
  std::unique_ptr<ChannelMeter> channelMeter_;

  // CesPlex — the L2 protocol multiplexer. Lives on rpcTaskIO_,
  // owns inbound-channel dispatch for the secondary port. Handed the
  // mount map from cfg_.cesplexMounts at ctor. Null when
  // cfg_.rpcPort == 0 or cesplexMounts is empty (no point
  // constructing if nothing will ever be selectable). All callbacks
  // on rpcRudp_ that CesPlex installs run on rpcTaskIO_.
  //
  // Forward-declared: defined in ces/cesplex/mux.h — only included where
  // needed (server.cpp) to avoid pulling the rudp headers into every
  // consumer of server.h.
  std::unique_ptr<CesPlex> cesplex_;

  // SYS_RPC dispatcher state. queueRpc runs on the logic strand
  // (validates the file, materializes request bytes, signs the
  // envelope); executeRpc runs on rpcTaskIO_ (allocates a channel,
  // constructs an RpcSession, kicks off async_write); completeRpc
  // runs on the logic strand (writes response into the same file,
  // schedules the followup).
  std::atomic<size_t> rpcPendingCount_{0};

  // RpcSession holds per-call RudpStream + async state. Defined
  // out-of-line as a nested class in server.cpp — the header only
  // needs a forward declaration because all uses here are via
  // shared_ptr members, and the destructor of this class runs in
  // server.cpp where RpcSession is complete.
  class RpcSession;
  std::map<std::pair<minx::SockAddr, uint32_t>,
           std::shared_ptr<RpcSession>> rpcSessions_; // rpcTaskIO_ only

  // Host-callback entry point. Runs on the logic strand. Validates
  // the destination, the request file's auth + size, materializes
  // the request bytes, builds the signed envelope, and posts to
  // rpcTaskIO_. Returns CES_OK on successful queue, error code
  // otherwise.
  struct PendingRpc {
    std::string host;                  // destination host / IP (ASCII)
    uint16_t port = 0;
    minx::Hash fileHeadKey;            // the file — request source AND
                                       // response destination
    minx::Hash followupProgramKey;     // scheduled on completion
    minx::Hash selfAssetKey;           // running VM program's boot asset
    HashPrefix callerPrefix;           // account paying for the followup
    HashPrefix programOwnerPrefix{};   // owner of the boot asset
    uint64_t followupBudget = 0;
    uint64_t followupAllowance =
      std::numeric_limits<uint64_t>::max();
    uint32_t followupInputTag = 0;

    // Filled in by queueRpc before the call is posted to rpcTaskIO_.
    // Just the raw request body: the signed bind handshake happens once
    // on the channel, so the body itself is unwrapped (the bound channel
    // authenticates the sender — no per-rpc envelope).
    ces::Bytes requestBody;
  };

  uint8_t queueRpc(PendingRpc pending);
  void    executeRpc(std::shared_ptr<PendingRpc> pending);
  void    completeRpc(std::shared_ptr<PendingRpc> pending,
                       uint8_t errorCode,
                       ces::Bytes responseBody);

  boost::asio::strand<boost::asio::io_context::executor_type> logicStrand_;
  std::thread verifyPoWThread_;
  std::atomic<bool> receiving_{false};
  std::atomic<bool> running_{false};
  uint16_t boundPort_ = 0;
  std::atomic<bool> paused_{false};
  std::atomic<uint64_t> txCount_{0};

  KeyPair serverKeyPair_;

  // Extension funding token bucket (see extFundingGrant). ratePerDay_ is the live
  // rate (cfg_.extFundingPerDay copied at start, then operator-settable);
  // allowance_ in raw credit units; lastUs_ a steady-clock micros stamp. Mutex is
  // mutable so the const extFundingPerDay() accessor can lock.
  mutable std::mutex extFundingMu_;
  uint64_t           extFundingRatePerDay_ = 0;
  double             extFundingAllowance_ = 0.0;
  int64_t            extFundingLastUs_ = 0;
  void               extFundingRefillLocked();   // refill; caller holds the mutex

  // Operator hello banner (see _getHello/_setHello). Guarded by its own
  // mutex: read on the logic strand by queryServerInfo, written by the
  // dashboard's web thread.
  std::mutex helloMutex_;
  std::string helloMessage_;
  void loadHelloFromFile();  // boot seed from <dataDir>/hello.txt

  std::atomic<uint64_t> lastTimePoWQueueSizeUpdated_ = 0;
  std::atomic<uint16_t> powQueueSize_ = 0;

  // 1Hz metrics pulse. Drives every BucketGauge roll and every PointGauge
  // resample on a single shared timer (see metricsTick).
  BucketGauge<60>       tpsGauge_;
  BucketGauge<60>       l1cpuGauge_;     // strand busy_ns per second
  BucketGauge<60>       netRxTxGauge_;   // /proc/net/dev rx+tx delta per second
  std::atomic<uint16_t> tpsCurrent_{0};  // cached average for getters
  PointGauge            l1cpuBp_;
  PointGauge            l2cpuBp_;
  PointGauge            l1memacBp_;
  PointGauge            l1memasBp_;
  PointGauge            l2memBp_;
  PointGauge            netBp_;

  // Net sampler state (touched only on taskIO_ from metricsTick).
  uint64_t lastNetCumulative_      = 0;
  bool     lastNetCumulativeValid_ = false;
  double   netPeakBps_             = 0.0;

  // Per-FeeKind discount multiplier (basis points 0..10000). Refreshed
  // by metricsTick from the gauge each FeeKind is mapped to. Reads are
  // lock-free from any thread; the writer is the metrics tick.
  std::array<std::atomic<uint16_t>, kFeeKindCount> feeMult_;

  std::shared_ptr<boost::asio::steady_timer> metricsTimer_;
  std::shared_ptr<boost::asio::system_timer> dailyTimer_;

  static constexpr uint64_t SNAPSHOT_COOLDOWN_SECS = 30;
  uint64_t lastSnapshotTime_ = 0; // epoch seconds, strand-only access

  Accounts accounts_;
  Assets assets_;

  // Scheduled (delayed) runAsset entries — RAM only, not persisted.
  struct ScheduledRun {
    HashPrefix callerPrefix;     // account that pays for gas
    minx::Hash assetId;          // program to run
    uint64_t budget;             // gas budget
    uint64_t allowance =         // per-run caller-debit cap (default = none)
      std::numeric_limits<uint64_t>::max();
    ces::Bytes input;  // input data
    // true = budget already debited at submission (future-time wire
    // CES_RUN_ASSET); executeScheduledRun must not debit again.
    bool prepaid = false;
  };
  // Map key: (timeUs, seq) tuple. `timeUs` sorts entries by their firing
  // deadline; `seq` is a monotonic tiebreaker so two runs scheduled for
  // the same microsecond preserve insertion order (FIFO within the slot).
  struct ScheduleKey {
    uint64_t timeUs;
    uint64_t seq;
    auto operator<=>(const ScheduleKey&) const = default;
  };
  std::map<ScheduleKey, ScheduledRun> scheduledRuns_;
  uint64_t scheduledSeq_ = 0;   // monotonic sequence for insertion order
  std::shared_ptr<boost::asio::steady_timer> cronTimer_;

  // scheduleRun's core, plus the inserted ScheduleKey so a VM transaction's
  // undo log can erase the enqueue on abort. scheduleRun() is the thin wrapper
  // that discards the key (for callers with no rollback context).
  uint8_t scheduleRunUndoable(const HashPrefix& callerPrefix,
                              const minx::Hash& assetId, uint64_t budget,
                              uint64_t allowance, const ces::Bytes& input,
                              uint64_t time_us, bool prepaid,
                              ScheduleKey& outKey);

  // Presence cache: tracks last known address of authenticated clients
  // for unsolicited push (send()). Updated on every dispatchSigned.
  BucketCache<HashPrefix, SockAddr> presence_;

  // Reverse of presence_: addr → HashPrefix. Populated alongside
  // presence_.put and used by CES_APP_COMPUTE_MSG dispatch to stamp
  // a real sender_pfx on inbound program-bound messages. Guarded
  // by its own mutex since incomingApplication fires on taskIO_
  // while the compute handler reads on rpcTaskIO_. Entries may
  // outlive the presence cache's rotations (stale addresses never
  // evict); lookups that matter are validated by checking
  // presence_.get(prefix) == addr before trusting the result.
  std::mutex presenceReverseMutex_;
  std::map<SockAddr, HashPrefix> presenceReverse_;

  struct PendingReply {
    minx::SockAddr addr;
    minx::MinxMessage msg;
    std::chrono::steady_clock::time_point triggerTime;
  };

  std::mutex replyMutex_;
  std::deque<PendingReply> replyQueueFast_;
  std::deque<PendingReply> replyQueueSlow_;
  std::shared_ptr<boost::asio::steady_timer> replyTimer_;

  void checkPause();

  void replyStartTimer();
  void replyTick(const boost::system::error_code& ec);

  void tpsInc();
  void metricsTick(const boost::system::error_code& ec);
  void metricsStartTimer();
  // Body of one metrics tick. Always runs on taskIO_ — both the timer
  // and runMetricsTickOnce serialize through that executor.
  void metricsCompute();

  // /proc parsers used by metricsTick. Linux-only; plain ASCII files.
  double   readLoadAvg();        // /proc/loadavg field 1, or 0.0
  uint64_t readMemUsedBp();      // (MemTotal-MemAvailable)*10000/MemTotal
  uint64_t readNetCumulative();  // /proc/net/dev sum of rx+tx (skip lo:)

  // Wrap a strand-bound handler with chrono so its on-strand wall time
  // accumulates into l1cpuGauge_. This is the canonical way to enqueue
  // work on logicStrand_ from anywhere in CesServer; the alternative —
  // direct boost::asio::post(logicStrand_, ...) — is uninstrumented and
  // should be avoided except for the metrics path itself.
  //
  // Perf note: the wrapper captures [this, fn], so the composed handler is
  // larger than a bare post. Captures already near Boost.Asio's ~32 B
  // small-object buffer can tip over and heap-allocate per post (~100 ns).
  // Currently negligible (strand handlers do microseconds of real work). If a
  // profiler flags it, pool-allocate handler frames via
  // boost::asio::associated_allocator<Handler> rather than adding it now.
  template <class F>
  void postLogic(F&& f) {
    boost::asio::post(logicStrand_,
      [this, fn = std::forward<F>(f)]() mutable {
        auto t0 = std::chrono::steady_clock::now();
        fn();
        auto dt = std::chrono::steady_clock::now() - t0;
        l1cpuGauge_.record(static_cast<uint64_t>(
          std::chrono::duration_cast<std::chrono::nanoseconds>(dt).count()));
      });
  }

 public:
  // Gauge readouts (basis points, 0..10000). Readable from any thread.
  uint16_t getL1cpuBp() const  { return static_cast<uint16_t>(l1cpuBp_.load()); }
  uint16_t getL2cpuBp() const  { return static_cast<uint16_t>(l2cpuBp_.load()); }
  uint16_t getL1memacBp() const{ return static_cast<uint16_t>(l1memacBp_.load()); }
  uint16_t getL1memasBp() const{ return static_cast<uint16_t>(l1memasBp_.load()); }
  uint16_t getL2memBp() const  { return static_cast<uint16_t>(l2memBp_.load()); }
  uint16_t getNetBp() const    { return static_cast<uint16_t>(netBp_.load()); }

  // Test hook: raw strand busy-ns sum over the active 60s window.
  // bp truncates anything below ~6ms, so unit tests assert on this
  // directly to detect that postLogic instrumentation is wired.
  uint64_t getL1cpuBusyNs() const  { return l1cpuGauge_.sum(); }

  // Test hook: run the metrics readout/refresh once, synchronously.
  // Equivalent to one timer fire without rescheduling. Lets tests
  // exercise gauge → bp → multiplier wiring without sleeping.
  void runMetricsTickOnce();

  // Look up the discount multiplier (bp 0..10000) for a fee kind.
  // Pinned to 10000 when cfg_.feeDiscountEnabled is false.
  uint16_t getFeeMult(FeeKind k) const {
    return feeMult_[static_cast<std::size_t>(k)].load(
             std::memory_order_relaxed);
  }

  // Apply the discount: raw fee × FeeKind's multiplier / 10000. Use
  // this at every named-fee debit site instead of billing raw.
  uint64_t discountFee(FeeKind k, uint64_t raw) const {
    uint64_t bp = getFeeMult(k);
    return (raw == 0) ? 0 : (raw * bp / 10000);
  }

  // Convenience: resolveFee + flat discount in one. Prepay-days fees
  // use attenuatedFundCost separately; this is for one-shot op fees.
  int64_t discountedFlatFee(int64_t passedFee, int64_t defaultFee,
                            FeeKind k) const {
    int64_t f = resolveFee(passedFee, defaultFee);
    return static_cast<int64_t>(discountFee(k, static_cast<uint64_t>(f)));
  }

  // Cost of prepaying `daysAdded` days of a per-day fee, given that
  // `daysAlreadyHeld` days are already on the cell. The discount
  // attenuates linearly to zero over kPrepaidDiscountWindowDays —
  // every day at distance D ≥ window from now is full price, every
  // day closer than that pays a blended (bp..10000) rate. Prevents
  // funding years of cheap rent during idle bp.
  uint64_t attenuatedFundCost(FeeKind k,
                              uint64_t feePerDay,
                              uint32_t daysAdded,
                              uint32_t daysAlreadyHeld) const;
 private:

  void dailyTaskTick(const boost::system::error_code& ec);
  void dailyTaskStartTimer();

  void cronTick(const boost::system::error_code& ec);
  void cronStartTimer();
  bool executeScheduledRun(ScheduledRun& run); // returns false if account gone/broke
  void runAutoexec(); // scan assets for autoexec keys, execute on boot

  // One-shot at boot: force the server's own account to exactly the
  // TARGET balance. Deeply bottomless yet far below INT64_MAX, so
  // deposits and fee receipts can never overflow signed-int64 addition;
  // forcing (not just topping up) also heals a stale balance corrupted
  // by an older build. The server account is counted in the raw credit
  // tally like any other and subtracted out at the stat
  // (circulatingCredits()).
  // Strand-only access (called via post(logicStrand_, ...)).
  void topUpServerAccount();

  // One-shot at boot, after the asset store has loaded from disk and
  // the server account has been topped up. Unconditionally writes the
  // canonical bytecode for each shipped `/b/<name>` program over
  // whatever asset (if any) sits at sha256("/b/<name>"). The `/b/`
  // prefix is reserved by convention for server-deployed bytecode
  // programs — owner = server, content = current build's bytecode,
  // days = max, no flag bits, price = 0. Squat-resistant: a user who
  // races to register the well-known key before this build first ships
  // the program loses on the next boot. Idempotent across reboots.
  // Strand-only access.
  void deployBuiltinVmPrograms();

  // One-shot at boot, after CesPlex/file/compute handlers have all
  // bound: deploy any [extension] /s/<name>.lua sources to the file
  // store (if missing) and launch one cesluajitd instance of each.
  // Posted onto rpcTaskIO_ — the file deploy uses the
  // fileHandlerEnsureServerFile cross-handler primitive; the launch
  // uses computeHandlerLaunchInternal. Skipped silently if any
  // prereq is missing (compute disabled, file disabled, etc.).
  void launchExtensions();

  void reply(const SockAddr& addr, const MinxMessage& msg);

  template <typename ResT>
  void sendSignedReply(const SockAddr& addr, const MinxMessage& msg, ResT res);

  template <typename ResT>
  void sendUnsignedReply(const SockAddr& addr, const MinxMessage& msg, ResT res);

  template <typename ReqT, typename Fn>
  void dispatchSigned(const SockAddr& addr, const MinxMessage& msg,
                      ReqT req, const Hash& keyField, Fn&& fn,
                      bool noncelessOk = false);

  int64_t resolveFee(int64_t passedFee, int64_t defaultFee) const;
  void checkAutoSnapshot();

  // -- Peer table --
  struct PeerEntry {
    minx::Hash ckey{};
    std::string declaredAddress;
    boost::asio::ip::address resolvedIP;
    // Full endpoint the peer miner resolved off-strand, so
    // getOrCreateSettlementClient never does a blocking getaddrinfo on the logic
    // strand. Runtime-only; not persisted (re-resolved on the next probe).
    boost::asio::ip::udp::endpoint resolvedEndpoint;
    bool resolvedEndpointValid = false;
    uint64_t totalInboundPoW = 0;
    uint64_t totalOutboundPoW = 0;
    int64_t ourBalanceThere = -1;
    uint64_t lastInboundTime = 0;
    uint64_t lastCheckTime = 0;
    bool reachable = false;
    bool verified = false;
    bool outbound = false;
    uint32_t pingFailures = 0;
    uint16_t rpcPort = 0;   // peer's CesPlex rpc port, learned at probe time
  };

  std::mutex peerTableMutex_;
  std::vector<PeerEntry> peerTable_;
  void upsertPeer(const minx::Hash& ckey, const std::string& address,
                   uint64_t inboundCredit);

  // -- Auto-nonce dedup constants --
  static constexpr uint64_t DEDUP_WINDOW_US = 3600ULL * 1000000;
  static constexpr uint64_t DEDUP_FUTURE_DRIFT_US = 300ULL * 1000000;

  static constexpr size_t MAX_PERSISTED_PEERS = 100;
  static constexpr size_t MAX_INMEM_PEERS = 2 * MAX_PERSISTED_PEERS;
  static constexpr uint32_t PEER_EVICTION_THRESHOLD = 5000;

  // Peer management
  void loadPeerData();
  void savePeerData();
  std::thread peerMinerThread_;
  std::atomic<bool> peerMinerRunning_{false};
  // Serializes ensurePeerMinerStarted()'s spawn against stop()'s join decision.
  std::mutex peerMinerLifecycleMutex_;
  void peerMinerLoop();

  // Runtime peer-credit target. Seeded from cfg_.peerTarget in the ctor and
  // read by the miner each cycle; the dashboard can change it live (CesConfig
  // is copyable, so its field can't itself be atomic). `peerMinerRunning_`
  // doubles as the spawn guard: ensurePeerMinerStarted() compare-exchanges it
  // so the miner thread is created exactly once even if peering is turned on
  // at runtime from a server that booted with target 0.
  std::atomic<uint64_t> peerTarget_{0};
  void ensurePeerMinerStarted();

  // Peer miner heartbeat — unix seconds of the last completed cycle and a
  // cumulative cycle count, surfaced to the dashboard so the operator can see
  // that the otherwise-opaque peering thread is alive and working.
  std::atomic<uint64_t> lastPeerMinerCycle_{0};
  std::atomic<uint64_t> peerMinerCycles_{0};
  // Live "actively mining" state (vs. just looping/probing) for the dashboard —
  // set only around the mineOnce() call. Guarded by its own mutex (the string
  // can't be atomic); read off-thread by the web layer via _peerMinerActivity().
  mutable std::mutex peerMinerActivityMutex_;
  bool peerMinerMining_ = false;
  std::string peerMinerMiningPeer_;
  uint8_t peerMinerMiningDiff_ = 0;
  uint64_t peerMinerMiningStartSecs_ = 0;  // when the current solve began
  double peerMinerHashRate_ = 0.0;         // EMA H/s from completed solves

  // Auto-nonce dedup table
  std::mutex dedupMutex_;
  std::unordered_set<uint64_t> dedupCurrent_;
  std::unordered_set<uint64_t> dedupOlder_;
  uint64_t dedupBaseTime_ = 0;
  // Atomic check+insert — used where seeing the request IS the dedupable
  // event (CesPlex per-op bind dedup).
  bool checkAndInsertDedup(uint64_t sigHash, uint64_t epochNow = 0);
  // Split check / record — used by NONCELESS ops, which must record the
  // dedup only after the op commits a ledger event (so a failed op stays
  // retryable). See resolveNonceless / recordDedup call sites.
  bool isDuplicateDedup(uint64_t sigHash, uint64_t epochNow = 0);
  void recordDedup(uint64_t sigHash, uint64_t epochNow = 0);
  void rotateDedupLocked(uint64_t epochNow);  // caller holds dedupMutex_

  // Async cross-transfer settlement
  IOContext settlementIO_;
  std::unique_ptr<boost::asio::executor_work_guard<IOContext::executor_type>>
    settlementWorkGuard_;
  std::thread settlementThread_;
  std::unordered_map<std::string, std::unique_ptr<CesClientAsync>>
    settlementClients_;
  CesClientAsync* getOrCreateSettlementClient(const std::string& address,
                                               const minx::Hash& peerKey);

};

} // namespace ces