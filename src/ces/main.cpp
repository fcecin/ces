/**
 * ces - A Hashcash server built on MINX
 *
 * Supports TOML config file (--config file.toml) and CLI switches.
 * CLI switches override config file values.
 * --config without argument dumps default config to stdout and exits.
 */

#include <chrono>
#include <filesystem>
#include <thread>
#include <unistd.h>

#include <CLI/CLI.hpp>
#include <toml++/toml.hpp>

#include <ces/cesco.h>
#include <ces/cesweb.h>
#include <ces/util/ctrlc.h>
#include <ces/util/log.h>
#include <ces/util/helpers.h>
#include <ces/server.h>

#include <minx/blog.h>

using namespace ces;

static const std::string DEFAULT_DATA_DIR = "./data";
static const std::string DEFAULT_PRIV_KEY_HEX_STR =
  "3fdade772f129d5b43e36fab610c77db6a4a697e9d0899b24b4254f0968aa7b5";

// Single source of truth for every value that appears both as a CLI11
// `default_val` and in the `dumpDefaultConfig()` TOML template. If you add
// a new option, add the constant here so the two stay in sync automatically.
constexpr uint64_t DEFAULT_MIN_ACC         = 131072;
constexpr uint64_t DEFAULT_MAX_ACC         = 16777216;
constexpr uint64_t DEFAULT_MIN_ASSET       = 131072;
constexpr uint64_t DEFAULT_MAX_ASSET       = 16777216;
constexpr uint8_t  DEFAULT_MIN_DIFF        = 10;
constexpr uint64_t DEFAULT_POW_DELAY       = 0;
constexpr uint64_t DEFAULT_SPEND_SLOT_SIZE = 3600;
constexpr uint64_t DEFAULT_FLUSH_VALUE     = 0;
constexpr uint64_t DEFAULT_MAX_LOG_SIZE_GB     = 100;
constexpr uint64_t DEFAULT_PEER_TARGET         = 0;
constexpr uint64_t DEFAULT_PEER_POW_INBOUND_RECIPROCATION_BPS = 0;

void dumpKeyPair(const KeyPair& keyPair) {
  std::cout << "Private Key: " << keyPair.getPrivateKeyHexStr() << std::endl;
  std::cout << "Public Key:  " << keyPair.getPublicKeyHexStr() << std::endl;
  exit(0);
}

// Dump default config to stdout.
void dumpDefaultConfig() {
  int defaultThreads =
    static_cast<int>(std::thread::hardware_concurrency()) / 2 - 2;
  if (defaultThreads < 1) defaultThreads = 1;

  std::cout << R"(# CES Server Configuration
# Load with: ces --config <file>

# Log level: trace, debug, info, warning, error, fatal
log_level = "info"

# Data directory for account/asset persistence
data_dir = ")" << DEFAULT_DATA_DIR << R"("

# Server UDP port
port = )" << DEFAULT_PORT << R"(

# Server private key (32-byte hex). Generate with: ces --genkeypair
server_key = ")" << DEFAULT_PRIV_KEY_HEX_STR << R"("

# Minimum proof-of-work difficulty
min_difficulty = )" << static_cast<int>(DEFAULT_MIN_DIFF) << R"(

# Delay in seconds before accepting PoW after startup (0 = immediate)
pow_delay = )" << DEFAULT_POW_DELAY << R"(

# Size of the PoW double-spend tracking slots in seconds
spend_slot_size = )" << DEFAULT_SPEND_SLOT_SIZE << R"(

# Don't create the RandomX verifier (no mining)
no_pow_engine = false

# Use cache-only RandomX (slower verification, less RAM)
cache_only_pow = false

# Number of task processing threads
threads = )" << defaultThreads << R"(

# Reserved account DB capacity (power of 2)
min_accounts = )" << DEFAULT_MIN_ACC << R"(

# Maximum accounts (power of 2)
max_accounts = )" << DEFAULT_MAX_ACC << R"(

# Reserved asset DB capacity (power of 2)
min_assets = )" << DEFAULT_MIN_ASSET << R"(

# Maximum assets (power of 2)
max_assets = )" << DEFAULT_MAX_ASSET << R"(

# Minimum value delta for flushing to OS buffers (0 = flush everything)
flush_value = )" << DEFAULT_FLUSH_VALUE << R"(

# Max events log size in GB before auto-snapshot (0 = disable)
max_log_size_gb = )" << DEFAULT_MAX_LOG_SIZE_GB << R"(

# Fees (in internal units, -1 = use built-in defaults)
# fee_account = -1
# fee_asset = -1
# fee_tx = -1
# fee_query = -1
# fee_vm_mult = )" << ces::BASE_FEE_VM_MULT << R"(

# Server's public address (optional, for peer discovery)
# If set, included in PoW submissions to peer servers.
# server_name = "myserver.example.com:53830"

# Peering: target credit balance to maintain on each peer server
peer_target = )" << DEFAULT_PEER_TARGET << R"(

# Inbound PoW reciprocation (basis points): outbound PoW we mine per unit of
# inbound PoW a peer mines on us. 0 = off (never mine on inbound-only peers).
# 10000 = 1:1, 20000 = 2x, 5000 = half. Outbound peers ignore this.
peer_pow_inbound_reciprocation_bps = )" << DEFAULT_PEER_POW_INBOUND_RECIPROCATION_BPS << R"(

# Async settlement max retries per operation (1 = no retries, for testing)
settlement_max_retries = )" << CesClientAsync::DEFAULT_MAX_RETRIES << R"(

# Admin console (Unix domain socket). Empty or omitted = disabled.
# admin_socket = "./admin.sock"

# Web dashboard (HTTP). Loopback only, NO authentication — reach it by
# SSH-tunneling to the host (e.g. ssh -L 8080:127.0.0.1:8080 host). The
# operator's control panel: peering, minting, lookups, billing, live log
# tail, and the server-info "hello" banner. 0 = disabled (default).
# web_port = 0
# web_bind = "127.0.0.1"

# Dedicated MINX/RUDP UDP port for the SYS_RPC syscall. 0 = disabled
# (no second Minx instance, SYS_RPC returns CES_ERROR_DISABLED). When
# nonzero, CES binds a second Minx on this port with a no-op listener;
# the port can be opened or closed at the firewall independently from
# the main CES protocol port.
rpc_port = 0

# SYS_RPC outbound flow control (only relevant when rpc_port != 0).
# - rpc_max_pending: cap on concurrent outbound calls; queueRpc returns
#   CES_ERROR_QUEUE_FULL beyond this.
# - rpc_max_request_bytes / rpc_max_response_bytes: size caps per call.
# - rpc_response_timeout_ms: per-call asio timer firing CES_ERROR_TIMEOUT.
# - rpc_rudp_bytes_per_second / rpc_rudp_burst_bytes: per-channel RUDP
#   pacing advertised in the handshake. 4294967295 = unlimited.
rpc_max_pending = 1000
rpc_max_request_bytes = 65536
rpc_max_response_bytes = 65536
rpc_response_timeout_ms = 30000
rpc_rudp_bytes_per_second = 4294967295
rpc_rudp_burst_bytes = 4294967295

# Transport caps on the rpc_port's RUDP. max_channels_per_peer is a
# CES opinion (default 2 — cesh/cesqt typically want a long-lived
# stream open while issuing other ops). The two reorder caps bound
# per-channel reassembly; -1 = leave the library default (currently
# 1 MB / 1024 messages).
[rpc_rudp]
max_channels_per_peer = 2
max_reorder_bytes_per_channel = -1
max_reorder_msgs_per_channel = -1

# --- File-storage feature (CesPlex builtin:file, v2) ---
#
# Master switch + hard capacity cap for the file-storage feature.
#   0 = feature OFF (default). /ces/file/* channels return nothing.
#   >0 = feature ON with a byte-cap. CREATE is rejected when the new
#        file's size would push total_bytes past this value.
# file_store_max_bytes = 0
#
# Storage directory (empty = "<data_dir>/cesfilestore").
# file_store_dir = ""
#
# Three fee knobs mapping to three physical costs. -1 = use default.
#   fee_file_rent  — retention (per byte per day)
#   fee_file_write — network + SSD write (per KB at WRITE)
#   fee_file_read  — network + SSD read  (per KB at READ)
# CREATE has no per-byte cost; rent starts accruing, paid from
# file_balance (which the signer deposits into at CREATE).
# fee_file_rent  = -1
# fee_file_write = -1
# fee_file_read  = -1
#
# --- Compute feature (CesPlex builtin:compute) ---
#
# Master switch + hard caps. Feature is OFF when
# compute_max_instances = 0 — the compute handler refuses to bind
# and all inbound /ces/compute/1 selects NACK. Bind also requires
# that builtin:file is mounted (compute uses the file handler for
# owner-authority file ops) and that compute_user exists on the
# host system.
# compute_max_instances    = 0       # 0 = OFF; caps child processes — the
#                                    # whole admission bound (× mem cap = RAM)
#
# L2 compute program UDP port range: [compute_port_base,
# compute_port_base + compute_port_count - 1]. Each instance binds its
# outbound CES client to a server-assigned port from this range — the
# child never picks an ephemeral port (a firewalled L2 host opens only
# known ports). Base and count are independent of compute_max_instances;
# open exactly [base, base+count-1] at the firewall to match. base = 0 =
# no range: instances run local-only and their outbound network verbs
# fail with "networking disabled". An exhausted range is NOT a launch
# failure — those instances just run local-only too.
# compute_port_base        = 0
# compute_port_count       = 0
#
# Per-process memory ceiling — RLIMIT_AS in the child (the kernel denies
# allocations past it; OOM is an instant, machine-wide attack vector).
# With compute_max_instances this bounds total compute memory. CPU is
# billed, not capped; the sandbox forbids forking.
# compute_process_mem_max  = 268435456   # 256 MB ceiling per process
#
# Fees — credits per unit time / per byte. -1 = use default.
#   fee_compute_cpu_sec     — CPU time, per second (unused in stub phase)
#   fee_compute_rss_byte_day — RSS, per byte per second (unused in stub phase)
#   fee_compute_net_byte    — outbound APPLICATION bytes, per byte
#   fee_compute_slot_sec    — nominal "occupy a slot" fee, per wall-second.
#                             Only fee actually charged in the stub phase.
#                             Default: rent on a 1 KB file per second
#                             (derived from fee_file_rent).
# fee_compute_cpu_sec      = -1
# fee_compute_rss_byte_day = -1
# fee_compute_net_byte     = -1
# fee_compute_slot_sec     = -1
# fee_bucket_byte_sec      = -1   # ces.bucket_new committed-capacity rent
#
# Storage dir for per-instance scratch / IPC sockets.
# compute_work_dir = ""   # default "<data_dir>/cescompute/"
#
# Unix user cesluad child processes drop to (must exist on host).
# compute_user = "cesluad"
#
# Compute child binary path. Empty/unset (default) = auto-discover
# `cesluajitd` next to ces's own binary (/proc/self/exe), then fall
# back to bare-name PATH lookup. Set explicitly to use a specific
# binary or pin a path that's not next to ces.
# compute_child_binary = ""

# CesPlex mounts. Each entry maps a protocol name to a target. Empty
# table (the default) disables all L2 protocol handlers even if the
# rpc_port is open. To enable the file feature, mount it here AND
# set file_store_max_bytes > 0. To enable compute, mount both
# /ces/file/1 and /ces/compute/1 AND set compute_max_instances > 0.
# [cesplex_mounts]
# "/ces/file/1"    = "builtin:file"
# "/ces/compute/1" = "builtin:compute"

# /s/ builtin apps — operator-deployed Lua programs that get
# autolaunched at boot. Drop dice.lua / chat.lua / etc. into
# <storeDir>/s/; the server auto-generates the sidecar (owner =
# server pubkey, file_balance = 0, /s/ is unmetered) and, for any
# name listed below as truthy, launches one cesluajitd instance.
# Programs in /s/ run with owner = server, so ces.transfer pulls
# from the server's bottomless auto-topped account.
#
# Names are arbitrary; the value just needs to be truthy.
# Requires: rpc_port > 0, builtin:file with file_store_max_bytes > 0,
# and builtin:compute with compute_max_instances > 0.
# [builtin_app]
# dice = 1    # /s/dice.lua
# chat = 1    # /s/chat.lua, etc.

# Peer servers
# [[peers]]
# key = "public_key_hex_of_peer_server"
# address = "host:port"
#
# [[peers]]
# key = "another_peer_key"
# address = "host2:port2"
)";
}

int main(int argc, char* argv[]) {
  blog::enable("minx");
  blog::enable("powengine");

  // -- CLI Options --
  std::string optLogLevel;
  std::string optDataDir;
  uint16_t optServerPort;
  std::string optServerPrivKey;
  uint64_t optMinAcc;
  uint64_t optMaxAcc;
  uint64_t optMinAsset;
  uint64_t optMaxAsset;
  uint8_t optMinDiff;
  uint64_t optPoWDelay;
  uint64_t optSpendSlotSize;
  std::string optGeneratePubKey;
  uint64_t optFlushValue = 0;
  uint64_t optMaxLogSizeGB = DEFAULT_MAX_LOG_SIZE_GB;
  int64_t optFeeAccount = -1;
  int64_t optFeeAsset = -1;
  int64_t optFeeTx = -1;
  int64_t optFeeQuery = -1;
  int64_t optFeeVmMult = -1;
  bool optGenerateKeyPair = false;
  bool optNoPowEngine = false;
  bool optCacheOnlyPoWEngine = false;
  int defaultOptTaskThreads =
    static_cast<int>(std::thread::hardware_concurrency()) / 2 - 2;
  int optTaskThreads = defaultOptTaskThreads;
  if (optTaskThreads < 1) optTaskThreads = 1;
  std::string optConfigFile;
  std::string optServerName;
  uint64_t optPeerTarget = 0;
  uint64_t optPeerPowInboundReciprocationBps = 0;
  int optPeerMinerInterval = 60;
  int optSettlementMaxRetries = CesClientAsync::DEFAULT_MAX_RETRIES;
  std::string optAdminSocket;
  uint16_t optWebPort = 0;
  std::string optWebBind = "127.0.0.1";
  uint16_t optRpcPort = 0;
  uint32_t optRpcMaxPending        = 1000;
  uint64_t optRpcMaxRequestBytes   = 64 * 1024;
  uint64_t optRpcMaxResponseBytes  = 64 * 1024;
  uint32_t optRpcResponseTimeoutMs = 30000;
  uint32_t optRpcRudpBytesPerSecond = 0xFFFFFFFFu;
  uint32_t optRpcRudpBurstBytes     = 0xFFFFFFFFu;
  uint64_t optRpcRudpMaxChannelsPerPeer        = 2;
  int64_t  optRpcRudpMaxReorderBytesPerChannel = -1;
  int64_t  optRpcRudpMaxReorderMsgsPerChannel  = -1;
  // File-storage feature (CesPlex builtin:file, v2).
  uint64_t optFileStoreMaxBytes = 0;
  std::string optFileStoreDir;
  int64_t optFeeFileRent  = -1;
  int64_t optFeeFileWrite = -1;
  int64_t optFeeFileRead  = -1;
  // Compute feature (CesPlex builtin:compute).
  uint32_t optComputeMaxInstances    = 0;
  uint16_t optComputePortBase        = 0;   // 0 = no range (network off)
  uint16_t optComputePortCount       = 0;   // ports in the range
  uint64_t optComputeProcessMemMax   = 268435456; // 256 MB
  int64_t optFeeComputeCpuSec     = -1;
  int64_t optFeeComputeRssByteSec = -1;
  int64_t optFeeComputeNetByte    = -1;
  int64_t optFeeComputeSlotSec    = -1;
  int64_t optFeeBucketByteSec     = -1;
  std::string optComputeWorkDir;
  std::string optComputeUser = "cesluad";
  // Empty default → auto-discover next to /proc/self/exe at startup
  // (typical case: ces and cesluajitd are siblings in the same dir).
  // Operators who want PATH lookup or an absolute path set it
  // explicitly via TOML or --computechildbinary.
  std::string optComputeChildBinary;
  // /s/ builtin apps — operator-deployed Lua programs in
  // <storeDir>/s/<name>.lua, autolaunched at boot when enabled.
  // Names are arbitrary basenames; CLI flag is repeatable.
  std::vector<std::string> optBuiltinApps;
  // CesPlex mounts — `proto=target` pairs. Target is
  // "builtin:<name>" (statically linked handler).
  std::vector<std::string> optCesplexMounts;
  std::vector<std::string> optPeers; // key@host:port
  std::string optCreditAccount, optDebitAccount;
  int64_t optCreditAmount = 0, optDebitAmount = 0;
  CLI::App* cmd_credit = nullptr;
  CLI::App* cmd_debit = nullptr;
  CLI::App* cmd_snapshot = nullptr;

  CLI::App app{"ces"};
  try {
    app.add_option("-l,--loglevel", optLogLevel,
      "Log level ([t]race, [d]ebug, [i]nfo, [w]arning, [e]rror, [f]atal)")
      ->default_val("info");
    app.add_option("-d,--datadir", optDataDir, "Data directory")
      ->default_val(DEFAULT_DATA_DIR);
    app.add_option("-p,--port", optServerPort, "Server port")
      ->default_val(DEFAULT_PORT);
    app.add_option("-k,--serverkey", optServerPrivKey,
      "Server key (32-byte hex)")
      ->default_val(DEFAULT_PRIV_KEY_HEX_STR);
    app.add_option("--minacc", optMinAcc,
      "Reserved account DB store capacity")
      ->default_val(std::to_string(DEFAULT_MIN_ACC));
    app.add_option("--maxacc", optMaxAcc,
      "Maximum account DB size")
      ->default_val(std::to_string(DEFAULT_MAX_ACC));
    app.add_option("--minasset", optMinAsset,
      "Reserved asset DB store capacity")
      ->default_val(std::to_string(DEFAULT_MIN_ASSET));
    app.add_option("--maxasset", optMaxAsset,
      "Maximum asset DB size")
      ->default_val(std::to_string(DEFAULT_MAX_ASSET));
    app.add_option("--flushvalue", optFlushValue,
      "Minimum value delta for flushing")
      ->default_val(std::to_string(DEFAULT_FLUSH_VALUE));
    app.add_option("--mindiff", optMinDiff,
      "Minimum proof-of-work difficulty")
      ->default_val(std::to_string(DEFAULT_MIN_DIFF));
    app.add_option("--powdelay", optPoWDelay,
      "Delay in seconds before accepting PoW")
      ->default_val(std::to_string(DEFAULT_POW_DELAY));
    app.add_option("--spendslotsize", optSpendSlotSize,
      "Size of spend db slots in seconds")
      ->default_val(std::to_string(DEFAULT_SPEND_SLOT_SIZE));
    app.add_option("--genpubkey", optGeneratePubKey,
      "Generate public key from private key")->default_val("");
    app.add_option("--threads", optTaskThreads,
      "Number of task processing threads")->default_val(defaultOptTaskThreads);
    app.add_option("--maxlogsize", optMaxLogSizeGB,
      "Max events log size in GB (0=disable)")
      ->default_val(std::to_string(DEFAULT_MAX_LOG_SIZE_GB));
    app.add_flag("--genkeypair", optGenerateKeyPair,
      "Generate a new Ed25519 key pair");
    app.add_flag("--nopowengine,-x", optNoPowEngine,
      "Don't create the RandomX verifier");
    app.add_flag("--cacheonlypowengine,-c", optCacheOnlyPoWEngine,
      "Cache-only RandomX verifier (slower, less RAM)");
    app.add_option("--feeaccount", optFeeAccount, "Fee for account rent");
    app.add_option("--feeasset", optFeeAsset, "Fee for asset operations");
    app.add_option("--feetx", optFeeTx, "Fee for transactions");
    app.add_option("--feequery", optFeeQuery, "Fee for queries");
    app.add_option("--feevmmult", optFeeVmMult, "VM gas cost multiplier");
    app.add_option("--config", optConfigFile,
      "Load TOML config file (no arg = dump default config)")
      ->expected(0, 1);
    app.add_option("--servername", optServerName,
      "Server's public address (e.g. myserver.com:53830)");
    app.add_option("--peertarget", optPeerTarget,
      "Credit target on each peer server")
      ->default_val(std::to_string(DEFAULT_PEER_TARGET));
    app.add_option("--peerpowinboundreciprocationbps",
      optPeerPowInboundReciprocationBps,
      "Inbound PoW reciprocation, basis points (0=off, 10000=1:1)")
      ->default_val(std::to_string(DEFAULT_PEER_POW_INBOUND_RECIPROCATION_BPS));
    app.add_option("--peerminerinterval", optPeerMinerInterval,
      "Seconds between peer miner cycles (default 60; lower for local/dev)")
      ->default_val("60");
    app.add_option("--settlementretries", optSettlementMaxRetries,
      "Async settlement max retries (1 = no retries)")
      ->default_val(std::to_string(CesClientAsync::DEFAULT_MAX_RETRIES));
    app.add_option("--adminsocket", optAdminSocket,
      "Admin console Unix socket path (empty = disabled)")->default_val("");
    app.add_option("--webport", optWebPort,
      "Web dashboard port (0 = disabled). Loopback only, no auth — "
      "reach it via SSH tunnel.")->default_val("0");
    app.add_option("--webbind", optWebBind,
      "Web dashboard bind address (loopback by design)")
      ->default_val("127.0.0.1");
    app.add_option("--rpcport", optRpcPort,
      "Dedicated MINX/RUDP UDP port for the SYS_RPC syscall "
      "(0 = disabled)")->default_val("0");
    app.add_option("--rpcmaxpending", optRpcMaxPending,
      "SYS_RPC: max concurrent outbound calls in flight")
      ->default_val("1000");
    app.add_option("--rpcmaxreqbytes", optRpcMaxRequestBytes,
      "SYS_RPC: max request body size in bytes")
      ->default_val(std::to_string(64 * 1024));
    app.add_option("--rpcmaxrespbytes", optRpcMaxResponseBytes,
      "SYS_RPC: max response body size in bytes")
      ->default_val(std::to_string(64 * 1024));
    app.add_option("--rpctimeoutms", optRpcResponseTimeoutMs,
      "SYS_RPC: per-call response timeout in milliseconds")
      ->default_val("30000");
    app.add_option("--rpcrudpbps", optRpcRudpBytesPerSecond,
      "SYS_RPC: per-channel RUDP pacing rate in bytes/sec "
      "(0xFFFFFFFF = unlimited)")
      ->default_val(std::to_string(0xFFFFFFFFu));
    app.add_option("--rpcrudpburst", optRpcRudpBurstBytes,
      "SYS_RPC: per-channel RUDP burst bytes "
      "(0xFFFFFFFF = unlimited)")
      ->default_val(std::to_string(0xFFFFFFFFu));
    app.add_option("--rpcrudpmaxchannels",
      optRpcRudpMaxChannelsPerPeer,
      "rpc_port RUDP: max RUDP channels per peer "
      "(CES default 2 — long-lived dial + side ops)")
      ->default_val("2");
    app.add_option("--rpcrudpmaxreorderbytes",
      optRpcRudpMaxReorderBytesPerChannel,
      "rpc_port RUDP: per-channel reorder buffer cap in bytes "
      "(-1 = library default)")
      ->default_val("-1");
    app.add_option("--rpcrudpmaxreordermsgs",
      optRpcRudpMaxReorderMsgsPerChannel,
      "rpc_port RUDP: per-channel reorder buffer cap in messages "
      "(-1 = library default)")
      ->default_val("-1");
    app.add_option("--peer", optPeers,
      "Peer server as key@host:port (repeatable)");

    // --- File-storage feature (CesPlex builtin:file) ---
    app.add_option("--filestoremaxbytes", optFileStoreMaxBytes,
      "File-storage feature max bytes (0 = feature off, >0 = hard cap "
      "on total stored bytes)")->default_val("0");
    app.add_option("--filestoredir", optFileStoreDir,
      "File-storage directory (empty = <datadir>/cesfilestore/)")
      ->default_val("");
    app.add_option("--feefilerent", optFeeFileRent,
      "File-storage rent fee (credits per byte per day, -1 = default)");
    app.add_option("--feefilewrite", optFeeFileWrite,
      "File-storage write fee (credits per KB, -1 = default)");
    app.add_option("--feefileread", optFeeFileRead,
      "File-storage read fee (credits per KB, -1 = default)");
    app.add_option("--cesplexmount", optCesplexMounts,
      "CesPlex mount as proto=target "
      "(e.g. /ces/file/1=builtin:file; repeatable)");

    // --- Compute feature (CesPlex builtin:compute) ---
    app.add_option("--computemaxinstances", optComputeMaxInstances,
      "Compute feature max concurrent instances "
      "(0 = feature off)")->default_val("0");
    app.add_option("--computeportbase", optComputePortBase,
      "Base UDP port for the L2 compute program range. 0 = ephemeral "
      "(loopback dev only). Open [base, base+count-1] at the firewall "
      "to match.")->default_val("0");
    app.add_option("--computeportcount", optComputePortCount,
      "Number of UDP ports in the L2 compute program range "
      "(independent of computemaxinstances).")->default_val("0");
    app.add_option("--computeprocessmemmax", optComputeProcessMemMax,
      "Per-process memory ceiling in bytes (child RLIMIT_AS)")
      ->default_val(std::to_string(268435456ULL));
    app.add_option("--feecomputecpusec", optFeeComputeCpuSec,
      "Compute fee for CPU time (credits per second, -1 = default)");
    app.add_option("--feecomputerssbyteday", optFeeComputeRssByteSec,
      "Compute fee for RSS (credits per byte per second, -1 = default)");
    app.add_option("--feecomputenetbyte", optFeeComputeNetByte,
      "Compute fee for outbound app bytes (credits per byte, -1 = default)");
    app.add_option("--feecomputeslotsec", optFeeComputeSlotSec,
      "Compute fee for just existing / occupying a monitoring slot "
      "(credits per second, -1 = default)");
    app.add_option("--feebucketbytesec", optFeeBucketByteSec,
      "Bucket cache fee per byte per second of declared capacity "
      "(credits, -1 = derive from feeComputeRssByteDay)");
    app.add_option("--computeworkdir", optComputeWorkDir,
      "Compute per-instance scratch / IPC socket dir "
      "(empty = <datadir>/cescompute/)")->default_val("");
    app.add_option("--computeuser", optComputeUser,
      "Unix user cesluad child processes drop to")
      ->default_val("cesluad");
    app.add_option("--computechildbinary", optComputeChildBinary,
      "Compute child binary path. Empty default = auto-discover "
      "`cesluajitd` next to ces's own binary (/proc/self/exe), with "
      "bare-name PATH fallback. Set explicitly to bypass discovery.");

    // --- /s/ builtin apps ---
    // Repeatable: --builtin-app dice --builtin-app chat. Each entry
    // is the basename of a Lua file the operator deployed to
    // <storeDir>/s/<name>.lua; the server autolaunches one
    // cesluajitd instance per entry at boot.
    app.add_option("--builtin-app", optBuiltinApps,
      "Autolaunch /s/<name>.lua at boot (repeatable)");

    // -- Subcommands (mutually exclusive with running the server) --
    cmd_credit = app.add_subcommand("credit",
      "Credit an account and exit (no server run)");
    cmd_credit->add_option("amount", optCreditAmount, "Amount to credit")
      ->required();
    cmd_credit->add_option("account", optCreditAccount,
      "Full public key hex (64 chars)")->required();

    cmd_debit = app.add_subcommand("debit",
      "Debit an account and exit (no server run)");
    cmd_debit->add_option("amount", optDebitAmount, "Amount to debit")
      ->required();
    cmd_debit->add_option("account", optDebitAccount,
      "Full public key hex (64 chars)")->required();

    cmd_snapshot = app.add_subcommand("snapshot",
      "Load data, write a snapshot, and exit (no server run)");

    app.require_subcommand(0, 1);

    app.parse(argc, argv);
  } catch (const CLI::ParseError& e) {
    return app.exit(e);
  }

  // -- --config with no argument: dump default config and exit --
  if (app.count("--config") && optConfigFile.empty()) {
    dumpDefaultConfig();
    return 0;
  }

  // -- Load config file (if provided), then let CLI switches override --
  if (!optConfigFile.empty()) {
    try {
      auto tbl = toml::parse_file(optConfigFile);

      // Helper: apply a TOML value into `var` only if the matching CLI
      // flag wasn't explicitly set on the command line. Precedence is
      // CLI > TOML > compiled default.
      auto applyIfDefault = [&](const char* tomlKey, auto& var,
                                 const char* cliFlag) {
        if (app[cliFlag]->count() != 0)
          return;  // CLI wins
        auto v = tbl[tomlKey];
        if (!v)
          return;  // not in config file
        using T = std::decay_t<decltype(var)>;
        if constexpr (std::is_same_v<T, std::string> ||
                      std::is_same_v<T, bool>)
          var = v.value_or(var);
        else if constexpr (std::is_same_v<T, uint8_t>)
          var = static_cast<uint8_t>(v.value_or(static_cast<int64_t>(var)));
        else if constexpr (std::is_same_v<T, uint16_t>)
          var = static_cast<uint16_t>(v.value_or(static_cast<int64_t>(var)));
        else if constexpr (std::is_same_v<T, int>)
          var = static_cast<int>(v.value_or(static_cast<int64_t>(var)));
        else
          var = static_cast<T>(v.value_or(static_cast<int64_t>(var)));
      };

      applyIfDefault("log_level", optLogLevel, "--loglevel");
      applyIfDefault("data_dir", optDataDir, "--datadir");
      applyIfDefault("port", optServerPort, "--port");
      applyIfDefault("server_key", optServerPrivKey, "--serverkey");
      applyIfDefault("min_difficulty", optMinDiff, "--mindiff");
      applyIfDefault("pow_delay", optPoWDelay, "--powdelay");
      applyIfDefault("spend_slot_size", optSpendSlotSize, "--spendslotsize");
      applyIfDefault("no_pow_engine", optNoPowEngine, "--nopowengine");
      applyIfDefault("cache_only_pow", optCacheOnlyPoWEngine, "--cacheonlypowengine");
      applyIfDefault("threads", optTaskThreads, "--threads");
      applyIfDefault("min_accounts", optMinAcc, "--minacc");
      applyIfDefault("max_accounts", optMaxAcc, "--maxacc");
      applyIfDefault("min_assets", optMinAsset, "--minasset");
      applyIfDefault("max_assets", optMaxAsset, "--maxasset");
      applyIfDefault("flush_value", optFlushValue, "--flushvalue");
      applyIfDefault("max_log_size_gb", optMaxLogSizeGB, "--maxlogsize");
      applyIfDefault("server_name", optServerName, "--servername");
      applyIfDefault("peer_target", optPeerTarget, "--peertarget");
      applyIfDefault("peer_pow_inbound_reciprocation_bps",
                     optPeerPowInboundReciprocationBps,
                     "--peerpowinboundreciprocationbps");
      applyIfDefault("peer_miner_interval", optPeerMinerInterval,
                     "--peerminerinterval");
      applyIfDefault("settlement_max_retries", optSettlementMaxRetries, "--settlementretries");
      applyIfDefault("admin_socket", optAdminSocket, "--adminsocket");
      applyIfDefault("web_port", optWebPort, "--webport");
      applyIfDefault("web_bind", optWebBind, "--webbind");
      applyIfDefault("rpc_port", optRpcPort, "--rpcport");
      applyIfDefault("rpc_max_pending", optRpcMaxPending, "--rpcmaxpending");
      applyIfDefault("rpc_max_request_bytes", optRpcMaxRequestBytes, "--rpcmaxreqbytes");
      applyIfDefault("rpc_max_response_bytes", optRpcMaxResponseBytes, "--rpcmaxrespbytes");
      applyIfDefault("rpc_response_timeout_ms", optRpcResponseTimeoutMs, "--rpctimeoutms");
      applyIfDefault("rpc_rudp_bytes_per_second", optRpcRudpBytesPerSecond, "--rpcrudpbps");
      applyIfDefault("rpc_rudp_burst_bytes", optRpcRudpBurstBytes, "--rpcrudpburst");

      // [rpc_rudp] table — transport caps on the rpc_port. Mirror the
      // CLI > TOML precedence the rest of the loader uses.
      if (auto t = tbl["rpc_rudp"].as_table()) {
        if (app["--rpcrudpmaxchannels"]->count() == 0) {
          if (auto v = (*t)["max_channels_per_peer"].value<int64_t>();
              v && *v >= 0)
            optRpcRudpMaxChannelsPerPeer = static_cast<uint64_t>(*v);
        }
        if (app["--rpcrudpmaxreorderbytes"]->count() == 0) {
          if (auto v = (*t)["max_reorder_bytes_per_channel"].value<int64_t>())
            optRpcRudpMaxReorderBytesPerChannel = *v;
        }
        if (app["--rpcrudpmaxreordermsgs"]->count() == 0) {
          if (auto v = (*t)["max_reorder_msgs_per_channel"].value<int64_t>())
            optRpcRudpMaxReorderMsgsPerChannel = *v;
        }
      }

      // Fees: config uses the same -1 = unset convention as the CLI.
      applyIfDefault("fee_account", optFeeAccount, "--feeaccount");
      applyIfDefault("fee_asset",   optFeeAsset,   "--feeasset");
      applyIfDefault("fee_tx",      optFeeTx,      "--feetx");
      applyIfDefault("fee_query",   optFeeQuery,   "--feequery");
      applyIfDefault("fee_vm_mult", optFeeVmMult,  "--feevmmult");

      // File-storage feature knobs.
      applyIfDefault("file_store_max_bytes", optFileStoreMaxBytes,
                     "--filestoremaxbytes");
      applyIfDefault("file_store_dir", optFileStoreDir, "--filestoredir");
      applyIfDefault("fee_file_rent",  optFeeFileRent,  "--feefilerent");
      applyIfDefault("fee_file_write", optFeeFileWrite, "--feefilewrite");
      applyIfDefault("fee_file_read",  optFeeFileRead,  "--feefileread");

      // Compute feature knobs.
      applyIfDefault("compute_max_instances",    optComputeMaxInstances,
                     "--computemaxinstances");
      applyIfDefault("compute_port_base",        optComputePortBase,
                     "--computeportbase");
      applyIfDefault("compute_port_count",       optComputePortCount,
                     "--computeportcount");
      applyIfDefault("compute_process_mem_max",  optComputeProcessMemMax,
                     "--computeprocessmemmax");
      applyIfDefault("fee_compute_cpu_sec",      optFeeComputeCpuSec,
                     "--feecomputecpusec");
      applyIfDefault("fee_compute_rss_byte_day", optFeeComputeRssByteSec,
                     "--feecomputerssbyteday");
      applyIfDefault("fee_compute_net_byte",     optFeeComputeNetByte,
                     "--feecomputenetbyte");
      applyIfDefault("fee_compute_slot_sec",     optFeeComputeSlotSec,
                     "--feecomputeslotsec");
      applyIfDefault("fee_bucket_byte_sec",      optFeeBucketByteSec,
                     "--feebucketbytesec");
      applyIfDefault("compute_work_dir",         optComputeWorkDir,
                     "--computeworkdir");
      applyIfDefault("compute_user",             optComputeUser,
                     "--computeuser");
      applyIfDefault("compute_child_binary",     optComputeChildBinary,
                     "--computechildbinary");

      // /s/ builtin apps from config. Names are arbitrary; any
      // truthy entry enables autolaunch of /s/<name>.lua. CLI's
      // repeatable --builtin-app overrides the TOML list when set.
      //   [builtin_app]
      //   dice = 1
      //   chat = 1
      if (optBuiltinApps.empty()) {
        if (auto t = tbl["builtin_app"].as_table()) {
          for (auto& [k, v] : *t) {
            bool enabled = false;
            if (auto i = v.value<int64_t>()) enabled = (*i != 0);
            else if (auto b = v.value<bool>()) enabled = *b;
            if (enabled) optBuiltinApps.push_back(std::string(k.str()));
          }
        }
      }

      // CesPlex mounts from config (only if no --cesplexmount on CLI).
      // TOML shape:
      //   [cesplex_mounts]
      //   "/ces/file/1" = "builtin:file"
      if (optCesplexMounts.empty()) {
        if (auto t = tbl["cesplex_mounts"].as_table()) {
          for (auto& [k, v] : *t) {
            auto s = v.value<std::string>();
            if (s && !s->empty())
              optCesplexMounts.push_back(
                std::string(k.str()) + "=" + *s);
          }
        }
      }

      // Peers from config (only if no CLI peers specified)
      if (optPeers.empty()) {
        if (auto peers = tbl["peers"].as_array()) {
          for (auto& p : *peers) {
            if (auto t = p.as_table()) {
              auto key = (*t)["key"].value_or(std::string(""));
              auto addr = (*t)["address"].value_or(std::string(""));
              if (!key.empty() && !addr.empty())
                optPeers.push_back(key + "@" + addr);
            }
          }
        }
      }

    } catch (const toml::parse_error& err) {
      std::cerr << "Config parse error: " << err.description() << "\n"
                << "  " << err.source().path->c_str() << ":"
                << err.source().begin.line << "\n";
      return 1;
    }
  }

  // -- Setup logging --
  try {
    ces::setupLogger(optLogLevel);
  } catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    std::exit(1);
  }

  // -- Key generation utilities (exit after) --
  if (optGenerateKeyPair) {
    KeyPair keyPair;
    dumpKeyPair(keyPair);
  }
  if (!optGeneratePubKey.empty()) {
    KeyPair keyPair(optGeneratePubKey);
    dumpKeyPair(keyPair);
  }

  // -- Validate peers (key@host:port) --
  for (auto& p : optPeers) {
    if (p.find('@') == std::string::npos) {
      std::cerr << "ERROR: invalid peer format (expected key@host:port): " << p << "\n";
      return 1;
    }
  }

#ifndef CES_GIT_HASH
#define CES_GIT_HASH "unknown"
#endif
  LOGINFO << "ces start" << VAL("version", CES_GIT_HASH);

  minx::Hash serverPrivKey;
  if (optServerPrivKey.size() != 64) {
    std::cerr << "Error: server_key must be a 64-character hex string.\n"
              << "Generate one with: ces --genkeypair\n";
    return 1;
  }
  try {
    minx::stringToHash(serverPrivKey, optServerPrivKey);
  } catch (std::exception& e) {
    std::cerr << "Error: invalid server_key: " << e.what() << "\n";
    return 1;
  }

  // -- Configure server --
  CesConfig config;
  config.dataDir = optDataDir;
  config.serverPrivKey = serverPrivKey;
  config.version = CES_GIT_HASH;
  config.minAcc = optMinAcc;
  config.maxAcc = optMaxAcc;
  config.minAsset = optMinAsset;
  config.maxAsset = optMaxAsset;
  config.minDiff = optMinDiff;
  config.spendSlotSize = optSpendSlotSize;
  config.taskThreads = optTaskThreads;
  config.flushValue = optFlushValue;
  config.maxLogBytes = optMaxLogSizeGB * 1024ULL * 1024 * 1024;

  if (optFeeAccount >= 0) config.feeAccount = static_cast<uint64_t>(optFeeAccount);
  if (optFeeAsset >= 0)   config.feeAsset   = static_cast<uint64_t>(optFeeAsset);
  if (optFeeTx >= 0)      config.feeTx      = static_cast<uint64_t>(optFeeTx);
  if (optFeeQuery >= 0)   config.feeQuery   = static_cast<uint64_t>(optFeeQuery);
  if (optFeeVmMult >= 0)  config.feeVmMult  = static_cast<uint64_t>(optFeeVmMult);

  uint64_t now = minx::getSecsSinceEpoch();
  if (optPoWDelay > 0)
    config.minProveWorkTimestamp = now + optPoWDelay;
  else
    config.minProveWorkTimestamp = 0;

  // Trim and normalize server name (empty/whitespace = unset)
  {
    auto s = optServerName;
    s.erase(0, s.find_first_not_of(" \t\r\n"));
    s.erase(s.find_last_not_of(" \t\r\n") + 1);
    config.serverName = s;
  }
  config.peerTarget = optPeerTarget;
  config.peerPowInboundReciprocationBps = optPeerPowInboundReciprocationBps;
  config.peerMinerIntervalSecs = optPeerMinerInterval;
  config.settlementMaxRetries = optSettlementMaxRetries;
  config.adminSocket = optAdminSocket;
  config.webPort = optWebPort;
  config.webBind = optWebBind;
  config.rpcPort = optRpcPort;
  config.rpcMaxPending        = optRpcMaxPending;
  config.rpcMaxRequestBytes   = static_cast<size_t>(optRpcMaxRequestBytes);
  config.rpcMaxResponseBytes  = static_cast<size_t>(optRpcMaxResponseBytes);
  config.rpcResponseTimeoutMs = optRpcResponseTimeoutMs;
  config.rpcRudpBytesPerSecond = optRpcRudpBytesPerSecond;
  config.rpcRudpBurstBytes     = optRpcRudpBurstBytes;
  config.rpcRudpMaxChannelsPerPeer        = static_cast<size_t>(optRpcRudpMaxChannelsPerPeer);
  config.rpcRudpMaxReorderBytesPerChannel = optRpcRudpMaxReorderBytesPerChannel;
  config.rpcRudpMaxReorderMsgsPerChannel  = optRpcRudpMaxReorderMsgsPerChannel;

  // File-storage feature config.
  config.cesFileStoreMaxBytes = optFileStoreMaxBytes;
  config.cesFileStoreDir      = optFileStoreDir;
  if (optFeeFileRent  >= 0) config.feeFileRent  = optFeeFileRent;
  if (optFeeFileWrite >= 0) config.feeFileWrite = optFeeFileWrite;
  if (optFeeFileRead  >= 0) config.feeFileRead  = optFeeFileRead;

  // Compute feature config.
  config.computeMaxInstances   = optComputeMaxInstances;
  config.computePortBase       = optComputePortBase;
  config.computePortCount      = optComputePortCount;
  config.computeProcessMemMax  = optComputeProcessMemMax;
  if (optFeeComputeCpuSec     >= 0)
    config.feeComputeCpuSec     = optFeeComputeCpuSec;
  if (optFeeComputeRssByteSec >= 0)
    config.feeComputeRssByteDay = optFeeComputeRssByteSec;
  if (optFeeComputeNetByte    >= 0)
    config.feeComputeNetByte    = optFeeComputeNetByte;
  if (optFeeComputeSlotSec    >= 0)
    config.feeComputeSlotSec    = optFeeComputeSlotSec;
  if (optFeeBucketByteSec     >= 0)
    config.feeBucketByteSec     = optFeeBucketByteSec;
  config.cesComputeWorkDir      = optComputeWorkDir;
  config.cesComputeUser         = optComputeUser;
  config.cesComputeChildBinary  = optComputeChildBinary;
  // Auto-discover cesluajitd next to our own binary if the operator
  // didn't specify a path. Typical install (build dir or /opt/ces/)
  // has ces and cesluajitd as siblings, so no toml line is needed.
  // Falls back to bare "cesluajitd" (PATH lookup) if discovery fails.
  if (config.cesComputeChildBinary.empty()) {
    char exePath[4096];
    ssize_t n = ::readlink("/proc/self/exe", exePath, sizeof(exePath) - 1);
    if (n > 0) {
      exePath[n] = '\0';
      auto candidate =
        std::filesystem::path(exePath).parent_path() / "cesluajitd";
      std::error_code ec;
      if (std::filesystem::exists(candidate, ec)) {
        config.cesComputeChildBinary = candidate.string();
        LOGINFO << "compute: auto-discovered cesluajitd next to ces"
                << SVAR(config.cesComputeChildBinary);
      }
    }
    if (config.cesComputeChildBinary.empty()) {
      config.cesComputeChildBinary = "cesluajitd";  // PATH fallback
    }
  }

  // /s/ builtin apps. Dedup via std::set semantics.
  for (const auto& n : optBuiltinApps) {
    if (!n.empty()) config.builtinApps.insert(n);
  }

  // CesPlex mounts: parse "proto=target" entries, skip malformed ones
  // with a warning (rather than exit — a typo shouldn't kill the whole
  // server if other mounts are fine).
  for (const auto& m : optCesplexMounts) {
    auto eq = m.find('=');
    if (eq == std::string::npos || eq == 0 || eq == m.size() - 1) {
      std::cerr << "WARN: ignoring malformed cesplex mount: " << m
                << " (expected proto=target)\n";
      continue;
    }
    config.cesplexMounts[m.substr(0, eq)] = m.substr(eq + 1);
  }

  LOGINFO << "ces config"
          << VAR(optServerPort) << VAR(config.dataDir)
          << VAR(config.minAcc) << VAR(config.maxAcc)
          << VAR(config.minDiff) << VAR(config.minProveWorkTimestamp)
          << VAR(config.spendSlotSize) << VAR(config.taskThreads)
          << VAR(config.feeAccount) << VAR(config.feeAsset)
          << VAR(config.feeTx) << VAR(config.feeQuery) << VAR(config.feeVmMult)
          << VAR(config.minAsset) << VAR(config.maxAsset)
          << VAR(config.flushValue) << VAR(config.maxLogBytes)
          << VAR(config.serverName) << VAR(config.peerTarget)
          << VAR(config.peerPowInboundReciprocationBps)
          << VAR(config.settlementMaxRetries)
          << VAR(config.rpcPort)
          << VAR(config.cesFileStoreMaxBytes)
          << VAR(optNoPowEngine);
  for (auto& p : optPeers) {
    auto at = p.find('@');
    if (at == std::string::npos) continue; // already validated above
    CesConfig::PeerConfig pc;
    pc.pubKeyHex = p.substr(0, at);
    pc.address = p.substr(at + 1);
    config.peers.push_back(pc);
  }

  if (!config.peers.empty()) {
    LOGINFO << "ces peers configured: " << config.peers.size()
            << " target=" << config.peerTarget;
    for (size_t i = 0; i < config.peers.size(); ++i)
      LOGINFO << "  peer " << i << ": " << config.peers[i].address
              << " key=" << config.peers[i].pubKeyHex.substr(0, 16) << "...";
  }

  auto server = std::make_unique<CesServer>(config);

  // -- Handle credit/debit commands (no networking needed) --
  if (cmd_credit->parsed() || cmd_debit->parsed()) {
    if (cmd_credit->parsed()) {
      minx::Hash key;
      minx::stringToHash(key, optCreditAccount);
      server->_brr(key, optCreditAmount);
      LOGINFO << "credited " << optCreditAmount << " to " << optCreditAccount;
      std::cout << "Credited " << optCreditAmount << " to "
                << optCreditAccount << "\n";
    } else {
      minx::Hash key;
      minx::stringToHash(key, optDebitAccount);
      server->_burn(key, optDebitAmount);
      LOGINFO << "debited " << optDebitAmount << " from " << optDebitAccount;
      std::cout << "Debited " << optDebitAmount << " from "
                << optDebitAccount << "\n";
    }

    server->_save();
    server.reset();
    return 0;
  }

  // -- Handle snapshot command (no networking needed) --
  if (cmd_snapshot->parsed()) {
    LOGINFO << "writing snapshot...";
    server->_save();
    LOGINFO << "snapshot complete";
    std::cout << "Snapshot written.\n";
    server.reset();
    return 0;
  }

  LOGINFO << "ces starting server";

  uint16_t boundPort = server->start(optServerPort);

  if (optNoPowEngine) {
    LOGINFO << "ces will not create the PoW engine";
  } else {
    LOGINFO << "ces creating pow engine" << VAR(optCacheOnlyPoWEngine);
    server->createPoWEngine(!optCacheOnlyPoWEngine);
  }

  if (!optNoPowEngine) {
    LOGINFO << "ces waiting for PoW engine to be ready (press Ctrl+C to stop)";
    int c = 0;
    while (ces::notInterrupted()) {
      ces::sleep(100);
      if (server->isPoWEngineReady()) {
        LOGINFO << "ces pow engine ready";
        break;
      }
      if (++c >= 50) {
        c = 0;
        LOGTRACE << "ces waiting for PoW engine to be ready...";
      }
    }
  }

  // Start peer miner (if peers configured and target > 0)
  server->startPeerMiner();

  // Start admin console (Cesco) if configured
  boost::asio::io_context cescoIO;
  std::unique_ptr<ces::Cesco> cesco;
  std::thread cescoThread;
  if (!config.adminSocket.empty()) {
    cesco = std::make_unique<ces::Cesco>(cescoIO, *server);
    if (cesco->listen(config.adminSocket)) {
      cescoThread = std::thread(
        [&cescoIO]() { ces::runGuardedThread([&cescoIO]{ cescoIO.run(); }, "cescoIO"); });
    } else {
      cesco.reset();
    }
  }

  // Start web dashboard if configured. Loopback only, no auth — reach it
  // over an SSH tunnel. Runs on its own io_context, like Cesco.
  boost::asio::io_context webIO;
  std::unique_ptr<ces::CesWeb> cesweb;
  std::vector<std::thread> webThreads;
  if (config.webPort != 0) {
    cesweb = std::make_unique<ces::CesWeb>(webIO, *server);
    if (cesweb->listen(config.webBind, config.webPort)) {
      // A small pool, not one thread: the dashboard's ledger reads block the
      // serving thread on a logicStrand_ hop, and a browser polls several
      // endpoints concurrently — a single thread stalls (dashboard "flicker")
      // whenever one read waits on a busy strand (e.g. a server being mined
      // on). The handlers are thread-safe (strand hops / mutexes / atomics),
      // so serving them across a few threads is safe.
      for (int i = 0; i < 4; ++i)
        webThreads.emplace_back(
          [&webIO]() { ces::runGuardedThread([&webIO]{ webIO.run(); }, "webIO"); });
    } else {
      cesweb.reset();
    }
  }

  LOGINFO << "ces running server" << VAR(boundPort)
          << "(press Ctrl+C to stop)";

  while (ces::notInterrupted()) {
    ces::sleep(100);
  }

  LOGINFO << "ces stopping server";
  if (cesweb) {
    cesweb->stop();
    webIO.stop();
    for (auto& t : webThreads)
      if (t.joinable())
        t.join();
    cesweb.reset();
  }
  if (cesco) {
    cesco->stop();
    cescoIO.stop();
    if (cescoThread.joinable())
      cescoThread.join();
    cesco.reset();
  }
  server->stop();
  LOGINFO << "ces destroying server";
  server.reset();
  LOGINFO << "ces exit";
  return 0;
}
