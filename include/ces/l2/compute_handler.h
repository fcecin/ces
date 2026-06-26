// compute_handler.h - builtin:compute handler lifecycle API.
//
// The compute handler is a compiled-in CesPlex handler registered as
// "compute" in the global builtin registry.
//
// The handler spawns `cesComputeChildBinary` (default `cesluajitd`, a
// sandboxed LuaJIT VM per process) as a separate OS process, holds a Unix
// domain socket to it, and charges `feeComputeSlotSec` per wall-clock second
// to the source file's `file_balance` while the instance runs. When the
// balance can't cover a tick the instance is SIGKILLed; likewise when the
// source file is deleted (file handler delete / rent-exhaust / GC).
//
// Lifecycle: CesServer::start() calls computeHandlerBind(this) after
// CesPlex is constructed and the file handler has been bound (the
// compute handler refuses to bind otherwise). computeHandlerBind(nullptr)
// on shutdown SIGKILLs all running instances and tears down timers.
//
// One translation unit, one handler instance. Same pattern as
// builtin:file.

#pragma once

#include <ces/types.h>
#include <ces/buffer.h>

#include <array>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace ces {

class CesServer;

// Bind / unbind the builtin:compute handler to a CesServer. Returns
// CES_OK if bind succeeded, or a CES_ERROR_COMPUTE_* code if any
// prerequisite was missing. On failure the handler stays unbound and
// inbound /ces/compute/* selects reach a handler with no bound server
// and drop (matching the file handler's off-switch behavior).
//
// Prereqs (all must hold):
//   1. cfg.computeMaxInstances > 0                       (off switch)
//   2. builtin:file is registered in the CesPlex registry  (we call
//      into fileHandler* primitives for source-file auth + fund ops)
//   3. cfg.cesComputeWorkDir resolves and is writable       (scratch
//      + IPC socket paths live there)
//   4. cfg.cesComputeChildBinary resolves on the host        (relative
//      names go through execvp; absolute paths are used directly)
//
// Pass `server = nullptr` to unbind. Unbind SIGKILLs every running
// instance synchronously, cancels the supervisor tick timer, and
// removes the handler's work-dir scratch files.
uint8_t computeHandlerBind(CesServer* server);

// Boot-time launch path for /s/ extensions. Bypasses the
// wire-auth/dedup/upfront-fee sequence used by dispatchLaunch — the
// caller is the server itself. The source file at `name` must
// already exist on disk (deploy via fileHandlerEnsureServerFile),
// be in /s/, and be owned by the server's pubkey.
//
// Must be called from rpcTaskIO_'s strand (post via
// CesServer::_rpcTaskIOExecutor). Validation (instance cap, source
// existence, server ownership) is synchronous and returns CES_OK, or a
// CES_ERROR_COMPUTE_*/CES_ERROR_FILE_*/CES_ERROR_BAD_NAME code. The
// child's connect-back is then awaited asynchronously, so CES_OK means
// "validated + spawn started," not "child connected"; a connect-back
// failure is logged, not returned.
//
// Owner pubkey is read fresh from the source's sidecar — the caller
// doesn't pass it. This keeps the contract symmetric with the wire
// path: source-of-truth for ownership is always the sidecar.
uint8_t computeHandlerLaunchInternal(const std::string& name);

// Deliver an inbound CES_APP_COMPUTE_MSG-shaped packet to the
// compute handler. Called from CesServer::incomingApplication after
// the hop onto rpcTaskIO_. `senderPfx` is the 8-byte prefix of the
// sending client's pubkey (resolved via the presence cache reverse
// index) — programs use it as the reply-to target for
// ces.client_send. All-zero means the sender wasn't in presence; the
// program will see the zero prefix and typically ignore the message.
void computeHandlerOnApplicationMsg(
    const uint8_t* data, std::size_t len,
    const std::array<uint8_t, 8>& senderPfx);

// ---------------------------------------------------------------------------
// /ces/lua/1 cross-handler primitives
// ---------------------------------------------------------------------------
//
// Used by the lua handler (compute_lua_handler.cpp) to route between
// inbound RUDP channels and the running cesluajitd children. All run
// on rpcTaskIO_'s strand — same as the supervisor itself — so they're
// safe to call from there but not elsewhere.

// Per-instance monitoring snapshot, surfaced to the web dashboard's
// Compute tab. CPU is in basis points of one core (10000 = a full core);
// rssBytes + cpuBasisPoints are the supervisor's last per-tick sample.
struct ComputeInstanceStat {
  uint64_t pid = 0;
  std::string source;          // source file path (e.g. /s/dice.lua)
  uint32_t cpuBasisPoints = 0; // 0..10000, of one core
  uint64_t rssBytes = 0;
  uint64_t uptimeSecs = 0;
  uint16_t clientPort = 0;     // outbound CES-client port (0 = none)
  uint16_t rpcPort = 0;        // inbound /ces/luarpc/1 host port (0 = none)
};

// Snapshot every running instance for monitoring. Safe to call from any
// thread; runs on the CesPlex strand internally (blocking post+wait), so
// it sees a consistent registry. Empty if the handler is unbound.
std::vector<ComputeInstanceStat> computeHandlerSnapshot();

// ---- Extension contract (ces.extension_admin{}). Read/drive a running /s/
// extension through the management surface the ExtensionManager exposes to the
// webadmin. Metadata (name/version/description) is NOT here — it comes from the
// file's static manifest header; this contract is caps/commands/config only. ----
constexpr uint8_t kComputeExtCapStatus         = 0x01;
constexpr uint8_t kComputeExtCapCommands       = 0x02;
constexpr uint8_t kComputeExtCapConfigDefaults = 0x04;
constexpr uint8_t kComputeExtCapOnConfig       = 0x08;
constexpr uint8_t kComputeExtReqStatus  = 0x00;
constexpr uint8_t kComputeExtReqCommand = 0x01;

struct ComputeExtInfo {
  // Identity, reported live via ces.manifest{} (may be set even with no contract).
  std::string name, version, description;
  // Admin contract, from ces.extension_admin{}.
  bool isExtension = false;
  uint8_t caps = 0;            // kComputeExtCap* bits the program registered
  std::vector<std::pair<std::string, std::string>> commands;  // {id, label}
  std::string configDefaults;
};

// What a running instance reported: identity (ces.manifest) + the contract
// (ces.extension_admin). false if pid unknown. Synchronous (CesPlex strand).
bool computeHandlerExtInfo(uint64_t pid, ComputeExtInfo& out);

// Round-trip a status/command request to a running extension; `out` is the
// reply payload after the status byte. false on timeout / unknown / non-ext /
// child error. For STATUS, out = [u16 count]([lp k][lp v])*; for COMMAND,
// `in` = [u16 idLen][id][arg] and out = the command's string result.
bool computeHandlerExtRequest(uint64_t pid, uint8_t kind, const ces::Bytes& in,
                              ces::Bytes& out, int timeoutMs);

// Push a config blob (text) to a running extension's on_config. Best-effort.
void computeHandlerExtConfig(uint64_t pid, const std::string& cfg);

// Kill every running instance of `sourceName` (e.g. "/s/discovery.lua"). Async
// (hops onto the CesPlex strand). The ExtensionManager's Disable.
void computeHandlerKillBySource(const std::string& sourceName);

// Bounded wait for in-flight ces.request_funds remote transfers to finish, so the
// CesServer isn't destroyed under them. Call before compute teardown.
void computeFundingDrain();

// True iff `pid` is currently registered in the supervisor.
// Used by the lua handler to disambiguate "no such instance" from
// "instance exists but accept gate closed".
bool computeInstanceExists(uint64_t pid);

// True iff the given instance has its accept gate open (the program
// has called ces.conn.set_listener(handler)). Returns false for any
// missing / dead instance.
bool computeInstanceAcceptsConnections(uint64_t pid);

// Allocate a fresh server-side conn_id for the given instance and
// send TAG_CONN_OPENED to its child (with the user's pubkey).
// Returns the new conn_id, or 0 if the instance is gone before the
// allocation lands.
uint64_t computeOpenConnection(uint64_t pid,
                                const std::array<uint8_t, 32>& userPubkey);

// Send TAG_CONN_DATA_IN (bytes flowing user → program) to the
// instance's child. No-op if the instance is gone.
void computeSendConnDataIn(uint64_t pid, uint64_t connId,
                            const uint8_t* data, std::size_t len);

// Send TAG_CONN_CLOSED (channel ended for any reason) to the
// instance's child. No-op if the instance is gone. The lua handler
// is responsible for cleaning up its own (pid, connId) routing
// entry separately.
void computeSendConnClosed(uint64_t pid, uint64_t connId,
                            uint8_t reason);

// Deliver a flooded gossip message to EVERY local compute instance (each child
// calls its program's on_gossip handler if defined). Called for gossip received
// from the mesh and for gossip this node originates itself, so local programs
// see the node's own messages too. Must run on the compute supervisor thread
// (rpcTaskIO_) — it touches the instance map. No-op if compute is disabled.
void computeHandlerDeliverGossip(const minx::Hash& author,
                                 const minx::Hash& sender,
                                 const minx::Hash& msgId,
                                 const minx::Hash& dest,
                                 const uint8_t* msg, std::size_t len);

// Test hook: reads CPU ticks (utime + stime from /proc/<pid>/stat)
// and resident-set-size bytes (resident × PAGESIZE from
// /proc/<pid>/statm) for the given pid. Returns false if /proc is
// unavailable or the pid is gone. Public only for unit tests — the
// per-instance sampler runs on the supervisor tick internally.
bool _computeTestReadProcSample(int pid,
                                uint64_t& outTicks,
                                uint64_t& outRssBytes);

// Test hook: fires one supervisor tick synchronously (sample + bill
// for every instance). Lets tests assert tick-driven behavior — CPU
// basis-points updating, slot-fee debit landing on the sidecar,
// SIGKILL on fund exhaustion — without waiting on the timer. Safe
// to call from any thread; runs on the CesPlex strand internally
// with a blocking post+wait. No-op if the handler is unbound.
void _computeTestForceTick();

// Test hook: floods an instance with `count` best-effort DELIVER frames
// back-to-back on the CesPlex strand and returns the resulting outbound
// queue (`outbox`) depth at saturation. With the flood guard in place this
// caps at kMaxDeliverBacklog; without it, it grows to `count`. Runs in a
// single non-yielding strand task so nothing drains mid-flood — the result
// is deterministic, with no socket-buffer or timing dependence. 0 if the
// handler is unbound or the instance is gone.
size_t _computeTestFloodDeliver(uint64_t pid, size_t count);

// Test hook: returns the UDP port the server statically assigned the
// given instance's outbound client (Instance::clientPort), or 0 if the
// instance is gone (or no static range was configured). Runs on the
// CesPlex strand with a blocking post+wait.
uint16_t _computeTestInstanceClientPort(uint64_t pid);
// Same, for the instance's inbound CesPlex host port (Instance::rpcPort).
uint16_t _computeTestInstanceRpcPort(uint64_t pid);

} // namespace ces
