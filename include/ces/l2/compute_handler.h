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

#include <array>
#include <cstdint>
#include <string>

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

// Boot-time launch path for /s/ builtin apps. Bypasses the
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

// True iff `instanceId` is currently registered in the supervisor.
// Used by the lua handler to disambiguate "no such instance" from
// "instance exists but accept gate closed".
bool computeInstanceExists(uint64_t instanceId);

// True iff the given instance has its accept gate open (the program
// has called ces.conn.set_listener(handler)). Returns false for any
// missing / dead instance.
bool computeInstanceAcceptsConnections(uint64_t instanceId);

// Allocate a fresh server-side conn_id for the given instance and
// send TAG_CONN_OPENED to its child (with the user's pubkey).
// Returns the new conn_id, or 0 if the instance is gone before the
// allocation lands.
uint64_t computeOpenConnection(uint64_t instanceId,
                                const std::array<uint8_t, 32>& userPubkey);

// Send TAG_CONN_DATA_IN (bytes flowing user → program) to the
// instance's child. No-op if the instance is gone.
void computeSendConnDataIn(uint64_t instanceId, uint64_t connId,
                            const uint8_t* data, std::size_t len);

// Send TAG_CONN_CLOSED (channel ended for any reason) to the
// instance's child. No-op if the instance is gone. The lua handler
// is responsible for cleaning up its own (instId, connId) routing
// entry separately.
void computeSendConnClosed(uint64_t instanceId, uint64_t connId,
                            uint8_t reason);

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
size_t _computeTestFloodDeliver(uint64_t instanceId, size_t count);

// Test hook: returns the UDP port the server statically assigned the
// given instance's outbound client (Instance::clientPort), or 0 if the
// instance is gone (or no static range was configured). Runs on the
// CesPlex strand with a blocking post+wait.
uint16_t _computeTestInstanceClientPort(uint64_t instanceId);
// Same, for the instance's inbound CesPlex host port (Instance::rpcPort).
uint16_t _computeTestInstanceRpcPort(uint64_t instanceId);

} // namespace ces
