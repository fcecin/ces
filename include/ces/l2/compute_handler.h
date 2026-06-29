// compute_handler.h - builtin:compute: per-server program-hosting handler.
//
// Mounts /ces/compute/1 on the plex (rpc) port. Each LAUNCH spawns
// `cesComputeChildBinary` (default `cesluajitd`, a sandboxed LuaJIT VM per
// process) as a separate OS process, holds a Unix domain socket to it, and
// charges slot/cpu/rss/bucket fees to the source file's `file_balance` while
// the instance runs. When the balance can't cover a tick the instance is
// SIGKILLed; likewise when the source file is deleted (file handler delete /
// rent-exhaust / GC).
//
// One ComputeHandler OBJECT per CesServer (owned by the server, holds a back
// pointer to it). No process-global state: N servers coexist in one process.
//
// Lifecycle: the server constructs a ComputeHandler(this) and mounts it into
// its CesPlex when /ces/compute/1 is wired in [cesplex_mounts], then calls
// start() (which self-gates on its prereqs: computeMaxInstances > 0, builtin:
// file mounted, work dir); on shutdown it calls fundingDrain() then stop() and
// drops the object (before CesPlex /
// rpcRudp_ go away).

#pragma once

#include <ces/types.h>
#include <ces/buffer.h>
#include <ces/cesplex/mux.h>      // CesPlexHandler, BoundChannelContext

#include <minx/rudp/rudp_stream.h>

#include <boost/asio/steady_timer.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace ces {

class CesServer;

// Per-instance supervisor state, defined in compute_handler.cpp (the only TU
// that touches it). Held here only through shared_ptr, so the header stays
// free of its definition.
struct Instance;
// In-flight EXT_REQ correlation state, also defined in the .cpp.
struct ExtPending;

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

class ComputeHandler : public CesPlexHandler {
public:
  explicit ComputeHandler(CesServer* server);
  ~ComputeHandler();

  ComputeHandler(const ComputeHandler&) = delete;
  ComputeHandler& operator=(const ComputeHandler&) = delete;

  // CesPlexHandler: a freshly-bound /ces/compute/1 channel. Runs the signed
  // per-op verb loop (cesPlexServe).
  void serve(std::shared_ptr<minx::RudpStream> stream,
             BoundChannelContext bound) override;

  // Bring the handler up: validate prereqs (computeMaxInstances > 0,
  // builtin:file up, work-dir + child binary resolvable), create the
  // work-dir, register the file-deletion interlock, and start the
  // supervisor tick. Returns CES_OK or a CES_ERROR_COMPUTE_* code.
  uint8_t start();

  // SIGKILL every running instance, cancel the supervisor tick, and stop
  // accepting verbs. Call on shutdown before CesPlex / rpcRudp_ go away.
  void stop();

  // Bounded wait for in-flight ces.request_funds remote transfers to finish,
  // so the CesServer isn't destroyed under them. Call before stop().
  void fundingDrain();

  // Boot-time launch path for /s/ extensions. Bypasses the
  // wire-auth/dedup/upfront-fee sequence used by the LAUNCH verb -- the caller
  // is the server itself. The source file at `name` must already exist on disk
  // (deploy via fileHandler), be in /s/, and be owned by the server's pubkey.
  // Must be called from rpcTaskIO_'s strand. CES_OK means "validated + spawn
  // started," not "child connected."
  uint8_t launchInternal(const std::string& name);

  // Deliver an inbound CES_APP_COMPUTE_MSG-shaped packet. Called from
  // CesServer::incomingApplication after the hop onto rpcTaskIO_. `senderPfx`
  // is the 8-byte prefix of the sending client's pubkey (reply-to target for
  // ces.client_send); all-zero means the sender wasn't in presence.
  void onApplicationMsg(const uint8_t* data, std::size_t len,
                        const std::array<uint8_t, 8>& senderPfx);

  // Snapshot every running instance for monitoring. Safe to call from any
  // thread; runs on the CesPlex strand internally (blocking post+wait).
  std::vector<ComputeInstanceStat> snapshot();

  // What a running instance reported: identity (ces.manifest) + the contract
  // (ces.extension_admin). false if pid unknown. Synchronous (CesPlex strand).
  bool extInfo(uint64_t pid, ComputeExtInfo& out);

  // Round-trip a status/command request to a running extension; `out` is the
  // reply payload after the status byte. false on timeout / unknown / non-ext /
  // child error.
  bool extRequest(uint64_t pid, uint8_t kind, const ces::Bytes& in,
                  ces::Bytes& out, int timeoutMs);

  // Push a config blob (text) to a running extension's on_config. Best-effort.
  void extConfig(uint64_t pid, const std::string& cfg);

  // Kill every running instance of `sourceName` (e.g. "/s/discovery.lua").
  // Async (hops onto the CesPlex strand). The ExtensionManager's Disable.
  void killBySource(const std::string& sourceName);

  // Deliver a flooded gossip message to EVERY local compute instance (each
  // child calls its program's on_gossip handler if defined). Must run on the
  // compute supervisor thread (rpcTaskIO_).
  void deliverGossip(const minx::Hash& author, const minx::Hash& sender,
                     const minx::Hash& msgId, const minx::Hash& dest,
                     const uint8_t* msg, std::size_t len);

  // ---- /ces/lua/1 + /ces/peer/1 cross-handler primitives. Used by the lua /
  // peer handlers; all run on rpcTaskIO_'s strand. ----

  // True iff `pid` is currently registered in the supervisor.
  bool instanceExists(uint64_t pid);
  // True iff the instance has its accept gate open (ces.conn.set_listener).
  bool instanceAcceptsConnections(uint64_t pid);
  // Allocate a fresh server-side conn_id and send TAG_CONN_OPENED to the child
  // (with the user's pubkey). Returns the new conn_id, or 0 if the instance
  // is gone before the allocation lands.
  uint64_t openConnection(uint64_t pid,
                          const std::array<uint8_t, 32>& userPubkey);
  // Send TAG_CONN_DATA_IN (bytes user -> program). No-op if instance is gone.
  void sendConnDataIn(uint64_t pid, uint64_t connId,
                      const uint8_t* data, std::size_t len);
  // Send TAG_CONN_CLOSED (channel ended). No-op if instance is gone. The lua
  // handler cleans up its own (pid, connId) routing entry separately.
  void sendConnClosed(uint64_t pid, uint64_t connId, uint8_t reason);
  // Route an inbound /ces/peer/1 mesh message to the local instance that
  // registered `service` via ces.peer.listen. No-op if none did.
  void routePeerMsg(const std::string& service, const minx::Hash& fromKey,
                    const uint8_t* data, std::size_t len);

  // ---- Test hooks (see comments at the definitions). ----
  void testForceTick();
  std::size_t testFloodDeliver(uint64_t pid, std::size_t count);
  uint16_t testInstanceClientPort(uint64_t pid);
  uint16_t testInstanceRpcPort(uint64_t pid);

  // Count of child instances that terminated by a signal (a crash, e.g. SIGSEGV
  // on a bad shutdown). Surfaced in the supervisor WARNING; lets a test assert
  // an instance shut down cleanly.
  std::size_t crashedCount() const { return crashedInstances_.load(); }

  // Per-server supervisor state. Public so this translation unit's free
  // helpers reach it via server->computeHandler(); not a stable API.
  CesServer* server_ = nullptr;
  std::map<uint64_t, std::shared_ptr<Instance>> instances_;
  std::map<std::array<uint8_t, 8>, std::set<uint64_t>> byPrefix_;
  std::map<std::string, std::set<uint64_t>> byName_;
  std::map<std::string, uint64_t> serviceTags_;
  uint64_t nextPid_ = 1;
  std::map<uint16_t, std::shared_ptr<ExtPending>> extPending_;
  uint16_t extCorr_ = 1;
  uint64_t pendingLaunches_ = 0;
  std::set<uint16_t> usedComputePorts_;
  std::shared_ptr<boost::asio::steady_timer> tickTimer_;
  std::atomic<bool> tickRunning_{false};
  std::atomic<int> fundingInFlight_{0};
  std::atomic<bool> stopped_{false};
  std::atomic<std::size_t> crashedInstances_{0};
};

// Test hook: reads CPU ticks (utime + stime from /proc/<pid>/stat) and
// resident-set-size bytes for the given pid. Stateless; not tied to a handler.
bool _computeTestReadProcSample(int pid,
                                uint64_t& outTicks,
                                uint64_t& outRssBytes);

} // namespace ces
