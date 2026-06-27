// peer_handler.h - builtin:peer: the per-server server-to-server mesh handler.
//
// Mounts /ces/peer/1 on the plex (rpc) port. A persistent, unmetered,
// bidirectional RUDP channel between two CES servers that are mutual entries
// in each other's peer tables, plus a service-tagged message bus that
// extensions ride (ces.peer.send / ces.peer.listen).
//
// One PeerHandler OBJECT per CesServer (owned by the server, holds a back
// pointer to it). No process-global state: N servers coexist in one process.
// All link bookkeeping runs on the server's rpcTaskIO_ strand.
//
// Lifecycle: the server constructs a PeerHandler(this), mounts it into its
// CesPlex (cesplex->mount(CES_PEER_PROTO, h)), and calls start(); on shutdown
// it calls stop() and drops the object (before CesPlex / rpcRudp_ go away).

#pragma once

#include <ces/cesplex/mux.h>   // CesPlexHandler, BoundChannelContext
#include <ces/keys.h>
#include <minx/types.h>
#include <minx/rudp/rudp_stream.h>

#include <atomic>
#include <cstddef>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include <boost/asio/steady_timer.hpp>

namespace ces {

class CesServer;

// Protocol name for the server-to-server mesh. Mounted whenever the plex
// port is up (the master switch is rpc_port).
inline constexpr const char* CES_PEER_PROTO = "/ces/peer/1";

// A candidate peer for the mesh, flattened from the peer table for the
// reconcile pass. dialable = we know where to reach its plex port.
struct PeerLinkTarget {
  minx::Hash     ckey{};      // peer identity (account / peer-table key)
  minx::SockAddr endpoint;    // peer's plex (rpc) endpoint, valid iff dialable
  bool           dialable = false;
};

// Pure reconcile decision (no I/O, no state): from the current peer set, our
// identity, and the ckeys we already hold links to, decide which to dial and
// which to drop. Dial only peers we are the lower-pubkey side of (one channel
// per pair) that are dialable and unlinked; drop links whose peer is gone.
// Separately unit-tested.
struct PeerLinkActions {
  std::vector<minx::Hash> toDial;
  std::vector<minx::Hash> toDrop;
};
PeerLinkActions computePeerLinkActions(
    const std::vector<PeerLinkTarget>& peers,
    const minx::Hash& ourKey,
    const std::set<minx::Hash>& currentLinks);

// Per-link state, defined in the .cpp.
struct PeerLink;

class PeerHandler : public CesPlexHandler {
public:
  explicit PeerHandler(CesServer* server);
  ~PeerHandler();

  PeerHandler(const PeerHandler&) = delete;
  PeerHandler& operator=(const PeerHandler&) = delete;

  // CesPlexHandler: an inbound /ces/peer/1 channel handed off after bind.
  void serve(std::shared_ptr<minx::RudpStream> stream,
             BoundChannelContext bound) override;

  // Begin the reconcile pass (dial / drop / hold the mesh). Idempotent-safe
  // to call once at server start, after the rpc threads exist.
  void start();
  // Cancel the reconcile pass and tear down every link. Call before CesPlex /
  // rpcRudp_ are destroyed.
  void stop();

  // Send a service-tagged message to peer `destKey` over its /ces/peer/1 link.
  // Framed [u16 service_len][service][payload]; the far side routes it by
  // service to the extension that registered. No-op if no established link.
  // Runs on rpcTaskIO_ (the compute handler relays a child's ces.peer.send).
  void sendMessage(const minx::Hash& destKey, const std::string& service,
                   const uint8_t* data, std::size_t len);

  // True if an established link to destKey exists right now. isLinked is
  // thread-safe (mutex-guarded mirror, for the web dashboard / tests);
  // hasLink is rpcTaskIO_-only (the message path).
  bool isLinked(const minx::Hash& ckey);
  bool hasLink(const minx::Hash& destKey);

  // Test hook: run one reconcile pass synchronously (blocks until dispatched
  // on rpcTaskIO_); dials it kicks off finish async, poll isLinked.
  void reconcileNow();

private:
  void teardownLink(std::shared_ptr<PeerLink> link);
  void establishLink(std::shared_ptr<PeerLink> link);
  void peerReadLoop(std::shared_ptr<PeerLink> link);
  void kickWrite(std::shared_ptr<PeerLink> link);
  void readDialBindReply(std::shared_ptr<PeerLink> link);
  void dialPeer(const minx::Hash& ckey, const minx::SockAddr& endpoint);
  void reconcileOnce();
  void scheduleReconcile();

  CesServer* server_;
  std::atomic<bool> running_{false};
  std::shared_ptr<boost::asio::steady_timer> reconcileTimer_;
  // rpcTaskIO_-only: the live links keyed by peer pubkey.
  std::map<minx::Hash, std::shared_ptr<PeerLink>> links_;
  // Cross-thread mirror of established link keys (web dashboard / tests).
  std::mutex linkMutex_;
  std::set<minx::Hash> established_;
};

} // namespace ces
