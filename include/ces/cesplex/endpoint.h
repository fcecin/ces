// endpoint.h — CesPlexEndpoint: a self-contained CesPlex host on a
// dedicated UDP port.
//
// Owns its own Minx + Rudp + two io threads + a Rudp tick + a ChannelMeter
// + a CesPlex, and serves the given protocol mounts. Construct to start
// listening; destroy to tear down (in the safe order: CesPlex → meter →
// Rudp → Minx, after both threads have joined).
//
// Use this when a process wants to host a CesPlex on a port of its OWN —
// e.g. the cesluajitd compute child hosting /ces/luarpc/1. CesServer does
// NOT use this: its rpc port is a shared, multi-tenant strand that also
// carries SYS_RPC outbound, with its own bespoke bring-up.
//
// Threading: all CesPlex / Rudp / handler work runs on the endpoint's
// single task strand (an internal io_context with one thread); a separate
// net thread runs the UDP socket I/O. The caller must keep `host` alive
// for the endpoint's whole lifetime.

#pragma once

#include <ces/cesplex/mux.h>
#include <ces/cesplex/meter.h>

#include <minx/minx.h>
#include <minx/rudp/rudp.h>
#include <minx/types.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>

#include <atomic>
#include <chrono>
#include <map>
#include <memory>
#include <string>
#include <thread>

namespace ces {

class CesPlexEndpoint {
public:
  // `port`     — UDP port to bind (0 = OS-assigned; read back via boundPort()).
  // `host`     — signs bind replies + sinks measured usage; its signing key
  //              also becomes the Minx server key. Must outlive the endpoint.
  // `mounts`   — protocol-name → handler object, mounted into the CesPlex at
  //              construction. Each handler must outlive the endpoint.
  // `minxCfg` / `rudpCfg` — fully specify the MINX + RUDP posture (the caller
  //              owns those decisions: anti-spam, pacing, buffer sizes). The
  //              server key is set internally from `host`.
  // `meterTick` — ChannelMeter cadence.
  CesPlexEndpoint(uint16_t port,
                  CesPlexHost* host,
                  std::map<std::string, CesPlexHandler*> mounts,
                  minx::MinxConfig minxCfg,
                  minx::RudpConfig rudpCfg,
                  std::chrono::seconds meterTick = std::chrono::seconds(60));
  ~CesPlexEndpoint();

  CesPlexEndpoint(const CesPlexEndpoint&) = delete;
  CesPlexEndpoint& operator=(const CesPlexEndpoint&) = delete;

  // The actually-bound port (the requested port, or the OS pick if 0). 0
  // means the socket failed to open and the endpoint is inert.
  uint16_t boundPort() const { return boundPort_; }
  bool listening() const { return boundPort_ != 0; }

  // True if any mount resolved to a registered handler. If false, every
  // inbound bind NACKs (nothing to accept) — the endpoint still listens.
  bool hasAnyBinding() const;

  // The endpoint's task strand. The owner (e.g. the lua host) posts onto it
  // to drive outbound work — conn writes/closes, dialing out — on the same
  // single thread the CesPlex + Rudp already run on, so no extra locking is
  // needed around per-channel state.
  boost::asio::io_context& io() { return taskIO_; }

  // The endpoint's Rudp, for opening OUTBOUND channels on the same socket
  // (e.g. dialing /ces/luarpc/1 from a lua program). Null if the socket
  // failed to open. Touch only on the io() strand.
  minx::Rudp* rudp() { return rudp_.get(); }

  // The endpoint's ChannelMeter, for registering OUTBOUND channels so they are
  // metered like the inbound ones (which are auto-tracked on bind). Null if the
  // endpoint failed to start. Touch only on the io() strand.
  ChannelMeter* meter() { return meter_.get(); }

private:
  // No-op MinxListener: the endpoint's Minx carries only the Rudp
  // extension lane, never CES signed-op traffic.
  struct MinxNoopListener : minx::MinxListener {};

  // Rudp::Listener: onSend → minx->sendExtension, onAccept → cesplex.
  class RudpListener : public minx::Rudp::Listener {
  public:
    explicit RudpListener(CesPlexEndpoint* ep) : ep_(ep) {}
    void onSend(const minx::SockAddr& peer, const minx::Bytes& bytes) override;
    std::shared_ptr<minx::Rudp::ChannelHandler> onAccept(
        const minx::SockAddr& peer, uint32_t channelId) override;
  private:
    CesPlexEndpoint* ep_;
  };

  void scheduleTick();

  CesPlexHost* host_;
  MinxNoopListener minxListener_;
  RudpListener rudpListener_{this};

  // Declared before the owned objects so it outlives them; the destructor
  // body does the real teardown in the correct order regardless.
  boost::asio::io_context netIO_;
  boost::asio::io_context taskIO_;
  std::thread netThread_;
  std::thread taskThread_;

  std::unique_ptr<minx::Minx> minx_;
  std::unique_ptr<minx::Rudp> rudp_;
  std::unique_ptr<ChannelMeter> meter_;
  std::unique_ptr<CesPlex> cesplex_;
  std::shared_ptr<boost::asio::steady_timer> tickTimer_;
  std::atomic<bool> running_{true};
  uint16_t boundPort_ = 0;
};

} // namespace ces
