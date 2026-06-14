// mux.h — CesPlex, the CES-protocol connection controller / multiplexer
//
// CesPlex is a Layer-1, general-purpose mechanism: it latches onto a MINX
// engine that speaks CES and multiplexes it. It knows the CES protocol and
// nothing about who hosts it (see CesPlexHost — the only seam: sign +
// rate disclosure + a sink for measured resource usage). CesServer uses
// one on its secondary port; a ledgerless host (the cesluajitd compute
// child) can use one too. The L2 protocols
// (file / compute / lua) are handlers that ride this bus — users of it,
// not part of it.
//
// Every inbound RUDP channel speaks a SIGNED protocol-select handshake
// (the bind contract — see cesplex/wire.h for the wire format) before any
// protocol-specific bytes flow. On bind OK, the handler registered under
// the requested name takes over the channel for its life and the channel
// is metered against its bound payer. On NACK, the channel closes.
//
// Handler shape: statically-linked C++ handler, registered at program
// load via a Meyer-style static init into a process-wide registry.
// CES core ships handlers for "file", "compute", and "lua"; downstream
// binaries can register their own (e.g., a content-server linking
// ceslib to add "rpc"). The protocol name "/ces/rpc/1" is reserved
// but unhandled by CES core itself.
//
// Threading: a CesPlex instance lives on its host's single bus strand
// (the CesServer's rpcTaskIO_). All of acceptInbound / per-channel
// session callbacks / handler.serve invocations run on that strand. A
// handler that wants to do anything long-running should hop off to
// another executor; the framework keeps its own bookkeeping on the strand.
//
// Extensibility: adding a new builtin handler is two files: the
// handler class + its REGISTER_CESPLEX_BUILTIN line at namespace
// scope. No dynamic loading, no plugin API beyond the wire protocol.

#pragma once

#include <ces/cesplex/wire.h>
#include <ces/keys.h>
#include <ces/types.h>
#include <minx/rudp/rudp.h>
#include <minx/rudp/rudp_stream.h>
#include <minx/types.h>

#include <boost/asio/io_context.hpp>

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>

namespace ces {
class ChannelMeter;
}

namespace ces {

// -----------------------------------------------------------------------
// Per-channel resource usage — what CesPlex measures, what the host prices
// -----------------------------------------------------------------------
//
// CesPlex measures; it does not price. A tick reports each channel's raw
// resource deltas to the host, which decides what they cost in its own
// units. No credits here — just bytes and byte-time.
struct CesPlexUsage {
  uint64_t bytesSent = 0;        // wire bytes sent this tick
  uint64_t bytesReceived = 0;    // wire bytes received this tick
  uint64_t memByteSeconds = 0;   // RUDP buffer residency this tick (byte·s)
  uint64_t ageSeconds = 0;       // wall seconds the channel lived this tick
};

// -----------------------------------------------------------------------
// CesPlexHost — the host seam
// -----------------------------------------------------------------------
//
// CesPlex is a general-purpose connection controller / multiplexer that
// latches onto a MINX engine speaking CES. It is Layer 1: it knows the CES
// protocol and measures its own memory + net resources, and nothing else.
// It does NOT know credits, does NOT price usage, and does NOT decide when
// a connection has "run out" — the host does all accounting and all
// closing. The host supplies an identity (to sign) and a sink for measured
// per-channel usage. CesServer implements this against its ledger; a
// ledgerless host (e.g. the cesluajitd compute child) forwards usage to its
// parent. No CesServer, no ledger, no L2 in here.
struct CesPlexHost {
  virtual ~CesPlexHost() = default;
  // Signs the bind reply and every per-op response on this bus.
  virtual const KeyPair& cesplexSigningKey() const = 0;
  // Report one channel's measured resource usage for this tick. The host
  // does ALL the accounting: it prices the usage in its own units, charges
  // `payer`, and — if the payer can't cover it — closes (peer, channelId).
  // Fire-and-forget from CesPlex's side: CesPlex never learns the cost and
  // never closes a channel for non-payment; it only stops tracking a
  // channel once the host has closed it (its metrics vanish).
  virtual void cesplexReportUsage(const HashPrefix& payer,
                                  const minx::SockAddr& peer,
                                  uint32_t channelId,
                                  const CesPlexUsage& usage) = 0;
};

// Graceful-close timeout for server-initiated channel teardown across
// every CesPlex handler. Plumbed into RudpStream::shutdown(timeout) at
// each handler's "we're done with this channel" site: the in-flight
// reply finishes draining into Rudp's sendBuf, then HS_CLOSE fires
// (or after this deadline elapses, whichever comes first). 0 here
// would equal closeChannel() — i.e. RST — which loses any final
// bytes the user hasn't ACKed yet. 3s is generous for a healthy wire
// and reclaims fast on a dead one.
inline constexpr auto kRudpStreamCloseTimeout = std::chrono::seconds(3);

// -----------------------------------------------------------------------
// Handler base class
// -----------------------------------------------------------------------
//
// A CesPlexHandler owns an inbound RUDP channel once the select handshake
// has completed successfully with its registered name. The single
// virtual is `serve`; the handler implements whatever protocol it
// speaks by reading/writing on the stream and closing when done.
//
// Handlers are long-lived SINGLETONS (one instance per protocol,
// registered once at static-init time). `serve` may be called for
// many channels — interleaved on the rpcTaskIO_ strand, not in
// parallel across threads — so handler state must use per-channel
// state captured in its own async continuations. No mutexes are
// needed for the strand-shared bookkeeping; do need them for state
// shared with handler-internal threads (if the handler spawns any).
//
// LIFETIME CONTRACT — every handler MUST obey this:
//
//   The handler is the SOLE strong owner of the stream after serve()
//   returns. CesPlex holds only a weak reference, used for routing
//   inbound bytes while the handler is active. When the handler is
//   done (successful completion, error, or peer disconnect), it must
//   drop every shared_ptr it holds to the stream. That destructs the
//   stream, which closes the RUDP channel, and CesPlex's weak_ptr
//   expires. CesPlex detects expiry lazily (on the next inbound
//   receive for that channel) and erases its session bookkeeping.
//
//   Consequence: if a handler stashes a shared_ptr<RudpStream> into
//   a long-lived context and forgets to release it, the channel
//   leaks. The framework does not detect or alarm on this; handlers
//   that spawn async op chains should have their outermost
//   continuation release the stream on both success AND failure paths.
class CesPlexHandler {
public:
  virtual ~CesPlexHandler() = default;
  // Called once per inbound channel after the signed select handshake
  // succeeded with this handler's name. The stream is pre-constructed
  // and ready for async_read/async_write. The bound context carries
  // the channel's principal identity (pubkey + payerPfx) and
  // anchoring state (sessionToken + bound rate schedule + bind time)
  // — all set once at handoff, immutable for the channel's lifetime.
  // The handler stores the BoundChannelContext on its per-channel
  // state struct and uses it for every per-op verify (verifyPerOp).
  //
  // The handler owns the stream lifetime from here; CesPlex has
  // dropped its strong reference. See the LIFETIME CONTRACT above.
  virtual void serve(std::shared_ptr<minx::RudpStream> stream,
                     BoundChannelContext bound) = 0;
};

// -----------------------------------------------------------------------
// Builtin registration
// -----------------------------------------------------------------------
//
// At program load time, builtin handlers self-register their short
// name → pointer-to-handler mapping into a process-wide registry.
// CesPlex looks up "builtin:<name>" targets in this registry at
// construction time. The typical pattern is the
// REGISTER_CESPLEX_BUILTIN macro at the bottom of this header.
//
// `handler` is a raw pointer because the convention is that handlers
// are process-lifetime singletons (a global static in their .cpp).
// The registry never owns; it just maps names to addresses. A handler
// destroyed before the registry is read is undefined behavior, but in
// practice that never happens — handlers outlive the process.

void registerCesPlexBuiltin(const std::string& name,
                            CesPlexHandler* handler);

// Lookup — returns nullptr if no handler is registered under `name`.
// Intended for CesPlex's ctor and for tests that want to introspect
// the registry. Not meant for hot-path use.
CesPlexHandler* findCesPlexBuiltin(const std::string& name);

// -----------------------------------------------------------------------
// CesPlex — the multiplexer
// -----------------------------------------------------------------------
//
// One CesPlex instance per host bus. Constructed when the host's CES
// port comes up; destroyed when it goes down. All methods are expected
// to run on the host's single bus strand.

class CesPlex {
public:
  // `mounts` maps protocol-name → target-string. Each target string
  // is "builtin:<name>" — looked up in the global builtin registry
  // at ctor time; unresolved bindings are logged and skipped.
  //
  // `rudp` is the Rudp instance on the secondary port. CesPlex
  // installs channel-opened + receive callbacks on it that route
  // inbound channels through the bind handshake. `io` is the
  // io_context those callbacks run on (rpcTaskIO_).
  //
  // `meter` is optional (may be null). When non-null, every
  // inbound channel is registered with it post-bind so the tick can
  // measure its resource deltas and report them to the host.
  //
  // `host` supplies the bind-reply ingredients: cesplexSigningKey() to
  // sign the reply. May be null only for tests that don't exercise the
  // bind handshake.
  CesPlex(const std::map<std::string, std::string>& mounts,
          minx::Rudp& rudp,
          boost::asio::io_context& io,
          CesPlexHost* host,
          ChannelMeter* meter = nullptr);

  ~CesPlex();

  CesPlex(const CesPlex&) = delete;
  CesPlex& operator=(const CesPlex&) = delete;

  // Called by the host's Rudp::Listener::onAccept hook for
  // every fresh inbound HS_OPEN. Constructs a per-channel
  // RudpStream + Session, kicks off the bind-handshake read, and
  // returns the stream as the channel handler for Rudp to wire.
  //
  // Returns null (silent rejection) if no bindings were resolved at
  // ctor time, or if a session for these (peer, channelId) coords
  // already exists (duplicate accept). Otherwise always succeeds.
  //
  // After this returns, RUDP routes per-channel events (bytes,
  // close) directly to the returned stream — CesPlex no longer
  // intercepts on the receive path.
  std::shared_ptr<minx::Rudp::ChannelHandler> acceptInbound(
      const minx::SockAddr& peer, uint32_t channelId);

  // True if any bindings resolved at ctor time. If false, the select
  // handshake on every inbound channel will NACK — fine, but the
  // caller may want to skip constructing us entirely.
  bool hasAnyBinding() const { return !bindings_.empty(); }

  // Introspection — test-only. Number of live sessions awaiting bind.
  size_t _pendingSessionCount() const { return sessions_.size(); }

private:
  // Per-channel session state: opens, reads the select header, either
  // hands off to a handler (OK) or closes (NACK).
  struct Session;
  using SessionKey = std::pair<minx::SockAddr, uint32_t>;

  minx::Rudp& rudp_;
  boost::asio::io_context& io_;
  CesPlexHost* host_;           // signs bind replies + supplies bind rates
  ChannelMeter* channelMeter_;  // optional, may be null

  // Protocol-name → registered handler, resolved at ctor.
  std::map<std::string, CesPlexHandler*> bindings_;

  // In-flight inbound select handshakes. Keyed by (peer, channelId).
  // Entries are removed once a handler takes over or the channel
  // closes.
  std::map<SessionKey, std::shared_ptr<Session>> sessions_;
};

// -----------------------------------------------------------------------
// Convenience macro — register a builtin handler at static-init time
// -----------------------------------------------------------------------
//
// Expands to a namespace-scope struct whose ctor registers the handler
// in the global registry. Place at the bottom of the handler's .cpp
// file. The `uniq` argument is a source-unique identifier (e.g. the
// handler class name) used to keep the generated struct name unique
// even if the same .cpp registers multiple handlers.

#define REGISTER_CESPLEX_BUILTIN(name_str, handler_instance, uniq)   \
  namespace {                                                        \
    struct _CesPlexReg_##uniq {                                      \
      _CesPlexReg_##uniq() {                                         \
        ::ces::registerCesPlexBuiltin((name_str), &(handler_instance)); \
      }                                                              \
    };                                                               \
    static _CesPlexReg_##uniq _cesplex_reg_##uniq;                   \
  }

} // namespace ces
