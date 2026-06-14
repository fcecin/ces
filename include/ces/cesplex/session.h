// session.h — the per-op CesPlex layer for handlers and clients.
//
// The pieces both sides of a bound CesPlex channel build on, layered over
// cesplex/wire.h (low-level wire format) and cesplex/mux.h (the bus: bind
// handshake + channel routing + handler registration + metering):
//
//   * Server side — the signed-request loop. A handler's serve() calls
//     cesPlexServe(); the framework reads [verb][envelope] ops, verifies
//     each against the bound pubkey, and hands them to the handler's
//     dispatch. CesPlexRequest::respond/error/respondAndClose emit the
//     server-signed reply and loop/close. builtin:file and
//     builtin:compute share this verbatim.
//
//   * Client side — CesPlexClient. One MINX socket + Rudp + io threads +
//     the signed bind handshake + the blocking verb driver. CesFileClient
//     and CesComputeClient are just verb methods over it.

#pragma once

#include <ces/cesplex/wire.h>
#include <ces/cesplex/mux.h>   // CesPlexHost, BoundChannelContext
#include <ces/buffer.h>
#include <ces/keys.h>
#include <minx/rudp/rudp_stream.h>
#include <minx/types.h>

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>

// Forward declarations for CesPlexChannel's injected-transport ctor — the
// concrete types are only needed in session.cpp.
namespace boost { namespace asio { class io_context; } }
namespace minx { class Rudp; }

namespace ces {

// ===========================================================================
// Server side — the signed-request loop
// ===========================================================================
//
// builtin:file and builtin:compute speak the same post-bind shape: a
// stream of per-op envelopes
//     [u8 verb][u32 BE preamble_len][preamble][65 sig]
// where the sig is verifyPerOp(bound, verb, preamble) and the preamble's
// first 4 bytes are reqNonce. cesPlexServe() drives that loop — read a
// verb, read + verify the envelope, peel reqNonce — and hands each
// verified op to the handler's CesPlexProtocol::dispatch with the request
// plus the rest of the preamble. The handler owns only its verb set and
// per-verb logic; it finishes each op via the CesPlexRequest helpers,
// which emit the server-signed response and loop (or close) the channel.
//
// (Handlers whose protocol isn't verb/envelope-shaped — builtin:lua's
// one-shot ATTACH — drive the stream directly in serve() instead.)

struct CesPlexRequest;

// Handler-supplied protocol descriptor for cesPlexServe.
struct CesPlexProtocol {
  // True if `verb` is one this handler serves right now. A verb outside
  // the set ends the channel without reading an envelope — so handlers
  // fold their "am I still bound?" check in here too (return false when
  // unbound), which is what stops in-flight channels on teardown.
  std::function<bool(uint8_t verb)> accepts;
  // Handle one verified op. `req` carries verb / reqNonce / reqSigHash /
  // bound; `preamble` is the preamble after the 4-byte reqNonce. Finish
  // via req->respond() / error() / respondAndClose().
  std::function<void(std::shared_ptr<CesPlexRequest> req,
                     ces::Bytes preamble)> dispatch;
};

// Per-op request handed to a handler's dispatch. Framework-built: the
// handler reads identity from `bound`, the op's nonce/sig from here, and
// finishes the op via the helpers below. Field names match the per-handler
// ReqCtx structs they replace, so dispatchers need no edits.
struct CesPlexRequest : std::enable_shared_from_this<CesPlexRequest> {
  std::shared_ptr<minx::RudpStream> stream;
  CesPlexHost* host = nullptr;        // signs responses; the host seam
  BoundChannelContext bound;
  uint8_t verb = 0;
  std::array<uint8_t, CES_PLEX_SIG_SIZE> sig{};
  uint64_t reqSigHash = 0;
  uint32_t reqNonce = 0;
  std::shared_ptr<CesPlexProtocol> proto;   // for looping to the next verb

  // Server-signed response for this op, then loop to the next verb.
  // `extraBody` streams after the envelope (e.g. a READ payload).
  void respond(uint8_t status, ces::Bytes preamble, ces::Bytes extraBody = {});
  // Server-signed error (empty preamble), then loop. Clean-stream
  // rejections — the envelope was consumed, nothing in flight.
  void error(uint8_t status) { respond(status, {}); }
  // Response (default empty preamble), then close the channel. For
  // body-bearing verbs rejected before their trailing body was read —
  // looping would desync the stream.
  void respondAndClose(uint8_t status, ces::Bytes preamble = {});
  void errorAndClose(uint8_t status) { respondAndClose(status); }
};

// Begin the signed-request loop on `stream`. Call from serve(); loops
// until the channel closes. Everything runs on the rpcTaskIO_ strand.
void cesPlexServe(std::shared_ptr<minx::RudpStream> stream,
                  BoundChannelContext bound,
                  CesPlexHost* host,
                  CesPlexProtocol proto);

// ===========================================================================
// CesPlexChannel — the per-channel client protocol, over an injected transport
// ===========================================================================
//
// The CesPlex client protocol — the signed bind handshake, per-op envelope
// signing, and the blocking verb-drive loop — with NO owned mechanics. It
// borrows a task io_context (where its async stream ops run) and a Rudp (where
// it opens its channel), so the SAME client codec composes onto any transport:
//
//   * CesPlexClient owns a Minx/Rudp/threads and hands this its taskIO + Rudp.
//   * a process already running a Rudp (the cesluajitd compute child's CesPlex
//     endpoint) hands this that same Rudp.
//
// CesFileClient / CesComputeClient are verb wrappers over a CesPlexChannel, so
// they have one implementation regardless of who owns the socket.
//
// Threading: the borrowed task io_context must be run by another thread; each
// verb posts its I/O there and blocks the CALLING thread on a future (caller
// thread must differ from the task io_context's thread).

class CesPlexChannel {
public:
  CesPlexChannel(boost::asio::io_context& taskIO, minx::Rudp* rudp);
  ~CesPlexChannel();
  CesPlexChannel(const CesPlexChannel&) = delete;
  CesPlexChannel& operator=(const CesPlexChannel&) = delete;

  // Open a fresh channel to `peer` and run the signed bind for `protocol`,
  // signed by `signerKey` (the per-op signer + billed principal).
  uint8_t select(const minx::SockAddr& peer, const std::string& protocol,
                 const KeyPair& signerKey);

  // Drop the bound stream (teardown).
  void reset();

  // Provide the server pubkey so response signatures verify (else each
  // response logs one LOGERROR and is treated as unverifiable).
  void setServerPubkey(const minx::Hash& pk);

  // See CesPlexClient::buildEnvelope.
  minx::Bytes buildEnvelope(uint8_t verb, std::span<const uint8_t> preamble);

  // See CesPlexClient::driveVerb (both overloads).
  uint8_t driveVerb(
      uint8_t verb,
      const minx::Bytes& envelope,
      size_t respFixedPreambleLen,
      const std::function<bool(ces::Bytes& preamble)>& readVariablePreamble,
      const std::function<uint64_t(const ces::Bytes& preamble)>& respBodyLen,
      const ces::Bytes& extraBodyToSend,
      ces::Bytes& outPreamble,
      ces::Bytes& outBody);

  uint8_t driveVerb(
      uint8_t verb,
      const minx::Bytes& envelope,
      size_t respFixedPreambleLen,
      const std::function<bool(ces::Bytes& preamble)>& readVariablePreamble,
      ces::Bytes& outPreamble);

  bool readExact(ces::Bytes& out, size_t n);

  uint64_t boundSessionToken() const;

  class Impl;

private:
  std::unique_ptr<Impl> impl_;
};

// ===========================================================================
// Client side — the shared blocking client
// ===========================================================================
//
// Owns one MINX socket + Rudp state machine + two io_contexts (net + task)
// with a thread each, drives Rudp ticks, runs the signed bind handshake
// for a protocol name, and exposes a blocking verb driver. A concrete
// client (CesFileClient, CesComputeClient) holds one of these and is just
// its per-verb preamble building + response parsing.
//
// Verb wire (per op): client writes [u8 verb][envelope][optional body],
// reads [u8 status], then on OK a fixed + optional variable preamble, then
// the server-signed trailer, then an optional response body. The bound
// channel survives across verbs; a wire error marks it dirty and the next
// verb reselects a fresh channel.

class CesPlexClient {
public:
  CesPlexClient();
  ~CesPlexClient();
  CesPlexClient(const CesPlexClient&) = delete;
  CesPlexClient& operator=(const CesPlexClient&) = delete;

  // Open a local UDP socket, wire up Rudp, and run the signed bind
  // handshake for `protocol` (e.g. "/ces/file/1") against the server.
  // `signerKey` becomes the channel principal.
  uint8_t connect(const std::string& host, uint16_t rpcPort,
                  const std::string& protocol, const KeyPair& signerKey);

  // Tear down the channel + I/O threads. Safe to call more than once.
  void disconnect();

  // Provide the server pubkey so response signatures verify (else each
  // response logs one LOGERROR and is treated as unverifiable).
  void setServerPubkey(const minx::Hash& pk);

  // The bound channel (valid after connect()), so a verb client can ride
  // this client's transport instead of opening its own.
  CesPlexChannel* channel();

  // Build a signed per-op envelope [u32 len][salt+preamble][65 sig] for
  // this channel. An 8-byte per-op salt is prepended so identical
  // (verb, preamble) ops still get distinct sigs (the server strips it);
  // the sig is over verb || salt || preamble || sessionToken.
  minx::Bytes buildEnvelope(uint8_t verb,
                            std::span<const uint8_t> preamble);

  // Drive one verb to completion. ensureClean() → write
  // [verb][envelope][extraBodyToSend?] → read status → on OK read the
  // fixed preamble (respFixedPreambleLen) + run readVariablePreamble →
  // verify the server-signed trailer → on OK read a response body whose
  // length respBodyLen() derives from the preamble. Returns the status
  // byte (or CES_ERROR_INTERNAL on a wire failure). Unused hooks: pass
  // nullptr / {} / 0.
  uint8_t driveVerb(
      uint8_t verb,
      const minx::Bytes& envelope,
      size_t respFixedPreambleLen,
      const std::function<bool(ces::Bytes& preamble)>& readVariablePreamble,
      const std::function<uint64_t(const ces::Bytes& preamble)>& respBodyLen,
      const ces::Bytes& extraBodyToSend,
      ces::Bytes& outPreamble,
      ces::Bytes& outBody);

  // Convenience for verbs with no body to send and no response body.
  uint8_t driveVerb(
      uint8_t verb,
      const minx::Bytes& envelope,
      size_t respFixedPreambleLen,
      const std::function<bool(ces::Bytes& preamble)>& readVariablePreamble,
      ces::Bytes& outPreamble);

  // Read n more bytes off the channel — for readVariablePreamble hooks
  // that pull trailing variable fields.
  bool readExact(ces::Bytes& out, size_t n);

  class Impl;

private:
  std::unique_ptr<Impl> impl_;
};

} // namespace ces
