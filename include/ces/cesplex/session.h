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
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
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
  CesPlexHost* host = nullptr;        // signs responses
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

// A streamed reply for one op. The reply wire is
//     ([u32 BE len][len bytes] | [u32 0xFFFFFFFF])* [u32 0] <signed response>
// Each frame has len > 0. A bare 0xFFFFFFFF is a keepalive with no bytes
// (see keepAlive): the reader skips it. The [u32 0] terminator ends the
// frames, and the usual server-signed response follows it. A handler opens one per op, calls
// write() for each piece of the reply as it has it, then calls finish() once.
// write() and finish() are safe from any thread. All stream writes run on the
// stream's executor, in call order. The client reads it with
// CesPlexChannel::driveStreamVerb.
// The [u32] length word of a keepalive in a streamed reply.
inline constexpr uint32_t kCesPlexKeepAlive = 0xFFFFFFFFu;

class CesPlexReplyStream
    : public std::enable_shared_from_this<CesPlexReplyStream> {
public:
  explicit CesPlexReplyStream(std::shared_ptr<CesPlexRequest> req);

  // Queue one frame. An empty chunk is ignored.
  void write(ces::Bytes chunk);
  // Queue the terminator and the signed response, then loop the channel.
  void finish(uint8_t status, ces::Bytes preamble = {});
  // As finish(), but close the channel after the response. For a verb that
  // rejects its request before it read the request body.
  void finishAndClose(uint8_t status, ces::Bytes preamble = {});
  // True when a stream write failed (the client is gone).
  bool dead() const { return dead_.load(); }
  // Send a keepalive whenever the stream has been quiet for `every`, until
  // finish. A channel with no traffic is dropped when it is idle for the
  // RUDP inactivity time (60 s on a default client), and a producer can be
  // silent longer than that. Call once.
  void keepAlive(std::chrono::milliseconds every);

private:
  struct Item {
    ces::Bytes bytes;      // frame bytes, or the terminator
    bool final = false;    // after `bytes`, send the response
    bool close = false;    // response, then close
    uint8_t status = 0;
    ces::Bytes preamble;
  };
  void enqueue(Item it);
  void pump();             // stream executor only
  void armKeepAlive();     // stream executor only

  std::shared_ptr<CesPlexRequest> req_;
  std::deque<Item> queue_; // stream executor only
  bool writing_ = false;   // stream executor only
  bool finished_ = false;  // stream executor only
  std::atomic<bool> dead_{false};
  std::chrono::milliseconds keepAliveEvery_{0};
  std::chrono::steady_clock::time_point lastWrite_{};  // stream executor only
  std::shared_ptr<void> keepAliveTimer_;               // a steady_timer

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

  // End the channel: send HS_CLOSE to the server and free the channel's slot
  // in the Rudp, then reset(). The owner calls it when it is done with the
  // channel, and the destructor sends nothing. From a thread other than the
  // task io_context's, it waits at most 1 s for that thread.
  void close();

  // Hang up on the verb that waits for its answer with no limit (untilClosed). It
  // ends with CES_ERROR_CONNECTION_LOST, and its channel with HS_CLOSE. When none
  // waits, the next one ends so, before it sends anything. A verb after that opens a
  // new channel. Other verbs ignore it. From any thread.
  void cancel();

  // How often a verb that waits with no limit tells the server that its client is
  // there (CES_PLEX_VERB_NOP). A test makes it short.
  void _testSetNopEvery(std::chrono::milliseconds every);

  // Provide the server pubkey so response signatures verify (else each
  // response logs one LOGERROR and is treated as unverifiable).
  void setServerPubkey(const minx::Hash& pk);

  // See CesPlexClient::buildEnvelope.
  minx::Bytes buildEnvelope(uint8_t verb, std::span<const uint8_t> preamble);

  // See CesPlexClient::driveVerb (both overloads). With `untilClosed` the wait for
  // the answer has no limit: it ends with the answer, or when the channel closes
  // (CES_ERROR_CONNECTION_LOST) or cancel() hangs up. While it waits, the client
  // tells the server that it is there (CES_PLEX_VERB_NOP), so that the channel does
  // not look idle to either end.
  uint8_t driveVerb(
      uint8_t verb,
      const minx::Bytes& envelope,
      size_t respFixedPreambleLen,
      const std::function<bool(ces::Bytes& preamble)>& readVariablePreamble,
      const std::function<uint64_t(const ces::Bytes& preamble)>& respBodyLen,
      const ces::Bytes& extraBodyToSend,
      ces::Bytes& outPreamble,
      ces::Bytes& outBody,
      bool untilClosed = false);

  uint8_t driveVerb(
      uint8_t verb,
      const minx::Bytes& envelope,
      size_t respFixedPreambleLen,
      const std::function<bool(ces::Bytes& preamble)>& readVariablePreamble,
      ces::Bytes& outPreamble);

  bool readExact(ces::Bytes& out, size_t n);

  // Drive one verb that has a streamed reply (see CesPlexReplyStream). Write
  // [verb][envelope][extraBodyToSend?], call onFrame for each reply frame in
  // order, then read the status, the fixed preamble on OK, and the signed
  // trailer. Keepalives are skipped. `frameTimeout` bounds each wait for a
  // frame or a keepalive, so a slow producer can take longer than the usual
  // verb timeout. `totalTimeout` bounds the whole reply. When onFrame
  // returns false the verb ends with CES_ERROR_INTERNAL and the channel is
  // reset. Returns the status byte. A failed read or write returns
  // CES_ERROR_TIMEOUT (no reply in time) or CES_ERROR_CONNECTION_LOST (the
  // channel closed), and a reply that breaks the protocol returns
  // CES_ERROR_INTERNAL.
  uint8_t driveStreamVerb(
      uint8_t verb,
      const minx::Bytes& envelope,
      const ces::Bytes& extraBodyToSend,
      const std::function<bool(const ces::Bytes& frame)>& onFrame,
      std::chrono::steady_clock::duration frameTimeout,
      std::chrono::steady_clock::duration totalTimeout,
      size_t respFixedPreambleLen,
      ces::Bytes& outPreamble);
  // The same, and after the fixed preamble readVariablePreamble reads the
  // rest of it (with readExact), so the signed trailer covers it all.
  uint8_t driveStreamVerb(
      uint8_t verb,
      const minx::Bytes& envelope,
      const ces::Bytes& extraBodyToSend,
      const std::function<bool(const ces::Bytes& frame)>& onFrame,
      std::chrono::steady_clock::duration frameTimeout,
      std::chrono::steady_clock::duration totalTimeout,
      size_t respFixedPreambleLen,
      const std::function<bool(ces::Bytes& preamble)>& readVariablePreamble,
      ces::Bytes& outPreamble);

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

  // Tear down the channel + I/O threads. Safe to call more than once. It
  // first closes the channel (CesPlexChannel::close), and the destructor
  // tears down without it.
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
  // the sig is over verb || salt || preamble || bind digest.
  minx::Bytes buildEnvelope(uint8_t verb,
                            std::span<const uint8_t> preamble);

  // Drive one verb to completion. ensureClean() → write
  // [verb][envelope][extraBodyToSend?] → read status → on OK read the
  // fixed preamble (respFixedPreambleLen) + run readVariablePreamble →
  // verify the server-signed trailer → on OK read a response body whose
  // length respBodyLen() derives from the preamble. Returns the status
  // byte, or the codes of driveStreamVerb for a failure on the wire. Unused
  // hooks: pass nullptr / {} / 0.
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
