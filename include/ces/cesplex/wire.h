// wire.h — wire format helpers for the CesPlex bind contract
// + per-op envelope.
//
//   1. The select handshake is a SIGNED bind contract. Both client and
//      server commit cryptographic artifacts to the binding event:
//
//      Client → Server (signed by client):
//        [u16 BE name_len][name]
//        [u64 BE client_time_us][32 client_pubkey]
//        [32 sha256(everything above)]
//        [65 sig]
//
//      Server → Client (signed by server):
//        [u8 status]                  (CES_PLEX_OK=0x01 / CES_PLEX_NACK=0x00)
//        [u64 BE server_time_us][32 server_pubkey]
//        [8  channel_session_token]   (from RUDP, anchors per-op sigs;
//                                      guaranteed non-zero in practice)
//        [u32 BE server_proto_version]
//        [32 sha256(status || client_sha256 || all-of-above)]
//        [65 sig]
//
//   2. Once bound, every per-op verb on the channel uses a minimal
//      envelope:
//
//        [u8 verb][u32 BE preamble_len][preamble bytes]
//        [65 sig over sha256(verb || preamble || sessionToken)]
//        [optional body: bytes whose sha256 is committed inside the
//         preamble for verbs that carry executable code (WRITE/APPEND).
//         READ has the symmetric thing on the response side.]
//
//      No per-op pubkey on the wire — the bound pubkey is implicit.
//      No per-op timestamp — the application's reqNonce in the
//      preamble + the channel's sessionToken give natural uniqueness
//      per channel-incarnation. Dedup key = first 8 bytes of sig as
//      big-endian u64. Sig space is per-channel-incarnation so
//      cross-channel collisions can't happen; within a channel the
//      birthday horizon is ~2^32 ops, well beyond any practical
//      channel lifetime.
//
//   3. The bound state (pubkey + sessionToken + bind time) lives on a
//      BoundChannelContext that the CesPlex Session passes to the
//      application handler at handoff (CesPlexHandler::serve).
//
// All multi-byte ints are big-endian on the wire.
//
// Status byte convention (OK=0x01, NACK=0x00) is opposite of the usual
// "0 = success" idiom: NACK is the safer default for an uninitialized
// ParsedBindReply, so a parse failure or zeroed buffer reads as
// "rejected" not "approved".
//
// The signing is anti-MITM only. Server sigs prove the bind reply came from
// the intended server; client sigs prove each op came from the bound
// principal. The bus carries no prices — it measures bytes and time and
// reports the counts to its host, which does all pricing and accounting.

#pragma once

#include <ces/keys.h>
#include <ces/types.h>
#include <ces/buffer.h>


#include <minx/types.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace ces {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Status byte values in the bind reply. NACK=0x00 is intentional —
// see the header comment.
constexpr uint8_t CES_PLEX_OK   = 0x01;
constexpr uint8_t CES_PLEX_NACK = 0x00;

// Initial server protocol version. Iterated freely inside the bound
// contract without re-bumping the protocol name (`/ces/file/N`).
// The protocol-name version reserves itself for handshake-shape
// breaks (decade-scale events).
constexpr uint32_t CES_PLEX_PROTO_VERSION_V1 = 1;

// Maximum protocol name length accepted in the bind preamble. Names
// longer than this are NACKed before the server reads them.
constexpr uint16_t CES_PLEX_MAX_NAME_LEN = 256;

// Wire layout sizes. PublicKey and Hash in CES are 32 bytes on the
// wire (the in-memory PublicKey class wraps a larger buffer to also
// hold the algorithm decorator and per-algo state, so its sizeof is
// not 32; the wire form is always serialized via PublicKey::toBytes).
// Signature on the wire is 65 bytes (1 algo decorator + 64-byte sig).
constexpr size_t CES_PLEX_SHA256_SIZE = 32;
constexpr size_t CES_PLEX_PUBKEY_SIZE = 32;
constexpr size_t CES_PLEX_SIG_SIZE    = 65;

static_assert(sizeof(minx::Hash) == CES_PLEX_SHA256_SIZE,
              "wire/type mismatch: minx::Hash vs CES_PLEX_SHA256_SIZE");
static_assert(sizeof(Signature) == CES_PLEX_SIG_SIZE,
              "wire/type mismatch: Signature vs CES_PLEX_SIG_SIZE");

// Bind reply fixed-shape size (the bytes between the status byte
// and the trailing sha256 + sig). Locked to its decomposition:
//   8  server_time_us
// + 32 server_pubkey         (= CES_PLEX_PUBKEY_SIZE)
// + 8  channel_session_token
// + 4  server_proto_version
// = 52 bytes
constexpr size_t CES_PLEX_BIND_REPLY_BODY_SIZE =
    8 + CES_PLEX_PUBKEY_SIZE + 8 + 4;
static_assert(CES_PLEX_BIND_REPLY_BODY_SIZE == 52,
              "bind reply body size diverged from documented layout");

// Total bind reply size = status + body + sha256 + sig.
constexpr size_t CES_PLEX_BIND_REPLY_TOTAL_SIZE =
    1 + CES_PLEX_BIND_REPLY_BODY_SIZE + CES_PLEX_SHA256_SIZE + CES_PLEX_SIG_SIZE;
static_assert(CES_PLEX_BIND_REPLY_TOTAL_SIZE == 150,
              "bind reply total size diverged");

// Per-op request envelope header: [u8 verb][u32 BE preamble_len].
constexpr size_t CES_PLEX_VERB_SIZE         = sizeof(uint8_t);
constexpr size_t CES_PLEX_PREAMBLE_LEN_SIZE = sizeof(uint32_t);

// Server-signed per-op response envelope:
//   [u8 status][preamble][u64 time_us][u64 req_sig_hash][sha256][sig]
constexpr size_t CES_PLEX_STATUS_SIZE       = sizeof(uint8_t);
constexpr size_t CES_PLEX_TIME_US_SIZE      = sizeof(uint64_t);
constexpr size_t CES_PLEX_REQ_SIG_HASH_SIZE = sizeof(uint64_t);

// Fixed bytes trailing the response preamble: time_us + req_sig_hash +
// digest + sig. The status byte and preamble precede it.
constexpr size_t CES_PLEX_RESP_TRAILER_SIZE =
    CES_PLEX_TIME_US_SIZE + CES_PLEX_REQ_SIG_HASH_SIZE
    + CES_PLEX_SHA256_SIZE + CES_PLEX_SIG_SIZE;
static_assert(CES_PLEX_RESP_TRAILER_SIZE == 113,
              "response trailer size diverged from documented layout");

// Bind request wire: [u16 name_len][name][u64 client_time_us]
//   [client_pubkey][client_sha256][sig]. The tail is everything after
// the name (time + pubkey + digest + sig).
constexpr size_t CES_PLEX_NAME_LEN_SIZE = sizeof(uint16_t);
constexpr size_t CES_PLEX_BIND_REQ_TAIL_SIZE =
    sizeof(uint64_t) + CES_PLEX_PUBKEY_SIZE
    + CES_PLEX_SHA256_SIZE + CES_PLEX_SIG_SIZE;
static_assert(CES_PLEX_BIND_REQ_TAIL_SIZE == 137,
              "bind request tail size diverged from documented layout");

// Bind-request freshness window. The signed client_time_us is rejected if more
// than CES_PLEX_BIND_MAX_AGE_US in the past or CES_PLEX_BIND_FUTURE_DRIFT_US in
// the future. Without it a captured bind replays indefinitely on fresh channels,
// each re-binding as the victim and accruing ChannelMeter against them. 5 min
// each way absorbs clock skew while bounding replay.
constexpr uint64_t CES_PLEX_BIND_MAX_AGE_US      = 300ULL * 1000000;
constexpr uint64_t CES_PLEX_BIND_FUTURE_DRIFT_US = 300ULL * 1000000;

// ---------------------------------------------------------------------------
// BoundChannelContext — what CesPlex passes to a handler at handoff
// ---------------------------------------------------------------------------
//
// Constructed by CesPlex Session after the signed select succeeds.
// Passed by value to CesPlexHandler::serve. Handlers store it on
// their per-channel state struct and use it for every per-op verify.

// What CesPlex passes to a server-side handler at bind handoff. No rate
// or price fields anywhere — the bus measures resource usage and reports
// counts to its host; the host does all pricing and accounting.
struct BoundChannelContext {
  // Identity
  PublicKey  boundPubkey;          // for sig verify
  HashPrefix payerPfx{};           // first 8 bytes of pubkey, account map key

  // Channel anchor (from RUDP). Always non-zero for a successful bind;
  // a 0 sessionToken indicates the context wasn't populated.
  uint64_t   sessionToken = 0;     // per-channel-incarnation salt for sigs

  // Server's wall-clock at bind (informational; useful for handler
  // logging and freshness checks).
  uint64_t   serverBoundAtUs = 0;
};

// ---------------------------------------------------------------------------
// Bind preamble — client side
// ---------------------------------------------------------------------------

// Build the signed bind request the client sends as the very first
// bytes on a freshly-opened RUDP channel. `name` is the protocol name
// (e.g. "/ces/file/1"). `clientKey` is the client's keypair; the
// resulting bind binds this channel to clientKey.getPublicKeyAsHash() as
// the principal identity on the server side.
//
// Output bytes are ready to async_write onto the RudpStream as a
// single buffer.
minx::Bytes buildBindRequest(const std::string& name,
                              uint64_t clientTimeUs,
                              const KeyPair& clientKey);

// Same wire as buildBindRequest, but with the signature supplied from outside
// instead of signing with a local KeyPair. For tunnelers (cesweb) where the
// private key never reaches this process: the caller signs the bind digest
// elsewhere (browser / node) and passes the 65-byte sig + the 32-byte pubkey.
// The digest is recomputed here from (name, time, pubkey) so it always matches
// what the server verifies; the caller's sig must be over that same digest.
minx::Bytes buildBindRequestSigned(const std::string& name,
                                   uint64_t clientTimeUs,
                                   std::span<const uint8_t> clientPubkey,
                                   const Signature& sig);

// Compute the digest the client signs over (and the server recomputes
// to verify): sha256(name_len || name || clientTimeUs || clientPubkey).
std::array<uint8_t, CES_PLEX_SHA256_SIZE>
computeBindRequestDigest(std::span<const uint8_t> name,
                         uint64_t clientTimeUs,
                         std::span<const uint8_t> clientPubkey);

// ---------------------------------------------------------------------------
// Bind reply — server side
// ---------------------------------------------------------------------------

// Inputs the server gathers when building the reply. Identity and
// anchoring only — the bind contract carries no prices.
struct BindReplyFields {
  uint8_t  status = CES_PLEX_OK;
  uint64_t serverTimeUs = 0;
  uint64_t channelSessionToken = 0;
  uint32_t serverProtoVersion = CES_PLEX_PROTO_VERSION_V1;
};

// Build the signed bind reply. `clientSha256` is the digest the
// client already signed (returned by computeBindRequestDigest at parse
// time); the reply binds to it so the client can confirm the server
// is responding to *this* bind.
minx::Bytes buildBindReply(const BindReplyFields& fields,
                            std::span<const uint8_t> clientSha256,
                            const KeyPair& serverKey);

// Parsed view of an inbound bind reply. The client populates this by
// reading the wire, then runs the four mandatory checks.
struct ParsedBindReply {
  uint8_t  status = CES_PLEX_NACK;
  uint64_t serverTimeUs = 0;
  std::array<uint8_t, CES_PLEX_PUBKEY_SIZE> serverPubkey{};
  uint64_t channelSessionToken = 0;
  uint32_t serverProtoVersion = 0;
  std::array<uint8_t, CES_PLEX_SHA256_SIZE> sha256{};
  std::array<uint8_t, CES_PLEX_SIG_SIZE> sig{};
};

// Compute the digest the server signs over and the client recomputes:
// sha256(status || clientSha256 || serverTimeUs || serverPubkey ||
//        channelSessionToken || serverProtoVersion).
//
// Reads only the input fields of `reply` (status / time / pubkey /
// token / version). Ignores reply.sha256 and reply.sig (those are the
// digest's *output*, populated by the signer). The type is shared with
// parseBindReply for caller convenience; the digest computation itself
// is symmetric on both sides.
std::array<uint8_t, CES_PLEX_SHA256_SIZE>
computeBindReplyDigest(const ParsedBindReply& reply,
                       std::span<const uint8_t> clientSha256);

// Decode CES_PLEX_BIND_REPLY_TOTAL_SIZE bytes off the wire into a
// ParsedBindReply. Pure parser — no validation. Caller checks status
// and runs verifyBindReply for digest + sig integrity.
ParsedBindReply parseBindReply(
    std::span<const uint8_t, CES_PLEX_BIND_REPLY_TOTAL_SIZE> buf);

// Recompute the reply digest, compare against the in-reply digest,
// then verify the server's sig against the in-reply pubkey. Returns
// true iff both checks pass. Deliberately doesn't distinguish
// digest-mismatch from sig-mismatch — both are "rejected", and
// leaking which check failed would help an attacker probe.
//
// Caller decides what to do with a true result (TOFU-capture the
// pubkey, hard-check against an expected one, etc.).
bool verifyBindReply(const ParsedBindReply& reply,
                     std::span<const uint8_t> clientSha256);

// ---------------------------------------------------------------------------
// Per-op envelope — minimal artifact, just a sig
// ---------------------------------------------------------------------------
//
// On the wire: [u8 verb][u32 BE preamble_len][preamble][65 sig]
//
// The sig is over sha256(verb || preamble || sessionToken). No pubkey,
// no timestamp — both implicit in the bound channel. For verbs with
// a body (WRITE/APPEND/READ-response), the preamble carries
// body_length + body_sha256; the body bytes follow the sig and are
// hashed incrementally on receive, compared to the authenticated
// digest in the preamble.

// Compute the digest the client signs over and the server recomputes
// to verify: sha256(verb || preamble || sessionToken).
std::array<uint8_t, CES_PLEX_SHA256_SIZE>
computePerOpDigest(uint8_t verb,
                   std::span<const uint8_t> preamble,
                   uint64_t sessionToken);

// Build the 65-byte sig for a per-op envelope. Caller emits
// [u8 verb][u32 preamble_len][preamble] and appends this sig.
Signature signPerOp(const KeyPair& signer,
                    uint8_t verb,
                    std::span<const uint8_t> preamble,
                    uint64_t sessionToken);

// Verify a per-op sig against the bound pubkey. Returns true on
// success; false on any mismatch (bad sig, wrong pubkey, etc.).
bool verifyPerOp(const BoundChannelContext& bound,
                 uint8_t verb,
                 std::span<const uint8_t> preamble,
                 const Signature& sig);

// Convenience: extract the dedup hash. Skips the 1-byte algorithm
// decorator at sig[0] and reads sig[1..8] as a big-endian u64. Sig
// space is per-channel-incarnation, so cross-channel collisions
// can't happen; within one channel the 64-bit prefix gives a
// birthday horizon of ~2^32 ops, well past any practical channel
// lifetime.
uint64_t sigDedupHash(const Signature& sig);

// Build a server-signed per-op response envelope:
//   [u8 status][preamble][u64 time_us][u64 req_sig_hash][sha256][sig]
// The signature covers sha256(status || verb || preamble || time_us ||
// req_sig_hash) — verb is bound into the digest but not emitted (the
// client already knows which verb it sent). Shared by every CesPlex
// handler that answers a per-op verb.
ces::Bytes buildPerOpResponse(const KeyPair& serverKey,
                              uint8_t verb,
                              uint8_t status,
                              std::span<const uint8_t> preamble,
                              uint64_t reqSigHash);

} // namespace ces
