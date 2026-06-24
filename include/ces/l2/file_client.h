// file_client.h - blocking client for the L2 file-store protocol.
//
// Wraps the full stack needed to drive `builtin:file` verbs from outside
// the server: MINX socket, RUDP, CesPlex select handshake, and per-verb
// preamble-first encoding with server-signed response parsing.
//
// The class is blocking: each verb posts to internal threads, waits for
// completion, returns. One instance talks to exactly one server over
// exactly one RUDP channel (opened at connect, closed at disconnect /
// destructor). Callers that need parallelism use multiple instances.
//
// Response signature verification: call setServerPubkey() with the
// operator's pubkey (fetched via `server-info` or provided by the
// user) before running any verb. Each response's server signature is
// then verified; on mismatch, a LOGERROR is emitted but the op's
// return value is unchanged — the caller decides whether to trust
// the bytes.
//
// Error model: every verb returns a `uint8_t` CES error code
// (CES_OK on success). Out-parameters are written only on CES_OK.

#pragma once

#include <ces/keys.h>
#include <ces/types.h>

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ces {

class CesPlexChannel;

class CesFileClient {
public:
  // Data returned by STAT.
  struct StatInfo {
    std::array<uint8_t, 32> ownerPubkey{};
    uint64_t fileBalance = 0;
    uint64_t pricePerKb = 0;
    uint64_t size = 0;
    uint64_t createdUs = 0;
    uint64_t modifiedUs = 0;
  };

  CesFileClient();
  ~CesFileClient();

  CesFileClient(const CesFileClient&) = delete;
  CesFileClient& operator=(const CesFileClient&) = delete;

  // Open a UDP socket, wire up Rudp, and perform the signed CesPlex
  // bind handshake for "/ces/file/1" against the target server.
  // `signerKey` is the principal identity for the channel — every
  // verb on this connection bills + acts as `signerKey.getPublicKeyAsHash()`.
  // To act as a different principal, open a new connection.
  //
  // Returns CES_OK on success; CES_ERROR_INTERNAL on transport
  // failure or sig-verify mismatch; CES_ERROR_PROTO_REJECTED on a
  // signed NACK reply.
  uint8_t connect(const std::string& host, uint16_t rpcPort,
                  const KeyPair& signerKey);

  // Drive verbs over a CesPlexChannel the caller owns and has already
  // bound (select()ed) — e.g. the compute child driving /ces/file/1 over
  // its own CesPlex endpoint, instead of opening a fresh socket. Mutually
  // exclusive with connect(); the caller owns the channel's lifetime.
  void attach(CesPlexChannel& channel);

  // Tear down the channel and I/O threads. Safe to call more than once.
  void disconnect();

  // Provide the server's 32-byte public key so response signatures can
  // be verified. Leaving this unset is permitted — responses are then
  // treated as unverifiable; one LOGERROR is emitted per response.
  void setServerPubkey(const minx::Hash& pk);

  // ---- Verbs ----
  //
  // The signing key is fixed at connect() time; every verb on this
  // connection is signed by + bills against that key. No per-verb
  // signer parameter — the bind contract makes the channel principal
  // immutable for the channel's lifetime.

  uint8_t create(const std::string& name,
                 uint64_t size, uint64_t pricePerKb,
                 uint64_t initialDeposit,
                 uint64_t& outFileBalance, uint64_t& outCostDebited);

  // `content.size()` must be ≤ 1 MB (server cap). For bigger payloads
  // the caller chunks and calls `write` multiple times.
  uint8_t write(const std::string& name,
                uint64_t offset, const ces::Bytes& content,
                uint64_t& outFileBalance);

  // `length` must be ≤ 1 MB.
  uint8_t read(const std::string& name,
               uint64_t offset, uint32_t length,
               ces::Bytes& outContent,
               minx::Hash& outRangeHash);

  uint8_t deposit(const std::string& name,
                  uint64_t amount, uint64_t& outFileBalance);

  // Fund a single key in a kv-store ("anyone funds any entry there"): adds
  // `amount` to that key's rent balance. Any signer, no owner check. The key
  // must already exist. Returns the key's new cell balance.
  uint8_t kvDeposit(const std::string& name, const ces::Bytes& key,
                    uint64_t amount, uint64_t& outCellBalance);

  uint8_t withdraw(const std::string& name,
                   uint64_t amount, uint64_t& outFileBalance);

  uint8_t setPrice(const std::string& name,
                   uint64_t newPrice, uint64_t& outPrice);

  uint8_t deleteFile(const std::string& name,
                     uint64_t& outRefunded);

  uint8_t append(const std::string& name,
                 const ces::Bytes& content,
                 uint64_t& outFileBalance, uint64_t& outNewSize);

  uint8_t resize(const std::string& name,
                 uint64_t newSize, uint64_t& outNewSize);

  uint8_t stat(const std::string& name, StatInfo& outInfo);

  // Declared public only so .cpp-local helpers can take Impl& as a
  // parameter. The full definition lives in the .cpp; callers have
  // no way to instantiate or inspect it.
  class Impl;

private:
  std::unique_ptr<Impl> impl_;
};

} // namespace ces
