// compute_client.h - blocking client for the L2 compute protocol.
//
// Same shape as CesFileClient: one instance, one RUDP channel, one
// server. Each verb method is blocking. Response signatures are
// verified if setServerPubkey() has been called; unverified responses
// log one LOGERROR and return the bytes.
//
// Verbs:
//   launch(signer, name)    → instance_id + started_at_us  (always mints
//                             a new id; multiple instances per source
//                             coexist up to compute_max_instances)
//   kill(signer, id)        → ok
//   list(signer)            → owner-scoped [instance_id, name,
//                             started_at_us, file_balance, cpu, rss,
//                             ports]*
//   stat(id)                → started_at_us, file_balance, cpu, rss,
//                             ports, name  (public — any signer)
//   instances(path)         → public [instance_id, started_at_us, cpu,
//                             rss, ports]* for `path` (no owner check;
//                             enables discovery AND dialing of services)
//
// LAUNCH / KILL are owner-gated (they mutate); LIST is scoped to the
// signer's own instances. STAT and INSTANCES are public to any signer —
// they expose a live instance's leased ports so anyone can discover a
// running service and dial it. No unsigned verbs in the compute protocol
// (every verb rides a signed bind and pays feeQuery).

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

class CesComputeClient {
public:
  struct InstanceInfo {
    uint64_t instanceId = 0;
    std::string sourceName;
    uint64_t startedAtUs = 0;
    uint64_t fileBalance = 0;
    // Last supervisor-tick sample. cpuBasisPoints is in units of
    // one core: 10000 = 100% of a single CPU (Lua children are
    // single-threaded so 10000 is the practical ceiling).
    uint32_t cpuBasisPoints = 0;
    uint64_t rssBytes = 0;
    // The instance's statically-leased UDP ports (0 = no lease):
    // clientPort = outbound CES-client source port; rpcPort = the
    // instance's own inbound /ces/luarpc/1 host port (directly dialable).
    uint16_t clientPort = 0;
    uint16_t rpcPort = 0;
    // The instance's program-keypair pubkey (0 = none). A peer needs it to
    // address this instance's /ces/luarpc/1 endpoint via ces.conn.connect.
    std::array<uint8_t, 32> programPubkey{};
  };

  CesComputeClient();
  ~CesComputeClient();

  CesComputeClient(const CesComputeClient&) = delete;
  CesComputeClient& operator=(const CesComputeClient&) = delete;

  // Open a UDP socket, wire up Rudp, and perform the signed CesPlex
  // bind handshake for "/ces/compute/1" against the target server.
  // `signerKey` becomes the channel principal — every verb on this
  // connection is signed by + bills against `signerKey.getPublicKeyAsHash()`.
  uint8_t connect(const std::string& host, uint16_t rpcPort,
                  const KeyPair& signerKey);

  // Drive verbs over a CesPlexChannel the caller owns and has already
  // bound — e.g. the compute child driving /ces/compute/1 over its own
  // CesPlex endpoint. Mutually exclusive with connect().
  void attach(CesPlexChannel& channel);

  // Tear down the channel and I/O threads. Safe to call more than once.
  void disconnect();

  // Provide the server's 32-byte public key so response signatures
  // can be verified. Leaving this unset is permitted — responses are
  // then treated as unverifiable; one LOGERROR is emitted per response.
  void setServerPubkey(const minx::Hash& pk);

  // ---- Verbs ----
  //
  // The signing key is fixed at connect() time. Each verb is signed
  // by + bills against the bound key.

  uint8_t launch(const std::string& name,
                 uint64_t& outInstanceId, uint64_t& outStartedAtUs);

  uint8_t kill(uint64_t instanceId);

  uint8_t list(std::vector<InstanceInfo>& out);

  uint8_t stat(uint64_t instanceId, InstanceInfo& out);

  // Public enumeration of live instances for a given source path —
  // discovery + endpoints in one call. Each InstanceInfo carries the
  // instance id, uptime, last cpu/rss sample, and leased ports (sourceName
  // is set to `path`; fileBalance is left 0 — use stat(id) for that).
  // Returns CES_OK with an empty `out` if nothing is running under `path`.
  // No owner check; signer just pays the per-op fee.
  uint8_t instances(const std::string& path, std::vector<InstanceInfo>& out);

  // Implementation detail; public only so the .cpp-local helpers can
  // take Impl& without forward-declaring everything inside the .cpp.
  class Impl;

private:
  std::unique_ptr<Impl> impl_;
};

} // namespace ces
