// compute_client.cpp - CesComputeClient.
//
// A thin verb layer over CesPlexClient (see cesplex.h), which owns all the
// MINX/Rudp/threads/bind plumbing. Each method here is just the verb's
// preamble building + response parsing; the shared client drives the wire.

#include <ces/l2/compute_client.h>
#include <ces/l2/cesplex.h>
#include <ces/buffer.h>
#include <ces/types.h>

#include <cstdint>
#include <functional>
#include <vector>

namespace ces {

namespace {

constexpr uint8_t kVerbLaunch    = 0x01;
constexpr uint8_t kVerbKill      = 0x02;
constexpr uint8_t kVerbList      = 0x03;
constexpr uint8_t kVerbStat      = 0x04;
constexpr uint8_t kVerbInstances = 0x05;

constexpr const char* kComputeProto = "/ces/compute/1";

// Parse a STAT response preamble: after the 36-byte fixed header
// (id | started_at | file_balance | cpu_bp | rss_bytes) comes u16
// name_len + name. Pulls the variable tail off the channel.
uint8_t statVariableReader(CesPlexClient& base,
                           CesComputeClient::InstanceInfo& out,
                           ces::Bytes& preamble) {
  ces::Bytes lenBuf;
  if (!base.readExact(lenBuf, 2)) return CES_ERROR_INTERNAL;
  preamble.insert(preamble.end(), lenBuf.begin(), lenBuf.end());
  uint16_t nameLen = ces::Buffer::peek<uint16_t>(lenBuf.data());
  ces::Bytes nameBuf;
  if (nameLen > 0) {
    if (!base.readExact(nameBuf, nameLen)) return CES_ERROR_INTERNAL;
    preamble.insert(preamble.end(), nameBuf.begin(), nameBuf.end());
  }
  out.instanceId     = ces::Buffer::peek<uint64_t>(preamble.data());
  out.startedAtUs    = ces::Buffer::peek<uint64_t>(preamble.data() + 8);
  out.fileBalance    = ces::Buffer::peek<uint64_t>(preamble.data() + 16);
  out.cpuBasisPoints = ces::Buffer::peek<uint32_t>(preamble.data() + 24);
  out.rssBytes       = ces::Buffer::peek<uint64_t>(preamble.data() + 28);
  out.sourceName.assign(nameBuf.begin(), nameBuf.end());
  return CES_OK;
}

} // namespace

class CesComputeClient::Impl {
public:
  CesPlexClient base;
};

CesComputeClient::CesComputeClient() : impl_(std::make_unique<Impl>()) {}
CesComputeClient::~CesComputeClient() = default;

uint8_t CesComputeClient::connect(const std::string& host, uint16_t rpcPort,
                                  const KeyPair& signerKey) {
  return impl_->base.connect(host, rpcPort, kComputeProto, signerKey);
}

void CesComputeClient::disconnect() { impl_->base.disconnect(); }

void CesComputeClient::setServerPubkey(const minx::Hash& pk) {
  impl_->base.setServerPubkey(pk);
}

uint8_t CesComputeClient::launch(const std::string& name,
                                 uint64_t& outInstanceId,
                                 uint64_t& outStartedAtUs) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = impl_->base.buildEnvelope(kVerbLaunch, pre);

  ces::Bytes resp;
  uint8_t rc = impl_->base.driveVerb(kVerbLaunch, env, /*fixedPre=*/16,
                                     nullptr, resp);
  if (rc != CES_OK) return rc;
  outInstanceId  = ces::Buffer::peek<uint64_t>(resp.data());
  outStartedAtUs = ces::Buffer::peek<uint64_t>(resp.data() + 8);
  return CES_OK;
}

uint8_t CesComputeClient::kill(uint64_t instanceId) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint64_t>(pre, instanceId);
  auto env = impl_->base.buildEnvelope(kVerbKill, pre);

  ces::Bytes resp;
  return impl_->base.driveVerb(kVerbKill, env, /*fixedPre=*/0, nullptr, resp);
}

uint8_t CesComputeClient::list(std::vector<InstanceInfo>& out) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  auto env = impl_->base.buildEnvelope(kVerbList, pre);

  out.clear();
  // Variable preamble: read u32 count, then count × entries.
  auto readVariable = [&](ces::Bytes& preamble) -> bool {
    ces::Bytes countBuf;
    if (!impl_->base.readExact(countBuf, 4)) return false;
    preamble.insert(preamble.end(), countBuf.begin(), countBuf.end());
    uint32_t count = ces::Buffer::peek<uint32_t>(countBuf.data());
    for (uint32_t i = 0; i < count; ++i) {
      ces::Bytes header;
      if (!impl_->base.readExact(header, sizeof(uint64_t) + sizeof(uint16_t)))
        return false;
      preamble.insert(preamble.end(), header.begin(), header.end());
      uint16_t nameLen = ces::Buffer::peek<uint16_t>(header.data() + 8);
      ces::Bytes nameBuf;
      if (nameLen > 0) {
        if (!impl_->base.readExact(nameBuf, nameLen)) return false;
        preamble.insert(preamble.end(), nameBuf.begin(), nameBuf.end());
      }
      // Per-entry trailer: startedAtUs | fileBalance | cpuBp | rssBytes.
      ces::Bytes tail;
      if (!impl_->base.readExact(tail, sizeof(uint64_t) + sizeof(uint64_t)
                                          + sizeof(uint32_t) + sizeof(uint64_t)))
        return false;
      preamble.insert(preamble.end(), tail.begin(), tail.end());

      InstanceInfo info;
      info.instanceId     = ces::Buffer::peek<uint64_t>(header.data());
      info.sourceName.assign(nameBuf.begin(), nameBuf.end());
      info.startedAtUs    = ces::Buffer::peek<uint64_t>(tail.data());
      info.fileBalance    = ces::Buffer::peek<uint64_t>(tail.data() + 8);
      info.cpuBasisPoints = ces::Buffer::peek<uint32_t>(tail.data() + 16);
      info.rssBytes       = ces::Buffer::peek<uint64_t>(tail.data() + 20);
      out.push_back(std::move(info));
    }
    return true;
  };

  ces::Bytes resp;
  uint8_t rc = impl_->base.driveVerb(kVerbList, env, /*fixedPre=*/0,
                                     readVariable, resp);
  if (rc != CES_OK) out.clear();
  return rc;
}

uint8_t CesComputeClient::stat(uint64_t instanceId, InstanceInfo& out) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint64_t>(pre, instanceId);
  auto env = impl_->base.buildEnvelope(kVerbStat, pre);

  out = InstanceInfo{};
  auto reader = [this, &out](ces::Bytes& preamble) -> bool {
    return statVariableReader(impl_->base, out, preamble) == CES_OK;
  };
  ces::Bytes resp;
  return impl_->base.driveVerb(kVerbStat, env, /*fixedPre=*/36, reader, resp);
}

uint8_t CesComputeClient::instances(const std::string& path,
                                    std::vector<uint64_t>& out) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(path.size()));
  pre.insert(pre.end(), path.begin(), path.end());
  auto env = impl_->base.buildEnvelope(kVerbInstances, pre);

  out.clear();
  // Variable preamble: read u32 count, then count × u64 ids.
  auto reader = [this, &out](ces::Bytes& preamble) -> bool {
    ces::Bytes countBuf;
    if (!impl_->base.readExact(countBuf, 4)) return false;
    preamble.insert(preamble.end(), countBuf.begin(), countBuf.end());
    uint32_t count = ces::Buffer::peek<uint32_t>(countBuf.data());
    out.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
      ces::Bytes idBuf;
      if (!impl_->base.readExact(idBuf, 8)) return false;
      preamble.insert(preamble.end(), idBuf.begin(), idBuf.end());
      out.push_back(ces::Buffer::peek<uint64_t>(idBuf.data()));
    }
    return true;
  };
  ces::Bytes resp;
  uint8_t rc = impl_->base.driveVerb(kVerbInstances, env, /*fixedPre=*/0,
                                     reader, resp);
  if (rc != CES_OK) out.clear();
  return rc;
}

} // namespace ces
