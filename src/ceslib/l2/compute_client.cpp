// compute_client.cpp - CesComputeClient.
//
// A thin verb layer over a CesPlexChannel (see cesplex/session.h) — the
// shared CesPlex client protocol. Each method is just the verb's preamble
// building + response parsing; the channel drives the wire on whatever
// transport it was handed (connect() = owned socket, attach() = external).

#include <ces/l2/compute_client.h>
#include <ces/cesplex/session.h>
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

// Parse a STAT response preamble: after the 40-byte fixed header
// (id | started_at | file_balance | cpu_bp | rss_bytes | client_port |
// rpc_port) comes u16 name_len + name. Pulls the variable tail off the
// channel.
uint8_t statVariableReader(CesPlexChannel& chan,
                           CesComputeClient::InstanceInfo& out,
                           ces::Bytes& preamble) {
  ces::Bytes lenBuf;
  if (!chan.readExact(lenBuf, 2)) return CES_ERROR_INTERNAL;
  preamble.insert(preamble.end(), lenBuf.begin(), lenBuf.end());
  uint16_t nameLen = ces::Buffer::peek<uint16_t>(lenBuf.data());
  ces::Bytes nameBuf;
  if (nameLen > 0) {
    if (!chan.readExact(nameBuf, nameLen)) return CES_ERROR_INTERNAL;
    preamble.insert(preamble.end(), nameBuf.begin(), nameBuf.end());
  }
  out.instanceId     = ces::Buffer::peek<uint64_t>(preamble.data());
  out.startedAtUs    = ces::Buffer::peek<uint64_t>(preamble.data() + 8);
  out.fileBalance    = ces::Buffer::peek<uint64_t>(preamble.data() + 16);
  out.cpuBasisPoints = ces::Buffer::peek<uint32_t>(preamble.data() + 24);
  out.rssBytes       = ces::Buffer::peek<uint64_t>(preamble.data() + 28);
  out.clientPort     = ces::Buffer::peek<uint16_t>(preamble.data() + 36);
  out.rpcPort        = ces::Buffer::peek<uint16_t>(preamble.data() + 38);
  out.sourceName.assign(nameBuf.begin(), nameBuf.end());
  return CES_OK;
}

} // namespace

class CesComputeClient::Impl {
public:
  // See CesFileClient::Impl: `owned` drives connect(); in attach() mode
  // `chan` points at a channel the caller owns. The verb codec rides `chan`.
  CesPlexClient owned;
  CesPlexChannel* chan = nullptr;
};

CesComputeClient::CesComputeClient() : impl_(std::make_unique<Impl>()) {}
CesComputeClient::~CesComputeClient() = default;

uint8_t CesComputeClient::connect(const std::string& host, uint16_t rpcPort,
                                  const KeyPair& signerKey) {
  uint8_t rc = impl_->owned.connect(host, rpcPort, kComputeProto, signerKey);
  if (rc == CES_OK) impl_->chan = impl_->owned.channel();
  return rc;
}

// Drive verbs over a channel the caller owns + has already select()ed.
// Mutually exclusive with connect().
void CesComputeClient::attach(CesPlexChannel& channel) {
  impl_->chan = &channel;
}

void CesComputeClient::disconnect() {
  impl_->owned.disconnect();
  impl_->chan = nullptr;
}

void CesComputeClient::setServerPubkey(const minx::Hash& pk) {
  if (impl_->chan) impl_->chan->setServerPubkey(pk);
  else impl_->owned.setServerPubkey(pk);
}

uint8_t CesComputeClient::launch(const std::string& name,
                                 uint64_t& outInstanceId,
                                 uint64_t& outStartedAtUs) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = impl_->chan->buildEnvelope(kVerbLaunch, pre);

  ces::Bytes resp;
  uint8_t rc = impl_->chan->driveVerb(kVerbLaunch, env, /*fixedPre=*/16,
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
  auto env = impl_->chan->buildEnvelope(kVerbKill, pre);

  ces::Bytes resp;
  return impl_->chan->driveVerb(kVerbKill, env, /*fixedPre=*/0, nullptr, resp);
}

uint8_t CesComputeClient::list(std::vector<InstanceInfo>& out) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  auto env = impl_->chan->buildEnvelope(kVerbList, pre);

  out.clear();
  // Variable preamble: read u32 count, then count × entries.
  auto readVariable = [&](ces::Bytes& preamble) -> bool {
    ces::Bytes countBuf;
    if (!impl_->chan->readExact(countBuf, 4)) return false;
    preamble.insert(preamble.end(), countBuf.begin(), countBuf.end());
    uint32_t count = ces::Buffer::peek<uint32_t>(countBuf.data());
    for (uint32_t i = 0; i < count; ++i) {
      ces::Bytes header;
      if (!impl_->chan->readExact(header, sizeof(uint64_t) + sizeof(uint16_t)))
        return false;
      preamble.insert(preamble.end(), header.begin(), header.end());
      uint16_t nameLen = ces::Buffer::peek<uint16_t>(header.data() + 8);
      ces::Bytes nameBuf;
      if (nameLen > 0) {
        if (!impl_->chan->readExact(nameBuf, nameLen)) return false;
        preamble.insert(preamble.end(), nameBuf.begin(), nameBuf.end());
      }
      // Per-entry trailer: startedAtUs | fileBalance | cpuBp | rssBytes |
      // client_port | rpc_port.
      ces::Bytes tail;
      if (!impl_->chan->readExact(tail, sizeof(uint64_t) + sizeof(uint64_t)
                                          + sizeof(uint32_t) + sizeof(uint64_t)
                                          + sizeof(uint16_t) + sizeof(uint16_t)))
        return false;
      preamble.insert(preamble.end(), tail.begin(), tail.end());

      InstanceInfo info;
      info.instanceId     = ces::Buffer::peek<uint64_t>(header.data());
      info.sourceName.assign(nameBuf.begin(), nameBuf.end());
      info.startedAtUs    = ces::Buffer::peek<uint64_t>(tail.data());
      info.fileBalance    = ces::Buffer::peek<uint64_t>(tail.data() + 8);
      info.cpuBasisPoints = ces::Buffer::peek<uint32_t>(tail.data() + 16);
      info.rssBytes       = ces::Buffer::peek<uint64_t>(tail.data() + 20);
      info.clientPort     = ces::Buffer::peek<uint16_t>(tail.data() + 28);
      info.rpcPort        = ces::Buffer::peek<uint16_t>(tail.data() + 30);
      out.push_back(std::move(info));
    }
    return true;
  };

  ces::Bytes resp;
  uint8_t rc = impl_->chan->driveVerb(kVerbList, env, /*fixedPre=*/0,
                                     readVariable, resp);
  if (rc != CES_OK) out.clear();
  return rc;
}

uint8_t CesComputeClient::stat(uint64_t instanceId, InstanceInfo& out) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint64_t>(pre, instanceId);
  auto env = impl_->chan->buildEnvelope(kVerbStat, pre);

  out = InstanceInfo{};
  auto reader = [this, &out](ces::Bytes& preamble) -> bool {
    return statVariableReader(*impl_->chan, out, preamble) == CES_OK;
  };
  ces::Bytes resp;
  return impl_->chan->driveVerb(kVerbStat, env, /*fixedPre=*/40, reader, resp);
}

uint8_t CesComputeClient::instances(const std::string& path,
                                    std::vector<InstanceInfo>& out) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(path.size()));
  pre.insert(pre.end(), path.begin(), path.end());
  auto env = impl_->chan->buildEnvelope(kVerbInstances, pre);

  out.clear();
  // Variable preamble: read u32 count, then count × fixed 32-byte entries:
  // id | started_at | cpu_bp | rss_bytes | client_port | rpc_port.
  auto reader = [this, &out, path](ces::Bytes& preamble) -> bool {
    ces::Bytes countBuf;
    if (!impl_->chan->readExact(countBuf, 4)) return false;
    preamble.insert(preamble.end(), countBuf.begin(), countBuf.end());
    uint32_t count = ces::Buffer::peek<uint32_t>(countBuf.data());
    out.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
      ces::Bytes e;
      if (!impl_->chan->readExact(e, 32)) return false;
      preamble.insert(preamble.end(), e.begin(), e.end());
      InstanceInfo info;
      info.instanceId     = ces::Buffer::peek<uint64_t>(e.data());
      info.startedAtUs    = ces::Buffer::peek<uint64_t>(e.data() + 8);
      info.cpuBasisPoints = ces::Buffer::peek<uint32_t>(e.data() + 16);
      info.rssBytes       = ces::Buffer::peek<uint64_t>(e.data() + 20);
      info.clientPort     = ces::Buffer::peek<uint16_t>(e.data() + 28);
      info.rpcPort        = ces::Buffer::peek<uint16_t>(e.data() + 30);
      info.sourceName     = path;  // the query key, echoed for convenience
      out.push_back(std::move(info));
    }
    return true;
  };
  ces::Bytes resp;
  uint8_t rc = impl_->chan->driveVerb(kVerbInstances, env, /*fixedPre=*/0,
                                     reader, resp);
  if (rc != CES_OK) out.clear();
  return rc;
}

} // namespace ces
