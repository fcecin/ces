// compute_client.cpp - implementation of CesComputeClient.
//
// Blocking client for builtin:compute. Mirrors file_client.cpp's Impl
// structure (MINX socket + Rudp + io_contexts + threads); the only
// divergences are the protocol name, verb set, and response shapes.
// The Impl plumbing (connect/stop/select/readAndVerifyTail/writeAll/
// readExact) is duplicated between the two clients.

#include <ces/l2/compute_client.h>
#include <ces/buffer.h>
#include <ces/ramfilestore.h> // ces::sha256
#include <ces/l2/net_envelope.h>
#include <ces/types.h>

#include <minx/blog.h>
#include <minx/minx.h>
#include <minx/rudp/rudp.h>
#include <minx/rudp/rudp_stream.h>
#include <minx/stdext.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/address.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <future>
#include <memory>
#include <random>
#include <span>
#include <thread>
#include <vector>

LOG_MODULE("ccc");

namespace ces {

namespace {

constexpr uint8_t kVerbLaunch    = 0x01;
constexpr uint8_t kVerbKill      = 0x02;
constexpr uint8_t kVerbList      = 0x03;
constexpr uint8_t kVerbStat      = 0x04;
constexpr uint8_t kVerbInstances = 0x05;

constexpr const char* kComputeProto = "/ces/compute/1";

constexpr auto kVerbTimeout    = std::chrono::seconds(30);
constexpr auto kConnectTimeout = std::chrono::seconds(10);

// All BE serialization goes through ces::Buffer (see ces/buffer.h).

uint64_t nowMicros() {
  return static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count());
}

// Per-op envelope is just a sig over sha256(verb||preamble||sessionToken).
// Pubkey + timestamp are not on the wire; both are implicit in the
// channel binding.
minx::Bytes buildSignedEnvelope(
    const KeyPair& signer, uint8_t verb,
    std::span<const uint8_t> preamble,
    uint64_t sessionToken) {
  Signature sig = ces::signPerOp(signer, verb, preamble, sessionToken);

  // [u32 len][preamble][65 sig]
  const size_t total = 4 + preamble.size() + ces::CES_PLEX_SIG_SIZE;
  minx::Bytes wire(total);
  minx::Buffer buf(wire);
  buf.put<uint32_t>(static_cast<uint32_t>(preamble.size()));
  buf.put(preamble);
  buf.put(sig);
  return wire;
}

class NoopMinxListener : public minx::MinxListener {};

// Outbound-only Rudp::Listener: forwards onSend to the local Minx,
// rejects any inbound HS_OPEN.
class ComputeClientRudpListener : public minx::Rudp::Listener {
public:
  void setMinx(minx::Minx* m) { minx_ = m; }
  void onSend(const minx::SockAddr& peer,
              const minx::Bytes& bytes) override {
    if (!minx_) return;
    try {
      minx_->sendExtension(peer, bytes);
    } catch (const std::exception&) {
      // Socket already closed during teardown.
    }
  }
private:
  minx::Minx* minx_ = nullptr;
};

} // namespace

class CesComputeClient::Impl {
public:
  Impl() : listener_(std::make_unique<NoopMinxListener>()) {}
  ~Impl() { stop(); }

  uint8_t connect(const std::string& host, uint16_t rpcPort,
                   const KeyPair& signerKey) {
    signerKey_ = std::make_unique<KeyPair>(signerKey);
    boost::system::error_code ec;
    boost::asio::io_context ioc;
    boost::asio::ip::udp::resolver res(ioc);
    boost::asio::ip::address addr;
    auto results = res.resolve(host, std::to_string(rpcPort), ec);
    if (ec || results.empty()) {
      LOGERROR << "ccc: resolve failed"
               << SVAR(host) << SVAR(ec.message());
      return CES_ERROR_INTERNAL;
    }
    addr = results.begin()->endpoint().address();
    if (addr.is_v4()) {
      addr = boost::asio::ip::make_address_v6(
        boost::asio::ip::v4_mapped, addr.to_v4());
    }
    peer_ = minx::SockAddr(addr, rpcPort);

    minx::MinxConfig mc{};
    mc.instanceName = "ccc";
    mc.randomXVMsToKeep = 0;
    mc.randomXInitThreads = 0;
    mc.trustLoopback = true;
    minx_ = std::make_unique<minx::Minx>(listener_.get(), mc);

    minx::RudpConfig rcfg{};
    rcfg.maxChannelsPerPeer = 8;
    rcfg.baseTickInterval = std::chrono::milliseconds(1);
    rudpListener_.setMinx(minx_.get());
    rudp_ = std::make_unique<minx::Rudp>(&rudpListener_, rcfg);

    {
      minx::MinxStdExtensions stdExt;
      stdExt.registerExtension(
        minx::Rudp::KEY_V0,
        [this](const minx::SockAddr& p, uint64_t key,
               const minx::Bytes& payload) {
          if (rudp_) rudp_->onPacket(p, key, payload, nowMicros());
        });
      minx_->setExtensionHandler(std::move(stdExt).build());
    }

    boundPort_ = minx_->openSocket(
      boost::asio::ip::address_v6::any(), 0, netIO_, taskIO_);
    if (boundPort_ == 0) {
      LOGERROR << "ccc: failed to open local UDP socket";
      return CES_ERROR_INTERNAL;
    }

    netGuard_ = std::make_unique<WorkGuard>(netIO_.get_executor());
    taskGuard_ = std::make_unique<WorkGuard>(taskIO_.get_executor());
    netThread_ = std::thread([this]() { netIO_.run(); });
    taskThread_ = std::thread([this]() { taskIO_.run(); });

    tickTimer_ = std::make_shared<boost::asio::steady_timer>(taskIO_);
    boost::asio::post(taskIO_, [this]() { scheduleTick(); });

    std::mt19937 rng(std::random_device{}());
    channel_ = 0;
    while (channel_ == 0) channel_ = rng();

    return doSelect();
  }

  void stop() {
    if (!minx_) return;
    if (tickTimer_) {
      boost::system::error_code ec;
      tickTimer_->cancel(ec);
    }
    minx_->closeSocket(false);
    if (netGuard_) netGuard_->reset();
    if (taskGuard_) taskGuard_->reset();
    netIO_.stop();
    taskIO_.stop();
    if (netThread_.joinable()) netThread_.join();
    if (taskThread_.joinable()) taskThread_.join();
    stream_.reset();
    tickTimer_.reset();
    rudp_.reset();
    minx_.reset();
    rudpListener_.setMinx(nullptr);
    netGuard_.reset();
    taskGuard_.reset();
    boundPort_ = 0;
  }

  void setServerPubkey(const minx::Hash& pk) {
    serverPk_ = pk;
    hasServerPk_ = true;
  }

  uint8_t reselect() {
    stream_.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    std::mt19937 rng(std::random_device{}());
    channel_ = 0;
    while (channel_ == 0) channel_ = rng();
    return doSelect();
  }

  void markDirty() { streamDirty_ = true; }

  uint8_t ensureClean() {
    if (!streamDirty_) return CES_OK;
    streamDirty_ = false;
    return reselect();
  }

  bool readAndVerifyTail(uint8_t status, uint8_t verb,
                         const ces::Bytes& preamble) {
    if (!stream_) return false;
    std::array<uint8_t, ces::CES_PLEX_RESP_TRAILER_SIZE> tail{};
    auto run = std::make_shared<std::promise<bool>>();
    auto fut = run->get_future();
    auto strm = stream_;
    boost::asio::post(taskIO_, [strm, &tail, run]() mutable {
      boost::asio::async_read(
        *strm, boost::asio::buffer(tail),
        [run](const boost::system::error_code& ec, std::size_t) {
          run->set_value(!ec);
        });
    });
    if (fut.wait_for(kVerbTimeout) != std::future_status::ready) return false;
    if (!fut.get()) return false;

    uint64_t timeUs = ces::Buffer::peek<uint64_t>(tail.data());
    // Response trailer layout: [u64 time_us][u64 req_sig_hash]
    //   [sha256 digest][sig]. Offsets accumulate those field sizes.
    constexpr size_t kReqSigHashOff = ces::CES_PLEX_TIME_US_SIZE;
    constexpr size_t kDigestOff =
        kReqSigHashOff + ces::CES_PLEX_REQ_SIG_HASH_SIZE;
    constexpr size_t kSigOff = kDigestOff + ces::CES_PLEX_SHA256_SIZE;

    std::array<uint8_t, ces::CES_PLEX_REQ_SIG_HASH_SIZE> reqSigHash{};
    std::memcpy(reqSigHash.data(), tail.data() + kReqSigHashOff,
                reqSigHash.size());
    std::array<uint8_t, ces::CES_PLEX_SHA256_SIZE> claimedHash{};
    std::memcpy(claimedHash.data(), tail.data() + kDigestOff,
                claimedHash.size());
    Signature sig{};
    std::memcpy(sig.data(), tail.data() + kSigOff, sig.size());

    ces::Buffer hashIn(ces::CES_PLEX_STATUS_SIZE + ces::CES_PLEX_VERB_SIZE
                       + preamble.size() + ces::CES_PLEX_TIME_US_SIZE
                       + ces::CES_PLEX_REQ_SIG_HASH_SIZE);
    hashIn.put<uint8_t>(status)
          .put<uint8_t>(verb)
          .putBytes(std::span<const uint8_t>(preamble))
          .put<uint64_t>(timeUs)
          .putBytes(std::span<const uint8_t>(
            reqSigHash.data(), reqSigHash.size()));
    minx::Hash computed = ces::sha256(hashIn.data(), hashIn.size());

    if (std::memcmp(computed.data(), claimedHash.data(),
                    claimedHash.size()) != 0) {
      LOGERROR << "ccc: response hash mismatch";
      return true;
    }
    if (!hasServerPk_) {
      LOGERROR << "ccc: server pubkey not set; response sig unverified";
      return true;
    }
    PublicKey pk(serverPk_);
    if (!pk.verifySignature(
          std::span<const uint8_t>(computed.data(), computed.size()), sig)) {
      LOGERROR << "ccc: response sig verification FAILED";
    }
    return true;
  }

  bool writeAll(const minx::Bytes& bytes) {
    if (!stream_) return false;
    auto run = std::make_shared<std::promise<bool>>();
    auto fut = run->get_future();
    auto strm = stream_;
    auto buf = std::make_shared<minx::Bytes>(bytes);
    boost::asio::post(taskIO_, [strm, buf, run]() mutable {
      boost::asio::async_write(
        *strm, boost::asio::buffer(*buf),
        [run, buf](const boost::system::error_code& ec, std::size_t) {
          run->set_value(!ec);
        });
    });
    return fut.get();
  }
  bool writeAll(const ces::Bytes& bytes) {
    if (!stream_) return false;
    auto run = std::make_shared<std::promise<bool>>();
    auto fut = run->get_future();
    auto strm = stream_;
    auto buf = std::make_shared<ces::Bytes>(bytes);
    boost::asio::post(taskIO_, [strm, buf, run]() mutable {
      boost::asio::async_write(
        *strm, boost::asio::buffer(*buf),
        [run, buf](const boost::system::error_code& ec, std::size_t) {
          run->set_value(!ec);
        });
    });
    if (fut.wait_for(kVerbTimeout) != std::future_status::ready) return false;
    return fut.get();
  }

  bool readExact(ces::Bytes& out, size_t n) {
    if (!stream_) return false;
    out.resize(n);
    auto run = std::make_shared<std::promise<bool>>();
    auto fut = run->get_future();
    auto strm = stream_;
    boost::asio::post(taskIO_,
      [strm, &out, run]() mutable {
        boost::asio::async_read(
          *strm, boost::asio::buffer(out),
          [run](const boost::system::error_code& ec, std::size_t) {
            run->set_value(!ec);
          });
      });
    if (fut.wait_for(kVerbTimeout) != std::future_status::ready) return false;
    return fut.get();
  }

private:
  using WorkGuard = boost::asio::executor_work_guard<
    boost::asio::io_context::executor_type>;

  void scheduleTick() {
    if (!tickTimer_ || !rudp_) return;
    tickTimer_->expires_after(std::chrono::milliseconds(10));
    tickTimer_->async_wait(
      [this](const boost::system::error_code& ec) {
        if (ec || !rudp_) return;
        rudp_->tick(nowMicros());
        scheduleTick();
      });
  }

  // Parse + verify the signed bind reply. Same shape as the file
  // client: self-consistency sig check, clientSha256 match, TOFU /
  // expected pubkey check, status==OK. Stashes boundSessionToken_.
  uint8_t parseBindReply(
      const std::array<uint8_t, ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE>& buf,
      const std::array<uint8_t, ces::CES_PLEX_SHA256_SIZE>& clientDigest) {
    auto r = ces::parseBindReply(
      std::span<const uint8_t, ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE>(
        buf.data(), buf.size()));
    if (r.status != ces::CES_PLEX_OK) return CES_ERROR_PROTO_REJECTED;
    if (!ces::verifyBindReply(
          r,
          std::span<const uint8_t>(clientDigest.data(), clientDigest.size()))) {
      LOGERROR << "ccc: bind reply digest/sig verify FAILED";
      return CES_ERROR_INTERNAL;
    }
    if (hasServerPk_) {
      if (std::memcmp(serverPk_.data(), r.serverPubkey.data(),
                      serverPk_.size()) != 0) {
        LOGERROR << "ccc: bind reply pubkey ≠ expected";
        return CES_ERROR_INTERNAL;
      }
    } else {
      std::memcpy(serverPk_.data(), r.serverPubkey.data(), serverPk_.size());
      hasServerPk_ = true;
    }
    boundSessionToken_ = r.channelSessionToken;
    return CES_OK;
  }

  uint8_t doSelect() {
    auto run = std::make_shared<std::promise<uint8_t>>();
    auto fut = run->get_future();
    boost::asio::post(taskIO_, [this, run]() {
      rudp_->tick(nowMicros());
      stream_ = std::make_shared<minx::RudpStream>(
        taskIO_.get_executor());
      if (!rudp_->registerChannel(peer_, channel_, stream_)) {
        run->set_value(CES_ERROR_INTERNAL);
        return;
      }

      const uint64_t bindNowUs = nowMicros();
      auto bindReq = std::make_shared<minx::Bytes>(
        ces::buildBindRequest(kComputeProto, bindNowUs, *signerKey_));
      const auto& pkArr = signerKey_->getPublicKeyAsHash();
      auto clientDigest = std::make_shared<
        std::array<uint8_t, ces::CES_PLEX_SHA256_SIZE>>(
          ces::computeBindRequestDigest(
            std::span<const uint8_t>(
              reinterpret_cast<const uint8_t*>(kComputeProto),
              std::strlen(kComputeProto)),
            bindNowUs,
            std::span<const uint8_t>(pkArr.data(), pkArr.size())));

      boost::asio::async_write(
        *stream_, boost::asio::buffer(*bindReq),
        [this, bindReq, clientDigest, run]
        (const boost::system::error_code& ec, std::size_t) {
          if (ec) { run->set_value(CES_ERROR_INTERNAL); return; }
          auto reply = std::make_shared<
            std::array<uint8_t, ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE>>();
          boost::asio::async_read(
            *stream_, boost::asio::buffer(*reply),
            [this, reply, clientDigest, run]
            (const boost::system::error_code& ec2, std::size_t) {
              if (ec2) { run->set_value(CES_ERROR_INTERNAL); return; }
              run->set_value(parseBindReply(*reply, *clientDigest));
            });
        });
    });
    if (fut.wait_for(kConnectTimeout) != std::future_status::ready) {
      LOGERROR << "ccc: bind handshake timed out";
      return CES_ERROR_INTERNAL;
    }
    uint8_t rc = fut.get();
    LOGDEBUG << "ccc: bind complete" << VAR(int(rc)) << VAR(channel_);
    return rc;
  }

public:
  // For per-op signing: bound channel state established by doSelect.
  const KeyPair& signerKey() const { return *signerKey_; }
  uint64_t boundSessionToken() const { return boundSessionToken_; }

private:
  std::unique_ptr<NoopMinxListener> listener_;
  ComputeClientRudpListener rudpListener_;
  std::unique_ptr<minx::Minx> minx_;
  std::unique_ptr<minx::Rudp> rudp_;
  boost::asio::io_context netIO_;
  boost::asio::io_context taskIO_;
  std::unique_ptr<WorkGuard> netGuard_;
  std::unique_ptr<WorkGuard> taskGuard_;
  std::thread netThread_;
  std::thread taskThread_;
  std::shared_ptr<boost::asio::steady_timer> tickTimer_;
  uint16_t boundPort_ = 0;

  minx::SockAddr peer_;
  uint32_t channel_ = 0;
  std::shared_ptr<minx::RudpStream> stream_;

  bool hasServerPk_ = false;
  minx::Hash serverPk_{};

  std::unique_ptr<KeyPair> signerKey_;
  uint64_t boundSessionToken_ = 0;

  bool streamDirty_ = false;
};

namespace {

// Core verb-drive helper. Reads status, fixed preamble, optional
// variable preamble, then the server-signed tail.
uint8_t driveVerb(
    CesComputeClient::Impl& impl,
    uint8_t verb,
    const minx::Bytes& envelope,
    size_t respFixedPreambleLen,
    const std::function<bool(ces::Bytes& preamble)>&
      readVariablePreamble,
    ces::Bytes& outPreamble) {
  if (impl.ensureClean() != CES_OK) return CES_ERROR_INTERNAL;

  auto fail = [&](uint8_t rc) -> uint8_t {
    impl.markDirty();
    return rc;
  };

  ces::Bytes verbByte{verb};
  if (!impl.writeAll(verbByte)) return fail(CES_ERROR_INTERNAL);
  if (!impl.writeAll(envelope)) return fail(CES_ERROR_INTERNAL);

  ces::Bytes statusBuf;
  if (!impl.readExact(statusBuf, 1)) return fail(CES_ERROR_INTERNAL);
  uint8_t status = statusBuf[0];

  outPreamble.clear();
  if (status == CES_OK) {
    if (respFixedPreambleLen > 0 &&
        !impl.readExact(outPreamble, respFixedPreambleLen))
      return fail(CES_ERROR_INTERNAL);
    if (readVariablePreamble && !readVariablePreamble(outPreamble))
      return fail(CES_ERROR_INTERNAL);
  }

  if (!impl.readAndVerifyTail(status, verb, outPreamble))
    return fail(CES_ERROR_INTERNAL);

  return status;
}

} // namespace

CesComputeClient::CesComputeClient() : impl_(std::make_unique<Impl>()) {}
CesComputeClient::~CesComputeClient() = default;

uint8_t CesComputeClient::connect(const std::string& host, uint16_t rpcPort, const KeyPair& signerKey) {
  return impl_->connect(host, rpcPort, signerKey);
}

void CesComputeClient::disconnect() { impl_->stop(); }

void CesComputeClient::setServerPubkey(const minx::Hash& pk) {
  impl_->setServerPubkey(pk);
}

uint8_t CesComputeClient::launch(const std::string& name,
                                 uint64_t& outInstanceId,
                                 uint64_t& outStartedAtUs) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(name.size()));
  pre.insert(pre.end(), name.begin(), name.end());
  auto env = buildSignedEnvelope(impl_->signerKey(), kVerbLaunch, pre, impl_->boundSessionToken());

  ces::Bytes resp;
  uint8_t rc = driveVerb(*impl_, kVerbLaunch, env,
                         /*fixedPre=*/16, nullptr, resp);
  if (rc != CES_OK) return rc;
  outInstanceId   = ces::Buffer::peek<uint64_t>(resp.data());
  outStartedAtUs  = ces::Buffer::peek<uint64_t>(resp.data() + 8);
  return CES_OK;
}

uint8_t CesComputeClient::kill(uint64_t instanceId) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint64_t>(pre, instanceId);
  auto env = buildSignedEnvelope(impl_->signerKey(), kVerbKill, pre, impl_->boundSessionToken());

  ces::Bytes resp;
  return driveVerb(*impl_, kVerbKill, env,
                   /*fixedPre=*/0, nullptr, resp);
}

uint8_t CesComputeClient::list(std::vector<InstanceInfo>& out) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  auto env = buildSignedEnvelope(impl_->signerKey(), kVerbList, pre, impl_->boundSessionToken());

  out.clear();
  // Variable preamble: read u32 count first, then count × entries.
  auto readVariable = [&](ces::Bytes& preamble) -> bool {
    ces::Bytes countBuf;
    if (!impl_->readExact(countBuf, 4)) return false;
    preamble.insert(preamble.end(), countBuf.begin(), countBuf.end());
    uint32_t count = ces::Buffer::peek<uint32_t>(countBuf.data());
    for (uint32_t i = 0; i < count; ++i) {
      ces::Bytes header;
      if (!impl_->readExact(header, sizeof(uint64_t) + sizeof(uint16_t)))
        return false;
      preamble.insert(preamble.end(), header.begin(), header.end());
      uint16_t nameLen = ces::Buffer::peek<uint16_t>(header.data() + 8);
      ces::Bytes nameBuf;
      if (nameLen > 0) {
        if (!impl_->readExact(nameBuf, nameLen)) return false;
        preamble.insert(preamble.end(), nameBuf.begin(), nameBuf.end());
      }
      // Per-entry trailer: startedAtUs | fileBalance | cpuBp | rssBytes.
      ces::Bytes tail;
      if (!impl_->readExact(tail, sizeof(uint64_t) + sizeof(uint64_t)
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
  uint8_t rc = driveVerb(*impl_, kVerbList, env,
                         /*fixedPre=*/0, readVariable, resp);
  if (rc != CES_OK) out.clear();
  return rc;
}

static uint8_t statVariableReader(CesComputeClient::Impl& impl,
                                   CesComputeClient::InstanceInfo& out,
                                   ces::Bytes& preamble) {
  // After the fixed header (8+8+8 + 4+8 = 36) we already have
  //   id | started_at | file_balance | cpu_bp | rss_bytes
  // Then u16 name_len + name.
  ces::Bytes lenBuf;
  if (!impl.readExact(lenBuf, 2)) return CES_ERROR_INTERNAL;
  preamble.insert(preamble.end(), lenBuf.begin(), lenBuf.end());
  uint16_t nameLen = ces::Buffer::peek<uint16_t>(lenBuf.data());
  ces::Bytes nameBuf;
  if (nameLen > 0) {
    if (!impl.readExact(nameBuf, nameLen)) return CES_ERROR_INTERNAL;
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

uint8_t CesComputeClient::stat(uint64_t instanceId,
                               InstanceInfo& out) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint64_t>(pre, instanceId);
  auto env = buildSignedEnvelope(impl_->signerKey(), kVerbStat, pre, impl_->boundSessionToken());

  out = InstanceInfo{};
  auto reader = [this, &out](ces::Bytes& preamble) -> bool {
    return statVariableReader(*impl_, out, preamble) == CES_OK;
  };
  ces::Bytes resp;
  return driveVerb(*impl_, kVerbStat, env,
                   /*fixedPre=*/36, reader, resp);
}

uint8_t CesComputeClient::instances(const std::string& path,
                                    std::vector<uint64_t>& out) {
  ces::Bytes pre;
  ces::Buffer::put<uint32_t>(pre, CES_NONCELESS);
  ces::Buffer::put<uint16_t>(pre, static_cast<uint16_t>(path.size()));
  pre.insert(pre.end(), path.begin(), path.end());
  auto env = buildSignedEnvelope(impl_->signerKey(), kVerbInstances, pre,
                                 impl_->boundSessionToken());

  out.clear();
  // Variable preamble: read u32 count, then count × u64 ids.
  auto reader = [this, &out](ces::Bytes& preamble) -> bool {
    ces::Bytes countBuf;
    if (!impl_->readExact(countBuf, 4)) return false;
    preamble.insert(preamble.end(), countBuf.begin(), countBuf.end());
    uint32_t count = ces::Buffer::peek<uint32_t>(countBuf.data());
    out.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
      ces::Bytes idBuf;
      if (!impl_->readExact(idBuf, 8)) return false;
      preamble.insert(preamble.end(), idBuf.begin(), idBuf.end());
      out.push_back(ces::Buffer::peek<uint64_t>(idBuf.data()));
    }
    return true;
  };
  ces::Bytes resp;
  uint8_t rc = driveVerb(*impl_, kVerbInstances, env,
                         /*fixedPre=*/0, reader, resp);
  if (rc != CES_OK) out.clear();
  return rc;
}

} // namespace ces
