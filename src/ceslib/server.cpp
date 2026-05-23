#include <ces/l2/net_multiplexer.h>
#include <ces/buffer.h>
#include <ces/l2/compute_handler.h>
#include <ces/l2/file_handler.h>
#include <ces/l2/compute_lua_handler.h>
#include <ces/cesvm.h>
#include <ces/util/ctrlc.h>
#include <ces/ramfilestore.h>
#include <ces/protocol.h>
#include <ces/server.h>
#include <ces/util/resolver.h>
#include <ces/util/vmprogram.h>
#include <ces/util/wallet.h>

#include <filesystem>
#include <fstream>
#include <future>
#include <limits>
#include <random>
#include <sstream>
#include <thread>
#include <minx/blog.h>
#include <minx/rudp/rudp.h>
#include <minx/rudp/rudp_stream.h>
#include <minx/stdext.h>
#include <toml++/toml.hpp>

#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/endian/conversion.hpp>
#include <ces/ramfilestore.h>

#include <logkv/serializer.h>
#include <logkv/autoser.h>
#include <logkv/autoser/bytes.h>
#include <logkv/autoser/associative.h>

LOG_MODULE("csv");

namespace ces {

constexpr size_t RANDOMX_VMS_TO_KEEP = 256;

// MinxConfig tuning for CesServer:
//   SPAM_SAMPLE_RATE * SPAM_THRESHOLD = ~33.5M packets/hour per /24 prefix
//   before the count-min sketch starts rejecting.
constexpr uint16_t SPAM_THRESHOLD_DISABLED = std::numeric_limits<uint16_t>::max();
constexpr uint16_t SPAM_SAMPLE_RATE = 512;

// Upper bound on `taskThreads` config value (sanity check).
constexpr int MAX_TASK_THREADS = 256;

// Cap on accounts logged at DEBUG during startup.
constexpr int BOOT_ACCOUNT_DUMP_MAX = 32;

// Refuse to delegate PoW verification when the MINX work queue exceeds this.
constexpr size_t POW_QUEUE_DELEGATE_LIMIT = 50000;

// Throttle: only refresh the cached PoW queue size every N seconds.
constexpr uint64_t POW_QUEUE_REFRESH_SECS = 3;

// PoW mining reward base: amount = (1 << (difficulty - 1)) * POW_REWARD_BASE.
constexpr uint64_t POW_REWARD_BASE = 1000;

// Reply retransmission schedule (UDP loss recovery on server -> client).
// Each delay is relative to the previous retransmission, not the original send.
constexpr int REPLY_FAST_DELAY_MS      = 250;  // first retransmit after initial
constexpr int REPLY_SLOW_DELAY_MS      = 1750; // second retransmit after first
constexpr int REPLY_TIMER_INITIAL_MS   = 50;   // startup tick
constexpr int REPLY_TIMER_TICK_MS      = 20;   // steady-state tick

// Daily maintenance timer: fires at 09:00 UTC every day.
constexpr uint64_t SECS_PER_DAY              = 86400;
constexpr uint64_t DAILY_MAINTENANCE_HOUR_UTC = 9;

// Peer miner policy: skip peers whose minimum difficulty exceeds our own
// minDifficulty by more than MARGIN, or whose absolute difficulty exceeds MAX.
constexpr uint8_t PEER_MINER_DIFF_MARGIN = 6;
constexpr uint8_t PEER_MINER_DIFF_MAX    = 24;

constexpr const char* ACCOUNTS_DATA_SUBDIRECTORY = "accounts";
constexpr const char* ASSETS_DATA_SUBDIRECTORY = "assets";

// Shared write-auth check for VM host callbacks.
// - Asset-owned assets: only the executing boot asset itself can write.
// - Account-owned assets: runner or program owner can write.
// Returns CES_OK or CES_ERROR_NOT_OWNER.
static inline uint8_t checkAssetWriteAuth(const Asset& asset,
                                           const HashPrefix& caller,
                                           const HashPrefix& programOwner,
                                           const minx::Hash& selfAssetKey) {
  // IMMUTABLE seals content; no caller (not even owner) may rewrite.
  if (isAssetImmutable(asset.getBalance()))
    return CES_ERROR_IMMUTABLE;
  const auto& owner = asset.getOwnerId();
  if (isAssetOwned(asset.getBalance())) {
    if (owner != Account::getMapKey(selfAssetKey))
      return CES_ERROR_NOT_OWNER;
  } else {
    if (owner != caller && owner != programOwner)
      return CES_ERROR_NOT_OWNER;
  }
  return CES_OK;
}

// ===========================================================================
// SYS_RPC dispatcher — helpers + RpcSession class
// ===========================================================================
//
// Defined here (above the CesServer constructor / start / stop)
// alongside the three-stage dispatcher trio (queueRpc / executeRpc /
// completeRpc, further down in the file). Each RpcSession owns a
// RudpStream that IS the per-channel handler — RUDP routes inbound
// bytes into the stream directly via the new ChannelHandler API, so
// the server's listener has nothing to demux at receive time.

namespace {

// Walk a cesh file chain via the server's asset store (no client
// round trip), returning `header.fileSize` bytes of payload. Pure
// read, runs on the logic strand. Returns CES_OK with outBytes
// populated, or an error code.
uint8_t readFileChunkBytes(Assets::AssetStore& store,
                            const minx::Hash& headKey,
                            ces::Bytes& outBytes,
                            size_t maxBytes = std::numeric_limits<size_t>::max()) {
  auto it = store.find(headKey);
  if (it == store.end()) return CES_ERROR_ASSET_NOT_FOUND;
  AssetData headContent = it->second.getContent();
  RamfileHeader header = parseRamfileHeader(headContent);
  if (!header.valid) return CES_ERROR_INTERNAL;
  // Enforce the caller's cap BEFORE reserve() — a hostile file header
  // with fileSize = 4 GiB would otherwise trigger that allocation.
  if (header.fileSize > maxBytes) return CES_ERROR_INSUFFICIENT_PAYMENT;
  if (header.fileSize == 0) { outBytes.clear(); return CES_OK; }
  outBytes.clear();
  outBytes.reserve(header.fileSize);
  minx::Hash nextKey = header.firstChunk;
  uint64_t remaining = header.fileSize;
  while (remaining > 0) {
    bool zero = true;
    for (auto b : nextKey) if (b) { zero = false; break; }
    if (zero) break;
    auto chunkIt = store.find(nextKey);
    if (chunkIt == store.end()) return CES_ERROR_INTERNAL;
    AssetData chunkContent = chunkIt->second.getContent();
    size_t take = std::min<size_t>(
      remaining, static_cast<size_t>(RAMFILE_CHUNK_DATA_SIZE));
    outBytes.insert(outBytes.end(),
                    chunkContent.begin(),
                    chunkContent.begin() + take);
    remaining -= take;
    std::memcpy(nextKey.data(), &chunkContent[RAMFILE_NEXT_OFFSET],
                RAMFILE_NEXT_SIZE);
  }
  return CES_OK;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// RpcSession: one outbound SYS_RPC call in flight
// ---------------------------------------------------------------------------

class CesServer::RpcSession
    : public std::enable_shared_from_this<CesServer::RpcSession> {
public:
  using Callback = std::function<void(uint8_t errorCode,
                                       ces::Bytes responseBody)>;

  RpcSession(boost::asio::io_context& io,
             minx::Rudp& rudp,
             const minx::SockAddr& peer,
             uint32_t channelId,
             ces::Bytes requestBody,
             uint32_t responseTimeoutMs,
             size_t maxResponseBytes,
             NetworkBilling* netBilling,
             const ces::KeyPair& serverKey,
             Callback cb)
    : io_(io),
      rudp_(rudp),
      peer_(peer),
      channelId_(channelId),
      stream_(std::make_shared<minx::RudpStream>(io.get_executor())),
      requestBody_(std::move(requestBody)),
      responseTimeoutMs_(responseTimeoutMs),
      maxResponseBytes_(maxResponseBytes),
      netBilling_(netBilling),
      serverKey_(serverKey),
      cb_(std::move(cb)),
      timeoutTimer_(io) {}

  // Kick off the request/response exchange. Must be called on
  // rpcTaskIO_ after the session is registered in rpcSessions_.
  //
  // Wire sequence:
  //
  //   1. Send CesPlex select header: [u16 BE 11]["/ces/rpc/1"]
  //      This commits the channel to the "rpc" protocol via CesPlex's
  //      multiplexer, so a single secondary port can carry multiple
  //      protocols. (See include/ces/l2/net_multiplexer.h for the mux
  //      wire format.)
  //
  //   2. Read back one status byte:
  //        0x01 = OK    -> proceed to step 3
  //        0x00 = NACK  -> fail with CES_ERROR_PROTO_REJECTED
  //      NACK means the target doesn't mount /ces/rpc/1. CES servers
  //      don't mount it by default — rpc is an outbound-only capability
  //      on CES. Content-server binaries and the test MockRpcServer do.
  //
  //   3. Write the signed envelope.
  //   4. Read [u32 BE len][body] response.
  //
  // Costs one extra RTT (steps 1-2) for a uniform L2 bus where every
  // protocol on the secondary port, including rpc, is gated by the same
  // select handshake.
  void start() {
    // Seed Rudp's clock before registerChannel — registerChannel
    // stamps the channel's lastActivityUs from currentTimeUs_,
    // which is zero until the first tick(). The next tick() would
    // then jump the clock and idle-GC the fresh channel.
    rudp_.tick(getMicrosSinceEpoch());
    // Bind the stream to the channel — RUDP starts the handshake on
    // the next pulse and routes per-channel events into the stream
    // automatically. Failure means the per-peer channel cap is
    // exhausted; surface as INTERNAL.
    if (!rudp_.registerChannel(peer_, channelId_, stream_)) {
      finish(CES_ERROR_INTERNAL, {});
      return;
    }
    // NetworkBilling tracking happens AFTER the bind reply lands —
    // we need to know the bound rate schedule the remote committed
    // before we can bill against it. See trackOnBindOk().
    arm_timeout();
    write_signed_bind();
  }

  const minx::SockAddr& peer() const { return peer_; }
  uint32_t channelId() const { return channelId_; }

private:
  // Hard-coded CesPlex protocol name for the rpc protocol. Matches
  // the builtin registration on the receive side.
  static constexpr const char* kRpcProtoName = "/ces/rpc/1";

  boost::asio::io_context& io_;
  minx::Rudp& rudp_;
  minx::SockAddr peer_;
  uint32_t channelId_;
  std::shared_ptr<minx::RudpStream> stream_;
  ces::Bytes requestBody_;
  uint32_t responseTimeoutMs_;
  size_t maxResponseBytes_;
  NetworkBilling* netBilling_;
  const ces::KeyPair& serverKey_;
  Callback cb_;
  boost::asio::steady_timer timeoutTimer_;
  // Wire buffers (signed bind contract).
  minx::Bytes bindReqBuf_;
  std::array<uint8_t, ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE> bindReplyBuf_{};
  std::array<uint8_t, ces::CES_PLEX_SHA256_SIZE> bindReqDigest_{};
  ces::Bytes requestWireBuf_;
  std::array<uint8_t, 4> respLenBuf_{};
  ces::Bytes respBodyBuf_;
  bool finished_ = false;

  // Send the signed bind preamble for /ces/rpc/1, signed by the
  // server's keypair (we are server-as-client here).
  void write_signed_bind() {
    const uint64_t nowUs = getMicrosSinceEpoch();
    bindReqBuf_ = ces::buildBindRequest(kRpcProtoName, nowUs, serverKey_);
    // Stash the digest so we can verify the reply binds to it.
    {
      const auto& pkArr = serverKey_.getPublicKeyAsHash();
      std::span<const uint8_t> nameSpan(
        reinterpret_cast<const uint8_t*>(kRpcProtoName),
        std::strlen(kRpcProtoName));
      bindReqDigest_ = ces::computeBindRequestDigest(
        nameSpan, nowUs,
        std::span<const uint8_t>(pkArr.data(), pkArr.size()));
    }
    auto self = shared_from_this();
    boost::asio::async_write(
      *stream_, boost::asio::buffer(bindReqBuf_),
      [self](const boost::system::error_code& ec, std::size_t) {
        if (ec) { self->finish(CES_ERROR_INTERNAL, {}); return; }
        self->read_signed_bind_reply();
      });
  }

  void read_signed_bind_reply() {
    auto self = shared_from_this();
    boost::asio::async_read(
      *stream_, boost::asio::buffer(bindReplyBuf_),
      [self](const boost::system::error_code& ec, std::size_t) {
        if (ec) { self->finish(CES_ERROR_INTERNAL, {}); return; }
        auto r = ces::parseBindReply(
          std::span<const uint8_t, ces::CES_PLEX_BIND_REPLY_TOTAL_SIZE>(
            self->bindReplyBuf_.data(), self->bindReplyBuf_.size()));
        // Reject NACK before any sig check (server may have NACKed
        // before reading our preamble; signed-NACK contract is best-
        // effort).
        if (r.status != ces::CES_PLEX_OK) {
          self->finish(CES_ERROR_PROTO_REJECTED, {});
          return;
        }
        if (!ces::verifyBindReply(
              r,
              std::span<const uint8_t>(self->bindReqDigest_.data(),
                                        self->bindReqDigest_.size()))) {
          self->finish(CES_ERROR_INTERNAL, {});
          return;
        }
        // (No expected-pubkey check in this code path — accept the
        // key the server presented; SYS_RPC callers don't pre-know
        // their target server's identity.)
        // Bind reply landed; register the outbound channel with the
        // local NetworkBilling for delta tracking. Billing uses the
        // local CesConfig rates (consistent with inbound channels)
        // and the local server's own pubkey as payer — which is the
        // bottomless server-self account, so the debit is effectively
        // observability. The remote's disclosed rates from the bind
        // reply are not enforced locally; the remote's own ledger
        // bills however it likes on its end.
        if (self->netBilling_) {
          std::ostringstream tag;
          tag << "rpc-out:" << self->peer_;
          self->netBilling_->track(
            self->peer_, self->channelId_, tag.str(),
            getHashPrefix(self->serverKey_.getPublicKeyAsHash()));
        }
        self->write_request_body();
      });
  }

  void write_request_body() {
    // Wire layout post-bind: [u32 body_len][body bytes].
    requestWireBuf_.clear();
    requestWireBuf_.reserve(4 + requestBody_.size());
    ces::Buffer::put<uint32_t>(
      requestWireBuf_, static_cast<uint32_t>(requestBody_.size()));
    ces::Buffer::putBytes(
      requestWireBuf_, std::span<const uint8_t>(requestBody_));
    auto self = shared_from_this();
    boost::asio::async_write(
      *stream_, boost::asio::buffer(requestWireBuf_),
      [self](const boost::system::error_code& ec, std::size_t) {
        if (ec) { self->finish(CES_ERROR_INTERNAL, {}); return; }
        self->read_length();
      });
  }

  void arm_timeout() {
    auto self = shared_from_this();
    timeoutTimer_.expires_after(
      std::chrono::milliseconds(responseTimeoutMs_));
    timeoutTimer_.async_wait(
      [self](const boost::system::error_code& ec) {
        if (ec) return; // cancelled
        self->finish(CES_ERROR_TIMEOUT, {});
      });
  }

  void read_length() {
    auto self = shared_from_this();
    boost::asio::async_read(
      *stream_, boost::asio::buffer(respLenBuf_),
      [self](const boost::system::error_code& ec, std::size_t) {
        if (ec) { self->finish(CES_ERROR_INTERNAL, {}); return; }
        uint32_t len = ces::Buffer::peek<uint32_t>(
          std::span<const uint8_t>(self->respLenBuf_), 0);
        if (len > self->maxResponseBytes_) {
          self->finish(CES_ERROR_INTERNAL, {});
          return;
        }
        if (len == 0) {
          self->finish(CES_OK, {});
          return;
        }
        self->respBodyBuf_.resize(len);
        self->read_body();
      });
  }

  void read_body() {
    auto self = shared_from_this();
    boost::asio::async_read(
      *stream_, boost::asio::buffer(respBodyBuf_),
      [self](const boost::system::error_code& ec, std::size_t) {
        if (ec) { self->finish(CES_ERROR_INTERNAL, {}); return; }
        self->finish(CES_OK, std::move(self->respBodyBuf_));
      });
  }

  void finish(uint8_t rc, ces::Bytes body) {
    if (finished_) return;
    finished_ = true;
    boost::system::error_code ec;
    timeoutTimer_.cancel(ec);
    if (stream_) stream_->close();
    if (cb_) {
      cb_(rc, std::move(body));
      cb_ = nullptr;
    }
  }
};

// ---------------------------------------------------------------------------
// CesServer::VmHost — production CesVMHost. Constructed inline at each VM
// run site with a CesServer& and a VmHostSetup that carries the per-run
// policy (undo-log hooks, deferred sinks, allowance, verifySig toggle).
// One vtable, no per-run closure construction.
// ---------------------------------------------------------------------------

class CesServer::VmHost final : public CesVMHost {
public:
  VmHost(CesServer& server, const VmHostSetup& setup)
      : server_(server),
        caller_(setup.callerPrefix),
        programOwnerPrefix_(setup.programOwnerPrefix),
        saveAccountFn_(setup.saveAccountFn),
        saveAssetFn_(setup.saveAssetFn),
        udpSink_(setup.sendUdpFn),
        crossSink_(setup.crossTransferFn),
        enableVerifySig_(setup.enableVerifySig) {
    this->allowance = setup.allowance;
    // Per-op fees mirror the protocol-side handlers (transfer/createAsset/...).
    // Each VM syscall that mutates or reads the ledger debits the same fee
    // its UDP-equivalent would debit, on top of the gas cost — otherwise a
    // VM run would be a multi-thousand-x discount on every state operation
    // and trivially sidestep the rent and tx-fee economics. Flat-discounted
    // fees ship to the VM with the multiplier already applied; syscall
    // handlers bill them as-is.
    this->feeQuery   = server_.discountFee(FeeKind::Query,       server_.cfg_.feeQuery);
    this->feeTx      = server_.discountFee(FeeKind::Tx,          server_.cfg_.feeTx);
    this->feeAsset   = server_.discountFee(FeeKind::AssetRent,   server_.cfg_.feeAsset);
    this->feeAccount = server_.discountFee(FeeKind::AccountRent, server_.cfg_.feeAccount);
    // SYS_SEND_CLIENT has no UDP equivalent; pick a placeholder bounded by
    // existing fees. TODO: resolve this fee/cost properly — outbound push
    // is its own resource (presence cache + UDP bandwidth) and probably
    // wants its own config knob with a per-recipient rate cap.
    this->feeSendClient = server_.discountFee(FeeKind::Tx,
        std::min<uint64_t>(server_.cfg_.feeQuery * 10, server_.cfg_.feeTx));
    // Inputs for attenuated prepay math (CREATE/FUND asset). The bp is
    // snapshotted at VmHost construction (start of the program run),
    // not re-read per syscall. A program's view of "now" is the moment
    // it started; the metrics tick refreshes the multiplier at 1 Hz so
    // any drift across a sub-second VM run is invisible. Scheduled and
    // RPC-followup runs construct a fresh VmHost at fire time, so they
    // see today's bp too.
    this->feeAssetRaw     = server_.cfg_.feeAsset;
    this->assetRentMultBp = server_.getFeeMult(FeeKind::AssetRent);
  }

  // ---- Reads --------------------------------------------------------------
  int64_t readAccountBalance(const HashPrefix& id) override {
    auto aa = server_.accounts_.get(id);
    return aa.exists() ? aa.balance() : 0;
  }
  uint32_t readAccountNonce(const HashPrefix& id) override {
    auto aa = server_.accounts_.get(id);
    return aa.exists() ? aa.nonce() : 0;
  }
  bool readAsset(const minx::Hash& key, HashPrefix& owner, AssetData& content,
                 uint16_t& balance, uint32_t& price) override {
    auto aa = server_.assets_.get(key);
    if (!aa.exists()) return false;
    owner   = aa.data().getOwnerId();
    content = aa.data().getContent();
    // Raw 16-bit balance: bits 0..12 days (0..8191), bit 13 immut, bit 14
    // aowned, bit 15 priv. Programs mask with 0x1FFF for days; the unstripped
    // form is what lets them branch on the flag bits at all.
    balance = aa.data().getBalance();
    price   = aa.data().getPrice();
    return true;
  }

  // ---- Caller debit chokepoint --------------------------------------------
  uint8_t debitCaller(uint64_t amount) override {
    if (amount == 0) return CES_OK;
    if (amount > this->allowance) return CES_ERROR_ALLOWANCE_EXCEEDED;
    auto callerIt = server_.accounts_->find(caller_);
    if (callerIt == server_.accounts_->end()) return CES_ERROR_ORIGIN_NOT_FOUND;
    if (callerIt->second.getBalance() < static_cast<int64_t>(amount))
      return CES_ERROR_INSUFFICIENT_BALANCE;
    maybeSaveAccount(caller_);
    callerIt->second.setBalance(callerIt->second.getBalance() -
                                static_cast<int64_t>(amount));
    // Saturate at 0 if we're already at UINT64_MAX (no enforcement) so the
    // io-mirrored remaining-allowance value still makes sense for programs
    // that read it without prior knowledge of the sentinel.
    if (this->allowance != std::numeric_limits<uint64_t>::max())
      this->allowance -= amount;
    return CES_OK;
  }

  // ---- Value-bearing writes ----------------------------------------------
  uint8_t transfer(const minx::Hash& dest, uint64_t amount) override {
    if (uint8_t rc = debitCaller(amount); rc != CES_OK) return rc;
    creditDest(dest, amount);
    return CES_OK;
  }

  uint8_t ownerTransfer(const minx::Hash& dest, uint64_t amount) override {
    if (uint8_t rc = debitProgramOwner(amount); rc != CES_OK) return rc;
    creditDest(dest, amount);
    return CES_OK;
  }

  uint8_t deposit(uint64_t amount) override {
    if (uint8_t rc = debitCaller(amount); rc != CES_OK) return rc;
    auto ownerIt = server_.accounts_->find(programOwnerPrefix_);
    if (ownerIt == server_.accounts_->end()) return CES_ERROR_ORIGIN_NOT_FOUND;
    maybeSaveAccount(programOwnerPrefix_);
    ownerIt->second.setBalance(ownerIt->second.getBalance() +
                               static_cast<int64_t>(amount));
    return CES_OK;
  }

  uint8_t withdraw(uint64_t amount) override {
    // programOwner -> caller. Not allowance-bound (the owner deployed the
    // bytecode, so they consented). Caller is the recipient — must exist
    // (they signed the run) so the credit always lands.
    if (uint8_t rc = debitProgramOwner(amount); rc != CES_OK) return rc;
    auto callerIt = server_.accounts_->find(caller_);
    if (callerIt == server_.accounts_->end()) return CES_ERROR_ORIGIN_NOT_FOUND;
    maybeSaveAccount(caller_);
    callerIt->second.setBalance(callerIt->second.getBalance() +
                                static_cast<int64_t>(amount));
    return CES_OK;
  }

  // ---- Asset writes -------------------------------------------------------
  uint8_t createAsset(const minx::Hash& key, const AssetData& content,
                      uint16_t days) override {
    auto it = server_.assets_->find(key);
    if (it != server_.assets_->end()) return CES_ERROR_ASSET_EXISTS;
    maybeSaveAsset(key);
    bool priv = isAssetPrivate(days);
    bool immut = isAssetImmutable(days);
    uint16_t cleanDays = assetDays(days);
    Asset newAsset(caller_, content,
                   assetBalance(1 + cleanDays, priv, /*aowned=*/false, immut), 0);
    server_.assets_->getObjects().emplace(key, newAsset);
    return CES_OK;
  }

  uint8_t createAssetManaged(const minx::Hash& key, const AssetData& content,
                             uint16_t days) override {
    auto it = server_.assets_->find(key);
    if (it != server_.assets_->end()) return CES_ERROR_ASSET_EXISTS;
    maybeSaveAsset(key);
    bool priv = isAssetPrivate(days);
    bool immut = isAssetImmutable(days);
    uint16_t cleanDays = assetDays(days);
    HashPrefix bootOwner = Account::getMapKey(this->selfAssetKey);
    Asset newAsset(bootOwner, content,
                   assetBalance(1 + cleanDays, priv, /*aowned=*/true, immut), 0);
    server_.assets_->getObjects().emplace(key, newAsset);
    return CES_OK;
  }

  uint8_t updateAsset(const minx::Hash& key, const AssetData& content) override {
    auto it = server_.assets_->find(key);
    if (it == server_.assets_->end()) return CES_ERROR_ASSET_NOT_FOUND;
    uint8_t authRc = checkAssetWriteAuth(
      it->second, caller_, programOwnerPrefix_, this->selfAssetKey);
    if (authRc != CES_OK) return authRc;
    maybeSaveAsset(key);
    it->second.setContent(content);
    return CES_OK;
  }

  uint8_t updateAssetMeta(const minx::Hash& key, const HashPrefix& newOwner,
                          uint32_t price) override {
    auto it = server_.assets_->find(key);
    if (it == server_.assets_->end()) return CES_ERROR_ASSET_NOT_FOUND;
    // Use the same write-auth path as updateAsset/giveAsset — the VM
    // permits programOwner and asset-owned chains, not just strict caller
    // ownership the way the wire CES_UPDATE_ASSET_META does.
    uint8_t authRc = checkAssetWriteAuth(
      it->second, caller_, programOwnerPrefix_, this->selfAssetKey);
    if (authRc != CES_OK) return authRc;
    maybeSaveAsset(key);
    it->second.setOwnerId(newOwner);
    it->second.setPrice(price);
    return CES_OK;
  }

  uint8_t fundAsset(const minx::Hash& key, uint16_t days) override {
    auto it = server_.assets_->find(key);
    if (it == server_.assets_->end()) return CES_ERROR_ASSET_NOT_FOUND;
    maybeSaveAsset(key);
    bool priv   = isAssetPrivate  (it->second.getBalance());
    bool aowned = isAssetOwned    (it->second.getBalance());
    bool immut  = isAssetImmutable(it->second.getBalance());
    uint16_t curDays = assetDays(it->second.getBalance());
    uint32_t newDays = curDays + days;
    if (newDays > 0x1FFF) newDays = 0x1FFF;
    it->second.setBalance(
      assetBalance(static_cast<uint16_t>(newDays), priv, aowned, immut));
    return CES_OK;
  }

  uint8_t buyAsset(const minx::Hash& key, uint64_t maxPrice) override {
    auto it = server_.assets_->find(key);
    if (it == server_.assets_->end()) return CES_ERROR_ASSET_NOT_FOUND;
    uint32_t storedPrice = it->second.getPrice();
    if (storedPrice == 0) return CES_ERROR_NOT_FOR_SALE;
    uint64_t realPrice = storedToRealPrice(storedPrice);
    if (realPrice > maxPrice) return CES_ERROR_INSUFFICIENT_PAYMENT;
    if (uint8_t rc = debitCaller(realPrice); rc != CES_OK) return rc;
    HashPrefix sellerId = it->second.getOwnerId();
    auto sellerIt = server_.accounts_->find(sellerId);
    if (sellerIt != server_.accounts_->end()) {
      maybeSaveAccount(sellerId);
      sellerIt->second.setBalance(sellerIt->second.getBalance() + realPrice);
    }
    maybeSaveAsset(key);
    it->second.setOwnerId(caller_);
    it->second.setPrice(0);
    return CES_OK;
  }

  uint8_t giveAsset(const minx::Hash& key, const HashPrefix& newOwner) override {
    auto it = server_.assets_->find(key);
    if (it == server_.assets_->end()) return CES_ERROR_ASSET_NOT_FOUND;
    uint8_t authRc = checkAssetWriteAuth(
      it->second, caller_, programOwnerPrefix_, this->selfAssetKey);
    if (authRc != CES_OK) return authRc;
    maybeSaveAsset(key);
    it->second.setOwnerId(newOwner);
    it->second.setPrice(0);
    return CES_OK;
  }

  // ---- Deferred / optional side effects -----------------------------------
  void sendUdp(const std::string& addr, uint16_t port,
               const uint8_t* data, size_t len) override {
    if (udpSink_) udpSink_(addr, port, data, len);
  }

  // Cross-transfer is special. Unlike the other syscalls, two concerns
  // touch the VM side: ledger mutation (caller debit + peer vostro credit
  // — must be rollback-safe via the undo log) and network dispatch (fire
  // settlement over CesClientAsync — must NOT fire if the VM later aborts).
  // Both are handled here, synchronously on the logic strand; the outer
  // crossSink decides *when* the network dispatch happens:
  //   - CES_RUN_ASSET path: sink buffers into deferredCrossXfers and the
  //     commit branch fires them after a successful VM run. A VM abort
  //     rolls back the ledger via the undo log and naturally drops the
  //     buffered dispatch on scope exit.
  //   - executeScheduledRun path: sink fires immediately (no rollback).
  //
  // VM users get the same "free local transfer" discount as SYS_TRANSFER
  // (no txFee), since they're already paying gas for the syscall. The
  // operation is net-zero on totalCredits_ (caller - amount, vostro +
  // amount), so bypassing ActiveAccount bookkeeping is safe here, the
  // same way it is for SYS_TRANSFER above.
  uint8_t crossTransfer(const minx::Hash& dest, uint64_t amount,
                        const std::string& server) override {
    if (!crossSink_) return CES_ERROR_DISABLED;
    minx::Hash peerKey{};
    bool peerFound = false;
    {
      std::lock_guard lock(server_.peerTableMutex_);
      for (auto& p : server_.peerTable_) {
        if (p.declaredAddress == server && p.reachable) {
          peerKey = p.ckey;
          peerFound = true;
          break;
        }
      }
    }
    if (!peerFound) {
      LOGDEBUG << "VM cross-transfer: unknown/unreachable peer" << SVAR(server);
      return CES_ERROR_UNKNOWN_PEER;
    }
    auto* settlementClient = server_.getOrCreateSettlementClient(server, peerKey);
    if (!settlementClient || settlementClient->load() >= 95) {
      LOGDEBUG << "VM cross-transfer: settlement queue full" << SVAR(server);
      return CES_ERROR_QUEUE_FULL;
    }
    if (uint8_t rc = debitCaller(amount); rc != CES_OK) {
      LOGDEBUG << "VM cross-transfer: debit failed" << VAR(amount) << VAR(rc);
      return rc;
    }
    HashPrefix peerPrefix = Account::getMapKey(peerKey);
    maybeSaveAccount(peerPrefix);
    auto peerIt = server_.accounts_->find(peerPrefix);
    if (peerIt != server_.accounts_->end()) {
      peerIt->second.setBalance(
        peerIt->second.getBalance() + static_cast<int64_t>(amount));
    } else {
      Account newAcc(peerKey, static_cast<int64_t>(amount), 0);
      server_.accounts_->getObjects().emplace(peerPrefix, newAcc);
    }
    crossSink_(dest, amount, server, peerKey);
    return CES_OK;
  }

  bool sendClient(const HashPrefix& clientId,
                  const uint8_t* data, size_t len) override {
    minx::Bytes payload(data, data + len);
    return server_.send(clientId, payload);
  }

  uint8_t schedule(const minx::Hash& assetId, uint64_t budget,
                   uint64_t allowance,
                   const uint8_t* input, size_t inputLen,
                   uint64_t time_us) override {
    return server_.scheduleRun(caller_, assetId, budget, allowance,
                               {input, input + inputLen}, time_us);
  }

  uint8_t rpc(const std::string& host, uint16_t port,
              const minx::Hash& fileHeadKey,
              const minx::Hash& followupProgramKey,
              uint64_t followupBudget,
              uint32_t followupInputTag) override {
    LOGTRACE << "sys_rpc host callback fired" << SVAR(host) << VAR(port)
             << VAR(followupBudget) << VAR(followupInputTag);
    PendingRpc pending;
    pending.host               = host;
    pending.port               = port;
    pending.fileHeadKey        = fileHeadKey;
    pending.followupProgramKey = followupProgramKey;
    pending.selfAssetKey       = this->selfAssetKey;
    pending.callerPrefix       = Account::getMapKey(this->callerKey);
    pending.programOwnerPrefix = this->programOwner;
    pending.followupBudget     = followupBudget;
    pending.followupAllowance  = this->allowance;
    pending.followupInputTag   = followupInputTag;
    return server_.queueRpc(std::move(pending));
  }

  bool verifySig(const uint8_t* data, size_t dataLen,
                 const uint8_t* sig, const uint8_t* pubkey) override {
    if (!enableVerifySig_) return false;
    try {
      Hash keyHash;
      std::memcpy(keyHash.data(), pubkey, 32);
      PublicKey pk(keyHash);
      Signature sigArr;
      std::memcpy(sigArr.data(), sig, 65);
      return pk.verifySignature(
        std::span<const uint8_t>(data, dataLen), sigArr);
    } catch (...) {
      return false;
    }
  }

private:
  CesServer& server_;
  HashPrefix caller_;
  HashPrefix programOwnerPrefix_;
  std::function<void(const HashPrefix&)>                 saveAccountFn_;
  std::function<void(const minx::Hash&)>                 saveAssetFn_;
  std::function<void(const std::string&, uint16_t,
                     const uint8_t*, size_t)>            udpSink_;
  std::function<void(const minx::Hash&, uint64_t,
                     const std::string&,
                     const minx::Hash&)>                 crossSink_;
  bool enableVerifySig_;

  void maybeSaveAccount(const HashPrefix& id) {
    if (saveAccountFn_) saveAccountFn_(id);
  }
  void maybeSaveAsset(const minx::Hash& key) {
    if (saveAssetFn_) saveAssetFn_(key);
  }

  // Credit-side of any transfer. Both transfer (caller-as-source) and
  // ownerTransfer (programOwner-as-source) credit through here.
  void creditDest(const minx::Hash& dest, uint64_t amount) {
    HashPrefix destPrefix = Account::getMapKey(dest);
    auto destIt = server_.accounts_->find(destPrefix);
    if (destIt != server_.accounts_->end()) {
      maybeSaveAccount(destPrefix);
      destIt->second.setBalance(destIt->second.getBalance() + amount);
    } else {
      maybeSaveAccount(destPrefix);
      Account newAcc(dest, amount, 0);
      server_.accounts_->getObjects().emplace(destPrefix, newAcc);
    }
  }

  // Debit programOwner's account directly. No allowance check — the owner
  // deployed the bytecode and thereby consented to its semantics. The
  // caller still pays the syscall's protocol fee (debited separately in
  // the SYS_OWNER_TRANSFER handler), but the value transfer drains the
  // owner. Returns ORIGIN_NOT_FOUND if programOwner has no account
  // (e.g. an asset-owned program chain).
  uint8_t debitProgramOwner(uint64_t amount) {
    if (amount == 0) return CES_OK;
    auto ownerIt = server_.accounts_->find(programOwnerPrefix_);
    if (ownerIt == server_.accounts_->end()) return CES_ERROR_ORIGIN_NOT_FOUND;
    if (ownerIt->second.getBalance() < static_cast<int64_t>(amount))
      return CES_ERROR_INSUFFICIENT_BALANCE;
    maybeSaveAccount(programOwnerPrefix_);
    ownerIt->second.setBalance(ownerIt->second.getBalance() -
                               static_cast<int64_t>(amount));
    return CES_OK;
  }
};

// ---------------------------------------------------------------------------
// CesRpcRudpListener — Rudp::Listener wired into CesServer
// ---------------------------------------------------------------------------

void CesRpcRudpListener::onSend(const minx::SockAddr& peer,
                                const minx::Bytes& bytes) {
  // minx::Bytes already start with the MinxStdExtensions routing key
  // that Rudp prepended. sendExtension takes the payload as-is.
  // Swallow the "no socket" exception during teardown — Rudp can
  // emit HS_CLOSE from RudpStream::close() at any point in the
  // shutdown sequence, including after rpcMinx_->closeSocket().
  if (!owner_->rpcMinx_) return;
  try {
    owner_->rpcMinx_->sendExtension(peer, bytes);
  } catch (const std::exception&) {
    // Socket already closed; nothing to do.
  }
}

std::shared_ptr<minx::Rudp::ChannelHandler>
CesRpcRudpListener::onAccept(const minx::SockAddr& peer,
                             uint32_t channelId) {
  // CesPlex inactive → reject inbound HS_OPEN silently. Outbound
  // channels (SYS_RPC) don't fire onAccept; this path is purely
  // inbound.
  if (!owner_->cesplex_) return nullptr;
  return owner_->cesplex_->acceptInbound(peer, channelId);
}

CesServer::CesServer(const CesConfig& config)
    : cfg_(config),
      logicStrand_(boost::asio::make_strand(taskIO_)),
      serverKeyPair_(config.serverPrivKey, config.serverKeyAlgo),
      accounts_((config.dataDir / ACCOUNTS_DATA_SUBDIRECTORY).string(),
                config.minAcc, config.flushValue,
                config.accountStoreBufferSize),
      assets_((config.dataDir / ASSETS_DATA_SUBDIRECTORY).string(),
              config.minAsset, config.flushValue, config.assetStoreBufferSize),
      presence_(config.presenceCacheSize) {
  // Default every fee multiplier to full price (10000 bp). The metrics
  // pulse overwrites these once a tick from the gauge each kind is
  // mapped to — but only when feeDiscountEnabled is true.
  for (auto& m : feeMult_)
    m.store(10000, std::memory_order_relaxed);
  minx_ = std::make_unique<minx::Minx>(
    this, minx::MinxConfig{
      .instanceName = "sv",
      .minProveWorkTimestamp = cfg_.minProveWorkTimestamp,
      .spendSlotSize = cfg_.spendSlotSize,
      .randomXVMsToKeep = RANDOMX_VMS_TO_KEEP,
      .randomXInitThreads = 0,
      .spamThreshold = SPAM_THRESHOLD_DISABLED,
      .spamSampleRate = SPAM_SAMPLE_RATE,
      .trustLoopback = true,
      .recvBuffersSize = cfg_.recvBuffersSize});
  if (cfg_.taskThreads < 1 || cfg_.taskThreads > MAX_TASK_THREADS) {
    throw std::runtime_error("bad value for taskThreads");
  }

  // Default the three file-storage fee knobs. Physical cost model:
  //   feeFileRent  — retention (per-byte-day), disk 100x cheaper
  //                   than asset-cell RAM. An asset is 256 B of RAM
  //                   costing feeAsset per day, so the per-byte-day
  //                   RAM rate is feeAsset / 256 and disk is that
  //                   divided by 100.
  //   feeFileWrite — network + SSD write (per-byte), ~10 days of
  //                   rent per byte
  //   feeFileRead  — SSD read (per-byte). Most of what was previously
  //                   bundled here moved to feeNetByte* (it was
  //                   network bandwidth, not SSD work). The remainder
  //                   covers the SSD's read-bandwidth-share — a small
  //                   floor since reads have no wear cost.
  // Zero values derive the default; minimum clamp of 1 prevents
  // free ops when feeAsset is tuned unusually low in tests.
  if (cfg_.feeFileRent == 0) {
    cfg_.feeFileRent = static_cast<int64_t>(cfg_.feeAsset) / 100 / 256;
    if (cfg_.feeFileRent == 0) cfg_.feeFileRent = 1;
  }
  if (cfg_.feeFileWrite == 0) {
    // The network share is billed separately via feeNetByteReceived
    // against the body bytes. Wear stays heavy: WRITE pays ~9x
    // per-byte-day rent per KB, vs READ's ~0.125x, preserving NAND's
    // ~10:1 wear-vs-bandwidth asymmetry.
    cfg_.feeFileWrite = cfg_.feeFileRent * 9;
    if (cfg_.feeFileWrite == 0) cfg_.feeFileWrite = 1;
  }
  if (cfg_.feeFileRead == 0) {
    // The network share is billed separately via feeNetByteSent. What
    // remains here is the SSD read-bandwidth share — a small floor (no
    // wear, no replacement cost, just bus time and power).
    cfg_.feeFileRead = cfg_.feeFileRent / 8;
    if (cfg_.feeFileRead == 0) cfg_.feeFileRead = 1;
  }
  // --- RUDP-tier billing rates ---
  // The bundled file/query fees implicitly priced networking; we
  // pull that share out and bill it explicitly per-byte/per-second
  // here. NetworkBilling reads these into each channel's bound
  // contract at bind time and debits the payer per tick.
  if (cfg_.feeNetByteSent == 0) {
    // Symmetric per-byte rate (sending and receiving cost the
    // same on the server side: NIC, kernel buffers, CPU per byte).
    // Anchor to per-byte-day rent / 1024 ≈ "1 byte ≈ 1 KB-day rent" —
    // small but non-zero, which is the right magnitude for transient
    // network bytes vs. long-lived disk bytes.
    uint64_t v = static_cast<uint64_t>(cfg_.feeFileRent) / 1024;
    if (v == 0) v = 1;
    cfg_.feeNetByteSent = v;
  }
  if (cfg_.feeNetByteReceived == 0) {
    cfg_.feeNetByteReceived = cfg_.feeNetByteSent;
  }
  if (cfg_.feeNetMemByteDay == 0) {
    // RAM equivalence: a byte sitting in a RUDP buffer for a day
    // costs the same as a byte of ledger RAM for a day. Same anchor
    // as feeComputeRssByteDay.
    uint64_t v = static_cast<uint64_t>(cfg_.feeAsset) / 256;
    if (v == 0) v = 1;
    cfg_.feeNetMemByteDay = v;
  }
  if (cfg_.feeNetChannelSec == 0) {
    // "Channel is open" rate. Anchor: one asset-day of supervisor +
    // bookkeeping overhead per second (≈ 296/sec at stock).
    uint64_t v = static_cast<uint64_t>(cfg_.feeAsset) / 86400;
    if (v == 0) v = 1;
    cfg_.feeNetChannelSec = v;
  }
  // feeQuery default lives in the BASE_FEE_QUERY constant (see the
  // comment on its declaration).
  // --- Compute fees (see comments on CesConfig). Derive from the
  //     ledger anchors; explicit non-zero values are honored as-is. ---
  if (cfg_.feeComputeSlotSec == 0) {
    cfg_.feeComputeSlotSec = static_cast<int64_t>(cfg_.feeAsset) / 86400;
    if (cfg_.feeComputeSlotSec == 0) cfg_.feeComputeSlotSec = 1;
  }
  if (cfg_.feeComputeRssByteDay == 0) {
    cfg_.feeComputeRssByteDay = static_cast<int64_t>(cfg_.feeAsset) / 256;
    if (cfg_.feeComputeRssByteDay == 0) cfg_.feeComputeRssByteDay = 1;
  }
  if (cfg_.feeComputeCpuSec == 0) {
    cfg_.feeComputeCpuSec = 5'000'000;
  }
  // Bucket cache capacity rent: same byte-day basis as RSS, but
  // charged per-second since buckets are a standing committed
  // footprint rather than a sampled measurement.
  if (cfg_.feeBucketByteSec == 0) {
    int64_t v = cfg_.feeComputeRssByteDay / 86400;
    if (v == 0) v = 1;
    cfg_.feeBucketByteSec = v;
  }
  // Default file store dir under dataDir. Used only when the
  // feature is active (cesFileStoreMaxBytes > 0); harmless to set
  // regardless.
  if (cfg_.cesFileStoreDir.empty()) {
    cfg_.cesFileStoreDir =
      (cfg_.dataDir / "cesfilestore").string();
  }

  LOGDEBUG << "CesServer fees"
           << VAR(cfg_.feeAsset) << VAR(cfg_.feeAccount)
           << VAR(cfg_.feeTx) << VAR(cfg_.feeQuery)
           << VAR(cfg_.feeFileRent) << VAR(cfg_.feeFileWrite)
           << VAR(cfg_.feeFileRead)
           << VAR(cfg_.feeNetByteSent) << VAR(cfg_.feeNetByteReceived)
           << VAR(cfg_.feeNetMemByteDay) << VAR(cfg_.feeNetChannelSec)
           << VAR(cfg_.feeComputeSlotSec)
           << VAR(cfg_.feeComputeRssByteDay)
           << VAR(cfg_.feeComputeCpuSec);

  minx_->setServerKey(serverKeyPair_.getPublicKeyAsHash());
  minx_->setMinimumDifficulty(cfg_.minDiff);
  minx_->setUseDataset(true);

  // Mark the server's own account as "uncounted" — its balance is
  // excluded from totalCredits_ and from credit/debit tally updates.
  // It's forced to exactly 2^60 every boot via topUpServerAccount (far
  // below INT64_MAX, so incoming transfers can never overflow). This must run
  // before the first ledger mutation so loaded balances are already
  // exempt by the time start() runs the top-up.
  accounts_.setUncountedAccount(
    Account::getMapKey(serverKeyPair_.getPublicKeyAsHash()));

  // Load persisted peer data, then seed with outbound config peers
  loadPeerData();
  for (auto& pc : cfg_.peers) {
    minx::Hash key;
    minx::stringToHash(key, pc.pubKeyHex);
    upsertPeer(key, pc.address, 0);
    // Mark as outbound
    std::lock_guard lock(peerTableMutex_);
    for (auto& p : peerTable_) {
      if (p.ckey == key) { p.outbound = true; break; }
    }
  }

  if (cfg_.maxAcc < cfg_.minAcc)
    throw std::runtime_error("maxAcc must be >= minAcc");
  if (cfg_.maxAsset < cfg_.minAsset)
    throw std::runtime_error("maxAsset must be >= minAsset");

  // Pre-threading startup logs (No locks needed, runs before threads spawn)
  {
    LOGDEBUG << "--- DB LOADED: " << accounts_->getObjects().size()
             << " ACCOUNTS ---";
    int shown = 0;
    for (auto& [prefix, acc] : accounts_->getObjects()) {
      if (shown >= BOOT_ACCOUNT_DUMP_MAX) {
        LOGDEBUG << "... ("
                 << (accounts_->getObjects().size() - BOOT_ACCOUNT_DUMP_MAX)
                 << " more accounts omitted) ...";
        break;
      }
      ++shown;
      minx::Hash fullKey = const_cast<Account&>(acc).getKey(prefix);
      LOGDEBUG << "[" << std::setw(2) << shown << "] "
               << minx::hashToString(fullKey)
               << " | Balance: " << acc.getBalance()
               << " | Nonce: " << acc.getNonce();
    }
  }
  LOGDEBUG << "-----------------------------------------------";
}

CesServer::~CesServer() {
  LOGTRACE << "~CesServer";
  stop(false);
  LOGTRACE << "~CesServer done";
}

uint16_t CesServer::start(uint16_t serverPort) {
  if (running_)
    return 0;
  if (netIO_.stopped())
    netIO_.restart();
  if (taskIO_.stopped())
    taskIO_.restart();
  LOGDEBUG << "server opening socket" << VAR(serverPort);
  receiving_ = true;
  running_ = true;
  uint16_t boundPort = minx_->openSocket(boost::asio::ip::address_v6::any(),
                                         serverPort, netIO_, taskIO_);
  if (boundPort == 0) {
    LOGDEBUG << "server failed to open socket";
    return 0;
  }
  boundPort_ = boundPort;
  LOGDEBUG << "server opened socket" << VAR(boundPort);
  LOGDEBUG << "starting IO threads" << VAR(cfg_.taskThreads);
  netIOThread_ = std::thread([this]() { netIO_.run(); });
  for (int i = 0; i < cfg_.taskThreads; ++i) {
    taskIOThreads_.emplace_back([this]() { taskIO_.run(); });
  }
  LOGDEBUG << "starting verifyPoW thread";
  verifyPoWThread_ = std::thread([this]() {
    while (running_) {
      minx_->verifyPoWs();
      ces::sleep(100);
    }
  });
  metricsStartTimer();
  dailyTaskStartTimer();
  replyStartTimer();
  cronStartTimer();
  // Top up the server's own account to near-INT64_MAX. Runs once
  // per boot, before any other strand work that might read or
  // mutate account state. See topUpServerAccount() for rationale.
  postLogic( [this]() { topUpServerAccount(); });
  // Deploy server-built /b/<name> bytecode programs over whatever
  // sits at their well-known asset keys. Posted after topUp so the
  // server account exists (these programs run as owner = server).
  postLogic( [this]() { deployBuiltinVmPrograms(); });
  // Run autoexec cron assets on boot (async, on the strand)
  postLogic( [this]() { runAutoexec(); });
  // Start settlement worker (async cross-transfer delivery)
  if (settlementIO_.stopped())
    settlementIO_.restart();
  settlementWorkGuard_ = std::make_unique<
    boost::asio::executor_work_guard<IOContext::executor_type>>(
    settlementIO_.get_executor());
  settlementThread_ = std::thread([this]() { settlementIO_.run(); });

  // SYS_RPC bridge: if the operator configured a dedicated RPC UDP
  // port (cfg_.rpcPort != 0), bind a second Minx instance on it with
  // a RUDP transport layered on its EXTENSION lane.
  //
  // Build order:
  //   1. Create rpcMinx_ with a no-op listener (the RPC Minx carries
  //      no CES protocol traffic).
  //   2. Create rpcRudp_ (passive state machine, no threads).
  //   3. Wire rpcRudp_'s send callback → rpcMinx_->sendExtension.
  //   4. Wire rpcRudp_'s receive callback (empty placeholder until
  //      the SYS_RPC dispatcher lands; any inbound message is
  //      dropped with a TRACE log).
  //   5. Register Rudp's KEY_V0 routing key with a MinxStdExtensions
  //      builder and install the resulting dispatcher as rpcMinx_'s
  //      extension handler.
  //   6. openSocket, start rpcNetIO_ / rpcTaskIO_ threads.
  //   7. Start the Rudp tick timer on rpcTaskIO_ (20ms cadence).
  //
  // All rpcRudp_ access (push, onPacket, tick, flush, callbacks) runs
  // on rpcTaskIO_'s single thread, so no mutex is needed on Rudp
  // state. The extension handler is invoked from rpcMinx_'s taskIO
  // callback path, which IS rpcTaskIO_ — same thread.
  if (cfg_.rpcPort != 0 || cfg_.rpcAutoPort) {
    LOGDEBUG << "rpc: opening dedicated MINX socket" << VAR(cfg_.rpcPort);
    if (rpcNetIO_.stopped())
      rpcNetIO_.restart();
    if (rpcTaskIO_.stopped())
      rpcTaskIO_.restart();

    rpcMinx_ = std::make_unique<minx::Minx>(
      &rpcListener_, minx::MinxConfig{
        .instanceName = "rpc",
        .minProveWorkTimestamp = cfg_.minProveWorkTimestamp,
        .spendSlotSize = cfg_.spendSlotSize,
        .randomXVMsToKeep = 0,           // no PoW engine on the RPC port
        .randomXInitThreads = 0,
        .spamThreshold = SPAM_THRESHOLD_DISABLED,
        .spamSampleRate = SPAM_SAMPLE_RATE,
        .trustLoopback = true,
        .recvBuffersSize = cfg_.recvBuffersSize});
    rpcMinx_->setServerKey(serverKeyPair_.getPublicKeyAsHash());

    // Construct the Rudp transport before opening the socket so no
    // packet can hit an unwired handler. The Rudp::Listener
    // (rpcRudpListener_) is bound at construction; it forwards onSend
    // to rpcMinx_ and onAccept to CesPlex when the latter is alive.
    // Per-channel pacing comes from config; defaults are
    // PER_CHANNEL_UNLIMITED so this is a no-op on stock deployments.
    minx::RudpConfig rudpCfg{};
    rudpCfg.perChannelBytesPerSecond = cfg_.rpcRudpBytesPerSecond;
    rudpCfg.perChannelBurstBytes     = cfg_.rpcRudpBurstBytes;
    rudpCfg.maxChannelsPerPeer       = cfg_.rpcRudpMaxChannelsPerPeer;
    if (cfg_.rpcRudpMaxReorderBytesPerChannel >= 0)
      rudpCfg.maxReorderBytesPerChannel =
        static_cast<size_t>(cfg_.rpcRudpMaxReorderBytesPerChannel);
    if (cfg_.rpcRudpMaxReorderMsgsPerChannel >= 0)
      rudpCfg.maxReorderMessagesPerChannel =
        static_cast<size_t>(cfg_.rpcRudpMaxReorderMsgsPerChannel);
    // RUDP's default 100 ms pulse emits only one packet per
    // channel-with-data per pulse. For a 275 MB file-store upload
    // that's ~198000 packets × 100 ms = 5.5 hours. 1 ms pulse gets
    // us ~1000 pkt/s per channel — the pulse only fires when there's
    // data to send, so a quiet channel stays quiet.
    rudpCfg.baseTickInterval = std::chrono::milliseconds(1);
    rpcRudp_ = std::make_unique<minx::Rudp>(
      &rpcRudpListener_, rudpCfg, rpcMinx_.get());

    // NetworkBilling: per-channel billing tick that debits the bound
    // payer at the channel's bound rates. Constructed before CesPlex so
    // CesPlex's Session can call track() with the bound rate schedule
    // at acceptInbound time.
    netBilling_ = std::make_unique<NetworkBilling>(
      *rpcRudp_, rpcTaskIO_, this);

    // CesPlex — the L2 protocol multiplexer. Constructed iff the
    // operator configured any mounts; otherwise we stay in "outbound
    // only" mode and inbound HS_OPENs are rejected (rpcRudpListener_
    // returns nullptr from onAccept when cesplex_ is null).
    // Construction happens before the socket is opened so the listener
    // sees a coherent CesPlex pointer before any packet can arrive.
    if (!cfg_.cesplexMounts.empty()) {
      cesplex_ = std::make_unique<CesPlex>(
        cfg_.cesplexMounts, *rpcRudp_, rpcTaskIO_, this, netBilling_.get());
      if (!cesplex_->hasAnyBinding()) {
        // All mounts resolved to unknown targets — construction
        // succeeded but there's nothing to accept. Tear it down so
        // we stay in the "inbound-rejected" mode instead of pretending
        // CesPlex is active.
        LOGDEBUG << "rpc: CesPlex has no resolved bindings; disabling";
        cesplex_.reset();
      } else {
        if (cfg_.cesFileStoreMaxBytes > 0) {
          // File-storage feature is on. Bind the builtin:file
          // handler and do the startup reconciliation walk.
          fileHandlerBind(this);
          fileHandlerStartupReconcile();
        } else {
          // CesPlex has other bindings but file-storage is off.
          LOGINFO << "file-store: disabled (cesFileStoreMaxBytes = 0)";
        }
        // Compute feature: binds after file, fails loudly with a
        // specific reason if its prereqs aren't satisfied.
        if (cfg_.computeMaxInstances > 0) {
          uint8_t rc = computeHandlerBind(this);
          if (rc != CES_OK) {
            LOGWARNING << "compute: handler bind refused"
                       << VAR(int(rc));
          }
        } else {
          LOGINFO << "compute: disabled (computeMaxInstances = 0)";
        }
        // /ces/lua/1 user-↔-program connection routing. Always bind
        // when CesPlex is up — the handler itself is cheap (no timer,
        // no resources) and bind-time visibility is the same as the
        // file/compute handlers above.
        luaHandlerBind(this);

        // Deploy + launch /s/ builtin apps. Posted onto rpcTaskIO_
        // (the supervisor strand); runs after the rpc threads spin
        // up. fileHandlerEnsureServerFile is idempotent; missing
        // file/compute prereqs surface as logged warnings.
        boost::asio::post(rpcTaskIO_,
          [this]() { launchBuiltinApps(); });
      }
    }

    // Register the Rudp family with a MinxStdExtensions builder.
    // Rudp::KEY_V0 is the sentinel routing key; the family id is
    // what matters, the sub-protocol byte is masked off by stdext.
    {
      minx::MinxStdExtensions stdExt;
      stdExt.registerExtension(
        minx::Rudp::KEY_V0,
        [this](const minx::SockAddr& peer, uint64_t key,
               const minx::Bytes& payload) {
          if (rpcRudp_) {
            rpcRudp_->onPacket(peer, key, payload, getMicrosSinceEpoch());
          }
        });
      rpcMinx_->setExtensionHandler(std::move(stdExt).build());
    }

    rpcBoundPort_ = rpcMinx_->openSocket(
      boost::asio::ip::address_v6::any(), cfg_.rpcPort,
      rpcNetIO_, rpcTaskIO_);
    if (rpcBoundPort_ == 0) {
      LOGDEBUG << "rpc: failed to open socket on" << VAR(cfg_.rpcPort);
      // Tear down in reverse construction order: CesPlex holds
      // references into rpcRudp_ and must go first; netBilling_
      // also references rpcRudp_.
      luaHandlerBind(nullptr);
      computeHandlerBind(nullptr);
      fileHandlerBind(nullptr);
      cesplex_.reset();
      netBilling_.reset();
      rpcMinx_.reset();
      rpcRudp_.reset();
    } else {
      LOGINFO << "rpc: MINX/RUDP port listening" << VAR(rpcBoundPort_);
      rpcNetIOThread_ = std::thread([this]() { rpcNetIO_.run(); });
      rpcTaskIOThread_ = std::thread([this]() { rpcTaskIO_.run(); });

      // Start the Rudp tick pulse. The timer schedules itself
      // recursively on rpcTaskIO_ until stop() cancels it.
      // Indirection via shared_ptr<std::function> to dodge the
      // self-capture ordering footgun of a locally-defined
      // recursive std::function lambda.
      rpcTickTimer_ = std::make_shared<boost::asio::steady_timer>(rpcTaskIO_);
      // Server-side rpcRudp tick cadence. baseTickInterval (set above
      // to 1 ms) rate-limits packet emission to 1000 pkt/sec/channel;
      // this timer just has to call tick() often enough that we don't
      // lose pulse budget to the MAX_PULSES_PER_CALL=100 cap. A 10 ms
      // timer gives 10 pulses/call × 100 calls/sec = same 1000 pkt/sec
      // with 1/10th the wakeup cost. scheduleHalvedFire() accelerates
      // the next pulse automatically on inbound traffic.
      auto scheduleTick = std::make_shared<std::function<void()>>();
      *scheduleTick = [this, scheduleTick]() {
        if (!rpcTickTimer_ || !running_) return;
        rpcTickTimer_->expires_after(std::chrono::milliseconds(10));
        auto timer = rpcTickTimer_;
        timer->async_wait(
          [this, scheduleTick](const boost::system::error_code& ec) {
            if (ec || !running_ || !rpcRudp_) return;
            rpcRudp_->tick(getMicrosSinceEpoch());
            (*scheduleTick)();
          });
      };
      boost::asio::post(rpcTaskIO_, [scheduleTick]() { (*scheduleTick)(); });
    }
  }

  LOGDEBUG << "server started";
  return boundPort;
}

void CesServer::stop(bool flushEvents) {
  if (!running_)
    return;
  LOGDEBUG << "stop flagging server for termination";
  receiving_ = false;
  int mul = 1;
  int ctrlCCount = ces::interruptCount();
  int maxCtrlCCount = 5;
  LOGDEBUG << "stop checking that PoW queue is empty";
  while (true) {
    size_t powQueueSize = minx_->getVerifyPoWQueueSize();
    if (!powQueueSize)
      break;
    if (ctrlCCount >= maxCtrlCCount) {
      LOGINFO << "stop interrupted waiting for PoW queue to empty out"
              << VAR(powQueueSize);
      break;
    }
    LOGTRACE << "stop waiting for PoW queue to empty out" << VAR(powQueueSize)
             << VAR(ctrlCCount) << VAR(maxCtrlCCount);
    ces::sleep(100 * mul);
  }
  running_ = false;

  // Stop peer miner if running
  if (peerMinerRunning_) {
    LOGDEBUG << "stop stopping peer miner";
    peerMinerRunning_ = false;
    if (peerMinerThread_.joinable())
      peerMinerThread_.join();
    LOGDEBUG << "stop peer miner stopped";
  }

  LOGDEBUG << "stop closing socket";
  minx_->closeSocket(false);
  LOGDEBUG << "stop stopping task timers";
  if (metricsTimer_) {
    boost::system::error_code ec;
    metricsTimer_->cancel(ec);
  }
  if (dailyTimer_) {
    boost::system::error_code ec;
    dailyTimer_->cancel(ec);
  }
  if (replyTimer_) {
    boost::system::error_code ec;
    replyTimer_->cancel(ec);
  }
  LOGDEBUG << "stop stopping IO contexts";
  netIO_.stop();
  taskIO_.stop();
  LOGDEBUG << "joining netIO threads";
  if (netIOThread_.joinable()) {
    netIOThread_.join();
  }
  LOGDEBUG << "joining taskIO threads";
  for (auto& thread : taskIOThreads_) {
    if (thread.joinable()) {
      thread.join();
    }
  }
  LOGDEBUG << "joining verifyPoWThread";
  if (verifyPoWThread_.joinable()) {
    verifyPoWThread_.join();
  }
  LOGDEBUG << "stopping settlement worker";
  for (auto& [addr, client] : settlementClients_)
    client->close();
  settlementClients_.clear();
  settlementWorkGuard_.reset();
  settlementIO_.stop();
  if (settlementThread_.joinable())
    settlementThread_.join();

  // SYS_RPC bridge teardown: cancel the Rudp tick timer, close the
  // socket, stop io contexts, join threads, destroy Rudp and Minx.
  // running_ was already cleared above so any in-flight tick
  // scheduling short-circuits. The Rudp instance outlives the
  // extension handler's ability to reach it (rpcMinx_ stops
  // accepting new packets after closeSocket) but we destroy it only
  // after both threads have joined — no more onPacket calls can
  // race with the destructor.
  if (rpcMinx_) {
    LOGDEBUG << "rpc: closing dedicated MINX socket";
    if (rpcTickTimer_) {
      boost::system::error_code ec;
      rpcTickTimer_->cancel(ec);
    }
    rpcMinx_->closeSocket(false);
    rpcNetIO_.stop();
    rpcTaskIO_.stop();
    if (rpcNetIOThread_.joinable())
      rpcNetIOThread_.join();
    if (rpcTaskIOThread_.joinable())
      rpcTaskIOThread_.join();
    rpcTickTimer_.reset();
    // CesPlex holds references into rpcRudp_ (via its per-session
    // RudpStreams) and registers callbacks on it. Tear it down
    // before rpcRudp_ so no callback fires into a half-destroyed
    // CesPlex, and no RudpStream outlives its Rudp. Compute unbind
    // must run BEFORE its rpcTaskIO_ executor goes away — it cancels
    // the supervisor timer and SIGKILLs live instances.
    luaHandlerBind(nullptr);
    computeHandlerBind(nullptr);
    fileHandlerBind(nullptr);
    cesplex_.reset();
    netBilling_.reset();
    rpcRudp_.reset();
    rpcMinx_.reset();
    rpcBoundPort_ = 0;
  }

  if (flushEvents) {
    LOGINFO << "flushing event logs...";
    accounts_->flush(true);
    assets_->flush(true);
    LOGINFO << "event logs flushed";
  }
  LOGDEBUG << "destroying minx";
  minx_.reset();
  LOGDEBUG << "server stopped";
}

void CesServer::pause() { paused_ = true; }
void CesServer::resume() { paused_ = false; }
bool CesServer::send(const HashPrefix& clientId, const minx::Bytes& data) {
  auto addr = presence_.get(clientId);
  if (!addr) return false;
  if (minx_)
    minx_->sendApplication(*addr, data);
  return true;
}

bool CesServer::send(const HashPrefix& clientId, uint8_t code,
                     const minx::Bytes& data) {
  auto addr = presence_.get(clientId);
  if (!addr) return false;
  if (minx_)
    minx_->sendApplication(*addr, data, code);
  return true;
}

void CesServer::checkPause() {
  while (paused_) {
    ces::sleep(10);
  }
}

uint64_t CesServer::getTxCount() { return txCount_.load(); }

void CesServer::createPoWEngine(bool fullMem) {
  minx_->setUseDataset(fullMem);
  minx_->createPoWEngine(serverKeyPair_.getPublicKeyAsHash());
}

bool CesServer::isPoWEngineReady() {
  return minx_->checkPoWEngine(serverKeyPair_.getPublicKeyAsHash());
}

bool CesServer::isConnected(const SockAddr& addr) {
  auto ip = addr.address();
  std::lock_guard lock(peerTableMutex_);
  for (const auto& p : peerTable_) {
    if (p.resolvedIP == ip) return true;
  }
  return false;
}

int64_t CesServer::resolveFee(int64_t passedFee, int64_t defaultFee) const {
  return (passedFee < 0) ? defaultFee : passedFee;
}

// Must be called on logicStrand_. Returns true if snapshot was taken.
bool CesServer::doSnapshot(const char* reason) {
  uint64_t now = minx::getSecsSinceEpoch();
  if (now - lastSnapshotTime_ < SNAPSHOT_COOLDOWN_SECS) {
    LOGWARNING << "snapshot debounced (cooldown " << SNAPSHOT_COOLDOWN_SECS
               << "s)" << VAL("reason", reason);
    return false;
  }
  lastSnapshotTime_ = now;
  LOGINFO << "snapshot" << VAL("reason", reason);
  accounts_->flush(true);
  accounts_->save(logkv::StoreSaveMode::forkSave);
  assets_->flush(true);
  assets_->save(logkv::StoreSaveMode::forkSave);
  return true;
}

void CesServer::checkAutoSnapshot() {
  if (cfg_.maxLogBytes == 0)
    return;
  // Skip the size read during cooldown — called on every mutation, so an
  // over-threshold condition without debounce would spam both the snapshot
  // queue and the log. doSnapshot enforces the cooldown too; this just
  // dampens here so we don't emit hundreds of "limit reached" INFO lines
  // while the previous snapshot is still draining event files.
  uint64_t now = minx::getSecsSinceEpoch();
  if (now - lastSnapshotTime_ < SNAPSHOT_COOLDOWN_SECS)
    return;
  uint64_t accSize = accounts_->getEventsFileSize();
  uint64_t astSize = assets_->getEventsFileSize();
  if (accSize >= cfg_.maxLogBytes || astSize >= cfg_.maxLogBytes) {
    LOGINFO << "auto-snapshot: event log size limit reached"
            << VAR(accSize) << VAR(astSize)
            << VAL("maxLogBytes", cfg_.maxLogBytes);
    postLogic( [this]() {
      doSnapshot("auto (event log size)");
    });
  }
}

// ----------------------------------------------------------------------------
// DISPATCH HELPERS
// ----------------------------------------------------------------------------

template <typename ResT>
void CesServer::sendSignedReply(const SockAddr& addr, const MinxMessage& msg,
                                ResT res) {
  tpsInc();
  boost::asio::post(taskIO_, [this, addr, msg, res = std::move(res)]() mutable {
    reply(addr, MinxMessage{msg.version, minx_->generatePassword(),
                            msg.gpassword, res.toBytes(serverKeyPair_)});
  });
}

template <typename ResT>
void CesServer::sendUnsignedReply(const SockAddr& addr, const MinxMessage& msg,
                                  ResT res) {
  tpsInc();
  boost::asio::post(taskIO_, [this, addr, msg, res = std::move(res)]() {
    reply(addr, MinxMessage{msg.version, minx_->generatePassword(),
                            msg.gpassword, res.toBytes()});
  });
}

template <typename ReqT, typename Fn>
void CesServer::dispatchSigned(const SockAddr& addr, const MinxMessage& msg,
                               ReqT req, const Hash& keyField, Fn&& fn) {
  if (!req.verifySignature(msg.data, PublicKey(keyField)))
    throw std::runtime_error("bad sig");

  // Verify server ID to prevent cross-server replay
  HashPrefix myId = Account::getMapKey(serverKeyPair_.getPublicKeyAsHash());
  if (req.serverId != myId) {
    LOGDEBUG << "dispatchSigned: wrong serverId";
    return;
  }

  // Track client presence for push (send())
  HashPrefix kp = Account::getMapKey(keyField);
  presence_.put(kp, addr);
  {
    std::lock_guard lk(presenceReverseMutex_);
    presenceReverse_[addr] = kp;
  }

  Hash key = keyField; // copy before req is moved
  postLogic(
    [this, addr, msg, req = std::move(req), key,
     fn = std::forward<Fn>(fn)]() {
      HashPrefix prefix = Account::getMapKey(key);
      ActiveAccount acc = accounts_.get(prefix);
      if (!acc.exists() || acc.data().getKey(prefix) != key)
        return;
      fn(req, prefix, addr, msg);
    });
}

// ----------------------------------------------------------------------------
// DATA MODEL MUTATORS
// ----------------------------------------------------------------------------

uint8_t CesServer::transfer(const minx::Hash& originKey,
                            const minx::Hash& destKey, uint64_t amount,
                            TransferMode mode, uint8_t paymentDays,
                            uint32_t providedNonce,
                            int64_t& outOriginBalance, int64_t txFee,
                            int64_t rentFee, int64_t errFee) {

  txFee = discountedFlatFee(txFee, cfg_.feeTx, FeeKind::Tx);
  // Keep rentFee raw — it's a per-day rate; the prepay-days creation
  // cost below routes through attenuatedFundCost.
  rentFee = resolveFee(rentFee, cfg_.feeAccount);
  errFee = discountedFlatFee(errFee, cfg_.getFeeError(), FeeKind::Query);
  uint64_t totalDeduction = amount + txFee;

  ActiveAccount origin = accounts_.get(Account::getMapKey(originKey));
  uint8_t rc = origin.validateSpend(amount, txFee, providedNonce, errFee);
  if (rc != CES_OK) {
    outOriginBalance = origin.balance();
    LOGDEBUG << "transfer: validateSpend failed" << VAR(rc);
    return rc;
  }

  HashPrefix destId = Account::getMapKey(destKey);
  ActiveAccount dest = accounts_.get(destId);

  if (!dest.exists()) {
    // Destination doesn't exist
    if (mode == TransferMode::Safe) {
      origin.chargeError(errFee);
      outOriginBalance = origin.balance();
      LOGDEBUG << "transfer: safe mode, target not found";
      return CES_ERROR_TARGET_NOT_FOUND;
    }

    if (accounts_->getObjects().size() >= cfg_.maxAcc) {
      LOGDEBUG << "transfer: max accounts reached";
      return CES_ERROR_INTERNAL;
    }

    uint64_t creationCost =
      (mode == TransferMode::Payment)
        ? attenuatedFundCost(FeeKind::AccountRent, rentFee,
                             2u + static_cast<uint32_t>(paymentDays), 0)
        : attenuatedFundCost(FeeKind::AccountRent, rentFee, 3, 0);

    if (Accounts::checkAddOverflow(totalDeduction, creationCost,
                                   totalDeduction)) {
      origin.chargeError(errFee);
      outOriginBalance = origin.balance();
      LOGDEBUG << "transfer: overflow with create cost";
      return CES_ERROR_INSUFFICIENT_BALANCE_WITH_CREATE;
    }

    if (origin.balance() < static_cast<int64_t>(totalDeduction)) {
      origin.chargeError(errFee);
      outOriginBalance = origin.balance();
      LOGDEBUG << "transfer: insufficient balance for create";
      return CES_ERROR_INSUFFICIENT_BALANCE_WITH_CREATE;
    }

    Account newAccount;
    if (mode == TransferMode::Payment) {
      newAccount =
        Account(destKey, -static_cast<int64_t>(amount), 1 + paymentDays);
    } else {
      newAccount = Account(destKey, amount, 0);
    }
    accounts_.createAccount(destId, newAccount);

  } else {
    // Destination exists
    if (mode == TransferMode::Payment) {
      origin.chargeError(errFee);
      outOriginBalance = origin.balance();
      LOGDEBUG << "transfer: payment mode, target already exists";
      return CES_ERROR_INVALID_TARGET_ACCOUNT;
    }

    if (dest.data().getKey(dest.id) != destKey) {
      origin.chargeError(errFee);
      outOriginBalance = origin.balance();
      LOGDEBUG << "transfer: wrong target account key";
      return CES_ERROR_WRONG_TARGET_ACCOUNT;
    }

    if (dest.balance() < 0) {
      if (amount != static_cast<uint64_t>(-dest.balance())) {
        origin.chargeError(errFee);
        outOriginBalance = origin.balance();
        LOGDEBUG << "transfer: wrong payment amount" << VAR(amount);
        return CES_ERROR_WRONG_PAYMENT_AMOUNT;
      }
      dest.settlePayment(amount);
    } else {
      dest.credit(amount);
    }
  }

  origin.debitTransfer(totalDeduction, destId, amount);
  outOriginBalance = origin.balance();
  accounts_.checkFlush(totalDeduction);
  checkAutoSnapshot();

  LOGTRACE << "transfer ok" << VAR(amount) << VAR(outOriginBalance);
  return CES_OK;
}

uint8_t CesServer::bulkTransfer(const minx::Hash& originKey,
                                const std::vector<BulkTransferItem>& items,
                                uint32_t providedNonce,
                                int64_t& outOriginBalance,
                                uint8_t& outSuccessfulCount, int64_t txFee,
                                int64_t rentFee, int64_t errFee) {

  txFee = discountedFlatFee(txFee, cfg_.feeTx, FeeKind::Tx);
  rentFee = resolveFee(rentFee, cfg_.feeAccount); // raw per-day rate
  errFee = discountedFlatFee(errFee, cfg_.getFeeError(), FeeKind::Query);

  ActiveAccount origin = accounts_.get(Account::getMapKey(originKey));

  // Validate nonce and charge the base fee for the envelope ONCE
  uint8_t rc = origin.validateSpend(0, txFee, providedNonce, errFee);
  if (rc != CES_OK) {
    outOriginBalance = origin.balance();
    outSuccessfulCount = 0;
    return rc;
  }

  outSuccessfulCount = 0;

  // The Stop-And-Commit Loop
  for (const auto& item : items) {
    // Charge the standard txFee for each internal transfer as well
    uint64_t totalDeduction = item.amount + txFee;

    HashPrefix destId = Account::getMapKey(item.destKey);
    ActiveAccount dest = accounts_.get(destId);

    if (!dest.exists()) {
      // Bulk transfer always auto-creates (Open mode)
      if (accounts_->getObjects().size() >= cfg_.maxAcc) {
        rc = CES_ERROR_INTERNAL;
        break;
      }

      uint64_t creationCost =
        attenuatedFundCost(FeeKind::AccountRent, rentFee, 3, 0);

      if (Accounts::checkAddOverflow(totalDeduction, creationCost,
                                     totalDeduction)) {
        origin.chargeError(errFee);
        rc = CES_ERROR_INSUFFICIENT_BALANCE_WITH_CREATE;
        break;
      }
      if (origin.balance() < static_cast<int64_t>(totalDeduction)) {
        origin.chargeError(errFee);
        rc = CES_ERROR_INSUFFICIENT_BALANCE_WITH_CREATE;
        break;
      }

      Account newAccount(item.destKey, item.amount, 0);
      accounts_.createAccount(destId, newAccount);
    } else {
      if (dest.data().getKey(dest.id) != item.destKey) {
        origin.chargeError(errFee);
        rc = CES_ERROR_WRONG_TARGET_ACCOUNT;
        break;
      }
      if (origin.balance() < static_cast<int64_t>(totalDeduction)) {
        origin.chargeError(errFee);
        rc = CES_ERROR_INSUFFICIENT_BALANCE;
        break;
      }

      if (dest.balance() < 0) {
        if (item.amount != static_cast<uint64_t>(-dest.balance())) {
          origin.chargeError(errFee);
          rc = CES_ERROR_WRONG_PAYMENT_AMOUNT;
          break;
        }
        dest.settlePayment(item.amount);
      } else {
        dest.credit(item.amount);
      }
    }

    origin.debit(totalDeduction);
    accounts_.checkFlush(totalDeduction);
    outSuccessfulCount++;
  }

  outOriginBalance = origin.balance();
  checkAutoSnapshot();
  return rc;
}

uint8_t CesServer::queryAccount(const minx::Hash& originKey,
                                const HashPrefix& queryId, uint8_t items,
                                uint32_t providedNonce,
                                int64_t& outOriginBalance,
                                std::vector<AccountEntry>& outResults,
                                int64_t queryFee, int64_t errFee) {
  if (items >= CesQueryAccount::MAX_ITEMS) {
    throw std::runtime_error("too many items");
  }

  queryFee = discountedFlatFee(queryFee, cfg_.feeQuery, FeeKind::Query);
  if (items > 0) {
    queryFee += (queryFee * (items + 1)) / CesQueryAccount::MAX_ITEMS;
  }
  errFee = discountedFlatFee(errFee, cfg_.getFeeError(), FeeKind::Query);

  ActiveAccount origin = accounts_.get(Account::getMapKey(originKey));

  uint8_t rc = origin.validateSpend(0, queryFee, providedNonce, errFee);
  if (rc != CES_OK) {
    if (origin.exists())
      outOriginBalance = origin.balance();
    return rc;
  }

  ActiveAccount target =
    LOGKV_IS_EMPTY(queryId) ? accounts_.getFirst() : accounts_.get(queryId);

  if (!target.exists()) {
    origin.chargeError(errFee);
    outOriginBalance = origin.balance();
    LOGDEBUG << "queryAccount: target not found";
    return CES_ERROR_INVALID_TARGET_ACCOUNT;
  }

  auto itQuery = target.it;
  size_t count = static_cast<size_t>(items) + 1;
  outResults.reserve(count);
  while (outResults.size() < count && itQuery != accounts_->end()) {
    AccountEntry entry;
    entry.key = itQuery->second.getKey(itQuery->first);
    entry.balance = itQuery->second.getBalance();
    entry.nonce = itQuery->second.getNonce();
    entry.lastXferDest = itQuery->second.getLastXferDest();
    entry.lastXferAmount = itQuery->second.getLastXferAmount();
    entry.lastXferTime = itQuery->second.getLastXferTime();
    outResults.push_back(entry);
    ++itQuery;
  }

  origin.debit(queryFee);
  outOriginBalance = origin.balance();
  accounts_.checkFlush(queryFee);

  LOGTRACE << "queryAccount ok" << VAR(outResults.size());
  return CES_OK;
}

void CesServer::unsignedQueryAccount(const HashPrefix& queryId,
                                     int64_t& outBalance, uint32_t& outNonce,
                                     HashPrefix& outLastXferDest,
                                     uint64_t& outLastXferAmount,
                                     uint32_t& outLastXferTime) {
  ActiveAccount acc = accounts_.get(queryId);
  if (acc.exists()) {
    outBalance = acc.balance();
    outNonce = acc.nonce();
    outLastXferDest = acc.data().getLastXferDest();
    outLastXferAmount = acc.data().getLastXferAmount();
    outLastXferTime = acc.data().getLastXferTime();
  } else {
    outBalance = 0;
    outNonce = 0;
    outLastXferDest = {};
    outLastXferAmount = 0;
    outLastXferTime = 0;
  }
}

uint8_t CesServer::queryServerInfo(const minx::Hash& originKey,
                                   uint32_t providedNonce,
                                   int64_t& outOriginBalance,
                                   std::vector<ServerInfoEntry>& outEntries,
                                   int64_t queryFee, int64_t errFee) {
  queryFee = discountedFlatFee(queryFee, cfg_.feeQuery, FeeKind::Query);
  errFee = discountedFlatFee(errFee, cfg_.getFeeError(), FeeKind::Query);

  ActiveAccount origin = accounts_.get(Account::getMapKey(originKey));

  uint8_t rc = origin.validateSpend(0, queryFee, providedNonce, errFee);
  if (rc != CES_OK) {
    if (origin.exists())
      outOriginBalance = origin.balance();
    return rc;
  }

  origin.debit(queryFee);
  outOriginBalance = origin.balance();
  accounts_.checkFlush(queryFee);

  auto kv = [&](const char* k, const std::string& v) {
    outEntries.push_back({k, v});
  };

  kv("totalAccounts", std::to_string(accounts_->getObjects().size()));
  kv("totalAssets", std::to_string(assets_->getObjects().size()));
  kv("totalCredits", std::to_string(accounts_.getTotalCredits()));
  kv("feeAccount", std::to_string(cfg_.feeAccount));
  kv("feeAsset", std::to_string(cfg_.feeAsset));
  kv("feeTx", std::to_string(cfg_.feeTx));
  kv("feeQuery", std::to_string(cfg_.feeQuery));
  kv("feeError", std::to_string(cfg_.getFeeError()));
  kv("feeVmMult", std::to_string(cfg_.feeVmMult));
  kv("feeFileRent", std::to_string(cfg_.feeFileRent));
  kv("feeFileWrite", std::to_string(cfg_.feeFileWrite));
  kv("feeFileRead", std::to_string(cfg_.feeFileRead));
  kv("cesFileStoreMaxBytes", std::to_string(cfg_.cesFileStoreMaxBytes));
  kv("minAccounts", std::to_string(cfg_.minAcc));
  kv("maxAccounts", std::to_string(cfg_.maxAcc));
  kv("minAssets", std::to_string(cfg_.minAsset));
  kv("maxAssets", std::to_string(cfg_.maxAsset));
  kv("minDifficulty", std::to_string(cfg_.minDiff));
  kv("spendSlotSize", std::to_string(cfg_.spendSlotSize));
  kv("tps", std::to_string(tpsCurrent_.load()));
  {
    std::lock_guard lock(peerTableMutex_);
    kv("peerCount", std::to_string(peerTable_.size()));
  }
  kv("serverPublicKey", minx::hashToString(serverKeyPair_.getPublicKeyAsHash()));
  if (!cfg_.serverName.empty())
    kv("serverName", cfg_.serverName);
  if (!cfg_.version.empty())
    kv("version", cfg_.version);

  return CES_OK;
}

uint8_t CesServer::crossTransfer(const minx::Hash& originKey,
                                  const minx::Hash& destKey, uint64_t amount,
                                  const std::string& destServer,
                                  uint32_t providedNonce,
                                  int64_t& outOriginBalance,
                                  int64_t txFee, int64_t errFee) {
  txFee = discountedFlatFee(txFee, cfg_.feeTx, FeeKind::Tx);
  errFee = discountedFlatFee(errFee, cfg_.getFeeError(), FeeKind::Query);

  // 1. Validate origin account
  ActiveAccount origin = accounts_.get(Account::getMapKey(originKey));
  uint8_t rc = origin.validateSpend(amount, txFee, providedNonce, errFee);
  if (rc != CES_OK) {
    outOriginBalance = origin.balance();
    LOGDEBUG << "crossTransfer: validateSpend failed" << VAR(rc);
    return rc;
  }

  // 2. Find peer in table
  minx::Hash peerKey{};
  bool peerFound = false;
  {
    std::lock_guard lock(peerTableMutex_);
    for (auto& p : peerTable_) {
      if (p.declaredAddress == destServer && p.reachable) {
        peerKey = p.ckey;
        peerFound = true;
        break;
      }
    }
  }
  if (!peerFound) {
    origin.chargeError(errFee);
    outOriginBalance = origin.balance();
    LOGDEBUG << "crossTransfer: unknown/unreachable peer" << VAR(destServer);
    return CES_ERROR_UNKNOWN_PEER;
  }

  // 3. Check settlement queue capacity
  auto* settlementClient = getOrCreateSettlementClient(destServer, peerKey);
  if (settlementClient && settlementClient->load() >= 95) {
    origin.chargeError(errFee);
    outOriginBalance = origin.balance();
    return CES_ERROR_QUEUE_FULL;
  }

  // 4. Debit origin, credit peer's vostro
  uint64_t totalDeduction = amount + txFee;
  origin.debitTransfer(totalDeduction,
                       Account::getMapKey(peerKey), amount);
  outOriginBalance = origin.balance();

  HashPrefix peerMapKey = Account::getMapKey(peerKey);
  ActiveAccount peerVostro = accounts_.get(peerMapKey);
  if (peerVostro.exists()) {
    peerVostro.credit(amount);
  } else {
    Account newAcc(peerKey, amount, 0);
    accounts_.createAccount(peerMapKey, newAcc);
  }

  accounts_.checkFlush(totalDeduction);

  // 5. Dispatch remote transfer
  if (settlementClient) {
    settlementClient->openTransfer(destKey, amount,
      [](uint8_t) {});
  }
  checkAutoSnapshot();
  return CES_OK;
}

uint8_t CesServer::createAsset(const minx::Hash& originKey,
                               const minx::Hash& assetId,
                               const AssetData& content, uint16_t balance,
                               uint32_t providedNonce, int64_t rentFee,
                               int64_t errFee) {
  rentFee = resolveFee(rentFee, cfg_.feeAsset);  // raw per-day rate
  errFee = discountedFlatFee(errFee, cfg_.getFeeError(), FeeKind::Query);

  ActiveAccount origin = accounts_.get(Account::getMapKey(originKey));
  if (!origin.exists())
    return CES_ERROR_ORIGIN_NOT_FOUND;

  uint64_t totalCost = attenuatedFundCost(
    FeeKind::AssetRent, rentFee,
    2u + static_cast<uint32_t>(assetDays(balance)), 0);

  uint8_t rc = origin.validateSpend(0, totalCost, providedNonce, errFee);
  if (rc != CES_OK)
    return rc;

  ActiveAsset asset = assets_.get(assetId);

  if (asset.exists()) {
    origin.chargeError(errFee);
    LOGDEBUG << "createAsset: asset already exists";
    return CES_ERROR_ASSET_EXISTS;
  }
  if (assets_->getObjects().size() >= cfg_.maxAsset) {
    LOGDEBUG << "createAsset: max assets reached";
    return CES_ERROR_INTERNAL;
  }

  origin.debit(totalCost);
  accounts_.checkFlush(totalCost);

  bool priv = isAssetPrivate(balance);
  bool immut = isAssetImmutable(balance);
  uint16_t days = assetDays(balance);
  Asset newAsset(origin.id, content,
                 assetBalance(1 + days, priv, /*aowned=*/false, immut), 0);
  Asset::SerModeGuard guard(Asset::SerMode::Full);
  assets_->update(assetId, newAsset);

  assets_.checkFlush(totalCost);
  checkAutoSnapshot();
  LOGTRACE << "createAsset ok" << VAR(assetId) << VAR(balance);
  return CES_OK;
}

uint8_t CesServer::updateAsset(const minx::Hash& originKey,
                               const minx::Hash& assetId,
                               const HashPrefix& newOwnerId,
                               const AssetData& content, uint32_t price,
                               uint32_t providedNonce, int64_t updateFee,
                               int64_t errFee) {
  updateFee = discountedFlatFee(updateFee, cfg_.feeAsset, FeeKind::AssetRent);
  errFee = discountedFlatFee(errFee, cfg_.getFeeError(), FeeKind::Query);

  ActiveAccount origin = accounts_.get(Account::getMapKey(originKey));
  if (!origin.exists())
    return CES_ERROR_ORIGIN_NOT_FOUND;

  uint8_t rc = origin.validateSpend(0, updateFee, providedNonce, errFee);
  if (rc != CES_OK)
    return rc;

  ActiveAsset asset = assets_.get(assetId);

  if (!asset.exists()) {
    origin.chargeError(errFee);
    LOGDEBUG << "updateAsset: not found";
    return CES_ERROR_ASSET_NOT_FOUND;
  }
  if (asset.getOwnerId() != origin.id) {
    origin.chargeError(errFee);
    LOGDEBUG << "updateAsset: not owner";
    return CES_ERROR_NOT_OWNER;
  }
  if (isAssetImmutable(asset.getBalance())) {
    origin.chargeError(errFee);
    LOGDEBUG << "updateAsset: immutable";
    return CES_ERROR_IMMUTABLE;
  }

  origin.debit(updateFee);
  accounts_.checkFlush(updateFee);

  asset.updateFull(newOwnerId, content, price);

  assets_.checkFlush(updateFee);
  checkAutoSnapshot();
  LOGTRACE << "updateAsset ok" << VAR(assetId);
  return CES_OK;
}

uint8_t CesServer::updateAssetMeta(const minx::Hash& originKey,
                                   const minx::Hash& assetId,
                                   const HashPrefix& newOwnerId, uint32_t price,
                                   uint32_t providedNonce, int64_t updateFee,
                                   int64_t errFee) {
  updateFee = discountedFlatFee(updateFee, cfg_.feeTx, FeeKind::Tx);
  errFee = discountedFlatFee(errFee, cfg_.getFeeError(), FeeKind::Query);

  ActiveAccount origin = accounts_.get(Account::getMapKey(originKey));
  if (!origin.exists())
    return CES_ERROR_ORIGIN_NOT_FOUND;

  uint8_t rc = origin.validateSpend(0, updateFee, providedNonce, errFee);
  if (rc != CES_OK)
    return rc;

  ActiveAsset asset = assets_.get(assetId);

  if (!asset.exists()) {
    origin.chargeError(errFee);
    LOGDEBUG << "updateAssetMeta: not found";
    return CES_ERROR_ASSET_NOT_FOUND;
  }
  if (asset.getOwnerId() != origin.id) {
    origin.chargeError(errFee);
    LOGDEBUG << "updateAssetMeta: not owner";
    return CES_ERROR_NOT_OWNER;
  }

  origin.debit(updateFee);
  accounts_.checkFlush(updateFee);

  asset.setPrice(price);
  asset.setOwner(newOwnerId);

  assets_.checkFlush(updateFee);
  checkAutoSnapshot();
  LOGTRACE << "updateAssetMeta ok" << VAR(assetId);
  return CES_OK;
}

uint8_t CesServer::updateAssetFast(const minx::Hash& originKey,
                                   const minx::Hash& assetId,
                                   const AssetData& content,
                                   uint32_t providedNonce,
                                   int64_t fastUpdateFee, int64_t errFee) {
  fastUpdateFee = discountedFlatFee(fastUpdateFee, cfg_.feeAsset,
                                    FeeKind::AssetRent);
  errFee = discountedFlatFee(errFee, cfg_.getFeeError(), FeeKind::Query);

  ActiveAccount origin = accounts_.get(Account::getMapKey(originKey));
  if (!origin.exists())
    return CES_ERROR_ORIGIN_NOT_FOUND;

  uint8_t rc = origin.validateSpend(0, fastUpdateFee, providedNonce, errFee);
  if (rc != CES_OK)
    return rc;

  ActiveAsset asset = assets_.get(assetId);

  if (!asset.exists()) {
    origin.chargeError(errFee);
    LOGDEBUG << "updateAssetFast: not found";
    return CES_ERROR_ASSET_NOT_FOUND;
  }
  if (asset.getOwnerId() != origin.id) {
    origin.chargeError(errFee);
    LOGDEBUG << "updateAssetFast: not owner";
    return CES_ERROR_NOT_OWNER;
  }
  if (isAssetImmutable(asset.getBalance())) {
    origin.chargeError(errFee);
    LOGDEBUG << "updateAssetFast: immutable";
    return CES_ERROR_IMMUTABLE;
  }

  origin.debit(fastUpdateFee);
  accounts_.checkFlush(fastUpdateFee);

  asset.setContent(content);

  checkAutoSnapshot();
  LOGTRACE << "updateAssetFast ok" << VAR(assetId);
  return CES_OK;
}

uint8_t CesServer::fundAsset(const minx::Hash& originKey,
                             const minx::Hash& assetId, uint16_t balance,
                             uint32_t providedNonce, int64_t fundFee,
                             int64_t rentFee, int64_t errFee) {
  fundFee = discountedFlatFee(fundFee, cfg_.feeTx, FeeKind::Tx);
  rentFee = resolveFee(rentFee, cfg_.feeAsset);  // raw per-day rate
  errFee = discountedFlatFee(errFee, cfg_.getFeeError(), FeeKind::Query);

  ActiveAccount origin = accounts_.get(Account::getMapKey(originKey));
  if (!origin.exists())
    return CES_ERROR_ORIGIN_NOT_FOUND;

  // Read existing days first so attenuation is correct against current
  // prepaid balance — funding when many days are already held costs
  // close to full price for the trailing days.
  ActiveAsset asset = assets_.get(assetId);
  uint32_t held = asset.exists() ? assetDays(asset.getBalance()) : 0u;
  uint64_t rentCost = attenuatedFundCost(
    FeeKind::AssetRent, rentFee, balance, held);
  uint64_t totalCost = rentCost + fundFee;

  uint8_t rc = origin.validateSpend(0, totalCost, providedNonce, errFee);
  if (rc != CES_OK)
    return rc;

  if (!asset.exists()) {
    origin.chargeError(errFee);
    LOGDEBUG << "fundAsset: not found";
    return CES_ERROR_ASSET_NOT_FOUND;
  }

  origin.debit(totalCost);
  accounts_.checkFlush(totalCost);

  bool priv = isAssetPrivate(asset.getBalance());
  bool aowned = isAssetOwned(asset.getBalance());
  bool immut = isAssetImmutable(asset.getBalance());
  uint16_t curDays = assetDays(asset.getBalance());
  uint32_t newDays = curDays + balance;
  if (newDays > 0x1FFF) newDays = 0x1FFF;
  asset.setBalance(
    assetBalance(static_cast<uint16_t>(newDays), priv, aowned, immut));

  assets_.checkFlush(totalCost);
  checkAutoSnapshot();
  LOGTRACE << "fundAsset ok" << VAR(assetId) << VAR(newDays);
  return CES_OK;
}

uint8_t CesServer::buyAsset(const minx::Hash& originKey,
                            const minx::Hash& assetId, uint64_t priceLimit,
                            uint32_t providedNonce, int64_t buyFee,
                            int64_t errFee) {
  buyFee = discountedFlatFee(buyFee, cfg_.feeTx, FeeKind::Tx);
  errFee = discountedFlatFee(errFee, cfg_.getFeeError(), FeeKind::Query);

  ActiveAccount buyer = accounts_.get(Account::getMapKey(originKey));
  if (!buyer.exists())
    return CES_ERROR_ORIGIN_NOT_FOUND;

  ActiveAsset asset = assets_.get(assetId);

  if (asset.getOwnerId() == buyer.id) {
    buyer.chargeError(errFee);
    LOGDEBUG << "buyAsset: buyer is already owner";
    return CES_ERROR_INVALID_TARGET_ACCOUNT;
  }

  if (!asset.exists()) {
    buyer.chargeError(errFee);
    LOGDEBUG << "buyAsset: not found";
    return CES_ERROR_ASSET_NOT_FOUND;
  }

  uint64_t price = storedToRealPrice(asset.getPrice());
  if (price == 0) {
    buyer.chargeError(errFee);
    LOGDEBUG << "buyAsset: not for sale";
    return CES_ERROR_NOT_FOR_SALE;
  }
  if (priceLimit < price) {
    buyer.chargeError(errFee);
    LOGDEBUG << "buyAsset: price exceeds limit" << VAR(price)
             << VAR(priceLimit);
    return CES_ERROR_INSUFFICIENT_PAYMENT;
  }

  uint8_t rc = buyer.validateSpend(price, buyFee, providedNonce, errFee);
  if (rc != CES_OK)
    return rc;

  uint64_t totalCost = price + buyFee;
  buyer.debit(totalCost);
  accounts_.checkFlush(totalCost);

  ActiveAccount seller = accounts_.get(asset.getOwnerId());
  if (seller.exists()) {
    seller.credit(price);
  }

  asset.transferOwnership(Account::getMapKey(originKey));

  assets_.checkFlush(totalCost);
  checkAutoSnapshot();
  LOGTRACE << "buyAsset ok" << VAR(assetId) << VAR(price);
  return CES_OK;
}

uint8_t CesServer::giveAsset(const minx::Hash& originKey,
                             const minx::Hash& assetId,
                             const HashPrefix& newOwnerId,
                             uint32_t providedNonce, int64_t giveFee,
                             int64_t errFee) {
  giveFee = discountedFlatFee(giveFee, cfg_.feeTx, FeeKind::Tx);
  errFee = discountedFlatFee(errFee, cfg_.getFeeError(), FeeKind::Query);

  ActiveAccount origin = accounts_.get(Account::getMapKey(originKey));
  if (!origin.exists())
    return CES_ERROR_ORIGIN_NOT_FOUND;

  uint8_t rc = origin.validateSpend(0, giveFee, providedNonce, errFee);
  if (rc != CES_OK)
    return rc;

  ActiveAsset asset = assets_.get(assetId);

  if (!asset.exists()) {
    origin.chargeError(errFee);
    LOGDEBUG << "giveAsset: not found";
    return CES_ERROR_ASSET_NOT_FOUND;
  }
  if (asset.getOwnerId() != origin.id) {
    origin.chargeError(errFee);
    LOGDEBUG << "giveAsset: not owner";
    return CES_ERROR_NOT_OWNER;
  }

  origin.debit(giveFee);
  accounts_.checkFlush(giveFee);

  asset.transferOwnership(newOwnerId);

  assets_.checkFlush(giveFee);
  checkAutoSnapshot();
  LOGTRACE << "giveAsset ok" << VAR(assetId) << VAR(newOwnerId);
  return CES_OK;
}

uint8_t CesServer::queryAsset(const minx::Hash& originKey,
                              const minx::Hash& assetId, uint8_t items,
                              uint32_t providedNonce,
                              std::vector<AssetEntry>& outResults,
                              int64_t queryFee, int64_t errFee) {
  queryFee = discountedFlatFee(queryFee, cfg_.feeQuery, FeeKind::Query);
  if (items > 0) {
    queryFee += (queryFee * (items + 1)) / CesQueryAsset::MAX_ITEMS;
  }
  errFee = discountedFlatFee(errFee, cfg_.getFeeError(), FeeKind::Query);

  ActiveAccount origin = accounts_.get(Account::getMapKey(originKey));
  if (!origin.exists())
    return CES_ERROR_ORIGIN_NOT_FOUND;

  uint8_t rc = origin.validateSpend(0, queryFee, providedNonce, errFee);
  if (rc != CES_OK)
    return rc;

  ActiveAsset target =
    LOGKV_IS_EMPTY(assetId) ? assets_.getFirst() : assets_.get(assetId);

  if (!target.exists()) {
    origin.chargeError(errFee);
    LOGDEBUG << "queryAsset: not found";
    return CES_ERROR_ASSET_NOT_FOUND;
  }

  // Treat private assets not owned by requester as not found
  HashPrefix requesterPrefix = Account::getMapKey(originKey);
  if (isAssetPrivate(target.data().getBalance()) &&
      target.data().getOwnerId() != requesterPrefix) {
    origin.chargeError(errFee);
    return CES_ERROR_ASSET_NOT_FOUND;
  }

  auto itAsset = target.it;
  size_t count = static_cast<size_t>(items) + 1;
  while (outResults.size() < count && itAsset != assets_->end()) {
    // Skip private assets not owned by the requester
    if (isAssetPrivate(itAsset->second.getBalance()) &&
        itAsset->second.getOwnerId() != requesterPrefix) {
      ++itAsset;
      continue;
    }
    AssetEntry entry;
    entry.ownerId = itAsset->second.getOwnerId();
    entry.content = itAsset->second.getContent();
    // Raw 16-bit balance — clients mask with assetDays() for the day count
    // and check bits 13/14/15 for immut/aowned/priv. Stripping here would
    // hide the flag bits from any wire client.
    entry.balance = itAsset->second.getBalance();
    entry.price = itAsset->second.getPrice();
    outResults.push_back(entry);
    ++itAsset;
  }

  origin.debit(queryFee);
  accounts_.checkFlush(queryFee);

  LOGTRACE << "queryAsset ok" << VAR(outResults.size());
  return CES_OK;
}

void CesServer::unsignedQueryAsset(const minx::Hash& assetId,
                                   HashPrefix& outOwner, AssetData& outContent,
                                   uint16_t& outBalance, uint32_t& outPrice) {
  ActiveAsset asset = assets_.get(assetId);

  if (asset.exists()) {
    outOwner = asset.getOwnerId();
    outContent = asset.getContent();
    outBalance = assetDays(asset.getBalance());
    outPrice = asset.getPrice();
  } else {
    outOwner = {};
    outContent = {};
    outBalance = 0;
    outPrice = 0;
  }
}

// ----------------------------------------------------------------------------
// NETWORK MESSAGE INGESTION
// ----------------------------------------------------------------------------

void CesServer::incomingInit(const SockAddr& addr, const MinxInit& msg) {
  checkPause();
  LOGTRACE << "got MinxInit" << VAR(addr);
  minx_->sendMessage(
    addr,
    MinxMessage{msg.version, minx_->generatePassword(), msg.gpassword, {}});
}

void CesServer::incomingMessage(const SockAddr& addr, const MinxMessage& msg) {
  checkPause();
  if (minx_->checkSpam(addr.address()))
    return;

  LOGTRACE << "got MinxMessage" << VAR(addr) << SVAR(msg);
  try {
    ConstBuffer buf(msg.data);
    uint8_t opCode = buf.get<uint8_t>();
    switch (opCode) {

    case CES_TRANSFER: {
      CesTransfer req;
      req.fromBytes(msg.data);
      Hash key = req.originId;
      dispatchSigned(addr, msg, std::move(req), key,
        [this](const CesTransfer& req, const HashPrefix& originPrefix,
               const SockAddr& addr, const MinxMessage& msg) {
          int64_t newBal = 0;
          uint8_t rc = transfer(req.originId, req.destKey, req.amount,
                                TransferMode::Safe, 0, req.reqNonce, newBal);

          CesTransferResult res;
          res.originId = originPrefix;
          res.reqNonce = req.reqNonce;
          res.destId = Account::getMapKey(req.destKey);
          res.amount = req.amount;
          res.originNewBalance = newBal;
          res.rcode = rc;
          sendSignedReply(addr, msg, std::move(res));
        });
      break;
    }

    case CES_OPEN_TRANSFER: {
      CesOpenTransfer req;
      req.fromBytes(msg.data);
      Hash key = req.originId;
      dispatchSigned(addr, msg, std::move(req), key,
        [this](const CesOpenTransfer& req, const HashPrefix& originPrefix,
               const SockAddr& addr, const MinxMessage& msg) {
          auto reply = [&](uint32_t nonce, int64_t bal, uint8_t rc) {
            CesOpenTransferResult res;
            res.originId = originPrefix;
            res.reqNonce = nonce;
            res.destId = Account::getMapKey(req.destKey);
            res.amount = req.amount;
            res.originNewBalance = bal;
            res.rcode = rc;
            sendSignedReply(addr, msg, std::move(res));
          };

          uint32_t effectiveNonce = req.reqNonce;
          if (req.reqNonce == CES_NONCELESS) {
            uint64_t now = getMicrosSinceEpoch();
            if (req.time > now + DEDUP_FUTURE_DRIFT_US ||
                req.time + DEDUP_WINDOW_US < now) {
              return reply(req.reqNonce, 0, CES_ERROR_WRONG_NONCE);
            }
            uint64_t sigHash;
            std::memcpy(&sigHash, req.sig.data(), sizeof(sigHash));
            if (!checkAndInsertDedup(sigHash)) {
              return reply(req.reqNonce, 0, CES_OK);
            }
            auto acc = accounts_.get(Account::getMapKey(req.originId));
            effectiveNonce = acc.exists() ? acc.nonce() + 1 : 1;
          }

          int64_t newBal = 0;
          uint8_t rc = transfer(req.originId, req.destKey, req.amount,
                                TransferMode::Open, 0, effectiveNonce, newBal);
          reply(effectiveNonce, newBal, rc);
        });
      break;
    }

    case CES_CREATE_PAYMENT: {
      CesCreatePayment req;
      req.fromBytes(msg.data);
      Hash key = req.originId;
      dispatchSigned(addr, msg, std::move(req), key,
        [this](const CesCreatePayment& req, const HashPrefix& originPrefix,
               const SockAddr& addr, const MinxMessage& msg) {
          int64_t newBal = 0;
          uint8_t rc = transfer(req.originId, req.destKey, req.amount,
                                TransferMode::Payment, req.days,
                                req.reqNonce, newBal);

          CesCreatePaymentResult res;
          res.originId = originPrefix;
          res.reqNonce = req.reqNonce;
          res.destId = Account::getMapKey(req.destKey);
          res.amount = req.amount;
          res.originNewBalance = newBal;
          res.rcode = rc;
          sendSignedReply(addr, msg, std::move(res));
        });
      break;
    }

    case CES_BULK_TRANSFER: {
      CesBulkTransfer req;
      req.fromBytes(msg.data);
      Hash key = req.originId;
      dispatchSigned(addr, msg, std::move(req), key,
        [this](const CesBulkTransfer& req, const HashPrefix& originPrefix,
               const SockAddr& addr, const MinxMessage& msg) {
          int64_t newBal = 0;
          uint8_t successfulCount = 0;
          uint8_t rc = bulkTransfer(req.originId, req.transfers, req.reqNonce,
                                    newBal, successfulCount);

          CesBulkTransferResult res;
          res.originId = originPrefix;
          res.reqNonce = req.reqNonce;
          res.rcode = rc;
          res.successfulCount = successfulCount;
          res.originNewBalance = newBal;
          sendSignedReply(addr, msg, std::move(res));
        });
      break;
    }

    case CES_QUERY_ACCOUNT: {
      CesQueryAccount req;
      req.fromBytes(msg.data);
      Hash key = req.originId;
      dispatchSigned(addr, msg, std::move(req), key,
        [this](const CesQueryAccount& req, const HashPrefix& originPrefix,
               const SockAddr& addr, const MinxMessage& msg) {
          int64_t newBal = 0;
          std::vector<AccountEntry> results;
          uint8_t rc = queryAccount(req.originId, req.queryId, req.items,
                                    req.reqNonce, newBal, results);

          CesQueryAccountResult res;
          res.originId = originPrefix;
          res.reqNonce = req.reqNonce;
          res.queryId = req.queryId;
          res.rcode = rc;
          if (rc == CES_OK) {
            res.accounts = std::move(results);
            res.items =
              res.accounts.empty() ? 0 : static_cast<uint8_t>(res.accounts.size() - 1);
          } else {
            res.items = req.items;
          }
          sendSignedReply(addr, msg, std::move(res));
        });
      break;
    }

    case CES_CREATE_ASSET: {
      CesCreateAsset req;
      req.fromBytes(msg.data);
      Hash key = req.ownerId;
      dispatchSigned(addr, msg, std::move(req), key,
        [this](const CesCreateAsset& req, const HashPrefix& ownerPrefix,
               const SockAddr& addr, const MinxMessage& msg) {
          uint8_t rc = createAsset(req.ownerId, req.assetId, req.content,
                                   req.amount, req.reqNonce);

          CesCreateAssetResult res;
          res.ownerId = ownerPrefix;
          res.reqNonce = req.reqNonce;
          res.assetId = req.assetId;
          res.amount = req.amount;
          res.price = req.price;
          res.rcode = rc;
          sendSignedReply(addr, msg, std::move(res));
        });
      break;
    }

    case CES_UPDATE_ASSET: {
      CesUpdateAsset req;
      req.fromBytes(msg.data);
      Hash key = req.ownerId;
      dispatchSigned(addr, msg, std::move(req), key,
        [this](const CesUpdateAsset& req, const HashPrefix& ownerPrefix,
               const SockAddr& addr, const MinxMessage& msg) {
          uint8_t rc = updateAsset(req.ownerId, req.assetId, req.newOwnerId,
                                   req.content, req.price, req.reqNonce);

          CesUpdateAssetResult res;
          res.ownerId = ownerPrefix;
          res.reqNonce = req.reqNonce;
          res.assetId = req.assetId;
          res.newOwnerId = req.newOwnerId;
          res.price = req.price;
          res.rcode = rc;
          sendSignedReply(addr, msg, std::move(res));
        });
      break;
    }

    case CES_UPDATE_ASSET_META: {
      CesUpdateAssetMeta req;
      req.fromBytes(msg.data);
      Hash key = req.ownerId;
      dispatchSigned(addr, msg, std::move(req), key,
        [this](const CesUpdateAssetMeta& req, const HashPrefix& ownerPrefix,
               const SockAddr& addr, const MinxMessage& msg) {
          uint8_t rc = updateAssetMeta(req.ownerId, req.assetId, req.newOwnerId,
                                       req.price, req.reqNonce);

          CesUpdateAssetMetaResult res;
          res.ownerId = ownerPrefix;
          res.reqNonce = req.reqNonce;
          res.assetId = req.assetId;
          res.newOwnerId = req.newOwnerId;
          res.price = req.price;
          res.rcode = rc;
          sendSignedReply(addr, msg, std::move(res));
        });
      break;
    }

    case CES_UPDATE_ASSET_FAST: {
      CesUpdateAssetFast req;
      req.fromBytes(msg.data);
      Hash key = req.ownerId;
      dispatchSigned(addr, msg, std::move(req), key,
        [this](const CesUpdateAssetFast& req, const HashPrefix& ownerPrefix,
               const SockAddr& addr, const MinxMessage& msg) {
          uint8_t rc =
            updateAssetFast(req.ownerId, req.assetId, req.content, req.reqNonce);

          CesUpdateAssetFastResult res;
          res.ownerId = ownerPrefix;
          res.reqNonce = req.reqNonce;
          res.assetId = req.assetId;
          res.rcode = rc;
          sendSignedReply(addr, msg, std::move(res));
        });
      break;
    }

    case CES_FUND_ASSET: {
      CesFundAsset req;
      req.fromBytes(msg.data);
      Hash key = req.originId;
      dispatchSigned(addr, msg, std::move(req), key,
        [this](const CesFundAsset& req, const HashPrefix& originPrefix,
               const SockAddr& addr, const MinxMessage& msg) {
          uint8_t rc =
            fundAsset(req.originId, req.assetId, req.amount, req.reqNonce);

          CesFundAssetResult res;
          res.originId = originPrefix;
          res.reqNonce = req.reqNonce;
          res.assetId = req.assetId;
          res.amount = req.amount;
          res.rcode = rc;
          sendSignedReply(addr, msg, std::move(res));
        });
      break;
    }

    case CES_BUY_ASSET: {
      CesBuyAsset req;
      req.fromBytes(msg.data);
      Hash key = req.originId;
      dispatchSigned(addr, msg, std::move(req), key,
        [this](const CesBuyAsset& req, const HashPrefix& originPrefix,
               const SockAddr& addr, const MinxMessage& msg) {
          uint8_t rc =
            buyAsset(req.originId, req.assetId, req.priceLimit, req.reqNonce);

          CesBuyAssetResult res;
          res.originId = originPrefix;
          res.reqNonce = req.reqNonce;
          res.assetId = req.assetId;
          res.priceLimit = req.priceLimit;
          res.rcode = rc;
          sendSignedReply(addr, msg, std::move(res));
        });
      break;
    }

    case CES_GIVE_ASSET: {
      CesGiveAsset req;
      req.fromBytes(msg.data);
      Hash key = req.ownerId;
      dispatchSigned(addr, msg, std::move(req), key,
        [this](const CesGiveAsset& req, const HashPrefix& ownerPrefix,
               const SockAddr& addr, const MinxMessage& msg) {
          uint8_t rc =
            giveAsset(req.ownerId, req.assetId, req.newOwnerId, req.reqNonce);

          CesGiveAssetResult res;
          res.ownerId = ownerPrefix;
          res.reqNonce = req.reqNonce;
          res.assetId = req.assetId;
          res.newOwnerId = req.newOwnerId;
          res.rcode = rc;
          sendSignedReply(addr, msg, std::move(res));
        });
      break;
    }

    case CES_QUERY_ASSET: {
      CesQueryAsset req;
      req.fromBytes(msg.data);
      Hash key = req.originId;
      dispatchSigned(addr, msg, std::move(req), key,
        [this](const CesQueryAsset& req, const HashPrefix& originPrefix,
               const SockAddr& addr, const MinxMessage& msg) {
          std::vector<AssetEntry> results;
          uint8_t rc = queryAsset(req.originId, req.assetId, req.items,
                                  req.reqNonce, results);

          CesQueryAssetResult res;
          res.originId = originPrefix;
          res.reqNonce = req.reqNonce;
          res.rcode = rc;
          if (rc == CES_OK) {
            res.assets = std::move(results);
            res.items = res.assets.empty() ? 0 : static_cast<uint8_t>(res.assets.size() - 1);
          } else {
            res.items = req.items;
          }
          sendSignedReply(addr, msg, std::move(res));
        });
      break;
    }

    case CES_UNSIGNED_QUERY_ACCOUNT: {
      CesUnsignedQueryAccount req;
      req.fromBytes(msg.data);
      postLogic( [this, addr, msg, req]() {
        int64_t bal = 0;
        uint32_t nonce = 0;
        HashPrefix lastXferDest{};
        uint64_t lastXferAmount = 0;
        uint32_t lastXferTime = 0;
        unsignedQueryAccount(req.accountMapKey, bal, nonce,
                             lastXferDest, lastXferAmount, lastXferTime);

        CesUnsignedQueryAccountResult res{req.accountMapKey, bal, nonce,
                                          lastXferDest, lastXferAmount,
                                          lastXferTime};
        sendUnsignedReply(addr, msg, std::move(res));
      });
      break;
    }

    case CES_UNSIGNED_QUERY_SOLUTION: {
      CesUnsignedQuerySolution req;
      req.fromBytes(msg.data);
      int queryResult = minx_->queryPoW(req.time, req.solution);
      CesUnsignedQuerySolutionResult res{req.solution,
                                         static_cast<uint8_t>(queryResult)};
      sendUnsignedReply(addr, msg, std::move(res));
      break;
    }

    case CES_UNSIGNED_QUERY_ASSET: {
      CesUnsignedQueryAsset req;
      req.fromBytes(msg.data);

      postLogic( [this, addr, msg, req]() {
        HashPrefix owner;
        AssetData content;
        uint16_t balance;
        uint32_t price;

        unsignedQueryAsset(req.assetId, owner, content, balance, price);

        // Check privacy: hide content from unsigned queries
        auto aa = assets_.get(req.assetId);
        if (aa.exists() && isAssetPrivate(aa.data().getBalance()))
          content = {};

        CesUnsignedQueryAssetResult res;
        res.assetId = req.assetId;
        res.ownerId = owner;
        res.content = content;
        res.balance = balance;
        res.price = price;
        sendUnsignedReply(addr, msg, std::move(res));
      });
      break;
    }

    case CES_QUERY_SERVER_INFO: {
      CesQueryServerInfo req;
      req.fromBytes(msg.data);
      Hash key = req.originId;
      dispatchSigned(addr, msg, std::move(req), key,
        [this](const CesQueryServerInfo& req, const HashPrefix& originPrefix,
               const SockAddr& addr, const MinxMessage& msg) {
          int64_t newBal = 0;
          std::vector<ServerInfoEntry> entries;
          uint8_t rc =
            queryServerInfo(req.originId, req.reqNonce, newBal, entries);

          CesQueryServerInfoResult res;
          res.originId = originPrefix;
          res.reqNonce = req.reqNonce;
          res.rcode = rc;
          if (rc == CES_OK)
            res.entries = std::move(entries);
          sendSignedReply(addr, msg, std::move(res));
        });
      break;
    }

    case CES_CROSS_TRANSFER: {
      CesCrossTransfer req;
      req.fromBytes(msg.data);
      Hash key = req.originId;
      dispatchSigned(addr, msg, std::move(req), key,
        [this](const CesCrossTransfer& req, const HashPrefix& originPrefix,
               const SockAddr& addr, const MinxMessage& msg) {
          int64_t newBal = 0;
          uint8_t rc = crossTransfer(req.originId, req.destKey, req.amount,
                                      req.destServer, req.reqNonce, newBal);

          CesCrossTransferResult res;
          res.originId = originPrefix;
          res.reqNonce = req.reqNonce;
          res.amount = req.amount;
          res.originNewBalance = newBal;
          res.rcode = rc;
          sendSignedReply(addr, msg, std::move(res));
        });
      break;
    }

    case CES_RUN_ASSET: {
      CesRunAsset req;
      req.fromBytes(msg.data);
      Hash key = req.originId;
      dispatchSigned(addr, msg, std::move(req), key,
        [this](const CesRunAsset& req, const HashPrefix& originPrefix,
               const SockAddr& addr, const MinxMessage& msg) {
          handleRunAsset(req, originPrefix, addr, msg);
        });
      break;
    }

    default:
      LOGTRACE << "unknown opcode";
      minx_->banAddress(addr.address());
      return;
    }
  } catch (const std::exception& e) {
    LOGTRACE << "malformed packet" << VAR(e.what());
    minx_->banAddress(addr.address());
    return;
  }
}

// ----------------------------------------------------------------------------
// handleRunAsset
// Invoked on logicStrand_ with an already-verified CesRunAsset. Manages
// the dedup window, gas debit + refund, undo log, deferred side effects,
// and VM execution.
// ----------------------------------------------------------------------------

void CesServer::handleRunAsset(const CesRunAsset& req,
                                const HashPrefix& originPrefix,
                                const SockAddr& addr,
                                const MinxMessage& msg) {
  CesRunAssetResult res;
  res.originId = originPrefix;
  res.vmError = CESVM_OK;
  res.budgetUsed = 0;
  res.allowanceUsed = 0;

  // --- Nonceless dedup ---
  uint32_t effectiveNonce = req.reqNonce;
  if (req.reqNonce == CES_NONCELESS) {
    uint64_t now = getMicrosSinceEpoch();
    if (req.time > now + DEDUP_FUTURE_DRIFT_US ||
        req.time + DEDUP_WINDOW_US < now) {
      res.reqNonce = req.reqNonce;
      res.rcode = CES_ERROR_WRONG_NONCE;
      sendSignedReply(addr, msg, std::move(res));
      return;
    }
    uint64_t sigHash;
    std::memcpy(&sigHash, req.sig.data(), sizeof(sigHash));
    if (!checkAndInsertDedup(sigHash)) {
      res.reqNonce = req.reqNonce;
      res.rcode = CES_OK; // already processed
      sendSignedReply(addr, msg, std::move(res));
      return;
    }
    auto acc = accounts_.get(originPrefix);
    effectiveNonce = acc.exists() ? acc.nonce() + 1 : 1;
  }
  res.reqNonce = effectiveNonce;

  // --- Pre-execution: validate and debit gas ---
  {
    auto origin = accounts_.get(originPrefix);
    uint8_t rc = origin.validateSpend(0, req.budget, effectiveNonce,
                                      resolveFee(-1, cfg_.getFeeError()));
    if (rc != CES_OK) {
      res.rcode = rc;
      sendSignedReply(addr, msg, std::move(res));
      return;
    }
    // Reserve the full budget upfront (WAL-logged, nonce incremented).
    // Unused portion is refunded once the VM finishes — see the
    // refund block after vm.execute returns.
    origin.debit(req.budget);
    accounts_.checkFlush(req.budget);
  }

  // --- Scheduled execution? ---
  if (req.time > 0 && req.reqNonce != CES_NONCELESS) {
    uint64_t now = getMicrosSinceEpoch();
    if (req.time > now) {
      // Schedule for future execution — gas already debited.
      // Allowance from the wire: an originally-signed runAsset with
      // a future time queues a single delayed run; the cap travels
      // verbatim into the eventual execution.
      res.rcode = scheduleRun(originPrefix, req.assetId, req.budget,
                              req.allowance, req.input, req.time);
      sendSignedReply(addr, msg, std::move(res));
      return;
    }
  }

  // --- Load program asset ---
  auto programAsset = assets_.get(req.assetId);
  if (!programAsset.exists()) {
    res.rcode = CES_ERROR_ASSET_NOT_FOUND;
    sendSignedReply(addr, msg, std::move(res));
    return;
  }

  HashPrefix programOwnerPrefix = programAsset.data().getOwnerId();
  AssetData programContent = programAsset.data().getContent();

  // --- Atomic context: undo log + deferred effects ---
  struct UndoEntry {
    bool isAccount;
    HashPrefix accountKey;
    Account oldAccount;
    bool accountExisted;
    minx::Hash assetKey;
    Asset oldAsset;
    bool assetExisted;
  };
  std::vector<UndoEntry> undoLog;

  struct DeferredUdp {
    std::string addr;
    uint16_t port;
    ces::Bytes data;
  };
  struct DeferredCrossXfer {
    minx::Hash dest;
    uint64_t amount;
    std::string server;
    minx::Hash peerKey; // resolved at syscall time by setupVmHost
  };
  std::vector<DeferredUdp> deferredUdp;
  std::vector<DeferredCrossXfer> deferredCrossXfers;

  // Helper: save account state before mutation
  auto saveAccount = [&](const HashPrefix& id) {
    auto it = accounts_->find(id);
    UndoEntry e{};
    e.isAccount = true;
    e.accountKey = id;
    if (it != accounts_->end()) {
      e.oldAccount = it->second;
      e.accountExisted = true;
    } else {
      e.accountExisted = false;
    }
    undoLog.push_back(std::move(e));
  };

  // Helper: save asset state before mutation
  auto saveAsset = [&](const minx::Hash& id) {
    auto it = assets_->find(id);
    UndoEntry e{};
    e.isAccount = false;
    e.assetKey = id;
    if (it != assets_->end()) {
      e.oldAsset = it->second;
      e.assetExisted = true;
    } else {
      e.assetExisted = false;
    }
    undoLog.push_back(std::move(e));
  };

  // Helper: revert all undo entries in reverse order
  auto revert = [&]() {
    for (auto it = undoLog.rbegin(); it != undoLog.rend(); ++it) {
      if (it->isAccount) {
        if (it->accountExisted) {
          auto mapIt = accounts_->find(it->accountKey);
          if (mapIt != accounts_->end())
            mapIt->second = it->oldAccount;
          else
            accounts_->getObjects().emplace(it->accountKey, it->oldAccount);
        } else {
          accounts_->getObjects().erase(it->accountKey);
        }
      } else {
        if (it->assetExisted) {
          auto mapIt = assets_->find(it->assetKey);
          if (mapIt != assets_->end())
            mapIt->second = it->oldAsset;
          else
            assets_->getObjects().emplace(it->assetKey, it->oldAsset);
        } else {
          assets_->getObjects().erase(it->assetKey);
        }
      }
    }
  };

  // --- Wire CesVMHost ---
  VmHostSetup setup;
  setup.callerPrefix = originPrefix;
  setup.programOwnerPrefix = programOwnerPrefix;
  setup.saveAccountFn = [&](const HashPrefix& id) { saveAccount(id); };
  setup.saveAssetFn = [&](const minx::Hash& key) { saveAsset(key); };
  setup.sendUdpFn = [&](const std::string& addr, uint16_t port,
                        const uint8_t* data, size_t len) {
    deferredUdp.push_back({addr, port, {data, data + len}});
  };
  setup.crossTransferFn = [&](const minx::Hash& dest, uint64_t amount,
                               const std::string& server,
                               const minx::Hash& peerKey) {
    deferredCrossXfers.push_back({dest, amount, server, peerKey});
  };
  setup.enableVerifySig = true;
  setup.allowance = req.allowance;

  VmHost vmHost(*this, setup);
  vmHost.callerKey    = req.originId;
  vmHost.selfAssetKey = req.assetId;
  vmHost.programOwner = programOwnerPrefix;
  vmHost.input        = req.input;

  // --- Execute VM ---
  CesVM vm;
  ces::Bytes code(programContent.begin(), programContent.end());
  CesVMResult vmResult;
  // Catch any exception that escapes the VM (host lambda throwing,
  // logkv serialization error, std::bad_alloc, CryptoPP throw, etc.)
  // so we don't fall through to incomingMessage's outer catch, which
  // treats a throw as a malformed-packet signal and bans the sender's
  // IP. A VM exception is a server-side failure, not client abuse.
  try {
    vmResult = vm.execute(code, vmHost, req.budget,
                          discountFee(FeeKind::VMMult, cfg_.feeVmMult));
  } catch (...) {
    vmResult.error = CESVM_HOST;
    // budgetUsed stays whatever the partial execution charged. The
    // error branch below reverts side effects and refunds.
  }

  res.vmError = vmResult.error;
  res.budgetUsed = vmResult.budgetUsed;
  // Allowance consumed = initial cap minus what's left. The unlimited
  // sentinel skips decrement entirely (see debitCaller in setupVmHost),
  // so that case naturally reports 0.
  if (req.allowance != std::numeric_limits<uint64_t>::max() &&
      vmHost.allowance <= req.allowance) {
    res.allowanceUsed = req.allowance - vmHost.allowance;
  } else {
    res.allowanceUsed = 0;
  }

  if (vmResult.error == CESVM_OK) {
    // Commit: fire deferred effects, output available
    res.rcode = CES_OK;
    res.output = std::move(vmResult.output);
    // Fire deferred UDP sends
    for (auto& udp : deferredUdp) {
      try {
        if (minx_) {
          minx::Bytes payload;
          ces::Buffer::putBytes(payload,
            std::span<const uint8_t>(udp.data));
          minx_->sendApplication(
            SockAddr(Resolver::parseIp(udp.addr), udp.port),
            payload);
        }
      } catch (...) {}
    }
    // Fire deferred cross-transfers. The accounting (caller debit, peer
    // vostro credit) already ran in the VM host lambda via the undo
    // log, so all that remains is dispatching the wire-level settlement
    // over CesClientAsync. Fire-and-forget: the VM already returned
    // CES_OK for the syscall, we have no way to surface a late delivery
    // failure back to the program.
    for (auto& cx : deferredCrossXfers) {
      auto* client = getOrCreateSettlementClient(cx.server, cx.peerKey);
      if (client) {
        client->openTransfer(cx.dest, cx.amount, [](uint8_t) {});
      }
    }
  } else {
    // Revert all atomic mutations
    revert();
    res.rcode = CES_ERROR_VM_FAILED;
  }
  // Refund unused budget on every termination path. ABORT and OK get
  // the full unused remainder; non-abort failures (crashes) eat a
  // small crash fee on top of budgetUsed.
  uint64_t penalty = (vmResult.error == CESVM_OK ||
                      vmResult.error == CESVM_ABORT)
                       ? 0
                       : CESVM_CRASH_FEE;
  uint64_t spent = vmResult.budgetUsed + penalty;
  if (spent < req.budget) {
    auto caller = accounts_.get(originPrefix);
    if (caller.exists())
      caller.credit(req.budget - spent);
  }

  tpsInc();
  checkAutoSnapshot();
  sendSignedReply(addr, msg, std::move(res));
}

void CesServer::incomingGetInfo(const SockAddr& addr, const MinxGetInfo& msg) {
  checkPause();
  LOGTRACE << "got MinxGetInfo" << VAR(addr);
  uint64_t now = minx::getSecsSinceEpoch();
  uint64_t minUntilAcceptPoW;
  if (now > cfg_.minProveWorkTimestamp) {
    minUntilAcceptPoW = 0;
  } else {
    minUntilAcceptPoW = (cfg_.minProveWorkTimestamp - now) / 60;
    if (minUntilAcceptPoW == 0)
      minUntilAcceptPoW = 1;
    else if (minUntilAcceptPoW > 255)
      minUntilAcceptPoW = 255;
  }
  uint8_t minSecsPoW = static_cast<uint8_t>(minUntilAcceptPoW);

  if (now > lastTimePoWQueueSizeUpdated_ + POW_QUEUE_REFRESH_SECS) {
    lastTimePoWQueueSizeUpdated_ = now;
    size_t q = minx_->getVerifyPoWQueueSize();
    constexpr size_t kU16Max = std::numeric_limits<uint16_t>::max();
    if (q > kU16Max)
      q = kU16Max;
    powQueueSize_ = q;
  }
  uint16_t pendingPoWs = powQueueSize_.load(std::memory_order_relaxed);
  uint16_t tps = tpsCurrent_.load(std::memory_order_relaxed);
  uint16_t rpcPort = rpcBoundPort_;

  minx::Bytes rdata(sizeof(minSecsPoW) + sizeof(pendingPoWs) + sizeof(tps) +
              sizeof(rpcPort));
  minx::Buffer rces(rdata);
  rces.put(minSecsPoW);
  rces.put(pendingPoWs);
  rces.put(tps);
  rces.put(rpcPort);
  auto rmsg =
    MinxInfo{msg.version,  minx_->generatePassword(),     msg.gpassword,
             cfg_.minDiff, serverKeyPair_.getPublicKeyAsHash(), std::move(rdata)};
  minx_->sendInfo(addr, rmsg);
}

void CesServer::incomingInfo(const SockAddr& addr, const MinxInfo& /* msg */) {
  checkPause();
  LOGTRACE << "got MinxInfo" << VAR(addr);
  minx_->banAddress(addr.address());
}

bool CesServer::delegateProveWork(const SockAddr& addr,
                                  const MinxProveWork& /* msg */) {
  checkPause();
  if (!receiving_ || !running_)
    return false;
  if (minx_->checkSpam(addr.address()))
    return false;
  if (minx_->getVerifyPoWQueueSize() >= POW_QUEUE_DELEGATE_LIMIT)
    return false;
  return true;
}

void CesServer::incomingProveWork(const SockAddr& addr,
                                  const MinxProveWork& msg,
                                  const int difficulty) {
  checkPause();
  postLogic( [this, addr, msg, difficulty]() {
    minx::Hash actualBeneficiaryFullKey;
    HashPrefix mapKey = Account::getMapKey(msg.ckey);
    uint64_t generatedAmount = (1ULL << (difficulty - 1)) * POW_REWARD_BASE;
    uint64_t creditAmount = generatedAmount;

    ActiveAccount acc = accounts_.get(mapKey);

    if (!acc.exists()) {
      if (accounts_.getStore().getObjects().size() >= cfg_.maxAcc)
        return;
      actualBeneficiaryFullKey = msg.ckey;
      // Account-slot allocation on the PoW-mint side is intentionally
      // raw (no FeeKind::AccountRent discount). Daily account rent
      // (search for cfg_.feeAccount under daily maintenance below)
      // discounts because that is consumer carrying cost; here we
      // are charging the structural cost of bringing a new slot
      // into existence. Discounting it would subsidize account
      // creation from minting, opening a Sybil vector.
      if (creditAmount < cfg_.feeAccount)
        return;
      creditAmount -= cfg_.feeAccount;
      Account newAccount(msg.ckey, creditAmount, 0);
      accounts_.createAccount(mapKey, newAccount);
    } else {
      if (acc.balance() < 0)
        return;
      actualBeneficiaryFullKey = acc.data().getKey(mapKey);
      acc.credit(creditAmount);
    }

    tpsInc();

    // Collect inbound peer info from appData (if present)
    if (!msg.data.empty()) {
      try {
        std::map<std::string, std::string> appData;
        logkv::serializer<std::map<std::string, std::string>>::read(
          msg.data.data(), msg.data.size(), appData);
        auto it = appData.find("server");
        if (it != appData.end() && !it->second.empty()) {
          upsertPeer(msg.ckey, it->second, creditAmount);
          LOGDEBUG << "inbound peer PoW: " << it->second
                   << " credited " << creditAmount;
        }
      } catch (...) {
        // Invalid appData — ignore silently
      }
    }

    CesProveWorkResult res{msg.solution, actualBeneficiaryFullKey, creditAmount,
                           getSecsSinceEpoch(), {}};

    boost::asio::post(taskIO_, [this, addr, msg, res]() mutable {
      reply(addr, MinxMessage{msg.version, minx_->generatePassword(),
                              msg.gpassword, res.toBytes(serverKeyPair_)});
    });
  });
}

void CesServer::incomingApplication(const SockAddr& addr, const uint8_t code,
                                    const minx::Bytes& data) {
  if (code == CES_APP_COMPUTE_MSG) {
    // Hop onto rpcTaskIO_ — the compute handler's strand owns the
    // instance map + peer sockets. We have a plain minx::Bytes here, copy
    // into a shared_ptr so the closure owns it.
    auto io = _rpcTaskIOExecutor();
    if (!io) return; // compute feature not wired (rpc port off)
    auto buf = std::make_shared<minx::Bytes>(data);
    // Stamp the real sender_pfx from the presence cache so the
    // program can ces.client_send a reply. If the client isn't
    // in presence yet (unsigned-only traffic), the senderPfx
    // stays zeroed and the program has no way to reply. Not a
    // protocol error — that caller should have done a signed op
    // first.
    std::array<uint8_t, 8> senderPfx{};
    {
      std::lock_guard lk(presenceReverseMutex_);
      auto it = presenceReverse_.find(addr);
      if (it != presenceReverse_.end()) senderPfx = it->second;
    }
    boost::asio::post(io, [buf, senderPfx]() {
      computeHandlerOnApplicationMsg(
        reinterpret_cast<const uint8_t*>(buf->data()), buf->size(),
        senderPfx);
    });
    return;
  }
  minx_->banAddress(addr.address());
}

void CesServer::reply(const SockAddr& addr, const MinxMessage& msg) {
  try {
    minx_->sendMessage(addr, msg);
  } catch (...) {
  }

  auto now = std::chrono::steady_clock::now();
  {
    std::lock_guard lock(replyMutex_);
    replyQueueFast_.push_back(
      {addr, msg, now + std::chrono::milliseconds(REPLY_FAST_DELAY_MS)});
  }
}

void CesServer::replyStartTimer() {
  if (!replyTimer_) {
    replyTimer_ = std::make_shared<boost::asio::steady_timer>(taskIO_);
  }
  replyTimer_->expires_after(std::chrono::milliseconds(REPLY_TIMER_INITIAL_MS));
  replyTimer_->async_wait(
    [this](const boost::system::error_code& ec) { replyTick(ec); });
}

void CesServer::replyTick(const boost::system::error_code& ec) {
  if (ec)
    return;

  auto now = std::chrono::steady_clock::now();
  std::lock_guard lock(replyMutex_);

  while (!replyQueueFast_.empty()) {
    auto& item = replyQueueFast_.front();
    if (item.triggerTime > now)
      break;

    try {
      minx_->sendMessage(item.addr, item.msg);
    } catch (...) {
    }

    item.triggerTime =
      now + std::chrono::milliseconds(REPLY_SLOW_DELAY_MS);
    replyQueueSlow_.push_back(std::move(item));

    replyQueueFast_.pop_front();
  }

  while (!replyQueueSlow_.empty()) {
    auto& item = replyQueueSlow_.front();
    if (item.triggerTime > now)
      break;

    try {
      minx_->sendMessage(item.addr, item.msg);
    } catch (...) {
    }

    replyQueueSlow_.pop_front();
  }

  replyTimer_->expires_after(std::chrono::milliseconds(REPLY_TIMER_TICK_MS));
  replyTimer_->async_wait([this](const auto& e) { replyTick(e); });
}

void CesServer::tpsInc() {
  tpsGauge_.record(1);
  ++txCount_;
}

// Run the metrics readout / sample / roll / multiplier-refresh logic
// once, on taskIO_, and wait for it to finish. Same path the live
// timer drives — letting tests exercise the wiring without sleeping.
// Serializing on taskIO_ also keeps net-sampler state (lastNetCumulative_,
// netPeakBps_) free of data races against the live tick.
void CesServer::runMetricsTickOnce() {
  std::promise<void> done;
  auto fut = done.get_future();
  boost::asio::post(taskIO_, [this, &done]() {
    metricsCompute();
    done.set_value();
  });
  fut.wait();
}

// Body of one tick. Touches mutable net-sampler doubles, must run on
// taskIO_ to serialize with the timer-driven invocation.
void CesServer::metricsCompute() {
  // tps: average ops/sec across the 60s window.
  uint64_t tpsAvg = tpsGauge_.average();
  constexpr uint64_t kU16Max = std::numeric_limits<uint16_t>::max();
  if (tpsAvg > kU16Max)
    tpsAvg = kU16Max;
  tpsCurrent_.store(static_cast<uint16_t>(tpsAvg), std::memory_order_relaxed);

  // l1cpu: strand busy_ns over the 60s window. 100% utilization of one
  // strand-thread for 60s = 60 * 1e9 ns. Cap at 10000 bp.
  constexpr uint64_t kWindowNs = 60ULL * 1'000'000'000ULL;
  uint64_t busyNs = l1cpuGauge_.sum();
  l1cpuBp_.store(clampBp(busyNs * 10000ULL / kWindowNs));

  // l2cpu: /proc/loadavg field 1, normalized by hardware concurrency.
  unsigned int hwc = std::thread::hardware_concurrency();
  if (hwc == 0) hwc = 1;
  double loadavg = readLoadAvg();
  uint64_t l2cpuRaw = static_cast<uint64_t>(loadavg * 10000.0 / hwc);
  l2cpuBp_.store(clampBp(l2cpuRaw));

  // l2mem: /proc/meminfo (MemTotal-MemAvailable)/MemTotal.
  l2memBp_.store(clampBp(readMemUsedBp()));

  // l1memac, l1memas: store sizes — must be read on logicStrand_.
  postLogic([this]() {
    if (cfg_.maxAcc > 0) {
      uint64_t sz = static_cast<uint64_t>(accounts_->getObjects().size());
      l1memacBp_.store(clampBp(sz * 10000ULL / cfg_.maxAcc));
    }
    if (cfg_.maxAsset > 0) {
      uint64_t sz = static_cast<uint64_t>(assets_->getObjects().size());
      l1memasBp_.store(clampBp(sz * 10000ULL / cfg_.maxAsset));
    }
  });

  // net: bytes/sec averaged over 60s, with EWMA-decaying RAM peak.
  // First tick has no previous reading — establish baseline only.
  uint64_t netCumulative = readNetCumulative();
  if (lastNetCumulativeValid_) {
    uint64_t delta = (netCumulative >= lastNetCumulative_)
                         ? netCumulative - lastNetCumulative_
                         : 0;
    netRxTxGauge_.record(delta);
  }
  lastNetCumulative_ = netCumulative;
  lastNetCumulativeValid_ = true;

  uint64_t currentBps = netRxTxGauge_.average();
  // Lifetime watermark: the highest sustained throughput we've seen on
  // this host since process start. "100%" means "as busy as we've ever
  // been." Stable reference, no time-decay tunable, never-decreasing
  // until a new high arrives.
  if (static_cast<double>(currentBps) > netPeakBps_)
    netPeakBps_ = static_cast<double>(currentBps);
  if (netPeakBps_ > 0.0) {
    uint64_t bp = static_cast<uint64_t>(
      static_cast<double>(currentBps) * 10000.0 / netPeakBps_);
    netBp_.store(clampBp(bp));
  } else {
    netBp_.store(0);
  }

  // Roll all bucket gauges into the next 1s slot.
  tpsGauge_.roll();
  l1cpuGauge_.roll();
  netRxTxGauge_.roll();

  // Refresh per-FeeKind multipliers from the gauge each is mapped to.
  // Pinned to 10000 (full price) when the discount is disabled.
  //
  // Invariant: the mapper must never write 0 into a multiplier just
  // because its source gauge is at 0. Two distinct cases:
  //   (a) the gauge is well-defined and legitimately reads 0
  //       (e.g. l1cpuBp_ when the strand is fully idle)
  //   (b) the gauge is undefined — i.e. its computation requires a
  //       config knob that's zero, so metricsCompute skips updating
  //       it (l1memacBp_ when maxAcc=0; l1memasBp_ when maxAsset=0).
  // Case (a) is the discount working; case (b) would charge zero
  // fees forever, which is the worst possible failure mode. Snap
  // undefined gauges to 10000 here so debit sites stay safe.
  if (cfg_.feeDiscountEnabled) {
    auto set = [&](FeeKind k, uint16_t bp) {
      feeMult_[static_cast<std::size_t>(k)].store(bp,
        std::memory_order_relaxed);
    };
    uint16_t l1cpu = static_cast<uint16_t>(l1cpuBp_.load());
    uint16_t l1mac = (cfg_.maxAcc   > 0) ? static_cast<uint16_t>(l1memacBp_.load()) : 10000;
    uint16_t l1mas = (cfg_.maxAsset > 0) ? static_cast<uint16_t>(l1memasBp_.load()) : 10000;
    uint16_t l2cpu = static_cast<uint16_t>(l2cpuBp_.load());
    uint16_t l2mem = static_cast<uint16_t>(l2memBp_.load());
    // netPeakBps_ is 0 until the first non-zero rx+tx delta is seen.
    // Until then, netBp_ reads 0 — undefined for fee purposes, snap
    // to 10000 (same pattern as the maxAcc=0 / maxAsset=0 cases).
    uint16_t net   = (netPeakBps_ > 0.0) ? static_cast<uint16_t>(netBp_.load()) : 10000;
    set(FeeKind::Tx,            l1cpu);
    set(FeeKind::Query,         l1cpu);
    set(FeeKind::VMMult,        l1cpu);
    set(FeeKind::AccountRent,   l1mac);
    set(FeeKind::AssetRent,     l1mas);
    set(FeeKind::ComputeSlot,   l2cpu);
    set(FeeKind::ComputeCpu,    l2cpu);
    set(FeeKind::ComputeRss,    l2mem);
    set(FeeKind::BucketByteSec, l2mem);
    set(FeeKind::Net,           net);
  } else {
    for (auto& m : feeMult_)
      m.store(10000, std::memory_order_relaxed);
  }
}

// Single 1Hz pulse. Already runs on taskIO_ via the timer — call
// metricsCompute directly (no post + wait dance) and reschedule.
void CesServer::metricsTick(const boost::system::error_code& ec) {
  if (ec)
    return;
  metricsCompute();
  metricsTimer_->expires_at(metricsTimer_->expiry() + std::chrono::seconds(1));
  metricsTimer_->async_wait(
    [this](const boost::system::error_code& ec) { metricsTick(ec); });
}

// Defers to computePrepayCost (feemult.h) so cesvm.cpp's syscall path
// bills off the same formula as the wire-protocol path.
uint64_t CesServer::attenuatedFundCost(FeeKind k,
                                       uint64_t feePerDay,
                                       uint32_t daysAdded,
                                       uint32_t daysAlreadyHeld) const {
  return computePrepayCost(feePerDay, getFeeMult(k),
                           daysAdded, daysAlreadyHeld);
}

double CesServer::readLoadAvg() {
  std::ifstream f("/proc/loadavg");
  if (!f) return 0.0;
  double v = 0.0;
  f >> v;
  return v;
}

uint64_t CesServer::readMemUsedBp() {
  std::ifstream f("/proc/meminfo");
  if (!f) return 0;
  uint64_t total = 0, available = 0;
  std::string line;
  while (std::getline(f, line)) {
    auto digit = line.find_first_of("0123456789");
    if (digit == std::string::npos) continue;
    if (line.starts_with("MemTotal:")) {
      total = std::stoull(line.substr(digit));
    } else if (line.starts_with("MemAvailable:")) {
      available = std::stoull(line.substr(digit));
    }
    if (total && available) break;
  }
  if (total == 0 || available > total) return 0;
  uint64_t used = total - available;
  return used * 10000ULL / total;
}

uint64_t CesServer::readNetCumulative() {
  // /proc/net/dev format:
  //   Inter-|   Receive                                                |  Transmit
  //    face |bytes packets errs drop fifo frame compressed multicast | bytes packets ...
  //   eth0:  12345  100   0    0    0    0     0          0           67890  120 ...
  //     lo:  ...
  std::ifstream f("/proc/net/dev");
  if (!f) return 0;
  std::string line;
  // skip two header lines
  std::getline(f, line);
  std::getline(f, line);
  uint64_t total = 0;
  while (std::getline(f, line)) {
    auto colon = line.find(':');
    if (colon == std::string::npos) continue;
    std::string ifname = line.substr(0, colon);
    auto first = ifname.find_first_not_of(" \t");
    auto last = ifname.find_last_not_of(" \t");
    if (first == std::string::npos) continue;
    ifname = ifname.substr(first, last - first + 1);
    if (ifname == "lo") continue;
    std::istringstream iss(line.substr(colon + 1));
    uint64_t rx = 0, tx = 0, skip = 0;
    iss >> rx;
    for (int i = 0; i < 7; ++i) iss >> skip;
    iss >> tx;
    total += rx + tx;
  }
  return total;
}

void CesServer::metricsStartTimer() {
  if (!metricsTimer_)
    metricsTimer_ = std::make_shared<boost::asio::steady_timer>(taskIO_);
  metricsTimer_->expires_after(std::chrono::seconds(1));
  metricsTimer_->async_wait(
    [this](const boost::system::error_code& ec) { metricsTick(ec); });
}

void CesServer::dailyTaskTick(const boost::system::error_code& ec) {
  if (ec)
    return;

  postLogic( [this]() {
    size_t accBefore = 0, accPayExpired = 0, accFeeDeleted = 0,
           accFeeDebited = 0;
    int64_t creditsDelta = 0;
    {
      // Daily account rent — billed at today's discounted rate. The
      // discount for AccountRent floats with l1memac (account slot
      // pressure), so an idle ledger costs ~nothing to keep accounts
      // alive while a saturated ledger pays full BASE_FEE_ACCOUNT.
      uint64_t dailyAccFee = discountFee(FeeKind::AccountRent,
                                         cfg_.feeAccount);
      auto& map = accounts_.getStore().getObjects();
      accBefore = map.size();
      boost::unordered::erase_if(map, [&](auto& pair) {
        Account& acc = pair.second;
        int64_t bal = acc.getBalance();
        if (bal < 0) {
          // Payment account (negative balance = marker, no real credits)
          uint32_t nonce = acc.getNonce();
          if (nonce <= 1) {
            ++accPayExpired;
            return true;
          }
          acc.setNonce(nonce - 1);
        } else {
          if (bal <= static_cast<int64_t>(dailyAccFee)) {
            creditsDelta -= bal;
            ++accFeeDeleted;
            return true;
          }
          creditsDelta -= static_cast<int64_t>(dailyAccFee);
          acc.setBalance(bal - static_cast<int64_t>(dailyAccFee));
          ++accFeeDebited;
        }
        return false;
      });
      accounts_.adjustTotalCredits(creditsDelta);
    }
    size_t astBefore = 0, astExpired = 0;
    {
      auto& map = assets_->getObjects();
      astBefore = map.size();
      boost::unordered::erase_if(map, [&](auto& pair) {
        Asset& asset = pair.second;
        bool priv = isAssetPrivate(asset.getBalance());
        bool aowned = isAssetOwned(asset.getBalance());
        bool immut = isAssetImmutable(asset.getBalance());
        uint16_t days = assetDays(asset.getBalance());
        if (days <= 1) {
          ++astExpired;
          return true;
        }
        asset.setBalance(assetBalance(days - 1, priv, aowned, immut));
        return false;
      });
    }
    LOGINFO << "daily maintenance"
            << VAR(accBefore) << VAR(accPayExpired)
            << VAR(accFeeDeleted) << VAR(accFeeDebited)
            << VAR(creditsDelta)
            << VAR(astBefore) << VAR(astExpired);
    doSnapshot("daily maintenance");
  });

  // File-store rent is collected lazily (per-op + JIT GC on CREATE).
  // No daily pass needed.

  dailyTaskStartTimer();
}

void CesServer::dailyTaskStartTimer() {
  if (!dailyTimer_)
    dailyTimer_ = std::make_shared<boost::asio::system_timer>(taskIO_);
  auto now = std::chrono::system_clock::now();
  uint64_t nowSec =
    std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch())
      .count();
  uint64_t secondsIntoDay = nowSec % SECS_PER_DAY;
  uint64_t targetSeconds = DAILY_MAINTENANCE_HOUR_UTC * 3600;
  uint64_t secondsToWait;
  if (secondsIntoDay < targetSeconds)
    secondsToWait = targetSeconds - secondsIntoDay;
  else
    secondsToWait = (SECS_PER_DAY - secondsIntoDay) + targetSeconds;
  dailyTimer_->expires_from_now(std::chrono::seconds(secondsToWait));
  dailyTimer_->async_wait(
    [this](const boost::system::error_code& ec) { dailyTaskTick(ec); });
}

void CesServer::_runDailyMaintenance() {
  boost::system::error_code ec;
  dailyTaskTick(ec);
}

void CesServer::_brr(const minx::Hash& accountKey, int64_t amount) {
  if (running_) {
    postLogic( [this, accountKey, amount]() {
      _brrInner(accountKey, amount);
    });
  } else {
    _brrInner(accountKey, amount);
  }
}

// Boot-time autolaunch of /s/ builtin apps. For each name in
// cfg_.builtinApps, calls computeHandlerLaunchInternal on
// /s/<name>.lua. The file itself is operator-deployed: drop it into
// <storeDir>/s/, the file handler's startup reconcile auto-generates
// the sidecar before this runs. Source missing → WRN, skip; the
// server keeps running.
//
// Runs on rpcTaskIO_ (caller posts it there). Posted after
// fileHandlerStartupReconcile so reconcile has already filled in any
// missing /s/ sidecars.
void CesServer::launchBuiltinApps() {
  for (const auto& name : cfg_.builtinApps) {
    std::string path = "/s/" + name + ".lua";
    uint8_t rc = computeHandlerLaunchInternal(path);
    if (rc != CES_OK) {
      LOGWARNING << "builtin_app: launch failed"
                 << SVAR(name) << SVAR(path) << VAR(int(rc));
      continue;
    }
    LOGINFO << "builtin_app launched"
            << SVAR(name) << SVAR(path);
  }
}

// Boot-time reset of the server's own account to exactly TARGET. Created
// at TARGET if absent; otherwise its balance is forced to TARGET whether
// it was below or above. The server account is uncounted and bottomless
// by design (see server.h).
//
// TARGET = 2^60, far below INT64_MAX so signed-int64 addition for incoming
// transfers (dice bets, fee receipts) cannot overflow. Forcing rather than
// topping up heals a stale balance corrupted (negative or near-saturation)
// by an older build, instead of overshooting it.
//
// Runs on logicStrand_ (caller posts it there).
void CesServer::topUpServerAccount() {
  static constexpr int64_t TARGET = int64_t(1) << 60;
  const minx::Hash& serverPubKey = serverKeyPair_.getPublicKeyAsHash();
  ActiveAccount acc = accounts_.get(serverPubKey);

  // Fresh account: create it at TARGET.
  if (!acc.exists()) {
    accounts_.createAccount(Account::getMapKey(serverPubKey),
                            Account(serverPubKey, TARGET, 0));
    LOGINFO << "server account created at bottomless target" << VAR(TARGET);
    return;
  }

  // Existing account: force the balance to exactly TARGET — reset it
  // whether it's below (underfunded) or above (accumulated deposits, or
  // a stale value corrupted negative / near-saturation by an older
  // build). Forcing rather than topping up means a wrong balance can
  // never get stuck overflowed. Uncounted, so totalCredits_ is untouched.
  int64_t cur = acc.balance();
  if (cur == TARGET) return;
  acc.data().setBalance(TARGET);
  Account::SerModeGuard guard(Account::SerMode::Full);
  accounts_->persist(acc.it);
  LOGINFO << "server account forced to bottomless target"
          << VAR(cur) << VAR(TARGET);
}

namespace {

// /b/dice — fair-coin double-or-nothing as pure-L1 bytecode.
//
// No input data, no preloaded house pubkey: the program uses
// SYS_DEPOSIT (caller → owner) for the bet and SYS_WITHDRAW (owner →
// caller) for the heads payout. Both endpoints are implicit on the
// C++ side. cesh just signs CES_RUN_ASSET with allowance = bet.
//
// Why allowance == bet works:
//   - Allowance is the cap on caller-side *spending* (transfer
//     amounts), not on protocol fees.
//   - Syscall fees (feeTx) come out of the run's pre-paid `budget`
//     via CesVM::billCredits — separate accounting bucket.
//
// VM flow:
//   1. Snapshot the bet (= io[ALLOWANCE]) into GPR0 — step 2 will
//      drain io[ALLOWANCE] to zero, but we still need 2*bet for the
//      heads payout in step 5.
//   2. SYS_DEPOSIT amount = GPR0 (caller pays owner the bet).
//   3. OP_RND fills R; R & 1 = the coin.
//   4. JF tails on R == 0.
//   5. heads: SHL bet, 1 -> R = 2*bet. SYS_WITHDRAW amount = R
//             (owner pays caller). Output byte 0 = 0x01.
//   6. tails: output byte 0 = 0x00.
//
// Net heads: caller -N (deposit) +2N (withdraw) = +N. Owner net -N.
// Net tails: caller -N. Owner +N.
ces::AssetData buildDiceVmProgram() {
  ces::VmProgram p;
  ces::VmLabel tails = p.label();

  // Snapshot bet — SYS_DEPOSIT will zero io[ALLOWANCE].
  p.set(ces::Imm(ces::CESVM_CELL_GPR0),
        ces::Ref(ces::CESVM_IO_ALLOWANCE));

  // Caller deposits the bet to the owner (the house).
  p.sysDeposit({.amount = ces::Ref(ces::CESVM_CELL_GPR0)});

  // Coin flip.
  p.rnd();
  p.and_(ces::Ref(ces::CESVM_CELL_R), ces::Imm(1));
  p.jf(ces::Ref(ces::CESVM_CELL_R), tails);

  // Heads: owner withdraws 2 * bet to caller.
  p.shl(ces::Ref(ces::CESVM_CELL_GPR0), ces::Imm(1));
  p.sysWithdraw({.amount = ces::Ref(ces::CESVM_CELL_R)});
  p.setOutput(ces::Imm(0x01), 1);  // HEADS marker
  p.term();

  // Tails: bet stays with the owner, output 0x00.
  p.place(tails);
  p.setOutput(ces::Imm(0x00), 1);
  p.term();

  return p.buildBootBlock();
}

} // namespace

void CesServer::deployBuiltinVmPrograms() {
  // Single shipped program for now: /b/dice. Add more here as they
  // come; each entry is (path, bytecode-builder).
  const std::string path = "/b/dice";
  AssetData content = buildDiceVmProgram();

  // Asset key derivation matches cesh's parseAssetKey for short
  // names: literal path bytes, zero-padded to 32 bytes. Lets users
  // refer to the program as `/b/dice` from the CLI without any extra
  // resolver step on the cesh side.
  minx::Hash key{};
  std::memcpy(key.data(), path.data(),
              std::min(path.size(), key.size()));

  HashPrefix serverOwner =
    Account::getMapKey(serverKeyPair_.getPublicKeyAsHash());

  // Canonical state: server-owned, current bytecode, max days, no
  // private/asset-owned/immutable bits, no price. Same struct on
  // first boot, on every subsequent boot, and after any squat.
  uint16_t bal = assetBalance(/*days=*/0x1FFF, /*priv=*/false,
                               /*assetOwned=*/false, /*immutable=*/false);
  Asset canonical(serverOwner, content, bal, /*price=*/0);

  Asset::SerModeGuard guard(Asset::SerMode::Full);
  assets_->update(key, canonical);

  LOGINFO << "deployed /b/<name> bytecode program" << SVAR(path);
}

void CesServer::_brrInner(const minx::Hash& accountKey, int64_t amount) {
  HashPrefix id = Account::getMapKey(accountKey);
  ActiveAccount acc = accounts_.get(id);
  if (acc.exists()) {
    acc.credit(amount);
  } else {
    Account newAcc(accountKey, amount, 0);
    accounts_.createAccount(id, newAcc);
  }
}

void CesServer::_burn(const minx::Hash& accountKey, int64_t amount) {
  if (running_) {
    postLogic( [this, accountKey, amount]() {
      _burnInner(accountKey, amount);
    });
  } else {
    _burnInner(accountKey, amount);
  }
}

void CesServer::_burnInner(const minx::Hash& accountKey, int64_t amount) {
  HashPrefix id = Account::getMapKey(accountKey);
  ActiveAccount acc = accounts_.get(id);
  if (acc.exists()) {
    int64_t bal = acc.balance();
    int64_t toDebit = std::min(amount, bal);
    if (toDebit > 0)
      acc.debit(static_cast<uint64_t>(toDebit));
  }
}

void CesServer::_l2ValidateDedupAndDebit(
    const ces::PublicKey& signer,
    int64_t amount,
    uint32_t reqNonce,
    uint64_t timeUs,
    uint64_t sigHash,
    std::function<void(uint8_t rc)> cb,
    boost::asio::any_io_executor cbExecutor) {
  (void)timeUs; // reserved for future time-window enforcement beyond dedup
  auto self = this;
  postLogic(
    [self, signer, amount, reqNonce, sigHash, cb, cbExecutor]() {
      // 1. NONCELESS dedup (idempotent-retry contract): if the
      // same signed envelope has already been processed this window,
      // return CES_OK without touching the account.
      if (reqNonce == CES_NONCELESS) {
        if (!self->checkAndInsertDedup(sigHash)) {
          boost::asio::post(cbExecutor, [cb]() { cb(CES_OK); });
          return;
        }
      }
      // 2. validateSpend handles all three nonce modes. errFee is
      // feeQuery (same as every other signed op).
      HashPrefix id = Account::getMapKey(signer.getHash());
      ActiveAccount acc = self->accounts_.get(id);
      const int64_t errFee = static_cast<int64_t>(self->cfg_.getFeeError());
      uint8_t rc = acc.validateSpend(
        static_cast<uint64_t>(amount), 0, reqNonce, errFee);
      if (rc != CES_OK) {
        boost::asio::post(cbExecutor, [cb, rc]() { cb(rc); });
        return;
      }
      // 3. Debit. No credit — the amount is burned (operator IS the
      // CES server; it mints what it needs, collection isn't the
      // model at L2-builtin scale).
      acc.debit(static_cast<uint64_t>(amount));
      boost::asio::post(cbExecutor, [cb]() { cb(CES_OK); });
    });
}

void CesServer::_l2CreditAccount(
    const ces::PublicKey& recipient,
    int64_t amount,
    std::function<void()> cb,
    boost::asio::any_io_executor cbExecutor) {
  auto self = this;
  minx::Hash key = recipient.getHash();
  postLogic(
    [self, key, amount, cb, cbExecutor]() {
      self->_brrInner(key, amount);
      if (cb) boost::asio::post(cbExecutor, cb);
    });
}

void CesServer::_l2CreateProgramAccount(
    int64_t initial,
    std::function<void(minx::Hash newPubkey)> cb,
    boost::asio::any_io_executor cbExecutor) {
  // 1. Generate 32 random bytes for the synthetic pubkey. PRNG is
  // thread-local; safe to call here on rpcTaskIO_ before posting.
  minx::Hash pubkey{};
  ces::getThreadLocalPRNG().GenerateBlock(
    reinterpret_cast<CryptoPP::byte*>(pubkey.data()), 32);

  auto self = this;
  postLogic(
    [self, pubkey, initial, cb, cbExecutor]() {
      // _brrInner: credits if account exists, creates if missing.
      self->_brrInner(pubkey, initial);
      if (cb)
        boost::asio::post(cbExecutor, [cb, pubkey]() { cb(pubkey); });
    });
}

void CesServer::_l2DebitProgramAccount(
    const minx::Hash& pubkey,
    int64_t amount,
    std::function<void(bool ok, int64_t newBalance)> cb,
    boost::asio::any_io_executor cbExecutor) {
  auto self = this;
  postLogic(
    [self, pubkey, amount, cb, cbExecutor]() {
      HashPrefix id = Account::getMapKey(pubkey);
      ActiveAccount acc = self->accounts_.get(id);
      if (!acc.exists()) {
        if (cb)
          boost::asio::post(cbExecutor,
            [cb]() { cb(false, 0); });
        return;
      }
      int64_t bal = acc.balance();
      if (bal < amount) {
        if (cb)
          boost::asio::post(cbExecutor,
            [cb, bal]() { cb(false, bal); });
        return;
      }
      acc.debit(static_cast<uint64_t>(amount));
      int64_t newBal = bal - amount;
      if (cb)
        boost::asio::post(cbExecutor,
          [cb, newBal]() { cb(true, newBal); });
    });
}

CesServer::ProgramAccountDebitResult
CesServer::_l2DebitProgramAccountSync(
    const minx::Hash& pubkey, int64_t amount) {
  std::promise<ProgramAccountDebitResult> p;
  auto fut = p.get_future();
  postLogic(
    [this, pubkey, amount, &p]() {
      HashPrefix id = Account::getMapKey(pubkey);
      ActiveAccount acc = accounts_.get(id);
      if (!acc.exists()) {
        p.set_value({false, 0});
        return;
      }
      int64_t bal = acc.balance();
      if (bal < amount) {
        p.set_value({false, bal});
        return;
      }
      acc.debit(static_cast<uint64_t>(amount));
      p.set_value({true, bal - amount});
    });
  return fut.get();
}

void CesServer::_l2CreditProgramAccountSync(
    const minx::Hash& pubkey, int64_t amount) {
  std::promise<void> p;
  auto fut = p.get_future();
  postLogic(
    [this, pubkey, amount, &p]() {
      _brrInner(pubkey, amount);
      p.set_value();
    });
  fut.get();
}

int64_t CesServer::_l2ProgramAccountBalanceSync(
    const minx::Hash& pubkey) {
  std::promise<int64_t> p;
  auto fut = p.get_future();
  postLogic(
    [this, pubkey, &p]() {
      HashPrefix id = Account::getMapKey(pubkey);
      ActiveAccount acc = accounts_.get(id);
      p.set_value(acc.exists() ? acc.balance() : 0);
    });
  return fut.get();
}

void CesServer::_l2Transfer(
    const minx::Hash& originKey,
    const minx::Hash& destKey,
    uint64_t amount,
    std::function<void(uint8_t rc, int64_t newOriginBalance)> cb,
    boost::asio::any_io_executor cbExecutor) {
  auto self = this;
  postLogic(
    [self, originKey, destKey, amount, cb, cbExecutor]() {
      int64_t newBal = 0;
      uint8_t rc = self->transfer(originKey, destKey, amount,
                                  TransferMode::Open, 0,
                                  CES_NONCELESS, newBal);
      boost::asio::post(cbExecutor,
        [cb, rc, newBal]() { cb(rc, newBal); });
    });
}

void CesServer::_l2CreateAuthenticAsset(
    const minx::Hash& originKey,
    const HashPrefix& assetOwnerId,
    const minx::Hash& assetId,
    const std::array<uint8_t, AUTHENTIC_ASSET_HASH_SIZE>& programHash,
    const AuthenticAssetData& payload,
    uint16_t days,
    std::function<void(uint8_t rc)> cb,
    boost::asio::any_io_executor cbExecutor) {
  // Authentic-asset content layout: [32B programHash][178B payload].
  AssetData content{};
  std::memcpy(content.data(),
              programHash.data(), AUTHENTIC_ASSET_HASH_SIZE);
  std::memcpy(content.data() + AUTHENTIC_ASSET_HASH_SIZE,
              payload.data(), AUTHENTIC_ASSET_PAYLOAD_SIZE);

  auto self = this;
  postLogic(
    [self, originKey, assetOwnerId, assetId, content, days,
     cb, cbExecutor]() {
      auto& cfg = self->cfg_;
      int64_t rentFee = cfg.feeAsset;  // raw per-day rate
      int64_t errFee = self->discountedFlatFee(
        -1, cfg.getFeeError(), FeeKind::Query);

      ActiveAccount origin =
        self->accounts_.get(Account::getMapKey(originKey));
      if (!origin.exists()) {
        boost::asio::post(cbExecutor,
          [cb]() { cb(CES_ERROR_ORIGIN_NOT_FOUND); });
        return;
      }

      uint16_t cleanDays = assetDays(days);
      uint64_t totalCost = self->attenuatedFundCost(
        FeeKind::AssetRent, rentFee, 2u + cleanDays, 0);

      uint8_t rc = origin.validateSpend(0, totalCost,
                                        CES_NONCELESS, errFee);
      if (rc != CES_OK) {
        boost::asio::post(cbExecutor, [cb, rc]() { cb(rc); });
        return;
      }

      auto asset = self->assets_.get(assetId);
      if (asset.exists()) {
        origin.chargeError(errFee);
        boost::asio::post(cbExecutor,
          [cb]() { cb(CES_ERROR_ASSET_EXISTS); });
        return;
      }
      if (self->assets_->getObjects().size() >= cfg.maxAsset) {
        boost::asio::post(cbExecutor,
          [cb]() { cb(CES_ERROR_INTERNAL); });
        return;
      }

      origin.debit(totalCost);
      self->accounts_.checkFlush(totalCost);

      // IMMUTABLE = true; PRIVATE / ASSET_OWNED = false.
      // assetBalance() masks days into the 13-bit field; we add 1 day
      // grace at create just like the wire path (createAsset).
      uint16_t balance = assetBalance(
        static_cast<uint16_t>(1 + cleanDays),
        /*priv=*/false, /*aowned=*/false, /*immutable=*/true);

      Asset newAsset(assetOwnerId, content, balance, 0);
      Asset::SerModeGuard guard(Asset::SerMode::Full);
      self->assets_->update(assetId, newAsset);

      self->assets_.checkFlush(totalCost);
      self->checkAutoSnapshot();

      boost::asio::post(cbExecutor, [cb]() { cb(CES_OK); });
    });
}

void CesServer::_l2QueryAccount(
    const minx::Hash& accountKey,
    std::function<void(int64_t, uint32_t, HashPrefix,
                       uint64_t, uint32_t)> cb,
    boost::asio::any_io_executor cbExecutor) {
  auto self = this;
  postLogic(
    [self, accountKey, cb, cbExecutor]() {
      HashPrefix qid = Account::getMapKey(accountKey);
      int64_t bal = 0;
      uint32_t nonce = 0;
      HashPrefix lastDest{};
      uint64_t lastAmount = 0;
      uint32_t lastTime = 0;
      self->unsignedQueryAccount(qid, bal, nonce, lastDest,
                                 lastAmount, lastTime);
      boost::asio::post(cbExecutor,
        [cb, bal, nonce, lastDest, lastAmount, lastTime]() {
          cb(bal, nonce, lastDest, lastAmount, lastTime);
        });
    });
}

void CesServer::_l2DebitNetworkBill(
    const HashPrefix& payerPfx,
    int64_t amount,
    std::function<void(bool ok)> cb,
    boost::asio::any_io_executor cbExecutor) {
  auto self = this;
  postLogic(
    [self, payerPfx, amount, cb, cbExecutor]() {
      bool ok = false;
      ActiveAccount acc = self->accounts_.get(payerPfx);
      if (acc.exists() && acc.balance() >= amount) {
        acc.debit(static_cast<uint64_t>(amount));
        ok = true;
      }
      // Account already-not-exists OR balance < amount → leave alone,
      // signal failure. NetworkBilling will closeChannel on the
      // callback hop.
      if (cb) boost::asio::post(cbExecutor, [cb, ok]() { cb(ok); });
    });
}

void CesServer::_l2CheckAssetOwner(
    const minx::Hash& assetId,
    const ces::PublicKey& signer,
    std::function<void(bool)> cb,
    boost::asio::any_io_executor cbExecutor) {
  auto self = this;
  minx::Hash signerKey = signer.getHash();
  postLogic(
    [self, assetId, signerKey, cb, cbExecutor]() {
      ActiveAsset asset = self->assets_.get(assetId);
      bool isOwner = false;
      if (asset.exists()) {
        HashPrefix signerPrefix = Account::getMapKey(signerKey);
        isOwner = (asset.getOwnerId() == signerPrefix);
      }
      boost::asio::post(cbExecutor, [cb, isOwner]() { cb(isOwner); });
    });
}

void CesServer::liveSnapshot(std::function<void(bool ok, std::string msg)> cb) {
  postLogic( [this, cb]() {
    try {
      if (doSnapshot("cesco")) {
        if (cb) cb(true, "Snapshot written.");
      } else {
        if (cb) cb(true, "Snapshot debounced (cooldown).");
      }
    } catch (std::exception& e) {
      LOGERROR << "live snapshot failed" << SVAR(e.what());
      if (cb) cb(false, std::string("Snapshot failed: ") + e.what());
    }
  });
}

void CesServer::_save() {
  if (running_)
    throw std::runtime_error("_save() cannot be called while server is running");
  accounts_->flush(true);
  accounts_->save(logkv::StoreSaveMode::syncSave);
  assets_->flush(true);
  assets_->save(logkv::StoreSaveMode::syncSave);
}

bool CesServer::checkAndInsertDedup(uint64_t sigHash, uint64_t epochNow) {
  if (epochNow == 0) epochNow = getMicrosSinceEpoch();
  std::lock_guard lock(dedupMutex_);
  if (dedupBaseTime_ == 0) dedupBaseTime_ = epochNow;
  if (epochNow - dedupBaseTime_ >= DEDUP_WINDOW_US) {
    dedupOlder_ = std::move(dedupCurrent_);
    dedupCurrent_.clear();
    dedupBaseTime_ = epochNow;
  }
  if (dedupOlder_.count(sigHash) || dedupCurrent_.count(sigHash))
    return false; // duplicate
  dedupCurrent_.insert(sigHash);
  return true; // new
}

CesClientAsync* CesServer::getOrCreateSettlementClient(
    const std::string& address, const minx::Hash& peerKey) {
  auto it = settlementClients_.find(address);
  if (it != settlementClients_.end())
    return it->second.get();
  try {
    auto ep = Resolver::resolveUdp(address);
    auto client = std::make_unique<CesClientAsync>(
      settlementIO_, ep, serverKeyPair_, peerKey,
      CesClientAsync::DEFAULT_CHANNELS, cfg_.settlementMaxRetries);
    auto* ptr = client.get();
    settlementClients_[address] = std::move(client);
    return ptr;
  } catch (std::exception& e) {
    LOGWARNING << "getOrCreateSettlementClient: " << e.what()
               << VAR(address);
    return nullptr;
  }
}

// =============================================================================
// Peer Table
// =============================================================================

static boost::asio::ip::address resolveIP(const std::string& hostPort) {
  if (hostPort.empty()) return {};
  try {
    auto ep = Resolver::resolveUdp(hostPort);
    return ep.address();
  } catch (...) {
    return {};
  }
}

void CesServer::upsertPeer(const minx::Hash& ckey, const std::string& address,
                            uint64_t inboundCredit) {
  std::lock_guard lock(peerTableMutex_);
  for (auto& p : peerTable_) {
    if (p.ckey == ckey) {
      if (!address.empty()) {
        p.declaredAddress = address;
        p.resolvedIP = resolveIP(address);
      }
      p.totalInboundPoW += inboundCredit;
      if (inboundCredit > 0) p.lastInboundTime = minx::getSecsSinceEpoch();
      return;
    }
  }
  // New entry
  PeerEntry pe;
  pe.ckey = ckey;
  pe.declaredAddress = address;
  pe.resolvedIP = resolveIP(address);
  pe.totalInboundPoW = inboundCredit;
  if (inboundCredit > 0) pe.lastInboundTime = minx::getSecsSinceEpoch();
  peerTable_.push_back(pe);
}

void CesServer::_markPeerReachable(const minx::Hash& ckey,
                                   const std::string& address) {
  upsertPeer(ckey, address, 0);
  std::lock_guard lock(peerTableMutex_);
  for (auto& p : peerTable_) {
    if (p.ckey == ckey) {
      p.reachable = true;
      return;
    }
  }
}

bool CesServer::_isPeerReachable(const minx::Hash& ckey) {
  std::lock_guard lock(peerTableMutex_);
  for (auto& p : peerTable_) {
    if (p.ckey == ckey) return p.reachable;
  }
  return false;
}

void CesServer::_runAutoexecSync() {
  std::promise<void> done;
  postLogic( [this, &done]() {
    runAutoexec();
    done.set_value();
  });
  done.get_future().wait();
}

void CesServer::_primePresence(const HashPrefix& prefix,
                               const minx::SockAddr& addr) {
  presence_.put(prefix, addr);
  std::lock_guard lk(presenceReverseMutex_);
  presenceReverse_[addr] = prefix;
}

void CesServer::loadPeerData() {
  auto path = (cfg_.dataDir / "peerdata.toml").string();
  try {
    if (!std::filesystem::exists(path)) return;
    auto tbl = toml::parse_file(path);
    if (auto peers = tbl["peers"].as_array()) {
      for (auto& p : *peers) {
        if (auto t = p.as_table()) {
          PeerEntry pe;
          auto keyHex = (*t)["key"].value_or(std::string(""));
          if (keyHex.empty()) continue;
          minx::stringToHash(pe.ckey, keyHex);
          pe.declaredAddress = (*t)["address"].value_or(std::string(""));
          pe.resolvedIP = resolveIP(pe.declaredAddress);
          pe.totalInboundPoW = static_cast<uint64_t>(
            (*t)["total_inbound_pow"].value_or(int64_t(0)));
          pe.totalOutboundPoW = static_cast<uint64_t>(
            (*t)["total_outbound_pow"].value_or(int64_t(0)));
          pe.ourBalanceThere = (*t)["our_balance"].value_or(int64_t(-1));
          pe.lastInboundTime = static_cast<uint64_t>(
            (*t)["last_inbound_time"].value_or(int64_t(0)));
          pe.lastCheckTime = static_cast<uint64_t>(
            (*t)["last_check_time"].value_or(int64_t(0)));
          pe.reachable = (*t)["reachable"].value_or(false);
          pe.verified = (*t)["verified"].value_or(false);
          pe.outbound = (*t)["outbound"].value_or(false);
          pe.pingFailures = static_cast<uint32_t>(
            (*t)["ping_failures"].value_or(int64_t(0)));
          peerTable_.push_back(pe);
        }
      }
    }
    LOGINFO << "loaded " << peerTable_.size() << " peer(s) from " << path;
  } catch (std::exception& e) {
    LOGWARNING << "failed to load peer data: " << e.what();
  }
}

void CesServer::savePeerData() {
  std::lock_guard lock(peerTableMutex_);
  auto path = (cfg_.dataDir / "peerdata.toml").string();

  // Sort by totalInboundPoW descending, take top 100
  auto sorted = peerTable_;
  std::sort(sorted.begin(), sorted.end(), [](const PeerEntry& a, const PeerEntry& b) {
    return a.totalInboundPoW > b.totalInboundPoW;
  });
  if (sorted.size() > MAX_PERSISTED_PEERS) sorted.resize(MAX_PERSISTED_PEERS);

  try {
    std::ofstream f(path);
    f << "# CES peer data (auto-generated, top MAX_PERSISTED_PEERS by inbound PoW)\n\n";
    for (auto& pe : sorted) {
      f << "[[peers]]\n";
      f << "key = \"" << minx::hashToString(pe.ckey) << "\"\n";
      f << "address = \"" << pe.declaredAddress << "\"\n";
      f << "total_inbound_pow = " << pe.totalInboundPoW << "\n";
      f << "total_outbound_pow = " << pe.totalOutboundPoW << "\n";
      f << "our_balance = " << pe.ourBalanceThere << "\n";
      f << "last_inbound_time = " << pe.lastInboundTime << "\n";
      f << "last_check_time = " << pe.lastCheckTime << "\n";
      f << "reachable = " << (pe.reachable ? "true" : "false") << "\n";
      f << "verified = " << (pe.verified ? "true" : "false") << "\n";
      f << "outbound = " << (pe.outbound ? "true" : "false") << "\n";
      f << "ping_failures = " << pe.pingFailures << "\n\n";
    }
    LOGDEBUG << "saved " << sorted.size() << " peer(s) to " << path;
  } catch (std::exception& e) {
    LOGWARNING << "failed to save peer data: " << e.what();
  }
}

// =============================================================================
// Peer Miner (unified: outbound + inbound autopeering)
// =============================================================================

void CesServer::startPeerMiner() {
  if (cfg_.peerTarget == 0) return;
  LOGINFO << "starting peer miner thread, target=" << cfg_.peerTarget;
  peerMinerRunning_ = true;
  peerMinerThread_ = std::thread(&CesServer::peerMinerLoop, this);
}

void CesServer::peerMinerLoop() {
  LOGINFO << "peer miner loop started";

  auto serverPubKey = serverKeyPair_.getPublicKeyAsHash();
  auto serverMapKey = Account::getMapKey(serverPubKey);

  std::string myServerAddr = cfg_.serverName.empty()
    ? ":" + std::to_string(boundPort_)
    : cfg_.serverName;

  while (peerMinerRunning_) {
    // Evict peers with too many consecutive ping failures
    {
      std::lock_guard lock(peerTableMutex_);
      auto it = std::remove_if(peerTable_.begin(), peerTable_.end(),
        [](const PeerEntry& p) { return p.pingFailures >= PEER_EVICTION_THRESHOLD; });
      if (it != peerTable_.end()) {
        LOGINFO << "peer miner: evicting " << std::distance(it, peerTable_.end())
                << " peer(s) with PEER_EVICTION_THRESHOLD+ ping failures";
        peerTable_.erase(it, peerTable_.end());
      }
    }

    // Snapshot top 100 peers by totalInboundPoW for this round
    std::vector<PeerEntry> candidates;
    {
      std::lock_guard lock(peerTableMutex_);
      candidates = peerTable_;
    }
    std::sort(candidates.begin(), candidates.end(),
      [](const PeerEntry& a, const PeerEntry& b) {
        return a.totalInboundPoW > b.totalInboundPoW;
      });
    if (candidates.size() > MAX_PERSISTED_PEERS) candidates.resize(MAX_PERSISTED_PEERS);

    // Find the best candidate: lowest ourBalanceThere below target
    // among reachable peers (or untested peers for first check)
    int bestIdx = -1;
    int64_t bestBalance = static_cast<int64_t>(cfg_.peerTarget);

    for (int i = 0; i < static_cast<int>(candidates.size()); ++i) {
      auto& peer = candidates[i];
      if (peer.declaredAddress.empty()) continue;

      // Outbound peers: mine up to peerTarget unconditionally.
      // Inbound peers: mine up to min(peerTarget, totalInboundPoW).
      int64_t peerLimit = static_cast<int64_t>(
        peer.outbound ? cfg_.peerTarget
                      : std::min(cfg_.peerTarget, peer.totalInboundPoW));
      if (peerLimit <= 0) continue;

      // Try to connect and query balance (this IS the verification)
      try {
        auto ep = Resolver::resolveUdp(peer.declaredAddress);
        CesClient client(ep, false);
        client.start(0);
        if (!client.connect()) {
          peer.reachable = false;
          peer.pingFailures++;
          peer.lastCheckTime = minx::getSecsSinceEpoch();
          LOGDEBUG << "peer miner: unreachable " << peer.declaredAddress
                   << " failures=" << peer.pingFailures;
          client.stop();
          continue;
        }

        // Verify server key from handshake matches expected peer key
        peer.reachable = true;
        peer.verified = (client.getServerKey() == peer.ckey);
        peer.pingFailures = 0;
        peer.lastCheckTime = minx::getSecsSinceEpoch();

        int64_t balance = 0;
        uint32_t nonce = 0;
        uint8_t rc = client.queryAccount(serverMapKey, balance, nonce);
        client.disconnect();
        client.stop();

        if (rc == CES_OK)
          peer.ourBalanceThere = balance;
        else
          peer.ourBalanceThere = 0;

      } catch (std::exception& e) {
        peer.reachable = false;
        peer.pingFailures++;
        peer.lastCheckTime = minx::getSecsSinceEpoch();
        LOGDEBUG << "peer miner: error checking " << peer.declaredAddress
                 << " " << e.what() << " failures=" << peer.pingFailures;
        continue;
      }

      // Compute target for this peer
      int64_t pt = static_cast<int64_t>(
        peer.outbound ? cfg_.peerTarget
                      : std::min(cfg_.peerTarget, peer.totalInboundPoW));

      if (peer.ourBalanceThere >= 0 && peer.ourBalanceThere < pt &&
          peer.ourBalanceThere < bestBalance) {
        bestBalance = peer.ourBalanceThere;
        bestIdx = i;
      }
    }

    if (bestIdx >= 0) {
      auto& peer = candidates[bestIdx];
      LOGDEBUG << "peer miner: mining on " << peer.declaredAddress
               << " (bal=" << peer.ourBalanceThere
               << " target=" << (peer.outbound ? cfg_.peerTarget
                                               : std::min(cfg_.peerTarget, peer.totalInboundPoW))
               << ")";

      try {
        auto ep = Resolver::resolveUdp(peer.declaredAddress);
        CesClient client(ep, cfg_.peerMiningFullDataset);
        client.setKey(serverKeyPair_);
        client.start(0);

        if (client.connect()) {
          // Skip peers with unreasonable difficulty
          uint8_t peerDiff = client.getMinDifficulty();
          uint8_t maxDiff = std::max<uint8_t>(
            cfg_.minDiff + PEER_MINER_DIFF_MARGIN, PEER_MINER_DIFF_MAX);
          if (peerDiff > maxDiff) {
            LOGDEBUG << "peer miner: skipping " << peer.declaredAddress
                     << " (diff " << (int)peerDiff << " > max " << (int)maxDiff << ")";
            client.disconnect();
            client.stop();
            break;
          }

          std::map<std::string, std::string> appData;
          appData["server"] = myServerAddr;

          auto result = mineOnce(client, 1, appData);
          if (result.success) {
            LOGDEBUG << "peer miner: mined " << result.credit
                     << " credits on " << peer.declaredAddress;
            peer.totalOutboundPoW += result.credit;
            if (peer.ourBalanceThere >= 0)
              peer.ourBalanceThere += static_cast<int64_t>(result.credit);
          } else {
            LOGDEBUG << "peer miner: mine failed on " << peer.declaredAddress
                     << " status=" << result.status;
          }
          client.disconnect();
        }
        client.stop();
      } catch (std::exception& e) {
        LOGDEBUG << "peer miner: mining error " << peer.declaredAddress
                 << " " << e.what();
      }
    } else {
      LOGTRACE << "peer miner: all peers at target or unreachable";
    }

    // Persist probe + mining results for every candidate we touched this
    // round. `lastCheckTime != 0` means the probe loop actually ran on
    // this candidate (either success or failure path updates it). Without
    // this pass, peers that were probed but not picked as `bestIdx` would
    // silently discard their fresh `reachable`/`ourBalanceThere` — so a
    // peer whose reserve is already at target never gets its reachability
    // persisted, and cross-transfers fail with CES_ERROR_UNKNOWN_PEER.
    {
      std::lock_guard lock(peerTableMutex_);
      for (const auto& c : candidates) {
        if (c.lastCheckTime == 0) continue;
        for (auto& p : peerTable_) {
          if (p.ckey == c.ckey) {
            p.ourBalanceThere = c.ourBalanceThere;
            p.totalOutboundPoW = c.totalOutboundPoW;
            p.reachable = c.reachable;
            p.verified = c.verified;
            p.pingFailures = c.pingFailures;
            p.lastCheckTime = c.lastCheckTime;
            break;
          }
        }
      }
    }
    savePeerData();

    // Sleep between cycles
    for (int i = 0; i < cfg_.peerMinerIntervalSecs && peerMinerRunning_; ++i)
      ces::sleep(1000);
  }

  savePeerData();
  LOGINFO << "peer miner loop stopped";
}

// --- Cron (scheduled runAsset) ---

void CesServer::cronStartTimer() {
  cronTimer_ = std::make_shared<boost::asio::steady_timer>(taskIO_);
  cronTimer_->expires_after(
    std::chrono::milliseconds(CesConfig::CRON_TICK_INTERVAL_MS));
  auto timer = cronTimer_;
  cronTimer_->async_wait(
    boost::asio::bind_executor(logicStrand_,
      [this, timer](const boost::system::error_code& ec) {
        auto t0 = std::chrono::steady_clock::now();
        cronTick(ec);
        auto dt = std::chrono::steady_clock::now() - t0;
        l1cpuGauge_.record(static_cast<uint64_t>(
          std::chrono::duration_cast<std::chrono::nanoseconds>(dt).count()));
      }));
}


void CesServer::cronTick(const boost::system::error_code& ec) {
  if (ec || !running_) return;

  uint64_t now = getMicrosSinceEpoch();
  uint64_t deadline = now + CesConfig::CRON_TICK_DEADLINE_MS * 1000;

  while (!scheduledRuns_.empty()) {
    auto it = scheduledRuns_.begin();
    if (it->first.timeUs > now) break; // not expired yet

    LOGTRACE << "cronTick: executing entry"
             << VAR(it->first.timeUs) << VAR(now);
    auto run = std::move(it->second);
    scheduledRuns_.erase(it);
    // Swallow any exception that escapes executeScheduledRun (host
    // lambda throwing, logkv serialization error, std::bad_alloc, etc.).
    // The scheduledRuns_ entry has already been erased above, so the
    // cron job is gone either way. No logging: a misbehaving program
    // shouldn't get to spam the server's logs as it fails out.
    try {
      executeScheduledRun(run);
    } catch (...) {
    }

    // Check deadline
    if (getMicrosSinceEpoch() > deadline) break;
  }

  // Reschedule
  cronTimer_->expires_after(
    std::chrono::milliseconds(CesConfig::CRON_TICK_INTERVAL_MS));
  auto timer = cronTimer_;
  cronTimer_->async_wait(
    boost::asio::bind_executor(logicStrand_,
      [this, timer](const boost::system::error_code& ec) {
        auto t0 = std::chrono::steady_clock::now();
        cronTick(ec);
        auto dt = std::chrono::steady_clock::now() - t0;
        l1cpuGauge_.record(static_cast<uint64_t>(
          std::chrono::duration_cast<std::chrono::nanoseconds>(dt).count()));
      }));
}

bool CesServer::executeScheduledRun(ScheduledRun& run) {
  // This runs on the logic strand — same as a normal runAsset handler
  // but without network, without signature, without nonce.
  // The caller is the account that scheduled it.

  auto origin = accounts_.get(run.callerPrefix);
  if (!origin.exists() || origin.balance() < static_cast<int64_t>(run.budget))
    return false;

  // Reserve the full budget upfront. Unused budget is refunded after
  // the run (see below) — same policy as the CES_RUN_ASSET path.
  origin.debit(run.budget);
  accounts_.checkFlush(run.budget);

  // Load program
  auto programAsset = assets_.get(run.assetId);
  if (!programAsset.exists()) return true; // program gone but account OK

  HashPrefix programOwnerPrefix = programAsset.data().getOwnerId();
  AssetData programContent = programAsset.data().getContent();

  // Wire host — scheduled runs use direct mutations (no undo log,
  // no deferred side effects, no sig verification).
  VmHostSetup setup;
  setup.callerPrefix = run.callerPrefix;
  setup.programOwnerPrefix = programOwnerPrefix;
  // No undo log, no UDP buffering — scheduled runs mutate directly and
  // have no rollback. Cross-transfer is still allowed: VmHost runs its
  // pre-validation + ledger mutation inline, and this sink fires the
  // wire-level dispatch immediately (no "commit" boundary exists).
  setup.crossTransferFn = [this](const minx::Hash& dest, uint64_t amount,
                                  const std::string& server,
                                  const minx::Hash& peerKey) {
    auto* client = getOrCreateSettlementClient(server, peerKey);
    if (client) {
      client->openTransfer(dest, amount, [](uint8_t) {});
    }
  };
  setup.enableVerifySig = false;
  // Carry-over allowance from the parent run (SYS_SCHEDULE followup, or
  // the wire field on a future-time CES_RUN_ASSET / autoexec). UINT64_MAX
  // = no enforcement, set explicitly by callers that don't want a cap.
  setup.allowance = run.allowance;

  VmHost vmHost(*this, setup);
  vmHost.callerKey    = origin.data().getKey(run.callerPrefix);
  vmHost.selfAssetKey = run.assetId;
  vmHost.programOwner = programOwnerPrefix;
  vmHost.input        = run.input;

  CesVM vm;
  ces::Bytes code(programContent.begin(), programContent.end());
  // Scheduled / cron VM runs intentionally consume the raw gas
  // multiplier — not the discounted one. SYS_SCHEDULE locked in a
  // budget at raw rates when the run was scheduled; firing-time
  // execution must consume that budget at the same rate to preserve
  // the prepaid contract. Wire-path CES_RUN_ASSET (further up this
  // file) discounts via FeeKind::VMMult because the caller spends a
  // fresh budget at op time.
  CesVMResult r = vm.execute(code, vmHost, run.budget, cfg_.feeVmMult);
  // Mutations are direct (no undo on the cron path). Refund unused
  // budget on every termination — same policy as the CES_RUN_ASSET
  // path, with a CESVM_CRASH_FEE eaten on non-abort failures.
  uint64_t penalty = (r.error == CESVM_OK || r.error == CESVM_ABORT)
                       ? 0
                       : CESVM_CRASH_FEE;
  uint64_t spent = r.budgetUsed + penalty;
  if (spent < run.budget) {
    auto caller = accounts_.get(run.callerPrefix);
    if (caller.exists())
      caller.credit(run.budget - spent);
  }

  tpsInc();
  return true;
}

uint8_t CesServer::scheduleRun(const HashPrefix& callerPrefix,
                                const minx::Hash& assetId,
                                uint64_t budget,
                                uint64_t allowance,
                                const ces::Bytes& input,
                                uint64_t time_us) {
  if (scheduledRuns_.size() >= cfg_.maxScheduledEntries)
    return CES_ERROR_QUEUE_FULL;
  if (time_us == 0) time_us = 1; // "next tick"
  LOGTRACE << "scheduleRun" << VAR(time_us) << VAR(budget) << VAR(allowance)
           << VAR(scheduledRuns_.size());
  scheduledRuns_.emplace(
    ScheduleKey{time_us, scheduledSeq_++},
    ScheduledRun{callerPrefix, assetId, budget, allowance, input});
  return CES_OK;
}

// ===========================================================================
// SYS_RPC dispatcher trio — queueRpc / executeRpc / completeRpc
// ===========================================================================
//
// Three-stage flow, each stage on a specific thread:
//
//   1. queueRpc — LOGIC STRAND
//      Validate destination + file auth, walk the chain to
//      materialize request bytes, build the signed envelope
//      (body + time + sender_key + sha256 + sig), post to rpcTaskIO_.
//
//   2. executeRpc — rpcTaskIO_ THREAD
//      Resolve (host, port) to a SockAddr (numeric IPs only for MVP),
//      allocate a channel_id, construct an RpcSession bound to a
//      RudpStream, register in rpcSessions_, kick off the write.
//
//   3. completeRpc — LOGIC STRAND
//      Write response bytes into the same file chain, update
//      header.fileSize, schedule the followup VM program.
//
// The RpcSession class and the envelope helpers live near the top
// of this file (above CesServer::CesServer) because start()'s Rudp
// receive callback demuxes to shared_ptr<RpcSession> and needs the
// complete type at the point where the lambda is defined.

// ---------------------------------------------------------------------------
// queueRpc (logic strand)
// ---------------------------------------------------------------------------

uint8_t CesServer::queueRpc(PendingRpc pending) {
  LOGTRACE << "queueRpc enter" << SVAR(pending.host) << VAR(pending.port);

  if (!rpcRudp_ || !rpcMinx_ ||
      (cfg_.rpcPort == 0 && !cfg_.rpcAutoPort)) {
    LOGDEBUG << "queueRpc: rpc port not configured on this server";
    return CES_ERROR_DISABLED;
  }
  if (pending.host.empty() || pending.host.size() > 255) {
    return CES_ERROR_INTERNAL;
  }
  if (pending.port == 0) {
    return CES_ERROR_INTERNAL;
  }

  // Backpressure: bounce before touching the asset store or allocating
  // any request bytes. rpcPendingCount_ is incremented after we pass
  // this check and decremented in completeRpc.
  if (rpcPendingCount_.load() >= cfg_.rpcMaxPending) {
    LOGDEBUG << "queueRpc: queue full"
             << VAR(rpcPendingCount_.load()) << VAR(cfg_.rpcMaxPending);
    return CES_ERROR_QUEUE_FULL;
  }

  // Validate the request file: must exist and be writable by the
  // caller. (Readable → writable for our purposes; the completion
  // path writes the response into this same file.)
  auto headIt = assets_->find(pending.fileHeadKey);
  if (headIt == assets_->end()) return CES_ERROR_ASSET_NOT_FOUND;
  uint8_t authRc = checkAssetWriteAuth(
    headIt->second, pending.callerPrefix, pending.programOwnerPrefix,
    pending.selfAssetKey);
  if (authRc != CES_OK) return authRc;

  // Walk the chain and materialize the request bytes. The cap is
  // enforced inside readFileChunkBytes BEFORE the destination vector
  // reserves, so a hostile fileSize in the head can't drive a huge
  // allocation. No per-rpc envelope — the body flows raw on the bound
  // channel; the signed bind contract authenticates the sender (this
  // server) once at channel open.
  uint8_t readRc = readFileChunkBytes(*assets_, pending.fileHeadKey,
                                       pending.requestBody,
                                       cfg_.rpcMaxRequestBytes);
  if (readRc != CES_OK) return readRc;

  // Post to rpcTaskIO_. rpcRudp_ access must happen on that thread.
  rpcPendingCount_.fetch_add(1);
  auto shared = std::make_shared<PendingRpc>(std::move(pending));
  boost::asio::post(rpcTaskIO_,
    [this, shared]() { executeRpc(shared); });
  return CES_OK;
}

// ---------------------------------------------------------------------------
// executeRpc (rpcTaskIO_ thread)
// ---------------------------------------------------------------------------

void CesServer::executeRpc(std::shared_ptr<PendingRpc> pending) {
  LOGTRACE << "executeRpc enter" << SVAR(pending->host)
           << VAR(pending->port);

  if (!rpcRudp_) {
    postLogic(
      [this, pending]() { completeRpc(pending, CES_ERROR_INTERNAL, {}); });
    return;
  }

  // Resolve host. For MVP we only support numeric IPs (address_v4 /
  // address_v6 from a plain string). DNS resolution can be added as
  // a follow-up if a real use case demands it.
  boost::system::error_code resolveEc;
  auto addr = Resolver::parseIp(pending->host, resolveEc);
  if (resolveEc) {
    LOGDEBUG << "executeRpc: host is not a numeric IP"
             << SVAR(pending->host);
    postLogic(
      [this, pending]() { completeRpc(pending, CES_ERROR_INTERNAL, {}); });
    return;
  }
  minx::SockAddr peer(addr, pending->port);
  // Channel ID from the OS CSPRNG. rpcTaskIO_ is a single thread, so a
  // function-local random_device is fine. Collisions within a live peer
  // session map are astronomically unlikely and not a correctness issue
  // (if one ever happened, the inserted session would stomp the older
  // entry — acceptable per the design decision that drove this path).
  std::random_device rd;
  const uint32_t channelId = static_cast<uint32_t>(rd());

  auto self = this;
  auto session = std::make_shared<RpcSession>(
    rpcTaskIO_, *rpcRudp_, peer, channelId,
    std::move(pending->requestBody),
    cfg_.rpcResponseTimeoutMs, cfg_.rpcMaxResponseBytes,
    netBilling_.get(), serverKeyPair_,
    [self, pending, peer, channelId]
    (uint8_t rc, ces::Bytes body) {
      // Runs on rpcTaskIO_'s thread. Unregister the session from the
      // demux map, then hop to the logic strand to apply the response
      // to the file and schedule the followup.
      self->rpcSessions_.erase(std::make_pair(peer, channelId));
      boost::asio::post(self->logicStrand_,
        [self, pending, rc, body = std::move(body)]() mutable {
          self->completeRpc(pending, rc, std::move(body));
        });
    });

  rpcSessions_[std::make_pair(peer, channelId)] = session;
  session->start();
}

// ---------------------------------------------------------------------------
// completeRpc (logic strand)
// ---------------------------------------------------------------------------

void CesServer::completeRpc(std::shared_ptr<PendingRpc> pending,
                             uint8_t errorCode,
                             ces::Bytes responseBody) {
  LOGTRACE << "completeRpc enter" << VAR(int(errorCode))
           << VAR(responseBody.size());

  rpcPendingCount_.fetch_sub(1);

  uint32_t status = (errorCode == CES_OK) ? 0u : uint32_t(errorCode);
  const uint32_t wireBodyLen = static_cast<uint32_t>(responseBody.size());
  uint32_t bytesWritten = 0;

  if (status == 0) {
    auto headIt = assets_->find(pending->fileHeadKey);
    if (headIt == assets_->end()) {
      status = CES_ERROR_ASSET_NOT_FOUND;
    } else {
      uint8_t authRc = checkAssetWriteAuth(
        headIt->second, pending->callerPrefix,
        pending->programOwnerPrefix, pending->selfAssetKey);
      if (authRc != CES_OK) {
        status = authRc;
      } else {
        AssetData headContent = headIt->second.getContent();
        RamfileHeader header = parseRamfileHeader(headContent);
        if (!header.valid) {
          status = CES_ERROR_INTERNAL;
        } else {
          // Walk the chain, writing the response bytes into each
          // chunk. Stops at end of response, end of chain, or the
          // first auth/query failure. Preserves each chunk's next-
          // pointer so the chain topology doesn't change.
          minx::Hash nextKey = header.firstChunk;
          while (bytesWritten < wireBodyLen) {
            bool zero = true;
            for (auto b : nextKey) if (b) { zero = false; break; }
            if (zero) break;
            auto chunkIt = assets_->find(nextKey);
            if (chunkIt == assets_->end()) break;
            if (checkAssetWriteAuth(
                  chunkIt->second, pending->callerPrefix,
                  pending->programOwnerPrefix,
                  pending->selfAssetKey) != CES_OK) break;

            AssetData chunkContent = chunkIt->second.getContent();
            minx::Hash chunkNext;
            std::memcpy(chunkNext.data(),
                        &chunkContent[RAMFILE_NEXT_OFFSET],
                        RAMFILE_NEXT_SIZE);

            size_t take = std::min<size_t>(
              wireBodyLen - bytesWritten,
              static_cast<size_t>(RAMFILE_CHUNK_DATA_SIZE));
            AssetData newChunk{};
            std::memcpy(newChunk.data(),
                        responseBody.data() + bytesWritten, take);
            std::memcpy(&newChunk[RAMFILE_NEXT_OFFSET],
                        chunkNext.data(), RAMFILE_NEXT_SIZE);
            chunkIt->second.setContent(newChunk);

            bytesWritten += static_cast<uint32_t>(take);
            nextKey = chunkNext;
          }

          // Rewrite the head with the new declared size = bytesWritten.
          // Zero the content hash (dirty) and bump mtime.
          const uint64_t now = getMicrosSinceEpoch();
          headIt->second.setContent(buildRamfileHeader(
            bytesWritten, minx::Hash{},
            header.createdTime, now,
            header.metadata.data(), RAMFILE_HEAD_META_SIZE,
            header.firstChunk));
        }
      }
    }
  }

  // Followup input: [u32 tag][u32 status][u32 wire_body_len]
  //                 [u32 bytes_written][32 file_head_key]
  // Integers go into VM cells in little-endian (matches the cell layout
  // the VM reads when accessing input).
  ces::Bytes input(48, 0);
  ces::Buffer::pokeLE<uint32_t>(input.data() +  0, pending->followupInputTag);
  ces::Buffer::pokeLE<uint32_t>(input.data() +  4, status);
  ces::Buffer::pokeLE<uint32_t>(input.data() +  8, wireBodyLen);
  ces::Buffer::pokeLE<uint32_t>(input.data() + 12, bytesWritten);
  std::memcpy(input.data() + 16, pending->fileHeadKey.data(), 32);

  if (scheduleRun(pending->callerPrefix, pending->followupProgramKey,
                   pending->followupBudget, pending->followupAllowance,
                   input, 0) != CES_OK) {
    LOGDEBUG << "completeRpc: failed to schedule followup (queue full)"
             << SVAR(pending->followupProgramKey);
  }

  if (_rpcCompletionObserver)
    _rpcCompletionObserver(static_cast<uint8_t>(status));
}

// --- Autoexec (cron assets on boot) ---

void CesServer::runAutoexec() {
  // Key layout: [8 zero bytes][8 CRON_MAGIC BE][16 rest]
  size_t found = 0, executed = 0;
  std::vector<minx::Hash> toDelete; // collect dead autoexec assets

  for (auto& [key, asset] : assets_->getObjects()) {
    // Check key pattern: first 8 bytes zero, next 8 bytes = magic.
    // peek<uint64_t> reads BE so the comparison is direct.
    if (ces::Buffer::peek<uint64_t>(key.data()) != 0) continue;
    if (ces::Buffer::peek<uint64_t>(key.data() + 8) !=
        CesConfig::AUTOEXEC_KEY_MAGIC) continue;

    found++;
    LOGINFO << "autoexec: found autoexec asset" << SVAR(key);

    // Parse content: [2 byte BE length][packet bytes including opcode]
    try {
      AssetData content = asset.getContent();
      uint16_t pktLen = ces::Buffer::peek<uint16_t>(
        std::span<const uint8_t>(content.data(), content.size()), 0);
      if (pktLen < 10 || pktLen > 208) {
        LOGTRACE << "autoexec: bad packet length, deleting" << VAR(pktLen);
        toDelete.push_back(key);
        continue;
      }
      minx::Bytes packet;
      ces::Buffer::putBytes(packet,
        std::span<const uint8_t>(content.data() + 2, pktLen));

      CesRunAsset req;
      req.fromBytes(packet);

      // Verify signature
      PublicKey pk(req.originId);
      if (!req.verifySignature(packet, pk)) {
        LOGTRACE << "autoexec: bad signature, deleting";
        toDelete.push_back(key);
        continue;
      }

      // Verify server ID
      HashPrefix myId = Account::getMapKey(serverKeyPair_.getPublicKeyAsHash());
      if (req.serverId != myId) {
        LOGTRACE << "autoexec: wrong serverId, deleting";
        toDelete.push_back(key);
        continue;
      }

      // Execute as a scheduled run (no nonce check, no time check).
      // Allowance comes from the signed wire packet stored in the asset
      // content — defaults to UINT64_MAX (no enforcement) for the typical
      // operator-installed autoexec, but a signer can opt into a cap.
      HashPrefix callerPrefix = Account::getMapKey(req.originId);
      ScheduledRun run;
      run.callerPrefix = callerPrefix;
      run.assetId = req.assetId;
      run.budget = req.budget;
      run.allowance = req.allowance;
      run.input = req.input;
      if (executeScheduledRun(run)) {
        executed++;
        LOGINFO << "autoexec: executed" << SVAR(req.assetId);
      } else {
        // Account gone or broke — mark for deletion
        toDelete.push_back(key);
        LOGINFO << "autoexec: account dead, will delete" << SVAR(key);
      }

    } catch (const std::exception& e) {
      LOGTRACE << "autoexec: parse failed, deleting" << VAR(e.what());
      toDelete.push_back(key);
    }
  }

  // Delete dead autoexec assets (can't erase during iteration)
  for (auto& k : toDelete)
    assets_->getObjects().erase(k);

  if (found > 0) {
    LOGINFO << "autoexec:" << VAR(found) << VAR(executed);
  }
}

} // namespace ces