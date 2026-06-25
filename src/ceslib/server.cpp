#include <ces/cesplex/mux.h>
#include <ces/buffer.h>
#include <ces/l2/compute_handler.h>
#include <ces/l2/file_handler.h>
#include <ces/l2/compute_lua_handler.h>
#include <ces/cesvm.h>
#include <ces/util/ctrlc.h>
#include <ces/util/helpers.h>
#include <ces/ramfilestore.h>
#include <ces/protocol.h>
#include <ces/server.h>
#include <ces/util/resolver.h>
#include <ces/util/vmprogram.h>
#include <ces/util/wallet.h>

#include <cerrno>
#include <cstring>
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

#include <logkv/serializer.h>
#include <logkv/autoser.h>
#include <logkv/autoser/bytes.h>
#include <logkv/autoser/associative.h>

LOG_MODULE("csv");

namespace ces {

constexpr size_t RANDOMX_VMS_TO_KEEP = 256;

// Spam filter (MINX count-min sketch, bucketed per /24 or /56). Servers run the
// max threshold; with 1-in-SPAM_SAMPLE_RATE sampling on handshaked packets that
// is a ~33.5M packets/window budget — the server-grade setting. (P2P nodes use a
// far lower threshold; MINX treats threshold 0 as disabled.)
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
// Ceiling on the difficulty used for the mint reward. (1<<(D-1))*POW_REWARD_BASE
// must not overflow uint64 (and the shift must stay < 64). With base≈2^10, D=54
// gives (1<<53)*1000 ≈ 9.0e18, well under 2^64; D≥56 overflows and D≥65
// is shift UB. A higher-difficulty solution still mints — capped at this reward.
// The exponential reward is bounded; the solution's validity is not.
constexpr int MAX_POW_DIFFICULTY = 54;

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
// How many difficulty levels above a peer's own minimum the smart-difficulty
// miner may scale UP to when sizing a single solution to the remaining credit
// gap. This bound is RELATIVE to the peer's floor, not absolute, on purpose: a
// solution N levels up costs 2^N times the per-solution RandomX work the peer's
// network is calibrated for, so an absolute cap would let a low-minDiff peer
// pull the miner into a solution thousands of times too large — locking the
// thread for hours/days on one peer and starving every other peer of its
// reserve top-up. Bounding it at +5 keeps each solution cheap enough that the
// cycle returns quickly and the miner fills every peer's quota round-robin.
constexpr uint8_t PEER_MINER_MAX_DIFF_ABOVE = 5;

constexpr const char* ACCOUNTS_DATA_SUBDIRECTORY = "accounts";
constexpr const char* ASSETS_DATA_SUBDIRECTORY = "assets";

// Shared write-auth check for VM host callbacks.
// - Immutable assets: nobody may write.
// - Asset-owned assets: only the executing boot asset itself can write.
// - Account-owned assets: runner or program owner can write.
// Returns CES_OK, CES_ERROR_IMMUTABLE, or CES_ERROR_NOT_OWNER.
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

// Saturating credit: add `amount` to an int64 balance, clamping at INT64_MAX
// instead of wrapping — matching the wire path's ActiveAccount::credit so the
// VM-host and wire credit paths never diverge on overflow. Unreachable in
// practice (total minted << INT64_MAX), but keeps the two paths symmetric.
static inline int64_t saturatingAddBalance(int64_t cur, uint64_t amount) {
  if (cur >= 0 &&
      static_cast<uint64_t>(std::numeric_limits<int64_t>::max() - cur) < amount)
    return std::numeric_limits<int64_t>::max();
  return cur + static_cast<int64_t>(amount);
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
             ChannelMeter* netBilling,
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
      channelMeter_(netBilling),
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
  //      protocols. (See include/ces/cesplex/mux.h for the mux
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
    // ChannelMeter tracking happens AFTER the bind reply lands —
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
  ChannelMeter* channelMeter_;
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
        // local ChannelMeter for delta tracking. Billing uses the
        // local CesConfig rates (consistent with inbound channels)
        // and the local server's own pubkey as payer — which is the
        // bottomless server-self account, so the debit is effectively
        // observability. The remote's disclosed rates from the bind
        // reply are not enforced locally; the remote's own ledger
        // bills however it likes on its end.
        if (self->channelMeter_) {
          std::ostringstream tag;
          tag << "rpc-out:" << self->peer_;
          self->channelMeter_->track(
            self->peer_, self->channelId_, tag.str(),
            getHashPrefix(self->serverKey_.getPublicKeyAsHash()));
        }
        self->write_request_body();
      });
  }

  void write_request_body() {
    // Wire layout post-bind: [u32 body_len][body bytes].
    requestWireBuf_.clear();
    requestWireBuf_.reserve(sizeof(uint32_t) + requestBody_.size());
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
        scheduleSink_(setup.scheduleFn),
        enableVerifySig_(setup.enableVerifySig) {
    this->allowance = setup.allowance;
    // Per-op fees mirror the protocol-side handlers (transfer/createAsset/...).
    // Each VM syscall that mutates or reads the ledger debits the same fee
    // its UDP-equivalent would debit, on top of the gas cost — otherwise a
    // VM run would be a multi-thousand-x discount on every state operation
    // and bypass the rent and tx-fee economics. Flat-discounted
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
    ownerIt->second.setBalance(
      saturatingAddBalance(ownerIt->second.getBalance(), amount));
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
    callerIt->second.setBalance(
      saturatingAddBalance(callerIt->second.getBalance(), amount));
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
    uint32_t storeDays = 1u + assetDays(days);
    if (storeDays > 0x1FFF) storeDays = 0x1FFF;
    Asset newAsset(caller_, content,
                   assetBalance(static_cast<uint16_t>(storeDays), priv,
                                /*aowned=*/false, immut), 0);
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
    uint32_t storeDays = 1u + assetDays(days);
    if (storeDays > 0x1FFF) storeDays = 0x1FFF;
    HashPrefix bootOwner = Account::getMapKey(this->selfAssetKey);
    Asset newAsset(bootOwner, content,
                   assetBalance(static_cast<uint16_t>(storeDays), priv,
                                /*aowned=*/true, immut), 0);
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
      sellerIt->second.setBalance(
        saturatingAddBalance(sellerIt->second.getBalance(), realPrice));
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
        saturatingAddBalance(peerIt->second.getBalance(), amount));
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
    // Route through the sink so executeVmRun can undo the enqueue if the VM
    // later aborts — an aborted run must not leave a scheduled run behind.
    if (!scheduleSink_) return CES_ERROR_DISABLED;
    return scheduleSink_(assetId, budget, allowance,
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
  std::function<uint8_t(const minx::Hash&, uint64_t, uint64_t,
                        const ces::Bytes&, uint64_t)>    scheduleSink_;
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
    maybeSaveAccount(destPrefix);
    auto destIt = server_.accounts_->find(destPrefix);
    if (destIt != server_.accounts_->end()) {
      destIt->second.setBalance(
        saturatingAddBalance(destIt->second.getBalance(), amount));
    } else {
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

// Normalize the operator hello banner: strip trailing CR/LF, then cap the
// UTF-8 encoding at HELLO_MAX_BYTES, backing up off any continuation byte so
// a multi-byte codepoint is never split.
static std::string normalizeHello(std::string s) {
  while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
    s.pop_back();
  if (s.size() > CesServer::HELLO_MAX_BYTES) {
    size_t cut = CesServer::HELLO_MAX_BYTES;
    while (cut > 0 && (static_cast<unsigned char>(s[cut]) & 0xC0) == 0x80)
      --cut;
    s.resize(cut);
  }
  return s;
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

  // Seed the runtime peer target from config. The miner reads this atomic
  // (not cfg_.peerTarget) so the dashboard can change it live.
  peerTarget_.store(cfg_.peerTarget, std::memory_order_relaxed);
  // Seed the live extension-funding rate from config (the dashboard sets it live
  // thereafter; the bucket reads this member, not cfg_). Start the bucket full so
  // a boot-configured budget is available immediately, like a dashboard set.
  extFundingRatePerDay_ = cfg_.extFundingPerDay;
  extFundingAllowance_  = static_cast<double>(cfg_.extFundingPerDay);
  extLocalBudget_.store(cfg_.extLocalBudget, std::memory_order_relaxed);
  minx_ = std::make_unique<minx::Minx>(
    this, minx::MinxConfig{
      .instanceName = "sv",
      .minProveWorkTimestamp = cfg_.minProveWorkTimestamp,
      .spendSlotSize = cfg_.spendSlotSize,
      .randomXVMsToKeep = RANDOMX_VMS_TO_KEEP,
      .randomXInitThreads = 0,
      .spamThreshold = minx::MinxConfig::MAX_SPAM_THRESHOLD,
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
  // here. ChannelMeter reads these into each channel's bound
  // contract at bind time and debits the payer per tick.
  if (cfg_.feeNetByteSent == 0) {
    // Symmetric per-byte rate (sending and receiving cost the
    // same on the server side: NIC, kernel buffers, CPU per byte).
    // Anchor to per-byte-day rent / 1024 ≈ "1 byte ≈ 1 KB-day rent":
    // small but non-zero, scaling transient network bytes below long-lived
    // disk bytes.
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

  // Load persisted peer data, then seed with outbound config peers
  loadPeerData();
  loadHelloFromFile();
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
      minx::Hash fullKey = acc.getKey(prefix);
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
    receiving_ = false;
    running_ = false;
    return 0;
  }
  boundPort_ = boundPort;
  LOGDEBUG << "server opened socket" << VAR(boundPort);
  LOGDEBUG << "starting IO threads" << VAR(cfg_.taskThreads);
  netIOThread_ =
    std::thread([this]() { runGuardedThread([this]{ netIO_.run(); }, "netIO"); });
  for (int i = 0; i < cfg_.taskThreads; ++i) {
    taskIOThreads_.emplace_back(
      [this]() { runGuardedThread([this]{ taskIO_.run(); }, "taskIO"); });
  }
  LOGDEBUG << "starting verifyPoW thread";
  verifyPoWThread_ = std::thread([this]() {
    while (running_) {
      try {
        minx_->verifyPoWs();
      } catch (const std::exception& e) {
        LOGERROR << "verifyPoW handler escaped an exception; continuing"
                 << SVAR(e.what());
      } catch (...) {
        LOGERROR << "verifyPoW handler escaped an unknown exception; continuing";
      }
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
  settlementThread_ = std::thread(
    [this]() { runGuardedThread([this]{ settlementIO_.run(); }, "settlementIO"); });

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
        .spamThreshold = minx::MinxConfig::MAX_SPAM_THRESHOLD,
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
    rudpCfg.channelInactivityTimeout =
      std::chrono::seconds(cfg_.rpcRudpChannelIdleSecs);
    // RUDP's default 100 ms pulse emits only one packet per
    // channel-with-data per pulse. For a 275 MB file-store upload
    // that's ~198000 packets × 100 ms = 5.5 hours. 1 ms pulse gets
    // us ~1000 pkt/s per channel — the pulse only fires when there's
    // data to send, so a quiet channel stays quiet.
    rudpCfg.baseTickInterval = std::chrono::milliseconds(1);
    rpcRudp_ = std::make_unique<minx::Rudp>(
      &rpcRudpListener_, rudpCfg, rpcMinx_.get());

    // ChannelMeter: per-channel billing tick that debits the bound
    // payer at the channel's bound rates. Constructed before CesPlex so
    // CesPlex's Session can call track() with the bound rate schedule
    // at acceptInbound time.
    channelMeter_ = std::make_unique<ChannelMeter>(
      *rpcRudp_, rpcTaskIO_, this);

    // CesPlex — the L2 protocol multiplexer. Constructed iff the
    // operator configured any mounts; otherwise we stay in "outbound
    // only" mode and inbound HS_OPENs are rejected (rpcRudpListener_
    // returns nullptr from onAccept when cesplex_ is null).
    // Construction happens before the socket is opened so the listener
    // sees a coherent CesPlex pointer before any packet can arrive.
    if (!cfg_.cesplexMounts.empty()) {
      cesplex_ = std::make_unique<CesPlex>(
        cfg_.cesplexMounts, *rpcRudp_, rpcTaskIO_, this, channelMeter_.get());
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

        // Deploy + launch /s/ extensions. Posted onto rpcTaskIO_
        // (the supervisor strand); runs after the rpc threads spin
        // up. fileHandlerEnsureServerFile is idempotent; missing
        // file/compute prereqs surface as logged warnings.
        boost::asio::post(rpcTaskIO_,
          [this]() { launchExtensions(); });
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
      // references into rpcRudp_ and must go first; channelMeter_
      // also references rpcRudp_.
      luaHandlerBind(nullptr);
      computeHandlerBind(nullptr);
      fileHandlerBind(nullptr);
      cesplex_.reset();
      channelMeter_.reset();
      rpcMinx_.reset();
      rpcRudp_.reset();
    } else {
      LOGINFO << "rpc: MINX/RUDP port listening" << VAR(rpcBoundPort_);
      rpcNetIOThread_ = std::thread(
        [this]() { runGuardedThread([this]{ rpcNetIO_.run(); }, "rpcNetIO"); });
      rpcTaskIOThread_ = std::thread(
        [this]() { runGuardedThread([this]{ rpcTaskIO_.run(); }, "rpcTaskIO"); });

      // Start the Rudp tick pulse. The timer schedules itself
      // recursively on rpcTaskIO_ until stop() cancels it.
      // Indirection via shared_ptr<std::function> so the recursive lambda can
      // reference itself: a locally-defined recursive std::function would be
      // captured before it is assigned.
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
  const int maxCtrlCCount = 5;
  LOGDEBUG << "stop checking that PoW queue is empty";
  while (true) {
    size_t powQueueSize = minx_->getVerifyPoWQueueSize();
    if (!powQueueSize)
      break;
    // Re-read the interrupt count every iteration — capturing it once before
    // the loop made the ctrl-C escape dead, so a stuck verify queue could
    // hang shutdown with no way out.
    int ctrlCCount = ces::interruptCount();
    if (ctrlCCount >= maxCtrlCCount) {
      LOGINFO << "stop interrupted waiting for PoW queue to empty out"
              << VAR(powQueueSize);
      break;
    }
    LOGTRACE << "stop waiting for PoW queue to empty out" << VAR(powQueueSize)
             << VAR(ctrlCCount) << VAR(maxCtrlCCount);
    ces::sleep(100);
  }
  running_ = false;

  // Stop peer miner if running. Flip the run flag under the lifecycle lock so a
  // concurrent ensurePeerMinerStarted() either already spawned (joined below) or
  // now sees running_==false and won't spawn — no thread can appear past here.
  {
    std::lock_guard lock(peerMinerLifecycleMutex_);
    peerMinerRunning_ = false;
  }
  if (peerMinerThread_.joinable()) {
    LOGDEBUG << "stop stopping peer miner";
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
  if (cronTimer_) {
    boost::system::error_code ec;
    cronTimer_->cancel(ec);
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
  // Stop and join settlementThread_ BEFORE closing the clients. close()
  // mutates per-channel state, the queue and the socket — all of which
  // otherwise live solely on settlementThread_ — so closing while that thread
  // still runs settlementIO_ would be a data race.
  settlementWorkGuard_.reset();
  settlementIO_.stop();
  if (settlementThread_.joinable())
    settlementThread_.join();
  for (auto& [addr, client] : settlementClients_)
    client->close();
  settlementClients_.clear();

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
    computeFundingDrain();        // let in-flight ces.request_funds transfers finish
    computeHandlerBind(nullptr);
    fileHandlerBind(nullptr);
    cesplex_.reset();
    channelMeter_.reset();
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

// Smallest PoW difficulty D whose mint, (1<<(D-1))*POW_REWARD_BASE, can cover
// account creation (one fee_account). Below this, a freshly-mined account
// can't be created and the solution is dropped. Uses the file-local mint
// constants POW_REWARD_BASE / MAX_POW_DIFFICULTY defined above.
static uint8_t minViableDifficulty(uint64_t feeAccount) {
  if (feeAccount <= POW_REWARD_BASE) return 1;
  uint64_t need = (feeAccount + POW_REWARD_BASE - 1) / POW_REWARD_BASE;  // ceil
  uint8_t d = 1;
  while (d < MAX_POW_DIFFICULTY && (1ULL << (d - 1)) < need) ++d;
  return d;
}

void CesServer::createPoWEngine(bool fullMem) {
  // Config sanity, loud at boot: can a minimum-difficulty PoW solution actually
  // pay for account creation? A solution at difficulty D mints
  // (2^(D-1))*POW_REWARD_BASE; creating a new (mined) account requires that mint
  // be >= fee_account (server.cpp incomingProveWork: `if (creditAmount <
  // feeAccount) return;`). If min_difficulty is below that, freshly-mined
  // accounts CANNOT be created — incoming PoW is silently dropped (clients see
  // MINX_SOLUTION_UNKNOWN) and the server mints nothing despite looking healthy.
  // This is precisely the trap a peer miner falls into.
  uint8_t needed = minViableDifficulty(cfg_.feeAccount);
  if (cfg_.minDiff < needed) {
    uint64_t mintAtMin =
      (cfg_.minDiff >= 1 && cfg_.minDiff <= MAX_POW_DIFFICULTY)
        ? (1ULL << (cfg_.minDiff - 1)) * POW_REWARD_BASE
        : 0;
    LOGWARNING << "PoW min_difficulty too low to mint: a freshly mined account"
                  " cannot pay its own creation fee, so solutions are dropped"
                  " (clients see MINX_SOLUTION_UNKNOWN) and the server mints"
                  " nothing despite looking healthy"
               << VAR(static_cast<int>(cfg_.minDiff)) << VAR(cfg_.feeAccount)
               << "; mint(D)=(2^(D-1))*" << POW_REWARD_BASE
               << ", a new account needs mint(D)>=fee_account, but at this"
                  " difficulty mint=" << mintAtMin << " < fee_account="
               << cfg_.feeAccount << "; FIX: set min_difficulty>="
               << static_cast<int>(needed) << " or fee_account<=" << mintAtMin;
  }
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
                               ReqT req, const Hash& keyField, Fn&& fn,
                               bool noncelessOk) {
  if (!req.verifySignature(msg.data, PublicKey(keyField)))
    throw std::runtime_error("bad sig");

  // NONCELESS is the time-boxed settlement / run-asset escape hatch — only
  // the handlers that dedup it (OPEN_TRANSFER, RUN_ASSET) opt in. Any other
  // signed op carrying it is misuse: drop it before it reaches validateSpend,
  // which would otherwise skip the nonce check and let the op replay.
  if (req.reqNonce == CES_NONCELESS && !noncelessOk)
    return;

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

CesServer::NoncelessResult CesServer::resolveNonceless(
    uint64_t time, const Signature& sig, const HashPrefix& originPrefix,
    uint32_t reqNonce, uint32_t& outNonce, uint64_t& outSigHash) {
  outNonce = reqNonce;
  outSigHash = 0;
  if (reqNonce != CES_NONCELESS)
    return NoncelessResult::Proceed;
  uint64_t now = getMicrosSinceEpoch();
  if (time > now + DEDUP_FUTURE_DRIFT_US || time + DEDUP_WINDOW_US < now)
    return NoncelessResult::Stale;
  uint64_t sigHash;
  std::memcpy(&sigHash, sig.data(), sizeof(sigHash));
  // Check only — the caller records the dedup after the op commits a ledger
  // event (recordDedup). A failed op records nothing and stays retryable.
  if (isDuplicateDedup(sigHash))
    return NoncelessResult::Duplicate;
  outSigHash = sigHash;
  auto acc = accounts_.get(originPrefix);
  outNonce = acc.exists() ? acc.nonce() + 1 : 1;
  return NoncelessResult::Proceed;
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
  kv("totalCredits", std::to_string(circulatingCredits()));
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
  // Where this server's CesPlex (file/compute/lua) listens; 0 = disabled.
  // Already advertised in the free MINX GetInfo (rdata), mirrored here so the
  // paid KV is self-complete too.
  kv("rpcPort", std::to_string(rpcBoundPort_));
  if (!cfg_.serverName.empty())
    kv("serverName", cfg_.serverName);
  if (!cfg_.version.empty())
    kv("version", cfg_.version);
  // Always emit hello, even when empty — an inspector wants to see that the
  // field exists and the server simply has no banner set, not have it vanish.
  kv("hello", _getHello());

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

  // 3. Resolve the settlement client and check queue capacity. A null
  // client means the peer's address would not resolve right now
  // (getOrCreateSettlementClient already logged it): reject BEFORE any
  // debit, so we never commit a local debit with no settlement dispatch
  // behind it. Mirrors the unreachable-peer rejection above.
  auto* settlementClient = getOrCreateSettlementClient(destServer, peerKey);
  if (!settlementClient) {
    origin.chargeError(errFee);
    outOriginBalance = origin.balance();
    return CES_ERROR_UNKNOWN_PEER;
  }
  if (settlementClient->load() >= 95) {
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

  // 5. Dispatch remote transfer (settlementClient is non-null here). The
  // callback fires only on a TERMINAL failure: settlement retries until the
  // peer confirms, so a non-OK rc means we ultimately gave up (peer stayed
  // unreachable past the dedup window). That should not happen in a healthy
  // mesh — if it does, it is probably a peering bug — so log every detail at
  // INFO. The local debit + vostro credit already stand.
  settlementClient->openTransfer(destKey, amount,
    [originKey, destKey, peerKey, destServer, amount](uint8_t rc) {
      if (rc != CES_OK) {
        LOGINFO << "cross-transfer settlement GAVE UP "
                   "(peer never confirmed; likely a peering bug)"
                << VAR(rc) << SVAR(destServer) << VAR(amount)
                << BVAR(originKey) << BVAR(destKey) << BVAR(peerKey);
      }
    });
  checkAutoSnapshot();
  return CES_OK;
}

uint8_t CesServer::createAsset(const minx::Hash& originKey,
                               const HashPrefix& ownerId,
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
  uint32_t storeDays = 1u + assetDays(balance);
  if (storeDays > 0x1FFF) storeDays = 0x1FFF;
  Asset newAsset(ownerId, content,
                 assetBalance(static_cast<uint16_t>(storeDays), priv,
                              /*aowned=*/false, immut), 0);
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
  // The day field caps at 0x1FFF, so bill only for the days actually
  // added: funding past the cap grants fewer days than requested.
  uint32_t granted = std::min<uint32_t>(0x1FFF, held + balance) - held;
  uint64_t rentCost = attenuatedFundCost(
    FeeKind::AssetRent, rentFee, granted, held);
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

  if (!asset.exists()) {
    buyer.chargeError(errFee);
    LOGDEBUG << "buyAsset: not found";
    return CES_ERROR_ASSET_NOT_FOUND;
  }

  if (asset.getOwnerId() == buyer.id) {
    buyer.chargeError(errFee);
    LOGDEBUG << "buyAsset: buyer is already owner";
    return CES_ERROR_INVALID_TARGET_ACCOUNT;
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
  if (items >= CesQueryAsset::MAX_ITEMS) {
    throw std::runtime_error("too many items");
  }
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

          uint32_t effectiveNonce;
          uint64_t sigHash = 0;
          switch (resolveNonceless(req.time, req.sig, originPrefix,
                                   req.reqNonce, effectiveNonce, sigHash)) {
            case NoncelessResult::Stale:
              return reply(req.reqNonce, 0, CES_ERROR_WRONG_NONCE);
            case NoncelessResult::Duplicate:
              return reply(req.reqNonce, 0, CES_OK);
            case NoncelessResult::Proceed:
              break;
          }

          int64_t newBal = 0;
          uint8_t rc = transfer(req.originId, req.destKey, req.amount,
                                TransferMode::Open, 0, effectiveNonce, newBal);
          // Record the dedup only once the transfer has committed: a NONCELESS
          // open-transfer that failed (e.g. insufficient balance) leaves no
          // event and must stay retryable so a later attempt can land.
          if (rc == CES_OK && req.reqNonce == CES_NONCELESS)
            recordDedup(sigHash);
          reply(effectiveNonce, newBal, rc);
        }, /*noncelessOk=*/true);
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
          uint8_t rc = createAsset(req.ownerId, Account::getMapKey(req.ownerId),
                                   req.assetId, req.content,
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

        // Privacy: hide CONTENT from unsigned queries. Metadata (owner, days,
        // price) stays visible by design — a private asset is "content-private",
        // not invisible (see PrivateAssetUnsignedQueryHidesContent). The signed
        // path is stricter for non-owners (not-found), but that asymmetry is
        // intentional.
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

    case CES_QUERY_PEER_INFO: {
      CesUnsignedQueryPeerInfo req;
      req.fromBytes(msg.data);
      CesUnsignedQueryPeerInfoResult res;
      res.index = req.index;
      res.found = 0;
      res.pubkey = {};
      res.address = {};
      {
        std::lock_guard lock(peerTableMutex_);
        res.peerCount =
          static_cast<uint16_t>(std::min<size_t>(peerTable_.size(), 0xFFFFu));
        if (req.index < peerTable_.size()) {
          const auto& pe = peerTable_[req.index];
          res.found = 1;
          res.pubkey = pe.ckey;
          size_t n = std::min(pe.declaredAddress.size(), res.address.size());
          std::memcpy(res.address.data(), pe.declaredAddress.data(), n);
        }
      }
      sendUnsignedReply(addr, msg, std::move(res));
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
        }, /*noncelessOk=*/true);
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
// executeVmRun
// The neutral VM-execution transaction core, shared by the wire run path
// (handleRunAsset) and the cron path (executeScheduledRun). Precondition:
// the gas budget has already been debited from the caller. Owns the undo
// log, deferred side effects, VM execution, commit-or-revert, the refund of
// unused budget, and the durability flush. See the durability note at the
// commit branch and the flush for why both are required (VM syscalls mutate
// the in-memory store directly, bypassing the WAL).
// ----------------------------------------------------------------------------

CesServer::VmRunResult CesServer::executeVmRun(const VmRunRequest& req) {
  VmRunResult out;

  // --- Atomic context: undo log + deferred effects ---
  struct UndoEntry {
    enum Kind { AccountEntry, AssetEntry, ScheduleEntry } kind;
    HashPrefix accountKey;
    Account oldAccount;
    bool accountExisted;
    minx::Hash assetKey;
    Asset oldAsset;
    bool assetExisted;
    ScheduleKey scheduleKey;       // Schedule kind: the enqueued run to erase
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
    minx::Hash peerKey;
  };
  std::vector<DeferredUdp> deferredUdp;
  std::vector<DeferredCrossXfer> deferredCrossXfers;

  auto saveAccount = [&](const HashPrefix& id) {
    auto it = accounts_->find(id);
    UndoEntry e{};
    e.kind = UndoEntry::AccountEntry;
    e.accountKey = id;
    if (it != accounts_->end()) {
      e.oldAccount = it->second;
      e.accountExisted = true;
    } else {
      e.accountExisted = false;
    }
    undoLog.push_back(std::move(e));
  };
  auto saveAsset = [&](const minx::Hash& id) {
    auto it = assets_->find(id);
    UndoEntry e{};
    e.kind = UndoEntry::AssetEntry;
    e.assetKey = id;
    if (it != assets_->end()) {
      e.oldAsset = it->second;
      e.assetExisted = true;
    } else {
      e.assetExisted = false;
    }
    undoLog.push_back(std::move(e));
  };
  auto revert = [&]() {
    for (auto it = undoLog.rbegin(); it != undoLog.rend(); ++it) {
      if (it->kind == UndoEntry::AccountEntry) {
        if (it->accountExisted) {
          auto mapIt = accounts_->find(it->accountKey);
          if (mapIt != accounts_->end())
            mapIt->second = it->oldAccount;
          else
            accounts_->getObjects().emplace(it->accountKey, it->oldAccount);
        } else {
          accounts_->getObjects().erase(it->accountKey);
        }
      } else if (it->kind == UndoEntry::AssetEntry) {
        if (it->assetExisted) {
          auto mapIt = assets_->find(it->assetKey);
          if (mapIt != assets_->end())
            mapIt->second = it->oldAsset;
          else
            assets_->getObjects().emplace(it->assetKey, it->oldAsset);
        } else {
          assets_->getObjects().erase(it->assetKey);
        }
      } else { // Schedule: undo the SYS_SCHEDULE enqueue
        scheduledRuns_.erase(it->scheduleKey);
      }
    }
  };

  // --- Wire CesVMHost (sinks buffer side effects until commit) ---
  VmHostSetup setup;
  setup.callerPrefix = req.callerPrefix;
  setup.programOwnerPrefix = req.programOwnerPrefix;
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
  // SYS_SCHEDULE: enqueue synchronously (so the program sees the real
  // QUEUE_FULL/OK rc) but record the enqueue in the undo log, so a later VM
  // abort rolls it back. scheduledRuns_ is RAM-only, so commit needs no
  // re-journal — only the abort path matters.
  setup.scheduleFn = [&](const minx::Hash& assetId, uint64_t budget,
                         uint64_t allowance, const ces::Bytes& input,
                         uint64_t time_us) -> uint8_t {
    ScheduleKey key;
    uint8_t rc = scheduleRunUndoable(req.callerPrefix, assetId, budget,
                                     allowance, input, time_us,
                                     /*prepaid=*/false, key);
    if (rc == CES_OK) {
      UndoEntry e{};
      e.kind = UndoEntry::ScheduleEntry;
      e.scheduleKey = key;
      undoLog.push_back(std::move(e));
    }
    return rc;
  };
  setup.enableVerifySig = req.enableVerifySig;
  setup.allowance = req.allowance;

  VmHost vmHost(*this, setup);
  vmHost.callerKey    = req.callerKey;
  vmHost.selfAssetKey = req.selfAssetKey;
  vmHost.programOwner = req.programOwnerPrefix;
  vmHost.input        = req.input;

  // --- Execute VM ---
  CesVM vm;
  ces::Bytes code = req.code;
  CesVMResult vmResult;
  // Catch any exception that escapes the VM (host lambda throwing, logkv
  // serialization error, std::bad_alloc, CryptoPP throw, etc.). A VM
  // exception is a server-side failure, not client abuse.
  try {
    vmResult = vm.execute(code, vmHost, req.budget, req.gasMult);
  } catch (...) {
    vmResult.error = CESVM_HOST;
  }

  out.vmError = vmResult.error;
  out.budgetUsed = vmResult.budgetUsed;
  // Allowance consumed = initial cap minus what's left. The unlimited
  // sentinel skips decrement entirely (see debitCaller), so it reports 0.
  if (req.allowance != std::numeric_limits<uint64_t>::max() &&
      vmHost.allowance <= req.allowance) {
    out.allowanceUsed = req.allowance - vmHost.allowance;
  } else {
    out.allowanceUsed = 0;
  }

  if (vmResult.error == CESVM_OK) {
    // Commit: fire deferred effects, output available.
    out.rcode = CES_OK;
    out.output = std::move(vmResult.output);
    for (auto& udp : deferredUdp) {
      try {
        if (minx_) {
          minx::Bytes payload;
          ces::Buffer::putBytes(payload, std::span<const uint8_t>(udp.data));
          minx_->sendApplication(
            SockAddr(Resolver::parseIp(udp.addr), udp.port), payload);
        }
      } catch (...) {}
    }
    // Fire deferred cross-transfers (ledger legs already ran via the undo
    // log; this only dispatches the wire-level settlement). Fire-and-forget.
    for (auto& cx : deferredCrossXfers) {
      auto* client = getOrCreateSettlementClient(cx.server, cx.peerKey);
      if (client) {
        // Terminal-failure callback (see crossTransfer): a non-OK rc means
        // settlement gave up after retries — should not happen; log it all
        // at INFO so a peering bug is debuggable.
        client->openTransfer(cx.dest, cx.amount,
          [server = cx.server, peerKey = cx.peerKey,
           dest = cx.dest, amount = cx.amount](uint8_t rc) {
            if (rc != CES_OK) {
              LOGINFO << "VM cross-transfer settlement GAVE UP "
                         "(peer never confirmed; likely a peering bug)"
                      << VAR(rc) << SVAR(server) << VAR(amount)
                      << BVAR(dest) << BVAR(peerKey);
            }
          });
      } else {
        // Null client: the peer address won't resolve right now, so the
        // deferred wire settlement is dropped while the VM's vostro credit
        // already stands (the ledger legs ran during execution and can't be
        // rejected here). Same "should not happen" peering-bug signal — log
        // every detail at INFO.
        LOGINFO << "VM cross-transfer settlement DROPPED "
                   "(peer address unresolvable; likely a peering bug)"
                << SVAR(cx.server) << VAR(cx.amount)
                << BVAR(cx.dest) << BVAR(cx.peerKey);
      }
    }
    // Durably journal the VM's committed ledger mutations. VM syscalls mutate
    // the in-memory store directly through the undo log (for atomic rollback),
    // which bypasses the WAL — so without this the run's effects survive only
    // to the next snapshot. Re-journal every touched cell at its final value
    // (Full mode handles both modified and VM-created cells); the flush below
    // makes the whole run (gas debit + these cells + refund) reach disk
    // atomically, preserving conservation across a crash.
    for (const auto& e : undoLog) {
      if (e.kind == UndoEntry::AccountEntry) {
        auto ait = accounts_->find(e.accountKey);
        if (ait != accounts_->end()) {
          Account::SerModeGuard guard(Account::SerMode::Full);
          accounts_->persist(ait);
        }
      } else if (e.kind == UndoEntry::AssetEntry) {
        auto sit = assets_->find(e.assetKey);
        if (sit != assets_->end()) {
          Asset::SerModeGuard guard(Asset::SerMode::Full);
          assets_->persist(sit);
        }
      }
      // Schedule entries: scheduledRuns_ is RAM-only, nothing to journal.
    }
  } else {
    // Revert all atomic mutations.
    revert();
    out.rcode = CES_ERROR_VM_FAILED;
  }

  // Refund unused budget on every termination path. ABORT and OK get the full
  // unused remainder; non-abort failures (crashes) eat a small crash fee.
  uint64_t penalty = (vmResult.error == CESVM_OK ||
                      vmResult.error == CESVM_ABORT)
                       ? 0
                       : CESVM_CRASH_FEE;
  uint64_t spent = vmResult.budgetUsed + penalty;
  if (spent < req.budget) {
    auto caller = accounts_.get(req.callerPrefix);
    if (caller.exists())
      caller.credit(req.budget - spent);
  }

  // Flush the run's ledger events to the WAL. The gas refund just above and
  // the VM-mutated cells re-journaled on commit are otherwise unflushed, while
  // the pre-run gas debit already flushed — leaving a half-state on the WAL
  // that breaks conservation on crash-recovery. Flushing here makes the run
  // atomic with respect to durability.
  if (!undoLog.empty() || spent < req.budget) {
    accounts_->flush();
    assets_->flush();
  }

  return out;
}

// ----------------------------------------------------------------------------
// handleRunAsset
// Wire CES_RUN_ASSET path. Invoked on logicStrand_ with an already-verified
// CesRunAsset. Handles the dedup window, the gas reservation, the future-time
// scheduling fork, and the signed reply; the VM transaction itself runs in
// executeVmRun.
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
  uint32_t effectiveNonce;
  uint64_t sigHash = 0;
  switch (resolveNonceless(req.time, req.sig, originPrefix,
                           req.reqNonce, effectiveNonce, sigHash)) {
    case NoncelessResult::Stale:
      res.reqNonce = req.reqNonce;
      res.rcode = CES_ERROR_WRONG_NONCE;
      sendSignedReply(addr, msg, std::move(res));
      return;
    case NoncelessResult::Duplicate:
      res.reqNonce = req.reqNonce;
      res.rcode = CES_OK; // already processed
      sendSignedReply(addr, msg, std::move(res));
      return;
    case NoncelessResult::Proceed:
      break;
  }
  res.reqNonce = effectiveNonce;

  // --- Pre-execution: validate and debit gas ---
  {
    auto origin = accounts_.get(originPrefix);
    uint8_t rc = origin.validateSpend(0, req.budget, effectiveNonce,
                                      resolveFee(-1, cfg_.getFeeError()));
    if (rc != CES_OK) {
      // No gas debited — nothing committed. Leave the dedup unrecorded so a
      // NONCELESS run that couldn't afford the budget stays retryable.
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

  // Gas is committed: this is the run's first ledger event, so record the
  // NONCELESS dedup here. Everything past this point (asset lookup, VM run,
  // vmError) is part of the same committed run and a retry must dedup to it.
  if (req.reqNonce == CES_NONCELESS)
    recordDedup(sigHash);

  // --- Scheduled execution? ---
  if (req.time > 0 && req.reqNonce != CES_NONCELESS) {
    uint64_t now = getMicrosSinceEpoch();
    if (req.time > now) {
      // Schedule for future execution. Gas was already debited above, so
      // mark the run prepaid (executeScheduledRun must not debit again).
      // The allowance cap travels verbatim into the eventual execution.
      res.rcode = scheduleRun(originPrefix, req.assetId, req.budget,
                              req.allowance, req.input, req.time,
                              /*prepaid=*/true);
      if (res.rcode != CES_OK) {
        // Nothing was queued — refund the upfront budget.
        auto refund = accounts_.get(originPrefix);
        if (refund.exists()) refund.credit(req.budget);
      }
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

  // --- Run the VM transaction. executeVmRun owns the undo log, deferred
  // effects, commit/abort, refund, and durability flush. ---
  VmRunRequest vreq;
  vreq.callerPrefix       = originPrefix;
  vreq.callerKey          = req.originId;
  vreq.selfAssetKey       = req.assetId;
  vreq.programOwnerPrefix = programOwnerPrefix;
  vreq.code               = ces::Bytes(programContent.begin(), programContent.end());
  vreq.input              = req.input;
  vreq.budget             = req.budget;
  vreq.allowance          = req.allowance;
  vreq.gasMult            = discountFee(FeeKind::VMMult, cfg_.feeVmMult);
  vreq.enableVerifySig    = true;

  VmRunResult vres = executeVmRun(vreq);
  res.rcode         = vres.rcode;
  res.vmError       = vres.vmError;
  res.budgetUsed    = vres.budgetUsed;
  res.allowanceUsed = vres.allowanceUsed;
  res.output        = std::move(vres.output);

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
  // Reject difficulty < 1: a difficulty-0 solution is ~free (≈half of all
  // hashes) and would underflow the `1ULL << (difficulty - 1)` reward shift
  // into an astronomical mint. min_difficulty should floor this, but guard
  // the mint math directly so a 0 floor can never become a credit faucet.
  if (difficulty < 1)
    return;
  postLogic( [this, addr, msg, difficulty]() {
    minx::Hash actualBeneficiaryFullKey;
    HashPrefix mapKey = Account::getMapKey(msg.ckey);
    // Cap the difficulty used for the reward so the shift/multiply can't
    // overflow (or become shift UB) on an extreme-difficulty solution.
    int effDiff = (difficulty > MAX_POW_DIFFICULTY) ? MAX_POW_DIFFICULTY
                                                    : difficulty;
    uint64_t generatedAmount = (1ULL << (effDiff - 1)) * POW_REWARD_BASE;
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
          // The peer advertises its listen port; the routable HOST comes from
          // the packet we just received from it (addr) — never from anything it
          // claims about itself. A peer with a real serverName is kept verbatim.
          std::string peerAddr = Resolver::fillHost(it->second, addr.address());
          upsertPeer(msg.ckey, peerAddr, creditAmount);
          // Start the peer miner (idempotent) so the discovered inbound peer is
          // probed for reachability and the table is persisted each cycle. A
          // pure-receiver node (peer_target 0) otherwise never runs the miner,
          // so every inbound discovery is in-memory only and lost on restart —
          // making the dashboard's inbound list look dead once mining stops.
          ensurePeerMinerStarted();
          LOGDEBUG << "inbound peer PoW: " << peerAddr
                   << " (advertised " << it->second << ") credited "
                   << creditAmount;
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
    // presenceReverse_ entries never evict, so a stale (or spoofed-source)
    // addr could stamp another client's prefix. Only trust it when the
    // forward presence cache still maps that prefix back to this exact addr.
    {
      auto fwd = presence_.get(senderPfx);
      if (!fwd || *fwd != addr)
        senderPfx = {};
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

  // Flat-file rent is collected lazily (per-op + JIT GC on CREATE), no daily
  // pass. kv-stores differ: each key is a self-renting cell, charged by a
  // per-key sweep the file service runs here. This runs on taskIO_, NOT the
  // logicStrand: the sweep takes gKvMutex then hops to logicStrand to burn the
  // rent (the lock order kv ops use), so running it inside the postLogic block
  // above would invert that order and deadlock.
  fileHandlerSweepKvRent(this);
  fileHandlerSweepExtensionBudget(this);

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

// Boot-time autolaunch of /s/ extensions. For each name in
// cfg_.extensions, calls computeHandlerLaunchInternal on
// /s/<name>.lua. The file itself is operator-deployed: drop it into
// <storeDir>/s/, the file handler's startup reconcile auto-generates
// the sidecar before this runs. Source missing → WRN, skip; the
// server keeps running.
//
// Runs on rpcTaskIO_ (caller posts it there). Posted after
// fileHandlerStartupReconcile so reconcile has already filled in any
// missing /s/ sidecars.
void CesServer::launchExtensions() {
  for (const auto& name : cfg_.extensions) {
    std::string path = "/s/" + name + ".lua";
    uint8_t rc = computeHandlerLaunchInternal(path);
    if (rc != CES_OK) {
      LOGWARNING << "extension: launch failed"
                 << SVAR(name) << SVAR(path) << VAR(int(rc));
      continue;
    }
    LOGINFO << "extension launched"
            << SVAR(name) << SVAR(path);
  }
}

// Boot-time reset of the server's own account to exactly TARGET. Created
// at TARGET if absent; otherwise its balance is forced to TARGET whether
// it was below or above.
//
// TARGET is far below INT64_MAX so signed-int64 addition for incoming
// transfers (dice bets, fee receipts) cannot overflow, yet still leaves
// the credit tally (which counts this balance) far from saturation.
// Forcing rather than topping up heals a stale balance corrupted
// (negative or near-saturation) by an older build.
//
// Runs on logicStrand_ (caller posts it there).
void CesServer::topUpServerAccount() {
  static constexpr int64_t TARGET = int64_t(1) << 50;
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
  // never get stuck overflowed. The direct setBalance bypasses the
  // credit/debit tally maintenance, so adjust totalCredits_ by the delta.
  int64_t cur = acc.balance();
  if (cur == TARGET) return;
  acc.data().setBalance(TARGET);
  Account::SerModeGuard guard(Account::SerMode::Full);
  accounts_->persist(acc.it);
  accounts_.adjustTotalCredits(TARGET - cur);
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

  LOGDEBUG << "deployed /b/<name> bytecode program" << SVAR(path);
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

bool CesServer::_walletSend(const minx::Hash& destKey, uint64_t amount) {
  bool ok = false;
  std::promise<void> done;
  postLogic([&]() {
    // One strand task so the balance check and the two ledger moves are atomic.
    ActiveAccount sacc = accounts_.get(serverKeyPair_.getPublicKeyAsHash());
    if (amount > 0 && sacc.exists() && sacc.balance() >= 0 &&
        static_cast<uint64_t>(sacc.balance()) >= amount) {
      // balance >= amount, so _burnInner debits exactly `amount` (its min() is
      // a no-op here); _brrInner credits/creates dest. Tally nets to zero.
      _burnInner(serverKeyPair_.getPublicKeyAsHash(), static_cast<int64_t>(amount));
      _brrInner(destKey, static_cast<int64_t>(amount));
      ok = true;
      LOGINFO << "wallet send from server account" << VAR(amount);
    }
    done.set_value();
  });
  done.get_future().get();
  return ok;
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

// Concrete LedgerTxn over CesServer's private stores. Constructed and used only
// inside _l2Transact's logicStrand_ task, so every op here runs on the strand.
struct ServerLedgerTxn : ces::LedgerTxn {
  CesServer* s;
  explicit ServerLedgerTxn(CesServer* srv) : s(srv) {}

  uint8_t signerSpend(const minx::Hash& signer, uint64_t amount,
                      uint32_t reqNonce, int64_t errFee) override {
    // A zero charge needs no account: an accountless signer can run a free op
    // (e.g. a feeQuery-0 read of a donated /s/ file). Replay of free ops is
    // bounded by the channel's own dedup, not the account.
    if (amount == 0) return CES_OK;
    auto acc = s->accounts_.get(Account::getMapKey(signer));
    uint8_t rc = acc.validateSpend(amount, 0, reqNonce, errFee);
    if (rc != CES_OK) return rc;
    acc.debit(amount);            // committed event; amount is burned
    return CES_OK;
  }
  bool debitAccount(const minx::Hash& pubkey, uint64_t amount) override {
    auto acc = s->accounts_.get(Account::getMapKey(pubkey));
    if (!acc.exists() || acc.balance() < static_cast<int64_t>(amount))
      return false;
    acc.debit(amount);
    return true;
  }
  void credit(const minx::Hash& pubkey, int64_t amount) override {
    s->_brrInner(pubkey, amount);
  }
  int64_t balance(const minx::Hash& pubkey) override {
    auto acc = s->accounts_.get(Account::getMapKey(pubkey));
    return acc.exists() ? acc.balance() : 0;
  }
  bool isReplay(uint64_t sigHash) override { return s->isDuplicateDedup(sigHash); }
  void recordDedup(uint64_t sigHash) override { s->recordDedup(sigHash); }
  bool assetOwnedBy(const minx::Hash& assetId, const minx::Hash& who) override {
    Assets::ActiveAsset asset = s->assets_.get(assetId);
    return asset.exists() && asset.getOwnerId() == Account::getMapKey(who);
  }
};

void CesServer::_l2Transact(const std::function<void(LedgerTxn&)>& fn) {
  std::promise<void> done;
  postLogic([this, &fn, &done]() {
    ServerLedgerTxn txn(this);
    fn(txn);
    done.set_value();
  });
  done.get_future().get();
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

void CesServer::_l2CrossTransfer(
    const minx::Hash& originKey,
    const minx::Hash& destKey,
    uint64_t amount,
    const std::string& destServer,
    std::function<void(uint8_t rc, int64_t newOriginBalance)> cb,
    boost::asio::any_io_executor cbExecutor) {
  auto self = this;
  postLogic(
    [self, originKey, destKey, amount, destServer, cb, cbExecutor]() {
      int64_t newBal = 0;
      uint8_t rc = self->crossTransfer(originKey, destKey, amount, destServer,
                                       CES_NONCELESS, newBal);
      boost::asio::post(cbExecutor,
        [cb, rc, newBal]() { cb(rc, newBal); });
    });
}

// ---- Extension funding rate gate. A token bucket refilling at
// extFundingRatePerDay_ raw units/day, capped at one day's worth. Caller holds
// extFundingMu_.
void CesServer::extFundingRefillLocked() {
  int64_t now = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()).count();
  double cap = static_cast<double>(extFundingRatePerDay_);
  if (extFundingLastUs_ == 0) {
    extFundingLastUs_ = now;               // first touch: just stamp; start empty
  } else {
    double rate = static_cast<double>(extFundingRatePerDay_) / 86400.0 / 1e6;
    double elapsed = static_cast<double>(now - extFundingLastUs_);
    if (elapsed > 0) {
      extFundingAllowance_ += elapsed * rate;
      extFundingLastUs_ = now;
    }
  }
  if (extFundingAllowance_ > cap) extFundingAllowance_ = cap;   // also clamps after a rate cut
  if (extFundingAllowance_ < 0)   extFundingAllowance_ = 0;
}

uint64_t CesServer::extFundingGrant(uint64_t requested) {
  std::lock_guard<std::mutex> lk(extFundingMu_);
  extFundingRefillLocked();
  uint64_t avail = static_cast<uint64_t>(extFundingAllowance_);
  uint64_t granted = requested < avail ? requested : avail;
  extFundingAllowance_ -= static_cast<double>(granted);
  return granted;
}

void CesServer::extFundingRefund(uint64_t amount) {
  std::lock_guard<std::mutex> lk(extFundingMu_);
  extFundingAllowance_ += static_cast<double>(amount);
  double cap = static_cast<double>(extFundingRatePerDay_);
  if (extFundingAllowance_ > cap) extFundingAllowance_ = cap;
}

uint64_t CesServer::extFundingRemaining() {
  std::lock_guard<std::mutex> lk(extFundingMu_);
  extFundingRefillLocked();
  return static_cast<uint64_t>(extFundingAllowance_);
}

void CesServer::extFundingSetPerDay(uint64_t perDay) {
  std::lock_guard<std::mutex> lk(extFundingMu_);
  extFundingRefillLocked();                // settle accrual at the old rate first
  bool raised = perDay > extFundingRatePerDay_;
  extFundingRatePerDay_ = perDay;
  double cap = static_cast<double>(perDay);
  if (raised) extFundingAllowance_ = cap;                       // enable/raise: full now
  else if (extFundingAllowance_ > cap) extFundingAllowance_ = cap;   // lower: clamp now
}

void CesServer::createAssetAsync(
    const minx::Hash& originKey,
    const HashPrefix& ownerId,
    const minx::Hash& assetId,
    const AssetData& content,
    uint16_t balance,
    std::function<void(uint8_t rc)> cb,
    boost::asio::any_io_executor cbExecutor) {
  auto self = this;
  postLogic(
    [self, originKey, ownerId, assetId, content, balance, cb, cbExecutor]() {
      uint8_t rc = self->createAsset(originKey, ownerId, assetId, content,
                                     balance, CES_NONCELESS);
      boost::asio::post(cbExecutor, [cb, rc]() { cb(rc); });
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

uint64_t CesServer::priceNetUsage(const CesPlexUsage& usage) const {
  // Price a channel's measured resource usage in credits at the live discounted
  // feeNet* rates. mem-byte-seconds → the per-byte-DAY rate (divide by
  // seconds/day); __uint128_t guards the conversion against overflow.
  const uint64_t feeChanSec = discountFee(FeeKind::Net, cfg_.feeNetChannelSec);
  const uint64_t feeMemDay  = discountFee(FeeKind::Net, cfg_.feeNetMemByteDay);
  const uint64_t feeBSent   = discountFee(FeeKind::Net, cfg_.feeNetByteSent);
  const uint64_t feeBRecv   = discountFee(FeeKind::Net, cfg_.feeNetByteReceived);

  __uint128_t debit = 0;
  debit += static_cast<__uint128_t>(usage.bytesSent)      * feeBSent;
  debit += static_cast<__uint128_t>(usage.bytesReceived)  * feeBRecv;
  debit += (static_cast<__uint128_t>(usage.memByteSeconds) * feeMemDay)
           / SECS_PER_DAY;
  debit += static_cast<__uint128_t>(usage.ageSeconds)     * feeChanSec;
  return debit > std::numeric_limits<uint64_t>::max()
           ? std::numeric_limits<uint64_t>::max()
           : static_cast<uint64_t>(debit);
}

void CesServer::cesplexReportUsage(const HashPrefix& payer,
                                   const minx::SockAddr& peer,
                                   uint32_t channelId,
                                   const CesPlexUsage& usage) {
  const uint64_t amount = priceNetUsage(usage);
  if (amount == 0) return;  // free at current rates — nothing to charge

  // Debit the payer on logicStrand; if it can't cover the tick, the host
  // closes the channel (on the rpc strand). The bus never sees the cost
  // and never evicts for non-payment.
  _l2DebitNetworkBill(
    payer, static_cast<int64_t>(amount),
    [this, peer, channelId, amount](bool ok) {
      if (ok) return;
      LOGDEBUG << "netbill: insufficient funds → close"
               << SVAR(peer) << VAR(channelId) << VAR(amount);
      if (rpcRudp_) rpcRudp_->closeChannel(peer, channelId);
    },
    rpcTaskIO_.get_executor());
}

void CesServer::debitNetworkBill(const HashPrefix& payerPfx, uint64_t amount) {
  // Per-instance endpoint billing: charge a child's INBOUND luarpc caller. No
  // close callback - the child owns the channel (no rpc-side channel to evict).
  if (amount == 0) return;
  _l2DebitNetworkBill(payerPfx, static_cast<int64_t>(amount), nullptr,
                      rpcTaskIO_.get_executor());
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
      // signal failure. ChannelMeter will closeChannel on the
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

void CesServer::rotateDedupLocked(uint64_t epochNow) {
  if (dedupBaseTime_ == 0) dedupBaseTime_ = epochNow;
  if (epochNow - dedupBaseTime_ >= DEDUP_WINDOW_US) {
    dedupOlder_ = std::move(dedupCurrent_);
    dedupCurrent_.clear();
    dedupBaseTime_ = epochNow;
  }
}

bool CesServer::checkAndInsertDedup(uint64_t sigHash, uint64_t epochNow) {
  if (epochNow == 0) epochNow = getMicrosSinceEpoch();
  std::lock_guard lock(dedupMutex_);
  rotateDedupLocked(epochNow);
  if (dedupOlder_.count(sigHash) || dedupCurrent_.count(sigHash))
    return false; // duplicate
  dedupCurrent_.insert(sigHash);
  return true; // new
}

bool CesServer::isDuplicateDedup(uint64_t sigHash, uint64_t epochNow) {
  if (epochNow == 0) epochNow = getMicrosSinceEpoch();
  std::lock_guard lock(dedupMutex_);
  rotateDedupLocked(epochNow);
  return dedupOlder_.count(sigHash) || dedupCurrent_.count(sigHash);
}

void CesServer::recordDedup(uint64_t sigHash, uint64_t epochNow) {
  if (epochNow == 0) epochNow = getMicrosSinceEpoch();
  std::lock_guard lock(dedupMutex_);
  rotateDedupLocked(epochNow);
  dedupCurrent_.insert(sigHash);
}

CesClientAsync* CesServer::getOrCreateSettlementClient(
    const std::string& address, const minx::Hash& peerKey) {
  auto it = settlementClients_.find(address);
  if (it != settlementClients_.end())
    return it->second.get();
  try {
    // Prefer the endpoint the peer miner already resolved off-strand. A
    // cross-transfer only reaches here for a `reachable` peer, and the miner
    // sets reachability and resolvedEndpoint together, so this avoids a blocking
    // getaddrinfo on the logic strand (the ledger heartbeat). resolveUdp stays
    // as a fallback for a reachable peer with no cached endpoint.
    boost::asio::ip::udp::endpoint ep;
    bool haveEp = false;
    {
      std::lock_guard lock(peerTableMutex_);
      for (const auto& p : peerTable_) {
        if (p.ckey == peerKey && p.resolvedEndpointValid) {
          ep = p.resolvedEndpoint;
          haveEp = true;
          break;
        }
      }
    }
    if (!haveEp) ep = Resolver::resolveUdp(address);
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

// Split "host:port" (and "[ipv6]:port") on the last colon into host + port. False
// if there is no port. No-throw, for comparing address representations.
static bool splitHostPort(const std::string& a,
                          std::string& host, std::string& port) {
  auto pos = a.find_last_of(':');
  if (pos == std::string::npos || pos == 0 || pos + 1 >= a.size()) return false;
  host = a.substr(0, pos);
  port = a.substr(pos + 1);
  if (host.size() >= 2 && host.front() == '[' && host.back() == ']')
    host = host.substr(1, host.size() - 2);
  return !host.empty();
}

void CesServer::upsertPeer(const minx::Hash& ckey, const std::string& address,
                            uint64_t inboundCredit) {
  // NOTE: this runs on the logic strand (incomingProveWork posts here with an
  // UNTRUSTED appData["server"] address). Do NOT resolve DNS here — a blocking
  // getaddrinfo on a hostile hostname would stall the whole ledger thread.
  // resolvedIP is populated off-strand by the peer miner when it probes the
  // peer (which already resolves declaredAddress, and is cost-gated to the
  // top peers by inbound PoW).
  std::lock_guard lock(peerTableMutex_);
  for (auto& p : peerTable_) {
    if (p.ckey == ckey) {
      // Address-claim policy. An UNVERIFIED entry's address is up for grabs:
      // whatever PoW spoke last wins (unverified claims brawl to the death, and
      // none is trusted while they do). But a VERIFIED address is STICKY — an
      // inbound PoW (inboundCredit > 0) carries no proof of identity, so it must
      // never move a binding we paid a signed server-info to confirm. That is
      // the whole anti-takeover rule: you cannot re-point a known server key with
      // unsigned work. Operator/discovery updates (inboundCredit == 0) stay
      // authoritative. On any real address change, reset the probe state so the
      // newcomer is re-checked — and re-verified — from scratch.
      bool fromInbound = (inboundCredit > 0);
      bool mayWrite = !address.empty() && (!fromInbound || !p.verified);
      // A peer re-added under a different address representation (a hostname vs the
      // IP it resolves to) is not a real change: keep the binding so a re-add never
      // resets/re-verifies a settled entry. Resolution stays off-strand (resolvedIP
      // is set by the miner); compare the incoming host to it on the same port.
      bool addrChanged = p.declaredAddress != address;
      if (addrChanged && !p.resolvedIP.is_unspecified()) {
        std::string nh, np, dh, dp;
        if (splitHostPort(address, nh, np) &&
            splitHostPort(p.declaredAddress, dh, dp) &&
            nh == p.resolvedIP.to_string() && np == dp)
          addrChanged = false;
      }
      if (mayWrite && addrChanged) {
        p.declaredAddress = address;
        p.verified = false;
        p.reachable = false;
        p.lastCheckTime = 0;
      }
      p.totalInboundPoW += inboundCredit;
      if (inboundCredit > 0) p.lastInboundTime = minx::getSecsSinceEpoch();
      return;
    }
  }
  // New entry. Bound the in-memory table so sustained inbound PoW from many
  // distinct keys can't grow it without limit between restarts (persistence and
  // the miner already keep only the top MAX_PERSISTED_PEERS). Operator/server
  // adds pass inboundCredit == 0 (configured peers, outbound adds, reachability
  // probes) and are always admitted; only the untrusted inbound-discovery path
  // (inboundCredit > 0) is capped. When full, make room by evicting the weakest
  // non-outbound resident (lowest accumulated inbound PoW) — NOT by refusing the
  // newcomer: a fresh peer always arrives with just one solution's credit, so
  // comparing that against residents' accumulated PoW would lock every new peer
  // out forever. Outbound (operator-pinned) peers are never evicted; if every
  // slot is one, drop the newcomer.
  if (inboundCredit > 0 && peerTable_.size() >= MAX_INMEM_PEERS) {
    auto victim = peerTable_.end();
    for (auto it = peerTable_.begin(); it != peerTable_.end(); ++it) {
      if (it->outbound) continue;
      if (victim == peerTable_.end() ||
          it->totalInboundPoW < victim->totalInboundPoW)
        victim = it;
    }
    if (victim == peerTable_.end())
      return;  // every slot is an operator-pinned outbound peer
    peerTable_.erase(victim);
  }
  PeerEntry pe;
  pe.ckey = ckey;
  pe.declaredAddress = address;
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

// =============================================================================
// Dashboard / admin surface
// =============================================================================

CesServer::AdminStats CesServer::_adminStats() {
  std::promise<AdminStats> pr;
  postLogic([&]() {
    AdminStats s;
    s.circulating = circulatingCredits();
    s.accounts = accounts_->getObjects().size();
    s.assets = assets_->getObjects().size();
    s.txCount = txCount_.load();
    pr.set_value(s);
  });
  return pr.get_future().get();
}

std::vector<int64_t> CesServer::_peerVostroBalances(
    const std::vector<minx::Hash>& keys) {
  std::promise<std::vector<int64_t>> pr;
  postLogic([&]() {
    std::vector<int64_t> out;
    out.reserve(keys.size());
    for (const auto& k : keys) {
      ActiveAccount acc = accounts_.get(Account::getMapKey(k));
      out.push_back(acc.exists() ? acc.data().getBalance() : 0);
    }
    pr.set_value(std::move(out));
  });
  return pr.get_future().get();
}

CesServer::AdminAccount CesServer::_adminQueryAccount(
    const minx::Hash& accountKey) {
  std::promise<AdminAccount> pr;
  postLogic([&]() {
    AdminAccount a;
    ActiveAccount acc = accounts_.get(Account::getMapKey(accountKey));
    if (acc.exists()) {
      const Account& d = acc.data();
      // The map is keyed by the 8-byte prefix only; confirm the full 32-byte
      // identity by matching the stored 24-byte keyTail. A mismatch means a
      // DIFFERENT account occupies this prefix (collision), not the one asked
      // for — so the queried account does not exist.
      if (d.getKeyTail() == getHashTail(accountKey)) {
        a.exists = true;
        a.balance = d.getBalance();
        a.nonce = d.getNonce();
        a.lastXferDest = d.getLastXferDest();
        a.lastXferAmount = d.getLastXferAmount();
        a.lastXferTime = d.getLastXferTime();
      } else {
        a.prefixTaken = true;
      }
    }
    pr.set_value(a);
  });
  return pr.get_future().get();
}

CesServer::AdminAsset CesServer::_adminQueryAsset(const minx::Hash& assetId) {
  std::promise<AdminAsset> pr;
  postLogic([&]() {
    AdminAsset a;
    ActiveAsset as = assets_.get(assetId);
    if (as.exists()) {
      a.exists = true;
      a.owner = as.getOwnerId();
      a.balance = as.getBalance();
      a.price = as.getPrice();
      a.content = as.getContent();
    }
    pr.set_value(a);
  });
  return pr.get_future().get();
}

CesServer::FileStat CesServer::_fileStat(const std::string& path) {
  FileStat out;
  // File feature needs the cap and CesPlex actually up; gate on the BOUND rpc
  // port (cfg_.rpcPort may be 0 under auto-port) so we never post to a dead IO.
  if (cfg_.cesFileStoreMaxBytes == 0 || _rpcBoundPort() == 0) return out;
  out.enabled = true;
  FileExecReq req;
  req.verb = 0x04;  // kVerbStat — public, no signer/owner required
  req.name = path;
  std::promise<FileExecResp> pr;
  // fileHandlerExec runs the verb body (sidecar read-modify-write + lazy rent)
  // on the CALLER thread; only the callback is posted to the executor. Run the
  // whole call on rpcTaskIO so it stays serialized with the handler's other
  // verbs instead of racing them from this web thread, then block on the future.
  boost::asio::post(_rpcTaskIOExecutor(), [this, &req, &pr]() {
    fileHandlerExec(req, [&pr](FileExecResp r) { pr.set_value(std::move(r)); },
                    _rpcTaskIOExecutor());
  });
  FileExecResp r = pr.get_future().get();
  if (r.status == CES_OK) {
    out.found = true;
    out.ownerPubkey = r.ownerPubkey;
    out.fileBalance = r.fileBalance;
    out.size = r.size;
    out.pricePerKb = r.pricePerKb;
    out.createdUs = r.createdUs;
    out.modifiedUs = r.modifiedUs;
  }
  return out;
}

std::vector<CesServer::PeerInfo> CesServer::_peerSnapshot() {
  std::vector<PeerInfo> out;
  std::lock_guard lock(peerTableMutex_);
  out.reserve(peerTable_.size());
  for (const auto& p : peerTable_) {
    PeerInfo pi;
    pi.ckey = p.ckey;
    pi.declaredAddress = p.declaredAddress;
    if (!p.resolvedIP.is_unspecified())
      pi.resolvedIP = p.resolvedIP.to_string();
    pi.outbound = p.outbound;
    pi.inbound = (p.totalInboundPoW > 0);
    pi.reachable = p.reachable;
    pi.verified = p.verified;
    pi.ourBalanceThere = p.ourBalanceThere;
    pi.totalInboundPoW = p.totalInboundPoW;
    pi.totalOutboundPoW = p.totalOutboundPoW;
    pi.lastInboundTime = p.lastInboundTime;
    pi.lastCheckTime = p.lastCheckTime;
    pi.pingFailures = p.pingFailures;
    pi.rpcPort = p.rpcPort;
    out.push_back(std::move(pi));
  }
  return out;
}

void CesServer::_addOutboundPeer(const minx::Hash& ckey,
                                 const std::string& address) {
  upsertPeer(ckey, address, 0);  // locks peerTableMutex_ internally
  {
    std::lock_guard lock(peerTableMutex_);
    for (auto& p : peerTable_) {
      if (p.ckey == ckey) {
        p.outbound = true;
        break;
      }
    }
  }
  // Persist now so a dashboard-added peer survives restart even if the
  // miner (which also persists each cycle) hasn't ticked yet.
  savePeerData();
  LOGINFO << "peer added via admin" << SVAR(address);
  // Start the probe/mine thread if it wasn't running — so the new peer gets
  // its reachability checked right away, even at target 0.
  ensurePeerMinerStarted();
}

bool CesServer::_removePeer(const minx::Hash& ckey) {
  bool removed = false;
  {
    std::lock_guard lock(peerTableMutex_);
    auto it = std::remove_if(peerTable_.begin(), peerTable_.end(),
      [&](const PeerEntry& p) { return p.ckey == ckey; });
    if (it != peerTable_.end()) {
      peerTable_.erase(it, peerTable_.end());
      removed = true;
    }
  }
  if (removed) {
    savePeerData();
    LOGINFO << "peer removed via admin" << SVAR(minx::hashToString(ckey));
  }
  return removed;
}

void CesServer::_setPeerTarget(uint64_t target) {
  peerTarget_.store(target);
  LOGINFO << "peer target set via admin" << VAR(target);
  if (target > 0) ensurePeerMinerStarted();
}

CesServer::RemoteServerInfo CesServer::_inspectRemoteServer(
    const std::string& address, bool fetchPaidInfo) {
  RemoteServerInfo out;
  boost::asio::ip::udp::endpoint ep;
  try {
    ep = Resolver::resolveUdp(address);
  } catch (std::exception& e) {
    LOGDEBUG << "inspect: resolve failed" << SVAR(address) << SVAR(e.what());
    return out;
  }
  try {
    // No RandomX dataset — this is a handshake/query probe, not mining.
    CesClient client(ep, false);
    client.setKey(serverKeyPair_);
    client.start(0);
    // Snappy interactive probe: an unreachable host should fail fast (a few
    // seconds), not the default nested-retry handshake (tens of seconds).
    client.setTries(2);
    if (client.connect()) {
      out.reachable = true;
      out.serverKey = client.getServerKey();
      out.minDifficulty = client.getMinDifficulty();
      // The paid KV info needs a funded account on the peer; if we have
      // none the query just errors and entries stays empty.
      if (fetchPaidInfo) {
        std::vector<ServerInfoEntry> entries;
        if (client.queryServerInfo(entries) == CES_OK)
          out.entries = std::move(entries);
      }
      client.disconnect();
    }
    client.stop();
  } catch (std::exception& e) {
    LOGDEBUG << "inspect: client error" << SVAR(address) << SVAR(e.what());
  }
  return out;
}

CesServer::RemoteMineResult CesServer::_mineRemoteServer(
    const std::string& address, int count) {
  RemoteMineResult r;
  if (count < 1) count = 1;
  boost::asio::ip::udp::endpoint ep;
  try {
    ep = Resolver::resolveUdp(address);
  } catch (std::exception& e) {
    r.error = std::string("resolve: ") + e.what();
    return r;
  }
  try {
    // Cache-only RandomX: an occasional dashboard bootstrap mine doesn't
    // justify a fresh ~2 GB dataset (the server already holds one for
    // verification — a second would risk OOM). Slower per hash, but this is
    // a few solutions, not the continuous peer miner.
    CesClient client(ep, false);
    client.setKey(serverKeyPair_);
    client.start(0);
    if (!client.connect()) {
      r.error = "unreachable";
      client.stop();
      return r;
    }
    std::map<std::string, std::string> appData;
    appData["server"] = cfg_.serverName.empty()
      ? (":" + std::to_string(boundPort_)) : cfg_.serverName;
    for (int i = 0; i < count && ces::notInterrupted(); ++i) {
      auto m = mineOnce(client, 1, appData);
      if (m.success) { r.ok = true; r.credit += m.credit; }
      else { r.status = m.status; break; }
    }
    client.disconnect();
    client.stop();
  } catch (std::exception& e) {
    r.error = e.what();
  }
  return r;
}

void CesServer::loadHelloFromFile() {
  auto path = (cfg_.dataDir / "hello.txt").string();
  std::error_code ec;
  if (!std::filesystem::exists(path, ec)) return;
  try {
    std::ifstream f(path, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    std::lock_guard lock(helloMutex_);
    helloMessage_ = normalizeHello(ss.str());
    LOGINFO << "loaded hello banner" << VAR(helloMessage_.size());
  } catch (std::exception& e) {
    LOGWARNING << "failed to read hello.txt" << SVAR(e.what());
  }
}

std::string CesServer::_getHello() {
  std::lock_guard lock(helloMutex_);
  return helloMessage_;
}

std::string CesServer::_setHello(const std::string& raw) {
  std::string norm = normalizeHello(raw);
  auto path = (cfg_.dataDir / "hello.txt").string();
  {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f << norm;
  }
  {
    std::lock_guard lock(helloMutex_);
    helloMessage_ = norm;
  }
  LOGINFO << "hello banner set via admin" << VAR(norm.size());
  return norm;
}

std::string CesServer::_loadHelloFile(bool& existed) {
  auto path = (cfg_.dataDir / "hello.txt").string();
  std::error_code ec;
  existed = std::filesystem::exists(path, ec);
  if (!existed) return std::string();
  std::ifstream f(path, std::ios::binary);
  std::ostringstream ss;
  ss << f.rdbuf();
  return normalizeHello(ss.str());
}

bool CesServer::_setConfigKnob(const std::string& key, uint64_t value) {
  // Mutate on logicStrand_. Base fees (account/asset/tx/query/vm) are also read
  // there during charging, so they are race-free. The L2/net fee and cap fields
  // are read off-strand (meter, compute supervisor, file handler, dashboard), so
  // those reads formally race this write; being aligned word-size scalars they
  // can only read the old or new value, never a torn one, taking effect next
  // tick (benign in practice). The fully race-free form would publish the config
  // as an immutable shared_ptr<const CesConfig> snapshot (RCU) loaded atomically,
  // skipped here as the only writer is this rare operator action.
  bool ok = false;
  std::promise<void> done;
  postLogic([&]() {
    if      (key == "fee_account")  { cfg_.feeAccount = value; ok = true; }
    else if (key == "fee_asset")    { cfg_.feeAsset   = value; ok = true; }
    else if (key == "fee_tx")       { cfg_.feeTx      = value; ok = true; }
    else if (key == "fee_query")    { cfg_.feeQuery   = value; ok = true; }
    else if (key == "fee_vm_mult")  { cfg_.feeVmMult  = value; ok = true; }
    // L2 file-store fees (per byte-day / per KB), live per-op like the base fees.
    else if (key == "fee_file_rent")  { cfg_.feeFileRent  = static_cast<int64_t>(value); ok = true; }
    else if (key == "fee_file_write") { cfg_.feeFileWrite = static_cast<int64_t>(value); ok = true; }
    else if (key == "fee_file_read")  { cfg_.feeFileRead  = static_cast<int64_t>(value); ok = true; }
    // L2 compute fees, live on the supervisor tick. Keys are the TOML keys
    // verbatim (no token-dropping drift): the switch IS the config name.
    else if (key == "fee_compute_slot_sec")     { cfg_.feeComputeSlotSec    = static_cast<int64_t>(value); ok = true; }
    else if (key == "fee_compute_cpu_sec")      { cfg_.feeComputeCpuSec     = static_cast<int64_t>(value); ok = true; }
    else if (key == "fee_compute_rss_byte_day") { cfg_.feeComputeRssByteDay = static_cast<int64_t>(value); ok = true; }
    else if (key == "fee_compute_net_byte")     { cfg_.feeComputeNetByte    = static_cast<int64_t>(value); ok = true; }
    else if (key == "fee_bucket_byte_sec")      { cfg_.feeBucketByteSec     = static_cast<int64_t>(value); ok = true; }
    // ChannelMeter (net metering) rates, live on the meter tick.
    else if (key == "fee_net_byte_sent")     { cfg_.feeNetByteSent     = value; ok = true; }
    else if (key == "fee_net_byte_received") { cfg_.feeNetByteReceived = value; ok = true; }
    else if (key == "fee_net_channel_sec")   { cfg_.feeNetChannelSec   = value; ok = true; }
    else if (key == "fee_net_mem_byte_day")  { cfg_.feeNetMemByteDay   = value; ok = true; }
    // Feature caps: the value is read live (file GC / compute LAUNCH admission),
    // but the handler binds/unbinds only at boot, so the 0 boundary is frozen in
    // both directions — a feature off at boot can't be enabled live, and an
    // enabled one can't be zeroed live. The `current != 0 && value != 0` guard
    // enforces exactly that; crossing 0 needs a config edit + restart.
    else if (key == "file_store_max_bytes") {
      if (cfg_.cesFileStoreMaxBytes != 0 && value != 0) { cfg_.cesFileStoreMaxBytes = value; ok = true; }
    }
    else if (key == "compute_max_instances") {
      if (cfg_.computeMaxInstances != 0 && value != 0) { cfg_.computeMaxInstances = static_cast<uint32_t>(value); ok = true; }
    }
    else if (key == "fee_discount_enabled") {
      cfg_.feeDiscountEnabled = (value != 0); ok = true;
    }
    else if (key == "min_difficulty") {
      // The PoW floor is not swallowed on construction: minx_ reads its minDiff_
      // live on every solution (filterPoW), and cfg_.minDiff is read live when we
      // advertise server-info, so updating both here takes effect immediately. We
      // only gate the main minting port; rpcMinx_ has no minting floor.
      if (value >= 1 && value <= static_cast<uint64_t>(MAX_POW_DIFFICULTY)) {
        cfg_.minDiff = static_cast<uint8_t>(value);
        if (minx_) minx_->setMinimumDifficulty(cfg_.minDiff);
        ok = true;
      }
    }
    if (ok) { LOGINFO << "config knob set via admin" << SVAR(key) << VAR(value); }
    done.set_value();
  });
  done.get_future().get();
  return ok;
}

std::string CesServer::_exportConfig(std::string* errReason) {
  auto path = (cfg_.dataDir / "ces.toml").string();
  try {
    std::ostringstream o;
    o << "# CES server config — exported live from the running server.\n"
      << "# Feed it back on the next boot with:  ces --config " << path << "\n"
      << "# Peers persist in peerdata.toml and the hello banner in hello.txt;\n"
      << "# both load automatically and are intentionally NOT duplicated here.\n\n";

    // The WHOLE live effective config, so a re-feed reproduces the running
    // server and set-vs-default is never ambiguous. Every key is exactly the
    // TOML/CLI name (the switch IS the config name — no drift). Top-level
    // scalars first; [table]s last (TOML scoping). Add new CesConfig fields
    // here when you add them, or the export silently rots.
    o << "data_dir = \"" << cfg_.dataDir.string() << "\"\n";
    o << "port = " << boundPort_ << "\n";
    o << "# server_key is the 32-byte private key (same identity on re-feed).\n";
    o << "server_key = \"" << minx::hashToString(cfg_.serverPrivKey) << "\"\n";
    if (!cfg_.serverName.empty())
      o << "server_name = \"" << cfg_.serverName << "\"\n";
    o << "min_difficulty = " << static_cast<int>(cfg_.minDiff) << "\n";
    o << "spend_slot_size = " << cfg_.spendSlotSize << "\n";
    o << "threads = " << cfg_.taskThreads << "\n";
    o << "min_accounts = " << cfg_.minAcc << "\n";
    o << "max_accounts = " << cfg_.maxAcc << "\n";
    o << "min_assets = " << cfg_.minAsset << "\n";
    o << "max_assets = " << cfg_.maxAsset << "\n";
    o << "flush_value = " << cfg_.flushValue << "\n";
    o << "max_log_size_gb = "
      << (cfg_.maxLogBytes / (1024ULL * 1024 * 1024)) << "\n\n";

    o << "# Boot/engine flags (no_pow_engine, cache_only_pow, pow_delay,\n"
         "# log_level) are launch-time choices not held in the live config;\n"
         "# carry them over from your launch flags / base config if you used them.\n\n";

    o << "# Base fees\n";
    o << "fee_account = " << cfg_.feeAccount << "\n";
    o << "fee_asset = " << cfg_.feeAsset << "\n";
    o << "fee_tx = " << cfg_.feeTx << "\n";
    o << "fee_query = " << cfg_.feeQuery << "\n";
    o << "fee_vm_mult = " << cfg_.feeVmMult << "\n";
    o << "fee_discount_enabled = "
      << (cfg_.feeDiscountEnabled ? "true" : "false") << "\n\n";

    o << "# L2 file-store fees\n";
    o << "fee_file_rent = "  << cfg_.feeFileRent  << "\n";
    o << "fee_file_write = " << cfg_.feeFileWrite << "\n";
    o << "fee_file_read = "  << cfg_.feeFileRead  << "\n\n";

    o << "# L2 compute fees\n";
    o << "fee_compute_slot_sec = "     << cfg_.feeComputeSlotSec    << "\n";
    o << "fee_compute_cpu_sec = "      << cfg_.feeComputeCpuSec     << "\n";
    o << "fee_compute_rss_byte_day = " << cfg_.feeComputeRssByteDay << "\n";
    o << "fee_compute_net_byte = "     << cfg_.feeComputeNetByte    << "\n";
    o << "fee_bucket_byte_sec = "      << cfg_.feeBucketByteSec     << "\n\n";

    o << "# ChannelMeter net-metering rates (0 = observe only)\n";
    o << "fee_net_byte_sent = "     << cfg_.feeNetByteSent     << "\n";
    o << "fee_net_byte_received = " << cfg_.feeNetByteReceived << "\n";
    o << "fee_net_channel_sec = "   << cfg_.feeNetChannelSec   << "\n";
    o << "fee_net_mem_byte_day = "  << cfg_.feeNetMemByteDay   << "\n\n";

    o << "# Peering — peer_target is the LIVE runtime value (dashboard edits land here).\n";
    o << "peer_target = " << peerTarget_.load() << "\n";
    o << "peer_miner_interval = " << cfg_.peerMinerIntervalSecs << "\n";
    o << "peer_pow_inbound_reciprocation_bps = "
      << cfg_.peerPowInboundReciprocationBps << "\n";
    o << "settlement_max_retries = " << cfg_.settlementMaxRetries << "\n\n";

    o << "# Interfaces\n";
    if (!cfg_.adminSocket.empty())
      o << "admin_socket = \"" << cfg_.adminSocket << "\"\n";
    o << "web_port = " << cfg_.webPort << "\n";
    o << "web_bind = \"" << cfg_.webBind << "\"\n";
    o << "rpc_port = " << cfg_.rpcPort << "\n";
    o << "rpc_max_pending = "        << cfg_.rpcMaxPending        << "\n";
    o << "rpc_max_request_bytes = "  << cfg_.rpcMaxRequestBytes   << "\n";
    o << "rpc_max_response_bytes = " << cfg_.rpcMaxResponseBytes  << "\n";
    o << "rpc_response_timeout_ms = "<< cfg_.rpcResponseTimeoutMs << "\n";
    o << "rpc_rudp_bytes_per_second = " << cfg_.rpcRudpBytesPerSecond << "\n";
    o << "rpc_rudp_burst_bytes = "      << cfg_.rpcRudpBurstBytes     << "\n\n";

    o << "# File store / compute\n";
    o << "file_store_max_bytes = " << cfg_.cesFileStoreMaxBytes << "\n";
    if (!cfg_.cesFileStoreDir.empty())
      o << "file_store_dir = \"" << cfg_.cesFileStoreDir << "\"\n";
    o << "compute_max_instances = " << cfg_.computeMaxInstances << "\n";
    o << "compute_port_base = " << cfg_.computePortBase << "\n";
    o << "compute_port_count = " << cfg_.computePortCount << "\n";
    o << "compute_process_mem_max = " << cfg_.computeProcessMemMax << "\n";
    o << "compute_client_pool_size = " << cfg_.computeClientPoolSize << "\n";
    if (!cfg_.cesComputeUser.empty())
      o << "compute_user = \"" << cfg_.cesComputeUser << "\"\n";
    if (!cfg_.cesComputeWorkDir.empty())
      o << "compute_work_dir = \"" << cfg_.cesComputeWorkDir << "\"\n";
    if (!cfg_.cesComputeChildBinary.empty())
      o << "compute_child_binary = \"" << cfg_.cesComputeChildBinary << "\"\n";
    if (!cfg_.cesExtensionsDir.empty())
      o << "extensions_dir = \"" << cfg_.cesExtensionsDir << "\"\n";
    o << "ext_funding_per_day = " << extFundingPerDay() << "\n";
    o << "ext_local_budget = " << extLocalBudget() << "\n\n";

    // Tables last (everything after a [table] header belongs to that table).
    if (!cfg_.cesplexMounts.empty()) {
      o << "[cesplex_mounts]\n";
      for (const auto& [proto, handler] : cfg_.cesplexMounts)
        o << "\"" << proto << "\" = \"" << handler << "\"\n";
      o << "\n";
    }

    o << "[rpc_rudp]\n";
    o << "max_channels_per_peer = " << cfg_.rpcRudpMaxChannelsPerPeer << "\n";
    o << "max_reorder_bytes_per_channel = "
      << cfg_.rpcRudpMaxReorderBytesPerChannel << "\n";
    o << "max_reorder_msgs_per_channel = "
      << cfg_.rpcRudpMaxReorderMsgsPerChannel << "\n";
    o << "channel_idle_secs = " << cfg_.rpcRudpChannelIdleSecs << "\n\n";

    o << "# The [extension] enabled set + [[peers]] are dynamic (dashboard /\n";
    o << "# peerdata.toml) and not captured here; peers reload from\n";
    o << "# peerdata.toml automatically. Re-add any [extension] <name> = 1 you rely on.\n";

    std::ofstream f(path, std::ios::trunc);
    f << o.str();
    if (!f) {
      std::string why = std::strerror(errno);
      LOGWARNING << "config export: write failed" << SVAR(path) << SVAR(why);
      if (errReason) *errReason = "write to " + path + " failed: " + why;
      return "";
    }
    LOGINFO << "config exported via admin" << SVAR(path);
    return path;
  } catch (std::exception& e) {
    LOGWARNING << "config export failed" << SVAR(e.what());
    if (errReason) *errReason = e.what();
    return "";
  }
}

void CesServer::_runAutoexecSync() {
  std::promise<void> done;
  postLogic( [this, &done]() {
    runAutoexec();
    done.set_value();
  });
  done.get_future().wait();
}

bool CesServer::_executeScheduledRunSync(const HashPrefix& callerPrefix,
                                         const minx::Hash& assetId,
                                         uint64_t budget, uint64_t allowance,
                                         const ces::Bytes& input) {
  std::promise<bool> done;
  postLogic( [&]() {
    ScheduledRun run;
    run.callerPrefix = callerPrefix;
    run.assetId      = assetId;
    run.budget       = budget;
    run.allowance    = allowance;
    run.input        = input;
    done.set_value(executeScheduledRun(run));
  });
  return done.get_future().get();
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
          // resolvedIP is left empty; the peer miner fills it on first probe
          // (off-strand). Keeps DNS off any path that could be hit eagerly.
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

void CesServer::ensurePeerMinerStarted() {
  // Hold the lifecycle lock across the running_ check + CAS + thread assign so
  // it's atomic w.r.t. stop() flipping peerMinerRunning_ and deciding whether to
  // join — a solution arriving at shutdown can't spawn a thread after stop() has
  // already passed the join.
  std::lock_guard lock(peerMinerLifecycleMutex_);
  if (!running_) return;
  // peerMinerRunning_ is both the loop's run flag and the one-shot spawn
  // guard: only the thread that flips it false→true creates the miner.
  bool expected = false;
  if (peerMinerRunning_.compare_exchange_strong(expected, true))
    peerMinerThread_ = std::thread(&CesServer::peerMinerLoop, this);
}

void CesServer::startPeerMiner() {
  bool havePeers;
  { std::lock_guard lock(peerTableMutex_); havePeers = !peerTable_.empty(); }
  // Run the miner whenever there's something to do: a target to mine toward,
  // OR peers whose reachability/verification we want kept fresh (the dashboard
  // and settlement both want live peer state, even at target 0 — mining itself
  // stays gated on the target inside the loop).
  if (peerTarget_.load() == 0 && !havePeers) return;
  LOGINFO << "starting peer miner thread" << VAR(peerTarget_.load())
          << VAR(havePeers);
  ensurePeerMinerStarted();
}

void CesServer::peerMinerLoop() {
  LOGINFO << "peer miner loop started";

  auto serverPubKey = serverKeyPair_.getPublicKeyAsHash();
  auto serverMapKey = Account::getMapKey(serverPubKey);

  std::string myServerAddr = cfg_.serverName.empty()
    ? ":" + std::to_string(boundPort_)
    : cfg_.serverName;

  while (peerMinerRunning_) {
   // A background maintenance thread must never take the process down: any
   // error in a cycle is logged and the loop keeps going (next cycle retries).
   try {
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

    // Two disjoint mining modes, selected by peer.outbound:
    //   outbound (trusted): maintain a CREDIT LEVEL — target = peerTarget,
    //     progress = our queried reserve there (ourBalanceThere).
    //   inbound (untrusted): pure PoW reciprocation — target = H_in * bps /
    //     10000, progress = our self-counted lifetime PoW on them
    //     (totalOutboundPoW). Never trusts a remote balance reading. bps =
    //     peerPowInboundReciprocationBps (0 = off); for bps <= 10000 our total
    //     mined stays <= their proven work, for any number of hosts.
    const uint64_t inboundBps = cfg_.peerPowInboundReciprocationBps;
    auto mineTarget = [&](const PeerEntry& p) -> int64_t {
      if (p.outbound) return static_cast<int64_t>(peerTarget_.load());
      if (inboundBps == 0) return 0;
      // H_in * bps / 10000, split so it stays within uint64 for realistic H_in.
      const uint64_t hin = p.totalInboundPoW;
      return static_cast<int64_t>((hin / 10000) * inboundBps
                                  + (hin % 10000) * inboundBps / 10000);
    };
    auto mineProgress = [](const PeerEntry& p) -> int64_t {
      return p.outbound ? p.ourBalanceThere
                        : static_cast<int64_t>(p.totalOutboundPoW);
    };

    // Merge probe + mining results for every candidate we touched this round
    // back into peerTable_. `lastCheckTime != 0` means the probe loop actually
    // ran on this candidate (either success or failure path updates it).
    // Called twice per cycle: once right after probing so reachability is
    // visible to cross-transfers immediately, and once after mining to persist
    // the updated reserve/PoW totals. The post-probe call matters because
    // mining a single peer can run RandomX for a long time; without it a peer
    // that needs mining holds its fresh reachability hostage to that mining,
    // and cross-transfers fail CES_ERROR_UNKNOWN_PEER for the whole duration.
    auto mergeCandidates = [&]() {
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
            p.rpcPort = c.rpcPort;
            p.lastCheckTime = c.lastCheckTime;
            p.resolvedIP = c.resolvedIP;
            p.resolvedEndpoint = c.resolvedEndpoint;
            p.resolvedEndpointValid = c.resolvedEndpointValid;
            break;
          }
        }
      }
    };

    // Pick the neediest reachable peer: largest positive gap (target - progress).
    int bestIdx = -1;
    int64_t bestGap = 0;

    for (int i = 0; i < static_cast<int>(candidates.size()); ++i) {
      auto& peer = candidates[i];
      if (peer.declaredAddress.empty()) continue;

      // Always probe every peer for reachability — a free connect + handshake
      // + unsigned balance query, independent of whether we'll mine it. Mining
      // is gated separately below on the credit target, so a peer with target 0
      // still reports accurate reachability/verification (e.g. to the
      // dashboard). Reachability TRANSITIONS log at INFO (a lifecycle event);
      // steady-state re-checks stay at DEBUG so a 60 s probe loop isn't spam.
      bool wasReachable = peer.reachable;
      bool everChecked = (peer.lastCheckTime != 0);

      // Try to connect and query balance (this IS the verification)
      try {
        auto ep = Resolver::resolveUdp(peer.declaredAddress);
        // Populate resolvedIP off-strand (here on the miner thread) — this is
        // the single source for it, feeding isConnected's peer-IP trust check.
        peer.resolvedIP = ep.address();
        // And the full endpoint, so settlement dispatch never has to resolve
        // DNS on the logic strand (see getOrCreateSettlementClient).
        peer.resolvedEndpoint = ep;
        peer.resolvedEndpointValid = true;
        CesClient client(ep, false);
        client.setKey(serverKeyPair_);  // to sign + pay for the verification query
        client.start(0);
        if (!client.connect()) {
          peer.reachable = false;
          peer.pingFailures++;
          peer.lastCheckTime = minx::getSecsSinceEpoch();
          if (wasReachable || !everChecked)
            LOGINFO << "peer miner: unreachable " << peer.declaredAddress
                    << " failures=" << peer.pingFailures;
          else
            LOGDEBUG << "peer miner: unreachable " << peer.declaredAddress
                     << " failures=" << peer.pingFailures;
          client.stop();
          continue;
        }

        // The connect/getInfo above is the FREE liveness probe — reachability,
        // never trust. `verified` is deliberately NOT set from the key the peer
        // merely CLAIMS in getInfo (a lying host can echo any pubkey); it flips
        // true only via the signed server-info below, and stays sticky after.
        peer.reachable = true;
        // The handshake already carries the peer's rpc port; capture it so the
        // peer table (and ces.peers()) expose where to reach the peer's CesPlex
        // handlers, no separate ces.ping needed on the discovery hot path.
        peer.rpcPort = client.getServerRpcPort();
        peer.pingFailures = 0;
        peer.lastCheckTime = minx::getSecsSinceEpoch();

        // Our reserve at the peer — the mining-progress reading AND the
        // affordability gate for the paid verification below.
        int64_t balance = 0;
        uint32_t nonce = 0;
        uint8_t rc = client.queryAccount(serverMapKey, balance, nonce);
        peer.ourBalanceThere = (rc == CES_OK) ? balance : 0;

        // Verification toll, paid once. A peer becomes `verified` only after a
        // SIGNED, paid server-info whose reply authenticates against its key —
        // proof the box actually holds the private half (an impostor that merely
        // echoes the pubkey in getInfo can't sign the reply). Fire it only while
        // still unverified, the claimed key matches what we expect, and we hold
        // enough at the peer to cover the query fee; otherwise the free getInfo
        // was liveness only. Once verified it is sticky — and upsertPeer won't let
        // an unsigned inbound PoW move a verified address. So an inbound PoW can
        // never bind a key to an address we didn't go confirm and pay to prove.
        if (!peer.verified &&
            client.getServerKey() == peer.ckey &&
            peer.ourBalanceThere >=
                static_cast<int64_t>(std::max<uint64_t>(cfg_.feeQuery, 1))) {
          std::vector<ServerInfoEntry> entries;
          if (client.queryServerInfo(entries) == CES_OK) {
            peer.verified = true;
            LOGINFO << "peer miner: verified " << peer.declaredAddress
                    << " via signed server-info";
          }
        }
        if (!wasReachable || !everChecked) {
          LOGINFO << "peer miner: reachable " << peer.declaredAddress
                  << " verified=" << peer.verified;
        }

        client.disconnect();
        client.stop();

      } catch (std::exception& e) {
        peer.reachable = false;
        peer.pingFailures++;
        peer.lastCheckTime = minx::getSecsSinceEpoch();
        if (wasReachable || !everChecked)
          LOGINFO << "peer miner: error checking " << peer.declaredAddress
                  << " " << e.what();
        else
          LOGDEBUG << "peer miner: error checking " << peer.declaredAddress
                   << " " << e.what() << " failures=" << peer.pingFailures;
        continue;
      }

      // Outbound needs a valid reserve reading; inbound is self-measured.
      if (peer.outbound && peer.ourBalanceThere < 0) continue;
      int64_t gap = mineTarget(peer) - mineProgress(peer);
      if (gap > bestGap) {
        bestGap = gap;
        bestIdx = i;
      }
    }

    // Make reachability visible before the (possibly long) mining step below.
    mergeCandidates();

    if (bestIdx >= 0) {
      auto& peer = candidates[bestIdx];
      LOGDEBUG << "peer miner: mining on " << peer.declaredAddress
               << " (" << (peer.outbound ? "outbound R=" : "inbound Hout=")
               << mineProgress(peer) << " target=" << mineTarget(peer) << ")";

      try {
        auto ep = Resolver::resolveUdp(peer.declaredAddress);
        // The peer miner ALWAYS uses the full RandomX dataset.
        //
        // TOMBSTONE — do NOT "upgrade" this to a cache-only / light-mode option
        // (a previous one was deliberately removed). It buys nothing: the miner
        // holds exactly ONE dataset at a time (it mines a single peer per cycle),
        // so there is no memory to save — while cache mode cripples the hash rate
        // so badly that reaching any real credit target crawls. If you want cheap
        // PoW for simulations or tests, MOCK the proofs; never run real mining in
        // cache mode. Full dataset, always.
        CesClient client(ep, /*useFullDataset=*/true);
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
          } else {
            std::map<std::string, std::string> appData;
            appData["server"] = myServerAddr;

            // Smart difficulty: scale UP from the peer's floor toward the
            // remaining credit gap, so a large target is reached in a few big
            // solutions instead of thousands of tiny ones. The hash cost per
            // credit is constant regardless of difficulty, so only the
            // per-solution network/cycle overhead differs — fewer, bigger
            // solutions amortize it. mint(D) = 2^(D-1) * POW_REWARD_BASE; grow D
            // while the next solution's mint still fits the gap. Floor = peerDiff
            // (never below: a fresh reserve account needs mint(D) >= the peer's
            // feeAccount, which a correctly configured peer keeps below
            // mint(peerDiff); and a missing account makes gap == full target, so
            // the floor is moot — the gap forces a high difficulty anyway). Cap
            // RELATIVE to peerDiff (PEER_MINER_MAX_DIFF_ABOVE) so one solution's
            // work stays a small multiple of what this peer expects — the cycle
            // returns quickly and the miner round-robins quotas across all peers
            // instead of locking for hours on one oversized solution.
            int64_t gap = mineTarget(peer) - mineProgress(peer);
            uint8_t mineCap = peerDiff + PEER_MINER_MAX_DIFF_ABOVE;
            uint8_t mineDiff = peerDiff;
            while (mineDiff < mineCap &&
                   (uint64_t(1) << mineDiff) * POW_REWARD_BASE <=
                       static_cast<uint64_t>(std::max<int64_t>(gap, 0)))
              ++mineDiff;
            LOGDEBUG << "peer miner: mining " << peer.declaredAddress
                     << " at difficulty " << static_cast<int>(mineDiff)
                     << " (peerMin=" << static_cast<int>(peerDiff)
                     << " gap=" << gap << ")";

            // Mark "actively mining" only around the real PoW work, so the
            // dashboard can distinguish hashing from a merely-looping thread.
            {
              std::lock_guard<std::mutex> lk(peerMinerActivityMutex_);
              peerMinerMining_ = true;
              peerMinerMiningPeer_ = peer.declaredAddress;
              peerMinerMiningDiff_ = mineDiff;
              peerMinerMiningStartSecs_ = minx::getSecsSinceEpoch();
            }
            auto mineT0 = std::chrono::steady_clock::now();
            auto result = mineOnce(client, mineDiff - peerDiff, appData);
            double mineSecs = std::chrono::duration<double>(
                std::chrono::steady_clock::now() - mineT0).count();
            {
              std::lock_guard<std::mutex> lk(peerMinerActivityMutex_);
              peerMinerMining_ = false;
              // Smoothed hash-rate estimate for the dashboard ETA: a solution at
              // difficulty D takes ~2^D hashes in expectation, so rate ≈ 2^D /
              // solve_time. EMA so one unlucky/lucky solve doesn't whipsaw it.
              if (result.success && mineSecs > 0.0 && mineDiff < 64) {
                double rate = std::ldexp(1.0, mineDiff) / mineSecs;  // 2^D / secs
                peerMinerHashRate_ = peerMinerHashRate_ > 0.0
                    ? 0.5 * peerMinerHashRate_ + 0.5 * rate
                    : rate;
              }
            }
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
          }
          client.disconnect();
        }
        client.stop();
      } catch (std::exception& e) {
        {  // mineOnce may have thrown mid-hash — don't leave "mining" stuck on.
          std::lock_guard<std::mutex> lk(peerMinerActivityMutex_);
          peerMinerMining_ = false;
        }
        LOGDEBUG << "peer miner: mining error " << peer.declaredAddress
                 << " " << e.what();
      }
    } else {
      LOGTRACE << "peer miner: all peers at target or unreachable";
    }

    // Persist the post-mining reserve/PoW totals (reachability was already
    // merged right after the probe loop above).
    mergeCandidates();
    savePeerData();

    // Heartbeat — a visible "the thread is alive and just cycled" signal for
    // the dashboard, so peering isn't an opaque background process.
    lastPeerMinerCycle_.store(minx::getSecsSinceEpoch(),
                              std::memory_order_relaxed);
    peerMinerCycles_.fetch_add(1, std::memory_order_relaxed);
   } catch (const std::exception& e) {
     LOGWARNING << "peer miner: cycle error (continuing): " << e.what();
   } catch (...) {
     LOGWARNING << "peer miner: unknown cycle error (continuing)";
   }

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
  if (!origin.exists())
    return false;

  // Caller's full key (reconstructed from prefix + tail) for the VM io
  // preload — captured before the gas debit, which can delete a just-emptied
  // account and invalidate the accessor.
  minx::Hash callerKey = origin.data().getKey(run.callerPrefix);

  // Reserve the full budget upfront; unused is refunded inside executeVmRun.
  // A prepaid run (future-time wire CES_RUN_ASSET) was already debited at
  // submission — don't double-charge it.
  if (!run.prepaid) {
    if (origin.balance() < static_cast<int64_t>(run.budget))
      return false;
    origin.debit(run.budget);
    accounts_.checkFlush(run.budget);
  }

  // Load program
  auto programAsset = assets_.get(run.assetId);
  if (!programAsset.exists()) return true; // program gone but account OK

  HashPrefix programOwnerPrefix = programAsset.data().getOwnerId();
  AssetData programContent = programAsset.data().getContent();

  // Same transactional core as the wire path: a scheduled run is now atomic
  // (undo-log rollback, durable re-journal, deferred cross-transfer) instead
  // of mutating directly. The raw (undiscounted) gas multiplier preserves the
  // prepaid budget contract locked in at schedule time; wire CES_RUN_ASSET
  // discounts via FeeKind::VMMult because the caller spends a fresh budget.
  VmRunRequest vreq;
  vreq.callerPrefix       = run.callerPrefix;
  vreq.callerKey          = callerKey;
  vreq.selfAssetKey       = run.assetId;
  vreq.programOwnerPrefix = programOwnerPrefix;
  vreq.code               = ces::Bytes(programContent.begin(), programContent.end());
  vreq.input              = run.input;
  vreq.budget             = run.budget;
  vreq.allowance          = run.allowance;
  vreq.gasMult            = cfg_.feeVmMult;
  vreq.enableVerifySig    = false;
  executeVmRun(vreq);

  tpsInc();
  return true;
}

uint8_t CesServer::scheduleRun(const HashPrefix& callerPrefix,
                                const minx::Hash& assetId,
                                uint64_t budget,
                                uint64_t allowance,
                                const ces::Bytes& input,
                                uint64_t time_us, bool prepaid) {
  ScheduleKey key;
  return scheduleRunUndoable(callerPrefix, assetId, budget, allowance, input,
                             time_us, prepaid, key);
}

uint8_t CesServer::scheduleRunUndoable(const HashPrefix& callerPrefix,
                                        const minx::Hash& assetId,
                                        uint64_t budget, uint64_t allowance,
                                        const ces::Bytes& input,
                                        uint64_t time_us, bool prepaid,
                                        ScheduleKey& outKey) {
  if (scheduledRuns_.size() >= cfg_.maxScheduledEntries)
    return CES_ERROR_QUEUE_FULL;
  if (time_us == 0) time_us = 1; // "next tick"
  outKey = ScheduleKey{time_us, scheduledSeq_++};
  LOGTRACE << "scheduleRun" << VAR(time_us) << VAR(budget) << VAR(allowance)
           << VAR(scheduledRuns_.size());
  scheduledRuns_.emplace(
    outKey,
    ScheduledRun{callerPrefix, assetId, budget, allowance, input, prepaid});
  return CES_OK;
}

// ===========================================================================
// SYS_RPC dispatcher trio — queueRpc / executeRpc / completeRpc
// ===========================================================================
//
// Three-stage flow, each stage on a specific thread:
//
//   1. queueRpc — LOGIC STRAND
//      Validate destination + file auth, walk the chain to materialize
//      the raw request bytes, post to rpcTaskIO_. No per-op envelope —
//      the signed bind contract authenticates the channel once at open,
//      and the body flows raw on it.
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
// The RpcSession class lives near the top of this file (above
// CesServer::CesServer) because start()'s Rudp receive callback demuxes
// to shared_ptr<RpcSession> and needs the complete type at the point
// where the lambda is defined.

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
  // function-local random_device is fine. A collision within a live peer
  // session map is negligibly unlikely and not a correctness issue: the
  // inserted session would replace the older entry, which is acceptable here.
  std::random_device rd;
  const uint32_t channelId = static_cast<uint32_t>(rd());

  auto self = this;
  auto session = std::make_shared<RpcSession>(
    rpcTaskIO_, *rpcRudp_, peer, channelId,
    std::move(pending->requestBody),
    cfg_.rpcResponseTimeoutMs, cfg_.rpcMaxResponseBytes,
    channelMeter_.get(), serverKeyPair_,
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