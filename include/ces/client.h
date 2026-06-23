#pragma once

#include <minx/minx.h>
#include <minx/proxy/minxclienttransport.h>

#include <ces/account.h>
#include <ces/asset.h>
#include <ces/util/ctrlc.h>
#include <ces/keys.h>
#include <ces/protocol.h>
#include <ces/types.h>

#include <atomic>
#include <limits>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace ces {

class CesClient : public minx::MinxListener {
public:
  /** Construct in UDP mode (direct connection to server). The default Minx
   *  config is server-sized (a ~32MB recv ring); a memory-constrained or
   *  one-shot caller can pass a lighter config (e.g. a small recvBuffersSize). */
  CesClient(const boost::asio::ip::udp::endpoint& serverEndpoint,
            bool useDataset = true,
            const minx::MinxConfig& config = minx::MinxConfig{"cl"});

  /** Construct in TCP proxy mode (connection through a MinxProxy). */
  CesClient(const boost::asio::ip::tcp::endpoint& proxyEndpoint,
            bool useDataset = true);

  virtual ~CesClient();

  void setKey(const KeyPair& keyPair);
  void setTries(int tries) { tries_ = tries > 0 ? tries : 1; }
  int getTries() const { return tries_; }
  // Per-attempt reply timeout, which doubles as the sleep between connect
  // retries (ms). Default 3000; a fast-fail caller (e.g. a crawler that must
  // not block 3s on a dead host) lowers it. Clamped to >= 1.
  void setRetryIntervalMs(int ms) { retryIntervalMs_ = ms > 0 ? ms : 1; }
  int getRetryIntervalMs() const { return retryIntervalMs_; }
  bool start(uint16_t localPort = 0);
  bool stop();
  bool connect();
  bool disconnect();

  // Move this (started) client to a different remote, reusing the transport.
  // The udp overload moves to a new server; the tcp overload reconnects to a
  // new proxy. Both disconnect() to drop per-peer session state; the udp
  // overload also moves the inbound fence (currentTarget_). Returns false in
  // the wrong mode or, for tcp, on reconnect failure. Call connect() after.
  bool setRemoteEndpoint(const boost::asio::ip::udp::endpoint& serverEndpoint);
  bool setRemoteEndpoint(const boost::asio::ip::tcp::endpoint& proxyEndpoint);
  bool getInfo();

  int proveWork(const minx::MinxProveWork& msg, minx::Hash& beneficiary,
                uint64_t& creditAmount, uint64_t& time);

  /**
   * Query the state of a given account.
   * @return CES_OK, CES_ERROR_NOT_FOUND, or CES_ERROR_TIMEOUT/INTERNAL
   */
  uint8_t queryAccount(const ces::HashPrefix& accountMapKey, int64_t& balance,
                       uint32_t& nonce,
                       ces::HashPrefix& lastXferDest,
                       uint64_t& lastXferAmount,
                       uint32_t& lastXferTime);
  uint8_t queryAccount(const ces::HashPrefix& accountMapKey, int64_t& balance,
                       uint32_t& nonce);

  /**
   * Signed query for account details.
   * @return CES_OK, protocol error, or CES_ERROR_TIMEOUT/INTERNAL
   */
  uint8_t queryAccountSigned(const ces::HashPrefix& accountMapKey,
                             uint8_t items,
                             std::vector<AccountEntry>& accounts);

  /**
   * Safe transfer — fails if destination account doesn't exist.
   * @return CES_OK on success, CES_ERROR_TARGET_NOT_FOUND, or other error.
   */
  uint8_t transfer(const ces::Hash& dest, uint64_t amount,
                   int64_t& newOriginBal);

  /**
   * Open transfer — auto-creates destination account if it doesn't exist.
   * @return CES_OK on success, otherwise specific error code.
   */
  uint8_t openTransfer(const ces::Hash& dest, uint64_t amount,
                       int64_t& newOriginBal);

  /**
   * Create payment account — creates dest with negative balance (amount owed).
   * Fails if destination already exists.
   * @return CES_OK on success, CES_ERROR_INVALID_TARGET_ACCOUNT if exists.
   */
  uint8_t createPayment(const ces::Hash& dest, uint64_t amount,
                        uint8_t days, int64_t& newOriginBal);

  /**
   * Cross-server transfer — send credits to a key on a peer server.
   * The local server handles the settlement.
   * @return CES_OK, CES_ERROR_UNKNOWN_PEER, CES_ERROR_QUEUE_FULL,
   *         or standard error.
   */
  uint8_t crossTransfer(const ces::Hash& dest, uint64_t amount,
                        const std::string& destServer,
                        int64_t& newOriginBal);

  // successfulCount sentinel for "outcome unknown" (a TIMEOUT: request sent,
  // reply lost). Distinct from 0 (= none applied). Real counts are 0..MAX_ITEMS.
  static constexpr uint8_t BULK_COUNT_UNKNOWN = 0xFF;

  // successfulCount: on CES_OK the true number applied (partial possible); on
  // CES_ERROR_TIMEOUT BULK_COUNT_UNKNOWN; on other errors 0.
  uint8_t bulkTransfer(const std::vector<BulkTransferItem>& transfers,
                       int64_t& newOriginBal, uint8_t& successfulCount);

  /**
   * Mine a PoW solution.
   * @param extraDifficulty Added to server's minDiff.
   * @param appData Optional application data (map<string,string>).
   *   Serialized into the PoW data field; hdata = SHA256 of that payload.
   *   An empty map hashes the empty payload (a fixed, non-zero digest).
   */
  std::optional<minx::MinxProveWork> mine(
    const uint8_t extraDifficulty,
    const std::map<std::string, std::string>& appData = {},
    int numThreads = 1,
    uint64_t startNonce = 0,
    uint64_t maxIters = 0);

  // --- Asset Operations (Return uint8_t status code) ---

  uint8_t createAsset(const Hash& assetId, const AssetData& content,
                      uint16_t days, bool private_ = false,
                      bool immutable = false);

  uint8_t updateAsset(const Hash& assetId, const HashPrefix& newOwner,
                      const AssetData& content, uint32_t price);

  uint8_t updateAssetMeta(const Hash& assetId, const HashPrefix& newOwner,
                          uint32_t price);

  uint8_t updateAssetFast(const Hash& assetId, const AssetData& content);

  uint8_t fundAsset(const Hash& assetId, uint16_t days);

  uint8_t buyAsset(const Hash& assetId, uint64_t amount);

  uint8_t giveAsset(const Hash& assetId, const HashPrefix& newOwner);

  /**
   * Execute VM bytecode on an asset.
   * @param allowance Per-run cap on caller-account debits inside the VM
   *   (transfers, asset purchases, protocol fees). UINT64_MAX = no
   *   enforcement. Use a smaller value when running an untrusted gateway
   *   program that should not be able to drain more than a budgeted amount
   *   from the caller's account beyond the gas budget itself.
   * @return CES_OK on VM success, CES_ERROR_VM_FAILED on VM error, or protocol error.
   * On success, outVmError=CESVM_OK. On VM failure, outVmError has the VM error code.
   */
  uint8_t runAsset(const Hash& assetId, uint64_t budget,
                   const ces::Bytes& input,
                   uint64_t& outVmError, uint64_t& outBudgetUsed,
                   ces::Bytes& outOutput,
                   bool nonceless = false,
                   uint64_t allowance =
                     std::numeric_limits<uint64_t>::max());

  // Allowance consumed by the most recent runAsset() reply. Always
  // 0 when the call used the unlimited-allowance sentinel.
  uint64_t getLastRunAssetAllowanceUsed() const {
    return runAssetResultAllowanceUsed_;
  }

  /**
   * Query asset.
   * @return CES_OK, CES_ERROR_ASSET_NOT_FOUND, etc.
   */
  uint8_t queryAssetSigned(const Hash& assetId, uint8_t items,
                           std::vector<AssetEntry>& assets);

  /**
   * Query asset (Unsigned/Public).
   * @param outBalance raw 16-bit balance — bits 0..12 = days remaining
   *   (max 8191); bit 13 = immutable; bit 14 = asset-owned; bit 15 =
   *   private. Use `assetDays(b)` for the day count and the
   *   `isAsset{Private,Owned,Immutable}(b)` predicates for flags.
   * @return CES_OK, CES_ERROR_NOT_FOUND, or CES_ERROR_TIMEOUT
   */
  uint8_t queryAsset(const Hash& assetId, HashPrefix& outOwner,
                     AssetData& outContent, uint16_t& outBalance,
                     uint32_t& outPrice);

  /**
   * Query a peer-table slot (Unsigned/Public) for discovery.
   * @return CES_OK (outFound says whether the slot held a peer) or
   *   CES_ERROR_TIMEOUT.
   */
  uint8_t queryPeerInfo(uint16_t index, uint16_t& outCount, bool& outFound,
                    Hash& outPubkey, std::string& outAddress);


  /**
   * Query extended server info (Signed/Paid).
   * Returns self-describing key-value pairs.
   * @return CES_OK, protocol error, or CES_ERROR_TIMEOUT/INTERNAL
   */
  uint8_t queryServerInfo(std::vector<ServerInfoEntry>& outEntries);

  // Info obtained from the MINX handshake (available after connect)
  uint8_t getMinDifficulty() const { return serverMinDiff_; }
  uint8_t getMinSecsPoW() const { return serverMinSecsPoW_; }
  uint16_t getPendingPoWs() const { return serverPendingPoWs_; }
  uint16_t getTps() const { return serverTps_; }
  uint16_t getServerRpcPort() const { return serverRpcPort_; }
  const minx::Hash& getServerKey() const { return serverKey_; }
  HashPrefix getServerId() const { return Account::getMapKey(serverKey_); }

  void incomingInfo(const minx::SockAddr& addr,
                    const minx::MinxInfo& msg) override;
  void incomingMessage(const minx::SockAddr& addr,
                       const minx::MinxMessage& msg) override;
  void incomingApplication(const minx::SockAddr& addr,
                           const uint8_t code,
                           const minx::Bytes& data) override;

  // Set a callback for incoming APPLICATION messages (server push).
  // Called on the network thread — keep it fast.
  using ApplicationCallback = std::function<void(const uint8_t* data, size_t len)>;
  void onApplicationMessage(ApplicationCallback cb) { appCallback_ = std::move(cb); }
  bool ensureServerTicket();

private:
  uint8_t getMyNonce(uint32_t& outNextNonce);

  // True iff `addr` is the server currently pointed at; always true in TCP
  // proxy mode. The incoming* handlers call it to drop a reply from a previous
  // server, which the re-pointable open socket can still deliver.
  bool isCurrentPeer(const minx::SockAddr& addr) const;

  // Send a signed request and wait for a matching response, with retries.
  // The caller is responsible for filling `req` completely (including
  // originId/ownerId, serverId, reqNonce, and op-specific fields) before
  // calling. `gen` is the generation counter that the incoming dispatcher
  // increments when the matching response arrives. `resultCode` is the
  // member where the dispatcher stores the response's rcode. `matchFn`
  // returns true when a newly-arrived response matches this request's
  // identity fields (typically checking reqNonce and originId/ownerId).
  //
  // Returns `resultCode` on success, CES_ERROR_INTERNAL on interrupt or
  // handshake failure, CES_ERROR_TIMEOUT after all retries exhausted.
  template <typename Req, typename MatchFn>
  uint8_t sendSigned(Req& req, std::atomic<uint64_t>& gen,
                     const uint8_t& resultCode, MatchFn&& matchFn) {
    if (!ensureServerTicket())
      return CES_ERROR_INTERNAL;

    minx::MinxMessage msg{0, transport_->generatePassword(), serverTicket_,
                          req.toBytes(keyPair_)};
    uint64_t g = gen.load();

    for (int i = 0; i < tries_; ++i) {
      transport_->sendMessage(msg);
      auto res = ces::waitFor(retryIntervalMs_, [&]() {
        return g < gen.load() && matchFn();
      });
      if (res == ces::WaitResult::Success) return resultCode;
      if (res == ces::WaitResult::Interrupted) return CES_ERROR_INTERNAL;
    }
    return CES_ERROR_TIMEOUT;
  }

  std::unique_ptr<minx::MinxClientTransport> transport_;
  KeyPair keyPair_;

  // The server currently pointed at, normalized to v4-mapped IPv6 to match
  // inbound sender addresses on the dual-stack v6 socket. Written by the ctor
  // and setRemoteEndpoint on the caller thread, read by the incoming* handlers
  // on the IO thread; the mutex guards that.
  minx::SockAddr currentTarget_;
  mutable std::mutex targetMutex_;
  int tries_ = 3;
  int retryIntervalMs_ = 3000;
  ApplicationCallback appCallback_;
  bool connected_ = false;
  minx::Hash serverKey_;
  uint8_t serverMinDiff_ = 0;
  uint64_t serverMinPoWTimestamp_ = 0;
  uint64_t serverTicket_ = 0;
  uint64_t serverTicketLastTime_ = 0;
  uint8_t serverMinSecsPoW_ = 0;
  uint16_t serverPendingPoWs_ = 0;
  uint16_t serverTps_ = 0;
  uint16_t serverRpcPort_ = 0;
  std::atomic<uint64_t> serverInfoGen_ = 0;

  // Tracking vars
  HashPrefix accQueryId_;
  int64_t accQueryBal_ = 0;
  uint32_t accQueryNonce_ = 0;
  HashPrefix accQueryLastXferDest_{};
  uint64_t accQueryLastXferAmount_ = 0;
  uint32_t accQueryLastXferTime_ = 0;
  std::atomic<uint64_t> accQueryGen_ = 0;

  minx::Hash solQueryHash_;
  uint8_t solQueryCode_ = 0;
  std::atomic<uint64_t> solQueryGen_ = 0;

  minx::Hash proveWorkSolHash_;
  minx::Hash proveWorkBeneficiary_;
  uint64_t proveWorkCreditAmount_ = 0;
  uint64_t proveWorkServerTimeSecsEpoch_ = 0;
  std::atomic<uint64_t> proveWorkGen_ = 0;

  uint8_t transferResultCode_ = 0;
  uint32_t transferResultNonce_ = 0;
  int64_t transferNewOriginBal_ = 0;
  std::atomic<uint64_t> transferGen_ = 0;

  uint8_t openTransferResultCode_ = 0;
  uint32_t openTransferResultNonce_ = 0;
  int64_t openTransferNewOriginBal_ = 0;
  std::atomic<uint64_t> openTransferGen_ = 0;

  uint8_t createPaymentResultCode_ = 0;
  uint32_t createPaymentResultNonce_ = 0;
  int64_t createPaymentNewOriginBal_ = 0;
  std::atomic<uint64_t> createPaymentGen_ = 0;

  uint8_t crossTransferResultCode_ = 0;
  uint32_t crossTransferResultNonce_ = 0;
  int64_t crossTransferNewOriginBal_ = 0;
  std::atomic<uint64_t> crossTransferGen_ = 0;

  uint8_t bulkTransferResultCode_ = 0;
  uint8_t bulkTransferSuccessfulCount_ = 0;
  uint32_t bulkTransferResultNonce_ = 0;
  int64_t bulkTransferNewOriginBal_ = 0;
  std::atomic<uint64_t> bulkTransferGen_{0};

  HashPrefix accSignedQueryOriginId_;
  uint32_t accSignedQueryReqNonce_ = 0;
  std::vector<AccountEntry> accSignedQueryAccounts_;
  uint8_t accSignedQueryResultCode_ = 0;
  std::atomic<uint64_t> accSignedQueryGen_ = 0;

  // Asset Results
  HashPrefix createAssetResultOriginId_;
  uint32_t createAssetResultNonce_ = 0;
  uint8_t createAssetResultCode_ = 0;
  std::atomic<uint64_t> createAssetGen_ = 0;

  HashPrefix updateAssetResultOwnerId_;
  uint32_t updateAssetResultNonce_ = 0;
  uint8_t updateAssetResultCode_ = 0;
  std::atomic<uint64_t> updateAssetGen_ = 0;

  HashPrefix updateAssetFastResultOwnerId_;
  uint32_t updateAssetFastResultNonce_ = 0;
  uint8_t updateAssetFastResultCode_ = 0;
  std::atomic<uint64_t> updateAssetFastGen_ = 0;

  HashPrefix updateAssetMetaResultOwnerId_;
  uint32_t updateAssetMetaResultNonce_ = 0;
  uint8_t updateAssetMetaResultCode_ = 0;
  std::atomic<uint64_t> updateAssetMetaGen_ = 0;

  HashPrefix fundAssetResultOriginId_;
  uint32_t fundAssetResultNonce_ = 0;
  uint8_t fundAssetResultCode_ = 0;
  std::atomic<uint64_t> fundAssetGen_ = 0;

  HashPrefix buyAssetResultOriginId_;
  uint32_t buyAssetResultNonce_ = 0;
  uint8_t buyAssetResultCode_ = 0;
  std::atomic<uint64_t> buyAssetGen_ = 0;

  HashPrefix giveAssetResultOwnerId_;
  uint32_t giveAssetResultNonce_ = 0;
  uint8_t giveAssetResultCode_ = 0;
  std::atomic<uint64_t> giveAssetGen_ = 0;

  HashPrefix runAssetResultOriginId_;
  uint32_t runAssetResultNonce_ = 0;
  uint8_t runAssetResultCode_ = 0;
  uint64_t runAssetResultVmError_ = 0;
  uint64_t runAssetResultBudgetUsed_ = 0;
  uint64_t runAssetResultAllowanceUsed_ = 0;
  ces::Bytes runAssetResultOutput_;
  std::atomic<uint64_t> runAssetGen_ = 0;

  uint32_t assetQueryReqNonce_ = 0;
  uint8_t assetQueryResultCode_ = 0;
  std::vector<AssetEntry> assetQueryAssets_;
  std::atomic<uint64_t> assetQueryGen_ = 0;

  Hash assetUnsignedQueryId_;
  HashPrefix assetUnsignedQueryOwner_;
  AssetData assetUnsignedQueryContent_;
  uint16_t assetUnsignedQueryBalance_ = 0;
  uint32_t assetUnsignedQueryPrice_ = 0;
  uint8_t assetUnsignedQueryResultCode_ = 0;
  std::atomic<uint64_t> assetUnsignedQueryGen_ = 0;

  uint16_t peerQueryIndex_ = 0;
  uint16_t peerQueryCount_ = 0;
  uint8_t peerQueryFound_ = 0;
  Hash peerQueryPubkey_{};
  PeerAddr peerQueryAddress_{};
  std::atomic<uint64_t> peerQueryGen_ = 0;


  HashPrefix serverInfoExtOriginId_;
  uint32_t serverInfoExtReqNonce_ = 0;
  uint8_t serverInfoExtResultCode_ = 0;
  std::vector<ServerInfoEntry> serverInfoExtEntries_;
  std::atomic<uint64_t> serverInfoExtGen_ = 0;
};

} // namespace ces