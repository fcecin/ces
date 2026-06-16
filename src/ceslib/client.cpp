#include <ces/client.h>

#include <minx/blog.h>
LOG_MODULE("ccl");

#include <minx/minx.h>

#include <ces/util/ctrlc.h>
#include <ces/protocol.h>

#include <cryptopp/sha.h>
#include <logkv/autoser.h>
#include <logkv/autoser/bytes.h>
#include <logkv/autoser/associative.h>

#include <limits>
#include <thread>

namespace ces {

// Plain unit conversion, used when the server reports its minimum-time-before-
// accepting-PoW in minutes and we need an absolute UTC-seconds deadline.
static constexpr uint64_t SECS_PER_MIN = 60;

// After this many seconds without a fresh INFO, `ensureServerTicket()` forces
// a new handshake — otherwise the cached `serverTicket_` goes stale.
static constexpr uint64_t SERVER_TICKET_REFRESH_SECS = 15;

// Polling interval while waiting for the RandomX VM/dataset to finish
// initializing before `mine()` can call `proveWork()`.
static constexpr int POW_INIT_POLL_MS = 1000;

CesClient::CesClient(const boost::asio::ip::udp::endpoint& serverEndpoint,
                      bool useDataset) {
  LOGTRACE << "CesClient (UDP)";
  transport_ =
    std::make_unique<minx::MinxClientTransport>(this, serverEndpoint);
  transport_->setUseDataset(useDataset);
}

CesClient::CesClient(const boost::asio::ip::tcp::endpoint& proxyEndpoint,
                      bool useDataset) {
  LOGTRACE << "CesClient (TCP)";
  transport_ = std::make_unique<minx::MinxClientTransport>(this, proxyEndpoint);
  transport_->setUseDataset(useDataset);
}

CesClient::~CesClient() {
  LOGTRACE << "~CesClient";
  stop();
  LOGTRACE << "~CesClient done";
}

void CesClient::setKey(const KeyPair& keyPair) { keyPair_ = keyPair; }

bool CesClient::start(uint16_t localPort) {
  LOGTRACE << "start";
  bool ok = transport_->start(localPort);
  LOGTRACE << "start done" << VAR(ok);
  return ok;
}

bool CesClient::stop() {
  if (!transport_)
    return true;
  LOGTRACE << "stop";
  transport_->stop();
  LOGTRACE << "stop done";
  return true;
}

bool CesClient::connect() {
  if (connected_) {
    disconnect();
  }
  LOGTRACE << "connect";

  for (int i = 0; i < tries_; ++i) {
    if (getInfo()) {
      LOGTRACE << "connect ok";
      return connected_ = true;
    }
    if (i + 1 < tries_) {
      LOGTRACE << "connect failed; retrying..." << VAR(i) << VAR(tries_);
      if (!ces::sleep(kRetryIntervalMs)) {
        LOGTRACE << "connect interrupted";
        return false;
      }
    }
  }

  LOGTRACE << "connect out of tries, failed";
  return connected_ = false;
}

bool CesClient::disconnect() {
  if (!connected_) {
    return true;
  }
  LOGTRACE << "disconnect";
  serverKey_ = {};
  serverMinDiff_ = 0;
  serverMinPoWTimestamp_ = 0;
  serverTicket_ = 0;
  serverTicketLastTime_ = 0;
  connected_ = false;
  return true;
}

bool CesClient::getInfo() {
  LOGTRACE << "getInfo";
  minx::MinxGetInfo msg{0, transport_->generatePassword(), {}};

  uint64_t g = serverInfoGen_;
  for (int i = 0; i < tries_; ++i) {
    LOGTRACE << "getInfo send message" << VAR(i) << VAR(tries_);
    transport_->sendGetInfo(msg);
    LOGTRACE << "getInfo wait for reply";
    auto res =
      ces::waitFor(kRetryIntervalMs, [&]() { return g < serverInfoGen_; });
    switch (res) {
    case ces::WaitResult::Success:
      LOGTRACE << "getInfo got new info";
      return true;
    case ces::WaitResult::Interrupted:
      LOGTRACE << "getInfo interrupted";
      return false;
    case ces::WaitResult::Timeout:
      break;
    }
    LOGTRACE << "getInfo timeout; retrying..." << VAR(i) << VAR(tries_);
  }
  LOGTRACE << "getInfo out of tries, failed";
  return false;
}

int CesClient::proveWork(const minx::MinxProveWork& msg,
                         minx::Hash& beneficiary, uint64_t& creditAmount,
                         uint64_t& time) {

  if (!ensureServerTicket()) {
    LOGTRACE << "proveWork can't get a server ticket for minx prove work";
    return minx::MINX_SOLUTION_UNKNOWN;
  }

  LOGTRACE << "proveWork";

  for (int i = 0; i < tries_; ++i) {
    // Fresh password (server spends on first receive)
    minx::MinxProveWork pwmsg{msg.version,
                              transport_->generatePassword(),
                              serverTicket_,
                              msg.ckey,
                              msg.hdata,
                              msg.time,
                              msg.nonce,
                              msg.solution,
                              msg.data};  // carry the appData (hdata commits to
                                          // it); dropping it here is why a mined
                                          // server's address never reached the
                                          // peer it mined — inbound discovery.

    // Capture gen right before sending so stale responses are already behind us
    uint64_t g = proveWorkGen_;

    LOGTRACE << "proveWork sending message" << VAR(i) << VAR(tries_);
    transport_->sendProveWork(pwmsg);
    LOGTRACE << "proveWork waiting for receipt";

    // Inner loop: wait for a gen bump, drain mismatched responses
    int staleCount = 0;
    while (staleCount < tries_) {
      auto res =
        ces::waitFor(kRetryIntervalMs, [&]() { return g < proveWorkGen_; });

      if (res == ces::WaitResult::Interrupted)
        return minx::MINX_SOLUTION_UNKNOWN;

      if (res == ces::WaitResult::Timeout) {
        LOGTRACE << "proveWork timeout; retrying..." << VAR(i)
                 << VAR(tries_);
        break; // retry send
      }

      // Got a response — check if it's for our solution
      if (proveWorkSolHash_ == msg.solution) {
        LOGTRACE << "proveWork got a receipt" << BVAR(proveWorkBeneficiary_)
                 << VAR(proveWorkCreditAmount_)
                 << VAR(proveWorkServerTimeSecsEpoch_)
                 << BVAR(proveWorkSolHash_);
        beneficiary = proveWorkBeneficiary_;
        if (beneficiary != msg.ckey) {
          LOGWARNING << "proveWork server informed mismatched beneficiary"
                     << BVAR(beneficiary) << BVAR(msg.ckey);
        }
        creditAmount = proveWorkCreditAmount_;
        time = proveWorkServerTimeSecsEpoch_;
        return minx::MINX_SOLUTION_SPENT;
      }

      // Stale response for a different solution — drain it and keep waiting
      // without re-sending (the server already has our request)
      LOGTRACE << "proveWork got stale receipt for another solution; draining"
               << BVAR(proveWorkSolHash_) << BVAR(msg.solution);
      g = proveWorkGen_;
      staleCount++;
    }
  }

  LOGTRACE << "proveWork failed to get a receipt; querying PoW status...";

  if (!ensureServerTicket()) {
    LOGTRACE << "proveWork can't get a server ticket for queryPoW";
    return minx::MINX_SOLUTION_UNKNOWN;
  }

  CesUnsignedQuerySolution cesUnsignedQuerySolution{msg.time, msg.solution};

  for (int i = 0; i < tries_; ++i) {
    // Fresh password each retry
    minx::MinxMessage pqmsg{0, transport_->generatePassword(), serverTicket_,
                            cesUnsignedQuerySolution.toBytes()};
    uint64_t g = solQueryGen_;

    LOGTRACE << "proveWork queryPoW sending message" << VAR(i)
             << VAR(tries_);
    transport_->sendMessage(pqmsg);
    LOGTRACE << "proveWork queryPoW waiting for reply";

    int staleCount = 0;
    while (staleCount < tries_) {
      auto res =
        ces::waitFor(kRetryIntervalMs, [&]() { return g < solQueryGen_; });

      if (res == ces::WaitResult::Interrupted) {
        LOGTRACE << "proveWork queryPoW interrupted";
        return minx::MINX_SOLUTION_UNKNOWN;
      }

      if (res == ces::WaitResult::Timeout) {
        LOGTRACE << "proveWork queryPoW timeout; retrying..." << VAR(i)
                 << VAR(tries_);
        break; // retry send
      }

      if (solQueryHash_ == msg.solution) {
        LOGTRACE << "proveWork queryPoW got answer" << VAR(solQueryCode_)
                 << BVAR(solQueryHash_);
        beneficiary = {};
        creditAmount = 0;
        time = 0;
        return solQueryCode_;
      }

      LOGTRACE << "proveWork queryPoW got stale answer; draining"
               << BVAR(solQueryHash_) << BVAR(msg.solution);
      g = solQueryGen_;
      staleCount++;
    }
  }
  LOGTRACE << "proveWork queryPoW out of tries";
  return minx::MINX_SOLUTION_UNKNOWN;
}

uint8_t CesClient::queryAccount(const ces::HashPrefix& accountMapKey,
                                int64_t& balance, uint32_t& nonce,
                                ces::HashPrefix& lastXferDest,
                                uint64_t& lastXferAmount,
                                uint32_t& lastXferTime) {
  LOGTRACE << "queryAccount";
  if (!ensureServerTicket())
    return CES_ERROR_INTERNAL;

  CesUnsignedQueryAccount cesUnsignedQueryAccount{accountMapKey};
  minx::MinxMessage msg{0, transport_->generatePassword(), serverTicket_,
                        cesUnsignedQueryAccount.toBytes()};

  uint64_t g = accQueryGen_;
  int staleCount = 0;
  for (int i = 0; i < tries_; ++i) {
    LOGTRACE << "query account sending message" << VAR(i) << VAR(tries_);
    transport_->sendMessage(msg);
    LOGTRACE << "query account waiting for reply";
    auto res =
      ces::waitFor(kRetryIntervalMs, [&]() { return g < accQueryGen_; });

    switch (res) {
    case ces::WaitResult::Success:
      if (accQueryId_ != accountMapKey) {
        LOGTRACE << "got queryAccount response mismatched ID; ignoring";
        g = accQueryGen_;
        if (++staleCount < tries_) { --i; }
        continue;
      }
      balance = accQueryBal_;
      nonce = accQueryNonce_;
      lastXferDest = accQueryLastXferDest_;
      lastXferAmount = accQueryLastXferAmount_;
      lastXferTime = accQueryLastXferTime_;
      return CES_OK;
    case ces::WaitResult::Interrupted:
      return CES_ERROR_INTERNAL;
    case ces::WaitResult::Timeout:
      break;
    }
    LOGTRACE << "queryAccount timeout; retrying..." << VAR(i)
             << VAR(tries_);
  }
  return CES_ERROR_TIMEOUT;
}

uint8_t CesClient::queryAccount(const ces::HashPrefix& accountMapKey,
                                int64_t& balance, uint32_t& nonce) {
  ces::HashPrefix xd{};
  uint64_t xa = 0;
  uint32_t xt = 0;
  return queryAccount(accountMapKey, balance, nonce, xd, xa, xt);
}

uint8_t CesClient::getMyNonce(uint32_t& outNextNonce) {
  Hash myFullKey = keyPair_.getPublicKeyAsHash();
  HashPrefix myId = Account::getMapKey(myFullKey);
  int64_t bal = 0;
  uint32_t nonce = 0;
  if (queryAccount(myId, bal, nonce) != CES_OK)
    return CES_ERROR_INTERNAL;
  outNextNonce = nonce + 1;
  return CES_OK;
}

uint8_t CesClient::queryAccountSigned(const ces::HashPrefix& accountMapKey,
                                      uint8_t items,
                                      std::vector<AccountEntry>& accounts) {
  LOGTRACE << "queryAccountSigned";
  uint32_t reqNonce;
  if (!ensureServerTicket() || getMyNonce(reqNonce) != CES_OK)
    return CES_ERROR_INTERNAL;

  Hash myFullKey = keyPair_.getPublicKeyAsHash();
  HashPrefix myId = Account::getMapKey(myFullKey);

  CesQueryAccount req;
  req.originId = myFullKey;
  req.serverId = getServerId();
  req.reqNonce = reqNonce;
  req.queryId = accountMapKey;
  req.items = items;

  uint8_t rc = sendSigned(req, accSignedQueryGen_, accSignedQueryResultCode_,
                          [&] {
    return accSignedQueryReqNonce_ == reqNonce &&
           accSignedQueryOriginId_ == myId;
  });

  if (rc != CES_ERROR_INTERNAL && rc != CES_ERROR_TIMEOUT) {
    if (accSignedQueryResultCode_ == CES_OK)
      accounts = accSignedQueryAccounts_;
    else
      accounts.clear();
  }
  return rc;
}

uint8_t CesClient::transfer(const ces::Hash& dest, uint64_t amount,
                            int64_t& newOriginBal) {
  LOGTRACE << "transfer (safe)";
  newOriginBal = std::numeric_limits<int64_t>::max();
  uint32_t reqNonce;
  if (!ensureServerTicket() || getMyNonce(reqNonce) != CES_OK)
    return CES_ERROR_INTERNAL;

  CesTransfer req;
  req.originId = keyPair_.getPublicKeyAsHash();
  req.serverId = getServerId();
  req.reqNonce = reqNonce;
  req.destKey = dest;
  req.amount = amount;

  uint8_t rc = sendSigned(req, transferGen_, transferResultCode_, [&] {
    return transferResultNonce_ == reqNonce;
  });
  if (rc != CES_ERROR_INTERNAL && rc != CES_ERROR_TIMEOUT)
    newOriginBal = transferNewOriginBal_;
  return rc;
}

uint8_t CesClient::openTransfer(const ces::Hash& dest, uint64_t amount,
                                int64_t& newOriginBal) {
  LOGTRACE << "openTransfer";
  newOriginBal = std::numeric_limits<int64_t>::max();
  uint32_t reqNonce;
  if (!ensureServerTicket() || getMyNonce(reqNonce) != CES_OK)
    return CES_ERROR_INTERNAL;

  CesOpenTransfer req;
  req.originId = keyPair_.getPublicKeyAsHash();
  req.serverId = getServerId();
  req.reqNonce = reqNonce;
  req.destKey = dest;
  req.amount = amount;

  uint8_t rc = sendSigned(req, openTransferGen_, openTransferResultCode_, [&] {
    return openTransferResultNonce_ == reqNonce;
  });
  if (rc != CES_ERROR_INTERNAL && rc != CES_ERROR_TIMEOUT)
    newOriginBal = openTransferNewOriginBal_;
  return rc;
}

uint8_t CesClient::createPayment(const ces::Hash& dest, uint64_t amount,
                                 uint8_t days, int64_t& newOriginBal) {
  LOGTRACE << "createPayment";
  newOriginBal = std::numeric_limits<int64_t>::max();
  uint32_t reqNonce;
  if (!ensureServerTicket() || getMyNonce(reqNonce) != CES_OK)
    return CES_ERROR_INTERNAL;

  CesCreatePayment req;
  req.originId = keyPair_.getPublicKeyAsHash();
  req.serverId = getServerId();
  req.reqNonce = reqNonce;
  req.destKey = dest;
  req.amount = amount;
  req.days = days;

  uint8_t rc = sendSigned(req, createPaymentGen_, createPaymentResultCode_, [&] {
    return createPaymentResultNonce_ == reqNonce;
  });
  if (rc != CES_ERROR_INTERNAL && rc != CES_ERROR_TIMEOUT)
    newOriginBal = createPaymentNewOriginBal_;
  return rc;
}

uint8_t CesClient::crossTransfer(const ces::Hash& dest, uint64_t amount,
                                 const std::string& destServer,
                                 int64_t& newOriginBal) {
  LOGTRACE << "crossTransfer";
  newOriginBal = std::numeric_limits<int64_t>::max();
  uint32_t reqNonce;
  if (!ensureServerTicket() || getMyNonce(reqNonce) != CES_OK)
    return CES_ERROR_INTERNAL;

  CesCrossTransfer req;
  req.originId = keyPair_.getPublicKeyAsHash();
  req.serverId = getServerId();
  req.reqNonce = reqNonce;
  req.destKey = dest;
  req.amount = amount;
  req.destServer = destServer;

  uint8_t rc = sendSigned(req, crossTransferGen_, crossTransferResultCode_, [&] {
    return crossTransferResultNonce_ == reqNonce;
  });
  if (rc != CES_ERROR_INTERNAL && rc != CES_ERROR_TIMEOUT)
    newOriginBal = crossTransferNewOriginBal_;
  return rc;
}

uint8_t CesClient::bulkTransfer(const std::vector<BulkTransferItem>& transfers,
                                int64_t& newOriginBal, uint8_t& successfulCount) {
  LOGTRACE << "bulkTransfer";
  newOriginBal = std::numeric_limits<int64_t>::max();
  successfulCount = 0;
  uint32_t reqNonce;
  if (!ensureServerTicket() || getMyNonce(reqNonce) != CES_OK)
    return CES_ERROR_INTERNAL;

  Hash myFullKey = keyPair_.getPublicKeyAsHash();

  CesBulkTransfer req;
  req.originId = myFullKey;
  req.serverId = getServerId();
  req.reqNonce = reqNonce;
  req.transfers = transfers;

  uint8_t rc = sendSigned(req, bulkTransferGen_, bulkTransferResultCode_, [&] {
    return bulkTransferResultNonce_ == reqNonce;
  });

  if (rc != CES_ERROR_INTERNAL && rc != CES_ERROR_TIMEOUT) {
    newOriginBal = bulkTransferNewOriginBal_;
    successfulCount = bulkTransferSuccessfulCount_;
    return rc;
  }
  if (rc == CES_ERROR_INTERNAL)
    return rc;

  // Reply lost: the outcome is unknown (a partial bulk advances the nonce too,
  // so a nonce check can't distinguish full from partial). Report TIMEOUT with
  // the explicit unknown sentinel rather than guessing a count; callers needing
  // the result re-query the destinations.
  successfulCount = BULK_COUNT_UNKNOWN;
  return CES_ERROR_TIMEOUT;
}

std::optional<minx::MinxProveWork>
CesClient::mine(const uint8_t extraDifficulty,
                const std::map<std::string, std::string>& appData,
                int numThreads, uint64_t startNonce, uint64_t maxIters) {
  LOGTRACE << "mine";
  if (!ensureServerTicket()) {
    LOGDEBUG << "mine can't refresh ticket / info";
    return {};
  }
  transport_->createPoWEngine(serverKey_);
  while (!transport_->checkPoWEngine(serverKey_)) {
    if (!ces::sleep(POW_INIT_POLL_MS))
      return {};
  }

  // Serialize app data and compute hdata = SHA256(serialized)
  minx::Hash hdata = {};
  std::vector<char> serializedData;
  if (!appData.empty()) {
    // Use logkv serialization
    size_t sz = logkv::serializer<std::map<std::string, std::string>>::get_size(appData);
    serializedData.resize(sz);
    logkv::serializer<std::map<std::string, std::string>>::write(
      serializedData.data(), sz, appData);
  }
  // Always hash (empty payload → hash of empty = deterministic)
  CryptoPP::SHA256().CalculateDigest(
    hdata.data(),
    reinterpret_cast<const uint8_t*>(serializedData.data()),
    serializedData.size());

  int targetDiff = serverMinDiff_ + extraDifficulty;
  auto myPubKey = keyPair_.getPublicKeyAsHash();
  auto result = transport_->proveWork(myPubKey, hdata, serverKey_, targetDiff,
                                       numThreads, startNonce, maxIters);

  // Attach serialized data to the PoW message
  if (result && !serializedData.empty())
    result->data = std::move(serializedData);

  return result;
}

// =============================================================================
// ASSET OPERATIONS
// =============================================================================

uint8_t CesClient::createAsset(const Hash& assetId, const AssetData& content,
                               uint16_t days, bool private_, bool immutable) {
  LOGTRACE << "createAsset";
  uint32_t reqNonce;
  if (!ensureServerTicket() || getMyNonce(reqNonce) != CES_OK)
    return CES_ERROR_INTERNAL;

  Hash myFullKey = keyPair_.getPublicKeyAsHash();
  HashPrefix myId = Account::getMapKey(myFullKey);

  CesCreateAsset req;
  req.ownerId = myFullKey;
  req.serverId = getServerId();
  req.reqNonce = reqNonce;
  req.assetId = assetId;
  req.content = content;
  req.amount = assetBalance(days, private_, /*aowned=*/false, immutable);
  req.price = 0;

  return sendSigned(req, createAssetGen_, createAssetResultCode_, [&] {
    return createAssetResultNonce_ == reqNonce &&
           createAssetResultOriginId_ == myId;
  });
}

uint8_t CesClient::updateAsset(const Hash& assetId, const HashPrefix& newOwner,
                               const AssetData& content, uint32_t price) {
  LOGTRACE << "updateAsset";
  uint32_t reqNonce;
  if (!ensureServerTicket() || getMyNonce(reqNonce) != CES_OK)
    return CES_ERROR_INTERNAL;

  Hash myFullKey = keyPair_.getPublicKeyAsHash();
  HashPrefix myId = Account::getMapKey(myFullKey);

  CesUpdateAsset req;
  req.ownerId = myFullKey;
  req.serverId = getServerId();
  req.reqNonce = reqNonce;
  req.assetId = assetId;
  req.content = content;
  req.price = price;
  req.newOwnerId = newOwner;

  return sendSigned(req, updateAssetGen_, updateAssetResultCode_, [&] {
    return updateAssetResultNonce_ == reqNonce &&
           updateAssetResultOwnerId_ == myId;
  });
}

uint8_t CesClient::updateAssetMeta(const Hash& assetId,
                                   const HashPrefix& newOwner, uint32_t price) {
  LOGTRACE << "updateAssetMeta";
  uint32_t reqNonce;
  if (!ensureServerTicket() || getMyNonce(reqNonce) != CES_OK)
    return CES_ERROR_INTERNAL;

  Hash myFullKey = keyPair_.getPublicKeyAsHash();
  HashPrefix myId = Account::getMapKey(myFullKey);

  CesUpdateAssetMeta req;
  req.ownerId = myFullKey;
  req.serverId = getServerId();
  req.reqNonce = reqNonce;
  req.assetId = assetId;
  req.newOwnerId = newOwner;
  req.price = price;

  return sendSigned(req, updateAssetMetaGen_, updateAssetMetaResultCode_, [&] {
    return updateAssetMetaResultNonce_ == reqNonce &&
           updateAssetMetaResultOwnerId_ == myId;
  });
}

uint8_t CesClient::updateAssetFast(const Hash& assetId,
                                   const AssetData& content) {
  LOGTRACE << "updateAssetFast";
  uint32_t reqNonce;
  if (!ensureServerTicket() || getMyNonce(reqNonce) != CES_OK)
    return CES_ERROR_INTERNAL;

  Hash myFullKey = keyPair_.getPublicKeyAsHash();
  HashPrefix myId = Account::getMapKey(myFullKey);

  CesUpdateAssetFast req;
  req.ownerId = myFullKey;
  req.serverId = getServerId();
  req.reqNonce = reqNonce;
  req.assetId = assetId;
  req.content = content;

  return sendSigned(req, updateAssetFastGen_, updateAssetFastResultCode_, [&] {
    return updateAssetFastResultNonce_ == reqNonce &&
           updateAssetFastResultOwnerId_ == myId;
  });
}

uint8_t CesClient::fundAsset(const Hash& assetId, uint16_t days) {
  LOGTRACE << "fundAsset";
  uint32_t reqNonce;
  if (!ensureServerTicket() || getMyNonce(reqNonce) != CES_OK)
    return CES_ERROR_INTERNAL;

  Hash myFullKey = keyPair_.getPublicKeyAsHash();
  HashPrefix myId = Account::getMapKey(myFullKey);

  CesFundAsset req;
  req.originId = myFullKey;
  req.serverId = getServerId();
  req.reqNonce = reqNonce;
  req.assetId = assetId;
  req.amount = days;

  return sendSigned(req, fundAssetGen_, fundAssetResultCode_, [&] {
    return fundAssetResultNonce_ == reqNonce &&
           fundAssetResultOriginId_ == myId;
  });
}

uint8_t CesClient::buyAsset(const Hash& assetId, uint64_t amount) {
  LOGTRACE << "buyAsset";
  uint32_t reqNonce;
  if (!ensureServerTicket() || getMyNonce(reqNonce) != CES_OK)
    return CES_ERROR_INTERNAL;

  Hash myFullKey = keyPair_.getPublicKeyAsHash();
  HashPrefix myId = Account::getMapKey(myFullKey);

  CesBuyAsset req;
  req.originId = myFullKey;
  req.serverId = getServerId();
  req.reqNonce = reqNonce;
  req.assetId = assetId;
  req.priceLimit = amount;

  return sendSigned(req, buyAssetGen_, buyAssetResultCode_, [&] {
    return buyAssetResultNonce_ == reqNonce &&
           buyAssetResultOriginId_ == myId;
  });
}

uint8_t CesClient::giveAsset(const Hash& assetId, const HashPrefix& newOwner) {
  LOGTRACE << "giveAsset";
  uint32_t reqNonce;
  if (!ensureServerTicket() || getMyNonce(reqNonce) != CES_OK)
    return CES_ERROR_INTERNAL;

  Hash myFullKey = keyPair_.getPublicKeyAsHash();
  HashPrefix myId = Account::getMapKey(myFullKey);

  CesGiveAsset req;
  req.ownerId = myFullKey;
  req.serverId = getServerId();
  req.reqNonce = reqNonce;
  req.assetId = assetId;
  req.newOwnerId = newOwner;

  return sendSigned(req, giveAssetGen_, giveAssetResultCode_, [&] {
    return giveAssetResultNonce_ == reqNonce &&
           giveAssetResultOwnerId_ == myId;
  });
}

uint8_t CesClient::runAsset(const Hash& assetId, uint64_t budget,
                            const ces::Bytes& input,
                            uint64_t& outVmError, uint64_t& outBudgetUsed,
                            ces::Bytes& outOutput,
                            bool nonceless,
                            uint64_t allowance) {
  LOGTRACE << "runAsset";
  if (!ensureServerTicket())
    return CES_ERROR_INTERNAL;

  uint32_t reqNonce;
  if (nonceless) {
    reqNonce = CES_NONCELESS;
  } else {
    if (getMyNonce(reqNonce) != CES_OK)
      return CES_ERROR_INTERNAL;
  }

  Hash myFullKey = keyPair_.getPublicKeyAsHash();
  HashPrefix myId = Account::getMapKey(myFullKey);

  CesRunAsset req;
  req.originId = myFullKey;
  req.serverId = getServerId();
  req.reqNonce = reqNonce;
  req.assetId = assetId;
  req.budget = budget;
  req.allowance = allowance;
  req.time = getMicrosSinceEpoch();
  req.input = input;

  // Nonceless mode uses a server-assigned nonce, so the nonce match is
  // skipped — we only check originId.
  uint8_t rc = sendSigned(req, runAssetGen_, runAssetResultCode_, [&] {
    if (nonceless)
      return runAssetResultOriginId_ == myId;
    return runAssetResultNonce_ == reqNonce &&
           runAssetResultOriginId_ == myId;
  });

  if (rc != CES_ERROR_INTERNAL && rc != CES_ERROR_TIMEOUT) {
    outVmError = runAssetResultVmError_;
    outBudgetUsed = runAssetResultBudgetUsed_;
    outOutput = runAssetResultOutput_;
  }
  return rc;
}

uint8_t CesClient::queryAssetSigned(const Hash& assetId, uint8_t items,
                                    std::vector<AssetEntry>& assets) {
  LOGTRACE << "queryAsset";
  uint32_t reqNonce;
  if (!ensureServerTicket() || getMyNonce(reqNonce) != CES_OK)
    return CES_ERROR_INTERNAL;

  CesQueryAsset req;
  req.originId = keyPair_.getPublicKeyAsHash();
  req.serverId = getServerId();
  req.reqNonce = reqNonce;
  req.assetId = assetId;
  req.items = items;

  // Loose match (gen only, no reqNonce/originId): the asset-query response
  // pipeline doesn't track which request is which.
  uint8_t rc = sendSigned(req, assetQueryGen_, assetQueryResultCode_,
                          [] { return true; });

  if (rc != CES_ERROR_INTERNAL && rc != CES_ERROR_TIMEOUT) {
    if (assetQueryResultCode_ == CES_OK)
      assets = assetQueryAssets_;
    else
      assets.clear();
  }
  return rc;
}

uint8_t CesClient::queryAsset(const Hash& assetId, HashPrefix& outOwner,
                              AssetData& outContent, uint16_t& outBalance,
                              uint32_t& outPrice) {
  LOGTRACE << "queryAsset (unsigned)";
  if (!ensureServerTicket())
    return CES_ERROR_INTERNAL;

  CesUnsignedQueryAsset req;
  req.assetId = assetId;

  minx::MinxMessage msg{0, transport_->generatePassword(), serverTicket_,
                        req.toBytes()};
  uint64_t g = assetUnsignedQueryGen_;
  int staleCount = 0;

  for (int i = 0; i < tries_; ++i) {
    transport_->sendMessage(msg);
    auto res = ces::waitFor(kRetryIntervalMs,
                            [&]() { return g < assetUnsignedQueryGen_; });

    switch (res) {
    case ces::WaitResult::Success:
      if (assetUnsignedQueryId_ != assetId) {
        LOGTRACE << "got queryAsset response mismatched ID; ignoring";
        g = assetUnsignedQueryGen_;
        if (++staleCount < tries_) { --i; }
        continue;
      }
      outOwner = assetUnsignedQueryOwner_;
      outContent = assetUnsignedQueryContent_;
      outBalance = assetUnsignedQueryBalance_;
      outPrice = assetUnsignedQueryPrice_;
      return CES_OK;

    case ces::WaitResult::Interrupted:
      return CES_ERROR_INTERNAL;
    case ces::WaitResult::Timeout:
      break;
    }
    LOGTRACE << "queryAsset timeout; retrying..." << VAR(i) << VAR(tries_);
  }
  return CES_ERROR_TIMEOUT;
}

uint8_t CesClient::queryPeerInfo(uint16_t index, uint16_t& outCount, bool& outFound,
                             Hash& outPubkey, std::string& outAddress) {
  if (!ensureServerTicket())
    return CES_ERROR_INTERNAL;

  CesUnsignedQueryPeerInfo req;
  req.index = index;
  minx::MinxMessage msg{0, transport_->generatePassword(), serverTicket_,
                        req.toBytes()};
  uint64_t g = peerQueryGen_;
  int staleCount = 0;

  for (int i = 0; i < tries_; ++i) {
    transport_->sendMessage(msg);
    auto res = ces::waitFor(kRetryIntervalMs,
                            [&]() { return g < peerQueryGen_; });
    switch (res) {
    case ces::WaitResult::Success:
      if (peerQueryIndex_ != index) {
        g = peerQueryGen_;
        if (++staleCount < tries_) { --i; }
        continue;
      }
      outCount = peerQueryCount_;
      outFound = peerQueryFound_ != 0;
      outPubkey = peerQueryPubkey_;
      {
        const auto& a = peerQueryAddress_;
        size_t n = 0;
        while (n < a.size() && a[n] != 0) ++n;
        outAddress.assign(reinterpret_cast<const char*>(a.data()), n);
      }
      return CES_OK;
    case ces::WaitResult::Interrupted:
      return CES_ERROR_INTERNAL;
    case ces::WaitResult::Timeout:
      break;
    }
  }
  return CES_ERROR_TIMEOUT;
}

uint8_t CesClient::queryServerInfo(std::vector<ServerInfoEntry>& outEntries) {
  LOGTRACE << "queryServerInfo";
  uint32_t reqNonce;
  if (!ensureServerTicket() || getMyNonce(reqNonce) != CES_OK)
    return CES_ERROR_INTERNAL;

  Hash myFullKey = keyPair_.getPublicKeyAsHash();
  HashPrefix myId = Account::getMapKey(myFullKey);

  CesQueryServerInfo req;
  req.originId = myFullKey;
  req.serverId = getServerId();
  req.reqNonce = reqNonce;

  uint8_t rc = sendSigned(req, serverInfoExtGen_, serverInfoExtResultCode_, [&] {
    return serverInfoExtReqNonce_ == reqNonce &&
           serverInfoExtOriginId_ == myId;
  });

  if (rc != CES_ERROR_INTERNAL && rc != CES_ERROR_TIMEOUT) {
    if (serverInfoExtResultCode_ == CES_OK)
      outEntries = serverInfoExtEntries_;
    else
      outEntries.clear();
  }
  return rc;
}

// =============================================================================
// MESSAGE DISPATCH
// =============================================================================

void CesClient::incomingInfo(const minx::SockAddr& /* addr */,
                             const minx::MinxInfo& msg) {
  LOGTRACE << "incomingInfo" << VAR(msg.data.size());
  serverTicket_ = msg.gpassword;
  serverTicketLastTime_ = minx::getSecsSinceEpoch();
  if (msg.data.size() < 7) {
    LOGTRACE << "incomingInfo got broken data";
    return;
  }
  serverMinDiff_ = msg.difficulty;
  serverKey_ = msg.skey;
  minx::ConstBuffer buf(msg.data);
  serverMinSecsPoW_ = buf.get<uint8_t>();
  serverPendingPoWs_ = buf.get<uint16_t>();
  serverTps_ = buf.get<uint16_t>();
  serverRpcPort_ = buf.get<uint16_t>();
  serverMinPoWTimestamp_ =
    minx::getSecsSinceEpoch() + serverMinSecsPoW_ * SECS_PER_MIN;
  ++serverInfoGen_;
}

void CesClient::incomingApplication(const minx::SockAddr& /* addr */,
                                    const uint8_t /* code */,
                                    const minx::Bytes& data) {
  if (appCallback_ && !data.empty())
    appCallback_(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

void CesClient::incomingMessage(const minx::SockAddr& /* addr */,
                                const minx::MinxMessage& msg) {
  LOGTRACE << "incomingMessage";
  serverTicket_ = msg.gpassword;
  serverTicketLastTime_ = minx::getSecsSinceEpoch();

  if (msg.data.empty())
    return;

  minx::ConstBuffer buf(msg.data);
  uint8_t code = buf.get<uint8_t>();

  try {
    PublicKey verifier(serverKey_);

    // Deserialize a signed response, verify its signature, invoke the
    // per-response field-copy lambda, then bump the generation counter.
    // On sig-fail: log and do nothing (caller's request will retry or time
    // out normally).
    auto handleSigned = [&](auto res, const char* name,
                            std::atomic<uint64_t>& gen,
                            auto&& copy) {
      if (!res.fromBytes(msg.data, verifier)) {
        LOGTRACE << name << " result sig fail";
        return;
      }
      copy(res);
      ++gen;
    };

    // Same as handleSigned but for unsigned responses (no verifier).
    auto handleUnsigned = [&](auto res, std::atomic<uint64_t>& gen,
                              auto&& copy) {
      res.fromBytes(msg.data);
      copy(res);
      ++gen;
    };

    switch (code) {
    case CES_TRANSFER_RESULT:
      handleSigned(CesTransferResult{}, "transfer", transferGen_, [&](auto& r) {
        transferResultCode_ = r.rcode;
        transferResultNonce_ = r.reqNonce;
        transferNewOriginBal_ = r.originNewBalance;
      });
      break;

    case CES_OPEN_TRANSFER_RESULT:
      handleSigned(CesOpenTransferResult{}, "open transfer", openTransferGen_,
                   [&](auto& r) {
        openTransferResultCode_ = r.rcode;
        openTransferResultNonce_ = r.reqNonce;
        openTransferNewOriginBal_ = r.originNewBalance;
      });
      break;

    case CES_CREATE_PAYMENT_RESULT:
      handleSigned(CesCreatePaymentResult{}, "create payment",
                   createPaymentGen_, [&](auto& r) {
        createPaymentResultCode_ = r.rcode;
        createPaymentResultNonce_ = r.reqNonce;
        createPaymentNewOriginBal_ = r.originNewBalance;
      });
      break;

    case CES_CROSS_TRANSFER_RESULT:
      handleSigned(CesCrossTransferResult{}, "cross transfer",
                   crossTransferGen_, [&](auto& r) {
        crossTransferResultCode_ = r.rcode;
        crossTransferResultNonce_ = r.reqNonce;
        crossTransferNewOriginBal_ = r.originNewBalance;
      });
      break;

    case CES_BULK_TRANSFER_RESULT:
      handleSigned(CesBulkTransferResult{}, "bulk transfer", bulkTransferGen_,
                   [&](auto& r) {
        bulkTransferResultCode_ = r.rcode;
        bulkTransferSuccessfulCount_ = r.successfulCount;
        bulkTransferResultNonce_ = r.reqNonce;
        bulkTransferNewOriginBal_ = r.originNewBalance;
      });
      break;

    case CES_QUERY_ACCOUNT_RESULT:
      handleSigned(CesQueryAccountResult{}, "signed query account",
                   accSignedQueryGen_, [&](auto& r) {
        accSignedQueryOriginId_ = r.originId;
        accSignedQueryReqNonce_ = r.reqNonce;
        accSignedQueryResultCode_ = r.rcode;
        accSignedQueryAccounts_ = r.accounts;
      });
      break;

    case CES_UNSIGNED_QUERY_ACCOUNT_RESULT:
      handleUnsigned(CesUnsignedQueryAccountResult{}, accQueryGen_,
                     [&](auto& r) {
        accQueryId_ = r.queryId;
        accQueryBal_ = r.bal;
        accQueryNonce_ = r.nonce;
        accQueryLastXferDest_ = r.lastXferDest;
        accQueryLastXferAmount_ = r.lastXferAmount;
        accQueryLastXferTime_ = r.lastXferTime;
      });
      break;

    case CES_UNSIGNED_QUERY_SOLUTION_RESULT:
      handleUnsigned(CesUnsignedQuerySolutionResult{}, solQueryGen_,
                     [&](auto& r) {
        solQueryHash_ = r.querySolution;
        solQueryCode_ = r.queryResult;
      });
      break;

    case CES_PROVE_WORK_RESULT:
      handleSigned(CesProveWorkResult{}, "prove work", proveWorkGen_,
                   [&](auto& r) {
        proveWorkSolHash_ = r.solution;
        proveWorkBeneficiary_ = r.beneficiary;
        proveWorkCreditAmount_ = r.creditAmount;
        proveWorkServerTimeSecsEpoch_ = r.serverTime;
      });
      break;

    case CES_CREATE_ASSET_RESULT:
      handleSigned(CesCreateAssetResult{}, "create asset", createAssetGen_,
                   [&](auto& r) {
        createAssetResultOriginId_ = r.ownerId;
        createAssetResultNonce_ = r.reqNonce;
        createAssetResultCode_ = r.rcode;
      });
      break;

    case CES_UPDATE_ASSET_RESULT:
      handleSigned(CesUpdateAssetResult{}, "update asset", updateAssetGen_,
                   [&](auto& r) {
        updateAssetResultOwnerId_ = r.ownerId;
        updateAssetResultNonce_ = r.reqNonce;
        updateAssetResultCode_ = r.rcode;
      });
      break;

    case CES_UPDATE_ASSET_META_RESULT:
      handleSigned(CesUpdateAssetMetaResult{}, "update asset meta",
                   updateAssetMetaGen_, [&](auto& r) {
        updateAssetMetaResultOwnerId_ = r.ownerId;
        updateAssetMetaResultNonce_ = r.reqNonce;
        updateAssetMetaResultCode_ = r.rcode;
      });
      break;

    case CES_UPDATE_ASSET_FAST_RESULT:
      handleSigned(CesUpdateAssetFastResult{}, "update asset fast",
                   updateAssetFastGen_, [&](auto& r) {
        updateAssetFastResultOwnerId_ = r.ownerId;
        updateAssetFastResultNonce_ = r.reqNonce;
        updateAssetFastResultCode_ = r.rcode;
      });
      break;

    case CES_FUND_ASSET_RESULT:
      handleSigned(CesFundAssetResult{}, "fund asset", fundAssetGen_,
                   [&](auto& r) {
        fundAssetResultOriginId_ = r.originId;
        fundAssetResultNonce_ = r.reqNonce;
        fundAssetResultCode_ = r.rcode;
      });
      break;

    case CES_BUY_ASSET_RESULT:
      handleSigned(CesBuyAssetResult{}, "buy asset", buyAssetGen_,
                   [&](auto& r) {
        buyAssetResultOriginId_ = r.originId;
        buyAssetResultNonce_ = r.reqNonce;
        buyAssetResultCode_ = r.rcode;
      });
      break;

    case CES_GIVE_ASSET_RESULT:
      handleSigned(CesGiveAssetResult{}, "give asset", giveAssetGen_,
                   [&](auto& r) {
        giveAssetResultOwnerId_ = r.ownerId;
        giveAssetResultNonce_ = r.reqNonce;
        giveAssetResultCode_ = r.rcode;
      });
      break;

    case CES_RUN_ASSET_RESULT:
      handleSigned(CesRunAssetResult{}, "run asset", runAssetGen_,
                   [&](auto& r) {
        runAssetResultOriginId_ = r.originId;
        runAssetResultNonce_ = r.reqNonce;
        runAssetResultCode_ = r.rcode;
        runAssetResultVmError_ = r.vmError;
        runAssetResultBudgetUsed_ = r.budgetUsed;
        runAssetResultAllowanceUsed_ = r.allowanceUsed;
        runAssetResultOutput_ = std::move(r.output);
      });
      break;

    case CES_QUERY_ASSET_RESULT:
      handleSigned(CesQueryAssetResult{}, "asset query", assetQueryGen_,
                   [&](auto& r) {
        assetQueryReqNonce_ = r.reqNonce;
        assetQueryResultCode_ = r.rcode;
        assetQueryAssets_ = r.assets;
      });
      break;

    case CES_UNSIGNED_QUERY_ASSET_RESULT:
      handleUnsigned(CesUnsignedQueryAssetResult{}, assetUnsignedQueryGen_,
                     [&](auto& r) {
        assetUnsignedQueryId_ = r.assetId;
        assetUnsignedQueryOwner_ = r.ownerId;
        assetUnsignedQueryContent_ = r.content;
        assetUnsignedQueryBalance_ = r.balance;
        assetUnsignedQueryPrice_ = r.price;
      });
      break;

    case CES_QUERY_PEER_INFO_RESULT:
      handleUnsigned(CesUnsignedQueryPeerInfoResult{}, peerQueryGen_,
                     [&](auto& r) {
        peerQueryIndex_ = r.index;
        peerQueryCount_ = r.peerCount;
        peerQueryFound_ = r.found;
        peerQueryPubkey_ = r.pubkey;
        peerQueryAddress_ = r.address;
      });
      break;

    case CES_QUERY_SERVER_INFO_RESULT:
      handleSigned(CesQueryServerInfoResult{}, "server info ext",
                   serverInfoExtGen_, [&](auto& r) {
        serverInfoExtOriginId_ = r.originId;
        serverInfoExtReqNonce_ = r.reqNonce;
        serverInfoExtResultCode_ = r.rcode;
        serverInfoExtEntries_ = std::move(r.entries);
      });
      break;

    default:
      LOGTRACE << "incomingMessage unknown message" << VAR(code);
      throw std::runtime_error("Unknown message code");
    }
  } catch (const std::exception& e) {
    LOGTRACE << "incomingMessage parse error: " << e.what();
  }
}

bool CesClient::ensureServerTicket() {
  if ((serverTicket_ == 0) ||
      (minx::getSecsSinceEpoch() >
       serverTicketLastTime_ + SERVER_TICKET_REFRESH_SECS)) {
    if (!getInfo()) {
      LOGTRACE << "ensureServerTicket can't refresh ticket";
      return false;
    }
  }
  return true;
}

} // namespace ces