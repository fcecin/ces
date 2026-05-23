#pragma once

#include <ces/asset.h>
#include <ces/keys.h>
#include <ces/types.h>
#include <minx/buffer.h>
#include <minx/types.h>

#include <logkv/autoser.h>
#include <logkv/autoser/bytes.h>
#include <logkv/autoser/associative.h>

#include <limits>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace ces {

// ============================================================================

#define CES_FIELD_DECL(type, name) type name;
#define CES_FIELD_SIZE(type, name) +sizeof(type)
#define CES_FIELD_PUT(type, name) buf.put(name);
#define CES_FIELD_GET(type, name) name = buf.get<type>();

#define CES_DECLARE_FIELDS(MACRO) MACRO(CES_FIELD_DECL)
#define CES_CALC_SIZE(MACRO) (0 MACRO(CES_FIELD_SIZE))
#define CES_WRITE_FIELDS(buf, MACRO) MACRO(CES_FIELD_PUT)
#define CES_READ_FIELDS(buf, MACRO) MACRO(CES_FIELD_GET)

// ============================================================================

#define CES_INJECT_FIXED_SIGNED_PAYLOAD(MACRO)                                 \
  static constexpr size_t SIZE = 1 + CES_CALC_SIZE(MACRO) + sizeof(Signature); \
  size_t getPayloadSize() const { return CES_CALC_SIZE(MACRO); }               \
  void writePayload(minx::Buffer& buf) {                                       \
    (void)buf; CES_WRITE_FIELDS(buf, MACRO) }                                  \
  void readPayload(minx::ConstBuffer& buf) {                                   \
    (void)buf; CES_READ_FIELDS(buf, MACRO) }

#define CES_INJECT_FIXED_UNSIGNED_PAYLOAD(MACRO)                               \
  static constexpr size_t SIZE = 1 + CES_CALC_SIZE(MACRO);                     \
  size_t getPayloadSize() const { return CES_CALC_SIZE(MACRO); }               \
  void writePayload(minx::Buffer& buf) const {                                 \
    (void)buf; CES_WRITE_FIELDS(buf, MACRO) }                                  \
  void readPayload(minx::ConstBuffer& buf) {                                   \
    (void)buf; CES_READ_FIELDS(buf, MACRO) }

// ============================================================================

#define CES_INJECT_SIGNED_METHODS(OpCode)                                      \
  minx::Bytes toBytes(KeyPair& k) {                                            \
    size_t payloadSz = this->getPayloadSize();                                 \
    minx::Bytes bytes(1 + payloadSz + sizeof(sig));                            \
    minx::Buffer buf(bytes);                                                   \
    buf.put<uint8_t>(OpCode);                                                  \
    this->writePayload(buf);                                                   \
    sig = k.signData(bytes.data(), 1 + payloadSz);                             \
    buf.put(sig);                                                              \
    return bytes;                                                              \
  }                                                                            \
  void fromBytes(const minx::Bytes& bytes) {                                   \
    minx::ConstBuffer buf(bytes);                                              \
    if (buf.get<uint8_t>() != OpCode)                                          \
      throw std::runtime_error("wrong code");                                  \
    this->readPayload(buf);                                                    \
    sig = buf.get<Signature>();                                                \
  }                                                                            \
  bool verifySignature(const minx::Bytes& originalBytes, const PublicKey& pk)  \
    const {                                                                    \
    size_t expectedSz = 1 + this->getPayloadSize() + sizeof(sig);              \
    if (originalBytes.size() != expectedSz)                                    \
      return false;                                                            \
    return pk.verifySignature(originalBytes.data(), expectedSz - sizeof(sig),  \
                              sig);                                            \
  }                                                                            \
  bool fromBytes(const minx::Bytes& bytes, const PublicKey& pk) {              \
    this->fromBytes(bytes);                                                    \
    return this->verifySignature(bytes, pk);                                   \
  }

#define CES_INJECT_UNSIGNED_METHODS(OpCode)                                    \
  minx::Bytes toBytes() const {                                                \
    minx::Bytes bytes(1 + this->getPayloadSize());                             \
    minx::Buffer buf(bytes);                                                   \
    buf.put<uint8_t>(OpCode);                                                  \
    this->writePayload(buf);                                                   \
    return bytes;                                                              \
  }                                                                            \
  void fromBytes(const minx::Bytes& bytes) {                                   \
    minx::ConstBuffer buf(bytes);                                              \
    if (buf.get<uint8_t>() != OpCode)                                          \
      throw std::runtime_error("wrong code");                                  \
    this->readPayload(buf);                                                    \
  }

// ============================================================================

// --- CES_TRANSFER (safe: fail if dest not found) ---
#define CES_TRANSFER_FIELDS(X)                                                 \
  X(Hash, originId) X(HashPrefix, serverId)                                    \
  X(uint32_t, reqNonce) X(Hash, destKey) X(uint64_t, amount)

struct CesTransfer {
  CES_DECLARE_FIELDS(CES_TRANSFER_FIELDS)
  Signature sig{};
  CES_INJECT_FIXED_SIGNED_PAYLOAD(CES_TRANSFER_FIELDS)
  CES_INJECT_SIGNED_METHODS(CES_TRANSFER)
};

// --- CES_TRANSFER_RESULT ---
#define CES_TRANSFER_RESULT_FIELDS(X)                                          \
  X(HashPrefix, originId)                                                      \
  X(uint32_t, reqNonce) X(HashPrefix, destId) X(uint64_t, amount)              \
    X(int64_t, originNewBalance) X(uint8_t, rcode)

struct CesTransferResult {
  CES_DECLARE_FIELDS(CES_TRANSFER_RESULT_FIELDS)
  Signature sig{};
  CES_INJECT_FIXED_SIGNED_PAYLOAD(CES_TRANSFER_RESULT_FIELDS)
  CES_INJECT_SIGNED_METHODS(CES_TRANSFER_RESULT)
};

// --- CES_OPEN_TRANSFER (auto-create dest if not found) ---
#define CES_OPEN_TRANSFER_FIELDS(X)                                            \
  X(Hash, originId) X(HashPrefix, serverId)                                    \
  X(uint32_t, reqNonce) X(Hash, destKey) X(uint64_t, amount)                   \
    X(uint64_t, time)

struct CesOpenTransfer {
  CES_DECLARE_FIELDS(CES_OPEN_TRANSFER_FIELDS)
  Signature sig{};
  CES_INJECT_FIXED_SIGNED_PAYLOAD(CES_OPEN_TRANSFER_FIELDS)
  CES_INJECT_SIGNED_METHODS(CES_OPEN_TRANSFER)
};

#define CES_OPEN_TRANSFER_RESULT_FIELDS(X)                                     \
  X(HashPrefix, originId)                                                      \
  X(uint32_t, reqNonce) X(HashPrefix, destId) X(uint64_t, amount)              \
    X(int64_t, originNewBalance) X(uint8_t, rcode)

struct CesOpenTransferResult {
  CES_DECLARE_FIELDS(CES_OPEN_TRANSFER_RESULT_FIELDS)
  Signature sig{};
  CES_INJECT_FIXED_SIGNED_PAYLOAD(CES_OPEN_TRANSFER_RESULT_FIELDS)
  CES_INJECT_SIGNED_METHODS(CES_OPEN_TRANSFER_RESULT)
};

// --- CES_CREATE_PAYMENT (create payment account with negative balance) ---
#define CES_CREATE_PAYMENT_FIELDS(X)                                           \
  X(Hash, originId) X(HashPrefix, serverId)                                    \
  X(uint32_t, reqNonce) X(Hash, destKey) X(uint64_t, amount)                   \
    X(uint8_t, days)

struct CesCreatePayment {
  CES_DECLARE_FIELDS(CES_CREATE_PAYMENT_FIELDS)
  Signature sig{};
  CES_INJECT_FIXED_SIGNED_PAYLOAD(CES_CREATE_PAYMENT_FIELDS)
  CES_INJECT_SIGNED_METHODS(CES_CREATE_PAYMENT)
};

#define CES_CREATE_PAYMENT_RESULT_FIELDS(X)                                    \
  X(HashPrefix, originId)                                                      \
  X(uint32_t, reqNonce) X(HashPrefix, destId) X(uint64_t, amount)              \
    X(int64_t, originNewBalance) X(uint8_t, rcode)

struct CesCreatePaymentResult {
  CES_DECLARE_FIELDS(CES_CREATE_PAYMENT_RESULT_FIELDS)
  Signature sig{};
  CES_INJECT_FIXED_SIGNED_PAYLOAD(CES_CREATE_PAYMENT_RESULT_FIELDS)
  CES_INJECT_SIGNED_METHODS(CES_CREATE_PAYMENT_RESULT)
};

// --- CES_CROSS_TRANSFER (inter-server transfer via peer) ---
struct CesCrossTransfer {
  Hash originId;
  HashPrefix serverId{};
  uint32_t reqNonce;
  Hash destKey;
  uint64_t amount;
  std::string destServer; // peer server address (host:port)
  Signature sig{};

  size_t getPayloadSize() const {
    return sizeof(originId) + sizeof(serverId) + sizeof(reqNonce) +
           sizeof(destKey) + sizeof(amount) + 1 + destServer.size();
  }

  void writePayload(minx::Buffer& buf) {
    buf.put(originId);
    buf.put(serverId);
    buf.put(reqNonce);
    buf.put(destKey);
    buf.put(amount);
    buf.put(static_cast<uint8_t>(destServer.size()));
    for (char c : destServer)
      buf.put(static_cast<uint8_t>(c));
  }

  void readPayload(minx::ConstBuffer& buf) {
    originId = buf.get<Hash>();
    serverId = buf.get<HashPrefix>();
    reqNonce = buf.get<uint32_t>();
    destKey = buf.get<Hash>();
    amount = buf.get<uint64_t>();
    uint8_t len = buf.get<uint8_t>();
    destServer.resize(len);
    for (uint8_t i = 0; i < len; ++i)
      destServer[i] = static_cast<char>(buf.get<uint8_t>());
  }
  CES_INJECT_SIGNED_METHODS(CES_CROSS_TRANSFER)
};

#define CES_CROSS_TRANSFER_RESULT_FIELDS(X)                                    \
  X(HashPrefix, originId)                                                      \
  X(uint32_t, reqNonce) X(uint64_t, amount)                                    \
    X(int64_t, originNewBalance) X(uint8_t, rcode)

struct CesCrossTransferResult {
  CES_DECLARE_FIELDS(CES_CROSS_TRANSFER_RESULT_FIELDS)
  Signature sig{};
  CES_INJECT_FIXED_SIGNED_PAYLOAD(CES_CROSS_TRANSFER_RESULT_FIELDS)
  CES_INJECT_SIGNED_METHODS(CES_CROSS_TRANSFER_RESULT)
};

// --- CES_RUN_ASSET ---
struct CesRunAsset {
  Hash originId;
  HashPrefix serverId{};
  uint32_t reqNonce;
  Hash assetId;
  uint64_t budget;
  // Per-run cap on caller-account debits (transfers, asset purchases, protocol
  // fees) inside the VM. UINT64_MAX = no enforcement (the default).
  uint64_t allowance = std::numeric_limits<uint64_t>::max();
  uint64_t time = 0; // UTC epoch seconds (required for CES_NONCELESS dedup)
  ces::Bytes input; // up to 1024 bytes
  Signature sig{};

  size_t getPayloadSize() const {
    return sizeof(originId) + sizeof(serverId) + sizeof(reqNonce) +
           sizeof(assetId) + sizeof(budget) + sizeof(allowance) +
           sizeof(time) + 2 + input.size();
  }

  void writePayload(minx::Buffer& buf) {
    buf.put(originId);
    buf.put(serverId);
    buf.put(reqNonce);
    buf.put(assetId);
    buf.put(budget);
    buf.put(allowance);
    buf.put(time);
    buf.put(static_cast<uint16_t>(input.size()));
    for (uint8_t b : input) buf.put(b);
  }

  void readPayload(minx::ConstBuffer& buf) {
    originId = buf.get<Hash>();
    serverId = buf.get<HashPrefix>();
    reqNonce = buf.get<uint32_t>();
    assetId = buf.get<Hash>();
    budget = buf.get<uint64_t>();
    allowance = buf.get<uint64_t>();
    time = buf.get<uint64_t>();
    uint16_t len = buf.get<uint16_t>();
    if (len > 1024) len = 1024;
    input.resize(len);
    for (uint16_t i = 0; i < len; ++i) input[i] = buf.get<uint8_t>();
  }
  CES_INJECT_SIGNED_METHODS(CES_RUN_ASSET)
};

struct CesRunAssetResult {
  HashPrefix originId;
  uint32_t reqNonce;
  uint8_t rcode;
  uint64_t vmError;
  uint64_t budgetUsed;
  // Allowance consumed by caller-side spending (transfer amounts,
  // purchase prices). Always 0 when allowance was set to the
  // unlimited sentinel. Distinct from budgetUsed, which covers gas
  // and protocol fees.
  uint64_t allowanceUsed;
  ces::Bytes output; // up to 1024 bytes
  Signature sig{};

  size_t getPayloadSize() const {
    return sizeof(originId) + sizeof(reqNonce) + sizeof(rcode) +
           sizeof(vmError) + sizeof(budgetUsed) + sizeof(allowanceUsed) +
           2 + output.size();
  }

  void writePayload(minx::Buffer& buf) {
    buf.put(originId);
    buf.put(reqNonce);
    buf.put(rcode);
    buf.put(vmError);
    buf.put(budgetUsed);
    buf.put(allowanceUsed);
    buf.put(static_cast<uint16_t>(output.size()));
    for (uint8_t b : output) buf.put(b);
  }

  void readPayload(minx::ConstBuffer& buf) {
    originId = buf.get<HashPrefix>();
    reqNonce = buf.get<uint32_t>();
    rcode = buf.get<uint8_t>();
    vmError = buf.get<uint64_t>();
    budgetUsed = buf.get<uint64_t>();
    allowanceUsed = buf.get<uint64_t>();
    uint16_t len = buf.get<uint16_t>();
    if (len > 1024) len = 1024;
    output.resize(len);
    for (uint16_t i = 0; i < len; ++i) output[i] = buf.get<uint8_t>();
  }
  CES_INJECT_SIGNED_METHODS(CES_RUN_ASSET_RESULT)
};

// --- CES_BULK_TRANSFER ---
struct BulkTransferItem {
  Hash destKey;
  uint64_t amount;
  static constexpr size_t SIZE =
    sizeof(destKey) + sizeof(amount);
};

struct CesBulkTransfer {
  Hash originId;
  HashPrefix serverId{};
  uint32_t reqNonce;
  uint8_t count;
  std::vector<BulkTransferItem> transfers;
  Signature sig{};

  static constexpr size_t MAX_ITEMS = 20;

  size_t getPayloadSize() const {
    return sizeof(originId) + sizeof(serverId) + sizeof(reqNonce) +
           sizeof(count) + transfers.size() * BulkTransferItem::SIZE;
  }

  void writePayload(minx::Buffer& buf) {
    if (transfers.size() > MAX_ITEMS)
      throw std::runtime_error("too many items");
    count = static_cast<uint8_t>(transfers.size());
    buf.put(originId);
    buf.put(serverId);
    buf.put(reqNonce);
    buf.put(count);
    for (const auto& item : transfers) {
      buf.put(item.destKey);
      buf.put(item.amount);
    }
  }

  void readPayload(minx::ConstBuffer& buf) {
    originId = buf.get<Hash>();
    serverId = buf.get<HashPrefix>();
    reqNonce = buf.get<uint32_t>();
    count = buf.get<uint8_t>();
    if (count > MAX_ITEMS)
      throw std::runtime_error("too many items");
    transfers.clear();
    transfers.reserve(count);
    for (size_t i = 0; i < count; ++i) {
      BulkTransferItem item;
      item.destKey = buf.get<Hash>();
      item.amount = buf.get<uint64_t>();
      transfers.push_back(item);
    }
  }
  CES_INJECT_SIGNED_METHODS(CES_BULK_TRANSFER)
};

#define CES_BULK_TRANSFER_RESULT_FIELDS(X)                                     \
  X(HashPrefix, originId)                                                      \
  X(uint32_t, reqNonce) X(uint8_t, rcode) X(uint8_t, successfulCount)          \
    X(int64_t, originNewBalance)

struct CesBulkTransferResult {
  CES_DECLARE_FIELDS(CES_BULK_TRANSFER_RESULT_FIELDS)
  Signature sig{};
  CES_INJECT_FIXED_SIGNED_PAYLOAD(CES_BULK_TRANSFER_RESULT_FIELDS)
  CES_INJECT_SIGNED_METHODS(CES_BULK_TRANSFER_RESULT)
};

// --- CES_QUERY_ACCOUNT (Custom Validation) ---
#define CES_QUERY_ACCOUNT_FIELDS(X)                                            \
  X(Hash, originId) X(HashPrefix, serverId)                                    \
  X(uint32_t, reqNonce) X(HashPrefix, queryId) X(uint8_t, items)

struct CesQueryAccount {
  CES_DECLARE_FIELDS(CES_QUERY_ACCOUNT_FIELDS)
  Signature sig{};
  static constexpr size_t MAX_ITEMS = 24;
  static constexpr size_t SIZE =
    1 + CES_CALC_SIZE(CES_QUERY_ACCOUNT_FIELDS) + sizeof(Signature);

  size_t getPayloadSize() const {
    return CES_CALC_SIZE(CES_QUERY_ACCOUNT_FIELDS);
  }
  void writePayload(minx::Buffer& buf) {
    if (items >= MAX_ITEMS)
      throw std::runtime_error("too many items");
    CES_WRITE_FIELDS(buf, CES_QUERY_ACCOUNT_FIELDS)
  }
  void readPayload(minx::ConstBuffer& buf){CES_READ_FIELDS(
    buf, CES_QUERY_ACCOUNT_FIELDS)} CES_INJECT_SIGNED_METHODS(CES_QUERY_ACCOUNT)
};

// --- ACCOUNT ENTRY & RESULT (Dynamic Size) ---
struct AccountEntry {
  Hash key;
  int64_t balance;
  uint32_t nonce;
  HashPrefix lastXferDest;
  uint64_t lastXferAmount;
  uint32_t lastXferTime;
  static constexpr size_t SIZE = sizeof(key) + sizeof(balance) + sizeof(nonce) +
                                 sizeof(lastXferDest) + sizeof(lastXferAmount) +
                                 sizeof(lastXferTime);
};

struct CesQueryAccountResult {
  HashPrefix originId;
  uint32_t reqNonce;
  HashPrefix queryId;
  uint8_t items;
  uint8_t rcode;
  std::vector<AccountEntry> accounts;
  Signature sig{};

  static constexpr size_t HEADER_SIZE =
    1 + sizeof(originId) + sizeof(reqNonce) + sizeof(queryId) + sizeof(items) +
    sizeof(rcode) + sizeof(sig);

  size_t getPayloadSize() const {
    size_t sz = sizeof(originId) + sizeof(reqNonce) + sizeof(queryId) +
                sizeof(items) + sizeof(rcode);
    if (rcode == CES_OK)
      sz += accounts.size() * AccountEntry::SIZE;
    return sz;
  }
  void writePayload(minx::Buffer& buf) {
    if (rcode == CES_OK) {
      if (accounts.empty())
        throw std::runtime_error("CES_OK response has no accounts");
      items = accounts.size() - 1;
    }
    buf.put(originId);
    buf.put(reqNonce);
    buf.put(queryId);
    buf.put(items);
    buf.put(rcode);
    if (rcode == CES_OK) {
      for (const auto& acc : accounts) {
        buf.put(acc.key);
        buf.put(acc.balance);
        buf.put(acc.nonce);
        buf.put(acc.lastXferDest);
        buf.put(acc.lastXferAmount);
        buf.put(acc.lastXferTime);
      }
    }
  }
  void readPayload(minx::ConstBuffer& buf) {
    originId = buf.get<HashPrefix>();
    reqNonce = buf.get<uint32_t>();
    queryId = buf.get<HashPrefix>();
    items = buf.get<uint8_t>();
    rcode = buf.get<uint8_t>();
    accounts.clear();
    if (rcode == CES_OK) {
      size_t count = static_cast<size_t>(items) + 1;
      accounts.reserve(count);
      for (size_t i = 0; i < count; ++i) {
        AccountEntry acc;
        acc.key = buf.get<Hash>();
        acc.balance = buf.get<int64_t>();
        acc.nonce = buf.get<uint32_t>();
        acc.lastXferDest = buf.get<HashPrefix>();
        acc.lastXferAmount = buf.get<uint64_t>();
        acc.lastXferTime = buf.get<uint32_t>();
        accounts.push_back(acc);
      }
    }
  }
  CES_INJECT_SIGNED_METHODS(CES_QUERY_ACCOUNT_RESULT)
};

// --- UNSIGNED QUERIES ---
#define CES_UNSIGNED_QUERY_ACCOUNT_FIELDS(X) X(HashPrefix, accountMapKey)
struct CesUnsignedQueryAccount {
  CES_DECLARE_FIELDS(CES_UNSIGNED_QUERY_ACCOUNT_FIELDS)
  CES_INJECT_FIXED_UNSIGNED_PAYLOAD(CES_UNSIGNED_QUERY_ACCOUNT_FIELDS)
  CES_INJECT_UNSIGNED_METHODS(CES_UNSIGNED_QUERY_ACCOUNT)
};

#define CES_UNSIGNED_QUERY_ACCOUNT_RESULT_FIELDS(X)                            \
  X(HashPrefix, queryId) X(int64_t, bal) X(uint32_t, nonce)                    \
  X(HashPrefix, lastXferDest) X(uint64_t, lastXferAmount)                      \
  X(uint32_t, lastXferTime)
struct CesUnsignedQueryAccountResult {
  CES_DECLARE_FIELDS(CES_UNSIGNED_QUERY_ACCOUNT_RESULT_FIELDS)
  CES_INJECT_FIXED_UNSIGNED_PAYLOAD(CES_UNSIGNED_QUERY_ACCOUNT_RESULT_FIELDS)
  CES_INJECT_UNSIGNED_METHODS(CES_UNSIGNED_QUERY_ACCOUNT_RESULT)
};

#define CES_UNSIGNED_QUERY_SOLUTION_FIELDS(X)                                  \
  X(uint64_t, time) X(Hash, solution)
struct CesUnsignedQuerySolution {
  CES_DECLARE_FIELDS(CES_UNSIGNED_QUERY_SOLUTION_FIELDS)
  CES_INJECT_FIXED_UNSIGNED_PAYLOAD(CES_UNSIGNED_QUERY_SOLUTION_FIELDS)
  CES_INJECT_UNSIGNED_METHODS(CES_UNSIGNED_QUERY_SOLUTION)
};

#define CES_UNSIGNED_QUERY_SOLUTION_RESULT_FIELDS(X)                           \
  X(Hash, querySolution) X(uint8_t, queryResult)
struct CesUnsignedQuerySolutionResult {
  CES_DECLARE_FIELDS(CES_UNSIGNED_QUERY_SOLUTION_RESULT_FIELDS)
  CES_INJECT_FIXED_UNSIGNED_PAYLOAD(CES_UNSIGNED_QUERY_SOLUTION_RESULT_FIELDS)
  CES_INJECT_UNSIGNED_METHODS(CES_UNSIGNED_QUERY_SOLUTION_RESULT)
};

// --- CES_PROVE_WORK_RESULT ---
#define CES_PROVE_WORK_RESULT_FIELDS(X)                                        \
  X(Hash, solution)                                                            \
  X(Hash, beneficiary) X(uint64_t, creditAmount) X(uint64_t, serverTime)
struct CesProveWorkResult {
  CES_DECLARE_FIELDS(CES_PROVE_WORK_RESULT_FIELDS)
  Signature sig{};
  CES_INJECT_FIXED_SIGNED_PAYLOAD(CES_PROVE_WORK_RESULT_FIELDS)
  CES_INJECT_SIGNED_METHODS(CES_PROVE_WORK_RESULT)
};

// --- ASSET CREATION & UPDATES ---
#define CES_CREATE_ASSET_FIELDS(X)                                             \
  X(Hash, ownerId) X(HashPrefix, serverId)                                     \
  X(uint32_t, reqNonce) X(Hash, assetId) X(uint16_t, amount)                   \
    X(uint32_t, price) X(AssetData, content)
struct CesCreateAsset {
  CES_DECLARE_FIELDS(CES_CREATE_ASSET_FIELDS)
  Signature sig{};
  CES_INJECT_FIXED_SIGNED_PAYLOAD(CES_CREATE_ASSET_FIELDS)
  CES_INJECT_SIGNED_METHODS(CES_CREATE_ASSET)
};

#define CES_CREATE_ASSET_RESULT_FIELDS(X)                                      \
  X(HashPrefix, ownerId)                                                       \
  X(uint32_t, reqNonce) X(Hash, assetId) X(uint16_t, amount)                   \
    X(uint32_t, price) X(uint8_t, rcode)
struct CesCreateAssetResult {
  CES_DECLARE_FIELDS(CES_CREATE_ASSET_RESULT_FIELDS)
  Signature sig{};
  CES_INJECT_FIXED_SIGNED_PAYLOAD(CES_CREATE_ASSET_RESULT_FIELDS)
  CES_INJECT_SIGNED_METHODS(CES_CREATE_ASSET_RESULT)
};

#define CES_UPDATE_ASSET_FIELDS(X)                                             \
  X(Hash, ownerId) X(HashPrefix, serverId)                                     \
  X(uint32_t, reqNonce) X(Hash, assetId) X(HashPrefix, newOwnerId)             \
    X(uint32_t, price) X(AssetData, content)
struct CesUpdateAsset {
  CES_DECLARE_FIELDS(CES_UPDATE_ASSET_FIELDS)
  Signature sig{};
  CES_INJECT_FIXED_SIGNED_PAYLOAD(CES_UPDATE_ASSET_FIELDS)
  CES_INJECT_SIGNED_METHODS(CES_UPDATE_ASSET)
};

#define CES_UPDATE_ASSET_RESULT_FIELDS(X)                                      \
  X(HashPrefix, ownerId)                                                       \
  X(uint32_t, reqNonce) X(Hash, assetId) X(HashPrefix, newOwnerId)             \
    X(uint32_t, price) X(uint8_t, rcode)
struct CesUpdateAssetResult {
  CES_DECLARE_FIELDS(CES_UPDATE_ASSET_RESULT_FIELDS)
  Signature sig{};
  CES_INJECT_FIXED_SIGNED_PAYLOAD(CES_UPDATE_ASSET_RESULT_FIELDS)
  CES_INJECT_SIGNED_METHODS(CES_UPDATE_ASSET_RESULT)
};

#define CES_UPDATE_ASSET_META_FIELDS(X)                                        \
  X(Hash, ownerId) X(HashPrefix, serverId)                                     \
  X(uint32_t, reqNonce) X(Hash, assetId) X(HashPrefix, newOwnerId)             \
    X(uint32_t, price)
struct CesUpdateAssetMeta {
  CES_DECLARE_FIELDS(CES_UPDATE_ASSET_META_FIELDS)
  Signature sig{};
  CES_INJECT_FIXED_SIGNED_PAYLOAD(CES_UPDATE_ASSET_META_FIELDS)
  CES_INJECT_SIGNED_METHODS(CES_UPDATE_ASSET_META)
};

#define CES_UPDATE_ASSET_META_RESULT_FIELDS(X)                                 \
  X(HashPrefix, ownerId)                                                       \
  X(uint32_t, reqNonce) X(Hash, assetId) X(HashPrefix, newOwnerId)             \
    X(uint32_t, price) X(uint8_t, rcode)
struct CesUpdateAssetMetaResult {
  CES_DECLARE_FIELDS(CES_UPDATE_ASSET_META_RESULT_FIELDS)
  Signature sig{};
  CES_INJECT_FIXED_SIGNED_PAYLOAD(CES_UPDATE_ASSET_META_RESULT_FIELDS)
  CES_INJECT_SIGNED_METHODS(CES_UPDATE_ASSET_META_RESULT)
};

#define CES_UPDATE_ASSET_FAST_FIELDS(X)                                        \
  X(Hash, ownerId) X(HashPrefix, serverId) X(uint32_t, reqNonce) X(Hash, assetId) X(AssetData, content)
struct CesUpdateAssetFast {
  CES_DECLARE_FIELDS(CES_UPDATE_ASSET_FAST_FIELDS)
  Signature sig{};
  CES_INJECT_FIXED_SIGNED_PAYLOAD(CES_UPDATE_ASSET_FAST_FIELDS)
  CES_INJECT_SIGNED_METHODS(CES_UPDATE_ASSET_FAST)
};

#define CES_UPDATE_ASSET_FAST_RESULT_FIELDS(X)                                 \
  X(HashPrefix, ownerId)                                                       \
  X(uint32_t, reqNonce) X(Hash, assetId) X(uint8_t, rcode)
struct CesUpdateAssetFastResult {
  CES_DECLARE_FIELDS(CES_UPDATE_ASSET_FAST_RESULT_FIELDS)
  Signature sig{};
  CES_INJECT_FIXED_SIGNED_PAYLOAD(CES_UPDATE_ASSET_FAST_RESULT_FIELDS)
  CES_INJECT_SIGNED_METHODS(CES_UPDATE_ASSET_FAST_RESULT)
};

// --- ASSET FUNDING, BUYING, GIVING ---
#define CES_FUND_ASSET_FIELDS(X)                                               \
  X(Hash, originId) X(HashPrefix, serverId) X(uint32_t, reqNonce) X(Hash, assetId) X(uint16_t, amount)
struct CesFundAsset {
  CES_DECLARE_FIELDS(CES_FUND_ASSET_FIELDS)
  Signature sig{};
  CES_INJECT_FIXED_SIGNED_PAYLOAD(CES_FUND_ASSET_FIELDS)
  CES_INJECT_SIGNED_METHODS(CES_FUND_ASSET)
};

#define CES_FUND_ASSET_RESULT_FIELDS(X)                                        \
  X(HashPrefix, originId)                                                      \
  X(uint32_t, reqNonce) X(Hash, assetId) X(uint16_t, amount) X(uint8_t, rcode)
struct CesFundAssetResult {
  CES_DECLARE_FIELDS(CES_FUND_ASSET_RESULT_FIELDS)
  Signature sig{};
  CES_INJECT_FIXED_SIGNED_PAYLOAD(CES_FUND_ASSET_RESULT_FIELDS)
  CES_INJECT_SIGNED_METHODS(CES_FUND_ASSET_RESULT)
};

#define CES_BUY_ASSET_FIELDS(X)                                                \
  X(Hash, originId) X(HashPrefix, serverId)                                    \
  X(uint32_t, reqNonce) X(Hash, assetId) X(uint64_t, priceLimit)
struct CesBuyAsset {
  CES_DECLARE_FIELDS(CES_BUY_ASSET_FIELDS)
  Signature sig{};
  CES_INJECT_FIXED_SIGNED_PAYLOAD(CES_BUY_ASSET_FIELDS)
  CES_INJECT_SIGNED_METHODS(CES_BUY_ASSET)
};

#define CES_BUY_ASSET_RESULT_FIELDS(X)                                         \
  X(HashPrefix, originId)                                                      \
  X(uint32_t, reqNonce) X(Hash, assetId) X(uint64_t, priceLimit)               \
    X(uint8_t, rcode)
struct CesBuyAssetResult {
  CES_DECLARE_FIELDS(CES_BUY_ASSET_RESULT_FIELDS)
  Signature sig{};
  CES_INJECT_FIXED_SIGNED_PAYLOAD(CES_BUY_ASSET_RESULT_FIELDS)
  CES_INJECT_SIGNED_METHODS(CES_BUY_ASSET_RESULT)
};

#define CES_GIVE_ASSET_FIELDS(X)                                               \
  X(Hash, ownerId) X(HashPrefix, serverId)                                     \
  X(uint32_t, reqNonce) X(Hash, assetId) X(HashPrefix, newOwnerId)
struct CesGiveAsset {
  CES_DECLARE_FIELDS(CES_GIVE_ASSET_FIELDS)
  Signature sig{};
  CES_INJECT_FIXED_SIGNED_PAYLOAD(CES_GIVE_ASSET_FIELDS)
  CES_INJECT_SIGNED_METHODS(CES_GIVE_ASSET)
};

#define CES_GIVE_ASSET_RESULT_FIELDS(X)                                        \
  X(HashPrefix, ownerId)                                                       \
  X(uint32_t, reqNonce) X(Hash, assetId) X(HashPrefix, newOwnerId)             \
    X(uint8_t, rcode)
struct CesGiveAssetResult {
  CES_DECLARE_FIELDS(CES_GIVE_ASSET_RESULT_FIELDS)
  Signature sig{};
  CES_INJECT_FIXED_SIGNED_PAYLOAD(CES_GIVE_ASSET_RESULT_FIELDS)
  CES_INJECT_SIGNED_METHODS(CES_GIVE_ASSET_RESULT)
};

// --- CES_QUERY_ASSET (Custom Validation) ---
#define CES_QUERY_ASSET_FIELDS(X)                                              \
  X(Hash, originId) X(HashPrefix, serverId) X(uint32_t, reqNonce) X(Hash, assetId) X(uint8_t, items)

struct CesQueryAsset {
  CES_DECLARE_FIELDS(CES_QUERY_ASSET_FIELDS)
  Signature sig{};
  static constexpr size_t MAX_ITEMS = 4;
  static constexpr size_t SIZE =
    1 + CES_CALC_SIZE(CES_QUERY_ASSET_FIELDS) + sizeof(Signature);

  size_t getPayloadSize() const {
    return CES_CALC_SIZE(CES_QUERY_ASSET_FIELDS);
  }
  void writePayload(minx::Buffer& buf) {
    if (items >= MAX_ITEMS)
      throw std::runtime_error("too many items");
    CES_WRITE_FIELDS(buf, CES_QUERY_ASSET_FIELDS)
  }
  void readPayload(minx::ConstBuffer& buf){CES_READ_FIELDS(
    buf, CES_QUERY_ASSET_FIELDS)} CES_INJECT_SIGNED_METHODS(CES_QUERY_ASSET)
};

// --- ASSET ENTRY & RESULT (Dynamic Size) ---
struct AssetEntry {
  HashPrefix ownerId;
  AssetData content;
  uint16_t balance;
  uint32_t price;
  static constexpr size_t SIZE =
    sizeof(ownerId) + sizeof(content) + sizeof(balance) + sizeof(price);
};

struct CesQueryAssetResult {
  HashPrefix originId;
  uint32_t reqNonce;
  uint8_t items;
  uint8_t rcode;
  std::vector<AssetEntry> assets;
  Signature sig{};

  static constexpr size_t HEADER_SIZE = 1 + sizeof(originId) +
                                        sizeof(reqNonce) + sizeof(items) +
                                        sizeof(rcode) + sizeof(sig);

  size_t getPayloadSize() const {
    size_t sz =
      sizeof(originId) + sizeof(reqNonce) + sizeof(items) + sizeof(rcode);
    if (rcode == CES_OK)
      sz += assets.size() * AssetEntry::SIZE;
    return sz;
  }
  void writePayload(minx::Buffer& buf) {
    if (rcode == CES_OK) {
      if (assets.empty())
        throw std::runtime_error("CES_OK response has no assets");
      items = assets.size() - 1;
    }
    buf.put(originId);
    buf.put(reqNonce);
    buf.put(items);
    buf.put(rcode);
    if (rcode == CES_OK) {
      for (const auto& a : assets) {
        buf.put(a.ownerId);
        buf.put(a.content);
        buf.put(a.balance);
        buf.put(a.price);
      }
    }
  }
  void readPayload(minx::ConstBuffer& buf) {
    originId = buf.get<HashPrefix>();
    reqNonce = buf.get<uint32_t>();
    items = buf.get<uint8_t>();
    rcode = buf.get<uint8_t>();
    assets.clear();
    if (rcode == CES_OK) {
      size_t count = static_cast<size_t>(items) + 1;
      assets.reserve(count);
      for (size_t i = 0; i < count; ++i) {
        AssetEntry a;
        a.ownerId = buf.get<HashPrefix>();
        a.content = buf.get<AssetData>();
        a.balance = buf.get<uint16_t>();
        a.price = buf.get<uint32_t>();
        assets.push_back(a);
      }
    }
  }
  CES_INJECT_SIGNED_METHODS(CES_QUERY_ASSET_RESULT)
};

// --- UNSIGNED ASSET QUERIES & SERVER INFO ---
#define CES_UNSIGNED_QUERY_ASSET_FIELDS(X) X(Hash, assetId)
struct CesUnsignedQueryAsset {
  CES_DECLARE_FIELDS(CES_UNSIGNED_QUERY_ASSET_FIELDS)
  CES_INJECT_FIXED_UNSIGNED_PAYLOAD(CES_UNSIGNED_QUERY_ASSET_FIELDS)
  CES_INJECT_UNSIGNED_METHODS(CES_UNSIGNED_QUERY_ASSET)
};

#define CES_UNSIGNED_QUERY_ASSET_RESULT_FIELDS(X)                              \
  X(Hash, assetId)                                                             \
  X(HashPrefix, ownerId) X(AssetData, content) X(uint16_t, balance)            \
    X(uint32_t, price)
struct CesUnsignedQueryAssetResult {
  CES_DECLARE_FIELDS(CES_UNSIGNED_QUERY_ASSET_RESULT_FIELDS)
  CES_INJECT_FIXED_UNSIGNED_PAYLOAD(CES_UNSIGNED_QUERY_ASSET_RESULT_FIELDS)
  CES_INJECT_UNSIGNED_METHODS(CES_UNSIGNED_QUERY_ASSET_RESULT)
};

// --- CES_QUERY_SERVER_INFO (Signed, self-describing KV response) ---
#define CES_QUERY_SERVER_INFO_FIELDS(X)                                        \
  X(Hash, originId) X(HashPrefix, serverId) X(uint32_t, reqNonce)

struct CesQueryServerInfo {
  CES_DECLARE_FIELDS(CES_QUERY_SERVER_INFO_FIELDS)
  Signature sig{};
  CES_INJECT_FIXED_SIGNED_PAYLOAD(CES_QUERY_SERVER_INFO_FIELDS)
  CES_INJECT_SIGNED_METHODS(CES_QUERY_SERVER_INFO)
};

struct ServerInfoEntry {
  std::string key;
  std::string value;
};

struct CesQueryServerInfoResult {
  HashPrefix originId;
  uint32_t reqNonce;
  uint8_t rcode;
  std::vector<ServerInfoEntry> entries;
  Signature sig{};

  size_t getPayloadSize() const {
    size_t sz = sizeof(originId) + sizeof(reqNonce) + sizeof(rcode);
    if (rcode == CES_OK) {
      // Convert to map for logkv serialization
      std::map<std::string, std::string> m;
      for (auto& e : entries) m[e.key] = e.value;
      sz += logkv::serializer<std::map<std::string, std::string>>::get_size(m);
    }
    return sz;
  }

  void writePayload(minx::Buffer& buf) {
    buf.put(originId);
    buf.put(reqNonce);
    buf.put(rcode);
    if (rcode == CES_OK) {
      std::map<std::string, std::string> m;
      for (auto& e : entries) m[e.key] = e.value;
      size_t sz = logkv::serializer<std::map<std::string, std::string>>::get_size(m);
      std::vector<char> tmp(sz);
      logkv::serializer<std::map<std::string, std::string>>::write(
        tmp.data(), sz, m);
      for (char c : tmp) buf.put(static_cast<uint8_t>(c));
    }
  }

  void readPayload(minx::ConstBuffer& buf) {
    originId = buf.get<HashPrefix>();
    reqNonce = buf.get<uint32_t>();
    rcode = buf.get<uint8_t>();
    entries.clear();
    if (rcode == CES_OK) {
      // Remaining payload bytes = total - opcode(1) - fixed fields - sig(64)
      // The buf already consumed opcode + fixed fields, so remaining
      // minus signature bytes is the map data.
      size_t remaining = buf.getRemainingBytesCount() - sizeof(Signature);
      std::vector<char> mapData(remaining);
      for (size_t i = 0; i < remaining; ++i)
        mapData[i] = static_cast<char>(buf.get<uint8_t>());
      std::map<std::string, std::string> m;
      logkv::serializer<std::map<std::string, std::string>>::read(
        mapData.data(), mapData.size(), m);
      for (auto& [k, v] : m)
        entries.push_back({k, v});
    }
  }
  CES_INJECT_SIGNED_METHODS(CES_QUERY_SERVER_INFO_RESULT)
};

} // namespace ces