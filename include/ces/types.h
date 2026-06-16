#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <vector>

#include <logkv/hex.h>
#include <minx/types.h>

namespace ces {

/**
 * Server incoming message codes.
 */
enum op_code_t : uint8_t {
  CES_TRANSFER = 0x00,           // safe: fail if dest not found
  CES_BULK_TRANSFER = 0x01,      // always auto-creates dest
  CES_QUERY_ACCOUNT = 0x02,
  CES_UNSIGNED_QUERY_ACCOUNT = 0x03,
  CES_UNSIGNED_QUERY_SOLUTION = 0x04,
  CES_CREATE_ASSET = 0x05,
  CES_UPDATE_ASSET = 0x06,
  CES_UPDATE_ASSET_META = 0x07,
  CES_UPDATE_ASSET_FAST = 0x08,
  CES_FUND_ASSET = 0x09,
  CES_BUY_ASSET = 0x0a,
  CES_GIVE_ASSET = 0x0b,
  CES_QUERY_ASSET = 0x0c,
  CES_UNSIGNED_QUERY_ASSET = 0x0d,
  CES_QUERY_SERVER_INFO = 0x0f,
  CES_OPEN_TRANSFER = 0x10,      // auto-create dest if not found
  CES_CREATE_PAYMENT = 0x11,     // create payment account
  CES_CROSS_TRANSFER = 0x12,     // inter-server transfer via peer
  CES_RUN_ASSET = 0x13,           // execute asset bytecode (CesVM)
  CES_QUERY_PEER_INFO = 0x14           // unsigned: peer-table slot lookup (discovery)
};

/**
 * APPLICATION-lane opcodes. These ride MINX's APPLICATION path (not
 * the signed-op path). Clients with an established MINX session may
 * push these directly; servers dispatch by opcode in
 * CesServer::incomingApplication. Values are in the 0x80+ range to
 * stay out of the signed-op op_code_t / result_code_t space.
 */
enum app_code_t : uint8_t {
  // Client↔program message (see L2 compute §4.2). Client→server:
  // target program file_key prefix + opaque payload. Server→client:
  // source program file_key prefix + opaque payload. Payload cap
  // 1 KB. Discarded silently if no program instance matches the
  // prefix.
  CES_APP_COMPUTE_MSG = 0x81
};

/**
 * Server outgoing message codes.
 */
enum result_code_t : uint8_t {
  CES_TRANSFER_RESULT = 0x00,
  CES_BULK_TRANSFER_RESULT = 0x01,
  CES_QUERY_ACCOUNT_RESULT = 0x02,
  CES_UNSIGNED_QUERY_ACCOUNT_RESULT = 0x03,
  CES_UNSIGNED_QUERY_SOLUTION_RESULT = 0x04,
  CES_CREATE_ASSET_RESULT = 0x05,
  CES_UPDATE_ASSET_RESULT = 0x06,
  CES_UPDATE_ASSET_META_RESULT = 0x07,
  CES_UPDATE_ASSET_FAST_RESULT = 0x08,
  CES_FUND_ASSET_RESULT = 0x09,
  CES_BUY_ASSET_RESULT = 0x0a,
  CES_GIVE_ASSET_RESULT = 0x0b,
  CES_QUERY_ASSET_RESULT = 0x0c,
  CES_UNSIGNED_QUERY_ASSET_RESULT = 0x0d,
  CES_QUERY_SERVER_INFO_RESULT = 0x0f,
  CES_OPEN_TRANSFER_RESULT = 0x10,
  CES_CREATE_PAYMENT_RESULT = 0x11,
  CES_CROSS_TRANSFER_RESULT = 0x12,
  CES_RUN_ASSET_RESULT = 0x13,
  CES_QUERY_PEER_INFO_RESULT = 0x14,
  // Request is MINX_PROVE_WORK (no CES opcode for the request side)
  CES_PROVE_WORK_RESULT = 0x80
};

/**
 * Operation error codes.
 */
enum error_code_t : uint8_t {
  CES_OK = 0x00,
  CES_ERROR_ORIGIN_NOT_FOUND = 0x01,
  CES_ERROR_WRONG_NONCE = 0x02,
  CES_ERROR_INSUFFICIENT_BALANCE = 0x03,
  CES_ERROR_INSUFFICIENT_BALANCE_WITH_CREATE = 0x04,
  CES_ERROR_INVALID_TARGET_ACCOUNT = 0x05,
  CES_ERROR_WRONG_TARGET_ACCOUNT = 0x06,
  CES_ERROR_WRONG_PAYMENT_AMOUNT = 0x07,
  CES_ERROR_ASSET_EXISTS = 0x08,
  CES_ERROR_ASSET_NOT_FOUND = 0x09,
  CES_ERROR_NOT_OWNER = 0x0a,
  CES_ERROR_NOT_FOR_SALE = 0x0b,
  CES_ERROR_INSUFFICIENT_PAYMENT = 0x0c,
  CES_ERROR_TIMEOUT = 0x0d,
  CES_ERROR_INTERNAL = 0x0e,
  CES_ERROR_TARGET_NOT_FOUND = 0x0f,
  CES_ERROR_UNKNOWN_PEER = 0x10,
  CES_ERROR_QUEUE_FULL = 0x11,
  CES_ERROR_VM_FAILED = 0x12,
  CES_ERROR_DISABLED = 0x13,
  CES_ERROR_ALLOWANCE_EXCEEDED = 0x14,
  // CesPlex protocol-select was NACKed by the target. Raised by the
  // outbound SYS_RPC path when the remote doesn't mount the rpc
  // protocol (e.g. a plain CES server talking to another plain CES
  // server — rpc is an outbound-only capability on CES). Distinct
  // from ERROR_INTERNAL because it's a clean protocol-level refusal,
  // not a wire or I/O failure.
  CES_ERROR_PROTO_REJECTED = 0x15,
  // CesPlex file handler — GET/WRITE/etc. against a name that doesn't exist.
  CES_ERROR_FILE_NOT_FOUND = 0x16,
  // CesPlex file handler — CREATE on a name that already exists.
  CES_ERROR_FILE_EXISTS = 0x17,
  // CesPlex file handler — name fails the §1 validation rules
  // (too long, too deep, bad component, non-canonical, etc.).
  CES_ERROR_BAD_NAME = 0x18,
  // CesPlex file handler — CREATE would collide with an existing
  // directory prefix, or a file exists where a directory is needed.
  CES_ERROR_PATH_CONFLICT = 0x19,
  // File storage — CREATE would push total_bytes past
  // cesFileStoreMaxBytes. Feature is on but at capacity.
  CES_ERROR_STORE_FULL = 0x1a,
  // Compute feature — feature off (compute_max_instances == 0).
  CES_ERROR_COMPUTE_DISABLED = 0x1b,
  // Compute feature — builtin:file prerequisite not registered at bind time.
  CES_ERROR_COMPUTE_NO_FILE_HANDLER = 0x1c,
  // Compute feature — source file's file_balance too low to cover the
  // 15-min upfront deposit at LAUNCH.
  CES_ERROR_COMPUTE_FUND_TOO_LOW = 0x1d,
  // Compute feature — KILL/STAT referenced an instance_id that isn't
  // running (already exited, never existed, wrong owner).
  CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND = 0x1e,
  // Compute feature — LAUNCH would exceed compute_max_instances.
  CES_ERROR_COMPUTE_MAX_INSTANCES = 0x1f,
  // /ces/lua/1 — ATTACH against an instance whose accept gate is
  // closed (the program hasn't called ces.conn.set_listener).
  CES_ERROR_NOT_LISTENING = 0x20,
  // Asset is marked IMMUTABLE — its content cannot be modified.
  // updateAsset / updateAssetFast / RPC writes against an immutable
  // asset return this code. Owner, price, and funding are still
  // mutable; this only seals the 210-byte content.
  CES_ERROR_IMMUTABLE = 0x21,
  // Caller-supplied input violates a syscall/handler precondition
  // that's *not* captured by a more specific code (e.g. a host
  // string longer than the wire field's max length, a CesPlex
  // preamble shorter than its declared structure, an out-of-range
  // numeric argument). Distinct from CES_ERROR_INTERNAL: the server
  // is healthy, the *caller* sent something it shouldn't have.
  CES_ERROR_BAD_INPUT = 0x22,
  CES_ERROR_LAST = CES_ERROR_BAD_INPUT
};

/// reqNonce value meaning "server assigns nonce, use time-based dedup."
static constexpr uint32_t CES_NONCELESS = UINT32_MAX;

/// Microseconds since epoch (UTC). Used for dedup time fields.
inline uint64_t getMicrosSinceEpoch() {
  return static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count());
}

// Heap-backed CES wire-bytes type. Defined here (alongside Hash /
// HashPrefix / HashTail) because half the codebase references it as a
// data type — function signatures, struct members — without needing
// the active read/write wrapper. The wrapper (ces::Buffer) lives in
// ces/buffer.h; include that when you want put/get/peek/poke methods.
//
// The MTU-bounded stack-vector wire-payload type is minx::Bytes; use
// that explicitly when you specifically want the 1280-cap
// static_vector for UDP packet construction.
using Bytes = std::vector<uint8_t>;
using Hash = minx::Hash;
using HashTail = std::array<uint8_t, 24>;
using HashPrefix = std::array<uint8_t, 8>;
using PeerAddr = std::array<uint8_t, 64>;

inline HashPrefix getHashPrefix(const Hash& full_hash) {
  HashPrefix prefix;
  std::copy(full_hash.begin(), full_hash.begin() + 8, prefix.begin());
  return prefix;
}

inline HashTail getHashTail(const Hash& full_hash) {
  HashTail tail;
  std::copy(full_hash.begin() + 8, full_hash.end(), tail.begin());
  return tail;
}

inline Hash getHash(const HashPrefix& prefix, const HashTail& tail) {
  Hash full_hash;
  std::copy(prefix.begin(), prefix.end(), full_hash.begin());
  std::copy(tail.begin(), tail.end(), full_hash.begin() + 8);
  return full_hash;
}

inline void hashPrefixToString(const HashPrefix& src, std::string& dest,
                               bool upper = false) {
  dest.resize(16);
  logkv::encodeHex(dest.data(), dest.size(),
                   reinterpret_cast<const char*>(src.data()), src.size(),
                   upper);
}

inline std::string hashPrefixToString(const HashPrefix& src,
                                      bool upper = false) {
  std::string dest(16, '\0');
  logkv::encodeHex(dest.data(), dest.size(),
                   reinterpret_cast<const char*>(src.data()), src.size(),
                   upper);
  return dest;
}

// ---- Error code to human-readable string ----

inline const char* errorString(uint8_t code) {
  switch (code) {
  case CES_OK:                                     return "CES_OK";
  case CES_ERROR_ORIGIN_NOT_FOUND:                 return "CES_ERROR_ORIGIN_NOT_FOUND";
  case CES_ERROR_WRONG_NONCE:                      return "CES_ERROR_WRONG_NONCE";
  case CES_ERROR_INSUFFICIENT_BALANCE:             return "CES_ERROR_INSUFFICIENT_BALANCE";
  case CES_ERROR_INSUFFICIENT_BALANCE_WITH_CREATE: return "CES_ERROR_INSUFFICIENT_BALANCE_WITH_CREATE";
  case CES_ERROR_INVALID_TARGET_ACCOUNT:           return "CES_ERROR_INVALID_TARGET_ACCOUNT";
  case CES_ERROR_WRONG_TARGET_ACCOUNT:             return "CES_ERROR_WRONG_TARGET_ACCOUNT";
  case CES_ERROR_WRONG_PAYMENT_AMOUNT:             return "CES_ERROR_WRONG_PAYMENT_AMOUNT";
  case CES_ERROR_ASSET_EXISTS:                     return "CES_ERROR_ASSET_EXISTS";
  case CES_ERROR_ASSET_NOT_FOUND:                  return "CES_ERROR_ASSET_NOT_FOUND";
  case CES_ERROR_NOT_OWNER:                        return "CES_ERROR_NOT_OWNER";
  case CES_ERROR_NOT_FOR_SALE:                     return "CES_ERROR_NOT_FOR_SALE";
  case CES_ERROR_INSUFFICIENT_PAYMENT:             return "CES_ERROR_INSUFFICIENT_PAYMENT";
  case CES_ERROR_TIMEOUT:                          return "CES_ERROR_TIMEOUT";
  case CES_ERROR_INTERNAL:                         return "CES_ERROR_INTERNAL";
  case CES_ERROR_TARGET_NOT_FOUND:                 return "CES_ERROR_TARGET_NOT_FOUND";
  case CES_ERROR_UNKNOWN_PEER:                     return "CES_ERROR_UNKNOWN_PEER";
  case CES_ERROR_QUEUE_FULL:                       return "CES_ERROR_QUEUE_FULL";
  case CES_ERROR_VM_FAILED:                        return "CES_ERROR_VM_FAILED";
  case CES_ERROR_DISABLED:                         return "CES_ERROR_DISABLED";
  case CES_ERROR_ALLOWANCE_EXCEEDED:               return "CES_ERROR_ALLOWANCE_EXCEEDED";
  case CES_ERROR_PROTO_REJECTED:                   return "CES_ERROR_PROTO_REJECTED";
  case CES_ERROR_FILE_NOT_FOUND:                   return "CES_ERROR_FILE_NOT_FOUND";
  case CES_ERROR_FILE_EXISTS:                      return "CES_ERROR_FILE_EXISTS";
  case CES_ERROR_BAD_NAME:                         return "CES_ERROR_BAD_NAME";
  case CES_ERROR_PATH_CONFLICT:                    return "CES_ERROR_PATH_CONFLICT";
  case CES_ERROR_STORE_FULL:                       return "CES_ERROR_STORE_FULL";
  case CES_ERROR_COMPUTE_DISABLED:                 return "CES_ERROR_COMPUTE_DISABLED";
  case CES_ERROR_COMPUTE_NO_FILE_HANDLER:          return "CES_ERROR_COMPUTE_NO_FILE_HANDLER";
  case CES_ERROR_COMPUTE_FUND_TOO_LOW:             return "CES_ERROR_COMPUTE_FUND_TOO_LOW";
  case CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND:       return "CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND";
  case CES_ERROR_COMPUTE_MAX_INSTANCES:            return "CES_ERROR_COMPUTE_MAX_INSTANCES";
  case CES_ERROR_NOT_LISTENING:                    return "CES_ERROR_NOT_LISTENING";
  case CES_ERROR_IMMUTABLE:                        return "CES_ERROR_IMMUTABLE";
  case CES_ERROR_BAD_INPUT:                        return "CES_ERROR_BAD_INPUT";
  default:                                         return "UNKNOWN_ERROR";
  }
}

// ---- Asset balance (days + privacy bit) ----
// The uint16_t balance field encodes:
//   bit 15    = private (hide content from unauthorized queries)
//   bit 14    = asset-owned (owner field is an asset key prefix, not an account prefix)
//   bit 13    = immutable (content/value cannot be changed; once set, cannot be unset)
//   bits 0-12 = days remaining (max 8191 ~= 22 years)
//
// IMMUTABLE seals content only. Owner, price, and rent (days) can still
// be updated, transferred, and funded on an immutable asset — only the
// 210-byte content array is locked.
inline bool isAssetPrivate(uint16_t balance) { return balance & 0x8000; }
inline bool isAssetOwned(uint16_t balance) { return balance & 0x4000; }
inline bool isAssetImmutable(uint16_t balance) { return balance & 0x2000; }
inline uint16_t assetDays(uint16_t balance) { return balance & 0x1FFF; }
inline uint16_t assetBalance(uint16_t days, bool priv,
                             bool assetOwned = false,
                             bool immutable = false) {
  return static_cast<uint16_t>(
    (priv ? 0x8000 : 0) |
    (assetOwned ? 0x4000 : 0) |
    (immutable ? 0x2000 : 0) |
    (days & 0x1FFF));
}

// ---- Price conversion utilities ----
// Asset prices are stored as uint32_t; real cost = storedPrice * PRICE_UNIT.
// PRICE_UNIT matches the currency display divisor (1.00000000 = 100,000,000).
// The minimum non-zero price is 1 whole credit (100,000,000 internal units).
// The price in the interface is an integer number of whole credits.

constexpr uint64_t PRICE_UNIT = 100'000'000ULL;
constexpr uint64_t PRICE_MAX = static_cast<uint64_t>(UINT32_MAX) * PRICE_UNIT;

// Default CES server UDP port.
constexpr uint16_t DEFAULT_PORT = 53830;

// Convert a user-facing price (whole credits) to stored form.
// Returns 0 on success, non-zero on validation failure.
// out receives the stored price on success.
inline int validatePrice(uint64_t wholeCredits, uint32_t& out) {
  if (wholeCredits == 0) { out = 0; return 0; }
  if (wholeCredits > UINT32_MAX) return 2;  // too high
  out = static_cast<uint32_t>(wholeCredits);
  return 0;
}

// Convert stored price back to real credits (internal units).
constexpr uint64_t storedToRealPrice(uint32_t stored) {
  return static_cast<uint64_t>(stored) * PRICE_UNIT;
}

} // namespace ces

namespace std {
template <> struct hash<ces::HashPrefix> {
  std::size_t operator()(const ces::HashPrefix& key) const noexcept {
    uint64_t raw_val;
    std::memcpy(&raw_val, key.data(), sizeof(uint64_t));
    return std::hash<uint64_t>{}(raw_val);
  }
};
} // namespace std
