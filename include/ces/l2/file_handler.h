// file_handler.h - builtin:file handler lifecycle API (v2)
//
// The file handler is a compiled-in CesPlex handler registered as
// "file" in the global builtin registry.
//
// Lifecycle: CesServer::start() calls fileHandlerBind(this) after
// CesPlex is constructed, and fileHandlerBind(nullptr) on shutdown
// before CesPlex is torn down. Not thread-safe; intended to run on
// the main thread during server start/stop.
//
// CesServer also drives one startup hook:
//   - fileHandlerStartupReconcile() runs once at start(), walking
//     the storage dir to rebuild .store.toml so crash-state drift
//     converges back to ground truth.
//
// Rent is collected lazily — on every non-DEPOSIT op touching a
// file, and on JIT GC during CREATE when the store is at capacity.
// No periodic "rent pass" runs; dead files stay on disk until the
// next CREATE (or op touching them) reclaims them.

#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include <boost/asio/any_io_executor.hpp>

namespace ces {

class CesServer;

// Bind/unbind the builtin:file handler to a CesServer. See header
// comment for semantics.
void fileHandlerBind(CesServer* server);

// One-time startup walk of the file store directory. Recomputes
// total_files and total_bytes from sidecars and rewrites .store.toml.
// Safe to call with no files present. No-op if not bound.
void fileHandlerStartupReconcile();

// Read store-level stats from .store.toml (under the store mutex) for
// monitoring. Returns false if the handler is unbound (feature off);
// otherwise fills the totals (0/0 when the store is empty). Any-thread
// safe — used by the web dashboard's File tab.
bool fileHandlerStoreStats(uint64_t& outTotalFiles, uint64_t& outTotalBytes);

// ---------------------------------------------------------------------------
// Cross-handler primitives
// ---------------------------------------------------------------------------
//
// These are intended for other CesPlex builtins that need to cooperate
// with the file store (currently: builtin:compute, which charges the
// source file's file_balance for hosting a running program). They are
// in-process, unsigned, and do NOT perform any feeQuery / nonce / dedup
// work — those are the caller's own concern. All three run on whatever
// thread invokes them; the file handler takes no internal locks beyond
// the small gStoreMetaMutex for the store-level TOML.

// Roll rent forward on the file and return its current owner pubkey
// and file_balance. Returns false if the file doesn't exist, the
// sidecar is unreadable, the handler is unbound, or rent drove the
// file into deletion (the deletion callback has already fired in that
// case).
bool fileHandlerReadOwnerAndBalance(
    const std::string& name,
    std::array<uint8_t, 32>& outOwnerPubkey,
    uint64_t& outFileBalance);

// Read the file's program-account pubkey (the ed25519 public key stored
// in the sidecar at CREATE time, identifying the ledger Account that
// running instances of this program share). Returns false if the file
// doesn't exist or the sidecar is unreadable.
bool fileHandlerReadProgramPubkey(
    const std::string& name,
    std::array<uint8_t, 32>& outProgramPubkey);

// Read the file's program-account ed25519 private key (sidecar). Returns
// false if the file doesn't exist or the sidecar is unreadable.
bool fileHandlerReadProgramPrivkey(
    const std::string& name,
    std::array<uint8_t, 32>& outProgramPrivkey);

// Debit `amount` credits from the file's file_balance. Rolls rent
// forward before the debit. If the post-roll balance cannot cover
// `amount`, the file is DELETED (like rent exhaustion) and the
// function returns false — the deletion callback has fired by then.
// On success, persists the new balance and returns true.
bool fileHandlerDebitBalance(const std::string& name, uint64_t amount);

// Credit `amount` credits into the file's file_balance. Rolls rent
// forward before the credit (so incoming credits don't pay off
// already-owed rent silently). Returns false if the file doesn't
// exist, the sidecar is unreadable, the handler is unbound, or
// rent drove the file into deletion during the roll-forward.
bool fileHandlerCreditBalance(const std::string& name, uint64_t amount);

// Returns the sha256(file_content || file_path) for the file at
// `name`, computing it lazily on first call (or after invalidation
// by a content-mutating verb). The result is cached in the sidecar
// — subsequent calls do no hashing until the file is WRITE/APPEND/
// RESIZE-ed, at which point the cached value is cleared and the
// next call recomputes. Used by builtin:compute when minting
// authentic assets, where the 32-byte hash becomes the asset
// content's protected prefix.
//
// Returns false if the file doesn't exist, the sidecar is
// unreadable, the handler is unbound, rent drove the file into
// deletion during the roll-forward, or content streaming failed.
bool fileHandlerGetProgramHash(
    const std::string& name,
    std::array<uint8_t, 32>& outHash);

// Register a callback invoked right after a file is deleted by any
// internal path (rent exhaustion via chargeRentOrDelete, the DELETE
// verb, the gcReclaim sweep, or the debit-exhaustion path in
// fileHandlerDebitBalance). Callback receives the file name and runs
// on the thread that drove the deletion — typically rpcTaskIO_, but
// not guaranteed. Must be quick and non-blocking. Multiple callbacks
// may be registered; they fire in registration order. There is no
// deregister — callbacks live for the process lifetime, which matches
// the handler-singleton lifecycle.
void fileHandlerRegisterDeletionCallback(
    std::function<void(const std::string&)> cb);

// ---------------------------------------------------------------------------
// In-process verb execution for L2 cross-handler use
// ---------------------------------------------------------------------------
//
// Parallel to the wire verbs, but takes an already-authorized owner
// pubkey (no wire signature verify, no nonce, no dedup). Intended
// for builtin:compute: a Lua program running under an owner's
// authority invokes these to touch the file store 1:1 as the owner
// would.
//
// Fees mirror the wire path exactly (feeQuery per op, feeFileWrite
// on WRITE/APPEND, feeFileRead + price_per_kb on non-owner READ,
// upfront rent on CREATE/APPEND/RESIZE-grow, initial_deposit on
// CREATE, etc.). The PAYER for every credit that would normally hit
// the wire signer's account is `sourceName` — the file_balance of
// the program's source file ("the program's wallet"). Refunds that
// would normally go to the wire signer's account (WITHDRAW amount,
// DELETE refund) also land in sourceName's file_balance. This keeps
// the program's credit exposure bounded by what the operator put
// into the source file's file_balance at LAUNCH time and prevents
// a running program from writing to the store without being charged.
//
// Zone-ownership gate (/h/, /f/, /p/, /s/) still applies: a program
// running under owner X can only CREATE in /h/<hex(X)>/ paths, /f/<n>
// paths whose asset X owns, /p/, or nothing in /s/. Subsequent ops
// on existing files check the sidecar's owner_pubkey against the
// passed-in owner.
//
// Returns via callback on `cbExecutor`. Thread-safe: internal calls
// hop to logicStrand_ as needed (/f/ zone check).

struct FileExecReq {
  std::array<uint8_t, 32> ownerPubkey{};
  std::string sourceName;         // program's source file — pays all fees
  uint8_t verb = 0;               // 0x01..0x0a (matches wire verb codes)
  std::string name;
  uint64_t offset = 0;            // WRITE, READ
  uint32_t length = 0;            // READ
  uint64_t size = 0;              // CREATE, RESIZE
  uint64_t pricePerKb = 0;        // CREATE, SET_PRICE
  uint64_t initialDeposit = 0;    // CREATE
  uint64_t amount = 0;            // DEPOSIT, WITHDRAW
  ces::Bytes body;      // WRITE, APPEND
};

struct FileExecResp {
  uint8_t status = 0xFF;          // CES_OK on success, else error_code_t
  // Verb-specific outputs. Zero-valued on verbs that don't set them.
  uint64_t fileBalance = 0;       // CREATE, WRITE, DEPOSIT, WITHDRAW, APPEND, RESIZE, STAT
  uint64_t size = 0;              // STAT, APPEND (new size), RESIZE (new size)
  uint64_t pricePerKb = 0;        // STAT, SET_PRICE
  uint64_t createdUs = 0;         // STAT
  uint64_t modifiedUs = 0;        // STAT
  uint64_t refunded = 0;          // DELETE
  std::array<uint8_t, 32> ownerPubkey{};  // STAT
  ces::Bytes data;      // READ
};

void fileHandlerExec(
    const FileExecReq& req,
    std::function<void(FileExecResp)> cb,
    boost::asio::any_io_executor cbExecutor);

} // namespace ces
