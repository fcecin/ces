// file_handler.h - builtin:file: per-server disk file storage handler.
//
// Mounts /ces/file/1 on the plex (rpc) port. Disk-backed file storage with
// four-zone naming, per-byte/day rent, and a kv-store file type.
//
// One FileHandler OBJECT per CesServer (owned by the server, holds a back
// pointer to it). No process-global state: N servers coexist in one process.
//
// Lifecycle: the server constructs a FileHandler(this) and mounts it into its
// CesPlex when /ces/file/1 is wired in [cesplex_mounts], then calls
// startupReconcile(); on shutdown it calls stop() and drops the object (before
// CesPlex / rpcRudp_ go away). cesFileStoreMaxBytes is only the metered-zone
// cap (/s/ is unmetered and served whenever mounted), not the on/off switch.
//
// Rent is collected lazily - on every non-DEPOSIT op touching a file, and on
// JIT GC during CREATE when the store is at capacity. No periodic "rent pass"
// runs; dead files stay on disk until the next CREATE (or op touching them)
// reclaims them.

#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <boost/asio/any_io_executor.hpp>

#include <ces/buffer.h>            // ces::Bytes
#include <ces/cesplex/mux.h>      // CesPlexHandler, BoundChannelContext
#include <minx/rudp/rudp_stream.h>

namespace ces {

class CesServer;

// The single /s/ ("server zone") predicate. /s/ paths are operator-deployed:
// unmetered, outside the store cap, server-key-write-only; a compute program
// sourced from /s/ runs privileged (may use operator-only API such as ces.log).
// Every /s/ and privilege decision routes through here -- do not re-derive it.
inline bool isServerZone(const std::string& name) {
  return name.size() >= 3 && name[0] == '/' &&
         name[1] == 's' && name[2] == '/';
}

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
// the wire signer's account is `sourceName` - the file_balance of
// the program's source file ("the program's wallet"). Refunds that
// would normally go to the wire signer's account (WITHDRAW amount,
// DELETE refund) also land in sourceName's file_balance.
//
// Zone-ownership gate (/h/, /f/, /p/, /s/) still applies.
//
// Returns via callback on `cbExecutor`. Thread-safe: internal calls
// hop to logicStrand_ as needed (/f/ zone check).

struct FileExecReq {
  std::array<uint8_t, 32> ownerPubkey{};
  std::string sourceName;         // program's source file - pays all fees
  uint8_t verb = 0;               // 0x01..0x0a (matches wire verb codes)
  std::string name;
  uint64_t offset = 0;            // WRITE, READ
  uint32_t length = 0;            // READ
  uint64_t size = 0;              // CREATE, RESIZE
  uint64_t pricePerKb = 0;        // CREATE, SET_PRICE
  uint64_t initialDeposit = 0;    // CREATE
  uint64_t amount = 0;            // DEPOSIT, WITHDRAW, KV_DEPOSIT, KV_RANGE byte budget
  ces::Bytes body;      // WRITE, APPEND
  ces::Bytes key;       // KV_PUT, KV_GET, KV_ERASE, KV_DEPOSIT
  ces::Bytes value;     // KV_PUT
  ces::Bytes rangeLo;   // KV_RANGE (inclusive lower bound; empty = start of store)
  ces::Bytes rangeHi;   // KV_RANGE (exclusive upper bound; empty = end of store)
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
  ces::Bytes value;             // KV_GET
  bool found = false;           // KV_GET
  std::vector<ces::Bytes> keys; // KV_ITER, KV_RANGE (sorted; parallel to values)
  std::vector<ces::Bytes> values; // KV_RANGE (parallel to keys)
  ces::Bytes rangeEnd;          // KV_RANGE: == requested hi if complete, else
                                // the next undelivered key (resume point)
};

// Per-server kv-store cache (mutex + open-store map). Defined in the .cpp,
// where the logkv store type is visible; the handler holds it by pointer so
// this header stays free of logkv.
struct FileKvCache;

class FileHandler : public CesPlexHandler {
public:
  explicit FileHandler(CesServer* server);
  ~FileHandler();

  FileHandler(const FileHandler&) = delete;
  FileHandler& operator=(const FileHandler&) = delete;

  // CesPlexHandler: a freshly-bound /ces/file/1 channel. Runs the signed
  // per-op verb loop (cesPlexServe).
  void serve(std::shared_ptr<minx::RudpStream> stream,
             BoundChannelContext bound) override;

  // Release kv handles and stop accepting verbs. Call on shutdown before
  // CesPlex / rpcRudp_ go away.
  void stop();

  // One-time startup walk of the file store directory: publish the bundled
  // /s/ site, reconcile /s/ sidecars, regenerate the /s/ index, and recompute
  // total_files/total_bytes into .store.toml. Safe with no files present.
  void startupReconcile();

  // Daily per-extension local-budget sweep: top every /s/ program account up
  // to the server's extLocalBudget (deficit only). Called from dailyTaskTick.
  // No-op if the file feature is off or the budget is 0.
  void sweepExtensionBudget();

  // Daily per-key rent sweep for kv-stores: charge each cell its rent, evict
  // cells whose balance hits 0, and burn the collected rent from the store's
  // program account. MUST run OFF logicStrand_ (takes the kv mutex then hops
  // to logicStrand for the burn).
  void sweepKvRent();

  // /s/ file read/write/remove for L2 cross-handler use (the extension
  // manager). Read returns "" and write/remove false if not /s/.
  std::string readServerFile(const std::string& name);
  bool writeServerFile(const std::string& name, const std::string& content);
  bool removeServerFile(const std::string& name);

  // Read store-level stats from .store.toml (under the store mutex) for
  // monitoring. Fills the totals (0/0 when empty). Any-thread safe.
  bool storeStats(uint64_t& outTotalFiles, uint64_t& outTotalBytes);

  // -------------------------------------------------------------------------
  // Cross-handler primitives (builtin:compute). In-process, unsigned; no
  // feeQuery / nonce / dedup. See the per-method comments in file_handler.cpp.
  // -------------------------------------------------------------------------

  // Roll rent forward and return the file's owner pubkey + program-account
  // balance. False if missing/unreadable or rent drove it into deletion.
  bool readOwnerAndBalance(const std::string& name,
                           std::array<uint8_t, 32>& outOwnerPubkey,
                           uint64_t& outFileBalance);
  // Read the file's program-account ed25519 public key from its sidecar.
  bool readProgramPubkey(const std::string& name,
                         std::array<uint8_t, 32>& outProgramPubkey);
  // Read the file's program-account ed25519 private key from its sidecar.
  bool readProgramPrivkey(const std::string& name,
                          std::array<uint8_t, 32>& outProgramPrivkey);
  // Debit `amount` from the file's program account (rolls rent first). The
  // file is DELETED if the post-roll balance cannot cover it; returns false.
  bool debitBalance(const std::string& name, uint64_t amount);
  // Credit `amount` into the file's program account (rolls rent first).
  bool creditBalance(const std::string& name, uint64_t amount);
  // sha256(file_content || file_path), cached in the sidecar until the file
  // is content-mutated. Used by builtin:compute for authentic asset minting.
  bool getProgramHash(const std::string& name,
                      std::array<uint8_t, 32>& outHash);
  // Register a callback invoked right after a file is deleted by any internal
  // path. Fires in registration order on the deleting thread. No deregister.
  void registerDeletionCallback(std::function<void(const std::string&)> cb);
  // In-process verb execution. See FileExecReq / FileExecResp above.
  void exec(const FileExecReq& req,
            std::function<void(FileExecResp)> cb,
            boost::asio::any_io_executor cbExecutor);

  // Per-server state. Public so this translation unit's free helpers
  // (file_handler.cpp) reach it via server->fileHandler(); not a stable API
  // for other code.
  CesServer* server_ = nullptr;
  std::mutex storeMetaMutex_;
  std::mutex deletionCallbacksMutex_;
  std::vector<std::function<void(const std::string&)>> deletionCallbacks_;
  std::unique_ptr<FileKvCache> kv_;

private:
  std::atomic<bool> stopped_{false};
};

} // namespace ces
