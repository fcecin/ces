// file_handler.cpp - builtin:file CesPlex handler (v2)
//
// Disk-backed file storage. This file implements:
//
//   - Name validation + filesystem-path mapping (5-component cap,
//     leading slash, no dotfiles, etc.)
//   - TOML sidecar load/save with write-rename atomicity
//   - Global .store.toml with process-wide mutex
//   - 8 verbs: CREATE, WRITE, READ, STAT (free unsigned), DEPOSIT,
//     WITHDRAW, SET_PRICE, DELETE
//   - Preamble-first wire framing; sig commits to preamble before
//     body bytes arrive; handler can verify+charge before streaming
//   - Server-signed response envelope on every verb (bound to the
//     request's sig hash so clients get a receipt)
//   - Handler loops on one channel: read verb → serve → read next verb
//   - Rent GC + startup reconciliation hooks for CesServer
//
// Economic rule: every signed op pays feeQuery from signer's account
// (the nonce/dedup machinery the rest of CES already uses). "Big"
// economic flows (amount deposited, amount withdrawn, write cost,
// read price) go where the spec says — file_balance, or between
// signer and file_balance, as each verb defines. STAT is free.
//
// Fee-discount policy. The per-channel RUDP rates that apply to a
// bound CesPlex channel are discounted at the ChannelMeter tick
// layer under FeeKind::Net (see cesplex/meter.cpp). The per-verb
// feeQuery debits dispatched here against the bound signer are
// intentionally raw — they are the flat anti-spam toll on top of
// the channel-level dynamic pricing. The compute handler discounts
// its per-verb feeQuery via FeeKind::Query because compute jobs are
// discrete one-shot work consuming l1cpu; file-handler verbs are
// bound-channel work whose dynamic component is already priced via
// Net, so the per-verb toll stays flat by design.

#include <ces/cesplex/mux.h>
#include <ces/cesplex/session.h>
#include <ces/l2/file_handler.h>
#include <ces/buffer.h>
#include <ces/ramfilestore.h>
#include <ces/keys.h>
#include <ces/server.h>
#include <ces/types.h>

#include <minx/blog.h>

#include <toml++/toml.hpp>

#include <cryptopp/sha.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <atomic>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <mutex>
#include <span>
#include <sstream>
#include <string>
#include <vector>

LOG_MODULE("plex");

namespace ces {

namespace {

// ---------------------------------------------------------------------------
// Global server binding — see file header.
// ---------------------------------------------------------------------------

std::atomic<CesServer*> gServer{nullptr};

// Process-wide mutex for .store.toml read-modify-write. Held only
// during the small TOML update, never across content I/O.
std::mutex gStoreMetaMutex;

// Registered deletion callbacks — invoked right after a file is
// deleted internally. See fileHandlerRegisterDeletionCallback in the
// public header for the contract. Append-only; callbacks live for the
// process lifetime.
std::mutex gDeletionCallbacksMutex;
std::vector<std::function<void(const std::string&)>> gDeletionCallbacks;

void notifyDeletion(const std::string& name) {
  std::vector<std::function<void(const std::string&)>> cbs;
  {
    std::lock_guard lk(gDeletionCallbacksMutex);
    cbs = gDeletionCallbacks; // copy under lock; fire outside
  }
  for (auto& cb : cbs) {
    try { cb(name); } catch (...) {}
  }
}

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

constexpr uint8_t kVerbCreate   = 0x01;
constexpr uint8_t kVerbWrite    = 0x02;
constexpr uint8_t kVerbRead     = 0x03;
constexpr uint8_t kVerbStat     = 0x04;
constexpr uint8_t kVerbDeposit  = 0x05;
constexpr uint8_t kVerbWithdraw = 0x06;
constexpr uint8_t kVerbSetPrice = 0x07;
constexpr uint8_t kVerbDelete   = 0x08;
constexpr uint8_t kVerbAppend   = 0x09;  // extend-write N bytes past size
constexpr uint8_t kVerbResize   = 0x0a;  // set new size (sparse extend or truncate)

constexpr uint16_t kMaxNameLen = 512;
constexpr uint16_t kMaxContentTypeLen = 128;
constexpr uint32_t kMaxWriteLen = 1024 * 1024; // 1 MB per WRITE
constexpr uint32_t kMaxReadLen  = 1024 * 1024; // 1 MB per READ
constexpr size_t   kMaxPathComponents = 5;
constexpr uint64_t kMaxFileSize = 64ull * 1024 * 1024 * 1024; // 64 GB

constexpr const char* kSidecarSuffix = ".sidecar.toml";
constexpr const char* kStoreMetaName = ".store.toml";
// Sidecar schema: `program_pubkey` (32B reference to a real Account in
// accountStore_) replaced the old sidecar-resident `file_balance` pool;
// the file's credits now live in the ledger account store like any other
// account (pays daily rent, supports deposit/withdraw/transfer, shared by
// every running instance). Older sidecars carrying the removed
// content_sha256 field are rejected on load.
constexpr uint32_t kSidecarVersion = 5;

// Microseconds per day — denominator in per-byte-day rent math.
constexpr uint64_t kUsecsPerDay = 86'400'000'000ull;

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

std::string hexOf(const uint8_t* data, size_t len) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out.push_back(kHex[data[i] >> 4]);
    out.push_back(kHex[data[i] & 0xF]);
  }
  return out;
}

bool hexTo(const std::string& s, uint8_t* out, size_t outLen) {
  if (s.size() != outLen * 2) return false;
  auto nibble = [](char c, uint8_t& v) -> bool {
    if (c >= '0' && c <= '9') { v = c - '0'; return true; }
    if (c >= 'a' && c <= 'f') { v = c - 'a' + 10; return true; }
    if (c >= 'A' && c <= 'F') { v = c - 'A' + 10; return true; }
    return false;
  };
  for (size_t i = 0; i < outLen; ++i) {
    uint8_t hi, lo;
    if (!nibble(s[i * 2], hi) || !nibble(s[i * 2 + 1], lo)) return false;
    out[i] = (hi << 4) | lo;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Name validation + path mapping
// ---------------------------------------------------------------------------

// Validates a CES file name against the spec. Returns CES_OK or a
// specific CES_ERROR_BAD_NAME. Never throws.
//
// Four mandatory zones — the first path component must be one of:
//   "h" → /h/<64 hex>/<path...>   (self-owned "home" dir; see dispatchCreate)
//   "f" → /f/<name>/<path...>    (asset-gated registered namespace)
//   "p" → /p/<anything>/<...>    (public, first-come-first-served)
//   "s" → /s/<anything>/<...>    (server-deployed, unmetered, outside
//                                 the cap — only the server's own
//                                 private key may CREATE/WRITE here)
//
// The minimum path is /<zone>/<something> (2 components). Zone-specific
// rules on the second component are enforced here; ledger/asset checks
// are the caller's job (dispatchCreate).
uint8_t validateCesFileName(const std::string& name) {
  if (name.empty()) return CES_ERROR_BAD_NAME;
  if (name[0] != '/') return CES_ERROR_BAD_NAME;
  if (name.size() > kMaxNameLen) return CES_ERROR_BAD_NAME;
  if (name.size() == 1) return CES_ERROR_BAD_NAME; // just "/"
  if (name.back() == '/') return CES_ERROR_BAD_NAME;

  // Walk components.
  size_t n = name.size();
  size_t comp_count = 0;
  size_t i = 1;
  size_t firstStart = 0, firstLen = 0;
  size_t secondStart = 0, secondLen = 0;
  const size_t sidecarSuffixLen = std::strlen(kSidecarSuffix);
  while (i < n) {
    size_t start = i;
    while (i < n && name[i] != '/') {
      if (name[i] == '\0') return CES_ERROR_BAD_NAME;
      ++i;
    }
    size_t len = i - start;
    if (len == 0) return CES_ERROR_BAD_NAME; // empty component
    if (len > 255) return CES_ERROR_BAD_NAME; // filesystem limit
    // Reject any component starting with '.' — one check covers ".", "..",
    // and dotfiles, blocking traversal and hidden entries.
    if (name[start] == '.') return CES_ERROR_BAD_NAME;
    // ".sidecar.toml" is reserved: a component ending in it would map a
    // content path onto a sidecar file on disk. Reject in any component.
    if (len >= sidecarSuffixLen &&
        name.compare(start + len - sidecarSuffixLen,
                     sidecarSuffixLen, kSidecarSuffix) == 0)
      return CES_ERROR_BAD_NAME;
    ++comp_count;
    if (comp_count > kMaxPathComponents) return CES_ERROR_BAD_NAME;
    if (comp_count == 1) { firstStart = start; firstLen = len; }
    else if (comp_count == 2) { secondStart = start; secondLen = len; }
    if (i < n) ++i; // skip '/'
  }

  // Must have at least 2 components total: zone + something.
  if (comp_count < 2) return CES_ERROR_BAD_NAME;

  // First component must be exactly one of the four zone markers.
  if (firstLen != 1) return CES_ERROR_BAD_NAME;
  char zone = name[firstStart];
  if (zone != 'h' && zone != 'f' && zone != 'p' && zone != 's')
    return CES_ERROR_BAD_NAME;

  // Zone-specific rules on the second component.
  if (zone == 'h') {
    // Must be exactly 64 lowercase hex chars = 32-byte pubkey.
    if (secondLen != 64) return CES_ERROR_BAD_NAME;
    for (size_t j = 0; j < secondLen; ++j) {
      char c = name[secondStart + j];
      if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
        return CES_ERROR_BAD_NAME;
    }
  }
  // /f/, /p/, /s/ all accept any valid segment (already filtered by
  // the dotfile / . / .. / length rules above). Asset-ownership check
  // for /f/ and server-key check for /s/ happen in checkZoneOwnership.
  return CES_OK;
}

// True iff `name` starts with "/s/". Used to gate the unmetered /
// outside-the-cap / server-owner-only code paths.
inline bool isServerZone(const std::string& name) {
  return name.size() >= 3 && name[0] == '/' &&
         name[1] == 's' && name[2] == '/';
}

// Per-KB fee arithmetic. feeFileWrite and feeFileRead are charged
// "credits per 1024 bytes" (ceiling-rounded); at the default values
// a per-byte reading would make a 1 MB file cost 20 B credits. Use
// this for every length → fee conversion.
inline uint64_t kbCeil(uint64_t bytes) {
  return (bytes + 1023u) / 1024u;
}

std::filesystem::path resolveContentPath(const std::string& dir,
                                         const std::string& name) {
  // name starts with '/', strip it for relative path under dir.
  std::string rel = name.substr(1);
  return std::filesystem::path(dir) / rel;
}

std::filesystem::path resolveSidecarPath(const std::string& dir,
                                         const std::string& name) {
  auto p = resolveContentPath(dir, name);
  p += kSidecarSuffix;
  return p;
}

std::filesystem::path storeMetaPath(const std::string& dir) {
  return std::filesystem::path(dir) / kStoreMetaName;
}

// Verify that a CES name doesn't collide with an existing path.
// Specifically: every prefix of the name's directory chain must
// either not exist, or exist as a directory (not a file); and the
// name itself must not collide with an existing directory.
uint8_t checkPathConflict(const std::string& dir,
                          const std::string& name,
                          bool createMode) {
  namespace fs = std::filesystem;
  fs::path full = resolveContentPath(dir, name);
  // Check intermediate parents.
  fs::path cur = dir;
  std::string rel = name.substr(1);
  size_t start = 0;
  while (true) {
    size_t slash = rel.find('/', start);
    if (slash == std::string::npos) break;
    std::string comp = rel.substr(start, slash - start);
    cur /= comp;
    std::error_code ec;
    if (fs::exists(cur, ec)) {
      if (!fs::is_directory(cur, ec)) return CES_ERROR_PATH_CONFLICT;
    }
    start = slash + 1;
  }
  // If CREATE: full path must not already be a directory or file.
  // If not CREATE: full path must exist and be a regular file.
  std::error_code ec;
  if (createMode) {
    if (fs::exists(full, ec)) {
      if (fs::is_directory(full, ec)) return CES_ERROR_PATH_CONFLICT;
      return CES_ERROR_FILE_EXISTS;
    }
  } else {
    if (!fs::exists(full, ec)) return CES_ERROR_FILE_NOT_FOUND;
    if (!fs::is_regular_file(full, ec)) return CES_ERROR_PATH_CONFLICT;
  }
  return CES_OK;
}

// ---------------------------------------------------------------------------
// Sidecar TOML
// ---------------------------------------------------------------------------

struct Sidecar {
  uint32_t version = kSidecarVersion;
  std::string name;
  std::array<uint8_t, 32> owner_pubkey{};
  // The file's "program account" in accountStore_, allocated at CREATE and
  // referenced by every running instance. Real ed25519 keypair: program_pubkey
  // keys the account; program_privkey is the private half the program signs its
  // own remote ops with. The private half lives only here on disk (server-side)
  // — STAT never returns it (allowlist), and the sidecar is unreachable as
  // content (.sidecar.toml is a reserved suffix). Inbound transfers work
  // normally; the account pays daily rent like any account.
  std::array<uint8_t, 32> program_pubkey{};
  std::array<uint8_t, 32> program_privkey{};
  uint64_t price_per_kb = 0;
  uint64_t size = 0;
  std::string content_type;
  uint64_t created_us = 0;
  uint64_t modified_us = 0;
  // Microseconds since epoch of the last moment rent was charged
  // against this file. Every non-DEPOSIT op rolls rent forward from
  // this to now before proceeding. Initialized to created_us at
  // CREATE.
  uint64_t last_rent_us = 0;
  // Lazily-computed sha256(content || path) used by authentic
  // asset minting. All-zero means "not yet computed" — recompute
  // on demand. Cleared back to all-zero by any content-mutating
  // verb (WRITE, APPEND, RESIZE) so the next mint recomputes.
  std::array<uint8_t, 32> program_hash{};
};

bool writeSidecar(const std::filesystem::path& path, const Sidecar& s) {
  // Serialize through tomlplusplus (symmetric with readSidecar) so name /
  // content_type are escaped. A hand-rolled `key = "val"` dump corrupts the
  // sidecar when those fields contain quotes or newlines, which they can:
  // validateCesFileName only filters '/' and NUL.
  toml::table tbl;
  tbl.insert_or_assign("version", static_cast<int64_t>(s.version));
  tbl.insert_or_assign("name", s.name);
  tbl.insert_or_assign("owner_pubkey",
                       hexOf(s.owner_pubkey.data(), s.owner_pubkey.size()));
  tbl.insert_or_assign("program_pubkey",
                       hexOf(s.program_pubkey.data(), s.program_pubkey.size()));
  tbl.insert_or_assign("program_privkey",
                       hexOf(s.program_privkey.data(), s.program_privkey.size()));
  tbl.insert_or_assign("price_per_kb", static_cast<int64_t>(s.price_per_kb));
  tbl.insert_or_assign("size", static_cast<int64_t>(s.size));
  tbl.insert_or_assign("content_type", s.content_type);
  tbl.insert_or_assign("created_us", static_cast<int64_t>(s.created_us));
  tbl.insert_or_assign("modified_us", static_cast<int64_t>(s.modified_us));
  tbl.insert_or_assign("last_rent_us", static_cast<int64_t>(s.last_rent_us));
  tbl.insert_or_assign("program_hash",
                       hexOf(s.program_hash.data(), s.program_hash.size()));

  std::filesystem::path tmp = path;
  tmp += ".tmp";
  {
    std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f << tbl << '\n';
    if (!f.good()) return false;
    f.flush();
  }
  std::error_code ec;
  std::filesystem::rename(tmp, path, ec);
  return !ec;
}

bool readSidecar(const std::filesystem::path& path, Sidecar& s) {
  std::error_code ec;
  if (!std::filesystem::exists(path, ec)) return false;
  toml::table tbl;
  try {
    tbl = toml::parse_file(path.string());
  } catch (...) {
    return false;
  }
  auto getU64 = [&](const char* k, uint64_t& out) -> bool {
    auto v = tbl[k].value<int64_t>();
    if (!v) return false;
    out = static_cast<uint64_t>(*v);
    return true;
  };
  auto getStr = [&](const char* k, std::string& out) -> bool {
    auto v = tbl[k].value<std::string>();
    if (!v) return false;
    out = *v;
    return true;
  };
  uint64_t version = 0;
  if (!getU64("version", version)) return false;
  if (version != kSidecarVersion) return false;
  if (!getStr("name", s.name)) return false;
  std::string ownerHex;
  if (!getStr("owner_pubkey", ownerHex)) return false;
  if (!hexTo(ownerHex, s.owner_pubkey.data(), s.owner_pubkey.size()))
    return false;
  std::string progPubkeyHex;
  if (!getStr("program_pubkey", progPubkeyHex)) return false;
  if (!hexTo(progPubkeyHex, s.program_pubkey.data(),
             s.program_pubkey.size()))
    return false;
  std::string progPrivkeyHex;
  if (!getStr("program_privkey", progPrivkeyHex)) return false;
  if (!hexTo(progPrivkeyHex, s.program_privkey.data(),
             s.program_privkey.size()))
    return false;
  if (!getU64("price_per_kb", s.price_per_kb)) return false;
  if (!getU64("size", s.size)) return false;
  if (!getStr("content_type", s.content_type)) return false;
  if (!getU64("created_us", s.created_us)) return false;
  if (!getU64("modified_us", s.modified_us)) return false;
  if (!getU64("last_rent_us", s.last_rent_us)) return false;
  // program_hash is optional (added later, missing in older sidecars
  // and on the freshly-emitted form before the first authentic-mint).
  // Treat missing or unparseable as "not yet computed" (all-zero).
  std::string hashHex;
  if (getStr("program_hash", hashHex)) {
    if (!hexTo(hashHex, s.program_hash.data(), s.program_hash.size()))
      s.program_hash.fill(0);
  } else {
    s.program_hash.fill(0);
  }
  s.version = kSidecarVersion;
  return true;
}

// ---------------------------------------------------------------------------
// Global store metadata (.store.toml)
// ---------------------------------------------------------------------------

struct StoreMeta {
  uint64_t total_files = 0;
  uint64_t total_bytes = 0;
  // Microseconds-since-epoch of the last gcReclaim run. Used to
  // debounce JIT GC on CREATE so a flood of over-cap requests can't
  // force a full-store scan on every failed CREATE.
  uint64_t last_gc_us = 0;
};

// Debounce window for JIT GC on CREATE. If the last gcReclaim ran
// less than this long ago, a CREATE that can't fit in the cap fails
// with STORE_FULL without rescanning — the just-completed GC already
// reflects the best we can do.
//
// This is also the upfront-rent window: every op that grows a file's
// size (CREATE, APPEND, RESIZE-grow) requires the file_balance to
// be able to cover 15 minutes of rent on the new bytes. Reasoning:
// a griefer can pin bytes in the cap for at most one GC cycle. Making
// them prepay that cycle's rent forces the grief to be economically
// painful — for the size of cap they're locking, at the rent rate
// for the window.
constexpr uint64_t kGcDebounceUs = 15ull * 60 * 1'000'000; // 15 min

bool readStoreMeta(const std::filesystem::path& path, StoreMeta& m) {
  std::error_code ec;
  if (!std::filesystem::exists(path, ec)) {
    m = StoreMeta{};
    return true;
  }
  toml::table tbl;
  try {
    tbl = toml::parse_file(path.string());
  } catch (...) {
    return false;
  }
  m.total_files = static_cast<uint64_t>(
    tbl["total_files"].value_or<int64_t>(0));
  m.total_bytes = static_cast<uint64_t>(
    tbl["total_bytes"].value_or<int64_t>(0));
  m.last_gc_us = static_cast<uint64_t>(
    tbl["last_gc_us"].value_or<int64_t>(0));
  return true;
}

bool writeStoreMeta(const std::filesystem::path& path, const StoreMeta& m) {
  std::ostringstream oss;
  oss << "version = 1\n";
  oss << "total_files = " << m.total_files << "\n";
  oss << "total_bytes = " << m.total_bytes << "\n";
  oss << "last_gc_us = " << m.last_gc_us << "\n";
  std::filesystem::path tmp = path;
  tmp += ".tmp";
  {
    std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    const std::string body = oss.str();
    f.write(body.data(), body.size());
    if (!f.good()) return false;
    f.flush();
  }
  std::error_code ec;
  std::filesystem::rename(tmp, path, ec);
  return !ec;
}

// Updates the store meta by (delta_files, delta_bytes). Caller must
// hold gStoreMetaMutex. Creates .store.toml if missing.
void adjustStoreMeta(const std::string& dir, int64_t df, int64_t db) {
  auto p = storeMetaPath(dir);
  StoreMeta m;
  readStoreMeta(p, m); // tolerant of missing file
  if (df >= 0) m.total_files += static_cast<uint64_t>(df);
  else m.total_files -= std::min(m.total_files, uint64_t(-df));
  if (db >= 0) m.total_bytes += static_cast<uint64_t>(db);
  else m.total_bytes -= std::min(m.total_bytes, uint64_t(-db));
  writeStoreMeta(p, m);
}

// ---------------------------------------------------------------------------
// Rent math + per-op rent collection
// ---------------------------------------------------------------------------

// Owed rent in credits for `elapsed_us` microseconds, floored.
// Uses __uint128_t for safety — realistic inputs don't come close to
// overflow, but a malicious tamper of last_rent_us or extreme values
// can; we clamp to UINT64_MAX in that case (effectively "dead file").
uint64_t computeOwedRent(uint64_t size, int64_t feeRent,
                         uint64_t lastRentUs, uint64_t nowUs) {
  if (nowUs <= lastRentUs) return 0;
  if (feeRent <= 0 || size == 0) return 0;
  __uint128_t owed = static_cast<__uint128_t>(size)
                   * static_cast<__uint128_t>(static_cast<uint64_t>(feeRent))
                   * static_cast<__uint128_t>(nowUs - lastRentUs);
  owed /= static_cast<__uint128_t>(kUsecsPerDay);
  if (owed > std::numeric_limits<uint64_t>::max())
    return std::numeric_limits<uint64_t>::max();
  return static_cast<uint64_t>(owed);
}

// Roll rent forward on a file up to now. Mutates `sc` in place.
//
// - If the file can cover the owed rent: deducts it, advances
//   `last_rent_us`, returns true. Caller is responsible for writing
//   the updated sidecar to disk (bundles nicely with the op's own
//   sidecar update, if any).
// - If the owed rent exceeds balance: deletes content + sidecar on
//   disk, bumps store meta (-1 file, -size bytes), returns false.
//   Caller should treat this as CES_ERROR_FILE_NOT_FOUND for the
//   in-flight op.
// - If owed is zero (same microsecond, free-tier, etc.): no-op,
//   returns true. Caller may skip writing the sidecar.
// True iff sc.program_pubkey is non-zero (the file has a program account).
bool sidecarHasProgramAccount(const Sidecar& sc) {
  for (auto b : sc.program_pubkey)
    if (b != 0) return true;
  return false;
}

// Read the file's program-account balance synchronously (sync hop
// to logicStrand_). Returns 0 if the account doesn't exist (e.g.,
// rent-collected by daily maintenance) or the sidecar has no
// program_pubkey (defensive — shouldn't happen post-v5).
uint64_t readProgramAccountBalance(CesServer* server, const Sidecar& sc) {
  if (!sidecarHasProgramAccount(sc)) return 0;
  minx::Hash pubkey{};
  std::memcpy(pubkey.data(), sc.program_pubkey.data(), 32);
  int64_t bal = server->_l2ProgramAccountBalanceSync(pubkey);
  return bal < 0 ? 0 : static_cast<uint64_t>(bal);
}

// Atomically debit `amount` from the file's program account.
// Returns (true, newBalance) on success or (false, currentBalance)
// on insufficient funds / missing account. Caller decides what
// "insufficient" means policy-wise.
struct ProgAcctDebitResult { bool ok; uint64_t newBalance; };
ProgAcctDebitResult
debitProgramAccount(CesServer* server, const Sidecar& sc, uint64_t amount) {
  if (!sidecarHasProgramAccount(sc)) return {false, 0};
  minx::Hash pubkey{};
  std::memcpy(pubkey.data(), sc.program_pubkey.data(), 32);
  auto r = server->_l2DebitProgramAccountSync(
    pubkey, static_cast<int64_t>(amount));
  return {r.ok,
          static_cast<uint64_t>(r.newBalance < 0 ? 0 : r.newBalance)};
}

// Credit `amount` into the file's program account. Creates the
// account from thin air if missing (server-mediated mint).
void creditProgramAccount(CesServer* server, const Sidecar& sc, uint64_t amount) {
  if (!sidecarHasProgramAccount(sc)) return;
  minx::Hash pubkey{};
  std::memcpy(pubkey.data(), sc.program_pubkey.data(), 32);
  server->_l2CreditProgramAccountSync(pubkey, static_cast<int64_t>(amount));
}

bool chargeRentOrDelete(const std::filesystem::path& cPath,
                        const std::filesystem::path& sPath,
                        Sidecar& sc,
                        int64_t feeRent,
                        const std::string& dir) {
  // /s/ files are unmetered. Never accrue rent, never die of
  // exhaustion. Caller may skip writing the sidecar (last_rent_us
  // is never advanced).
  if (isServerZone(sc.name)) return true;
  uint64_t now = getMicrosSinceEpoch();
  uint64_t owed = computeOwedRent(
    sc.size, feeRent, sc.last_rent_us, now);
  if (owed == 0) return true;

  CesServer* server = gServer.load();
  if (!server) return false;
  minx::Hash pubkey{};
  std::memcpy(pubkey.data(), sc.program_pubkey.data(), 32);
  auto r = server->_l2DebitProgramAccountSync(
    pubkey, static_cast<int64_t>(owed));
  bool dead = !r.ok;

  if (dead) {
    // Dead. Delete and bump meta.
    std::error_code ec;
    std::filesystem::remove(cPath, ec);
    std::filesystem::remove(sPath, ec);
    // Best-effort rmdir of empty parents.
    {
      std::filesystem::path p = cPath.parent_path();
      std::filesystem::path base = dir;
      while (p != base) {
        std::error_code rmec;
        if (!std::filesystem::remove(p, rmec)) break;
        p = p.parent_path();
      }
    }
    {
      std::lock_guard lk(gStoreMetaMutex);
      adjustStoreMeta(dir, -1, -static_cast<int64_t>(sc.size));
    }
    notifyDeletion(sc.name);
    return false;
  }
  sc.last_rent_us = now;
  return true;
}

// ---------------------------------------------------------------------------
// Wire helpers (BE int readers/writers on byte vectors)
// ---------------------------------------------------------------------------

// All BE serialization goes through ces::Buffer (see ces/buffer.h).

// ---------------------------------------------------------------------------
// Common per-request state
// ---------------------------------------------------------------------------

// The signed-request loop lives in the CesPlex framework (cesPlexServe /
// CesPlexRequest, see cesplex/mux.h). ReqCtx aliases the framework
// request so the dispatchers below need no changes; the thin senders
// forward to its respond/error helpers. respond's `extraBody` streams a
// READ payload after the envelope; errorAndClose drops the channel for a
// body-bearing verb rejected before its trailing body was consumed (a
// loop there would desync the stream).

using ReqCtx = ces::CesPlexRequest;

// The CesPlex bus is host-generic (it knows only CesPlexHost). builtin:file
// is a CES core feature, so its host is always the CesServer — recover the
// concrete server for the ledger-facing calls below.
inline CesServer* reqServer(const std::shared_ptr<ReqCtx>& ctx) {
  return static_cast<CesServer*>(ctx->host);
}

inline void sendResponseAndLoop(std::shared_ptr<ReqCtx> ctx, uint8_t status,
                                ces::Bytes preamble,
                                ces::Bytes extraBody = {}) {
  ctx->respond(status, std::move(preamble), std::move(extraBody));
}
inline void sendErrorAndLoop(std::shared_ptr<ReqCtx> ctx, uint8_t status) {
  ctx->error(status);
}
inline void sendErrorAndClose(std::shared_ptr<ReqCtx> ctx, uint8_t status) {
  ctx->errorAndClose(status);
}

// Per-verb dispatch after signed envelope is verified and debited.
// Declared here; defined below verb-by-verb.
void dispatchCreate (std::shared_ptr<ReqCtx> ctx, ces::Bytes pre);
void dispatchStat   (std::shared_ptr<ReqCtx> ctx, ces::Bytes pre);
void dispatchAppend (std::shared_ptr<ReqCtx> ctx, ces::Bytes pre);
void dispatchResize (std::shared_ptr<ReqCtx> ctx, ces::Bytes pre);

// JIT rent GC — forward decl so dispatchers that grow total_bytes
// (CREATE, APPEND, RESIZE-grow) can call it below. Caller must hold
// gStoreMetaMutex.
uint64_t gcReclaim(const std::string& dir, int64_t feeRent,
                   uint64_t bytesNeeded);

// Cap-and-GC helper. Returns CES_OK if `addBytes` fits under `cap`
// (possibly after a debounced GC), CES_ERROR_STORE_FULL otherwise.
// Caller must hold gStoreMetaMutex. Does not bump total_bytes —
// caller commits after the op's disk work succeeds.
uint8_t checkCapAndMaybeGc(const std::string& dir,
                           uint64_t cap,
                           int64_t feeRent,
                           uint64_t addBytes);
void dispatchWrite  (std::shared_ptr<ReqCtx> ctx, ces::Bytes pre);
void dispatchRead   (std::shared_ptr<ReqCtx> ctx, ces::Bytes pre);
void dispatchDeposit(std::shared_ptr<ReqCtx> ctx, ces::Bytes pre);
void dispatchWithdraw(std::shared_ptr<ReqCtx> ctx, ces::Bytes pre);
void dispatchSetPrice(std::shared_ptr<ReqCtx> ctx, ces::Bytes pre);
void dispatchDelete (std::shared_ptr<ReqCtx> ctx, ces::Bytes pre);

class FileHandler : public CesPlexHandler {
public:
  void serve(std::shared_ptr<minx::RudpStream> stream,
             BoundChannelContext bound) override {
    CesServer* server = gServer.load();
    if (!server) {
      LOGWARNING << "builtin:file invoked with no bound CesServer";
      return;
    }
    CesPlexProtocol proto;
    // accepts() also gates "still bound?" — false on unbind stops the loop.
    proto.accepts = [](uint8_t verb) {
      return gServer.load() != nullptr &&
             (verb == kVerbStat || (verb >= kVerbCreate && verb <= kVerbResize));
    };
    proto.dispatch = [](std::shared_ptr<ReqCtx> ctx, ces::Bytes pre) {
      switch (ctx->verb) {
        case kVerbCreate:   dispatchCreate  (ctx, std::move(pre)); break;
        case kVerbWrite:    dispatchWrite   (ctx, std::move(pre)); break;
        case kVerbRead:     dispatchRead    (ctx, std::move(pre)); break;
        case kVerbStat:     dispatchStat    (ctx, std::move(pre)); break;
        case kVerbDeposit:  dispatchDeposit (ctx, std::move(pre)); break;
        case kVerbWithdraw: dispatchWithdraw(ctx, std::move(pre)); break;
        case kVerbSetPrice: dispatchSetPrice(ctx, std::move(pre)); break;
        case kVerbDelete:   dispatchDelete  (ctx, std::move(pre)); break;
        case kVerbAppend:   dispatchAppend  (ctx, std::move(pre)); break;
        case kVerbResize:   dispatchResize  (ctx, std::move(pre)); break;
        default:            ctx->error(CES_ERROR_BAD_INPUT); break;
      }
    };
    cesPlexServe(std::move(stream), std::move(bound), server,
                 std::move(proto));
  }
};

FileHandler gFileHandler;

// ---------------------------------------------------------------------------
// Dispatch: CREATE
//   preamble (after reqNonce):
//     u64 size, u64 price_per_kb, u64 initial_deposit,
//     u16 ct_len, ct, u16 name_len, name
// ---------------------------------------------------------------------------

// Extract zone ('h', 'f', or 'p') and the second-component offset +
// length from a name that has already passed validateCesFileName.
// Pre: name starts with /<zone>/<second>/... with zone exactly 1
// char. Returns zone char, and span of the second component.
void extractZoneAndNamespace(const std::string& name,
                             char& zone,
                             std::string& secondComponent) {
  zone = name[1];
  size_t start = 3;                // past "/x/"
  size_t end = name.find('/', start);
  if (end == std::string::npos) end = name.size();
  secondComponent = name.substr(start, end - start);
}

// Hex-decode 64 lowercase hex chars into a 32-byte Hash. Pre:
// already validated as 64 lowercase-hex (via validateCesFileName).
void hexDecodePubkey32(const std::string& hex64, minx::Hash& out) {
  auto nib = [](char c) -> uint8_t {
    if (c >= '0' && c <= '9') return c - '0';
    return c - 'a' + 10;
  };
  for (size_t i = 0; i < 32; ++i) {
    out[i] = static_cast<uint8_t>(
      (nib(hex64[i * 2]) << 4) | nib(hex64[i * 2 + 1]));
  }
}

// Perform the zone-ownership check for a CREATE. For /h/ and /p/
// this returns synchronously via `onDone`. For /f/ it hops to the
// ledger strand to check asset ownership and calls `onDone` from
// cbExecutor.
void checkZoneOwnership(
    CesServer* server,
    const std::string& name,
    const std::array<uint8_t, 32>& signerKey,
    boost::asio::any_io_executor cbExecutor,
    std::function<void(uint8_t rc)> onDone) {
  char zone;
  std::string second;
  extractZoneAndNamespace(name, zone, second);
  if (zone == 'p') {
    onDone(CES_OK);
    return;
  }
  if (zone == 's') {
    // Server-deployed zone: only the server's own public key may
    // create (or otherwise mutate) files here. The operator signs
    // with their server private key — same one in server.toml.
    const auto& srvPk = server->_serverKeyPair().getPublicKeyAsHash();
    if (std::memcmp(srvPk.data(), signerKey.data(), 32) != 0) {
      onDone(CES_ERROR_NOT_OWNER);
    } else {
      onDone(CES_OK);
    }
    return;
  }
  if (zone == 'h') {
    minx::Hash pathPk;
    hexDecodePubkey32(second, pathPk);
    if (std::memcmp(pathPk.data(), signerKey.data(), 32) != 0) {
      onDone(CES_ERROR_NOT_OWNER);
    } else {
      onDone(CES_OK);
    }
    return;
  }
  // zone == 'f': async asset ownership check.
  std::string canonical = "/f/" + second;
  minx::Hash assetId = ces::sha256(
    reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
  ces::PublicKey signer(signerKey);
  server->_l2CheckAssetOwner(
    assetId, signer,
    [onDone](bool isOwner) {
      onDone(isOwner ? CES_OK : CES_ERROR_NOT_OWNER);
    },
    cbExecutor);
}

void dispatchCreate(std::shared_ptr<ReqCtx> ctx, ces::Bytes pre) {
  ces::Buffer buf(std::move(pre));
  uint64_t size = 0, pricePerKb = 0, initialDeposit = 0;
  std::string contentType, name;
  try {
    size = buf.get<uint64_t>();
    pricePerKb = buf.get<uint64_t>();
    initialDeposit = buf.get<uint64_t>();
    uint16_t ctLen = buf.get<uint16_t>();
    if (ctLen > kMaxContentTypeLen) {
      sendErrorAndLoop(ctx, CES_ERROR_BAD_INPUT); return;
    }
    contentType = buf.getBytes<std::string>(ctLen);
    uint16_t nameLen = buf.get<uint16_t>();
    if (nameLen == 0 || nameLen > kMaxNameLen) {
      sendErrorAndLoop(ctx, CES_ERROR_BAD_NAME); return;
    }
    name = buf.getBytes<std::string>(nameLen);
  } catch (const std::out_of_range&) {
    sendErrorAndLoop(ctx, CES_ERROR_BAD_INPUT); return;
  }

  if (size == 0 || size > kMaxFileSize) {
    sendErrorAndLoop(ctx, CES_ERROR_BAD_INPUT); return;
  }
  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) { sendErrorAndLoop(ctx, rc); return; }

  // Zone-ownership gate. For /h/ this resolves sync; for /f/ it
  // hops to the ledger strand and back. After it resolves, we
  // finish the CREATE under `finishCreate` below.
  auto finishCreate =
    [ctx, size, pricePerKb, initialDeposit, contentType, name]
    (uint8_t zoneRc) mutable {
    if (zoneRc != CES_OK) { sendErrorAndLoop(ctx, zoneRc); return; }

    const auto& cfg = reqServer(ctx)->_config();
    uint8_t rc = checkPathConflict(
      cfg.cesFileStoreDir, name, /*createMode=*/true);
    if (rc != CES_OK) { sendErrorAndLoop(ctx, rc); return; }

    const bool serverZone = isServerZone(name);

    if (!serverZone) {
      std::lock_guard lk(gStoreMetaMutex);
      uint8_t capRc = checkCapAndMaybeGc(
        cfg.cesFileStoreDir, cfg.cesFileStoreMaxBytes,
        cfg.feeFileRent, size);
      if (capRc != CES_OK) { sendErrorAndLoop(ctx, capRc); return; }
    }

    // Anti-grief upfront rent: the debounce window's worth of rent
    // on the reserved bytes is BURNED at CREATE — not a runtime
    // credit. Minimum deposit = upfront so the file starts with at
    // least a zero balance (never negative).
    uint64_t upfrontBurn = 0;
    if (!serverZone) {
      upfrontBurn = computeOwedRent(
        size, cfg.feeFileRent, 0, kGcDebounceUs);
      if (initialDeposit < upfrontBurn) {
        sendErrorAndLoop(ctx, CES_ERROR_INSUFFICIENT_BALANCE); return;
      }
    } else {
      // /s/ is unmetered; file_balance is decorative. Force the
      // deposit to 0 so the signer isn't billed for a field the
      // server never consults.
      initialDeposit = 0;
    }

    int64_t signerDebit =
      static_cast<int64_t>(initialDeposit) +
      static_cast<int64_t>(cfg.feeQuery);

    const ces::PublicKey& signer = ctx->bound.boundPubkey;

    auto after =
      [ctx, size, pricePerKb, initialDeposit, upfrontBurn,
       contentType, name]
      (uint8_t rc, bool duplicate) mutable {
        if (rc != CES_OK) { sendErrorAndLoop(ctx, rc); return; }
        // Concurrent duplicate CREATE (two identical envelopes racing past the
        // existence precheck): re-running would truncate the file and mint a
        // second program account. Replay the same response from the captured
        // deposit, touching neither disk nor ledger (the sidecar may not exist
        // yet — the first envelope's side effect is still in flight).
        if (duplicate) {
          uint64_t programAccountInitial = (initialDeposit > upfrontBurn)
            ? (initialDeposit - upfrontBurn) : 0;
          const auto& cfg = reqServer(ctx)->_config();
          ces::Bytes pre;
          ces::Buffer::put<uint64_t>(pre, programAccountInitial);
          ces::Buffer::put<uint64_t>(pre, static_cast<uint64_t>(cfg.feeQuery) +
            static_cast<uint64_t>(initialDeposit));
          sendResponseAndLoop(ctx, CES_OK, std::move(pre));
          return;
        }
        const auto& cfg = reqServer(ctx)->_config();
        auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
        auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);

        // mkdir -p parent
        std::error_code ec;
        std::filesystem::create_directories(cPath.parent_path(), ec);
        if (ec) { sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return; }

        // Sparse-allocate the content file at `size`.
        {
          std::ofstream f(cPath, std::ios::binary | std::ios::trunc);
          if (!f) { sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return; }
        }
        std::filesystem::resize_file(cPath, size, ec);
        if (ec) { sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return; }

        // The seed deposit minus the upfront-burn lands in the
        // file's program account (a fresh ledger Account allocated
        // here). Allocate via _l2CreateProgramAccount, which mints a
        // fresh ed25519 keypair and creates the account on logicStrand_.
        uint64_t programAccountInitial = (initialDeposit > upfrontBurn)
          ? (initialDeposit - upfrontBurn) : 0;

        reqServer(ctx)->_l2CreateProgramAccount(
          static_cast<int64_t>(programAccountInitial),
          [ctx, size, pricePerKb, initialDeposit, programAccountInitial,
           contentType, name, cPath, sPath]
          (minx::Hash programPubkey, minx::Hash programPrivkey) mutable {
            std::error_code ec;
            Sidecar s{};
            s.version = kSidecarVersion;
            s.name = name;
            std::memcpy(s.owner_pubkey.data(),
                        ctx->bound.boundPubkey.getHash().data(), 32);
            std::memcpy(s.program_pubkey.data(),
                        programPubkey.data(), 32);
            std::memcpy(s.program_privkey.data(),
                        programPrivkey.data(), 32);
            s.price_per_kb = pricePerKb;
            s.size = size;
            s.content_type = contentType;
            s.created_us = getMicrosSinceEpoch();
            s.modified_us = s.created_us;
            s.last_rent_us = s.created_us;
            if (!writeSidecar(sPath, s)) {
              std::filesystem::remove(cPath, ec);
              sendErrorAndLoop(ctx, CES_ERROR_INTERNAL);
              return;
            }

            // Bump store meta (mutex). /s/ files live outside the
            // cap, so skip the meta update — reconcile would
            // subtract them back on next startup anyway.
            const auto& cfg = reqServer(ctx)->_config();
            if (!isServerZone(name)) {
              std::lock_guard lk(gStoreMetaMutex);
              adjustStoreMeta(cfg.cesFileStoreDir, +1,
                              static_cast<int64_t>(size));
            }

            // Response preamble: [u64 file_balance][u64 cost_debited]
            // file_balance now mirrors the program account.
            ces::Bytes pre;
            ces::Buffer::put<uint64_t>(pre, programAccountInitial);
            ces::Buffer::put<uint64_t>(pre, static_cast<uint64_t>(
              static_cast<int64_t>(cfg.feeQuery) +
              static_cast<int64_t>(initialDeposit)));
            sendResponseAndLoop(ctx, CES_OK, std::move(pre));
          },
          ctx->stream->get_executor());
      };

    reqServer(ctx)->_l2ValidateDedupAndDebit(
      signer, signerDebit, ctx->reqNonce, getMicrosSinceEpoch(), ctx->reqSigHash,
      std::move(after), ctx->stream->get_executor());
  };  // end finishCreate lambda

  // Kick off the zone check. /h/ and /p/ resolve synchronously;
  // /f/ hops to logicStrand_ to verify asset ownership.
  checkZoneOwnership(
    reqServer(ctx), name, ctx->bound.boundPubkey.getHash(),
    ctx->stream->get_executor(), std::move(finishCreate));
}

// ---------------------------------------------------------------------------
// Dispatch: WRITE
//   preamble (after reqNonce):
//     u64 offset, u32 length, u8[32] content_hash,
//     u16 name_len, name
//   body: `length` bytes
// ---------------------------------------------------------------------------

struct WriteBodyState : std::enable_shared_from_this<WriteBodyState> {
  std::shared_ptr<ReqCtx> ctx;
  ces::Bytes body;
  uint64_t offset = 0;
  uint32_t length = 0;
  std::array<uint8_t, 32> contentHash{};
  std::string name;
};

void dispatchWrite(std::shared_ptr<ReqCtx> ctx, ces::Bytes pre) {
  // WRITE pre-body rejects must close the channel (not loop) because
  // the client has already started streaming `length` body bytes;
  // looping would let those bytes land as phantom next-verbs on the
  // wire. The body-phase (after async_read of `state->body`) can use
  // sendErrorAndLoop because the body was consumed.
  ces::Buffer buf(std::move(pre));
  uint64_t offset = 0;
  uint32_t length = 0;
  std::array<uint8_t, 32> contentHash{};
  std::string name;
  try {
    offset = buf.get<uint64_t>();
    length = buf.get<uint32_t>();
    contentHash = buf.get<std::array<uint8_t, 32>>();
    uint16_t nameLen = buf.get<uint16_t>();
    if (nameLen == 0 || nameLen > kMaxNameLen) {
      sendErrorAndClose(ctx, CES_ERROR_BAD_NAME); return;
    }
    name = buf.getBytes<std::string>(nameLen);
  } catch (const std::out_of_range&) {
    sendErrorAndClose(ctx, CES_ERROR_BAD_INPUT); return;
  }

  if (length == 0 || length > kMaxWriteLen) {
    sendErrorAndClose(ctx, CES_ERROR_BAD_INPUT); return;
  }
  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) { sendErrorAndClose(ctx, rc); return; }

  const auto& cfg = reqServer(ctx)->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) {
    sendErrorAndClose(ctx, CES_ERROR_FILE_NOT_FOUND); return;
  }
  if (!chargeRentOrDelete(cPath, sPath, sc, cfg.feeFileRent,
                          cfg.cesFileStoreDir)) {
    sendErrorAndClose(ctx, CES_ERROR_FILE_NOT_FOUND); return;
  }
  if (std::memcmp(sc.owner_pubkey.data(), ctx->bound.boundPubkey.getHash().data(), 32) != 0) {
    sendErrorAndClose(ctx, CES_ERROR_NOT_OWNER); return;
  }
  if (offset > sc.size || offset + uint64_t(length) > sc.size) {
    sendErrorAndClose(ctx, CES_ERROR_BAD_INPUT); return;
  }
  // /s/ is unmetered — operator donates the write bandwidth.
  uint64_t writeCost = isServerZone(name)
    ? 0 : kbCeil(length) * uint64_t(cfg.feeFileWrite);
  if (writeCost > 0 &&
      readProgramAccountBalance(reqServer(ctx), sc) < writeCost) {
    sendErrorAndClose(ctx, CES_ERROR_INSUFFICIENT_BALANCE); return;
  }
  // Persist the rent-advanced sidecar before the body phase so that
  // if anything downstream touches the file, it sees up-to-date rent.
  writeSidecar(sPath, sc);

  const ces::PublicKey& signer = ctx->bound.boundPubkey;

  auto state = std::make_shared<WriteBodyState>();
  state->ctx = ctx;
  state->offset = offset;
  state->length = length;
  state->contentHash = contentHash;
  state->name = name;

  auto after = [ctx, state, writeCost, cPath, sPath](uint8_t rc, bool duplicate) {
    // Debit failed → body is still in flight. Close the channel.
    if (rc != CES_OK) { sendErrorAndClose(ctx, rc); return; }
    // Stream the body even on a duplicate: the client is already sending
    // `length` bytes; not consuming them desyncs the wire.
    state->body.resize(state->length);
    boost::asio::async_read(
      *ctx->stream, boost::asio::buffer(state->body),
      [ctx, state, writeCost, cPath, sPath, duplicate]
      (const boost::system::error_code& ec, std::size_t) {
        if (ec) return; // stream dead
        minx::Hash got = ces::sha256(
          state->body.data(), state->body.size());
        if (std::memcmp(got.data(), state->contentHash.data(), 32) != 0) {
          sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
        }
        Sidecar sc{};
        if (!readSidecar(sPath, sc)) {
          sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
        }
        // Duplicate: the bytes were already written and writeCost charged. Skip
        // the disk write + debit; re-read the balance for the reply.
        if (duplicate) {
          ces::Bytes pre;
          ces::Buffer::put<uint64_t>(
            pre, readProgramAccountBalance(reqServer(ctx), sc));
          sendResponseAndLoop(ctx, CES_OK, std::move(pre));
          return;
        }
        FILE* fp = std::fopen(cPath.string().c_str(), "rb+");
        if (!fp) { sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return; }
        if (std::fseek(fp, static_cast<long>(state->offset),
                       SEEK_SET) != 0) {
          std::fclose(fp);
          sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
        }
        size_t wrote = std::fwrite(
          state->body.data(), 1, state->body.size(), fp);
        std::fflush(fp);
        std::fclose(fp);
        if (wrote != state->body.size()) {
          sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
        }
        uint64_t newBal = 0;
        if (writeCost > 0) {
          auto debit = debitProgramAccount(
            reqServer(ctx), sc, writeCost);
          if (!debit.ok) {
            sendErrorAndLoop(ctx, CES_ERROR_INSUFFICIENT_BALANCE);
            return;
          }
          newBal = debit.newBalance;
        } else {
          newBal = readProgramAccountBalance(reqServer(ctx), sc);
        }
        sc.modified_us = getMicrosSinceEpoch();
        // Content changed → invalidate the lazily-cached program hash.
        sc.program_hash.fill(0);
        if (!writeSidecar(sPath, sc)) {
          sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
        }
        ces::Bytes pre;
        ces::Buffer::put<uint64_t>(pre, newBal);
        sendResponseAndLoop(ctx, CES_OK, std::move(pre));
      });
  };

  reqServer(ctx)->_l2ValidateDedupAndDebit(
    signer, static_cast<int64_t>(cfg.feeQuery),
    ctx->reqNonce, getMicrosSinceEpoch(), ctx->reqSigHash,
    std::move(after), ctx->stream->get_executor());
}

// ---------------------------------------------------------------------------
// Dispatch: READ
//   preamble (after reqNonce):
//     u64 offset, u32 length, u16 name_len, name
// ---------------------------------------------------------------------------

void dispatchRead(std::shared_ptr<ReqCtx> ctx, ces::Bytes pre) {
  ces::Buffer buf(std::move(pre));
  uint64_t offset = 0;
  uint32_t length = 0;
  std::string name;
  try {
    offset = buf.get<uint64_t>();
    length = buf.get<uint32_t>();
    uint16_t nameLen = buf.get<uint16_t>();
    if (nameLen == 0 || nameLen > kMaxNameLen) {
      sendErrorAndLoop(ctx, CES_ERROR_BAD_NAME); return;
    }
    name = buf.getBytes<std::string>(nameLen);
  } catch (const std::out_of_range&) {
    sendErrorAndLoop(ctx, CES_ERROR_BAD_INPUT); return;
  }

  if (length == 0 || length > kMaxReadLen) {
    sendErrorAndLoop(ctx, CES_ERROR_BAD_INPUT); return;
  }
  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) { sendErrorAndLoop(ctx, rc); return; }

  const auto& cfg = reqServer(ctx)->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) {
    sendErrorAndLoop(ctx, CES_ERROR_FILE_NOT_FOUND); return;
  }
  if (!chargeRentOrDelete(cPath, sPath, sc, cfg.feeFileRent,
                          cfg.cesFileStoreDir)) {
    sendErrorAndLoop(ctx, CES_ERROR_FILE_NOT_FOUND); return;
  }
  writeSidecar(sPath, sc);
  if (offset > sc.size || offset + uint64_t(length) > sc.size) {
    sendErrorAndLoop(ctx, CES_ERROR_BAD_INPUT); return;
  }
  bool isOwner = (std::memcmp(sc.owner_pubkey.data(),
                              ctx->bound.boundPubkey.getHash().data(), 32) == 0);
  // Three-cost model for READ:
  //   network + SSD read = length * feeFileRead   (burned, covers
  //                        server's I/O work — charged to everyone
  //                        including owner, since the server does
  //                        the work regardless)
  //   owner price        = ceil(len/1024) * price_per_kb (→ file_balance;
  //                        waived when owner reads own file)
  //   op fee             = feeQuery   (burned, replay/dedup gate)
  // /s/ is unmetered for readers: server operator donates I/O, and
  // the owner field is decorative so price_per_kb is ignored.
  const bool serverZone = isServerZone(name);
  uint64_t readIoCost = serverZone
    ? 0 : kbCeil(length) * uint64_t(cfg.feeFileRead);
  uint64_t readPrice = 0;
  if (!serverZone && !isOwner) {
    readPrice = kbCeil(length) * sc.price_per_kb;
  }
  int64_t signerDebit = static_cast<int64_t>(cfg.feeQuery) +
                        static_cast<int64_t>(readIoCost) +
                        static_cast<int64_t>(readPrice);

  const ces::PublicKey& signer = ctx->bound.boundPubkey;

  auto after = [ctx, offset, length, name, readPrice, isOwner]
    (uint8_t rc, bool duplicate) mutable {
      if (rc != CES_OK) { sendErrorAndLoop(ctx, rc); return; }
      const auto& cfg = reqServer(ctx)->_config();
      auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
      auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
      // Read range from disk.
      std::ifstream f(cPath, std::ios::binary);
      if (!f) { sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return; }
      f.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
      ces::Bytes data(length);
      f.read(reinterpret_cast<char*>(data.data()), length);
      if (f.gcount() != static_cast<std::streamsize>(length)) {
        sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
      }
      // Credit the file's program account with readPrice (non-owner). Skip on a
      // duplicate: re-crediting would mint (the reader wasn't re-charged). The
      // file is unchanged, so the re-read data below is still correct.
      if (!isOwner && readPrice > 0 && !duplicate) {
        Sidecar sc{};
        if (readSidecar(sPath, sc)) {
          creditProgramAccount(reqServer(ctx), sc, readPrice);
          sc.modified_us = getMicrosSinceEpoch();
          writeSidecar(sPath, sc);
        }
      }
      // Response preamble: [u64 length][u8[32] sha256_of_range]
      minx::Hash h = ces::sha256(data.data(), data.size());
      ces::Bytes pre;
      ces::Buffer::put<uint64_t>(pre, uint64_t(length));
      pre.insert(pre.end(), h.begin(), h.end());
      sendResponseAndLoop(ctx, CES_OK, std::move(pre), std::move(data));
    };

  reqServer(ctx)->_l2ValidateDedupAndDebit(
    signer, signerDebit, ctx->reqNonce, getMicrosSinceEpoch(), ctx->reqSigHash,
    std::move(after), ctx->stream->get_executor());
}

// ---------------------------------------------------------------------------
// Dispatch: DEPOSIT
//   preamble (after reqNonce):
//     u64 amount, u16 name_len, name
// ---------------------------------------------------------------------------

void dispatchDeposit(std::shared_ptr<ReqCtx> ctx, ces::Bytes pre) {
  ces::Buffer buf(std::move(pre));
  uint64_t amount = 0;
  std::string name;
  try {
    amount = buf.get<uint64_t>();
    uint16_t nameLen = buf.get<uint16_t>();
    if (nameLen == 0 || nameLen > kMaxNameLen) {
      sendErrorAndLoop(ctx, CES_ERROR_BAD_NAME); return;
    }
    name = buf.getBytes<std::string>(nameLen);
  } catch (const std::out_of_range&) {
    sendErrorAndLoop(ctx, CES_ERROR_BAD_INPUT); return;
  }

  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) { sendErrorAndLoop(ctx, rc); return; }
  const auto& cfg = reqServer(ctx)->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) {
    sendErrorAndLoop(ctx, CES_ERROR_FILE_NOT_FOUND); return;
  }

  int64_t signerDebit = static_cast<int64_t>(amount) +
                        static_cast<int64_t>(cfg.feeQuery);

  const ces::PublicKey& signer = ctx->bound.boundPubkey;

  auto after = [ctx, amount, name](uint8_t rc, bool duplicate) {
    if (rc != CES_OK) { sendErrorAndLoop(ctx, rc); return; }
    const auto& cfg = reqServer(ctx)->_config();
    auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
    Sidecar sc{};
    if (!readSidecar(sPath, sc)) {
      sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
    }
    // Duplicate: re-crediting would mint (the signer wasn't re-debited). Skip;
    // the balance re-read below reflects the first deposit.
    if (!duplicate) {
      creditProgramAccount(reqServer(ctx), sc, amount);
      sc.modified_us = getMicrosSinceEpoch();
      if (!writeSidecar(sPath, sc)) {
        sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
      }
    }
    uint64_t newBal = readProgramAccountBalance(reqServer(ctx), sc);
    ces::Bytes pre;
    ces::Buffer::put<uint64_t>(pre, newBal);
    sendResponseAndLoop(ctx, CES_OK, std::move(pre));
  };

  reqServer(ctx)->_l2ValidateDedupAndDebit(
    signer, signerDebit, ctx->reqNonce, getMicrosSinceEpoch(), ctx->reqSigHash,
    std::move(after), ctx->stream->get_executor());
}

// ---------------------------------------------------------------------------
// Dispatch: WITHDRAW (owner only)
//   preamble (after reqNonce):
//     u64 amount, u16 name_len, name
// ---------------------------------------------------------------------------

void dispatchWithdraw(std::shared_ptr<ReqCtx> ctx, ces::Bytes pre) {
  ces::Buffer buf(std::move(pre));
  uint64_t amount = 0;
  std::string name;
  try {
    amount = buf.get<uint64_t>();
    uint16_t nameLen = buf.get<uint16_t>();
    if (nameLen == 0 || nameLen > kMaxNameLen) {
      sendErrorAndLoop(ctx, CES_ERROR_BAD_NAME); return;
    }
    name = buf.getBytes<std::string>(nameLen);
  } catch (const std::out_of_range&) {
    sendErrorAndLoop(ctx, CES_ERROR_BAD_INPUT); return;
  }

  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) { sendErrorAndLoop(ctx, rc); return; }
  const auto& cfg = reqServer(ctx)->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) {
    sendErrorAndLoop(ctx, CES_ERROR_FILE_NOT_FOUND); return;
  }
  if (!chargeRentOrDelete(cPath, sPath, sc, cfg.feeFileRent,
                          cfg.cesFileStoreDir)) {
    sendErrorAndLoop(ctx, CES_ERROR_FILE_NOT_FOUND); return;
  }
  writeSidecar(sPath, sc);
  if (std::memcmp(sc.owner_pubkey.data(), ctx->bound.boundPubkey.getHash().data(), 32) != 0) {
    sendErrorAndLoop(ctx, CES_ERROR_NOT_OWNER); return;
  }
  if (readProgramAccountBalance(reqServer(ctx), sc) < amount) {
    sendErrorAndLoop(ctx, CES_ERROR_INSUFFICIENT_BALANCE); return;
  }

  const ces::PublicKey& signer = ctx->bound.boundPubkey;

  auto after = [ctx, amount, name](uint8_t rc, bool duplicate) {
    if (rc != CES_OK) { sendErrorAndLoop(ctx, rc); return; }
    const auto& cfg = reqServer(ctx)->_config();
    auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
    Sidecar sc{};
    if (!readSidecar(sPath, sc)) {
      sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
    }
    // Duplicate: re-running would double-pay the owner and drain the program
    // account twice. Replay OK with the current balance, no re-debit/re-credit.
    if (duplicate) {
      uint64_t bal = readProgramAccountBalance(reqServer(ctx), sc);
      ces::Bytes pre;
      ces::Buffer::put<uint64_t>(pre, bal);
      sendResponseAndLoop(ctx, CES_OK, std::move(pre));
      return;
    }
    auto debit = debitProgramAccount(reqServer(ctx), sc, amount);
    if (!debit.ok) {
      sendErrorAndLoop(ctx, CES_ERROR_INSUFFICIENT_BALANCE); return;
    }
    sc.modified_us = getMicrosSinceEpoch();
    if (!writeSidecar(sPath, sc)) {
      sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
    }
    // Credit owner's account.
    ces::PublicKey ownerPk(sc.owner_pubkey);
    reqServer(ctx)->_l2CreditAccount(
      ownerPk, static_cast<int64_t>(amount),
      [ctx, balance = debit.newBalance]() {
        ces::Bytes pre;
        ces::Buffer::put<uint64_t>(pre, balance);
        sendResponseAndLoop(ctx, CES_OK, std::move(pre));
      },
      ctx->stream->get_executor());
  };

  reqServer(ctx)->_l2ValidateDedupAndDebit(
    signer, static_cast<int64_t>(cfg.feeQuery),
    ctx->reqNonce, getMicrosSinceEpoch(), ctx->reqSigHash,
    std::move(after), ctx->stream->get_executor());
}

// ---------------------------------------------------------------------------
// Dispatch: SET_PRICE (owner only)
//   preamble (after reqNonce):
//     u64 price_per_kb, u16 name_len, name
// ---------------------------------------------------------------------------

void dispatchSetPrice(std::shared_ptr<ReqCtx> ctx, ces::Bytes pre) {
  ces::Buffer buf(std::move(pre));
  uint64_t newPrice = 0;
  std::string name;
  try {
    newPrice = buf.get<uint64_t>();
    uint16_t nameLen = buf.get<uint16_t>();
    if (nameLen == 0 || nameLen > kMaxNameLen) {
      sendErrorAndLoop(ctx, CES_ERROR_BAD_NAME); return;
    }
    name = buf.getBytes<std::string>(nameLen);
  } catch (const std::out_of_range&) {
    sendErrorAndLoop(ctx, CES_ERROR_BAD_INPUT); return;
  }

  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) { sendErrorAndLoop(ctx, rc); return; }
  const auto& cfg = reqServer(ctx)->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) {
    sendErrorAndLoop(ctx, CES_ERROR_FILE_NOT_FOUND); return;
  }
  if (!chargeRentOrDelete(cPath, sPath, sc, cfg.feeFileRent,
                          cfg.cesFileStoreDir)) {
    sendErrorAndLoop(ctx, CES_ERROR_FILE_NOT_FOUND); return;
  }
  writeSidecar(sPath, sc);
  if (std::memcmp(sc.owner_pubkey.data(), ctx->bound.boundPubkey.getHash().data(), 32) != 0) {
    sendErrorAndLoop(ctx, CES_ERROR_NOT_OWNER); return;
  }

  const ces::PublicKey& signer = ctx->bound.boundPubkey;

  auto after = [ctx, newPrice, name](uint8_t rc, bool duplicate) {
    if (rc != CES_OK) { sendErrorAndLoop(ctx, rc); return; }
    const auto& cfg = reqServer(ctx)->_config();
    auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
    Sidecar sc{};
    if (!readSidecar(sPath, sc)) {
      sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
    }
    // Duplicate: the price was already set; skip the re-write + mtime bump. The
    // read-back below reflects the first set.
    if (!duplicate) {
      sc.price_per_kb = newPrice;
      sc.modified_us = getMicrosSinceEpoch();
      if (!writeSidecar(sPath, sc)) {
        sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
      }
    }
    ces::Bytes pre;
    ces::Buffer::put<uint64_t>(pre, sc.price_per_kb);
    sendResponseAndLoop(ctx, CES_OK, std::move(pre));
  };

  reqServer(ctx)->_l2ValidateDedupAndDebit(
    signer, static_cast<int64_t>(cfg.feeQuery),
    ctx->reqNonce, getMicrosSinceEpoch(), ctx->reqSigHash,
    std::move(after), ctx->stream->get_executor());
}

// ---------------------------------------------------------------------------
// Dispatch: STAT
//   preamble (after reqNonce): u16 name_len, name
//
// Like every verb, STAT is on a bound channel and verifies through the
// same envelope; the channel signer pays feeQuery. No unsigned fast path.
// ---------------------------------------------------------------------------

void dispatchStat(std::shared_ptr<ReqCtx> ctx, ces::Bytes pre) {
  ces::Buffer buf(std::move(pre));
  std::string name;
  try {
    uint16_t nameLen = buf.get<uint16_t>();
    if (nameLen == 0 || nameLen > kMaxNameLen) {
      sendErrorAndLoop(ctx, CES_ERROR_BAD_NAME); return;
    }
    name = buf.getBytes<std::string>(nameLen);
  } catch (const std::out_of_range&) {
    sendErrorAndLoop(ctx, CES_ERROR_BAD_NAME); return;
  }

  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) { sendErrorAndLoop(ctx, rc); return; }

  const auto& cfg = reqServer(ctx)->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) {
    sendErrorAndLoop(ctx, CES_ERROR_FILE_NOT_FOUND); return;
  }
  if (!chargeRentOrDelete(cPath, sPath, sc, cfg.feeFileRent,
                          cfg.cesFileStoreDir)) {
    sendErrorAndLoop(ctx, CES_ERROR_FILE_NOT_FOUND); return;
  }
  writeSidecar(sPath, sc);

  const ces::PublicKey& signer = ctx->bound.boundPubkey;

  auto after = [ctx, sc](uint8_t rc, bool /*duplicate*/) {
    if (rc != CES_OK) { sendErrorAndLoop(ctx, rc); return; }
    // Read-only (the rent-roll ran before dedup); a duplicate just re-reads.
    // STAT response preamble:
    //   [u8[32] owner_pubkey][u64 file_balance][u64 price_per_kb]
    //   [u64 size][u16 ct_len][ct][u64 created_us][u64 modified_us]
    // file_balance is now the file's program-account balance.
    uint64_t fileBalance = readProgramAccountBalance(reqServer(ctx), sc);
    ces::Bytes resp;
    resp.insert(resp.end(),
                sc.owner_pubkey.begin(), sc.owner_pubkey.end());
    ces::Buffer::put<uint64_t>(resp, fileBalance);
    ces::Buffer::put<uint64_t>(resp, sc.price_per_kb);
    ces::Buffer::put<uint64_t>(resp, sc.size);
    ces::Buffer::put<uint16_t>(resp, static_cast<uint16_t>(sc.content_type.size()));
    resp.insert(resp.end(),
                sc.content_type.begin(), sc.content_type.end());
    ces::Buffer::put<uint64_t>(resp, sc.created_us);
    ces::Buffer::put<uint64_t>(resp, sc.modified_us);
    sendResponseAndLoop(ctx, CES_OK, std::move(resp));
  };

  reqServer(ctx)->_l2ValidateDedupAndDebit(
    signer, static_cast<int64_t>(cfg.feeQuery),
    ctx->reqNonce, getMicrosSinceEpoch(), ctx->reqSigHash,
    std::move(after), ctx->stream->get_executor());
}

// ---------------------------------------------------------------------------
// Dispatch: DELETE (owner only)
//   preamble (after reqNonce):
//     u16 name_len, name
// ---------------------------------------------------------------------------

void dispatchDelete(std::shared_ptr<ReqCtx> ctx, ces::Bytes pre) {
  ces::Buffer buf(std::move(pre));
  std::string name;
  try {
    uint16_t nameLen = buf.get<uint16_t>();
    if (nameLen == 0 || nameLen > kMaxNameLen) {
      sendErrorAndLoop(ctx, CES_ERROR_BAD_NAME); return;
    }
    name = buf.getBytes<std::string>(nameLen);
  } catch (const std::out_of_range&) {
    sendErrorAndLoop(ctx, CES_ERROR_BAD_INPUT); return;
  }

  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) { sendErrorAndLoop(ctx, rc); return; }
  const auto& cfg = reqServer(ctx)->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) {
    sendErrorAndLoop(ctx, CES_ERROR_FILE_NOT_FOUND); return;
  }
  if (!chargeRentOrDelete(cPath, sPath, sc, cfg.feeFileRent,
                          cfg.cesFileStoreDir)) {
    sendErrorAndLoop(ctx, CES_ERROR_FILE_NOT_FOUND); return;
  }
  writeSidecar(sPath, sc);
  if (std::memcmp(sc.owner_pubkey.data(), ctx->bound.boundPubkey.getHash().data(), 32) != 0) {
    sendErrorAndLoop(ctx, CES_ERROR_NOT_OWNER); return;
  }

  const ces::PublicKey& signer = ctx->bound.boundPubkey;

  auto after = [ctx, name, cPath, sPath, scSaved = sc](uint8_t rc,
                                                       bool duplicate) mutable {
    if (rc != CES_OK) { sendErrorAndLoop(ctx, rc); return; }
    // Duplicate: the delete + refund already committed. Replay OK with refund 0
    // (re-refunding would mint; the sidecar is likely already gone).
    if (duplicate) {
      ces::Bytes pre;
      ces::Buffer::put<uint64_t>(pre, uint64_t(0));
      sendResponseAndLoop(ctx, CES_OK, std::move(pre));
      return;
    }
    const auto& cfg = reqServer(ctx)->_config();
    // Re-read sidecar (race-free-ish: we're the only writer for this
    // op in practice; v1 accepts the dice roll).
    Sidecar sc{};
    if (!readSidecar(sPath, sc)) {
      sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
    }
    // Refund = remaining program account balance, drained
    // atomically. The account row stays (zero-balance accounts are
    // collected by daily maintenance later), but every credit is
    // moved out before the file goes away.
    uint64_t refund = readProgramAccountBalance(reqServer(ctx), sc);
    if (refund > 0) {
      auto debit = debitProgramAccount(reqServer(ctx), sc, refund);
      if (!debit.ok) refund = 0;
    }
    uint64_t size = sc.size;
    // Delete files first, then update meta, then credit owner. /s/
    // lives outside the cap so no meta update.
    std::error_code ec;
    std::filesystem::remove(cPath, ec);
    std::filesystem::remove(sPath, ec);
    if (!isServerZone(name)) {
      std::lock_guard lk(gStoreMetaMutex);
      adjustStoreMeta(cfg.cesFileStoreDir, -1, -static_cast<int64_t>(size));
    }
    // Best-effort rmdir of empty parents up to cesFileStoreDir.
    {
      std::filesystem::path p = cPath.parent_path();
      std::filesystem::path base = cfg.cesFileStoreDir;
      while (p != base) {
        std::error_code rmec;
        if (!std::filesystem::remove(p, rmec)) break;
        p = p.parent_path();
      }
    }
    ces::PublicKey ownerPk(scSaved.owner_pubkey);
    notifyDeletion(name);
    reqServer(ctx)->_l2CreditAccount(
      ownerPk, static_cast<int64_t>(refund),
      [ctx, refund]() {
        ces::Bytes pre;
        ces::Buffer::put<uint64_t>(pre, refund);
        sendResponseAndLoop(ctx, CES_OK, std::move(pre));
      },
      ctx->stream->get_executor());
  };

  reqServer(ctx)->_l2ValidateDedupAndDebit(
    signer, static_cast<int64_t>(cfg.feeQuery),
    ctx->reqNonce, getMicrosSinceEpoch(), ctx->reqSigHash,
    std::move(after), ctx->stream->get_executor());
}

// ---------------------------------------------------------------------------
// Dispatch: APPEND (owner only) — extend-write `length` bytes past
// current end. Like WRITE, but grows size, so it charges feeFileWrite
// AND hits the store-wide cap (with JIT GC fallback).
//   preamble (after reqNonce):
//     u32 length, u8[32] content_hash, u16 name_len, name
//   body: `length` bytes
// ---------------------------------------------------------------------------

struct AppendBodyState : std::enable_shared_from_this<AppendBodyState> {
  std::shared_ptr<ReqCtx> ctx;
  ces::Bytes body;
  uint32_t length = 0;
  uint64_t oldSize = 0;
  std::array<uint8_t, 32> contentHash{};
  std::string name;
};

void dispatchAppend(std::shared_ptr<ReqCtx> ctx, ces::Bytes pre) {
  // APPEND pre-body rejects must CLOSE (body in flight — same
  // rationale as WRITE).
  ces::Buffer buf(std::move(pre));
  uint32_t length = 0;
  std::array<uint8_t, 32> contentHash{};
  std::string name;
  try {
    length = buf.get<uint32_t>();
    contentHash = buf.get<std::array<uint8_t, 32>>();
    uint16_t nameLen = buf.get<uint16_t>();
    if (nameLen == 0 || nameLen > kMaxNameLen) {
      sendErrorAndClose(ctx, CES_ERROR_BAD_NAME); return;
    }
    name = buf.getBytes<std::string>(nameLen);
  } catch (const std::out_of_range&) {
    sendErrorAndClose(ctx, CES_ERROR_BAD_INPUT); return;
  }

  if (length == 0 || length > kMaxWriteLen) {
    sendErrorAndClose(ctx, CES_ERROR_BAD_INPUT); return;
  }
  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) { sendErrorAndClose(ctx, rc); return; }

  const auto& cfg = reqServer(ctx)->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) {
    sendErrorAndClose(ctx, CES_ERROR_FILE_NOT_FOUND); return;
  }
  if (!chargeRentOrDelete(cPath, sPath, sc, cfg.feeFileRent,
                          cfg.cesFileStoreDir)) {
    sendErrorAndClose(ctx, CES_ERROR_FILE_NOT_FOUND); return;
  }
  writeSidecar(sPath, sc);
  if (std::memcmp(sc.owner_pubkey.data(), ctx->bound.boundPubkey.getHash().data(), 32) != 0) {
    sendErrorAndClose(ctx, CES_ERROR_NOT_OWNER); return;
  }
  // Overflow guard on new size.
  if (length > kMaxFileSize - sc.size) {
    sendErrorAndClose(ctx, CES_ERROR_BAD_INPUT); return;
  }

  const bool serverZone = isServerZone(name);

  // Store-wide cap check + JIT GC on the delta. /s/ lives outside
  // the cap — skip.
  if (!serverZone) {
    std::lock_guard lk(gStoreMetaMutex);
    uint8_t capRc = checkCapAndMaybeGc(
      cfg.cesFileStoreDir, cfg.cesFileStoreMaxBytes,
      cfg.feeFileRent, length);
    if (capRc != CES_OK) { sendErrorAndClose(ctx, capRc); return; }
  }

  // Program account must cover the write cost + 15 min of upfront
  // rent on the newly-added bytes (anti-grief: stops zombie appends
  // that vanish before the GC debounce window closes). Both waived
  // on /s/.
  uint64_t writeCost = serverZone
    ? 0 : kbCeil(length) * uint64_t(cfg.feeFileWrite);
  uint64_t upfront = serverZone
    ? 0 : computeOwedRent(length, cfg.feeFileRent, 0, kGcDebounceUs);
  if ((writeCost + upfront) > 0 &&
      readProgramAccountBalance(reqServer(ctx), sc) < writeCost + upfront) {
    sendErrorAndClose(ctx, CES_ERROR_INSUFFICIENT_BALANCE); return;
  }

  const ces::PublicKey& signer = ctx->bound.boundPubkey;

  auto state = std::make_shared<AppendBodyState>();
  state->ctx = ctx;
  state->length = length;
  state->oldSize = sc.size;
  state->contentHash = contentHash;
  state->name = name;

  auto after = [ctx, state, writeCost, upfront, cPath, sPath]
    (uint8_t rc, bool duplicate) {
    // Debit failed → body in flight. Close the channel.
    if (rc != CES_OK) { sendErrorAndClose(ctx, rc); return; }
    state->body.resize(state->length);
    boost::asio::async_read(
      *ctx->stream, boost::asio::buffer(state->body),
      [ctx, state, writeCost, upfront, cPath, sPath, duplicate]
      (const boost::system::error_code& ec, std::size_t) {
        if (ec) return;
        minx::Hash got = ces::sha256(
          state->body.data(), state->body.size());
        if (std::memcmp(got.data(),
                        state->contentHash.data(), 32) != 0) {
          sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
        }
        Sidecar sc{};
        if (!readSidecar(sPath, sc)) {
          sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
        }
        // Duplicate: re-running would double the file content (a resent APPEND
        // re-reads the grown size as its offset) and double-bill. Skip the
        // pwrite + debit; replay [balance][size] from current state.
        if (duplicate) {
          ces::Bytes pre;
          ces::Buffer::put<uint64_t>(
            pre, readProgramAccountBalance(reqServer(ctx), sc));
          ces::Buffer::put<uint64_t>(pre, sc.size);
          sendResponseAndLoop(ctx, CES_OK, std::move(pre));
          return;
        }
        // pwrite at old end.
        FILE* fp = std::fopen(cPath.string().c_str(), "rb+");
        if (!fp) { sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return; }
        if (std::fseek(fp, static_cast<long>(state->oldSize),
                       SEEK_SET) != 0) {
          std::fclose(fp);
          sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
        }
        size_t wrote = std::fwrite(
          state->body.data(), 1, state->body.size(), fp);
        std::fflush(fp);
        std::fclose(fp);
        if (wrote != state->body.size()) {
          sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
        }
        // Update sidecar + store meta. Drain writeCost + upfront
        // together — upfront is a burn against new-byte anti-grief.
        uint64_t newBal = 0;
        uint64_t totalDebit = writeCost + upfront;
        if (totalDebit > 0) {
          auto debit = debitProgramAccount(
            reqServer(ctx), sc, totalDebit);
          if (!debit.ok) {
            sendErrorAndLoop(ctx, CES_ERROR_INSUFFICIENT_BALANCE);
            return;
          }
          newBal = debit.newBalance;
        } else {
          newBal = readProgramAccountBalance(reqServer(ctx), sc);
        }
        sc.size = state->oldSize + state->length;
        sc.modified_us = getMicrosSinceEpoch();
        // Content extended → invalidate the lazily-cached program hash.
        sc.program_hash.fill(0);
        if (!writeSidecar(sPath, sc)) {
          sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
        }
        if (!isServerZone(sc.name)) {
          std::lock_guard lk(gStoreMetaMutex);
          const auto& cfg = reqServer(ctx)->_config();
          adjustStoreMeta(cfg.cesFileStoreDir, 0,
                          static_cast<int64_t>(state->length));
        }
        ces::Bytes pre;
        ces::Buffer::put<uint64_t>(pre, newBal);
        ces::Buffer::put<uint64_t>(pre, sc.size);
        sendResponseAndLoop(ctx, CES_OK, std::move(pre));
      });
  };

  reqServer(ctx)->_l2ValidateDedupAndDebit(
    signer, static_cast<int64_t>(cfg.feeQuery),
    ctx->reqNonce, getMicrosSinceEpoch(), ctx->reqSigHash,
    std::move(after), ctx->stream->get_executor());
}

// ---------------------------------------------------------------------------
// Dispatch: RESIZE (owner only) — change file's logical size. Sparse
// on grow (ftruncate, no bytes transferred; same as CREATE's sparse
// allocation — no feeFileWrite charge). Truncates tail on shrink.
// Cap check fires only on growth.
//   preamble (after reqNonce):
//     u64 new_size, u16 name_len, name
// ---------------------------------------------------------------------------

void dispatchResize(std::shared_ptr<ReqCtx> ctx, ces::Bytes pre) {
  ces::Buffer buf(std::move(pre));
  uint64_t newSize = 0;
  std::string name;
  try {
    newSize = buf.get<uint64_t>();
    uint16_t nameLen = buf.get<uint16_t>();
    if (nameLen == 0 || nameLen > kMaxNameLen) {
      sendErrorAndLoop(ctx, CES_ERROR_BAD_NAME); return;
    }
    name = buf.getBytes<std::string>(nameLen);
  } catch (const std::out_of_range&) {
    sendErrorAndLoop(ctx, CES_ERROR_BAD_INPUT); return;
  }

  if (newSize == 0 || newSize > kMaxFileSize) {
    sendErrorAndLoop(ctx, CES_ERROR_BAD_INPUT); return;
  }
  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) { sendErrorAndLoop(ctx, rc); return; }

  const auto& cfg = reqServer(ctx)->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) {
    sendErrorAndLoop(ctx, CES_ERROR_FILE_NOT_FOUND); return;
  }
  if (!chargeRentOrDelete(cPath, sPath, sc, cfg.feeFileRent,
                          cfg.cesFileStoreDir)) {
    sendErrorAndLoop(ctx, CES_ERROR_FILE_NOT_FOUND); return;
  }
  writeSidecar(sPath, sc);
  if (std::memcmp(sc.owner_pubkey.data(), ctx->bound.boundPubkey.getHash().data(), 32) != 0) {
    sendErrorAndLoop(ctx, CES_ERROR_NOT_OWNER); return;
  }

  uint64_t oldSize = sc.size;
  int64_t bytesDelta = static_cast<int64_t>(newSize)
                     - static_cast<int64_t>(oldSize);

  const bool serverZone = isServerZone(name);

  uint64_t upfrontBurn = 0;
  if (bytesDelta > 0 && !serverZone) {
    // Growing — cap check + JIT GC on the delta. Skipped on /s/.
    {
      std::lock_guard lk(gStoreMetaMutex);
      uint8_t capRc = checkCapAndMaybeGc(
        cfg.cesFileStoreDir, cfg.cesFileStoreMaxBytes,
        cfg.feeFileRent, static_cast<uint64_t>(bytesDelta));
      if (capRc != CES_OK) { sendErrorAndLoop(ctx, capRc); return; }
    }
    // Upfront rent on the extension — BURNED (anti-grief), not
    // deferred. Program account must cover it.
    upfrontBurn = computeOwedRent(
      static_cast<uint64_t>(bytesDelta), cfg.feeFileRent,
      0, kGcDebounceUs);
    if (upfrontBurn > 0 &&
        readProgramAccountBalance(reqServer(ctx), sc) < upfrontBurn) {
      sendErrorAndLoop(ctx, CES_ERROR_INSUFFICIENT_BALANCE); return;
    }
  }

  const ces::PublicKey& signer = ctx->bound.boundPubkey;

  auto after = [ctx, newSize, oldSize, bytesDelta, upfrontBurn, name,
                cPath, sPath](uint8_t rc, bool duplicate) {
    if (rc != CES_OK) { sendErrorAndLoop(ctx, rc); return; }
    // Duplicate: the resize already committed and the grow-rent burned;
    // re-running would double-charge. Replay the current size, skip resize+debit.
    if (duplicate) {
      Sidecar sc{};
      if (!readSidecar(sPath, sc)) {
        sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
      }
      ces::Bytes pre;
      ces::Buffer::put<uint64_t>(pre, sc.size);
      sendResponseAndLoop(ctx, CES_OK, std::move(pre));
      return;
    }
    // Truncate/extend the content file. resize_file handles both:
    // grow → sparse zeros (no disk use on Linux), shrink → truncate.
    std::error_code ec;
    std::filesystem::resize_file(cPath, newSize, ec);
    if (ec) {
      sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
    }
    // Update sidecar. Burn upfront from program account on grow.
    Sidecar sc{};
    if (!readSidecar(sPath, sc)) {
      sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
    }
    if (upfrontBurn > 0) {
      auto debit = debitProgramAccount(
        reqServer(ctx), sc, upfrontBurn);
      if (!debit.ok) {
        sendErrorAndLoop(ctx, CES_ERROR_INSUFFICIENT_BALANCE); return;
      }
    }
    sc.size = newSize;
    sc.modified_us = getMicrosSinceEpoch();
    // Content resized → invalidate the lazily-cached program hash.
    sc.program_hash.fill(0);
    if (!writeSidecar(sPath, sc)) {
      sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
    }
    // Store meta: bytes delta (either sign). /s/ is outside the cap.
    if (bytesDelta != 0 && !isServerZone(name)) {
      std::lock_guard lk(gStoreMetaMutex);
      const auto& cfg = reqServer(ctx)->_config();
      adjustStoreMeta(cfg.cesFileStoreDir, 0, bytesDelta);
    }
    ces::Bytes pre;
    ces::Buffer::put<uint64_t>(pre, sc.size);
    sendResponseAndLoop(ctx, CES_OK, std::move(pre));
  };

  reqServer(ctx)->_l2ValidateDedupAndDebit(
    signer, static_cast<int64_t>(cfg.feeQuery),
    ctx->reqNonce, getMicrosSinceEpoch(), ctx->reqSigHash,
    std::move(after), ctx->stream->get_executor());
}

// ---------------------------------------------------------------------------
// Rent + reconciliation (called from CesServer)
// ---------------------------------------------------------------------------

void walkFileStore(const std::filesystem::path& root,
                   const std::function<void(
                     const std::filesystem::path& /*sidecarPath*/,
                     const std::filesystem::path& /*contentPath*/,
                     Sidecar&)>& visitor) {
  namespace fs = std::filesystem;
  std::error_code ec;
  if (!fs::exists(root, ec)) return;
  const std::string suffix = kSidecarSuffix;
  for (auto it = fs::recursive_directory_iterator(root, ec);
       !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
    if (!it->is_regular_file()) continue;
    auto p = it->path();
    std::string fn = p.filename().string();
    if (fn.size() <= suffix.size()) continue;
    if (fn.compare(fn.size() - suffix.size(), suffix.size(), suffix) != 0)
      continue;
    Sidecar s{};
    if (!readSidecar(p, s)) continue;
    // Content path = sidecar path minus the ".sidecar.toml" suffix.
    auto contentPath = p;
    contentPath.replace_filename(fn.substr(0, fn.size() - suffix.size()));
    visitor(p, contentPath, s);
  }
}

uint64_t gcReclaim(const std::string& dir, int64_t feeRent,
                   uint64_t bytesNeeded) {
  uint64_t reclaimed = 0;
  int64_t files_delta = 0;
  int64_t bytes_delta = 0;
  uint64_t now = getMicrosSinceEpoch();
  walkFileStore(std::filesystem::path(dir),
    [&](const std::filesystem::path& sp,
        const std::filesystem::path& cp, Sidecar& s) {
      if (bytesNeeded > 0 && reclaimed >= bytesNeeded) return;
      // /s/ files are exempt from rent-based GC — unmetered by
      // definition.
      if (isServerZone(s.name)) return;
      uint64_t owed = computeOwedRent(
        s.size, feeRent, s.last_rent_us, now);
      CesServer* server = gServer.load();
      uint64_t bal = server ? readProgramAccountBalance(server, s) : 0;
      if (owed > bal) {
        // Dead. Delete content + sidecar. Best-effort rmdir of
        // empty parents.
        std::error_code ec;
        std::filesystem::remove(cp, ec);
        std::filesystem::remove(sp, ec);
        std::filesystem::path p = cp.parent_path();
        std::filesystem::path base = dir;
        while (p != base) {
          std::error_code rmec;
          if (!std::filesystem::remove(p, rmec)) break;
          p = p.parent_path();
        }
        reclaimed += s.size;
        files_delta -= 1;
        bytes_delta -= static_cast<int64_t>(s.size);
        notifyDeletion(s.name);
      }
      // Live files: leave alone. Their rent advances on next touch.
    });
  if (files_delta != 0 || bytes_delta != 0)
    adjustStoreMeta(dir, files_delta, bytes_delta);
  return reclaimed;
}

uint8_t checkCapAndMaybeGc(const std::string& dir,
                           uint64_t cap,
                           int64_t feeRent,
                           uint64_t addBytes) {
  StoreMeta m;
  auto metaP = storeMetaPath(dir);
  readStoreMeta(metaP, m);
  if (m.total_bytes + addBytes <= cap) return CES_OK;
  uint64_t now = getMicrosSinceEpoch();
  if (m.last_gc_us != 0 && now - m.last_gc_us < kGcDebounceUs) {
    return CES_ERROR_STORE_FULL;
  }
  uint64_t need = (m.total_bytes + addBytes) - cap;
  uint64_t reclaimed = gcReclaim(dir, feeRent, need);
  readStoreMeta(metaP, m);
  m.last_gc_us = now;
  writeStoreMeta(metaP, m);
  LOGINFO << "file-store: JIT GC" << VAR(need) << VAR(reclaimed);
  if (m.total_bytes + addBytes > cap) return CES_ERROR_STORE_FULL;
  return CES_OK;
}

// ---------------------------------------------------------------------------
// In-process verb execution (cross-handler path)
// ---------------------------------------------------------------------------
//
// Parallel to dispatch* but take an already-authorized owner pubkey.
// No wire I/O, no sig verify, no nonce, no dedup. All wire fees
// still apply 1:1 — the payer is req.sourceName's file_balance
// ("the program's wallet"), not the owner's account. Without this,
// the file API through compute is spammable.
//
// Fire-and-finish: each exec* completes by calling cb(resp) on cbEx.
// Strand hops only happen for the /f/-zone asset-ownership check on
// CREATE.

// Debit `amount` from the source file's file_balance, mirroring the
// wire path's signer-account debit. On failure (source file missing
// or out of funds, including the post-roll rent exhaustion inside
// fileHandlerDebitBalance), posts `st` to cb on cbEx and returns
// false. Caller should return immediately if this returns false.
bool debitSourceOrFail(const std::string& sourceName, uint64_t amount,
                       const std::function<void(FileExecResp)>& cb,
                       boost::asio::any_io_executor cbEx) {
  if (amount == 0) return true;
  if (sourceName.empty()) {
    // Defensive: the compute handler should always populate sourceName.
    // If not, we can't enforce billing, which defeats the purpose —
    // reject.
    FileExecResp r; r.status = CES_ERROR_INTERNAL;
    boost::asio::post(cbEx, [cb, r]() { cb(r); });
    return false;
  }
  if (!fileHandlerDebitBalance(sourceName, amount)) {
    FileExecResp r; r.status = CES_ERROR_INSUFFICIENT_BALANCE;
    boost::asio::post(cbEx, [cb, r]() { cb(r); });
    return false;
  }
  return true;
}

void execStat(CesServer* server, FileExecReq req,
              std::function<void(FileExecResp)> cb,
              boost::asio::any_io_executor cbEx) {
  FileExecResp resp;
  uint8_t rc = validateCesFileName(req.name);
  if (rc != CES_OK) { resp.status = rc;
    boost::asio::post(cbEx, [cb, resp]() { cb(resp); }); return; }
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, req.name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, req.name);
  Sidecar s{};
  if (!readSidecar(sPath, s)) { resp.status = CES_ERROR_FILE_NOT_FOUND;
    boost::asio::post(cbEx, [cb, resp]() { cb(resp); }); return; }
  if (!chargeRentOrDelete(cPath, sPath, s, cfg.feeFileRent,
                          cfg.cesFileStoreDir)) {
    resp.status = CES_ERROR_FILE_NOT_FOUND;
    boost::asio::post(cbEx, [cb, resp]() { cb(resp); }); return;
  }
  writeSidecar(sPath, s);
  resp.status = CES_OK;
  resp.ownerPubkey = s.owner_pubkey;
  resp.fileBalance = readProgramAccountBalance(server, s);
  resp.pricePerKb = s.price_per_kb;
  resp.size = s.size;
  resp.contentType = s.content_type;
  resp.createdUs = s.created_us;
  resp.modifiedUs = s.modified_us;
  boost::asio::post(cbEx, [cb, resp]() { cb(resp); });
}

void execRead(CesServer* server, FileExecReq req,
              std::function<void(FileExecResp)> cb,
              boost::asio::any_io_executor cbEx) {
  FileExecResp resp;
  auto fail = [&](uint8_t st) {
    resp.status = st;
    boost::asio::post(cbEx, [cb, resp]() { cb(resp); });
  };
  if (req.length == 0 || req.length > kMaxReadLen) {
    fail(CES_ERROR_INTERNAL); return;
  }
  uint8_t rc = validateCesFileName(req.name);
  if (rc != CES_OK) { fail(rc); return; }
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, req.name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, req.name);
  Sidecar s{};
  if (!readSidecar(sPath, s)) { fail(CES_ERROR_FILE_NOT_FOUND); return; }
  if (!chargeRentOrDelete(cPath, sPath, s, cfg.feeFileRent,
                          cfg.cesFileStoreDir)) {
    fail(CES_ERROR_FILE_NOT_FOUND); return;
  }
  writeSidecar(sPath, s);
  if (req.offset > s.size ||
      req.offset + uint64_t(req.length) > s.size) {
    fail(CES_ERROR_INTERNAL); return;
  }
  bool isOwner = (std::memcmp(s.owner_pubkey.data(),
                              req.ownerPubkey.data(), 32) == 0);
  const bool serverZone = isServerZone(req.name);
  uint64_t readIoCost = serverZone
    ? 0 : kbCeil(req.length) * uint64_t(cfg.feeFileRead);
  uint64_t readPrice = 0;
  if (!serverZone && !isOwner) {
    readPrice = kbCeil(req.length) * s.price_per_kb;
  }
  uint64_t totalSignerFee = uint64_t(cfg.feeQuery) + readIoCost + readPrice;
  if (!debitSourceOrFail(req.sourceName, totalSignerFee, cb, cbEx))
    return;
  std::ifstream f(cPath, std::ios::binary);
  if (!f) { fail(CES_ERROR_INTERNAL); return; }
  f.seekg(static_cast<std::streamoff>(req.offset), std::ios::beg);
  ces::Bytes data(req.length);
  f.read(reinterpret_cast<char*>(data.data()), req.length);
  if (f.gcount() != static_cast<std::streamsize>(req.length)) {
    fail(CES_ERROR_INTERNAL); return;
  }
  // Credit target program account with readPrice (non-owner only).
  if (readPrice > 0) {
    Sidecar sc2{};
    if (readSidecar(sPath, sc2)) {
      creditProgramAccount(server, sc2, readPrice);
      sc2.modified_us = getMicrosSinceEpoch();
      writeSidecar(sPath, sc2);
    }
  }
  resp.status = CES_OK;
  resp.data = std::move(data);
  boost::asio::post(cbEx, [cb, resp]() { cb(resp); });
}

void execSetPrice(CesServer* server, FileExecReq req,
                  std::function<void(FileExecResp)> cb,
                  boost::asio::any_io_executor cbEx) {
  FileExecResp resp;
  auto fail = [&](uint8_t st) {
    resp.status = st;
    boost::asio::post(cbEx, [cb, resp]() { cb(resp); });
  };
  uint8_t rc = validateCesFileName(req.name);
  if (rc != CES_OK) { fail(rc); return; }
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, req.name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, req.name);
  Sidecar s{};
  if (!readSidecar(sPath, s)) { fail(CES_ERROR_FILE_NOT_FOUND); return; }
  if (!chargeRentOrDelete(cPath, sPath, s, cfg.feeFileRent,
                          cfg.cesFileStoreDir)) {
    fail(CES_ERROR_FILE_NOT_FOUND); return;
  }
  writeSidecar(sPath, s);
  if (std::memcmp(s.owner_pubkey.data(),
                  req.ownerPubkey.data(), 32) != 0) {
    fail(CES_ERROR_NOT_OWNER); return;
  }
  if (!debitSourceOrFail(req.sourceName, cfg.feeQuery, cb, cbEx))
    return;
  s.price_per_kb = req.pricePerKb;
  s.modified_us = getMicrosSinceEpoch();
  if (!writeSidecar(sPath, s)) { fail(CES_ERROR_INTERNAL); return; }
  resp.status = CES_OK;
  resp.pricePerKb = s.price_per_kb;
  boost::asio::post(cbEx, [cb, resp]() { cb(resp); });
}

void execWrite(CesServer* server, FileExecReq req,
               std::function<void(FileExecResp)> cb,
               boost::asio::any_io_executor cbEx) {
  FileExecResp resp;
  auto fail = [&](uint8_t st) {
    resp.status = st;
    boost::asio::post(cbEx, [cb, resp]() { cb(resp); });
  };
  if (req.body.empty() || req.body.size() > kMaxWriteLen) {
    fail(CES_ERROR_INTERNAL); return;
  }
  uint8_t rc = validateCesFileName(req.name);
  if (rc != CES_OK) { fail(rc); return; }
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, req.name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, req.name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) { fail(CES_ERROR_FILE_NOT_FOUND); return; }
  if (!chargeRentOrDelete(cPath, sPath, sc, cfg.feeFileRent,
                          cfg.cesFileStoreDir)) {
    fail(CES_ERROR_FILE_NOT_FOUND); return;
  }
  if (std::memcmp(sc.owner_pubkey.data(),
                  req.ownerPubkey.data(), 32) != 0) {
    fail(CES_ERROR_NOT_OWNER); return;
  }
  uint32_t length = static_cast<uint32_t>(req.body.size());
  if (req.offset > sc.size ||
      req.offset + uint64_t(length) > sc.size) {
    fail(CES_ERROR_INTERNAL); return;
  }
  uint64_t writeCost = isServerZone(req.name)
    ? 0 : kbCeil(length) * uint64_t(cfg.feeFileWrite);
  if (writeCost > 0 &&
      readProgramAccountBalance(server, sc) < writeCost) {
    fail(CES_ERROR_INSUFFICIENT_BALANCE); return;
  }
  writeSidecar(sPath, sc);
  if (!debitSourceOrFail(req.sourceName, cfg.feeQuery, cb, cbEx))
    return;
  // Write body to disk.
  FILE* fp = std::fopen(cPath.string().c_str(), "rb+");
  if (!fp) { fail(CES_ERROR_INTERNAL); return; }
  if (std::fseek(fp, static_cast<long>(req.offset), SEEK_SET) != 0) {
    std::fclose(fp); fail(CES_ERROR_INTERNAL); return;
  }
  size_t wrote = std::fwrite(req.body.data(), 1, req.body.size(), fp);
  std::fflush(fp);
  std::fclose(fp);
  if (wrote != req.body.size()) { fail(CES_ERROR_INTERNAL); return; }
  // Debit program account by writeCost and persist sidecar.
  if (!readSidecar(sPath, sc)) { fail(CES_ERROR_INTERNAL); return; }
  uint64_t newBal = 0;
  if (writeCost > 0) {
    auto debit = debitProgramAccount(server, sc, writeCost);
    if (!debit.ok) { fail(CES_ERROR_INSUFFICIENT_BALANCE); return; }
    newBal = debit.newBalance;
  } else {
    newBal = readProgramAccountBalance(server, sc);
  }
  sc.modified_us = getMicrosSinceEpoch();
  if (!writeSidecar(sPath, sc)) { fail(CES_ERROR_INTERNAL); return; }
  resp.status = CES_OK;
  resp.fileBalance = newBal;
  boost::asio::post(cbEx, [cb, resp]() { cb(resp); });
}

void execDeposit(CesServer* server, FileExecReq req,
                 std::function<void(FileExecResp)> cb,
                 boost::asio::any_io_executor cbEx) {
  auto fail = [cb, cbEx](uint8_t st) {
    FileExecResp r; r.status = st;
    boost::asio::post(cbEx, [cb, r]() { cb(r); });
  };
  uint8_t rc = validateCesFileName(req.name);
  if (rc != CES_OK) { fail(rc); return; }
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, req.name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) { fail(CES_ERROR_FILE_NOT_FOUND); return; }
  uint64_t totalSignerFee = uint64_t(cfg.feeQuery) + req.amount;
  if (!debitSourceOrFail(req.sourceName, totalSignerFee, cb, cbEx))
    return;
  // Re-read sidecar (debit above may have touched rent on source, but
  // the target sidecar is untouched; re-read for freshness).
  if (!readSidecar(sPath, sc)) { fail(CES_ERROR_INTERNAL); return; }
  creditProgramAccount(server, sc, req.amount);
  sc.modified_us = getMicrosSinceEpoch();
  if (!writeSidecar(sPath, sc)) { fail(CES_ERROR_INTERNAL); return; }
  FileExecResp r; r.status = CES_OK;
  r.fileBalance = readProgramAccountBalance(server, sc);
  boost::asio::post(cbEx, [cb, r]() { cb(r); });
}

void execWithdraw(CesServer* server, FileExecReq req,
                  std::function<void(FileExecResp)> cb,
                  boost::asio::any_io_executor cbEx) {
  auto fail = [cb, cbEx](uint8_t st) {
    FileExecResp r; r.status = st;
    boost::asio::post(cbEx, [cb, r]() { cb(r); });
  };
  uint8_t rc = validateCesFileName(req.name);
  if (rc != CES_OK) { fail(rc); return; }
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, req.name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, req.name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) { fail(CES_ERROR_FILE_NOT_FOUND); return; }
  if (!chargeRentOrDelete(cPath, sPath, sc, cfg.feeFileRent,
                          cfg.cesFileStoreDir)) {
    fail(CES_ERROR_FILE_NOT_FOUND); return;
  }
  writeSidecar(sPath, sc);
  if (std::memcmp(sc.owner_pubkey.data(),
                  req.ownerPubkey.data(), 32) != 0) {
    fail(CES_ERROR_NOT_OWNER); return;
  }
  if (readProgramAccountBalance(server, sc) < req.amount) {
    fail(CES_ERROR_INSUFFICIENT_BALANCE); return;
  }
  if (!debitSourceOrFail(req.sourceName, cfg.feeQuery, cb, cbEx))
    return;
  if (!readSidecar(sPath, sc)) { fail(CES_ERROR_INTERNAL); return; }
  auto debit = debitProgramAccount(server, sc, req.amount);
  if (!debit.ok) { fail(CES_ERROR_INSUFFICIENT_BALANCE); return; }
  sc.modified_us = getMicrosSinceEpoch();
  if (!writeSidecar(sPath, sc)) { fail(CES_ERROR_INTERNAL); return; }
  // Credit the withdrawn amount back to the program's wallet
  // (source's program account). No-op-ish if source == target
  // (target just lost `amount`; re-crediting source by the same
  // amount makes it a wash — matches wire's signer==owner case).
  (void)fileHandlerCreditBalance(req.sourceName, req.amount);
  FileExecResp r; r.status = CES_OK;
  r.fileBalance = debit.newBalance;
  boost::asio::post(cbEx, [cb, r]() { cb(r); });
}

void execDelete(CesServer* server, FileExecReq req,
                std::function<void(FileExecResp)> cb,
                boost::asio::any_io_executor cbEx) {
  auto fail = [cb, cbEx](uint8_t st) {
    FileExecResp r; r.status = st;
    boost::asio::post(cbEx, [cb, r]() { cb(r); });
  };
  uint8_t rc = validateCesFileName(req.name);
  if (rc != CES_OK) { fail(rc); return; }
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, req.name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, req.name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) { fail(CES_ERROR_FILE_NOT_FOUND); return; }
  if (!chargeRentOrDelete(cPath, sPath, sc, cfg.feeFileRent,
                          cfg.cesFileStoreDir)) {
    fail(CES_ERROR_FILE_NOT_FOUND); return;
  }
  writeSidecar(sPath, sc);
  if (std::memcmp(sc.owner_pubkey.data(),
                  req.ownerPubkey.data(), 32) != 0) {
    fail(CES_ERROR_NOT_OWNER); return;
  }
  if (!debitSourceOrFail(req.sourceName, cfg.feeQuery, cb, cbEx))
    return;
  // Drain remaining program account balance — that's the refund.
  uint64_t refund = readProgramAccountBalance(server, sc);
  if (refund > 0) {
    auto debit = debitProgramAccount(server, sc, refund);
    if (!debit.ok) refund = 0;
  }
  uint64_t size = sc.size;
  std::string name = req.name;
  std::error_code ec;
  std::filesystem::remove(cPath, ec);
  std::filesystem::remove(sPath, ec);
  if (!isServerZone(name)) {
    std::lock_guard lk(gStoreMetaMutex);
    adjustStoreMeta(cfg.cesFileStoreDir, -1,
                    -static_cast<int64_t>(size));
  }
  {
    std::filesystem::path p = cPath.parent_path();
    std::filesystem::path base = cfg.cesFileStoreDir;
    while (p != base) {
      std::error_code rmec;
      if (!std::filesystem::remove(p, rmec)) break;
      p = p.parent_path();
    }
  }
  notifyDeletion(name);
  // Credit refund to program wallet (source file_balance). If the
  // program just deleted its own source, the source is gone and
  // this is a no-op — the supervisor will tear down the instance.
  (void)fileHandlerCreditBalance(req.sourceName, refund);
  FileExecResp r; r.status = CES_OK; r.refunded = refund;
  boost::asio::post(cbEx, [cb, r]() { cb(r); });
}

void execResize(CesServer* server, FileExecReq req,
                std::function<void(FileExecResp)> cb,
                boost::asio::any_io_executor cbEx) {
  auto fail = [cb, cbEx](uint8_t st) {
    FileExecResp r; r.status = st;
    boost::asio::post(cbEx, [cb, r]() { cb(r); });
  };
  if (req.size == 0 || req.size > kMaxFileSize) {
    fail(CES_ERROR_INTERNAL); return;
  }
  uint8_t rc = validateCesFileName(req.name);
  if (rc != CES_OK) { fail(rc); return; }
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, req.name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, req.name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) { fail(CES_ERROR_FILE_NOT_FOUND); return; }
  if (!chargeRentOrDelete(cPath, sPath, sc, cfg.feeFileRent,
                          cfg.cesFileStoreDir)) {
    fail(CES_ERROR_FILE_NOT_FOUND); return;
  }
  writeSidecar(sPath, sc);
  if (std::memcmp(sc.owner_pubkey.data(),
                  req.ownerPubkey.data(), 32) != 0) {
    fail(CES_ERROR_NOT_OWNER); return;
  }
  uint64_t oldSize = sc.size;
  uint64_t newSize = req.size;
  int64_t bytesDelta = static_cast<int64_t>(newSize)
                     - static_cast<int64_t>(oldSize);
  const bool serverZone = isServerZone(req.name);
  uint64_t upfront = 0;
  if (bytesDelta > 0 && !serverZone) {
    std::lock_guard lk(gStoreMetaMutex);
    uint8_t capRc = checkCapAndMaybeGc(
      cfg.cesFileStoreDir, cfg.cesFileStoreMaxBytes,
      cfg.feeFileRent, static_cast<uint64_t>(bytesDelta));
    if (capRc != CES_OK) { fail(capRc); return; }
    upfront = computeOwedRent(
      static_cast<uint64_t>(bytesDelta), cfg.feeFileRent,
      0, kGcDebounceUs);
    // Target program account must cover the upfront burn.
    if (upfront > 0 &&
        readProgramAccountBalance(server, sc) < upfront) {
      fail(CES_ERROR_INSUFFICIENT_BALANCE); return;
    }
  }
  // Charge feeQuery from source (signer analog).
  if (!debitSourceOrFail(req.sourceName, uint64_t(cfg.feeQuery),
                         cb, cbEx))
    return;
  std::error_code ec;
  std::filesystem::resize_file(cPath, newSize, ec);
  if (ec) { fail(CES_ERROR_INTERNAL); return; }
  if (!readSidecar(sPath, sc)) { fail(CES_ERROR_INTERNAL); return; }
  uint64_t newBal = 0;
  if (upfront > 0) {
    auto debit = debitProgramAccount(server, sc, upfront);
    if (!debit.ok) {
      fail(CES_ERROR_INSUFFICIENT_BALANCE); return;
    }
    newBal = debit.newBalance;
  } else {
    newBal = readProgramAccountBalance(server, sc);
  }
  sc.size = newSize;
  sc.modified_us = getMicrosSinceEpoch();
  if (!writeSidecar(sPath, sc)) { fail(CES_ERROR_INTERNAL); return; }
  if (bytesDelta != 0 && !serverZone) {
    std::lock_guard lk(gStoreMetaMutex);
    adjustStoreMeta(cfg.cesFileStoreDir, 0, bytesDelta);
  }
  FileExecResp r;
  r.status = CES_OK;
  r.fileBalance = newBal;
  r.size = sc.size;
  boost::asio::post(cbEx, [cb, r]() { cb(r); });
  (void)oldSize;
}

void execAppend(CesServer* server, FileExecReq req,
                std::function<void(FileExecResp)> cb,
                boost::asio::any_io_executor cbEx) {
  auto fail = [cb, cbEx](uint8_t st) {
    FileExecResp r; r.status = st;
    boost::asio::post(cbEx, [cb, r]() { cb(r); });
  };
  if (req.body.empty() || req.body.size() > kMaxWriteLen) {
    fail(CES_ERROR_INTERNAL); return;
  }
  uint8_t rc = validateCesFileName(req.name);
  if (rc != CES_OK) { fail(rc); return; }
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, req.name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, req.name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) { fail(CES_ERROR_FILE_NOT_FOUND); return; }
  if (!chargeRentOrDelete(cPath, sPath, sc, cfg.feeFileRent,
                          cfg.cesFileStoreDir)) {
    fail(CES_ERROR_FILE_NOT_FOUND); return;
  }
  writeSidecar(sPath, sc);
  if (std::memcmp(sc.owner_pubkey.data(),
                  req.ownerPubkey.data(), 32) != 0) {
    fail(CES_ERROR_NOT_OWNER); return;
  }
  uint32_t length = static_cast<uint32_t>(req.body.size());
  if (length > kMaxFileSize - sc.size) {
    fail(CES_ERROR_INTERNAL); return;
  }
  const bool serverZone = isServerZone(req.name);
  if (!serverZone) {
    std::lock_guard lk(gStoreMetaMutex);
    uint8_t capRc = checkCapAndMaybeGc(
      cfg.cesFileStoreDir, cfg.cesFileStoreMaxBytes,
      cfg.feeFileRent, length);
    if (capRc != CES_OK) { fail(capRc); return; }
  }
  uint64_t writeCost = serverZone
    ? 0 : kbCeil(length) * uint64_t(cfg.feeFileWrite);
  uint64_t upfront = serverZone
    ? 0 : computeOwedRent(length, cfg.feeFileRent, 0, kGcDebounceUs);
  // Target program account must cover (writeCost + upfront).
  // Upfront is a burn against create-and-shrink churn on new bytes
  // — not credited to the file.
  uint64_t totalDebit = writeCost + upfront;
  if (totalDebit > 0 &&
      readProgramAccountBalance(server, sc) < totalDebit) {
    fail(CES_ERROR_INSUFFICIENT_BALANCE); return;
  }
  // Charge feeQuery from source program account (signer analog).
  if (!debitSourceOrFail(req.sourceName, uint64_t(cfg.feeQuery),
                         cb, cbEx))
    return;
  uint64_t oldSize = sc.size;
  FILE* fp = std::fopen(cPath.string().c_str(), "rb+");
  if (!fp) { fail(CES_ERROR_INTERNAL); return; }
  if (std::fseek(fp, static_cast<long>(oldSize), SEEK_SET) != 0) {
    std::fclose(fp); fail(CES_ERROR_INTERNAL); return;
  }
  size_t wrote = std::fwrite(req.body.data(), 1, req.body.size(), fp);
  std::fflush(fp); std::fclose(fp);
  if (wrote != req.body.size()) { fail(CES_ERROR_INTERNAL); return; }
  if (!readSidecar(sPath, sc)) { fail(CES_ERROR_INTERNAL); return; }
  uint64_t newBal = 0;
  if (totalDebit > 0) {
    auto debit = debitProgramAccount(server, sc, totalDebit);
    if (!debit.ok) {
      fail(CES_ERROR_INSUFFICIENT_BALANCE); return;
    }
    newBal = debit.newBalance;
  } else {
    newBal = readProgramAccountBalance(server, sc);
  }
  sc.size = oldSize + length;
  sc.modified_us = getMicrosSinceEpoch();
  if (!writeSidecar(sPath, sc)) { fail(CES_ERROR_INTERNAL); return; }
  if (!serverZone) {
    std::lock_guard lk(gStoreMetaMutex);
    adjustStoreMeta(cfg.cesFileStoreDir, 0,
                    static_cast<int64_t>(length));
  }
  FileExecResp r;
  r.status = CES_OK;
  r.fileBalance = newBal;
  r.size = sc.size;
  boost::asio::post(cbEx, [cb, r]() { cb(r); });
}

void execCreate(CesServer* server, FileExecReq req,
                std::function<void(FileExecResp)> cb,
                boost::asio::any_io_executor cbEx) {
  auto fail = [cb, cbEx](uint8_t st) {
    FileExecResp r; r.status = st;
    boost::asio::post(cbEx, [cb, r]() { cb(r); });
  };
  if (req.size == 0 || req.size > kMaxFileSize) {
    fail(CES_ERROR_INTERNAL); return;
  }
  if (req.contentType.size() > kMaxContentTypeLen) {
    fail(CES_ERROR_INTERNAL); return;
  }
  uint8_t rc = validateCesFileName(req.name);
  if (rc != CES_OK) { fail(rc); return; }

  // Zone-ownership gate may hop to logicStrand for /f/. Callback
  // fires on cbEx.
  std::array<uint8_t, 32> signerKey = req.ownerPubkey;
  std::string nameCopy = req.name;
  auto finish = [server, cb, cbEx, req = std::move(req)]
    (uint8_t zoneRc) mutable {
    FileExecResp r;
    if (zoneRc != CES_OK) { r.status = zoneRc;
      boost::asio::post(cbEx, [cb, r]() { cb(r); }); return; }
    const auto& cfg = server->_config();
    uint8_t rc2 = checkPathConflict(
      cfg.cesFileStoreDir, req.name, /*createMode=*/true);
    if (rc2 != CES_OK) { r.status = rc2;
      boost::asio::post(cbEx, [cb, r]() { cb(r); }); return; }
    const bool serverZone = isServerZone(req.name);
    if (!serverZone) {
      std::lock_guard lk(gStoreMetaMutex);
      uint8_t capRc = checkCapAndMaybeGc(
        cfg.cesFileStoreDir, cfg.cesFileStoreMaxBytes,
        cfg.feeFileRent, req.size);
      if (capRc != CES_OK) { r.status = capRc;
        boost::asio::post(cbEx, [cb, r]() { cb(r); }); return; }
    }
    uint64_t initialDeposit = req.initialDeposit;
    uint64_t upfrontBurn = 0;
    if (!serverZone) {
      upfrontBurn = computeOwedRent(
        req.size, cfg.feeFileRent, 0, kGcDebounceUs);
      if (initialDeposit < upfrontBurn) {
        r.status = CES_ERROR_INSUFFICIENT_BALANCE;
        boost::asio::post(cbEx, [cb, r]() { cb(r); }); return;
      }
    } else {
      initialDeposit = 0;
    }
    // Charge feeQuery + initialDeposit from source file_balance —
    // mirrors wire path's (initialDeposit + feeQuery) on signer
    // account. feeQuery is burned; initialDeposit seeds the new
    // file's file_balance, minus the upfront burn.
    uint64_t totalSignerFee =
      uint64_t(cfg.feeQuery) + initialDeposit;
    if (!debitSourceOrFail(req.sourceName, totalSignerFee, cb, cbEx))
      return;
    auto cPath = resolveContentPath(cfg.cesFileStoreDir, req.name);
    auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, req.name);
    std::error_code ec;
    std::filesystem::create_directories(cPath.parent_path(), ec);
    if (ec) { r.status = CES_ERROR_INTERNAL;
      boost::asio::post(cbEx, [cb, r]() { cb(r); }); return; }
    {
      std::ofstream f(cPath, std::ios::binary | std::ios::trunc);
      if (!f) { r.status = CES_ERROR_INTERNAL;
        boost::asio::post(cbEx, [cb, r]() { cb(r); }); return; }
    }
    std::filesystem::resize_file(cPath, req.size, ec);
    if (ec) { r.status = CES_ERROR_INTERNAL;
      boost::asio::post(cbEx, [cb, r]() { cb(r); }); return; }
    // Allocate a fresh program account for the new file with the
    // post-upfront-burn deposit as its starting balance.
    uint64_t programAccountInitial = (initialDeposit > upfrontBurn)
      ? (initialDeposit - upfrontBurn) : 0;
    std::array<uint8_t, 32> programPubkey{};
    std::array<uint8_t, 32> programPrivkey{};
    {
      // Generate a real ed25519 keypair for the file's program account on
      // rpcTaskIO_ before hopping to logicStrand_ to mint the account. The
      // public half keys the account; the private half is stored in the sidecar
      // so the program can sign its own remote ops.
      ces::KeyPair kp = ces::KeyPair::generate();
      const auto& pub = kp.getPublicKeyAsHash();
      const auto& priv = kp.getPrivateKey();
      std::memcpy(programPubkey.data(), pub.data(), 32);
      std::memcpy(programPrivkey.data(), priv.data(), 32);
      minx::Hash pubkey{};
      std::memcpy(pubkey.data(), programPubkey.data(), 32);
      server->_l2CreditProgramAccountSync(
        pubkey, static_cast<int64_t>(programAccountInitial));
    }
    Sidecar s{};
    s.version = kSidecarVersion;
    s.name = req.name;
    std::memcpy(s.owner_pubkey.data(), req.ownerPubkey.data(), 32);
    s.program_pubkey = programPubkey;
    s.program_privkey = programPrivkey;
    s.price_per_kb = req.pricePerKb;
    s.size = req.size;
    s.content_type = req.contentType;
    s.created_us = getMicrosSinceEpoch();
    s.modified_us = s.created_us;
    s.last_rent_us = s.created_us;
    if (!writeSidecar(sPath, s)) {
      std::filesystem::remove(cPath, ec);
      r.status = CES_ERROR_INTERNAL;
      boost::asio::post(cbEx, [cb, r]() { cb(r); }); return;
    }
    if (!isServerZone(req.name)) {
      std::lock_guard lk(gStoreMetaMutex);
      adjustStoreMeta(cfg.cesFileStoreDir, +1,
                      static_cast<int64_t>(req.size));
    }
    r.status = CES_OK;
    r.fileBalance = programAccountInitial;
    boost::asio::post(cbEx, [cb, r]() { cb(r); });
  };
  checkZoneOwnership(server, nameCopy, signerKey, cbEx, std::move(finish));
}

} // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void fileHandlerBind(CesServer* server) {
  gServer.store(server);
}

bool fileHandlerReadProgramPubkey(
    const std::string& name,
    std::array<uint8_t, 32>& outProgramPubkey) {
  CesServer* server = gServer.load();
  if (!server) return false;
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) return false;
  outProgramPubkey = sc.program_pubkey;
  return true;
}

// Read the file's program-account ed25519 private key from its sidecar.
// All-zero on success means the account has no signing key (no remote
// signing). False if the sidecar is unreadable.
bool fileHandlerReadProgramPrivkey(
    const std::string& name,
    std::array<uint8_t, 32>& outProgramPrivkey) {
  CesServer* server = gServer.load();
  if (!server) return false;
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) return false;
  outProgramPrivkey = sc.program_privkey;
  return true;
}

bool fileHandlerReadOwnerAndBalance(
    const std::string& name,
    std::array<uint8_t, 32>& outOwnerPubkey,
    uint64_t& outFileBalance) {
  CesServer* server = gServer.load();
  if (!server) return false;
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) return false;
  if (!chargeRentOrDelete(cPath, sPath, sc, cfg.feeFileRent,
                          cfg.cesFileStoreDir)) {
    // chargeRentOrDelete already fired notifyDeletion + removed disk.
    return false;
  }
  if (!writeSidecar(sPath, sc)) return false;
  outOwnerPubkey = sc.owner_pubkey;
  outFileBalance = readProgramAccountBalance(server, sc);
  return true;
}

bool fileHandlerCreditBalance(const std::string& name, uint64_t amount) {
  CesServer* server = gServer.load();
  if (!server) return false;
  if (amount == 0) return true;
  // /s/ files are unmetered — operator donates via the reconcile-time
  // top-up. Treat additional credits as a no-op; the /s/ balance is
  // decorative and never consulted for billing.
  if (isServerZone(name)) return true;
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) return false;
  if (!chargeRentOrDelete(cPath, sPath, sc, cfg.feeFileRent,
                          cfg.cesFileStoreDir)) {
    return false; // chargeRentOrDelete already notified
  }
  creditProgramAccount(server, sc, amount);
  sc.modified_us = getMicrosSinceEpoch();
  if (!writeSidecar(sPath, sc)) return false;
  return true;
}

bool fileHandlerGetProgramHash(
    const std::string& name,
    std::array<uint8_t, 32>& outHash) {
  CesServer* server = gServer.load();
  if (!server) return false;
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) return false;
  if (!chargeRentOrDelete(cPath, sPath, sc, cfg.feeFileRent,
                          cfg.cesFileStoreDir)) {
    return false;
  }

  // Cached?
  bool cached = false;
  for (auto b : sc.program_hash) if (b != 0) { cached = true; break; }
  if (cached) {
    if (!writeSidecar(sPath, sc)) return false; // persist rent advance
    outHash = sc.program_hash;
    return true;
  }

  // Compute sha256(content || name) by streaming the file.
  CryptoPP::SHA256 hasher;
  std::ifstream f(cPath, std::ios::binary);
  if (!f) return false;
  std::array<char, 4096> buf;
  while (f) {
    f.read(buf.data(), static_cast<std::streamsize>(buf.size()));
    auto got = f.gcount();
    if (got > 0) {
      hasher.Update(reinterpret_cast<const CryptoPP::byte*>(buf.data()),
                    static_cast<size_t>(got));
    }
  }
  if (f.bad()) return false;
  hasher.Update(reinterpret_cast<const CryptoPP::byte*>(name.data()),
                name.size());
  std::array<uint8_t, 32> digest{};
  hasher.Final(reinterpret_cast<CryptoPP::byte*>(digest.data()));

  // All-zero is the "uncomputed" sentinel. A real SHA-256 is non-zero with
  // overwhelming probability; if one ever comes out all-zero, treat it as a
  // failure rather than storing it as the sentinel.
  bool digestZero = true;
  for (auto b : digest) if (b != 0) { digestZero = false; break; }
  if (digestZero) return false;

  sc.program_hash = digest;
  if (!writeSidecar(sPath, sc)) return false;
  outHash = digest;
  return true;
}

bool fileHandlerDebitBalance(const std::string& name, uint64_t amount) {
  CesServer* server = gServer.load();
  if (!server) return false;
  // /s/ files are unmetered — operator donates everything via the
  // reconcile-time top-up. Treat any debit as a successful no-op so
  // the compute supervisor tick / /s/ program ops don't accidentally
  // trip the balance-exhausted deletion path.
  if (isServerZone(name)) return true;
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) return false;
  if (!chargeRentOrDelete(cPath, sPath, sc, cfg.feeFileRent,
                          cfg.cesFileStoreDir)) {
    return false; // chargeRentOrDelete already notified
  }

  auto debit = debitProgramAccount(server, sc, amount);
  bool insufficient = !debit.ok;

  if (insufficient) {
    // Debit exhaustion — treat exactly like rent exhaustion: delete.
    std::error_code ec;
    std::filesystem::remove(cPath, ec);
    std::filesystem::remove(sPath, ec);
    {
      std::filesystem::path p = cPath.parent_path();
      std::filesystem::path base = cfg.cesFileStoreDir;
      while (p != base) {
        std::error_code rmec;
        if (!std::filesystem::remove(p, rmec)) break;
        p = p.parent_path();
      }
    }
    {
      std::lock_guard lk(gStoreMetaMutex);
      adjustStoreMeta(cfg.cesFileStoreDir, -1,
                      -static_cast<int64_t>(sc.size));
    }
    notifyDeletion(sc.name);
    return false;
  }
  sc.modified_us = getMicrosSinceEpoch();
  if (!writeSidecar(sPath, sc)) return false;
  return true;
}

void fileHandlerRegisterDeletionCallback(
    std::function<void(const std::string&)> cb) {
  if (!cb) return;
  std::lock_guard lk(gDeletionCallbacksMutex);
  gDeletionCallbacks.push_back(std::move(cb));
}

void fileHandlerExec(
    const FileExecReq& req,
    std::function<void(FileExecResp)> cb,
    boost::asio::any_io_executor cbEx) {
  CesServer* server = gServer.load();
  if (!server) {
    FileExecResp r; r.status = CES_ERROR_DISABLED;
    boost::asio::post(cbEx, [cb, r]() { cb(r); });
    return;
  }
  switch (req.verb) {
    case kVerbCreate:   execCreate  (server, req, cb, cbEx); return;
    case kVerbWrite:    execWrite   (server, req, cb, cbEx); return;
    case kVerbRead:     execRead    (server, req, cb, cbEx); return;
    case kVerbStat:     execStat    (server, req, cb, cbEx); return;
    case kVerbDeposit:  execDeposit (server, req, cb, cbEx); return;
    case kVerbWithdraw: execWithdraw(server, req, cb, cbEx); return;
    case kVerbSetPrice: execSetPrice(server, req, cb, cbEx); return;
    case kVerbDelete:   execDelete  (server, req, cb, cbEx); return;
    case kVerbAppend:   execAppend  (server, req, cb, cbEx); return;
    case kVerbResize:   execResize  (server, req, cb, cbEx); return;
    default: {
      FileExecResp r; r.status = CES_ERROR_INTERNAL;
      boost::asio::post(cbEx, [cb, r]() { cb(r); });
    }
  }
}

// Best-effort content-type inference from filename extension. /s/ is
// operator-controlled at the disk level; the operator can drop any
// file there and we infer a reasonable content_type for the sidecar.
// Unknown extension → application/octet-stream.
inline std::string inferContentType(const std::string& name) {
  auto dot = name.rfind('.');
  if (dot == std::string::npos) return "application/octet-stream";
  std::string ext = name.substr(dot + 1);
  for (auto& c : ext) c = static_cast<char>(std::tolower(c));
  if (ext == "lua")  return "text/x-lua";
  if (ext == "toml") return "text/x-toml";
  if (ext == "md")   return "text/markdown";
  if (ext == "txt")  return "text/plain";
  if (ext == "json") return "application/json";
  if (ext == "html" || ext == "htm") return "text/html";
  return "application/octet-stream";
}

// Top-up amount the server credits to each /s/ file's program account on
// every reconcile. /s/ programs are operator-donated; the server keeps the
// account funded (~100 user-credits at default fees).
constexpr int64_t kServerZoneProgramAccountTopUp = 10'000'000'000LL;

// Walk <storeDir>/s/ and ensure every regular non-sidecar file has a
// well-formed sidecar pointing at the server's pubkey. Handles two cases:
//   * sidecar missing entirely (operator dropped a fresh file)
//   * sidecar present but stale (size changed, owner not server, or
//     parse-failure). Rewritten in place; /s/ is unmetered so there's no
//     balance to preserve.
// Already-correct sidecars are left alone (no atomic rewrite churn).
//
// Each /s/ file gets a dedicated program account in accountStore_, with a
// fresh ed25519 keypair minted on first reconcile and preserved across
// reboots (the keypair stays in the sidecar). Every reconcile pass tops the
// program account up to the default; the operator funds the program's bankroll.
void reconcileServerZone(CesServer* server, const std::string& dir) {
  namespace fs = std::filesystem;
  fs::path sRoot = fs::path(dir) / "s";
  std::error_code ec;
  if (!fs::exists(sRoot, ec)) return;

  std::array<uint8_t, 32> serverPk{};
  std::memcpy(serverPk.data(),
              server->_serverKeyPair().getPublicKeyAsHash().data(), 32);
  const std::string suffix = kSidecarSuffix;

  for (auto it = fs::recursive_directory_iterator(sRoot, ec);
       !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
    if (!it->is_regular_file()) continue;
    auto cPath = it->path();
    std::string fn = cPath.filename().string();
    // Skip sidecars themselves.
    if (fn.size() >= suffix.size() &&
        fn.compare(fn.size() - suffix.size(), suffix.size(), suffix) == 0)
      continue;

    // Compute the canonical CES name: "/s/<rel>". it->path() is
    // absolute; strip the dir prefix and prepend "/".
    fs::path rel = fs::relative(cPath, fs::path(dir));
    std::string name = "/" + rel.generic_string();

    auto sPath = resolveSidecarPath(dir, name);
    uint64_t size = 0;
    {
      std::error_code sec;
      size = static_cast<uint64_t>(fs::file_size(cPath, sec));
      if (sec) continue;
    }

    Sidecar existing{};
    bool haveExisting = readSidecar(sPath, existing);

    // Preserve an existing non-zero program_pubkey across reboots so
    // already-minted assets stamped with that program identity stay
    // resolvable. Generate a fresh one only on first sight.
    std::array<uint8_t, 32> programPubkey{};
    std::array<uint8_t, 32> programPrivkey{};
    bool existingHasPubkey = haveExisting &&
      sidecarHasProgramAccount(existing);
    if (existingHasPubkey) {
      programPubkey = existing.program_pubkey;
      programPrivkey = existing.program_privkey;
    } else {
      ces::KeyPair kp = ces::KeyPair::generate();
      std::memcpy(programPubkey.data(), kp.getPublicKeyAsHash().data(), 32);
      std::memcpy(programPrivkey.data(), kp.getPrivateKey().data(), 32);
    }

    bool sidecarOk = haveExisting &&
      existing.size == size &&
      existing.owner_pubkey == serverPk &&
      existing.name == name &&
      existingHasPubkey;

    if (!sidecarOk) {
      Sidecar s{};
      s.version = kSidecarVersion;
      s.name = name;
      s.owner_pubkey = serverPk;
      s.program_pubkey = programPubkey;
      s.program_privkey = programPrivkey;
      s.price_per_kb = 0;
      s.size = size;
      s.content_type = inferContentType(name);
      s.created_us = haveExisting && existing.created_us > 0
        ? existing.created_us : getMicrosSinceEpoch();
      s.modified_us = getMicrosSinceEpoch();
      s.last_rent_us = s.modified_us;

      if (writeSidecar(sPath, s)) {
        LOGINFO << "builtin:file /s/ sidecar generated"
                << SVAR(name) << VAR(size);
      } else {
        LOGWARNING << "builtin:file /s/ sidecar write failed"
                   << SVAR(name);
        continue;
      }
    }

    // Top up the program account from thin air. _brrInner creates
    // the account if missing (e.g., recovered from rent exhaustion)
    // and credits otherwise. /s/ programs draw on this for compute
    // supervision + Lua-side ces.transfer / asset minting.
    minx::Hash pubkey{};
    std::memcpy(pubkey.data(), programPubkey.data(), 32);
    server->_l2CreditProgramAccountSync(
      pubkey, kServerZoneProgramAccountTopUp);
  }
}

void fileHandlerStartupReconcile() {
  CesServer* server = gServer.load();
  if (!server) return;
  const std::string& dir = server->_config().cesFileStoreDir;
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  // Auto-generate sidecars for any /s/ files the operator dropped on
  // disk. /s/ is operator-controlled — drop files in <storeDir>/s/,
  // server fills in metadata.
  reconcileServerZone(server, dir);
  StoreMeta m{};
  walkFileStore(dir, [&m](const std::filesystem::path&,
                          const std::filesystem::path&, Sidecar& s) {
    // /s/ files live outside the cap — don't count them.
    if (isServerZone(s.name)) return;
    m.total_files += 1;
    m.total_bytes += s.size;
  });
  std::lock_guard lk(gStoreMetaMutex);
  writeStoreMeta(storeMetaPath(dir), m);
  LOGINFO << "builtin:file store reconciled"
          << VAR(m.total_files) << VAR(m.total_bytes);
}


} // namespace ces

// ---------------------------------------------------------------------------
// Static registration: map protocol name "file" → gFileHandler.
// ---------------------------------------------------------------------------

REGISTER_CESPLEX_BUILTIN("file", ::ces::gFileHandler, FileHandler)

// TU anchor — cesplex/mux.cpp references this via its anchor array.
extern "C" { int file_handler_anchor = 1; }
