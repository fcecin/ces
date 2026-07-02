// file_handler.cpp - builtin:file CesPlex handler (v2)
//
// Disk-backed file storage. This file implements:
//
//   - Name validation + filesystem-path mapping (5-component cap,
//     leading slash, no dotfiles, etc.)
//   - TOML sidecar load/save with write-rename atomicity
//   - Per-server .store.toml guarded by the handler's store-meta mutex
//   - 8 verbs: CREATE, WRITE, READ, STAT (free unsigned), DEPOSIT,
//     WITHDRAW, SET_PRICE, DELETE
//   - Preamble-first wire framing; sig commits to preamble before
//     body bytes arrive; handler can verify+charge before streaming
//   - Server-signed response envelope on every verb (bound to the
//     request's sig hash so clients get a receipt)
//   - Handler loops on one channel: read verb -> serve -> read next verb
//   - Rent GC + startup reconciliation hooks for CesServer
//
// Economic rule: every signed op pays feeQuery from signer's account
// (the nonce/dedup machinery the rest of CES already uses). "Big"
// economic flows (amount deposited, amount withdrawn, write cost,
// read price) go where the spec says - file_balance, or between
// signer and file_balance, as each verb defines. STAT is free.
//
// Fee-discount policy. The per-channel RUDP rates that apply to a
// bound CesPlex channel are discounted at the ChannelMeter tick
// layer under FeeKind::Net (see cesplex/meter.cpp). The per-verb
// feeQuery debits dispatched here against the bound signer are
// intentionally raw - they are the flat anti-spam toll on top of
// the channel-level dynamic pricing. The compute handler discounts
// its per-verb feeQuery via FeeKind::Query because compute jobs are
// discrete one-shot work consuming l1cpu; file-handler verbs are
// bound-channel work whose dynamic component is already priced via
// Net, so the per-verb toll stays flat by design.

#include <ces/cesplex/mux.h>
#include <ces/cesplex/session.h>
#include <ces/l2/file_handler.h>
#include <ces/l2/builtin_site.h>
#include <ces/buffer.h>
#include <ces/ramfilestore.h>
#include <ces/keys.h>
#include <ces/server.h>
#include <ces/types.h>

#include <minx/blog.h>

#include <toml++/toml.hpp>

#include <logkv/store.h>
#include <logkv/bytes.h>

#include <boost/unordered/unordered_flat_map.hpp>

#include <map>
#include <memory>
#include <mutex>
#include <unordered_map>

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
#include <algorithm>
#include <filesystem>
#include <optional>
#include <fstream>
#include <limits>
#include <memory>
#include <mutex>
#include <span>
#include <sstream>
#include <string>
#include <vector>

LOG_MODULE("file");

namespace ces {

namespace {

// ---------------------------------------------------------------------------
// Deletion notify - fire the owning handler's registered callbacks right
// after a file is deleted internally. The callback list + its mutex, the
// store-meta mutex, and the kv cache are all per-server FileHandler members,
// reached from these free helpers via server->fileHandler().
// ---------------------------------------------------------------------------

void notifyDeletion(CesServer* server, const std::string& name) {
  FileHandler* fh = server ? server->fileHandler() : nullptr;
  if (!fh) return;
  std::vector<std::function<void(const std::string&)>> cbs;
  {
    std::lock_guard lk(fh->deletionCallbacksMutex_);
    cbs = fh->deletionCallbacks_; // copy under lock; fire outside
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

// File types stored in the sidecar. A flat file is opaque bytes; a kv file is
// a logkv key-value store whose content path is a directory of logkv files.
constexpr uint8_t kFileTypeFlat = 0;
constexpr uint8_t kFileTypeKv   = 1;

// kv-file verbs. Exec-only except kVerbKvDeposit, which also has a wire path
// (external funders bind /ces/file/1 and fund a key).
constexpr uint8_t kVerbKvCreate  = 0x0b;
constexpr uint8_t kVerbKvPut     = 0x0c;
constexpr uint8_t kVerbKvGet     = 0x0d;
constexpr uint8_t kVerbKvErase   = 0x0e;
constexpr uint8_t kVerbKvIter    = 0x0f;
constexpr uint8_t kVerbKvDeposit = 0x10;
constexpr uint8_t kVerbKvRange   = 0x11;

// Max kv key length (bytes). Values are bounded by kMaxWriteLen like a write.
constexpr size_t kMaxKvKeyLen = 256;

// Hard cap on a KV_RANGE response payload (sum of returned key+value bytes),
// well under the IPC frame so the reply always fits. A caller's requested
// budget is clamped to this; one in-range pair is always returned so a lone
// oversized value can't stall a paginated scan.
constexpr uint64_t kKvRangeMaxBytes = 8u * 1024 * 1024;

constexpr uint16_t kMaxNameLen = 512;
constexpr uint32_t kMaxWriteLen = 1024 * 1024; // 1 MB per WRITE
constexpr uint32_t kMaxReadLen  = 1024 * 1024; // 1 MB per READ
constexpr size_t   kMaxPathComponents = 5;
constexpr uint64_t kMaxFileSize = 64ull * 1024 * 1024 * 1024; // 64 GB

constexpr const char* kSidecarSuffix = ".sidecar.toml";
constexpr const char* kStoreMetaName = ".store.toml";
// Auto-generated catalog of the /s/ zone (see regenerateServerIndex).
constexpr const char* kServerIndexName = "/s/index.html";
// Sidecar schema: `program_pubkey` (32B reference to a real Account in
// accountStore_) replaced the old sidecar-resident `file_balance` pool;
// the file's credits now live in the ledger account store like any other
// account (pays daily rent, supports deposit/withdraw/transfer, shared by
// every running instance). Older sidecars carrying the removed
// content_sha256 field are rejected on load.
constexpr uint32_t kSidecarVersion = 5;

// Microseconds per day - denominator in per-byte-day rent math.
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
// Four mandatory zones - the first path component must be one of:
//   "h" -> /h/<64 hex>/<path...>   (self-owned "home" dir; see dispatchCreate)
//   "f" -> /f/<name>/<path...>    (asset-gated registered namespace)
//   "p" -> /p/<anything>/<...>    (public, first-come-first-served)
//   "s" -> /s/<anything>/<...>    (server-deployed, unmetered, outside
//                                 the cap - only the server's own
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
    // Reject any component starting with '.' - one check covers ".", "..",
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

// Per-KB fee arithmetic. feeFileWrite and feeFileRead are charged
// "credits per 1024 bytes" (ceiling-rounded); at the default values
// a per-byte reading would make a 1 MB file cost 20 B credits. Use
// this for every length -> fee conversion.
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

// ---------------------------------------------------------------------------
// kv file type: a logkv key-value store living in the file's content
// directory. The file driver owns the directory (creation, billing, eviction)
// the same way it owns flat files; logkv only uses the directory. Stores are
// opened lazily and cached, keyed by file name; access is serialized by
// the kv cache mutex (logkv::Store has no internal locking). Keys and values are byte
// strings (logkv::Bytes); logkv treats an empty value as "absent", so a kv
// PUT of an empty value is an erase and callers must not rely on storing one.
// ---------------------------------------------------------------------------
// Ordered backing (std::map, not unordered): keys iterate and bisect in sorted
// byte order, so range queries are native (lower_bound/upper_bound) and RBSR
// gets the sorted keyspace it needs. logkv::Store needs only standard
// associative API, which std::map provides.
//
// The order is UNSIGNED byte order (memcmp). logkv::Bytes is vector<char> whose
// default operator< compares signed chars, which would sort a 0x80-prefixed key
// before a 0x00-prefixed one; DHT keys are hashes treated as unsigned, so the
// comparator must match memcmp. A 2-arg alias carries the comparator through
// logkv::Store's M<K,V> template parameter.
struct KvKeyLess {
  bool operator()(const logkv::Bytes& a, const logkv::Bytes& b) const {
    size_t n = a.size() < b.size() ? a.size() : b.size();
    int c = n ? std::memcmp(a.data(), b.data(), n) : 0;
    if (c != 0) return c < 0;
    return a.size() < b.size();
  }
};
template <class K, class V> using KvMap = std::map<K, V, KvKeyLess>;
using KvStore = logkv::Store<KvMap, logkv::Bytes, logkv::Bytes>;

}  // namespace (anon)

// Per-server kv-store cache: the open-store map plus the mutex serializing
// access to it and to logkv (which has no internal locking). Held by the
// FileHandler; the free helpers below reach it via server->fileHandler()->kv_.
// TODO: those free helpers take CesServer* and round-trip server->fileHandler()
// to get back to effectively `this`. Passing the FileHandler* (or making them
// methods) would drop the round-trip; only valid because they run inside a
// mounted handler.
struct FileKvCache {
  std::mutex mutex;
  std::unordered_map<std::string, std::unique_ptr<KvStore>> stores;
};

namespace {

// Open (or return the cached) logkv store for kv-file `name`. The content
// directory must already exist (the driver creates it at CREATE). Returns
// nullptr if the directory is missing or logkv fails to load. Caller holds
// the kv cache mutex.
KvStore* kvStoreOpenLocked(CesServer* server, const std::string& dir,
                           const std::string& name) {
  auto& stores = server->fileHandler()->kv_->stores;
  auto cPath = resolveContentPath(dir, name);
  // Cache key is the ABSOLUTE content path, not the bare CES name: a logical
  // name reused across store dirs (a stop/start with dir reuse) must not alias.
  std::string key = cPath.string();
  std::error_code ec;
  auto it = stores.find(key);
  if (it != stores.end()) {
    // A cached store whose directory was deleted (rent GC / DELETE) is stale:
    // drop it (closes logkv's file handles) and fail. The op's sidecar read
    // reports FILE_NOT_FOUND. This lazy check lets delete paths just
    // remove_all the dir without taking the kv mutex (avoids a lock-order
    // inversion with gcReclaim, which deletes under the store-meta mutex).
    if (std::filesystem::is_directory(cPath, ec)) return it->second.get();
    stores.erase(it);
    return nullptr;
  }
  if (!std::filesystem::is_directory(cPath, ec)) return nullptr;
  try {
    auto st = std::make_unique<KvStore>(cPath.string());   // loads existing data
    KvStore* raw = st.get();
    stores.emplace(key, std::move(st));
    return raw;
  } catch (...) {
    return nullptr;
  }
}

// ces::Bytes (vector<uint8_t>) <-> logkv::Bytes (vector<char>).
inline logkv::Bytes toLogkvBytes(const ces::Bytes& b) {
  const char* p = reinterpret_cast<const char*>(b.data());
  return logkv::Bytes(p, p + b.size());
}
inline ces::Bytes fromLogkvBytes(const logkv::Bytes& b) {
  const uint8_t* p = reinterpret_cast<const uint8_t*>(b.data());
  return ces::Bytes(p, p + b.size());
}

// ---------------------------------------------------------------------------
// Per-cell billing header. Every kv value is stored as
//   [balance u64 BE][last_charged_us u64 BE][user bytes]
// The file service owns the 16-byte header: KV_DEPOSIT funds it, the daily
// sweep charges rent against it and erases the key at balance 0, and GET strips
// it (the program sees only its own bytes). Invariant: a store's program-account
// balance equals the sum of its cell balances.
// ---------------------------------------------------------------------------
constexpr size_t kKvHeaderLen = 16;

struct KvCell {
  uint64_t balance = 0;
  uint64_t lastChargedUs = 0;
  const char* user = nullptr;   // pointer into the stored value (after header)
  size_t userLen = 0;
};

// Parse a stored value into its header + user span. Returns false if the value
// is too short to hold a header (the file service writes every kv value, so
// this is a fail-safe).
inline bool kvCellParse(const logkv::Bytes& v, KvCell& out) {
  if (v.size() < kKvHeaderLen) return false;
  const uint8_t* p = reinterpret_cast<const uint8_t*>(v.data());
  out.balance       = ces::Buffer::peek<uint64_t>(p);
  out.lastChargedUs = ces::Buffer::peek<uint64_t>(p + 8);
  out.user    = v.data() + kKvHeaderLen;
  out.userLen = v.size() - kKvHeaderLen;
  return true;
}

// Build a stored value from header fields + user bytes (raw pointer span).
inline logkv::Bytes kvCellBuild(uint64_t balance, uint64_t lastChargedUs,
                                const char* user, size_t userLen) {
  logkv::Bytes v;
  v.resize(kKvHeaderLen + userLen);
  uint8_t* p = reinterpret_cast<uint8_t*>(v.data());
  ces::Buffer::poke<uint64_t>(p, balance);
  ces::Buffer::poke<uint64_t>(p + 8, lastChargedUs);
  if (userLen) std::memcpy(v.data() + kKvHeaderLen, user, userLen);
  return v;
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
  // - STAT never returns it (allowlist), and the sidecar is unreachable as
  // content (.sidecar.toml is a reserved suffix). Inbound transfers work
  // normally; the account pays daily rent like any account.
  std::array<uint8_t, 32> program_pubkey{};
  std::array<uint8_t, 32> program_privkey{};
  uint64_t price_per_kb = 0;
  uint64_t size = 0;
  uint64_t created_us = 0;
  uint64_t modified_us = 0;
  // Microseconds since epoch of the last moment rent was charged
  // against this file. Every non-DEPOSIT op rolls rent forward from
  // this to now before proceeding. Initialized to created_us at
  // CREATE.
  uint64_t last_rent_us = 0;
  // Lazily-computed sha256(content || path) used by authentic
  // asset minting. All-zero means "not yet computed" - recompute
  // on demand. Cleared back to all-zero by any content-mutating
  // verb (WRITE, APPEND, RESIZE) so the next mint recomputes.
  std::array<uint8_t, 32> program_hash{};
  // kFileTypeFlat (opaque bytes) or kFileTypeKv (logkv key-value store whose
  // content path is a directory). Optional in the sidecar; sidecars written
  // before this field load as flat.
  uint8_t type = kFileTypeFlat;
};

bool writeSidecar(const std::filesystem::path& path, const Sidecar& s) {
  // Serialize through tomlplusplus (symmetric with readSidecar) so name is
  // escaped. A hand-rolled `key = "val"` dump corrupts the sidecar when that
  // field contains quotes or newlines, which it can:
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
  tbl.insert_or_assign("created_us", static_cast<int64_t>(s.created_us));
  tbl.insert_or_assign("modified_us", static_cast<int64_t>(s.modified_us));
  tbl.insert_or_assign("last_rent_us", static_cast<int64_t>(s.last_rent_us));
  tbl.insert_or_assign("program_hash",
                       hexOf(s.program_hash.data(), s.program_hash.size()));
  tbl.insert_or_assign("type", static_cast<int64_t>(s.type));

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
  // type is optional (sidecars predating it load as flat).
  uint64_t typeVal = kFileTypeFlat;
  getU64("type", typeVal);
  s.type = static_cast<uint8_t>(typeVal);
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
// with STORE_FULL without rescanning - the just-completed GC already
// reflects the best we can do.
//
// This is also the upfront-rent window: every op that grows a file's
// size (CREATE, APPEND, RESIZE-grow) requires the file_balance to
// be able to cover 15 minutes of rent on the new bytes. Reasoning:
// a griefer can pin bytes in the cap for at most one GC cycle. Making
// them prepay that cycle's rent forces the grief to be economically
// painful - for the size of cap they're locking, at the rent rate
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
// hold the store-meta mutex. Creates .store.toml if missing.
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
// Uses __uint128_t for safety - realistic inputs don't come close to
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
// program_pubkey (defensive - shouldn't happen post-v5).
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

// Top up a /s/ program account to the server's per-extension local budget (credit
// only the deficit, never burn). Shared by the boot/lazy reconcile and the daily
// sweep. cap 0 = off. Returns true if it credited.
static bool topUpProgramAccountToCap(CesServer* server, const Sidecar& sc) {
  if (!server || !sidecarHasProgramAccount(sc)) return false;
  uint64_t cap = server->extLocalBudget();
  if (cap == 0) return false;
  uint64_t bal = readProgramAccountBalance(server, sc);
  if (bal < cap) { creditProgramAccount(server, sc, cap - bal); return true; }
  return false;
}

// Reconcile one /s/ file: ensure it has a valid server-owned sidecar (minting a
// fresh program keypair on first sight, preserving an existing one across
// reboots, rewriting a stale one) and top up its program account. Pure disk
// plus a sync hop to logicStrand_ for the credit, so it MUST run off
// logicStrand_ (the file/rpc strand or boot). Returns the resulting sidecar in
// `out`; false if the content file is unreadable. Shared by the boot scan
// (reconcileServerZone) and the on-access lazy path (loadSidecar).
bool reconcileOneServerZoneFile(CesServer* server, const std::string& dir,
                                const std::string& name, Sidecar& out) {
  namespace fs = std::filesystem;
  auto cPath = resolveContentPath(dir, name);
  std::error_code sec;
  uint64_t size = static_cast<uint64_t>(fs::file_size(cPath, sec));
  if (sec) return false;

  std::array<uint8_t, 32> serverPk{};
  std::memcpy(serverPk.data(),
              server->_serverKeyPair().getPublicKeyAsHash().data(), 32);

  auto sPath = resolveSidecarPath(dir, name);
  Sidecar existing{};
  bool haveExisting = readSidecar(sPath, existing);

  // Preserve an existing non-zero program keypair across reboots so assets
  // already stamped with that identity stay resolvable; generate a fresh one
  // only on first sight.
  std::array<uint8_t, 32> programPubkey{};
  std::array<uint8_t, 32> programPrivkey{};
  bool existingHasPubkey = haveExisting && sidecarHasProgramAccount(existing);
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

  out = existing;
  if (!sidecarOk) {
    Sidecar s{};
    s.version = kSidecarVersion;
    s.name = name;
    s.owner_pubkey = serverPk;
    s.program_pubkey = programPubkey;
    s.program_privkey = programPrivkey;
    s.price_per_kb = 0;
    s.size = size;
    s.created_us = haveExisting && existing.created_us > 0
      ? existing.created_us : getMicrosSinceEpoch();
    s.modified_us = getMicrosSinceEpoch();
    s.last_rent_us = s.modified_us;
    if (!writeSidecar(sPath, s)) {
      LOGWARNING << "/s/ sidecar write failed" << SVAR(name);
      return false;
    }
    LOGDEBUG << "/s/ sidecar generated" << SVAR(name) << VAR(size);
    out = s;
  }

  // Top up the program account to the per-extension local budget (deficit only).
  topUpProgramAccountToCap(server, out);
  return true;
}

// Fetch a file's sidecar by name. For the /s/ zone, if the sidecar is missing
// but the content file is present (the operator dropped it on disk without a
// signed CREATE), mint it on the fly via the same reconcile the boot scan runs
// -- so "cp into /s/ and use it" works without a restart. The generated /s/
// catalog and the bundled welcome site are static server content whose sidecars
// are seeded elsewhere; they are never auto-minted a program account. MUST run
// off logicStrand_ (the lazy mint may top up the program account via a sync
// hop). Non-/s/ names: a plain readSidecar, no auto-create.
bool loadSidecar(CesServer* server, const std::string& dir,
                 const std::string& name, Sidecar& sc) {
  auto sPath = resolveSidecarPath(dir, name);
  if (readSidecar(sPath, sc)) return true;
  if (!isServerZone(name)) return false;
  if (name == kServerIndexName || isBuiltinSitePath(name)) return false;
  if (!server) return false;
  return reconcileOneServerZoneFile(server, dir, name, sc);
}

bool chargeRentOrDelete(CesServer* server,
                        const std::filesystem::path& cPath,
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

  if (!server) return false;
  minx::Hash pubkey{};
  std::memcpy(pubkey.data(), sc.program_pubkey.data(), 32);
  auto r = server->_l2DebitProgramAccountSync(
    pubkey, static_cast<int64_t>(owed));
  bool dead = !r.ok;

  if (dead) {
    // Dead. Delete and bump meta.
    std::error_code ec;
    if (sc.type == kFileTypeKv) std::filesystem::remove_all(cPath, ec);
    else                        std::filesystem::remove(cPath, ec);
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
      std::lock_guard lk(server->fileHandler()->storeMetaMutex_);
      adjustStoreMeta(dir, -1, -static_cast<int64_t>(sc.size));
    }
    notifyDeletion(server, sc.name);
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
// is a CES core feature, so its host is always the CesServer - recover the
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

// JIT rent GC - forward decl so dispatchers that grow total_bytes
// (CREATE, APPEND, RESIZE-grow) can call it below. Caller must hold
// the store-meta mutex.
uint64_t gcReclaim(CesServer* server, const std::string& dir, int64_t feeRent,
                   uint64_t bytesNeeded);

// Cap-and-GC helper. Returns CES_OK if `addBytes` fits under `cap`
// (possibly after a debounced GC), CES_ERROR_STORE_FULL otherwise.
// Caller must hold the store-meta mutex. Does not bump total_bytes -
// caller commits after the op's disk work succeeds.
uint8_t checkCapAndMaybeGc(CesServer* server,
                           const std::string& dir,
                           uint64_t cap,
                           int64_t feeRent,
                           uint64_t addBytes);
void dispatchWrite  (std::shared_ptr<ReqCtx> ctx, ces::Bytes pre);
void dispatchRead   (std::shared_ptr<ReqCtx> ctx, ces::Bytes pre);
void dispatchDeposit(std::shared_ptr<ReqCtx> ctx, ces::Bytes pre);
void dispatchKvDeposit(std::shared_ptr<ReqCtx> ctx, ces::Bytes pre);
void dispatchWithdraw(std::shared_ptr<ReqCtx> ctx, ces::Bytes pre);
void dispatchSetPrice(std::shared_ptr<ReqCtx> ctx, ces::Bytes pre);
void dispatchDelete (std::shared_ptr<ReqCtx> ctx, ces::Bytes pre);

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
    // with their server private key - same one in server.toml.
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

// ---------------------------------------------------------------------------
// /s/ auto-index - the one zone where enumeration is safe.
//
// /s/ is the only WRITE-operator-only zone (server key alone can create/write
// there), so listing it can only ever reveal operator-curated, public content -
// no untrusted uploads, no abuse surface. Every other zone is deliberately
// non-enumerable (knowing the path is the capability). So we keep a generated
// /s/index.html catalog in sync: regenerated on every /s/ file-set change, and
// at boot if it is missing.
//
// Pure disk I/O on the file/rpc strand: it never touches logicStrand_ (no fee,
// no program account), and it writes the index DIRECTLY here - not through the
// CREATE verb - so it can never re-trigger itself (no churn loop). /s/ changes
// only when the operator acts, so unconditional regen is fine forever.
void regenerateServerIndex(CesServer* server, const std::string& dir) {
  if (!server) return;
  namespace fs = std::filesystem;
  std::error_code ec;
  fs::path sRoot = fs::path(dir) / "s";
  if (!fs::exists(sRoot, ec)) return;

  const std::string suffix = kSidecarSuffix;
  std::vector<std::string> names;   // CES names, e.g. "/s/dice.lua"
  for (auto it = fs::recursive_directory_iterator(sRoot, ec);
       !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
    if (!it->is_regular_file()) continue;
    std::string fn = it->path().filename().string();
    if (fn.size() >= suffix.size() &&
        fn.compare(fn.size() - suffix.size(), suffix.size(), suffix) == 0)
      continue;                                   // skip sidecars
    fs::path rel = fs::relative(it->path(), fs::path(dir), ec);
    if (ec) { ec.clear(); continue; }
    std::string nm = "/" + rel.generic_string();
    if (nm == kServerIndexName) continue;         // never list the index itself
    names.push_back(std::move(nm));
  }
  std::sort(names.begin(), names.end());

  std::string html =
    "<!doctype html><html lang=en><meta charset=utf-8>"
    "<meta name=viewport content=\"width=device-width,initial-scale=1\">"
    "<title>/s/ \xe2\x80\x94 server catalog</title>"
    "<style>body{font:16px/1.6 system-ui,sans-serif;max-width:48rem;"
    "margin:2.5rem auto;padding:0 1rem;color:#1c1c1e}h1{font-size:1.4rem}"
    "ul{list-style:none;padding:0}li{padding:.3em 0;border-bottom:1px solid #eee}"
    "a{color:#0a7d33;text-decoration:none}a:hover{text-decoration:underline}"
    "footer{margin-top:1.5rem;color:#999;font-size:.85rem}</style>"
    "<h1>/s/ \xe2\x80\x94 server catalog</h1><ul>";
  for (const auto& nm : names)
    html += "<li><a href=\"" + nm + "\">" + nm + "</a></li>";
  html += "</ul><footer>auto-generated index of the operator-curated /s/ zone ("
          + std::to_string(names.size()) + " files)</footer></html>\n";

  // Write content atomically (temp + rename) so a concurrent READ never sees a
  // partial index.
  fs::path cPath = resolveContentPath(dir, kServerIndexName);
  fs::create_directories(cPath.parent_path(), ec);
  fs::path tmp = cPath; tmp += ".tmp";
  {
    std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
    if (!f) { LOGWARNING << "/s/ index: open failed"; return; }
    f.write(html.data(), static_cast<std::streamsize>(html.size()));
    if (!f.good()) { LOGWARNING << "/s/ index: write failed"; return; }
  }
  fs::rename(tmp, cPath, ec);
  if (ec) {
    LOGWARNING << "/s/ index: rename failed";
    std::filesystem::remove(tmp, ec);
    return;
  }

  // Minimal sidecar so READ serves it (owner = server; no program account - a
  // generated static file, not a program). reconcileServerZone skips this name,
  // so the zero program account is never "fixed up". Pure disk, no logicStrand_.
  Sidecar s{};
  s.version = kSidecarVersion;
  s.name = kServerIndexName;
  std::memcpy(s.owner_pubkey.data(),
              server->_serverKeyPair().getPublicKeyAsHash().data(), 32);
  s.price_per_kb = 0;
  s.size = html.size();
  s.created_us = getMicrosSinceEpoch();
  s.modified_us = s.created_us;
  s.last_rent_us = s.created_us;
  writeSidecar(resolveSidecarPath(dir, kServerIndexName), s);
  LOGDEBUG << "/s/ index regenerated" << VAR(names.size());
}

// Hook fired at the success of a /s/ file-set change (CREATE / DELETE). Guarded
// to the /s/ zone and self-bypassing (the index write above never goes through
// the verbs, so this can't recurse). Runs on the file/rpc strand.
void noteServerZoneMutation(CesServer* server, const std::string& name) {
  if (!isServerZone(name)) return;
  if (name == kServerIndexName) return;          // recursion guard (belt + braces)
  if (!server) return;
  regenerateServerIndex(server, server->_config().cesFileStoreDir);
}

// ---------------------------------------------------------------------------
// A verb is a pure body plus an injected billing policy, run inside one ledger
// transaction (CesServer::_l2Transact). bill returns {rc, duplicate}: rc != OK
// is an error; duplicate is an idempotent replay (no re-credit); rc == OK and
// not duplicate proceeds with the mutation. The session adapter supplies
// signerBilling (network signer + dedup); the in-process adapter supplies a
// source-balance policy.
struct L2ChargeResult { uint8_t rc; bool duplicate; };
using L2Billing = std::function<L2ChargeResult(ces::LedgerTxn&, int64_t cost)>;

// Network billing: signer pays `cost`, with NONCELESS replay dedup.
inline L2Billing signerBilling(const ces::PublicKey& signer, uint32_t reqNonce,
                               uint64_t sigHash, int64_t errFee) {
  minx::Hash signerHash = signer.getHash();
  return [signerHash, reqNonce, sigHash, errFee]
         (ces::LedgerTxn& t, int64_t cost) -> L2ChargeResult {
    if (reqNonce == CES_NONCELESS && t.isReplay(sigHash)) return { CES_OK, true };
    uint8_t rc = t.signerSpend(signerHash, static_cast<uint64_t>(cost), reqNonce, errFee);
    if (rc != CES_OK) return { rc, false };
    if (reqNonce == CES_NONCELESS) t.recordDedup(sigHash);
    return { CES_OK, false };
  };
}

struct CreateOutcome { uint8_t status; uint64_t fileBalance; uint64_t costDebited; };

// CREATE core, shared by both adapters; runs after the async zone gate.
// Off-strand: path/cap/GC/upfront checks, keypair gen, file + sidecar write.
// One transaction: dedup, charge (feeQuery + initialDeposit), account mint.
CreateOutcome createCore(CesServer* server, const std::string& name,
                         uint64_t size, uint64_t pricePerKb,
                         uint64_t initialDeposit, const minx::Hash& caller,
                         const L2Billing& bill, uint8_t type = kFileTypeFlat) {
  const auto& cfg = server->_config();
  uint8_t rc = checkPathConflict(cfg.cesFileStoreDir, name, /*createMode=*/true);
  if (rc != CES_OK) return { rc, 0, 0 };
  const bool serverZone = isServerZone(name);
  if (!serverZone) {
    std::lock_guard lk(server->fileHandler()->storeMetaMutex_);
    uint8_t capRc = checkCapAndMaybeGc(server, cfg.cesFileStoreDir, cfg.cesFileStoreMaxBytes,
                                       cfg.feeFileRent, size);
    if (capRc != CES_OK) return { capRc, 0, 0 };
  }
  uint64_t upfrontBurn = 0;
  if (!serverZone) {
    upfrontBurn = computeOwedRent(size, cfg.feeFileRent, 0, kGcDebounceUs);
    if (initialDeposit < upfrontBurn) return { CES_ERROR_INSUFFICIENT_BALANCE, 0, 0 };
  } else {
    initialDeposit = 0;       // /s/ unmetered: file_balance is decorative
  }
  const uint64_t programAccountInitial =
      initialDeposit > upfrontBurn ? initialDeposit - upfrontBurn : 0;
  const uint64_t costDebited =
      static_cast<uint64_t>(cfg.feeQuery) + initialDeposit;

  ces::KeyPair kp = ces::KeyPair::generate();   // off-strand; never on the logic strand
  minx::Hash progPub = kp.getPublicKeyAsHash();
  minx::Hash progPriv = kp.getPrivateKey();

  uint8_t status = CES_ERROR_INTERNAL;
  bool duplicate = false;
  server->_l2Transact([&](ces::LedgerTxn& t) {
    L2ChargeResult c = bill(t, static_cast<int64_t>(costDebited));
    if (c.rc != CES_OK) { status = c.rc; return; }
    if (c.duplicate) { duplicate = true; status = CES_OK; return; }
    t.credit(progPub, static_cast<int64_t>(programAccountInitial));   // mint
    status = CES_OK;
  });
  if (status != CES_OK) return { status, 0, 0 };
  if (duplicate) return { CES_OK, programAccountInitial, costDebited };

  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  std::error_code ec;
  std::filesystem::create_directories(cPath.parent_path(), ec);
  if (ec) return { CES_ERROR_INTERNAL, 0, 0 };
  if (type == kFileTypeKv) {
    // kv content is a directory: the driver creates it, logkv uses it.
    std::filesystem::create_directory(cPath, ec);
    if (ec) return { CES_ERROR_INTERNAL, 0, 0 };
    std::lock_guard<std::mutex> lk(server->fileHandler()->kv_->mutex);
    if (!kvStoreOpenLocked(server, cfg.cesFileStoreDir, name)) {
      std::filesystem::remove_all(cPath, ec);
      return { CES_ERROR_INTERNAL, 0, 0 };
    }
  } else {
    { std::ofstream f(cPath, std::ios::binary | std::ios::trunc);
      if (!f) return { CES_ERROR_INTERNAL, 0, 0 }; }
    std::filesystem::resize_file(cPath, size, ec);
    if (ec) return { CES_ERROR_INTERNAL, 0, 0 };
  }

  Sidecar s{};
  s.version = kSidecarVersion;
  s.name = name;
  std::memcpy(s.owner_pubkey.data(), caller.data(), 32);
  std::memcpy(s.program_pubkey.data(), progPub.data(), 32);
  std::memcpy(s.program_privkey.data(), progPriv.data(), 32);
  s.price_per_kb = pricePerKb;
  s.size = size;
  s.type = type;
  s.created_us = getMicrosSinceEpoch();
  s.modified_us = s.created_us;
  s.last_rent_us = s.created_us;
  if (!writeSidecar(sPath, s)) {
    std::filesystem::remove(cPath, ec);
    return { CES_ERROR_INTERNAL, 0, 0 };
  }
  if (!serverZone) {
    std::lock_guard lk(server->fileHandler()->storeMetaMutex_);
    adjustStoreMeta(cfg.cesFileStoreDir, +1, static_cast<int64_t>(size));
  }
  noteServerZoneMutation(server, name);
  return { CES_OK, programAccountInitial, costDebited };
}

void dispatchCreate(std::shared_ptr<ReqCtx> ctx, ces::Bytes pre) {
  ces::Buffer buf(std::move(pre));
  uint64_t size = 0, pricePerKb = 0, initialDeposit = 0;
  std::string name;
  try {
    size = buf.get<uint64_t>();
    pricePerKb = buf.get<uint64_t>();
    initialDeposit = buf.get<uint64_t>();
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
    [ctx, size, pricePerKb, initialDeposit, name]
    (uint8_t zoneRc) mutable {
    if (zoneRc != CES_OK) { sendErrorAndLoop(ctx, zoneRc); return; }

    const auto& cfg = reqServer(ctx)->_config();
    CreateOutcome out = createCore(
      reqServer(ctx), name, size, pricePerKb, initialDeposit,
      ctx->bound.boundPubkey.getHash(),
      signerBilling(ctx->bound.boundPubkey, ctx->reqNonce, ctx->reqSigHash,
                    static_cast<int64_t>(cfg.getFeeError())));
    if (out.status != CES_OK) { sendErrorAndLoop(ctx, out.status); return; }
    ces::Bytes pre;
    ces::Buffer::put<uint64_t>(pre, out.fileBalance);
    ces::Buffer::put<uint64_t>(pre, out.costDebited);
    sendResponseAndLoop(ctx, CES_OK, std::move(pre));
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

struct WriteOutcome { uint8_t status; uint64_t balance; };

// WRITE core: overwrite [offset, offset+len) with `body`. feeQuery via bill +
// writeCost from the target program account in one transaction. writeCost
// balance is checked before the fee, so an insufficient target burns no fee and
// never touches the source.
WriteOutcome writeCore(CesServer* server, const std::string& name,
                       uint64_t offset, const ces::Bytes& body,
                       const minx::Hash& caller, const L2Billing& bill) {
  uint32_t length = static_cast<uint32_t>(body.size());
  if (length == 0 || length > kMaxWriteLen) return { CES_ERROR_BAD_INPUT, 0 };
  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) return { rc, 0 };
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) return { CES_ERROR_FILE_NOT_FOUND, 0 };
  if (!chargeRentOrDelete(server, cPath, sPath, sc, cfg.feeFileRent, cfg.cesFileStoreDir))
    return { CES_ERROR_FILE_NOT_FOUND, 0 };
  if (std::memcmp(sc.owner_pubkey.data(), caller.data(), 32) != 0)
    return { CES_ERROR_NOT_OWNER, 0 };
  if (offset > sc.size || offset + uint64_t(length) > sc.size)
    return { CES_ERROR_BAD_INPUT, 0 };
  uint64_t writeCost = isServerZone(name) ? 0 : kbCeil(length) * uint64_t(cfg.feeFileWrite);
  writeSidecar(sPath, sc);     // persist rent advance before disk
  minx::Hash prog{};
  std::memcpy(prog.data(), sc.program_pubkey.data(), 32);

  uint8_t status = CES_ERROR_INTERNAL;
  bool duplicate = false;
  uint64_t newBal = 0;
  server->_l2Transact([&](ces::LedgerTxn& t) {
    if (writeCost > 0 && t.balance(prog) < static_cast<int64_t>(writeCost)) {
      status = CES_ERROR_INSUFFICIENT_BALANCE; return;          // before fee
    }
    L2ChargeResult c = bill(t, static_cast<int64_t>(cfg.feeQuery));
    if (c.rc != CES_OK) { status = c.rc; return; }
    if (c.duplicate) { duplicate = true; status = CES_OK; newBal = static_cast<uint64_t>(t.balance(prog)); return; }
    if (writeCost > 0) t.debitAccount(prog, writeCost);
    newBal = static_cast<uint64_t>(t.balance(prog));
    status = CES_OK;
  });
  if (status != CES_OK) return { status, 0 };
  if (!duplicate) {
    FILE* fp = std::fopen(cPath.string().c_str(), "rb+");
    if (!fp) return { CES_ERROR_INTERNAL, 0 };
    if (std::fseek(fp, static_cast<long>(offset), SEEK_SET) != 0) {
      std::fclose(fp); return { CES_ERROR_INTERNAL, 0 };
    }
    size_t wrote = std::fwrite(body.data(), 1, body.size(), fp);
    std::fflush(fp); std::fclose(fp);
    if (wrote != body.size()) return { CES_ERROR_INTERNAL, 0 };
    Sidecar sc2{};
    if (!readSidecar(sPath, sc2)) return { CES_ERROR_INTERNAL, 0 };
    sc2.modified_us = getMicrosSinceEpoch();
    sc2.program_hash.fill(0);    // content changed -> invalidate cached hash
    if (!writeSidecar(sPath, sc2)) return { CES_ERROR_INTERNAL, 0 };
  }
  return { CES_OK, newBal };
}

void dispatchWrite(std::shared_ptr<ReqCtx> ctx, ces::Bytes pre) {
  // Parse + length-bound must precede the body stream (close on failure, since
  // the body is in flight). The body is always consumed before writeCore runs,
  // so every post-stream outcome can loop (the wire stays in sync).
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
  ces::PublicKey signer = ctx->bound.boundPubkey;
  uint32_t reqNonce = ctx->reqNonce;
  uint64_t sigHash = ctx->reqSigHash;
  int64_t errFee = static_cast<int64_t>(reqServer(ctx)->_config().getFeeError());
  auto body = std::make_shared<ces::Bytes>(length);

  boost::asio::async_read(
    *ctx->stream, boost::asio::buffer(*body),
    [ctx, offset, contentHash, name, signer, reqNonce, sigHash, errFee, body]
    (const boost::system::error_code& ec, std::size_t) {
      if (ec) return;   // stream dead
      minx::Hash got = ces::sha256(body->data(), body->size());
      if (std::memcmp(got.data(), contentHash.data(), 32) != 0) {
        sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
      }
      WriteOutcome out = writeCore(
        reqServer(ctx), name, offset, *body, signer.getHash(),
        signerBilling(signer, reqNonce, sigHash, errFee));
      if (out.status != CES_OK) { sendErrorAndLoop(ctx, out.status); return; }
      ces::Bytes resp;
      ces::Buffer::put<uint64_t>(resp, out.balance);
      sendResponseAndLoop(ctx, CES_OK, std::move(resp));
    });
}

// ---------------------------------------------------------------------------
// Dispatch: READ
//   preamble (after reqNonce):
//     u64 offset, u32 length, u16 name_len, name
// ---------------------------------------------------------------------------

struct ReadOutcome { uint8_t status; ces::Bytes data; };

// READ core: three-cost model in one transaction. Signer pays feeQuery + IO +
// price; the price portion credits the file's program account for a non-owner,
// non-duplicate read. The disk read runs off-strand; a duplicate re-reads the
// unchanged bytes without re-crediting.
ReadOutcome readCore(CesServer* server, const std::string& name,
                     uint64_t offset, uint32_t length, const minx::Hash& caller,
                     const L2Billing& bill) {
  if (length == 0 || length > kMaxReadLen) return { CES_ERROR_BAD_INPUT, {} };
  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) return { rc, {} };
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!loadSidecar(server, cfg.cesFileStoreDir, name, sc)) return { CES_ERROR_FILE_NOT_FOUND, {} };
  if (!chargeRentOrDelete(server, cPath, sPath, sc, cfg.feeFileRent, cfg.cesFileStoreDir))
    return { CES_ERROR_FILE_NOT_FOUND, {} };
  writeSidecar(sPath, sc);
  if (offset > sc.size || offset + uint64_t(length) > sc.size)
    return { CES_ERROR_BAD_INPUT, {} };

  const bool isOwner = (std::memcmp(sc.owner_pubkey.data(), caller.data(), 32) == 0);
  const bool serverZone = isServerZone(name);
  const uint64_t readIoCost = serverZone ? 0 : kbCeil(length) * uint64_t(cfg.feeFileRead);
  const uint64_t readPrice = (!serverZone && !isOwner) ? kbCeil(length) * sc.price_per_kb : 0;
  const int64_t cost = static_cast<int64_t>(cfg.feeQuery) +
                       static_cast<int64_t>(readIoCost) + static_cast<int64_t>(readPrice);
  minx::Hash prog{};
  std::memcpy(prog.data(), sc.program_pubkey.data(), 32);

  uint8_t status = CES_ERROR_INTERNAL;
  bool credited = false;
  server->_l2Transact([&](ces::LedgerTxn& t) {
    L2ChargeResult c = bill(t, cost);
    if (c.rc != CES_OK) { status = c.rc; return; }
    if (!c.duplicate && readPrice > 0) {     // owner already excluded (readPrice==0)
      t.credit(prog, static_cast<int64_t>(readPrice));
      credited = true;
    }
    status = CES_OK;
  });
  if (status != CES_OK) return { status, {} };
  if (credited) { sc.modified_us = getMicrosSinceEpoch(); writeSidecar(sPath, sc); }

  std::ifstream f(cPath, std::ios::binary);
  if (!f) return { CES_ERROR_INTERNAL, {} };
  f.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
  ces::Bytes data(length);
  f.read(reinterpret_cast<char*>(data.data()), length);
  if (f.gcount() != static_cast<std::streamsize>(length)) return { CES_ERROR_INTERNAL, {} };
  return { CES_OK, std::move(data) };
}

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
  const auto& cfg = reqServer(ctx)->_config();
  ReadOutcome out = readCore(
    reqServer(ctx), name, offset, length, ctx->bound.boundPubkey.getHash(),
    signerBilling(ctx->bound.boundPubkey, ctx->reqNonce, ctx->reqSigHash,
                  static_cast<int64_t>(cfg.getFeeError())));
  if (out.status != CES_OK) { sendErrorAndLoop(ctx, out.status); return; }
  // [u64 length][u8[32] sha256_of_range] + body
  minx::Hash h = ces::sha256(out.data.data(), out.data.size());
  ces::Bytes resp;
  ces::Buffer::put<uint64_t>(resp, uint64_t(out.data.size()));
  resp.insert(resp.end(), h.begin(), h.end());
  sendResponseAndLoop(ctx, CES_OK, std::move(resp), std::move(out.data));
}

// ---------------------------------------------------------------------------
// Dispatch: DEPOSIT
//   preamble (after reqNonce):
//     u64 amount, u16 name_len, name
// ---------------------------------------------------------------------------

struct DepositOutcome { uint8_t status; uint64_t balance; };

// DEPOSIT core: credit a file's program account, charged via `bill`. One body,
// one strand transaction (dedup + debit + credit + balance, atomic).
DepositOutcome depositCore(CesServer* server, const std::string& name,
                           uint64_t amount, const L2Billing& bill) {
  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) return { rc, 0 };
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) return { CES_ERROR_FILE_NOT_FOUND, 0 };
  minx::Hash prog{};
  std::memcpy(prog.data(), sc.program_pubkey.data(), 32);
  const int64_t cost = static_cast<int64_t>(cfg.feeQuery) +
                       static_cast<int64_t>(amount);

  uint8_t status = CES_ERROR_INTERNAL;
  uint64_t bal = 0;
  bool mutated = false;
  server->_l2Transact([&](ces::LedgerTxn& t) {
    L2ChargeResult c = bill(t, cost);
    if (c.rc != CES_OK) { status = c.rc; return; }
    if (c.duplicate)    { status = CES_OK; bal = static_cast<uint64_t>(t.balance(prog)); return; }
    t.credit(prog, static_cast<int64_t>(amount));
    status = CES_OK; bal = static_cast<uint64_t>(t.balance(prog)); mutated = true;
  });
  if (status == CES_OK && mutated) {
    sc.modified_us = getMicrosSinceEpoch();
    writeSidecar(sPath, sc);
  }
  return { status, bal };
}

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
  const auto& cfg = reqServer(ctx)->_config();
  DepositOutcome out = depositCore(
    reqServer(ctx), name, amount,
    signerBilling(ctx->bound.boundPubkey, ctx->reqNonce, ctx->reqSigHash,
                  static_cast<int64_t>(cfg.getFeeError())));
  if (out.status != CES_OK) { sendErrorAndLoop(ctx, out.status); return; }
  ces::Bytes resp;
  ces::Buffer::put<uint64_t>(resp, out.balance);
  sendResponseAndLoop(ctx, CES_OK, std::move(resp));
}

// ---------------------------------------------------------------------------
// Dispatch: WITHDRAW (owner only)
//   preamble (after reqNonce):
//     u64 amount, u16 name_len, name
// ---------------------------------------------------------------------------

struct WithdrawOutcome { uint8_t status; uint64_t balance; };

// WITHDRAW core: owner pulls `amount` from the program account to creditDest.
// Off-strand authz, then one transaction. Balance is checked before dedup/fee,
// so a replay whose first withdraw drained the balance returns INSUFFICIENT
// rather than idempotent-OK.
WithdrawOutcome withdrawCore(CesServer* server, const std::string& name,
                             uint64_t amount, const minx::Hash& caller,
                             const std::optional<minx::Hash>& creditDest,
                             const L2Billing& bill) {
  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) return { rc, 0 };
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) return { CES_ERROR_FILE_NOT_FOUND, 0 };
  if (!chargeRentOrDelete(server, cPath, sPath, sc, cfg.feeFileRent, cfg.cesFileStoreDir))
    return { CES_ERROR_FILE_NOT_FOUND, 0 };
  writeSidecar(sPath, sc);
  if (std::memcmp(sc.owner_pubkey.data(), caller.data(), 32) != 0)
    return { CES_ERROR_NOT_OWNER, 0 };
  minx::Hash prog{};
  std::memcpy(prog.data(), sc.program_pubkey.data(), 32);

  uint8_t status = CES_ERROR_INTERNAL;
  uint64_t bal = 0;
  bool mutated = false;
  server->_l2Transact([&](ces::LedgerTxn& t) {
    if (t.balance(prog) < static_cast<int64_t>(amount)) {
      status = CES_ERROR_INSUFFICIENT_BALANCE; return;          // before fee
    }
    L2ChargeResult c = bill(t, static_cast<int64_t>(cfg.feeQuery));
    if (c.rc != CES_OK) { status = c.rc; return; }
    if (c.duplicate) { status = CES_OK; bal = static_cast<uint64_t>(t.balance(prog)); return; }
    t.debitAccount(prog, amount);                  // balance checked above
    if (creditDest) t.credit(*creditDest, static_cast<int64_t>(amount));
    status = CES_OK; bal = static_cast<uint64_t>(t.balance(prog)); mutated = true;
  });
  if (status == CES_OK && mutated) {
    sc.modified_us = getMicrosSinceEpoch();
    writeSidecar(sPath, sc);
  }
  return { status, bal };
}

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
  const auto& cfg = reqServer(ctx)->_config();
  minx::Hash signerHash = ctx->bound.boundPubkey.getHash();
  WithdrawOutcome out = withdrawCore(
    reqServer(ctx), name, amount, signerHash, signerHash,   // owner == signer == dest
    signerBilling(ctx->bound.boundPubkey, ctx->reqNonce, ctx->reqSigHash,
                  static_cast<int64_t>(cfg.getFeeError())));
  if (out.status != CES_OK) { sendErrorAndLoop(ctx, out.status); return; }
  ces::Bytes resp;
  ces::Buffer::put<uint64_t>(resp, out.balance);
  sendResponseAndLoop(ctx, CES_OK, std::move(resp));
}

// ---------------------------------------------------------------------------
// Dispatch: SET_PRICE (owner only)
//   preamble (after reqNonce):
//     u64 price_per_kb, u16 name_len, name
// ---------------------------------------------------------------------------

struct SetPriceOutcome { uint8_t status; uint64_t price; };

// SET_PRICE core: owner sets price_per_kb. Off-strand authz; fee in one
// transaction; the sidecar price is written off-strand after a non-duplicate
// commit (a replay leaves the already-set price).
SetPriceOutcome setPriceCore(CesServer* server, const std::string& name,
                             uint64_t newPrice, const minx::Hash& caller,
                             const L2Billing& bill) {
  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) return { rc, 0 };
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) return { CES_ERROR_FILE_NOT_FOUND, 0 };
  if (!chargeRentOrDelete(server, cPath, sPath, sc, cfg.feeFileRent, cfg.cesFileStoreDir))
    return { CES_ERROR_FILE_NOT_FOUND, 0 };
  writeSidecar(sPath, sc);
  if (std::memcmp(sc.owner_pubkey.data(), caller.data(), 32) != 0)
    return { CES_ERROR_NOT_OWNER, 0 };

  uint8_t status = CES_ERROR_INTERNAL;
  bool mutated = false;
  server->_l2Transact([&](ces::LedgerTxn& t) {
    L2ChargeResult c = bill(t, static_cast<int64_t>(cfg.feeQuery));
    if (c.rc != CES_OK) { status = c.rc; return; }
    status = CES_OK; mutated = !c.duplicate;
  });
  if (status != CES_OK) return { status, 0 };
  if (mutated) {
    sc.price_per_kb = newPrice;
    sc.modified_us = getMicrosSinceEpoch();
    writeSidecar(sPath, sc);
  }
  return { CES_OK, sc.price_per_kb };
}

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
  const auto& cfg = reqServer(ctx)->_config();
  SetPriceOutcome out = setPriceCore(
    reqServer(ctx), name, newPrice, ctx->bound.boundPubkey.getHash(),
    signerBilling(ctx->bound.boundPubkey, ctx->reqNonce, ctx->reqSigHash,
                  static_cast<int64_t>(cfg.getFeeError())));
  if (out.status != CES_OK) { sendErrorAndLoop(ctx, out.status); return; }
  ces::Bytes resp;
  ces::Buffer::put<uint64_t>(resp, out.price);
  sendResponseAndLoop(ctx, CES_OK, std::move(resp));
}

// ---------------------------------------------------------------------------
// Dispatch: STAT
//   preamble (after reqNonce): u16 name_len, name
//
// Like every verb, STAT is on a bound channel and verifies through the
// same envelope; the channel signer pays feeQuery. No unsigned fast path.
// ---------------------------------------------------------------------------

struct StatOutcome {
  uint8_t status;
  std::array<uint8_t, 32> owner;
  uint64_t fileBalance, price, size, createdUs, modifiedUs;
};

// STAT core: read-only metadata + program-account balance, charged feeQuery.
// loadSidecar lazy-mints a dropped /s/ file on first stat. A duplicate replay
// just re-reads (read-only).
StatOutcome statCore(CesServer* server, const std::string& name,
                     const L2Billing& bill) {
  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) return { rc, {}, 0, 0, 0, 0, 0 };
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!loadSidecar(server, cfg.cesFileStoreDir, name, sc))
    return { CES_ERROR_FILE_NOT_FOUND, {}, 0, 0, 0, 0, 0 };
  if (!chargeRentOrDelete(server, cPath, sPath, sc, cfg.feeFileRent, cfg.cesFileStoreDir))
    return { CES_ERROR_FILE_NOT_FOUND, {}, 0, 0, 0, 0, 0 };
  writeSidecar(sPath, sc);

  minx::Hash prog{};
  std::memcpy(prog.data(), sc.program_pubkey.data(), 32);
  uint8_t status = CES_ERROR_INTERNAL;
  uint64_t bal = 0;
  server->_l2Transact([&](ces::LedgerTxn& t) {
    L2ChargeResult c = bill(t, static_cast<int64_t>(cfg.feeQuery));
    if (c.rc != CES_OK) { status = c.rc; return; }
    bal = static_cast<uint64_t>(t.balance(prog));   // read-only, dup-safe
    status = CES_OK;
  });
  if (status != CES_OK) return { status, {}, 0, 0, 0, 0, 0 };
  return { CES_OK, sc.owner_pubkey, bal, sc.price_per_kb, sc.size,
           sc.created_us, sc.modified_us };
}

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
  const auto& cfg = reqServer(ctx)->_config();
  StatOutcome out = statCore(
    reqServer(ctx), name,
    signerBilling(ctx->bound.boundPubkey, ctx->reqNonce, ctx->reqSigHash,
                  static_cast<int64_t>(cfg.getFeeError())));
  if (out.status != CES_OK) { sendErrorAndLoop(ctx, out.status); return; }
  // [u8[32] owner][u64 file_balance][u64 price][u64 size][u64 created][u64 modified]
  ces::Bytes resp;
  resp.insert(resp.end(), out.owner.begin(), out.owner.end());
  ces::Buffer::put<uint64_t>(resp, out.fileBalance);
  ces::Buffer::put<uint64_t>(resp, out.price);
  ces::Buffer::put<uint64_t>(resp, out.size);
  ces::Buffer::put<uint64_t>(resp, out.createdUs);
  ces::Buffer::put<uint64_t>(resp, out.modifiedUs);
  sendResponseAndLoop(ctx, CES_OK, std::move(resp));
}

// ---------------------------------------------------------------------------
// Dispatch: DELETE (owner only)
//   preamble (after reqNonce):
//     u16 name_len, name
// ---------------------------------------------------------------------------

struct DeleteOutcome { uint8_t status; uint64_t refunded; };

// DELETE core: owner removes a file. Fee + drain-refund (program account ->
// creditDest) are one atomic transaction; the disk removal happens off-strand
// after a non-duplicate commit. A replay returns refund 0 (already gone).
DeleteOutcome deleteCore(CesServer* server, const std::string& name,
                         const minx::Hash& caller,
                         const std::optional<minx::Hash>& creditDest,
                         const L2Billing& bill) {
  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) return { rc, 0 };
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) return { CES_ERROR_FILE_NOT_FOUND, 0 };
  if (!chargeRentOrDelete(server, cPath, sPath, sc, cfg.feeFileRent, cfg.cesFileStoreDir))
    return { CES_ERROR_FILE_NOT_FOUND, 0 };
  writeSidecar(sPath, sc);
  if (std::memcmp(sc.owner_pubkey.data(), caller.data(), 32) != 0)
    return { CES_ERROR_NOT_OWNER, 0 };

  minx::Hash prog{};  std::memcpy(prog.data(), sc.program_pubkey.data(), 32);
  uint8_t status = CES_ERROR_INTERNAL;
  uint64_t refund = 0;
  bool mutated = false;
  server->_l2Transact([&](ces::LedgerTxn& t) {
    L2ChargeResult c = bill(t, static_cast<int64_t>(cfg.feeQuery));
    if (c.rc != CES_OK)  { status = c.rc; return; }
    if (c.duplicate)     { status = CES_OK; return; }       // already deleted
    int64_t bal = t.balance(prog);                          // drain to dest
    if (bal > 0) { t.debitAccount(prog, static_cast<uint64_t>(bal));
                   if (creditDest) t.credit(*creditDest, bal);
                   refund = static_cast<uint64_t>(bal); }
    status = CES_OK; mutated = true;
  });
  if (status != CES_OK) return { status, 0 };
  if (mutated) {
    uint64_t size = sc.size;
    std::error_code ec;
    if (sc.type == kFileTypeKv) std::filesystem::remove_all(cPath, ec);
    else                        std::filesystem::remove(cPath, ec);
    std::filesystem::remove(sPath, ec);
    if (!isServerZone(name)) {
      std::lock_guard lk(server->fileHandler()->storeMetaMutex_);
      adjustStoreMeta(cfg.cesFileStoreDir, -1, -static_cast<int64_t>(size));
    }
    std::filesystem::path p = cPath.parent_path();
    std::filesystem::path base = cfg.cesFileStoreDir;
    while (p != base) {
      std::error_code rmec;
      if (!std::filesystem::remove(p, rmec)) break;
      p = p.parent_path();
    }
    notifyDeletion(server, name);
    noteServerZoneMutation(server, name);
  }
  return { CES_OK, refund };
}

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
  const auto& cfg = reqServer(ctx)->_config();
  minx::Hash signerHash = ctx->bound.boundPubkey.getHash();
  DeleteOutcome out = deleteCore(
    reqServer(ctx), name, signerHash, signerHash,   // owner == signer == refund dest
    signerBilling(ctx->bound.boundPubkey, ctx->reqNonce, ctx->reqSigHash,
                  static_cast<int64_t>(cfg.getFeeError())));
  if (out.status != CES_OK) { sendErrorAndLoop(ctx, out.status); return; }
  ces::Bytes resp;
  ces::Buffer::put<uint64_t>(resp, out.refunded);
  sendResponseAndLoop(ctx, CES_OK, std::move(resp));
}

// ---------------------------------------------------------------------------
// Dispatch: APPEND (owner only) - extend-write `length` bytes past
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

struct AppendOutcome { uint8_t status; uint64_t balance; uint64_t size; };

// APPEND core: extend the file with `body`. Like WRITE plus grow: cap check +
// writeCost + upfront-rent, all from the target program account, with the
// grow-cost balance checked before the fee.
AppendOutcome appendCore(CesServer* server, const std::string& name,
                         const ces::Bytes& body, const minx::Hash& caller,
                         const L2Billing& bill) {
  uint32_t length = static_cast<uint32_t>(body.size());
  if (length == 0 || length > kMaxWriteLen) return { CES_ERROR_BAD_INPUT, 0, 0 };
  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) return { rc, 0, 0 };
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) return { CES_ERROR_FILE_NOT_FOUND, 0, 0 };
  if (!chargeRentOrDelete(server, cPath, sPath, sc, cfg.feeFileRent, cfg.cesFileStoreDir))
    return { CES_ERROR_FILE_NOT_FOUND, 0, 0 };
  writeSidecar(sPath, sc);
  if (std::memcmp(sc.owner_pubkey.data(), caller.data(), 32) != 0)
    return { CES_ERROR_NOT_OWNER, 0, 0 };
  if (length > kMaxFileSize - sc.size) return { CES_ERROR_BAD_INPUT, 0, 0 };

  const bool serverZone = isServerZone(name);
  if (!serverZone) {
    std::lock_guard lk(server->fileHandler()->storeMetaMutex_);
    uint8_t capRc = checkCapAndMaybeGc(server, cfg.cesFileStoreDir, cfg.cesFileStoreMaxBytes,
                                       cfg.feeFileRent, length);
    if (capRc != CES_OK) return { capRc, 0, 0 };
  }
  uint64_t writeCost = serverZone ? 0 : kbCeil(length) * uint64_t(cfg.feeFileWrite);
  uint64_t upfront = serverZone ? 0 : computeOwedRent(length, cfg.feeFileRent, 0, kGcDebounceUs);
  uint64_t oldSize = sc.size;
  minx::Hash prog{};
  std::memcpy(prog.data(), sc.program_pubkey.data(), 32);

  uint8_t status = CES_ERROR_INTERNAL;
  bool duplicate = false;
  uint64_t newBal = 0;
  server->_l2Transact([&](ces::LedgerTxn& t) {
    uint64_t totalDebit = writeCost + upfront;
    if (totalDebit > 0 && t.balance(prog) < static_cast<int64_t>(totalDebit)) {
      status = CES_ERROR_INSUFFICIENT_BALANCE; return;          // before fee
    }
    L2ChargeResult c = bill(t, static_cast<int64_t>(cfg.feeQuery));
    if (c.rc != CES_OK) { status = c.rc; return; }
    if (c.duplicate) { duplicate = true; status = CES_OK; newBal = static_cast<uint64_t>(t.balance(prog)); return; }
    if (totalDebit > 0) t.debitAccount(prog, totalDebit);
    newBal = static_cast<uint64_t>(t.balance(prog));
    status = CES_OK;
  });
  if (status != CES_OK) return { status, 0, 0 };
  if (duplicate) {
    Sidecar scd{};
    if (!readSidecar(sPath, scd)) return { CES_ERROR_INTERNAL, 0, 0 };
    return { CES_OK, newBal, scd.size };
  }
  FILE* fp = std::fopen(cPath.string().c_str(), "rb+");
  if (!fp) return { CES_ERROR_INTERNAL, 0, 0 };
  if (std::fseek(fp, static_cast<long>(oldSize), SEEK_SET) != 0) {
    std::fclose(fp); return { CES_ERROR_INTERNAL, 0, 0 };
  }
  size_t wrote = std::fwrite(body.data(), 1, body.size(), fp);
  std::fflush(fp); std::fclose(fp);
  if (wrote != body.size()) return { CES_ERROR_INTERNAL, 0, 0 };
  Sidecar sc2{};
  if (!readSidecar(sPath, sc2)) return { CES_ERROR_INTERNAL, 0, 0 };
  sc2.size = oldSize + length;
  sc2.modified_us = getMicrosSinceEpoch();
  sc2.program_hash.fill(0);
  if (!writeSidecar(sPath, sc2)) return { CES_ERROR_INTERNAL, 0, 0 };
  if (!serverZone) {
    std::lock_guard lk(server->fileHandler()->storeMetaMutex_);
    adjustStoreMeta(cfg.cesFileStoreDir, 0, static_cast<int64_t>(length));
  }
  return { CES_OK, newBal, sc2.size };
}

void dispatchAppend(std::shared_ptr<ReqCtx> ctx, ces::Bytes pre) {
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
  ces::PublicKey signer = ctx->bound.boundPubkey;
  uint32_t reqNonce = ctx->reqNonce;
  uint64_t sigHash = ctx->reqSigHash;
  int64_t errFee = static_cast<int64_t>(reqServer(ctx)->_config().getFeeError());
  auto body = std::make_shared<ces::Bytes>(length);

  boost::asio::async_read(
    *ctx->stream, boost::asio::buffer(*body),
    [ctx, contentHash, name, signer, reqNonce, sigHash, errFee, body]
    (const boost::system::error_code& ec, std::size_t) {
      if (ec) return;
      minx::Hash got = ces::sha256(body->data(), body->size());
      if (std::memcmp(got.data(), contentHash.data(), 32) != 0) {
        sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
      }
      AppendOutcome out = appendCore(
        reqServer(ctx), name, *body, signer.getHash(),
        signerBilling(signer, reqNonce, sigHash, errFee));
      if (out.status != CES_OK) { sendErrorAndLoop(ctx, out.status); return; }
      ces::Bytes resp;
      ces::Buffer::put<uint64_t>(resp, out.balance);
      ces::Buffer::put<uint64_t>(resp, out.size);
      sendResponseAndLoop(ctx, CES_OK, std::move(resp));
    });
}

// ---------------------------------------------------------------------------
// Dispatch: RESIZE (owner only) - change file's logical size. Sparse
// on grow (ftruncate, no bytes transferred; same as CREATE's sparse
// allocation - no feeFileWrite charge). Truncates tail on shrink.
// Cap check fires only on growth.
//   preamble (after reqNonce):
//     u64 new_size, u16 name_len, name
// ---------------------------------------------------------------------------

struct ResizeOutcome { uint8_t status; uint64_t size; uint64_t balance; };

// RESIZE core: grow (cap + upfront burn from the target program account) or
// shrink. No body. Off-strand authz; fee + upfront fold into one transaction,
// balance checked before the fee.
ResizeOutcome resizeCore(CesServer* server, const std::string& name,
                         uint64_t newSize, const minx::Hash& caller,
                         const L2Billing& bill) {
  if (newSize == 0 || newSize > kMaxFileSize) return { CES_ERROR_BAD_INPUT, 0, 0 };
  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) return { rc, 0, 0 };
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) return { CES_ERROR_FILE_NOT_FOUND, 0, 0 };
  if (!chargeRentOrDelete(server, cPath, sPath, sc, cfg.feeFileRent, cfg.cesFileStoreDir))
    return { CES_ERROR_FILE_NOT_FOUND, 0, 0 };
  writeSidecar(sPath, sc);
  if (std::memcmp(sc.owner_pubkey.data(), caller.data(), 32) != 0)
    return { CES_ERROR_NOT_OWNER, 0, 0 };

  int64_t bytesDelta = static_cast<int64_t>(newSize) - static_cast<int64_t>(sc.size);
  const bool serverZone = isServerZone(name);
  uint64_t upfront = 0;
  if (bytesDelta > 0 && !serverZone) {
    { std::lock_guard lk(server->fileHandler()->storeMetaMutex_);
      uint8_t capRc = checkCapAndMaybeGc(server, cfg.cesFileStoreDir, cfg.cesFileStoreMaxBytes,
                                         cfg.feeFileRent, static_cast<uint64_t>(bytesDelta));
      if (capRc != CES_OK) return { capRc, 0, 0 }; }
    upfront = computeOwedRent(static_cast<uint64_t>(bytesDelta), cfg.feeFileRent, 0, kGcDebounceUs);
  }
  minx::Hash prog{};
  std::memcpy(prog.data(), sc.program_pubkey.data(), 32);

  uint8_t status = CES_ERROR_INTERNAL;
  bool duplicate = false;
  uint64_t bal = 0;
  server->_l2Transact([&](ces::LedgerTxn& t) {
    if (upfront > 0 && t.balance(prog) < static_cast<int64_t>(upfront)) {
      status = CES_ERROR_INSUFFICIENT_BALANCE; return;          // before fee
    }
    L2ChargeResult c = bill(t, static_cast<int64_t>(cfg.feeQuery));
    if (c.rc != CES_OK) { status = c.rc; return; }
    if (c.duplicate) { duplicate = true; status = CES_OK; bal = static_cast<uint64_t>(t.balance(prog)); return; }
    if (upfront > 0) t.debitAccount(prog, upfront);
    bal = static_cast<uint64_t>(t.balance(prog));
    status = CES_OK;
  });
  if (status != CES_OK) return { status, 0, 0 };
  if (duplicate) {
    Sidecar scd{};
    if (!readSidecar(sPath, scd)) return { CES_ERROR_INTERNAL, 0, 0 };
    return { CES_OK, scd.size, bal };
  }
  std::error_code ec;
  std::filesystem::resize_file(cPath, newSize, ec);
  if (ec) return { CES_ERROR_INTERNAL, 0, 0 };
  Sidecar sc2{};
  if (!readSidecar(sPath, sc2)) return { CES_ERROR_INTERNAL, 0, 0 };
  sc2.size = newSize;
  sc2.modified_us = getMicrosSinceEpoch();
  sc2.program_hash.fill(0);
  if (!writeSidecar(sPath, sc2)) return { CES_ERROR_INTERNAL, 0, 0 };
  if (bytesDelta != 0 && !serverZone) {
    std::lock_guard lk(server->fileHandler()->storeMetaMutex_);
    adjustStoreMeta(cfg.cesFileStoreDir, 0, bytesDelta);
  }
  return { CES_OK, sc2.size, bal };
}

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
  const auto& cfg = reqServer(ctx)->_config();
  ResizeOutcome out = resizeCore(
    reqServer(ctx), name, newSize, ctx->bound.boundPubkey.getHash(),
    signerBilling(ctx->bound.boundPubkey, ctx->reqNonce, ctx->reqSigHash,
                  static_cast<int64_t>(cfg.getFeeError())));
  if (out.status != CES_OK) { sendErrorAndLoop(ctx, out.status); return; }
  ces::Bytes resp;
  ces::Buffer::put<uint64_t>(resp, out.size);
  sendResponseAndLoop(ctx, CES_OK, std::move(resp));
}

// ---------------------------------------------------------------------------
// kv-file cores. Billing differs from the flat cores: a kv cell's RENT is NOT
// rolled per-op. It is charged only by the daily sweep (sweepKvRent, run from
// CesServer::dailyTaskTick), which charges every cell its per-byte rent and
// erases zero-balance keys. A PUT pays the per-KB write cost (feeFileWrite; 0 in
// the /s/ zone) plus feeQuery from the bound signer, credits any deposit into the
// cell balance and the file's program account, and on growth runs the cap/GC
// check (checkCapAndMaybeGc) -- there is no 15-min upfront rent on kv puts.
// Logical size lives in the sidecar (size). The logkv store is accessed under the
// kv cache mutex; the ledger transaction is taken while holding it (no path takes
// the store-meta mutex then the kv mutex, so the brief store-meta acquisitions
// here cannot deadlock).
// ---------------------------------------------------------------------------

struct KvPutOutcome     { uint8_t status; uint64_t balance; uint64_t size; };
struct KvGetOutcome     { uint8_t status; ces::Bytes value; bool found; };
struct KvEraseOutcome   { uint8_t status; uint64_t size; };
struct KvIterOutcome    { uint8_t status; std::vector<ces::Bytes> keys; };
struct KvDepositOutcome { uint8_t status; uint64_t balance; };
struct KvRangeOutcome   { uint8_t status; ces::Bytes effectiveHi;
                          std::vector<ces::Bytes> keys;
                          std::vector<ces::Bytes> values; };

// Store (or overwrite) a key's record, adding `deposit` to the cell's rent
// balance. No whole-store rent here; the daily sweep charges rent. The funder
// pays a one-time write cost (burned) plus `deposit` (moved into the store pot
// and credited to the cell balance). An overwrite keeps the existing cell
// balance and last-charged stamp, so funding survives content updates.
KvPutOutcome kvPutCore(CesServer* server, const std::string& name,
                       const ces::Bytes& key, const ces::Bytes& value,
                       const minx::Hash& caller, uint64_t deposit,
                       const L2Billing& bill) {
  if (key.empty() || key.size() > kMaxKvKeyLen) return { CES_ERROR_BAD_INPUT, 0, 0 };
  if (value.empty() || value.size() > kMaxWriteLen) return { CES_ERROR_BAD_INPUT, 0, 0 };
  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) return { rc, 0, 0 };
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) return { CES_ERROR_FILE_NOT_FOUND, 0, 0 };
  if (sc.type != kFileTypeKv) return { CES_ERROR_BAD_INPUT, 0, 0 };
  if (std::memcmp(sc.owner_pubkey.data(), caller.data(), 32) != 0)
    return { CES_ERROR_NOT_OWNER, 0, 0 };

  const bool serverZone = isServerZone(name);
  minx::Hash prog{};
  std::memcpy(prog.data(), sc.program_pubkey.data(), 32);
  logkv::Bytes k = toLogkvBytes(key);
  uint64_t now = getMicrosSinceEpoch();

  std::lock_guard<std::mutex> kvLk(server->fileHandler()->kv_->mutex);
  KvStore* st = kvStoreOpenLocked(server, cfg.cesFileStoreDir, name);
  if (!st) return { CES_ERROR_INTERNAL, 0, 0 };

  uint64_t cellBalance = 0, lastCharged = now, oldStored = 0;
  { auto it = st->find(k);
    if (it != st->end()) {
      KvCell c{};
      if (kvCellParse(it->second, c)) { cellBalance = c.balance; lastCharged = c.lastChargedUs; }
      oldStored = key.size() + it->second.size();
    } }
  uint64_t newStored = key.size() + kKvHeaderLen + value.size();
  int64_t storedDelta = static_cast<int64_t>(newStored) - static_cast<int64_t>(oldStored);
  uint64_t grow = storedDelta > 0 ? static_cast<uint64_t>(storedDelta) : 0;

  if (grow > 0 && !serverZone) {
    std::lock_guard<std::mutex> mlk(server->fileHandler()->storeMetaMutex_);
    uint8_t capRc = checkCapAndMaybeGc(server, cfg.cesFileStoreDir, cfg.cesFileStoreMaxBytes,
                                       cfg.feeFileRent, grow);
    if (capRc != CES_OK) return { capRc, 0, 0 };
  }
  uint64_t writeCost = serverZone ? 0 : kbCeil(value.size()) * uint64_t(cfg.feeFileWrite);

  uint8_t status = CES_ERROR_INTERNAL;
  bool duplicate = false;
  server->_l2Transact([&](ces::LedgerTxn& t) {
    L2ChargeResult c = bill(t, static_cast<int64_t>(writeCost + deposit));
    if (c.rc != CES_OK) { status = c.rc; return; }
    if (c.duplicate) { duplicate = true; status = CES_OK; return; }
    if (deposit > 0) t.credit(prog, static_cast<int64_t>(deposit));
    status = CES_OK;
  });
  if (status != CES_OK) return { status, 0, 0 };
  if (duplicate) return { CES_OK, cellBalance, sc.size };

  cellBalance += deposit;
  logkv::Bytes nv = kvCellBuild(cellBalance, lastCharged,
      reinterpret_cast<const char*>(value.data()), value.size());
  st->update(k, nv);
  st->flush(true);

  Sidecar sc2{};
  if (!readSidecar(sPath, sc2)) return { CES_ERROR_INTERNAL, 0, 0 };
  uint64_t base = sc2.size > oldStored ? sc2.size - oldStored : 0;
  sc2.size = base + newStored;
  sc2.modified_us = now;
  if (!writeSidecar(sPath, sc2)) return { CES_ERROR_INTERNAL, 0, 0 };
  if (storedDelta != 0 && !serverZone) {
    std::lock_guard<std::mutex> mlk(server->fileHandler()->storeMetaMutex_);
    adjustStoreMeta(cfg.cesFileStoreDir, 0, storedDelta);
  }
  return { CES_OK, cellBalance, sc2.size };
}

// Add `amount` to an existing key's rent balance. Any signer; no owner check.
// Moves `amount` into the store pot and the cell balance. The key must already
// exist.
KvDepositOutcome kvDepositCore(CesServer* server, const std::string& name,
                               const ces::Bytes& key, uint64_t amount,
                               const L2Billing& bill) {
  if (key.empty() || key.size() > kMaxKvKeyLen) return { CES_ERROR_BAD_INPUT, 0 };
  if (amount == 0) return { CES_ERROR_BAD_INPUT, 0 };
  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) return { rc, 0 };
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) return { CES_ERROR_FILE_NOT_FOUND, 0 };
  if (sc.type != kFileTypeKv) return { CES_ERROR_BAD_INPUT, 0 };
  minx::Hash prog{};
  std::memcpy(prog.data(), sc.program_pubkey.data(), 32);
  logkv::Bytes k = toLogkvBytes(key);

  std::lock_guard<std::mutex> kvLk(server->fileHandler()->kv_->mutex);
  KvStore* st = kvStoreOpenLocked(server, cfg.cesFileStoreDir, name);
  if (!st) return { CES_ERROR_INTERNAL, 0 };
  auto it = st->find(k);
  if (it == st->end()) return { CES_ERROR_FILE_NOT_FOUND, 0 };
  KvCell c{};
  if (!kvCellParse(it->second, c)) return { CES_ERROR_INTERNAL, 0 };
  // Copy the user bytes before the update (c.user points into the stored value).
  logkv::Bytes nv = kvCellBuild(c.balance + amount, c.lastChargedUs, c.user, c.userLen);

  uint8_t status = CES_ERROR_INTERNAL;
  bool duplicate = false;
  server->_l2Transact([&](ces::LedgerTxn& t) {
    L2ChargeResult ch = bill(t, static_cast<int64_t>(amount));
    if (ch.rc != CES_OK) { status = ch.rc; return; }
    if (ch.duplicate) { duplicate = true; status = CES_OK; return; }
    t.credit(prog, static_cast<int64_t>(amount));
    status = CES_OK;
  });
  if (status != CES_OK) return { status, 0 };
  if (duplicate) return { CES_OK, c.balance };

  st->update(k, nv);
  st->flush(true);
  return { CES_OK, c.balance + amount };
}

KvGetOutcome kvGetCore(CesServer* server, const std::string& name,
                       const ces::Bytes& key, const L2Billing& bill) {
  (void)bill;  // reads are free at the kv layer (bandwidth is billed at the channel)
  if (key.empty() || key.size() > kMaxKvKeyLen) return { CES_ERROR_BAD_INPUT, {}, false };
  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) return { rc, {}, false };
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) return { CES_ERROR_FILE_NOT_FOUND, {}, false };
  if (sc.type != kFileTypeKv) return { CES_ERROR_BAD_INPUT, {}, false };

  std::lock_guard<std::mutex> kvLk(server->fileHandler()->kv_->mutex);
  KvStore* st = kvStoreOpenLocked(server, cfg.cesFileStoreDir, name);
  if (!st) return { CES_ERROR_INTERNAL, {}, false };
  auto it = st->find(toLogkvBytes(key));
  if (it == st->end()) return { CES_OK, {}, false };
  KvCell c{};
  if (!kvCellParse(it->second, c)) return { CES_ERROR_INTERNAL, {}, false };
  ces::Bytes user(reinterpret_cast<const uint8_t*>(c.user),
                  reinterpret_cast<const uint8_t*>(c.user) + c.userLen);
  return { CES_OK, std::move(user), true };
}

KvEraseOutcome kvEraseCore(CesServer* server, const std::string& name,
                           const ces::Bytes& key, const minx::Hash& caller,
                           const L2Billing& bill) {
  (void)bill;  // erase is free at the kv layer
  if (key.empty() || key.size() > kMaxKvKeyLen) return { CES_ERROR_BAD_INPUT, 0 };
  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) return { rc, 0 };
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) return { CES_ERROR_FILE_NOT_FOUND, 0 };
  if (sc.type != kFileTypeKv) return { CES_ERROR_BAD_INPUT, 0 };
  if (std::memcmp(sc.owner_pubkey.data(), caller.data(), 32) != 0)
    return { CES_ERROR_NOT_OWNER, 0 };
  const bool serverZone = isServerZone(name);

  uint64_t oldStored = 0, forfeit = 0;
  {
    std::lock_guard<std::mutex> kvLk(server->fileHandler()->kv_->mutex);
    KvStore* st = kvStoreOpenLocked(server, cfg.cesFileStoreDir, name);
    if (!st) return { CES_ERROR_INTERNAL, 0 };
    logkv::Bytes k = toLogkvBytes(key);
    auto it = st->find(k);
    if (it != st->end()) {
      KvCell c{}; if (kvCellParse(it->second, c)) forfeit = c.balance;
      oldStored = key.size() + it->second.size();
      st->erase(k); st->flush(true);
    }
  }
  // Burn the cell's forfeited balance from the store pot to keep the pot equal
  // to the sum of live cell balances. The kv mutex is released; no lock is held
  // across the logicStrand hop.
  if (forfeit > 0 && !serverZone) debitProgramAccount(server, sc, forfeit);

  Sidecar sc2{};
  if (!readSidecar(sPath, sc2)) return { CES_ERROR_INTERNAL, 0 };
  sc2.size = sc2.size > oldStored ? sc2.size - oldStored : 0;
  sc2.modified_us = getMicrosSinceEpoch();
  if (!writeSidecar(sPath, sc2)) return { CES_ERROR_INTERNAL, 0 };
  if (oldStored > 0 && !serverZone) {
    std::lock_guard<std::mutex> mlk(server->fileHandler()->storeMetaMutex_);
    adjustStoreMeta(cfg.cesFileStoreDir, 0, -static_cast<int64_t>(oldStored));
  }
  return { CES_OK, sc2.size };
}

KvIterOutcome kvIterCore(CesServer* server, const std::string& name,
                         const L2Billing& bill) {
  (void)bill;  // iteration is free at the kv layer
  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) return { rc, {} };
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) return { CES_ERROR_FILE_NOT_FOUND, {} };
  if (sc.type != kFileTypeKv) return { CES_ERROR_BAD_INPUT, {} };

  std::lock_guard<std::mutex> kvLk(server->fileHandler()->kv_->mutex);
  KvStore* st = kvStoreOpenLocked(server, cfg.cesFileStoreDir, name);
  if (!st) return { CES_ERROR_INTERNAL, {} };
  std::vector<ces::Bytes> keys;
  for (auto& kv : st->getObjects()) keys.push_back(fromLogkvBytes(kv.first));
  return { CES_OK, std::move(keys) };
}

// Ordered range scan: return sorted (key, value) pairs in [lo, hi) up to a byte
// budget, with the effective upper bound covered. lo empty = start of store;
// hi empty = end of store. effectiveHi == hi means the whole range was
// delivered; effectiveHi < hi is the next undelivered key (resume point), so
// the caller continues with range(effectiveHi, hi). At least one in-range pair
// is always returned so a lone oversized value cannot stall a scan. Read-only,
// unbilled at the kv layer (the channel meters the bytes).
KvRangeOutcome kvRangeCore(CesServer* server, const std::string& name,
                           const ces::Bytes& lo, const ces::Bytes& hi,
                           uint64_t maxBytes) {
  uint8_t rc = validateCesFileName(name);
  if (rc != CES_OK) return { rc, {}, {}, {} };
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) return { CES_ERROR_FILE_NOT_FOUND, {}, {}, {} };
  if (sc.type != kFileTypeKv) return { CES_ERROR_BAD_INPUT, {}, {}, {} };

  if (maxBytes == 0 || maxBytes > kKvRangeMaxBytes) maxBytes = kKvRangeMaxBytes;
  const bool hasHi = !hi.empty();
  logkv::Bytes hiB = toLogkvBytes(hi);

  std::lock_guard<std::mutex> kvLk(server->fileHandler()->kv_->mutex);
  KvStore* st = kvStoreOpenLocked(server, cfg.cesFileStoreDir, name);
  if (!st) return { CES_ERROR_INTERNAL, {}, {}, {} };
  auto& m = st->getObjects();

  KvRangeOutcome out{}; out.status = CES_OK;
  out.effectiveHi = hi;                       // default: whole range delivered
  uint64_t used = 0;
  auto less = m.key_comp();                   // the map's unsigned-byte order
  auto it = lo.empty() ? m.begin() : m.lower_bound(toLogkvBytes(lo));
  for (; it != m.end(); ++it) {
    if (hasHi && !less(it->first, hiB)) break; // reached hi (same order as the map)
    KvCell c{};
    if (!kvCellParse(it->second, c)) continue;
    uint64_t entryBytes = it->first.size() + c.userLen;
    if (!out.keys.empty() && used + entryBytes > maxBytes) {
      out.effectiveHi = fromLogkvBytes(it->first);  // truncated: resume here
      return out;
    }
    out.keys.push_back(fromLogkvBytes(it->first));
    out.values.emplace_back(reinterpret_cast<const uint8_t*>(c.user),
                            reinterpret_cast<const uint8_t*>(c.user) + c.userLen);
    used += entryBytes;
  }
  return out;                                 // ran to hi or end of store
}

// Wire KV_DEPOSIT: a bound signer funds a key in a kv-store directly. Any
// signer, no owner check. Preamble: u64 amount, u16 key_len, key, u16 name_len,
// name. Defined here, after kvDepositCore, so KvDepositOutcome is in scope; the
// serve switch reaches it through the forward declaration above.
void dispatchKvDeposit(std::shared_ptr<ReqCtx> ctx, ces::Bytes pre) {
  ces::Buffer buf(std::move(pre));
  uint64_t amount = 0;
  ces::Bytes key;
  std::string name;
  try {
    amount = buf.get<uint64_t>();
    uint16_t klen = buf.get<uint16_t>();
    if (klen == 0 || klen > kMaxKvKeyLen) {
      sendErrorAndLoop(ctx, CES_ERROR_BAD_INPUT); return;
    }
    key = buf.getBytes<ces::Bytes>(klen);
    uint16_t nameLen = buf.get<uint16_t>();
    if (nameLen == 0 || nameLen > kMaxNameLen) {
      sendErrorAndLoop(ctx, CES_ERROR_BAD_NAME); return;
    }
    name = buf.getBytes<std::string>(nameLen);
  } catch (const std::out_of_range&) {
    sendErrorAndLoop(ctx, CES_ERROR_BAD_INPUT); return;
  }
  const auto& cfg = reqServer(ctx)->_config();
  // kvDepositCore touches logkv, which throws on a disk error. The CesPlex
  // dispatch path does not catch, so contain it here (other file dispatchers
  // use error codes and never throw).
  KvDepositOutcome out{};
  try {
    out = kvDepositCore(
      reqServer(ctx), name, key, amount,
      signerBilling(ctx->bound.boundPubkey, ctx->reqNonce, ctx->reqSigHash,
                    static_cast<int64_t>(cfg.getFeeError())));
  } catch (...) {
    sendErrorAndLoop(ctx, CES_ERROR_INTERNAL); return;
  }
  if (out.status != CES_OK) { sendErrorAndLoop(ctx, out.status); return; }
  ces::Bytes resp;
  ces::Buffer::put<uint64_t>(resp, out.balance);
  sendResponseAndLoop(ctx, CES_OK, std::move(resp));
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

uint64_t gcReclaim(CesServer* server, const std::string& dir, int64_t feeRent,
                   uint64_t bytesNeeded) {
  uint64_t reclaimed = 0;
  int64_t files_delta = 0;
  int64_t bytes_delta = 0;
  uint64_t now = getMicrosSinceEpoch();
  walkFileStore(std::filesystem::path(dir),
    [&](const std::filesystem::path& sp,
        const std::filesystem::path& cp, Sidecar& s) {
      if (bytesNeeded > 0 && reclaimed >= bytesNeeded) return;
      // /s/ files are exempt from rent-based GC - unmetered by
      // definition.
      if (isServerZone(s.name)) return;
      uint64_t owed = computeOwedRent(
        s.size, feeRent, s.last_rent_us, now);
      uint64_t bal = server ? readProgramAccountBalance(server, s) : 0;
      if (owed > bal) {
        // Dead. Delete content + sidecar. Best-effort rmdir of
        // empty parents.
        std::error_code ec;
        if (s.type == kFileTypeKv) std::filesystem::remove_all(cp, ec);
        else                       std::filesystem::remove(cp, ec);
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
        notifyDeletion(server, s.name);
      }
      // Live files: leave alone. Their rent advances on next touch.
    });
  if (files_delta != 0 || bytes_delta != 0)
    adjustStoreMeta(dir, files_delta, bytes_delta);
  return reclaimed;
}

uint8_t checkCapAndMaybeGc(CesServer* server,
                           const std::string& dir,
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
  uint64_t reclaimed = gcReclaim(server, dir, feeRent, need);
  readStoreMeta(metaP, m);
  m.last_gc_us = now;
  writeStoreMeta(metaP, m);
  LOGINFO << "file-store: JIT GC" << VAR(need) << VAR(reclaimed);
  if (m.total_bytes + addBytes > cap) return CES_ERROR_STORE_FULL;
  return CES_OK;
}

// In-process verb execution (cross-handler path). Parallel to dispatch* but
// takes an already-authorized owner pubkey: no wire I/O, sig verify, nonce, or
// dedup. Wire fees still apply, paid from req.sourceName's file_balance (the
// program's wallet), not the owner's account. Each exec* completes by calling
// cb(resp) on cbEx; the only strand hop is the /f/-zone ownership check on CREATE.

// In-process (exec) adapters: the same verb cores as the session path, billed to
// the source file's program account instead of a network signer. The source
// charge is three parts: resolveSourceForBilling (rent-roll the source off-strand
// -> its program pubkey), sourceBilling (debit it inside the core's transaction),
// and deleteExhaustedSource (delete the source when it cannot pay). /s/ sources
// are unmetered.
uint8_t resolveSourceForBilling(CesServer* server, const std::string& sourceName,
                                minx::Hash& outProg, bool& outMetered) {
  outMetered = false;
  if (isServerZone(sourceName)) return CES_OK;          // /s/ unmetered
  if (sourceName.empty()) return CES_ERROR_INTERNAL;    // compute must set it
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, sourceName);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, sourceName);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) return CES_ERROR_FILE_NOT_FOUND;
  if (!chargeRentOrDelete(server, cPath, sPath, sc, cfg.feeFileRent, cfg.cesFileStoreDir))
    return CES_ERROR_FILE_NOT_FOUND;
  writeSidecar(sPath, sc);
  std::memcpy(outProg.data(), sc.program_pubkey.data(), 32);
  outMetered = true;
  return CES_OK;
}

void deleteExhaustedSource(CesServer* server, const std::string& sourceName) {
  if (isServerZone(sourceName)) return;
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, sourceName);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, sourceName);
  Sidecar sc{};
  uint64_t size = readSidecar(sPath, sc) ? sc.size : 0;
  std::error_code ec;
  std::filesystem::remove(cPath, ec);
  std::filesystem::remove(sPath, ec);
  std::filesystem::path p = cPath.parent_path();
  std::filesystem::path base = cfg.cesFileStoreDir;
  while (p != base) {
    std::error_code rmec;
    if (!std::filesystem::remove(p, rmec)) break;
    p = p.parent_path();
  }
  { std::lock_guard lk(server->fileHandler()->storeMetaMutex_);
    adjustStoreMeta(cfg.cesFileStoreDir, -1, -static_cast<int64_t>(size)); }
  notifyDeletion(server, sourceName);
}

// The flag is set iff the SOURCE itself could not pay (so the adapter knows to
// delete the exhausted source). A target-side INSUFFICIENT leaves it clear.
inline L2Billing sourceBilling(minx::Hash sourceProg, bool metered,
                               bool* sourceInsufficient) {
  return [sourceProg, metered, sourceInsufficient]
         (ces::LedgerTxn& t, int64_t cost) -> L2ChargeResult {
    if (!metered) return { CES_OK, false };            // /s/ unmetered
    if (!t.debitAccount(sourceProg, static_cast<uint64_t>(cost))) {
      if (sourceInsufficient) *sourceInsufficient = true;
      return { CES_ERROR_INSUFFICIENT_BALANCE, false };
    }
    return { CES_OK, false };
  };
}

inline L2Billing noBilling() {
  return [](ces::LedgerTxn&, int64_t) -> L2ChargeResult { return { CES_OK, false }; };
}

inline minx::Hash hashOf(const std::array<uint8_t, 32>& a) {
  minx::Hash h{}; std::memcpy(h.data(), a.data(), 32); return h;
}

// Resolve source, run the verb core with source billing, delete the source on
// exhaustion, post the FileExecResp. Returns false (already replied) if the
// source could not be resolved.
template <typename Fn>
void execWithSource(CesServer* server, const FileExecReq& req,
                    std::function<void(FileExecResp)> cb,
                    boost::asio::any_io_executor cbEx, Fn&& run) {
  minx::Hash srcProg{}; bool metered = false;
  uint8_t srcRc = resolveSourceForBilling(server, req.sourceName, srcProg, metered);
  if (srcRc != CES_OK) {
    FileExecResp r; r.status = srcRc;
    boost::asio::post(cbEx, [cb, r]() { cb(r); }); return;
  }
  bool sourceInsufficient = false;
  FileExecResp r = run(sourceBilling(srcProg, metered, &sourceInsufficient),
                       srcProg, metered);
  // Delete the source only when the SOURCE itself ran out (not a target-side
  // INSUFFICIENT) - mirrors the old FileHandler::debitBalance exhaustion-delete.
  if (sourceInsufficient && metered)
    deleteExhaustedSource(server, req.sourceName);
  boost::asio::post(cbEx, [cb, r]() { cb(r); });
}

void execStat(CesServer* server, FileExecReq req,
              std::function<void(FileExecResp)> cb,
              boost::asio::any_io_executor cbEx) {
  // STAT is free for the in-process caller (no source charge).
  StatOutcome out = statCore(server, req.name, noBilling());
  FileExecResp r; r.status = out.status;
  if (out.status == CES_OK) {
    r.ownerPubkey = out.owner;
    r.fileBalance = out.fileBalance;
    r.pricePerKb = out.price;
    r.size = out.size;
    r.createdUs = out.createdUs;
    r.modifiedUs = out.modifiedUs;
  }
  boost::asio::post(cbEx, [cb, r]() { cb(r); });
}

void execRead(CesServer* server, FileExecReq req,
              std::function<void(FileExecResp)> cb,
              boost::asio::any_io_executor cbEx) {
  execWithSource(server, req, cb, cbEx, [&](L2Billing bill, minx::Hash, bool) -> FileExecResp {
    ReadOutcome out = readCore(server, req.name, req.offset, req.length,
                               hashOf(req.ownerPubkey), bill);
    FileExecResp r; r.status = out.status;
    if (out.status == CES_OK) r.data = std::move(out.data);
    return r;
  });
}

void execSetPrice(CesServer* server, FileExecReq req,
                  std::function<void(FileExecResp)> cb,
                  boost::asio::any_io_executor cbEx) {
  execWithSource(server, req, cb, cbEx, [&](L2Billing bill, minx::Hash, bool) -> FileExecResp {
    SetPriceOutcome out = setPriceCore(server, req.name, req.pricePerKb,
                                       hashOf(req.ownerPubkey), bill);
    FileExecResp r; r.status = out.status; r.pricePerKb = out.price;
    return r;
  });
}

void execWrite(CesServer* server, FileExecReq req,
               std::function<void(FileExecResp)> cb,
               boost::asio::any_io_executor cbEx) {
  execWithSource(server, req, cb, cbEx,
    [&](L2Billing bill, minx::Hash, bool) -> FileExecResp {
      WriteOutcome out = writeCore(server, req.name, req.offset, req.body,
                                   hashOf(req.ownerPubkey), bill);
      FileExecResp r; r.status = out.status; r.fileBalance = out.balance;
      return r;
    });
}

void execDeposit(CesServer* server, FileExecReq req,
                 std::function<void(FileExecResp)> cb,
                 boost::asio::any_io_executor cbEx) {
  execWithSource(server, req, cb, cbEx, [&](L2Billing bill, minx::Hash, bool) -> FileExecResp {
    DepositOutcome out = depositCore(server, req.name, req.amount, bill);
    FileExecResp r; r.status = out.status; r.fileBalance = out.balance;
    return r;
  });
}

void execWithdraw(CesServer* server, FileExecReq req,
                  std::function<void(FileExecResp)> cb,
                  boost::asio::any_io_executor cbEx) {
  execWithSource(server, req, cb, cbEx,
    [&](L2Billing bill, minx::Hash srcProg, bool metered) -> FileExecResp {
      // Withdrawn amount returns to the source program account (burned if /s/).
      std::optional<minx::Hash> dest =
        metered ? std::optional<minx::Hash>(srcProg) : std::nullopt;
      WithdrawOutcome out = withdrawCore(server, req.name, req.amount,
                                         hashOf(req.ownerPubkey), dest, bill);
      FileExecResp r; r.status = out.status; r.fileBalance = out.balance;
      return r;
    });
}

void execDelete(CesServer* server, FileExecReq req,
                std::function<void(FileExecResp)> cb,
                boost::asio::any_io_executor cbEx) {
  execWithSource(server, req, cb, cbEx,
    [&](L2Billing bill, minx::Hash srcProg, bool metered) -> FileExecResp {
      // Refund returns to the source program account (burned if /s/).
      std::optional<minx::Hash> dest =
        metered ? std::optional<minx::Hash>(srcProg) : std::nullopt;
      DeleteOutcome out = deleteCore(server, req.name, hashOf(req.ownerPubkey),
                                     dest, bill);
      FileExecResp r; r.status = out.status; r.refunded = out.refunded;
      return r;
    });
}

void execResize(CesServer* server, FileExecReq req,
                std::function<void(FileExecResp)> cb,
                boost::asio::any_io_executor cbEx) {
  execWithSource(server, req, cb, cbEx,
    [&](L2Billing bill, minx::Hash, bool) -> FileExecResp {
      ResizeOutcome out = resizeCore(server, req.name, req.size,
                                     hashOf(req.ownerPubkey), bill);
      FileExecResp r; r.status = out.status; r.fileBalance = out.balance;
      r.size = out.size;
      return r;
    });
}

void execAppend(CesServer* server, FileExecReq req,
                std::function<void(FileExecResp)> cb,
                boost::asio::any_io_executor cbEx) {
  execWithSource(server, req, cb, cbEx,
    [&](L2Billing bill, minx::Hash, bool) -> FileExecResp {
      AppendOutcome out = appendCore(server, req.name, req.body,
                                     hashOf(req.ownerPubkey), bill);
      FileExecResp r; r.status = out.status; r.fileBalance = out.balance;
      r.size = out.size;
      return r;
    });
}

void execCreate(CesServer* server, FileExecReq req,
                std::function<void(FileExecResp)> cb,
                boost::asio::any_io_executor cbEx) {
  if (req.size == 0 || req.size > kMaxFileSize) {
    FileExecResp r; r.status = CES_ERROR_BAD_INPUT;
    boost::asio::post(cbEx, [cb, r]() { cb(r); }); return;
  }
  uint8_t rc = validateCesFileName(req.name);
  if (rc != CES_OK) {
    FileExecResp r; r.status = rc;
    boost::asio::post(cbEx, [cb, r]() { cb(r); }); return;
  }
  std::array<uint8_t, 32> signerKey = req.ownerPubkey;
  std::string nameCopy = req.name;
  auto finish = [server, cb, cbEx, req = std::move(req)](uint8_t zoneRc) mutable {
    if (zoneRc != CES_OK) {
      FileExecResp r; r.status = zoneRc;
      boost::asio::post(cbEx, [cb, r]() { cb(r); }); return;
    }
    minx::Hash srcProg{}; bool metered = false;
    uint8_t srcRc = resolveSourceForBilling(server, req.sourceName, srcProg, metered);
    if (srcRc != CES_OK) {
      FileExecResp r; r.status = srcRc;
      boost::asio::post(cbEx, [cb, r]() { cb(r); }); return;
    }
    bool sourceInsufficient = false;
    CreateOutcome out = createCore(
      server, req.name, req.size, req.pricePerKb, req.initialDeposit,
      hashOf(req.ownerPubkey),
      sourceBilling(srcProg, metered, &sourceInsufficient));
    if (sourceInsufficient && metered) deleteExhaustedSource(server, req.sourceName);
    FileExecResp r; r.status = out.status; r.fileBalance = out.fileBalance;
    boost::asio::post(cbEx, [cb, r]() { cb(r); });
  };
  checkZoneOwnership(server, nameCopy, signerKey, cbEx, std::move(finish));
}

void execKvPut(CesServer* server, FileExecReq req,
               std::function<void(FileExecResp)> cb,
               boost::asio::any_io_executor cbEx) {
  execWithSource(server, req, cb, cbEx,
    [&](L2Billing bill, minx::Hash, bool) -> FileExecResp {
      KvPutOutcome out = kvPutCore(server, req.name, req.key, req.value,
                                   hashOf(req.ownerPubkey), req.amount, bill);
      FileExecResp r; r.status = out.status; r.fileBalance = out.balance;
      r.size = out.size; return r;
    });
}

void execKvDeposit(CesServer* server, FileExecReq req,
                   std::function<void(FileExecResp)> cb,
                   boost::asio::any_io_executor cbEx) {
  execWithSource(server, req, cb, cbEx,
    [&](L2Billing bill, minx::Hash, bool) -> FileExecResp {
      KvDepositOutcome out = kvDepositCore(server, req.name, req.key,
                                           req.amount, bill);
      FileExecResp r; r.status = out.status; r.fileBalance = out.balance;
      return r;
    });
}

void execKvGet(CesServer* server, FileExecReq req,
               std::function<void(FileExecResp)> cb,
               boost::asio::any_io_executor cbEx) {
  execWithSource(server, req, cb, cbEx,
    [&](L2Billing bill, minx::Hash, bool) -> FileExecResp {
      KvGetOutcome out = kvGetCore(server, req.name, req.key, bill);
      FileExecResp r; r.status = out.status; r.value = std::move(out.value);
      r.found = out.found; return r;
    });
}

void execKvErase(CesServer* server, FileExecReq req,
                 std::function<void(FileExecResp)> cb,
                 boost::asio::any_io_executor cbEx) {
  execWithSource(server, req, cb, cbEx,
    [&](L2Billing bill, minx::Hash, bool) -> FileExecResp {
      KvEraseOutcome out = kvEraseCore(server, req.name, req.key,
                                       hashOf(req.ownerPubkey), bill);
      FileExecResp r; r.status = out.status; r.size = out.size; return r;
    });
}

void execKvIter(CesServer* server, FileExecReq req,
                std::function<void(FileExecResp)> cb,
                boost::asio::any_io_executor cbEx) {
  execWithSource(server, req, cb, cbEx,
    [&](L2Billing bill, minx::Hash, bool) -> FileExecResp {
      KvIterOutcome out = kvIterCore(server, req.name, bill);
      FileExecResp r; r.status = out.status; r.keys = std::move(out.keys); return r;
    });
}

void execKvRange(CesServer* server, FileExecReq req,
                 std::function<void(FileExecResp)> cb,
                 boost::asio::any_io_executor cbEx) {
  execWithSource(server, req, cb, cbEx,
    [&](L2Billing, minx::Hash, bool) -> FileExecResp {
      KvRangeOutcome out = kvRangeCore(server, req.name, req.rangeLo,
                                       req.rangeHi, req.amount);
      FileExecResp r; r.status = out.status;
      r.keys = std::move(out.keys); r.values = std::move(out.values);
      r.rangeEnd = std::move(out.effectiveHi); return r;
    });
}

// kv CREATE mirrors flat CREATE: zone-check, then createCore with type=kv and
// size 0 (kv logical size starts empty and grows with PUT).
void execKvCreate(CesServer* server, FileExecReq req,
                  std::function<void(FileExecResp)> cb,
                  boost::asio::any_io_executor cbEx) {
  uint8_t rc = validateCesFileName(req.name);
  if (rc != CES_OK) {
    FileExecResp r; r.status = rc;
    boost::asio::post(cbEx, [cb, r]() { cb(r); }); return;
  }
  std::array<uint8_t, 32> signerKey = req.ownerPubkey;
  std::string nameCopy = req.name;
  auto finish = [server, cb, cbEx, req = std::move(req)](uint8_t zoneRc) mutable {
    if (zoneRc != CES_OK) {
      FileExecResp r; r.status = zoneRc;
      boost::asio::post(cbEx, [cb, r]() { cb(r); }); return;
    }
    minx::Hash srcProg{}; bool metered = false;
    uint8_t srcRc = resolveSourceForBilling(server, req.sourceName, srcProg, metered);
    if (srcRc != CES_OK) {
      FileExecResp r; r.status = srcRc;
      boost::asio::post(cbEx, [cb, r]() { cb(r); }); return;
    }
    bool sourceInsufficient = false;
    CreateOutcome out = createCore(
      server, req.name, /*size=*/0, req.pricePerKb, req.initialDeposit,
      hashOf(req.ownerPubkey),
      sourceBilling(srcProg, metered, &sourceInsufficient), kFileTypeKv);
    if (sourceInsufficient && metered) deleteExhaustedSource(server, req.sourceName);
    FileExecResp r; r.status = out.status; r.fileBalance = out.fileBalance;
    boost::asio::post(cbEx, [cb, r]() { cb(r); });
  };
  checkZoneOwnership(server, nameCopy, signerKey, cbEx, std::move(finish));
}

} // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

FileHandler::FileHandler(CesServer* server)
    : server_(server), kv_(std::make_unique<FileKvCache>()) {}

FileHandler::~FileHandler() { stop(); }

void FileHandler::stop() {
  stopped_.store(true);
  // Release kv handles so logkv flushes and a rebind reloads from disk. Each
  // mutation already flushed, so the flush here is belt-and-braces.
  std::lock_guard<std::mutex> lk(kv_->mutex);
  for (auto& [k, st] : kv_->stores) { try { st->flush(true); } catch (...) {} }
  kv_->stores.clear();
}

void FileHandler::serve(std::shared_ptr<minx::RudpStream> stream,
                        BoundChannelContext bound) {
  CesServer* server = server_;
  CesPlexProtocol proto;
  // accepts() also gates "still serving?" - false after stop() ends the loop.
  proto.accepts = [this](uint8_t verb) {
    return !stopped_.load() &&
           (verb == kVerbStat || (verb >= kVerbCreate && verb <= kVerbResize) ||
            verb == kVerbKvDeposit);
  };
  proto.dispatch = [](std::shared_ptr<ReqCtx> ctx, ces::Bytes pre) {
    switch (ctx->verb) {
      case kVerbCreate:    dispatchCreate   (ctx, std::move(pre)); break;
      case kVerbWrite:     dispatchWrite    (ctx, std::move(pre)); break;
      case kVerbRead:      dispatchRead     (ctx, std::move(pre)); break;
      case kVerbStat:      dispatchStat     (ctx, std::move(pre)); break;
      case kVerbDeposit:   dispatchDeposit  (ctx, std::move(pre)); break;
      case kVerbWithdraw:  dispatchWithdraw (ctx, std::move(pre)); break;
      case kVerbSetPrice:  dispatchSetPrice (ctx, std::move(pre)); break;
      case kVerbDelete:    dispatchDelete   (ctx, std::move(pre)); break;
      case kVerbAppend:    dispatchAppend   (ctx, std::move(pre)); break;
      case kVerbResize:    dispatchResize   (ctx, std::move(pre)); break;
      case kVerbKvDeposit: dispatchKvDeposit(ctx, std::move(pre)); break;
      default:             ctx->error(CES_ERROR_BAD_INPUT); break;
    }
  };
  cesPlexServe(std::move(stream), std::move(bound), server, std::move(proto));
}

void FileHandler::sweepKvRent() {
  CesServer* server = server_;
  const auto& cfg = server->_config();
  const int64_t feeRent = cfg.feeFileRent;
  const uint64_t now = getMicrosSinceEpoch();

  // Collect metered kv-store names first (the walk does not hold the kv mutex).
  std::vector<std::string> stores;
  walkFileStore(cfg.cesFileStoreDir,
    [&](const std::filesystem::path&, const std::filesystem::path&, Sidecar& s) {
      if (s.type == kFileTypeKv && !isServerZone(s.name)) stores.push_back(s.name);
    });

  for (const auto& name : stores) {
    // logkv update/flush throw on a disk error. This runs on taskIO_, so an
    // escaped throw would terminate the server; contain it per store (one bad
    // store is skipped, the rest still sweep).
    try {
      auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
      Sidecar sc{};
      if (!readSidecar(sPath, sc)) continue;       // GC'd between walk and now
      if (sc.type != kFileTypeKv) continue;

      uint64_t totalCharge = 0;
      int64_t sizeDelta = 0;
      {
        std::lock_guard<std::mutex> kvLk(server->fileHandler()->kv_->mutex);
        KvStore* st = kvStoreOpenLocked(server, cfg.cesFileStoreDir, name);
        if (!st) continue;
        std::vector<logkv::Bytes> toErase;
        std::vector<std::pair<logkv::Bytes, logkv::Bytes>> toUpdate;
        for (auto& kv : st->getObjects()) {
          KvCell c{};
          if (!kvCellParse(kv.second, c)) continue;
          uint64_t bytes = kv.first.size() + kv.second.size();
          uint64_t owed = computeOwedRent(bytes, feeRent, c.lastChargedUs, now);
          uint64_t charge = owed < c.balance ? owed : c.balance;
          totalCharge += charge;
          uint64_t nb = c.balance - charge;
          if (nb == 0) {
            toErase.push_back(kv.first);
            sizeDelta -= static_cast<int64_t>(bytes);
          } else {
            // Copy user bytes now: c.user points into the stored value.
            toUpdate.emplace_back(kv.first, kvCellBuild(nb, now, c.user, c.userLen));
          }
        }
        for (auto& [k, v] : toUpdate) st->update(k, v);
        for (auto& k : toErase) st->erase(k);
        if (!toUpdate.empty() || !toErase.empty()) st->flush(true);
      }
      // Burn the rent from the store pot. The kv mutex is released, so the
      // logicStrand hop holds no kv lock.
      if (totalCharge > 0) debitProgramAccount(server, sc, totalCharge);
      if (sizeDelta != 0) {
        Sidecar sc2{};
        if (readSidecar(sPath, sc2)) {
          uint64_t dec = static_cast<uint64_t>(-sizeDelta);
          sc2.size = sc2.size > dec ? sc2.size - dec : 0;
          sc2.modified_us = now;
          writeSidecar(sPath, sc2);
          std::lock_guard<std::mutex> mlk(server->fileHandler()->storeMetaMutex_);
          adjustStoreMeta(cfg.cesFileStoreDir, 0, sizeDelta);
        }
      }
    } catch (const std::exception& e) {
      LOGDEBUG << "kv rent sweep skipped a store" << SVAR(name) << SVAR(e.what());
    } catch (...) {
      LOGDEBUG << "kv rent sweep skipped a store" << SVAR(name);
    }
  }
}

bool FileHandler::readProgramPubkey(
    const std::string& name,
    std::array<uint8_t, 32>& outProgramPubkey) {
  CesServer* server = server_;
  if (!server) return false;
  const auto& cfg = server->_config();
  Sidecar sc{};
  if (!loadSidecar(server, cfg.cesFileStoreDir, name, sc)) return false;
  outProgramPubkey = sc.program_pubkey;
  return true;
}

// Read the file's program-account ed25519 private key from its sidecar.
// All-zero on success means the account has no signing key (no remote
// signing). False if the sidecar is unreadable.
bool FileHandler::readProgramPrivkey(
    const std::string& name,
    std::array<uint8_t, 32>& outProgramPrivkey) {
  CesServer* server = server_;
  if (!server) return false;
  const auto& cfg = server->_config();
  Sidecar sc{};
  if (!loadSidecar(server, cfg.cesFileStoreDir, name, sc)) return false;
  outProgramPrivkey = sc.program_privkey;
  return true;
}

bool FileHandler::readOwnerAndBalance(
    const std::string& name,
    std::array<uint8_t, 32>& outOwnerPubkey,
    uint64_t& outFileBalance) {
  CesServer* server = server_;
  if (!server) return false;
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!loadSidecar(server, cfg.cesFileStoreDir, name, sc)) return false;
  if (!chargeRentOrDelete(server, cPath, sPath, sc, cfg.feeFileRent,
                          cfg.cesFileStoreDir)) {
    // chargeRentOrDelete already fired notifyDeletion + removed disk.
    return false;
  }
  if (!writeSidecar(sPath, sc)) return false;
  outOwnerPubkey = sc.owner_pubkey;
  outFileBalance = readProgramAccountBalance(server, sc);
  return true;
}

bool FileHandler::creditBalance(const std::string& name, uint64_t amount) {
  CesServer* server = server_;
  if (!server) return false;
  if (amount == 0) return true;
  // /s/ files are unmetered - operator donates via the reconcile-time
  // top-up. Treat additional credits as a no-op; the /s/ balance is
  // decorative and never consulted for billing.
  if (isServerZone(name)) return true;
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) return false;
  if (!chargeRentOrDelete(server, cPath, sPath, sc, cfg.feeFileRent,
                          cfg.cesFileStoreDir)) {
    return false; // chargeRentOrDelete already notified
  }
  creditProgramAccount(server, sc, amount);
  sc.modified_us = getMicrosSinceEpoch();
  if (!writeSidecar(sPath, sc)) return false;
  return true;
}

bool FileHandler::getProgramHash(
    const std::string& name,
    std::array<uint8_t, 32>& outHash) {
  CesServer* server = server_;
  if (!server) return false;
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) return false;
  if (!chargeRentOrDelete(server, cPath, sPath, sc, cfg.feeFileRent,
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

bool FileHandler::debitBalance(const std::string& name, uint64_t amount) {
  CesServer* server = server_;
  if (!server) return false;
  // /s/ files are unmetered - operator donates everything via the
  // reconcile-time top-up. Treat any debit as a successful no-op so
  // the compute supervisor tick / /s/ program ops don't accidentally
  // trip the balance-exhausted deletion path.
  if (isServerZone(name)) return true;
  const auto& cfg = server->_config();
  auto sPath = resolveSidecarPath(cfg.cesFileStoreDir, name);
  auto cPath = resolveContentPath(cfg.cesFileStoreDir, name);
  Sidecar sc{};
  if (!readSidecar(sPath, sc)) return false;
  if (!chargeRentOrDelete(server, cPath, sPath, sc, cfg.feeFileRent,
                          cfg.cesFileStoreDir)) {
    return false; // chargeRentOrDelete already notified
  }

  auto debit = debitProgramAccount(server, sc, amount);
  bool insufficient = !debit.ok;

  if (insufficient) {
    // Debit exhaustion - treat exactly like rent exhaustion: delete.
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
      std::lock_guard lk(server->fileHandler()->storeMetaMutex_);
      adjustStoreMeta(cfg.cesFileStoreDir, -1,
                      -static_cast<int64_t>(sc.size));
    }
    notifyDeletion(server, sc.name);
    return false;
  }
  sc.modified_us = getMicrosSinceEpoch();
  if (!writeSidecar(sPath, sc)) return false;
  return true;
}

void FileHandler::registerDeletionCallback(
    std::function<void(const std::string&)> cb) {
  if (!cb) return;
  std::lock_guard lk(deletionCallbacksMutex_);
  deletionCallbacks_.push_back(std::move(cb));
}

void FileHandler::exec(
    const FileExecReq& req,
    std::function<void(FileExecResp)> cb,
    boost::asio::any_io_executor cbEx) {
  CesServer* server = server_;
  if (!server) {
    FileExecResp r; r.status = CES_ERROR_DISABLED;
    boost::asio::post(cbEx, [cb, r]() { cb(r); });
    return;
  }
  // The kv cores call into logkv, which throws std::runtime_error on any
  // filesystem/write error (disk full, IO fault); the synchronous exec path
  // runs on rpcTaskIO, so an escaped throw would std::terminate the server. A
  // catch-all here converts it into an INTERNAL reply: the verb fails, the
  // server lives. The flat cores never throw past their own narrow catches, so
  // this is the real guard for the kv verbs.
  try {
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
      case kVerbKvCreate: execKvCreate(server, req, cb, cbEx); return;
      case kVerbKvPut:    execKvPut   (server, req, cb, cbEx); return;
      case kVerbKvGet:    execKvGet   (server, req, cb, cbEx); return;
      case kVerbKvErase:  execKvErase (server, req, cb, cbEx); return;
      case kVerbKvIter:   execKvIter  (server, req, cb, cbEx); return;
      case kVerbKvDeposit: execKvDeposit(server, req, cb, cbEx); return;
      case kVerbKvRange:  execKvRange (server, req, cb, cbEx); return;
      default: break;
    }
  } catch (const std::exception& e) {
    LOGDEBUG << "exec threw" << VAR((int)req.verb) << SVAR(e.what());
  } catch (...) {
    LOGDEBUG << "exec threw (non-std)" << VAR((int)req.verb);
  }
  FileExecResp r; r.status = CES_ERROR_INTERNAL;
  boost::asio::post(cbEx, [cb, r]() { cb(r); });
}


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

    // Compute the canonical CES name: "/s/<rel>". it->path() is absolute;
    // strip the dir prefix and prepend "/".
    fs::path rel = fs::relative(cPath, fs::path(dir));
    std::string name = "/" + rel.generic_string();
    // The generated /s/ catalog and the bundled welcome site are static server
    // content (seeded with their own sidecars elsewhere) - never mint them a
    // program account.
    if (name == kServerIndexName) continue;
    if (isBuiltinSitePath(name)) continue;

    // Same per-file mint the on-access lazy path uses: one mechanism, two
    // callers. Boot eagerly walks the whole zone so already-deployed programs
    // are stamped and topped up before launchExtensions runs.
    Sidecar s{};
    reconcileOneServerZoneFile(server, dir, name, s);
  }
}

// Daily per-extension local-budget sweep: top every /s/ program account up to the
// server's extLocalBudget (deficit only). Runs off logicStrand_ (the top-up
// sync-hops to it), called from dailyTaskTick. No-op if the file feature or the
// budget is off.
void FileHandler::sweepExtensionBudget() {
  CesServer* server = server_;
  const auto& cfg = server->_config();
  // No cap gate: /s/ is unmetered and present whenever file is mounted (this
  // is a FileHandler method, so the handler exists), even at cap 0. The only
  // gate is the budget itself.
  if (server->extLocalBudget() == 0) return;
  namespace fs = std::filesystem;
  const std::string& dir = cfg.cesFileStoreDir;
  fs::path sRoot = fs::path(dir) / "s";
  std::error_code ec;
  if (!fs::exists(sRoot, ec)) return;
  const std::string suffix = kSidecarSuffix;
  size_t topped = 0;
  for (auto it = fs::recursive_directory_iterator(sRoot, ec);
       !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
    if (!it->is_regular_file()) continue;
    std::string fn = it->path().filename().string();
    if (fn.size() >= suffix.size() &&
        fn.compare(fn.size() - suffix.size(), suffix.size(), suffix) == 0) continue;
    fs::path rel = fs::relative(it->path(), fs::path(dir));
    std::string name = "/" + rel.generic_string();
    if (name == kServerIndexName || isBuiltinSitePath(name)) continue;
    Sidecar sc{};
    if (!loadSidecar(server, dir, name, sc)) continue;
    if (topUpProgramAccountToCap(server, sc)) ++topped;
  }
  LOGINFO << "extension budget swept" << VAR(topped);
}

// Publish the bundled /s/welcome site into the file store. Forced by the file
// feature (no switch) and overwritten on every boot, so the served demo always
// matches the binary. Pure disk on the file/rpc strand (like
// regenerateServerIndex): no verbs, no logicStrand_, no program account. Each
// file gets a minimal server-owned sidecar; reconcileServerZone skips these
// names (isBuiltinSitePath), so they're never minted one.
void seedBuiltinSite(CesServer* server, const std::string& dir) {
  if (!server) return;
  namespace fs = std::filesystem;
  std::array<uint8_t, 32> serverPk{};
  std::memcpy(serverPk.data(),
              server->_serverKeyPair().getPublicKeyAsHash().data(), 32);
  for (const auto& f : builtinSiteFiles()) {
    const std::string name = "/s/" + f.relPath;
    std::error_code ec;
    fs::path cPath = resolveContentPath(dir, name);
    fs::create_directories(cPath.parent_path(), ec);
    fs::path tmp = cPath; tmp += ".tmp";
    {
      std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
      if (!out) { LOGWARNING << "/s/ site open failed" << SVAR(name); continue; }
      out.write(f.content.data(), static_cast<std::streamsize>(f.content.size()));
      if (!out.good()) { LOGWARNING << "/s/ site write failed" << SVAR(name); continue; }
    }
    fs::rename(tmp, cPath, ec);
    if (ec) { LOGWARNING << "/s/ site rename failed" << SVAR(name); fs::remove(tmp, ec); continue; }

    Sidecar s{};
    s.version = kSidecarVersion;
    s.name = name;
    s.owner_pubkey = serverPk;
    s.price_per_kb = 0;
    s.size = f.content.size();
    s.created_us = getMicrosSinceEpoch();
    s.modified_us = s.created_us;
    s.last_rent_us = s.created_us;
    writeSidecar(resolveSidecarPath(dir, name), s);
  }
  LOGDEBUG << "/s/welcome site published";
}

void FileHandler::startupReconcile() {
  CesServer* server = server_;
  if (!server) return;
  const std::string& dir = server->_config().cesFileStoreDir;
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  // Publish the bundled /s/welcome site (forced with the file feature), then
  // auto-generate sidecars for any /s/ files the operator dropped on disk.
  seedBuiltinSite(server, dir);
  reconcileServerZone(server, dir);
  // (Re)generate the /s/ catalog at boot so it reflects the seeded site plus
  // whatever the operator dropped. Runtime /s/ changes keep it current after.
  regenerateServerIndex(server, dir);
  StoreMeta m{};
  walkFileStore(dir, [&m](const std::filesystem::path&,
                          const std::filesystem::path&, Sidecar& s) {
    // /s/ files live outside the cap - don't count them.
    if (isServerZone(s.name)) return;
    m.total_files += 1;
    m.total_bytes += s.size;
  });
  std::lock_guard lk(server->fileHandler()->storeMetaMutex_);
  writeStoreMeta(storeMetaPath(dir), m);
  LOGINFO << "store reconciled"
          << VAR(m.total_files) << VAR(m.total_bytes);
}

// --- /s/ file read/write/remove for L2 cross-handler use (the extension manager) -
// A /s/ file is content-on-disk plus a reconcile-stamped sidecar. The write is
// atomic and re-stamps the sidecar; it runs off logicStrand_ (its reconcile
// sync-hops to it), like the boot scan.

std::string FileHandler::readServerFile(const std::string& name) {
  CesServer* server = server_;
  if (!server || !isServerZone(name)) return "";
  std::ifstream f(resolveContentPath(server->_config().cesFileStoreDir, name),
                  std::ios::binary);
  if (!f) return "";
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

bool FileHandler::writeServerFile(const std::string& name, const std::string& content) {
  CesServer* server = server_;
  if (!server || !isServerZone(name)) return false;
  const std::string& dir = server->_config().cesFileStoreDir;
  auto cPath = resolveContentPath(dir, name);
  std::error_code ec;
  std::filesystem::create_directories(cPath.parent_path(), ec);
  // Atomic temp + rename: a crash mid-write never leaves a half file.
  auto tmp = cPath; tmp += ".tmp";
  {
    std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write(content.data(), static_cast<std::streamsize>(content.size()));
    if (!f.good()) return false;
  }
  std::filesystem::rename(tmp, cPath, ec);
  if (ec) return false;
  // Re-stamp the sidecar to the new content (reconcileOneServerZoneFile).
  Sidecar sc{};
  reconcileOneServerZoneFile(server, dir, name, sc);
  return true;
}

bool FileHandler::removeServerFile(const std::string& name) {
  CesServer* server = server_;
  if (!server || !isServerZone(name)) return false;
  const std::string& dir = server->_config().cesFileStoreDir;
  std::error_code ec;
  std::filesystem::remove(resolveContentPath(dir, name), ec);
  std::filesystem::remove(resolveSidecarPath(dir, name), ec);
  return true;
}

bool FileHandler::storeStats(uint64_t& outTotalFiles, uint64_t& outTotalBytes) {
  CesServer* server = server_;
  if (!server) return false;
  const std::string& dir = server->_config().cesFileStoreDir;
  StoreMeta m{};
  std::lock_guard lk(server->fileHandler()->storeMetaMutex_);
  readStoreMeta(storeMetaPath(dir), m);  // tolerant of a missing file
  outTotalFiles = m.total_files;
  outTotalBytes = m.total_bytes;
  return true;
}


} // namespace ces
