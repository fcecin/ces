#include <ces/ramfilestore.h>
#include <ces/buffer.h>


#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <random>
#include <set>
#include <sstream>

#include <cryptopp/sha.h>
#include <minx/types.h>

namespace ces {

// Random 32-byte chunk keys collide vanishingly rarely, but a user who pins
// their RNG or reuses the same seed could hit repeated ASSET_EXISTS rejections.
// Retry this many times before surfacing the error.
static constexpr int MAX_CHUNK_COLLISION_RETRIES = 10;

// Upper bound on the bytes ramfileGet pre-reserves from a head's declared
// size, so a corrupt/hostile head can't request a giant allocation up front.
// The output still grows past this if the real chain actually carries more.
static constexpr size_t RAMFILE_GET_RESERVE_CAP = 64u * 1024 * 1024;

// --- Helpers ---

minx::Hash sha256(const uint8_t* data, size_t len) {
  minx::Hash h;
  CryptoPP::SHA256().CalculateDigest(h.data(), data, len);
  return h;
}

static uint64_t nowMicros() {
  return static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count());
}

static bool isZeroHash(const minx::Hash& h) {
  for (auto b : h) if (b != 0) return false;
  return true;
}

// All BE serialization goes through ces::Buffer (see ces/buffer.h).

// --- File format ---

RamfileHeader parseRamfileHeader(const AssetData& c) {
  RamfileHeader h;
  if (c[0] != RAMFILE_MAGIC) return h;
  h.fileSize = ces::Buffer::peek<uint64_t>(&c[1]);
  std::memcpy(h.contentHash.data(), &c[9], 32);
  h.createdTime = ces::Buffer::peek<uint64_t>(&c[RAMFILE_HEAD_CTIME_OFFSET]);
  h.modifiedTime = ces::Buffer::peek<uint64_t>(&c[RAMFILE_HEAD_MTIME_OFFSET]);
  std::memcpy(h.metadata.data(), &c[RAMFILE_HEAD_META_OFFSET], RAMFILE_HEAD_META_SIZE);
  std::memcpy(h.firstChunk.data(), &c[RAMFILE_NEXT_OFFSET], RAMFILE_NEXT_SIZE);
  h.valid = true;
  return h;
}

AssetData buildRamfileHeader(uint64_t fileSize, const minx::Hash& contentHash,
                          uint64_t createdTime, uint64_t modifiedTime,
                          const uint8_t* metadata, size_t metaLen,
                          const minx::Hash& firstChunk) {
  AssetData d{};
  d[0] = RAMFILE_MAGIC;
  ces::Buffer::poke<uint64_t>(&d[1], fileSize);
  std::memcpy(&d[9], contentHash.data(), 32);
  ces::Buffer::poke<uint64_t>(&d[RAMFILE_HEAD_CTIME_OFFSET], createdTime);
  ces::Buffer::poke<uint64_t>(&d[RAMFILE_HEAD_MTIME_OFFSET], modifiedTime);
  if (metadata && metaLen > 0) {
    size_t n = std::min(metaLen, RAMFILE_HEAD_META_SIZE);
    std::memcpy(&d[RAMFILE_HEAD_META_OFFSET], metadata, n);
  }
  std::memcpy(&d[RAMFILE_NEXT_OFFSET], firstChunk.data(), RAMFILE_NEXT_SIZE);
  return d;
}

AssetData buildRamfileChunk(const uint8_t* data, size_t dataLen,
                     const minx::Hash& nextKey) {
  AssetData d{};
  size_t n = std::min(dataLen, RAMFILE_CHUNK_DATA_SIZE);
  if (data && n > 0)
    std::memcpy(d.data(), data, n);
  std::memcpy(&d[RAMFILE_NEXT_OFFSET], nextKey.data(), RAMFILE_NEXT_SIZE);
  return d;
}

// Fetch the head asset at `headKey`, parse the file header, and return it.
// Returns CES_OK on success, CES_ERROR_INTERNAL if the content is not a valid
// file header, or the underlying query error code.
static uint8_t readHead(CesClient& client, const minx::Hash& headKey,
                        RamfileHeader& outHeader, AssetData* outRawContent = nullptr) {
  HashPrefix owner;
  AssetData content;
  uint16_t balance = 0;
  uint32_t price = 0;
  uint8_t rc = client.queryAsset(headKey, owner, content, balance, price);
  if (rc != CES_OK) return rc;
  outHeader = parseRamfileHeader(content);
  if (!outHeader.valid) return CES_ERROR_INTERNAL;
  if (outRawContent) *outRawContent = content;
  return CES_OK;
}

// Rebuild the head content from `header` and write it via updateAssetFast.
// Bumps `modifiedTime` to now. Pass an explicit `contentHash` (zeros for
// "dirty" / unknown, or an actual hash for rehash).
static uint8_t touchHead(CesClient& client, const minx::Hash& headKey,
                         RamfileHeader& header,
                         const minx::Hash& contentHash) {
  header.contentHash = contentHash;
  header.modifiedTime = nowMicros();
  AssetData headContent = buildRamfileHeader(
    header.fileSize, header.contentHash,
    header.createdTime, header.modifiedTime,
    header.metadata.data(), RAMFILE_HEAD_META_SIZE,
    header.firstChunk);
  return client.updateAssetFast(headKey, headContent);
}

// Create a chain of chunks covering `data[0..totalLen)` by splitting it into
// RAMFILE_CHUNK_DATA_SIZE-sized pieces, working backward so each chunk can embed
// the key of its successor. `terminalNextKey` is the "next" pointer of the
// last chunk (zero hash for a new tail, or an existing chunk key when
// prepending before an existing chain).
//
// On success, appends the newly-created chunk keys in FORWARD order (first
// chunk → last chunk) to `outKeys`. Chunk keys are random uint256 values
// with retry-on-collision. Returns CES_OK or the underlying error.
//
static uint8_t createChunkChain(CesClient& client,
                                const uint8_t* data, size_t totalLen,
                                uint16_t days,
                                const minx::Hash& terminalNextKey,
                                std::vector<minx::Hash>& outKeys) {
  const size_t count =
    (totalLen + RAMFILE_CHUNK_DATA_SIZE - 1) / RAMFILE_CHUNK_DATA_SIZE;
  if (count == 0) return CES_OK;

  std::mt19937_64 rng(std::random_device{}());
  minx::Hash nextKey = terminalNextKey;
  const size_t firstAppendIdx = outKeys.size();

  for (size_t ri = 0; ri < count; ++ri) {
    const size_t i = count - 1 - ri;
    const size_t off = i * RAMFILE_CHUNK_DATA_SIZE;
    const size_t len = std::min(RAMFILE_CHUNK_DATA_SIZE, totalLen - off);

    auto content = buildRamfileChunk(data + off, len, nextKey);

    minx::Hash chunkKey;
    uint8_t rc = CES_ERROR_INTERNAL;
    for (int attempt = 0; attempt < MAX_CHUNK_COLLISION_RETRIES; ++attempt) {
      for (auto& b : chunkKey) b = static_cast<uint8_t>(rng());
      rc = client.createAsset(chunkKey, content, days);
      if (rc == CES_OK) break;
      if (rc != CES_ERROR_ASSET_EXISTS) return rc;
    }
    if (rc != CES_OK) return rc;

    nextKey = chunkKey;
    outKeys.push_back(chunkKey);
  }

  // We pushed backward — flip the newly-added range to forward order.
  std::reverse(outKeys.begin() + firstAppendIdx, outKeys.end());
  return CES_OK;
}

// --- Upload ---

uint8_t ramfilePut(CesClient& client, const minx::Hash& headKey,
                const uint8_t* data, size_t dataLen,
                uint16_t days,
                const uint8_t* metadata, size_t metaLen,
                std::function<void(size_t, size_t)> progress) {
  // Create the chunk chain (backward, so each chunk knows its successor).
  std::vector<minx::Hash> chunkKeys;
  uint8_t rc = createChunkChain(client, data, dataLen, days,
                                minx::Hash{}, chunkKeys);
  if (rc != CES_OK) return rc;

  const size_t numChunks = chunkKeys.size();
  if (progress)
    progress(numChunks, numChunks + 1); // +1 for head

  // Build and create head asset
  minx::Hash firstChunkKey = numChunks > 0 ? chunkKeys[0] : minx::Hash{};
  minx::Hash contentHash = sha256(data, dataLen);
  uint64_t now = nowMicros();
  auto headContent = buildRamfileHeader(dataLen, contentHash,
                                      now, now,
                                      metadata, metaLen, firstChunkKey);

  rc = client.createAsset(headKey, headContent, days);
  if (rc != CES_OK) return rc;

  if (progress)
    progress(numChunks + 1, numChunks + 1);

  return CES_OK;
}

// --- Download ---

uint8_t ramfileGet(CesClient& client, const minx::Hash& headKey,
                ces::Bytes& outData,
                RamfileHeader* outHeader,
                bool* hashMismatch) {
  RamfileHeader header;
  uint8_t rc = readHead(client, headKey, header);
  if (rc != CES_OK) return rc;
  if (outHeader) *outHeader = header;

  outData.clear();
  if (header.fileSize == 0) {
    if (hashMismatch) *hashMismatch = false;
    return CES_OK;
  }

  // Walk chunk chain
  outData.reserve(std::min<uint64_t>(header.fileSize, RAMFILE_GET_RESERVE_CAP));
  minx::Hash nextKey = header.firstChunk;
  std::set<minx::Hash> visited;

  while (!isZeroHash(nextKey) && outData.size() < header.fileSize) {
    if (!visited.insert(nextKey).second) return CES_ERROR_INTERNAL; // cycle
    HashPrefix chunkOwner;
    AssetData chunkContent;
    uint16_t chunkBalance = 0;
    uint32_t chunkPrice = 0;
    rc = client.queryAsset(nextKey, chunkOwner, chunkContent, chunkBalance, chunkPrice);
    if (rc != CES_OK) return rc;

    // Extract payload
    size_t remaining = header.fileSize - outData.size();
    size_t take = std::min(remaining, RAMFILE_CHUNK_DATA_SIZE);
    outData.insert(outData.end(), chunkContent.begin(),
                   chunkContent.begin() + take);

    // Follow next pointer
    std::memcpy(nextKey.data(), &chunkContent[RAMFILE_NEXT_OFFSET], RAMFILE_NEXT_SIZE);
  }

  // Verify hash
  if (hashMismatch) {
    minx::Hash actual = sha256(outData.data(), outData.size());
    *hashMismatch = (actual != header.contentHash);
  }

  return CES_OK;
}

// --- Fund ---

uint8_t ramfileFund(CesClient& client, const minx::Hash& headKey, uint16_t days) {
  // Fund head
  uint8_t rc = client.fundAsset(headKey, days);
  if (rc != CES_OK) return rc;

  // Read head to get first chunk
  RamfileHeader header;
  rc = readHead(client, headKey, header);
  if (rc != CES_OK) return rc;

  // Walk and fund each chunk
  minx::Hash nextKey = header.firstChunk;
  std::set<minx::Hash> visited;
  while (!isZeroHash(nextKey)) {
    if (!visited.insert(nextKey).second) return CES_ERROR_INTERNAL; // cycle
    rc = client.fundAsset(nextKey, days);
    if (rc != CES_OK) return rc;

    // Read chunk to follow chain
    HashPrefix chunkOwner;
    AssetData chunkContent;
    uint16_t chunkBalance = 0;
    uint32_t chunkPrice = 0;
    rc = client.queryAsset(nextKey, chunkOwner, chunkContent, chunkBalance, chunkPrice);
    if (rc != CES_OK) return rc;

    std::memcpy(nextKey.data(), &chunkContent[RAMFILE_NEXT_OFFSET], RAMFILE_NEXT_SIZE);
  }

  return CES_OK;
}

// --- Scan ---

uint8_t ramfileScan(CesClient& client, const minx::Hash& headKey,
                 std::vector<minx::Hash>& outKeys) {
  outKeys.clear();
  outKeys.push_back(headKey);

  RamfileHeader header;
  uint8_t rc = readHead(client, headKey, header);
  if (rc != CES_OK) return rc;

  minx::Hash nextKey = header.firstChunk;
  std::set<minx::Hash> visited;
  while (!isZeroHash(nextKey)) {
    if (!visited.insert(nextKey).second) return CES_ERROR_INTERNAL; // cycle
    outKeys.push_back(nextKey);

    HashPrefix chunkOwner;
    AssetData chunkContent;
    uint16_t chunkBalance = 0;
    uint32_t chunkPrice = 0;
    rc = client.queryAsset(nextKey, chunkOwner, chunkContent, chunkBalance, chunkPrice);
    if (rc != CES_OK) return rc;

    std::memcpy(nextKey.data(), &chunkContent[RAMFILE_NEXT_OFFSET], RAMFILE_NEXT_SIZE);
  }

  return CES_OK;
}

uint8_t ramfileFundFromScan(CesClient& client,
                         const std::vector<minx::Hash>& keys, uint16_t days) {
  for (auto& key : keys) {
    uint8_t rc = client.fundAsset(key, days);
    if (rc != CES_OK) return rc;
  }
  return CES_OK;
}

// --- Scan file I/O ---

static bool isReadableUTF8(const minx::Hash& key) {
  // Check if key is a short null-terminated printable ASCII string
  size_t len = 0;
  for (size_t i = 0; i < key.size(); ++i) {
    if (key[i] == 0) break;
    if (key[i] < 32 || key[i] > 126) return false;
    len = i + 1;
  }
  return len > 0 && len <= 31;
}

std::string buildRamfileScanFilename(const minx::Hash& headKey,
                              const std::string& serverAddr) {
  std::string name;
  if (isReadableUTF8(headKey)) {
    size_t len = 0;
    for (size_t i = 0; i < headKey.size() && headKey[i]; ++i) len++;
    name = std::string(reinterpret_cast<const char*>(headKey.data()), len);
  } else {
    name = minx::hashToString(headKey);
  }
  // Replace ':' with '.' in server address (port separator breaks filenames)
  std::string safeAddr = serverAddr;
  for (auto& c : safeAddr) if (c == ':') c = '.';
  return name + "@" + safeAddr + ".scan";
}

void writeRamfileScan(const std::string& path,
                   const std::vector<minx::Hash>& keys) {
  std::ofstream ofs(path);
  for (auto& key : keys)
    ofs << minx::hashToString(key) << "\n";
}

std::vector<minx::Hash> readRamfileScan(const std::string& path) {
  std::vector<minx::Hash> keys;
  std::ifstream ifs(path);
  if (!ifs) return keys;
  std::string line;
  while (std::getline(ifs, line)) {
    if (line.empty()) continue;
    minx::Hash h;
    minx::stringToHash(h, line);
    keys.push_back(h);
  }
  return keys;
}

// --- Read at offset ---

uint8_t ramfileRead(CesClient& client, const std::vector<minx::Hash>& keys,
                 uint64_t offset, uint64_t length,
                 ces::Bytes& outData) {
  if (keys.empty()) return CES_ERROR_INTERNAL;
  outData.clear();

  // Read head to get file size
  RamfileHeader header;
  uint8_t rc = readHead(client, keys[0], header);
  if (rc != CES_OK) return rc;
  HashPrefix owner;  // used below for chunk queries

  if (offset >= header.fileSize) return CES_OK; // past end
  uint64_t available = header.fileSize - offset;
  if (length > available) length = available;
  outData.reserve(length);

  // Find starting chunk: keys[0] = head (no data), keys[1..] = data chunks
  // Each chunk holds RAMFILE_CHUNK_DATA_SIZE bytes
  size_t startChunk = offset / RAMFILE_CHUNK_DATA_SIZE;       // 0-based chunk index
  size_t startByte = offset % RAMFILE_CHUNK_DATA_SIZE;         // byte within chunk
  size_t chunkKeyIdx = startChunk + 1;                      // keys[0] is head

  uint64_t remaining = length;
  while (remaining > 0 && chunkKeyIdx < keys.size()) {
    AssetData chunkContent;
    uint16_t cd = 0; uint32_t cp = 0;
    rc = client.queryAsset(keys[chunkKeyIdx], owner, chunkContent, cd, cp);
    if (rc != CES_OK) return rc;

    size_t chunkDataAvail = RAMFILE_CHUNK_DATA_SIZE - startByte;
    size_t take = std::min(static_cast<uint64_t>(chunkDataAvail), remaining);
    outData.insert(outData.end(),
                   chunkContent.begin() + startByte,
                   chunkContent.begin() + startByte + take);
    remaining -= take;
    startByte = 0; // subsequent chunks start at 0
    ++chunkKeyIdx;
  }

  return CES_OK;
}

// --- Write at offset ---

// Writes bytes at `offset` into the file's pre-allocated chain. Bounded
// by chain capacity (keys.size() - 1) * RAMFILE_CHUNK_DATA_SIZE, not by the
// declared `header.fileSize`. If the write extends past the current
// declared size, `header.fileSize` is grown to cover the written range.
// The declared size is never shrunk here.
//
// The write walks chunks via the scan file. On the first chunk-level
// failure (query returns non-OK, updateAssetFast returns non-OK — most
// commonly CES_ERROR_NOT_OWNER if ownership of a pre-existing chunk
// has changed), the function stops mid-stream, touches the head (with
// whatever the new fileSize is), and returns the underlying error.
//
// Return semantics:
//   CES_OK                 — every byte was written
//   CES_ERROR_INTERNAL     — ran out of chain capacity before `dataLen` bytes
//                            were consumed (no chunk error; just ran out)
//   other error            — first chunk-level error encountered
//
// Partial-write observability: if the write extended past the old
// `fileSize`, the new `fileSize` reflects exactly how far the write
// reached. If the write was entirely within the old `fileSize` region,
// `fileSize` is unchanged and the caller cannot tell from the header
// alone how much landed — that region is indeterminate on failure.

uint8_t ramfileWrite(CesClient& client, const std::vector<minx::Hash>& keys,
                  uint64_t offset, const uint8_t* data, size_t dataLen) {
  if (keys.empty()) return CES_ERROR_INTERNAL;

  RamfileHeader header;
  uint8_t rc = readHead(client, keys[0], header);
  if (rc != CES_OK) return rc;

  const uint64_t capacity =
    static_cast<uint64_t>(keys.size() - 1) * RAMFILE_CHUNK_DATA_SIZE;
  if (offset > capacity) return CES_ERROR_INTERNAL;

  // Walk chunks from the starting position, writing payload.
  size_t chunkKeyIdx = (offset / RAMFILE_CHUNK_DATA_SIZE) + 1; // keys[0] is head
  size_t startByte = offset % RAMFILE_CHUNK_DATA_SIZE;
  size_t written = 0;
  uint8_t writeErr = CES_OK;

  while (written < dataLen && chunkKeyIdx < keys.size()) {
    HashPrefix chunkOwner;
    AssetData chunkContent;
    uint16_t cd = 0;
    uint32_t cp = 0;
    rc = client.queryAsset(keys[chunkKeyIdx], chunkOwner, chunkContent,
                           cd, cp);
    if (rc != CES_OK) { writeErr = rc; break; }

    size_t space = RAMFILE_CHUNK_DATA_SIZE - startByte;
    size_t take = std::min(space, dataLen - written);
    std::memcpy(&chunkContent[startByte], data + written, take);

    rc = client.updateAssetFast(keys[chunkKeyIdx], chunkContent);
    if (rc != CES_OK) { writeErr = rc; break; }

    written += take;
    startByte = 0;
    ++chunkKeyIdx;
  }

  // Extend fileSize if the write pushed past it. fileSize never shrinks
  // here — a short write that overlaps the old live region leaves
  // fileSize unchanged and the caller cannot observe the partial write
  // from the header alone.
  const uint64_t writeEnd = offset + written;
  if (writeEnd > header.fileSize) header.fileSize = writeEnd;

  // Always touch the head (zero hash + bump mtime). Even on partial
  // writes, the file is now dirty.
  rc = touchHead(client, keys[0], header, minx::Hash{});
  if (rc != CES_OK) return rc;

  if (writeErr != CES_OK) return writeErr;
  if (written < dataLen) return CES_ERROR_INTERNAL; // ran out of capacity
  return CES_OK;
}

// --- Resize ---

// Resize the file's declared content size. On grow, allocates new chunks
// only if the target exceeds the current chain capacity, so a shrink
// followed by a grow back within the old capacity costs no chunk work.
//
// On shrink, only the declared size moves; old chunks stay linked in the
// chain as reusable capacity for a future grow or write.

uint8_t ramfileResize(CesClient& client, std::vector<minx::Hash>& keys,
                   uint64_t newSize, uint16_t days) {
  if (keys.empty()) return CES_ERROR_INTERNAL;

  RamfileHeader header;
  uint8_t rc = readHead(client, keys[0], header);
  if (rc != CES_OK) return rc;

  if (newSize == header.fileSize) return CES_OK; // nop

  if (newSize > header.fileSize) {
    // Check current chain capacity (total bytes the existing chunks
    // can hold, ignoring declared size).
    const uint64_t capacity =
      static_cast<uint64_t>(keys.size() - 1) * RAMFILE_CHUNK_DATA_SIZE;

    if (newSize > capacity) {
      // Need to extend the chain. Allocate enough new zero-filled
      // chunks to cover the shortfall. Backward-chained via
      // createChunkChain so each chunk carries its successor's key.
      const uint64_t extraBytes = newSize - capacity;
      const size_t extraChunksBytes =
        static_cast<size_t>(
          ((extraBytes + RAMFILE_CHUNK_DATA_SIZE - 1) / RAMFILE_CHUNK_DATA_SIZE)
          * RAMFILE_CHUNK_DATA_SIZE);
      ces::Bytes zeros(extraChunksBytes, 0);

      std::vector<minx::Hash> newKeys;
      rc = createChunkChain(client, zeros.data(), zeros.size(),
                            days, minx::Hash{}, newKeys);
      if (rc != CES_OK) return rc;
      if (newKeys.empty()) return CES_ERROR_INTERNAL;

      // Splice the new chunks onto the existing chain's tail. If the
      // old chain was empty (keys.size() == 1, head-only), patch the
      // head's firstChunk field. Otherwise patch the previous last
      // chunk's next-pointer to point at the first new chunk.
      if (keys.size() == 1) {
        header.firstChunk = newKeys.front();
      } else {
        HashPrefix owner;
        AssetData tailContent;
        uint16_t cd = 0;
        uint32_t cp = 0;
        rc = client.queryAsset(keys.back(), owner, tailContent, cd, cp);
        if (rc != CES_OK) return rc;
        std::memcpy(&tailContent[RAMFILE_NEXT_OFFSET],
                    newKeys.front().data(), RAMFILE_NEXT_SIZE);
        rc = client.updateAssetFast(keys.back(), tailContent);
        if (rc != CES_OK) return rc;
      }

      keys.insert(keys.end(), newKeys.begin(), newKeys.end());
    }

    header.fileSize = newSize;
    return touchHead(client, keys[0], header, minx::Hash{});
  }

  // Truncate: just update the size in the head. Old chunks stay on disk
  // (they expire naturally via rent, or remain as dangling capacity for
  // a future ramfileResize grow / ramfileWrite extend). ramfileGet / ramfileRead
  // respect fileSize and stop reading.
  header.fileSize = newSize;
  return touchHead(client, keys[0], header, minx::Hash{});
}

// --- Rehash ---

uint8_t ramfileRehash(CesClient& client, const minx::Hash& headKey) {
  ces::Bytes data;
  RamfileHeader header;
  uint8_t rc = ramfileGet(client, headKey, data, &header, nullptr);
  if (rc != CES_OK) return rc;

  return touchHead(client, headKey, header, sha256(data.data(), data.size()));
}

} // namespace ces
