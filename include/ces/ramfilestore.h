#pragma once

/**
 * Ramfile — chunked file storage over CES assets.
 *
 * File format:
 *   Head asset (210 bytes):
 *     Byte 0:       magic 0x46 ('F')
 *     Bytes 1-8:    file size (uint64 BE)
 *     Bytes 9-40:   SHA256 of complete file content
 *     Bytes 41-48:  created time (uint64 BE, microseconds since epoch UTC)
 *     Bytes 49-56:  modified time (uint64 BE, microseconds since epoch UTC)
 *     Bytes 57-177: metadata (121 bytes, app-defined, zero-padded)
 *     Bytes 178-209: first chunk key (32 bytes, zeros if empty file)
 *
 *   Data chunk (210 bytes):
 *     Bytes 0-177:  payload (178 bytes)
 *     Bytes 178-209: next chunk key (32 bytes, zeros = last chunk)
 *
 * Upload order: last chunk first (backward), so each chunk is created
 * with its correct next pointer. No patching needed.
 *
 * Head asset key is user-chosen (the "filename").
 * Chunk keys are random (CES_CREATE_ASSET with random ID).
 */

#include <ces/types.h>
#include <ces/client.h>

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace ces {

// File format constants
static constexpr uint8_t  RAMFILE_MAGIC = 0x46; // 'F'
static constexpr size_t   RAMFILE_HEAD_CTIME_OFFSET = 41;
static constexpr size_t   RAMFILE_HEAD_MTIME_OFFSET = 49;
static constexpr size_t   RAMFILE_HEAD_META_OFFSET = 57;
static constexpr size_t   RAMFILE_HEAD_META_SIZE = 121;
static constexpr size_t   RAMFILE_NEXT_OFFSET = 178;
static constexpr size_t   RAMFILE_NEXT_SIZE = 32;
static constexpr size_t   RAMFILE_CHUNK_DATA_SIZE = 178;

// Layout must exactly fill one asset cell — the head metadata section
// followed by the next-chunk pointer has to sum to the asset content size.
// `sizeof(AssetData)` works here because AssetData is a std::array of uint8_t.
static_assert(RAMFILE_HEAD_META_OFFSET + RAMFILE_HEAD_META_SIZE == RAMFILE_NEXT_OFFSET,
              "Ramfile head layout: META region must end at RAMFILE_NEXT_OFFSET");
static_assert(RAMFILE_NEXT_OFFSET + RAMFILE_NEXT_SIZE == sizeof(AssetData),
              "Ramfile head layout: must exactly fill AssetData");
static_assert(RAMFILE_CHUNK_DATA_SIZE + RAMFILE_NEXT_SIZE == sizeof(AssetData),
              "Ramfile chunk layout: must exactly fill AssetData");

// Parsed file header
struct RamfileHeader {
  uint64_t fileSize = 0;
  minx::Hash contentHash{};
  uint64_t createdTime = 0;   // microseconds since epoch UTC
  uint64_t modifiedTime = 0;  // microseconds since epoch UTC
  std::array<uint8_t, RAMFILE_HEAD_META_SIZE> metadata{};
  minx::Hash firstChunk{};
  bool valid = false;
};

// Parse a head asset's content into a RamfileHeader
RamfileHeader parseRamfileHeader(const AssetData& headContent);

// Build a head asset content from components
AssetData buildRamfileHeader(uint64_t fileSize, const minx::Hash& contentHash,
                          uint64_t createdTime, uint64_t modifiedTime,
                          const uint8_t* metadata, size_t metaLen,
                          const minx::Hash& firstChunk);

// Build a data chunk content
AssetData buildRamfileChunk(const uint8_t* data, size_t dataLen,
                     const minx::Hash& nextKey);

// Compute SHA256 of raw data
minx::Hash sha256(const uint8_t* data, size_t len);

/**
 * Upload a file as a chain of assets.
 * @param client Connected CesClient
 * @param headKey The key for the head asset (the "filename")
 * @param data File content bytes
 * @param days Days to fund each asset
 * @param metadata Optional metadata (up to 121 bytes, zero-padded)
 * @param metaLen Length of metadata
 * @param progress Optional callback(chunksCreated, totalChunks)
 * @return CES_OK on success, error code on failure
 */
uint8_t ramfilePut(CesClient& client, const minx::Hash& headKey,
                const uint8_t* data, size_t dataLen,
                uint16_t days,
                const uint8_t* metadata = nullptr, size_t metaLen = 0,
                std::function<void(size_t, size_t)> progress = nullptr);

/**
 * Download a file from a chain of assets.
 * @param client Connected CesClient
 * @param headKey The key of the head asset
 * @param outData Output: file content bytes
 * @param outHeader Output: parsed header (optional)
 * @param hashMismatch Output: true if SHA256 doesn't match (optional)
 * @return CES_OK on success, error code on failure
 */
uint8_t ramfileGet(CesClient& client, const minx::Hash& headKey,
                ces::Bytes& outData,
                RamfileHeader* outHeader = nullptr,
                bool* hashMismatch = nullptr);

/**
 * Fund all assets in a file chain.
 * @param client Connected CesClient
 * @param headKey The key of the head asset
 * @param days Days to add to each asset
 * @return CES_OK on success, error code on first failure
 */
uint8_t ramfileFund(CesClient& client, const minx::Hash& headKey, uint16_t days);

/**
 * Scan a file chain and return all asset keys (head + chunks) in order.
 * @param client Connected CesClient
 * @param headKey The key of the head asset
 * @param outKeys Output: head key followed by chunk keys in order
 * @return CES_OK on success, error code on failure
 */
uint8_t ramfileScan(CesClient& client, const minx::Hash& headKey,
                 std::vector<minx::Hash>& outKeys);

/**
 * Fund all assets listed in a scan file (no chain walking needed).
 * @param client Connected CesClient
 * @param keys Vector of asset keys (head + chunks)
 * @param days Days to add to each asset
 * @return CES_OK on success, error code on first failure
 */
uint8_t ramfileFundFromScan(CesClient& client,
                         const std::vector<minx::Hash>& keys, uint16_t days);

/**
 * Build scan filename: <name>@<server>.scan
 * If headKey is valid null-terminated UTF-8 (printable, <=31 chars),
 * use that as name. Otherwise use 64-char hex.
 */
std::string buildRamfileScanFilename(const minx::Hash& headKey,
                              const std::string& serverAddr);

/**
 * Write scan file (one hex key per line).
 */
void writeRamfileScan(const std::string& path,
                   const std::vector<minx::Hash>& keys);

/**
 * Read scan file (one hex key per line). Returns empty on failure.
 */
std::vector<minx::Hash> readRamfileScan(const std::string& path);

/**
 * Read bytes from a file at an offset (requires scan file keys).
 * @param client Connected CesClient
 * @param keys Scan file keys (head + chunks)
 * @param offset Byte offset into file
 * @param length Number of bytes to read
 * @param outData Output bytes
 * @return CES_OK on success
 */
uint8_t ramfileRead(CesClient& client, const std::vector<minx::Hash>& keys,
                 uint64_t offset, uint64_t length,
                 ces::Bytes& outData);

/**
 * Write bytes to a file at an offset (requires scan file keys).
 *
 * Zeroes the head SHA256 (marks file as dirty) and bumps mtime. The
 * write is bounded by the file's pre-allocated chain CAPACITY
 * (keys.size() - 1) * RAMFILE_CHUNK_DATA_SIZE, NOT by the file's
 * declared size. If the write extends past `header.fileSize`, the
 * declared size is extended to cover the written range. If the write
 * exceeds the chain's capacity, the function writes what fits and
 * returns an error code; the caller can re-read the head to see how
 * much landed.
 *
 * Writes stop on the first chunk-level failure (query or update). On
 * failure, the head is still touched: the declared size reflects how
 * many bytes were successfully written (if the write extended past
 * the old size). Writes that were entirely within the pre-existing
 * `header.fileSize` region do not update the declared size, so on a
 * partial failure the caller cannot tell from `fileSize` alone how
 * much data was written — treat the region as indeterminate.
 *
 * To grow a file's chain (allocate more chunks), use `ramfileResize` —
 * which grows the declared size, allocating chunks as needed, and
 * leaves the chain intact on a subsequent shrink so the capacity
 * remains available to a future grow or write.
 *
 * @param client Connected CesClient
 * @param keys Scan file keys (head + chunks)
 * @param offset Byte offset into file. Must be ≤ capacity.
 * @param data Bytes to write
 * @param dataLen Length of data
 * @return CES_OK if every byte was written, error code otherwise
 */
uint8_t ramfileWrite(CesClient& client, const std::vector<minx::Hash>& keys,
                  uint64_t offset, const uint8_t* data, size_t dataLen);

/**
 * Rehash a file: download all data, recompute SHA256, update head.
 * @param client Connected CesClient
 * @param headKey The key of the head asset
 * @return CES_OK on success
 */
uint8_t ramfileRehash(CesClient& client, const minx::Hash& headKey);

/**
 * Resize a file. Truncate if shorter, zero-extend if longer, nop if same.
 * Requires scan file keys. Updates keys vector (may grow on extend; never
 * shrinks — truncated chunks stay linked as reusable capacity).
 * Zeroes head hash (dirty).
 * @param client Connected CesClient
 * @param keys Scan file keys — may be modified
 * @param newSize Target file size in bytes
 * @param days Days for any new chunks (only used if extending)
 * @return CES_OK on success
 */
uint8_t ramfileResize(CesClient& client, std::vector<minx::Hash>& keys,
                   uint64_t newSize, uint16_t days);

} // namespace ces
