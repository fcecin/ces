/**
 * Integration tests for Ramfile (chunked file storage over CES assets).
 */

#include "test_common.h"
#include <ces/ramfilestore.h>

using namespace ces;

BOOST_AUTO_TEST_SUITE(RamfileTests)

BOOST_FIXTURE_TEST_CASE(PutGetSmall, CesFixture) {
  ces::Bytes data(500, 0x42);
  for (size_t i = 0; i < data.size(); ++i)
    data[i] = static_cast<uint8_t>(i & 0xFF);

  minx::Hash key;
  key.fill(0);
  key[0] = 0xF1; key[1] = 0xF2;

  uint8_t rc = ramfilePut(*client, key, data.data(), data.size(), 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  ces::Bytes got;
  RamfileHeader header;
  bool mismatch = false;
  rc = ramfileGet(*client, key, got, &header, &mismatch);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK(header.valid);
  BOOST_CHECK_EQUAL(header.fileSize, 500);
  BOOST_CHECK(!mismatch);
  BOOST_CHECK(got == data);
}

BOOST_FIXTURE_TEST_CASE(PutGetEmpty, CesFixture) {
  minx::Hash key;
  key.fill(0);
  key[0] = 0xE1;

  uint8_t rc = ramfilePut(*client, key, nullptr, 0, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  ces::Bytes got;
  RamfileHeader header;
  bool mismatch = false;
  rc = ramfileGet(*client, key, got, &header, &mismatch);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK(header.valid);
  BOOST_CHECK_EQUAL(header.fileSize, 0);
  BOOST_CHECK(!mismatch);
  BOOST_CHECK(got.empty());
}

BOOST_FIXTURE_TEST_CASE(PutGetWithMeta, CesFixture) {
  ces::Bytes data(100, 0xAB);
  std::string meta = "text/plain";

  minx::Hash key;
  key.fill(0);
  key[0] = 0xD1;

  uint8_t rc = ramfilePut(*client, key, data.data(), data.size(), 30,
                        reinterpret_cast<const uint8_t*>(meta.data()), meta.size());
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  ces::Bytes got;
  RamfileHeader header;
  rc = ramfileGet(*client, key, got, &header, nullptr);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK(header.valid);
  std::string gotMeta(reinterpret_cast<const char*>(header.metadata.data()), meta.size());
  BOOST_CHECK_EQUAL(gotMeta, meta);
}

BOOST_FIXTURE_TEST_CASE(Fund, CesFixture) {
  ces::Bytes data(400, 0x33);

  minx::Hash key;
  key.fill(0);
  key[0] = 0xC1;

  uint8_t rc = ramfilePut(*client, key, data.data(), data.size(), 10);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  rc = ramfileFund(*client, key, 20);
  BOOST_CHECK_EQUAL(rc, CES_OK);
}

BOOST_FIXTURE_TEST_CASE(GetNonexistent, CesFixture) {
  minx::Hash key;
  key.fill(0xFF);

  ces::Bytes got;
  uint8_t rc = ramfileGet(*client, key, got);
  BOOST_CHECK_NE(rc, CES_OK);
}

// --- Scan and scan-based fund ---

BOOST_FIXTURE_TEST_CASE(ScanAndFundFromScan, CesFixture) {
  // Upload a multi-chunk file
  ces::Bytes data(600, 0x77);
  minx::Hash key;
  key.fill(0);
  key[0] = 0xA1;

  uint8_t rc = ramfilePut(*client, key, data.data(), data.size(), 10);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Scan
  std::vector<minx::Hash> keys;
  rc = ramfileScan(*client, key, keys);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  // 600 bytes / 178 per chunk = 4 chunks + 1 head = 5 assets
  BOOST_CHECK_EQUAL(keys.size(), 5);
  BOOST_CHECK(keys[0] == key); // first entry is head

  // Write scan file and read it back
  std::string scanPath = (tempDir / "test.scan").string();
  writeRamfileScan(scanPath, keys);
  auto readBack = readRamfileScan(scanPath);
  BOOST_REQUIRE_EQUAL(readBack.size(), keys.size());
  for (size_t i = 0; i < keys.size(); ++i)
    BOOST_CHECK(readBack[i] == keys[i]);

  // Fund from scan
  rc = ramfileFundFromScan(*client, readBack, 20);
  BOOST_CHECK_EQUAL(rc, CES_OK);
}

BOOST_FIXTURE_TEST_CASE(ScanEmptyFile, CesFixture) {
  minx::Hash key;
  key.fill(0);
  key[0] = 0xA2;

  uint8_t rc = ramfilePut(*client, key, nullptr, 0, 10);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  std::vector<minx::Hash> keys;
  rc = ramfileScan(*client, key, keys);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(keys.size(), 1); // head only, no chunks
}

// --- Scan filename generation ---

BOOST_AUTO_TEST_CASE(ScanFilenameReadableKey) {
  minx::Hash key{};
  std::memcpy(key.data(), "hello", 5);
  auto name = buildRamfileScanFilename(key, "localhost:53830");
  BOOST_CHECK_EQUAL(name, "hello@localhost.53830.scan");
}

BOOST_AUTO_TEST_CASE(ScanFilenameHexKey) {
  minx::Hash key;
  key.fill(0xFF);
  auto name = buildRamfileScanFilename(key, "myserver:9000");
  // Should be 64-char hex + @server.port.scan
  BOOST_CHECK(name.find("@myserver.9000.scan") != std::string::npos);
  BOOST_CHECK(name.size() > 64); // hex key is 64 chars
}

// A short printable key is used verbatim as the scan filename, and
// isReadableUTF8 accepts '/' and '.'. A key like "../../evil" must not yield a
// path-traversing filename when the caller prepends a directory.
BOOST_AUTO_TEST_CASE(ScanFilenameSanitizesTraversal) {
  minx::Hash key{};
  const std::string evil = "../../evil";
  std::memcpy(key.data(), evil.data(), evil.size());
  auto name = buildRamfileScanFilename(key, "host:1234");
  BOOST_CHECK(name.find('/') == std::string::npos);   // no path separator
  BOOST_CHECK(name.find('\\') == std::string::npos);
  BOOST_REQUIRE(!name.empty());
  BOOST_CHECK(name[0] != '.');                          // not '.', '..', dotfile
  // Still carries the server suffix.
  BOOST_CHECK(name.find("@host.1234.scan") != std::string::npos);
}

// --- Read / Write / Append ---

BOOST_FIXTURE_TEST_CASE(ReadAtOffset, CesFixture) {
  ces::Bytes data(500);
  for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(i & 0xFF);

  minx::Hash key; key.fill(0); key[0] = 0xB1;
  uint8_t rc = ramfilePut(*client, key, data.data(), data.size(), 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  std::vector<minx::Hash> keys;
  rc = ramfileScan(*client, key, keys);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Read 10 bytes at offset 200
  ces::Bytes got;
  rc = ramfileRead(*client, keys, 200, 10, got);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(got.size(), 10);
  for (size_t i = 0; i < 10; ++i)
    BOOST_CHECK_EQUAL(got[i], static_cast<uint8_t>((200 + i) & 0xFF));
}

BOOST_FIXTURE_TEST_CASE(WriteAtOffset, CesFixture) {
  ces::Bytes data(500, 0x00);
  minx::Hash key; key.fill(0); key[0] = 0xB2;
  uint8_t rc = ramfilePut(*client, key, data.data(), data.size(), 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  std::vector<minx::Hash> keys;
  rc = ramfileScan(*client, key, keys);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Write "HELLO" at offset 100
  std::string patch = "HELLO";
  rc = ramfileWrite(*client, keys, 100,
                  reinterpret_cast<const uint8_t*>(patch.data()), patch.size());
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Read it back
  ces::Bytes got;
  rc = ramfileRead(*client, keys, 98, 9, got);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(got.size(), 9);
  BOOST_CHECK_EQUAL(got[0], 0x00); // before patch
  BOOST_CHECK_EQUAL(got[1], 0x00);
  BOOST_CHECK_EQUAL(got[2], 'H');
  BOOST_CHECK_EQUAL(got[3], 'E');
  BOOST_CHECK_EQUAL(got[4], 'L');
  BOOST_CHECK_EQUAL(got[5], 'L');
  BOOST_CHECK_EQUAL(got[6], 'O');
  BOOST_CHECK_EQUAL(got[7], 0x00); // after patch
  BOOST_CHECK_EQUAL(got[8], 0x00);
}

// "Append" is now the composition of ramfileResize (grow declared size,
// allocating chunks if needed) + ramfileWrite (write into the newly-grown
// region). fileAppend was deleted.
BOOST_FIXTURE_TEST_CASE(AppendToFile, CesFixture) {
  ces::Bytes data(100, 0xAA);
  minx::Hash key; key.fill(0); key[0] = 0xB3;
  uint8_t rc = ramfilePut(*client, key, data.data(), data.size(), 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  std::vector<minx::Hash> keys;
  rc = ramfileScan(*client, key, keys);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Append 200 bytes: grow declared size, then write at the old size.
  ces::Bytes appendData(200, 0xBB);
  rc = ramfileResize(*client, keys, 100 + appendData.size(), 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  rc = ramfileWrite(*client, keys, 100, appendData.data(), appendData.size());
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Verify via full get
  ces::Bytes got;
  rc = ramfileGet(*client, key, got);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(got.size(), 300);
  for (size_t i = 0; i < 100; ++i) BOOST_CHECK_EQUAL(got[i], 0xAA);
  for (size_t i = 100; i < 300; ++i) BOOST_CHECK_EQUAL(got[i], 0xBB);
}

BOOST_FIXTURE_TEST_CASE(AppendToEmpty, CesFixture) {
  minx::Hash key; key.fill(0); key[0] = 0xB4;
  uint8_t rc = ramfilePut(*client, key, nullptr, 0, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  std::vector<minx::Hash> keys;
  rc = ramfileScan(*client, key, keys);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(keys.size(), 1); // head only

  ces::Bytes appendData(50, 0xCC);
  rc = ramfileResize(*client, keys, appendData.size(), 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(keys.size(), 2); // head + 1 chunk
  rc = ramfileWrite(*client, keys, 0, appendData.data(), appendData.size());
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  ces::Bytes got;
  rc = ramfileGet(*client, key, got);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(got.size(), 50);
  for (auto b : got) BOOST_CHECK_EQUAL(b, 0xCC);
}

// --- New tests for the split capacity/size model ---

// The preallocation idiom: grow a file to a target capacity, shrink it
// back down, then use the pre-allocated chain for subsequent writes
// without any further chunk allocation.
BOOST_FIXTURE_TEST_CASE(PreallocateAndWrite, CesFixture) {
  minx::Hash key; key.fill(0); key[0] = 0xBD;
  uint8_t rc = ramfilePut(*client, key, nullptr, 0, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  std::vector<minx::Hash> keys;
  rc = ramfileScan(*client, key, keys);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(keys.size(), 1); // head only

  // Preallocate 500 bytes of chain capacity (≈ 3 chunks).
  rc = ramfileResize(*client, keys, 500, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  const size_t preallocatedKeysCount = keys.size();
  BOOST_CHECK_GT(preallocatedKeysCount, 1u); // chunks were allocated

  // Shrink declared size back to 0 — chunks stay in the chain.
  rc = ramfileResize(*client, keys, 0, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(keys.size(), preallocatedKeysCount); // scan file preserved

  // Write 300 bytes. No new allocation should happen (fits in capacity).
  ces::Bytes data(300, 0xEE);
  rc = ramfileWrite(*client, keys, 0, data.data(), data.size());
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(keys.size(), preallocatedKeysCount);

  // Verify the write extended fileSize and the data is readable.
  ces::Bytes got;
  rc = ramfileGet(*client, key, got);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(got.size(), 300);
  for (auto b : got) BOOST_CHECK_EQUAL(b, 0xEE);
}

// A truncated file's chunks remain in the chain. A subsequent grow
// that fits within the old chain does NOT allocate — it just updates
// the declared size.
BOOST_FIXTURE_TEST_CASE(ReusePostTruncateCapacity, CesFixture) {
  // 500 bytes with a recognizable byte pattern.
  ces::Bytes data(500);
  for (size_t i = 0; i < data.size(); ++i)
    data[i] = static_cast<uint8_t>(i & 0xFF);
  minx::Hash key; key.fill(0); key[0] = 0xBC;
  uint8_t rc = ramfilePut(*client, key, data.data(), data.size(), 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  std::vector<minx::Hash> keys;
  rc = ramfileScan(*client, key, keys);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  const size_t origKeysCount = keys.size();

  // Truncate to 100 bytes — chain stays intact.
  rc = ramfileResize(*client, keys, 100, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(keys.size(), origKeysCount);

  // Grow to 300 — within original capacity, no allocation.
  rc = ramfileResize(*client, keys, 300, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(keys.size(), origKeysCount);

  // The original byte pattern is still in the chunks — the truncate
  // didn't overwrite anything, just moved the declared-size fence.
  // Growing the fence reveals those bytes again.
  ces::Bytes got;
  rc = ramfileGet(*client, key, got);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(got.size(), 300);
  for (size_t i = 0; i < 300; ++i) {
    BOOST_CHECK_EQUAL(got[i], static_cast<uint8_t>(i & 0xFF));
  }
}

// ramfileWrite past the current declared size extends fileSize up to the
// end of the actual write, as long as the write stays within chain
// capacity.
BOOST_FIXTURE_TEST_CASE(WriteExtendsFileSize, CesFixture) {
  ces::Bytes data(100, 0xAA);
  minx::Hash key; key.fill(0); key[0] = 0xBE;
  uint8_t rc = ramfilePut(*client, key, data.data(), data.size(), 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  std::vector<minx::Hash> keys;
  rc = ramfileScan(*client, key, keys);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Preallocate 500 bytes of capacity via the grow-then-shrink idiom.
  rc = ramfileResize(*client, keys, 500, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  rc = ramfileResize(*client, keys, 100, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  const size_t preallocatedKeysCount = keys.size();

  // Write 50 bytes at offset 100 — this is past the current fileSize
  // (100) and should extend it to 150 without adding chunks.
  ces::Bytes patch(50, 0xBB);
  rc = ramfileWrite(*client, keys, 100, patch.data(), patch.size());
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(keys.size(), preallocatedKeysCount); // no allocation

  // Verify: fileSize is now 150, first 100 bytes 0xAA, next 50 0xBB.
  ces::Bytes got;
  rc = ramfileGet(*client, key, got);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(got.size(), 150);
  for (size_t i = 0; i < 100; ++i) BOOST_CHECK_EQUAL(got[i], 0xAA);
  for (size_t i = 100; i < 150; ++i) BOOST_CHECK_EQUAL(got[i], 0xBB);
}

// ramfileWrite past the chain's allocated capacity writes what fits,
// reports an error, and updates fileSize to reflect how far the write
// reached.
BOOST_FIXTURE_TEST_CASE(WritePastCapacityFails, CesFixture) {
  // ramfilePut a 100-byte file. This allocates exactly one chunk
  // (ceil(100 / 178) = 1) — so the chain's capacity is 178 bytes.
  ces::Bytes data(100, 0xAA);
  minx::Hash key; key.fill(0); key[0] = 0xBF;
  uint8_t rc = ramfilePut(*client, key, data.data(), data.size(), 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  std::vector<minx::Hash> keys;
  rc = ramfileScan(*client, key, keys);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(keys.size(), 2); // head + 1 chunk = 178 bytes

  // Try to write 1024 bytes starting at offset 0. ramfileWrite should
  // write the first 178 bytes (filling the chunk), then stop and
  // return an error because there is no next chunk to walk into.
  ces::Bytes big(1024, 0xCC);
  rc = ramfileWrite(*client, keys, 0, big.data(), big.size());
  BOOST_CHECK_NE(rc, static_cast<uint8_t>(CES_OK));
  BOOST_CHECK_EQUAL(keys.size(), 2); // ramfileWrite does not allocate

  // The declared size should now be 178 (the write extended from 100
  // to 178 before running out of chain).
  ces::Bytes got;
  rc = ramfileGet(*client, key, got);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(got.size(), 178);
  for (auto b : got) BOOST_CHECK_EQUAL(b, 0xCC);
}

BOOST_FIXTURE_TEST_CASE(ResizeTruncate, CesFixture) {
  ces::Bytes data(500, 0x55);
  minx::Hash key; key.fill(0); key[0] = 0xB6;
  uint8_t rc = ramfilePut(*client, key, data.data(), data.size(), 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  std::vector<minx::Hash> keys;
  rc = ramfileScan(*client, key, keys);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  rc = ramfileResize(*client, keys, 100, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Data truncated to 100 bytes (old chunks still exist but ignored)
  ces::Bytes got;
  rc = ramfileGet(*client, key, got);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(got.size(), 100);
  for (auto b : got) BOOST_CHECK_EQUAL(b, 0x55);
}

BOOST_FIXTURE_TEST_CASE(ResizeExtend, CesFixture) {
  ces::Bytes data(100, 0x66);
  minx::Hash key; key.fill(0); key[0] = 0xB7;
  uint8_t rc = ramfilePut(*client, key, data.data(), data.size(), 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  std::vector<minx::Hash> keys;
  rc = ramfileScan(*client, key, keys);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  rc = ramfileResize(*client, keys, 300, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  ces::Bytes got;
  rc = ramfileGet(*client, key, got);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(got.size(), 300);
  for (size_t i = 0; i < 100; ++i) BOOST_CHECK_EQUAL(got[i], 0x66);
  for (size_t i = 100; i < 300; ++i) BOOST_CHECK_EQUAL(got[i], 0x00);
}

BOOST_FIXTURE_TEST_CASE(ResizeToZero, CesFixture) {
  ces::Bytes data(200, 0x77);
  minx::Hash key; key.fill(0); key[0] = 0xB8;
  uint8_t rc = ramfilePut(*client, key, data.data(), data.size(), 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  std::vector<minx::Hash> keys;
  rc = ramfileScan(*client, key, keys);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  rc = ramfileResize(*client, keys, 0, 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  ces::Bytes got;
  rc = ramfileGet(*client, key, got);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK(got.empty());
}

BOOST_FIXTURE_TEST_CASE(WriteAndRehash, CesFixture) {
  ces::Bytes data(200, 0x00);
  minx::Hash key; key.fill(0); key[0] = 0xB5;
  uint8_t rc = ramfilePut(*client, key, data.data(), data.size(), 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Verify hash is clean
  ces::Bytes got;
  RamfileHeader header;
  bool mismatch = false;
  rc = ramfileGet(*client, key, got, &header, &mismatch);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK(!mismatch);

  // Write makes hash dirty
  std::vector<minx::Hash> keys;
  rc = ramfileScan(*client, key, keys);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  uint8_t patch[] = {0xFF};
  rc = ramfileWrite(*client, keys, 0, patch, 1);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Hash should be dirty now
  rc = ramfileGet(*client, key, got, &header, &mismatch);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK(mismatch);

  // Rehash fixes it
  rc = ramfileRehash(*client, key);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  rc = ramfileGet(*client, key, got, &header, &mismatch);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK(!mismatch);
  BOOST_CHECK_EQUAL(got[0], 0xFF); // write was preserved
}

BOOST_FIXTURE_TEST_CASE(ReadPastEnd, CesFixture) {
  ces::Bytes data(100, 0x44);
  minx::Hash key; key.fill(0); key[0] = 0xB9;
  uint8_t rc = ramfilePut(*client, key, data.data(), data.size(), 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  std::vector<minx::Hash> keys;
  rc = ramfileScan(*client, key, keys);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  // Read starting past end
  ces::Bytes got;
  rc = ramfileRead(*client, keys, 200, 50, got);
  BOOST_CHECK_EQUAL(rc, CES_OK);
  BOOST_CHECK(got.empty());

  // Read crossing end
  rc = ramfileRead(*client, keys, 90, 50, got);
  BOOST_CHECK_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(got.size(), 10); // only 10 bytes available
}

BOOST_FIXTURE_TEST_CASE(ResizeNop, CesFixture) {
  ces::Bytes data(100, 0x55);
  minx::Hash key; key.fill(0); key[0] = 0xBA;
  uint8_t rc = ramfilePut(*client, key, data.data(), data.size(), 30);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  std::vector<minx::Hash> keys;
  rc = ramfileScan(*client, key, keys);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);

  rc = ramfileResize(*client, keys, 100, 30); // same size = nop
  BOOST_CHECK_EQUAL(rc, CES_OK);

  ces::Bytes got;
  rc = ramfileGet(*client, key, got);
  BOOST_CHECK_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(got.size(), 100);
}

// --- Edge cases ---

BOOST_AUTO_TEST_CASE(ReadScanFileMissing) {
  auto keys = readRamfileScan("/tmp/nonexistent_scan_file_12345.scan");
  BOOST_CHECK(keys.empty());
}

BOOST_FIXTURE_TEST_CASE(CyclicChainRejected, CesFixture) {
  // A chunk whose next-pointer points at itself, under a head whose declared
  // size spans more than one chunk: without the cycle guard the chain walks
  // loop forever (Fund would also drain the wallet). All three must error.
  minx::Hash chunkKey;
  chunkKey.fill(0);
  chunkKey[0] = 0xC1;
  chunkKey[1] = 0xC2;
  ces::Bytes payload(RAMFILE_CHUNK_DATA_SIZE, 0x7E);
  AssetData chunk = buildRamfileChunk(payload.data(), payload.size(), chunkKey);
  BOOST_REQUIRE_EQUAL(client->createAsset(chunkKey, chunk, 30), CES_OK);

  minx::Hash headKey;
  headKey.fill(0);
  headKey[0] = 0xC0;
  AssetData head = buildRamfileHeader(1u << 20, minx::Hash{}, 0, 0,
                                      nullptr, 0, chunkKey);
  BOOST_REQUIRE_EQUAL(client->createAsset(headKey, head, 30), CES_OK);

  ces::Bytes got;
  BOOST_CHECK_EQUAL(ramfileGet(*client, headKey, got, nullptr, nullptr),
                    CES_ERROR_INTERNAL);

  std::vector<minx::Hash> keys;
  BOOST_CHECK_EQUAL(ramfileScan(*client, headKey, keys), CES_ERROR_INTERNAL);

  BOOST_CHECK_EQUAL(ramfileFund(*client, headKey, 1), CES_ERROR_INTERNAL);
}

BOOST_AUTO_TEST_SUITE_END()
