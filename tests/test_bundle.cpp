/**
 * test_bundle.cpp — tests for the bundler (include/ces/lang/bundle.h):
 * boot-only packaging, chunk/table shape and key determinism, base-
 * independent compile length, and the end-to-end ledger run of a
 * multi-chunk program (chained key tables, cross-chunk fn call) via
 * CES_RUN_ASSET.
 */

#include "test_common.h"

#include <ces/cesvm.h>
#include <ces/lang/bundle.h>
#include <ces/lang/cesl.h>

#include <cstdint>
#include <string>

using namespace ces;

namespace {

// A cesl program whose body compiles well past one 210-byte block:
// `reps` increment statements plus a trailing fn (emitted after the
// top-level term, so the call from chunk 0 targets the last chunk).
// The first statement captures the register state the boot loader must
// hand over zeroed (READ_ASSET writes io[7]/io[8]); z != 0 blows up the
// result, so the ledger run also pins the loader's fresh-VM contract.
std::string bigProgram(int reps) {
  std::string src = "fn plus_one(v) { return v + 1; }\n"
                    "let z = r + s + arg1 + arg3;\n"
                    "let sum = 0;\n";
  for (int i = 0; i < reps; ++i) src += "sum = sum + 1;\n";
  src += "return plus_one(sum) + z * 100000;\n";
  return src;
}

uint64_t outU64(const ces::Bytes& out) {
  uint64_t v = 0;
  for (size_t i = 0; i < 8 && i < out.size(); ++i)
    v |= static_cast<uint64_t>(out[i]) << (8 * i);
  return v;
}

} // namespace

BOOST_AUTO_TEST_SUITE(BundleTests)

BOOST_AUTO_TEST_CASE(BootOnlyBundle) {
  auto body = ceslCompile("return 7;");
  BOOST_REQUIRE_LE(body.size(), 210u);
  auto b = bundleProgram(body);
  BOOST_CHECK(b.chunks.empty());
  BOOST_CHECK(b.tables.empty());

  CesVM vm;
  CesVMHost host;
  ces::Bytes boot(b.boot.begin(), b.boot.end());
  auto r = vm.execute(boot, host, 1'000'000);
  BOOST_CHECK_EQUAL(r.error, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(outU64(r.output), 7u);
}

BOOST_AUTO_TEST_CASE(CompiledLengthIsBaseIndependent) {
  const std::string src = bigProgram(160);
  auto flat = ceslCompile(src, 0);
  auto based = ceslCompile(src, 210);
  BOOST_CHECK_EQUAL(flat.size(), based.size());
  BOOST_CHECK(flat != based);  // relocated jump targets differ
}

BOOST_AUTO_TEST_CASE(BundleShapeAndDeterminism) {
  const std::string src = bigProgram(160);
  auto body = ceslCompile(src, 210);
  BOOST_REQUIRE_GT(body.size(), 5u * 210u);  // forces a chained table

  auto b = bundleProgram(body, "salt-a");
  const size_t n = (body.size() + 209) / 210;
  BOOST_CHECK_EQUAL(b.chunks.size(), n);
  BOOST_CHECK_EQUAL(b.chunkKeys.size(), n);
  BOOST_CHECK_EQUAL(b.tables.size(), (n + 4) / 5);
  BOOST_REQUIRE_GE(b.tables.size(), 2u);

  // Chunks reassemble to the body (plus zero padding on the last).
  ces::Bytes joined;
  for (const auto& c : b.chunks) joined.insert(joined.end(), c.begin(), c.end());
  BOOST_REQUIRE_GE(joined.size(), body.size());
  BOOST_CHECK(std::equal(body.begin(), body.end(), joined.begin()));

  // Table 0 carries chunk keys 0..4 and chains to table 1; the last
  // table's next-key slot is zeros.
  BOOST_CHECK(std::equal(b.chunkKeys[0].begin(), b.chunkKeys[0].end(),
                         b.tables[0].begin()));
  BOOST_CHECK(std::equal(b.tableKeys[1].begin(), b.tableKeys[1].end(),
                         b.tables[0].begin() + 160));
  const auto& last = b.tables.back();
  for (size_t i = 160; i < 192; ++i) BOOST_CHECK_EQUAL(last[i], 0u);

  // Deterministic keys: same body+salt reproduces, different salt diverges.
  auto b2 = bundleProgram(body, "salt-a");
  BOOST_CHECK(b2.chunkKeys == b.chunkKeys);
  BOOST_CHECK(b2.tableKeys == b.tableKeys);
  auto b3 = bundleProgram(body, "salt-b");
  BOOST_CHECK(b3.chunkKeys != b.chunkKeys);

  // Body too large for the code space behind the boot block.
  ces::Bytes huge(CESVM_MAX_CODE - 210 + 1, OP_NOP);
  BOOST_CHECK_THROW(bundleProgram(huge), CesBundleError);
}

// The money test: a >1KB cesl program deployed as real ledger assets
// (6 chunks, 2 chained key tables) and executed via CES_RUN_ASSET. The
// final fn call crosses from chunk 0 into the last chunk, so relocated
// label targets are exercised end to end.
BOOST_FIXTURE_TEST_CASE(MultiChunkProgramRunsFromLedger, CesFixture) {
  const int reps = 160;
  auto body = ceslCompile(bigProgram(reps), 210);
  BOOST_REQUIRE_GT(body.size(), 5u * 210u);
  auto b = bundleProgram(body);

  for (size_t i = 0; i < b.chunks.size(); ++i) {
    CES_REQUIRE_OK(client->createAsset(b.chunkKeys[i], b.chunks[i], 30));
  }
  for (size_t i = 0; i < b.tables.size(); ++i) {
    CES_REQUIRE_OK(client->createAsset(b.tableKeys[i], b.tables[i], 30));
  }
  minx::Hash bootKey;
  bootKey.fill(0x77);
  CES_REQUIRE_OK(client->createAsset(bootKey, b.boot, 30));

  uint64_t vmError = 0, budgetUsed = 0;
  ces::Bytes output;
  uint8_t rc = client->runAsset(bootKey, 1'000'000'000, {}, vmError,
                                budgetUsed, output);
  BOOST_REQUIRE_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(vmError, static_cast<uint64_t>(CESVM_OK));
  BOOST_CHECK_EQUAL(outU64(output), static_cast<uint64_t>(reps) + 1);
}

BOOST_AUTO_TEST_SUITE_END()
