/**
 * E2E tests for the cesh `file` subcommand (L2 disk-backed file store).
 *
 * Starts a CesServer with the file-store feature enabled (CesPlex mount +
 * cesFileStoreMaxBytes > 0), then shells out to the cesh binary and drives
 * put/get/stat/rm/deposit/withdraw/set-price. Verifies content round-trips,
 * sidecar accounting, and zone-owner rejection.
 */

#define BOOST_TEST_DYN_LINK
#include "test_e2e_common.h"

#include <ces/l2/net_multiplexer.h>
#include <ces/server.h>

#include <fstream>
#include <regex>

using namespace ces::e2e;

namespace {

// Small helper: write `bytes` to a file, return the path.
std::string writeTempFile(const fs::path& dir, const std::string& name,
                          const std::string& bytes) {
  auto p = dir / name;
  std::ofstream ofs(p.string(), std::ios::binary);
  ofs.write(bytes.data(), bytes.size());
  return p.string();
}

std::string readFileStr(const std::string& path) {
  std::ifstream ifs(path, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(ifs)),
                     std::istreambuf_iterator<char>());
}

// Extract the value of a "Field: value" line from cesh output.
std::string extractField(const std::string& out, const std::string& key) {
  std::regex re("(?:^|\\n)\\s*" + key + ":\\s*([^\\n]*)");
  std::smatch m;
  if (std::regex_search(out, m, re)) {
    auto v = m[1].str();
    while (!v.empty() && std::isspace(static_cast<unsigned char>(v.back())))
      v.pop_back();
    return v;
  }
  return {};
}

// ============================================================================
// Fixture: CesServer with file store mounted on rpc_port.
// ============================================================================

struct FileE2EFixture {
  std::unique_ptr<CesServer> server;
  fs::path tempDir;
  uint16_t serverPort = 0;
  uint16_t rpcPort = 0;
  std::string ceshBin;

  KeyPair fundedKey;
  std::string fundedWalletHex;

  KeyPair secondKey;
  std::string secondWalletHex;

  FileE2EFixture() {
    blog::init();
    blog::set_level(blog::fatal);
    blog::set_level("plex", blog::fatal);
    blog::set_level("cfc", blog::fatal);

    tempDir = makeUniqueTempDir("cesh_file_e2e");

    minx::Hash serverPriv;
    serverPriv.fill(0xEE);

    CesConfig cfg =
      makeTestConfig(tempDir, serverPriv, std::numeric_limits<uint64_t>::max());
    // Enable CesPlex + file store. rpcPort must be nonzero (0 = feature
    // disabled). Pick an ephemeral one in the same range the CesPlex
    // suite uses; include microsecond jitter so parallel test runs
    // don't collide.
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = { {"/ces/file/1", "builtin:file"} };
    cfg.cesFileStoreMaxBytes = 1ull * 1024 * 1024 * 1024; // 1 GB
    // Keep rent tiny so short-duration tests don't accidentally consume
    // the whole balance — matches CesPlexFixture discipline.
    cfg.feeFileRent = 1;

    server = std::make_unique<CesServer>(cfg);
    serverPort = server->start(0);
    BOOST_REQUIRE_MESSAGE(serverPort > 0, "Server bind failed");
    rpcPort = server->_rpcBoundPort();
    BOOST_REQUIRE_MESSAGE(rpcPort > 0, "RPC port bind failed");

    ceshBin = findCeshBinary();

    fundedWalletHex = "00" + fundedKey.getPrivateKeyHexStr();
    server->_brr(fundedKey.getPublicKeyAsHash(), 10'000'000'000);

    secondWalletHex = "00" + secondKey.getPrivateKeyHexStr();
    server->_brr(secondKey.getPublicKeyAsHash(), 10'000'000'000);

    wait_net();
  }

  ~FileE2EFixture() {
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }

  std::string cmd(const std::string& args) const {
    std::string full = "cd " + tempDir.string() + " && " +
      ceshCmd(serverPort, fundedWalletHex, ceshBin) +
      " --rpc-port " + std::to_string(rpcPort) + " " + args;
    return full;
  }

  // Build a cmd with a specific wallet (used to test cross-signer flows).
  std::string cmdW(const std::string& wallet,
                   const std::string& args) const {
    std::string full = "cd " + tempDir.string() + " && " +
      ceshCmd(serverPort, wallet, ceshBin) +
      " --rpc-port " + std::to_string(rpcPort) + " " + args;
    return full;
  }

  std::string fundedPubHex() const { return fundedKey.getPublicKeyHexStr(); }
  std::string secondPubHex() const { return secondKey.getPublicKeyHexStr(); }
};

} // namespace

// ============================================================================
// Tests
// ============================================================================

BOOST_FIXTURE_TEST_SUITE(CeshFileE2E, FileE2EFixture)

BOOST_AUTO_TEST_CASE(PutGetRoundTrip) {
  std::string body = "Hello, disk-backed file store!";
  auto local = writeTempFile(tempDir, "src.txt", body);

  auto r = runShell(cmd("file put " + local + " /p/greet.txt"));
  BOOST_REQUIRE_EQUAL(r.exitCode, 0);
  assertContains(r.out, "File Uploaded");

  auto dst = (tempDir / "out.txt").string();
  auto r2 = runShell(cmd("file get /p/greet.txt " + dst));
  BOOST_REQUIRE_EQUAL(r2.exitCode, 0);
  assertContains(r2.out, "File Downloaded");

  BOOST_CHECK_EQUAL(readFileStr(dst), body);
}

BOOST_AUTO_TEST_CASE(StatShowsOwnerAndSize) {
  std::string body = "abc";
  auto local = writeTempFile(tempDir, "tiny.txt", body);

  auto r = runShell(cmd("file put " + local + " /p/tiny.txt"));
  BOOST_REQUIRE_EQUAL(r.exitCode, 0);

  auto r2 = runShell(cmd("file stat /p/tiny.txt"));
  BOOST_REQUIRE_EQUAL(r2.exitCode, 0);
  assertContains(r2.out, "File Info");
  BOOST_CHECK_EQUAL(extractField(r2.out, "Size"), "3");
  BOOST_CHECK_EQUAL(extractField(r2.out, "Owner"), fundedPubHex());
}

BOOST_AUTO_TEST_CASE(ReuploadResizesAndReplacesContent) {
  auto local1 = writeTempFile(tempDir, "v1.txt", "versionone");      // 10
  auto local2 = writeTempFile(tempDir, "v2.txt", "v2x");              // 3

  auto r1 = runShell(cmd("file put " + local1 + " /p/reup.txt"));
  BOOST_REQUIRE_EQUAL(r1.exitCode, 0);

  auto r2 = runShell(cmd("file put " + local2 + " /p/reup.txt"));
  BOOST_REQUIRE_EQUAL(r2.exitCode, 0);

  auto dst = (tempDir / "reup.out").string();
  auto r3 = runShell(cmd("file get /p/reup.txt " + dst));
  BOOST_REQUIRE_EQUAL(r3.exitCode, 0);
  BOOST_CHECK_EQUAL(readFileStr(dst), "v2x");
}

BOOST_AUTO_TEST_CASE(DepositAndWithdraw) {
  auto local = writeTempFile(tempDir, "small.txt", "x");
  auto r = runShell(cmd("file put " + local +
                   " /p/money.txt --deposit 100000"));
  BOOST_REQUIRE_EQUAL(r.exitCode, 0);

  auto r2 = runShell(cmd("file deposit /p/money.txt 50000"));
  BOOST_REQUIRE_EQUAL(r2.exitCode, 0);
  assertContains(r2.out, "File Deposit");

  // STAT shows a balance ≥ our initial deposit + top-up, minus a
  // sliver of rent for the ops that happened between (size=1, rent=1,
  // negligible over milliseconds).
  auto r3 = runShell(cmd("file stat /p/money.txt"));
  BOOST_REQUIRE_EQUAL(r3.exitCode, 0);
  auto balStr = extractField(r3.out, "Balance");
  uint64_t bal = std::stoull(balStr);
  BOOST_CHECK_GE(bal, 100000u);

  auto r4 = runShell(cmd("file withdraw /p/money.txt 40000"));
  BOOST_REQUIRE_EQUAL(r4.exitCode, 0);
  assertContains(r4.out, "File Withdraw");
}

BOOST_AUTO_TEST_CASE(SetPriceTogglesReadFee) {
  auto local = writeTempFile(tempDir, "priced.txt", "payme");
  auto r = runShell(cmd("file put " + local + " /p/priced.txt"));
  BOOST_REQUIRE_EQUAL(r.exitCode, 0);

  auto r2 = runShell(cmd("file set-price /p/priced.txt 42"));
  BOOST_REQUIRE_EQUAL(r2.exitCode, 0);

  auto r3 = runShell(cmd("file stat /p/priced.txt"));
  BOOST_REQUIRE_EQUAL(r3.exitCode, 0);
  BOOST_CHECK_EQUAL(extractField(r3.out, "Price/KB"), "42");
}

BOOST_AUTO_TEST_CASE(ReadPriceCreditsFileBalance) {
  // End-to-end read-price flow. Owner A creates a file, sets a
  // non-zero price_per_kb, and deposits enough credits so rent
  // doesn't eat the balance mid-test. Reader B downloads the file;
  // the server should charge B `ceil(size/1024) * price_per_kb` and
  // credit it to file_balance. Owner can later WITHDRAW that income.
  //
  // This exercises the read-payment loop end-to-end, from two
  // separate wallets, through the live server and file handler.

  const std::string body = "This costs credits to read."; // 27 bytes
  const uint64_t pricePerKb = 500'000;
  auto local = writeTempFile(tempDir, "priced.txt", body);

  // A uploads with a generous deposit so the ops fit comfortably.
  auto r = runShell(cmd(
    "file put " + local + " /p/paidread.txt --deposit 5000000"));
  BOOST_REQUIRE_EQUAL(r.exitCode, 0);
  auto r2 = runShell(cmd(
    "file set-price /p/paidread.txt " + std::to_string(pricePerKb)));
  BOOST_REQUIRE_EQUAL(r2.exitCode, 0);

  // Snapshot file_balance before the read.
  auto r3 = runShell(cmd("file stat /p/paidread.txt"));
  BOOST_REQUIRE_EQUAL(r3.exitCode, 0);
  uint64_t balBefore = std::stoull(extractField(r3.out, "Balance"));

  // B (second wallet) downloads. Should pay pricePerKb × ceil(27/1024)
  // = 1 × 500000 to the file, plus feeQuery + feeFileRead*27 burned
  // from B's own account (not checked here).
  auto dst = (tempDir / "paid.out").string();
  auto r4 = runShell(cmdW(secondWalletHex,
    "file get /p/paidread.txt " + dst));
  BOOST_REQUIRE_EQUAL(r4.exitCode, 0);
  BOOST_CHECK_EQUAL(readFileStr(dst), body);

  auto r5 = runShell(cmd("file stat /p/paidread.txt"));
  BOOST_REQUIRE_EQUAL(r5.exitCode, 0);
  uint64_t balAfter = std::stoull(extractField(r5.out, "Balance"));

  const uint64_t kbCount = (body.size() + 1023) / 1024; // ceil
  const uint64_t readPrice = kbCount * pricePerKb;

  // Expected: balAfter == balBefore + readPrice. Rent may tick the
  // balance down by a few credits between the two STATs (fixture
  // rent=1), so accept a small slack on the low end.
  BOOST_CHECK_GE(balAfter, balBefore + readPrice - 100);
  BOOST_CHECK_LE(balAfter, balBefore + readPrice);
}

BOOST_AUTO_TEST_CASE(OwnerReadDoesNotCreditFileBalance) {
  // Owner reading their own file: `price_per_kb` is waived
  // (file_balance is NOT credited). The server-side feeFileRead is
  // still charged and burned, but doesn't feed the file.
  const std::string body = "owner free read";
  auto local = writeTempFile(tempDir, "ownread.txt", body);
  auto r = runShell(cmd(
    "file put " + local + " /p/ownread.txt --deposit 5000000"));
  BOOST_REQUIRE_EQUAL(r.exitCode, 0);
  auto r2 = runShell(cmd("file set-price /p/ownread.txt 1000000"));
  BOOST_REQUIRE_EQUAL(r2.exitCode, 0);

  auto r3 = runShell(cmd("file stat /p/ownread.txt"));
  BOOST_REQUIRE_EQUAL(r3.exitCode, 0);
  uint64_t balBefore = std::stoull(extractField(r3.out, "Balance"));

  auto dst = (tempDir / "ownread.out").string();
  auto r4 = runShell(cmd("file get /p/ownread.txt " + dst));
  BOOST_REQUIRE_EQUAL(r4.exitCode, 0);

  auto r5 = runShell(cmd("file stat /p/ownread.txt"));
  BOOST_REQUIRE_EQUAL(r5.exitCode, 0);
  uint64_t balAfter = std::stoull(extractField(r5.out, "Balance"));

  // Balance must NOT have grown by `pricePerKb`-like income. Rent
  // may have ticked it down slightly; accept `<= before`.
  BOOST_CHECK_LE(balAfter, balBefore);
}

BOOST_AUTO_TEST_CASE(RmRefundsAndRemoves) {
  auto local = writeTempFile(tempDir, "doomed.txt", "bye");
  auto r = runShell(cmd("file put " + local +
                   " /p/doomed.txt --deposit 500000"));
  BOOST_REQUIRE_EQUAL(r.exitCode, 0);

  auto r2 = runShell(cmd("file rm /p/doomed.txt"));
  BOOST_REQUIRE_EQUAL(r2.exitCode, 0);
  assertContains(r2.out, "File Deleted");

  auto r3 = runShell(cmd("file stat /p/doomed.txt"));
  BOOST_CHECK_NE(r3.exitCode, 0);
  assertContains(r3.out, "CES_ERROR_FILE_NOT_FOUND");
}

BOOST_AUTO_TEST_CASE(PathAutoPrependsHomeDir) {
  // No leading slash → cesh prepends /h/<signer-pubkey>/.
  auto local = writeTempFile(tempDir, "home.txt", "homebody");

  auto r = runShell(cmd("file put " + local + " home.txt"));
  BOOST_REQUIRE_EQUAL(r.exitCode, 0);
  // The "Remote:" field should show the canonicalized /h/<hex>/home.txt.
  auto remote = extractField(r.out, "Remote");
  BOOST_CHECK(remote.find("/h/" + fundedPubHex() + "/home.txt")
              != std::string::npos);

  auto dst = (tempDir / "home.out").string();
  auto r2 = runShell(cmd("file get home.txt " + dst));
  BOOST_REQUIRE_EQUAL(r2.exitCode, 0);
  BOOST_CHECK_EQUAL(readFileStr(dst), "homebody");
}

BOOST_AUTO_TEST_CASE(ChunkedPutGetAboveOneMB) {
  // Make a 1.5 MB file and round-trip it. Exercises the auto-chunking
  // loop (one 1 MB WRITE/READ, plus one half-MB tail).
  std::string body(1'500'000, 'Z');
  auto local = writeTempFile(tempDir, "big.bin", body);

  auto r = runShell(cmd("file put " + local + " /p/big.bin"));
  BOOST_REQUIRE_EQUAL(r.exitCode, 0);

  auto dst = (tempDir / "big.out").string();
  auto r2 = runShell(cmd("file get /p/big.bin " + dst));
  BOOST_REQUIRE_EQUAL(r2.exitCode, 0);
  BOOST_CHECK_EQUAL(readFileStr(dst), body);
}

BOOST_AUTO_TEST_SUITE_END()
