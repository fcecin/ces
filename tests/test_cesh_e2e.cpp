/**
 * E2E tests for the cesh CLI tool.
 *
 * Starts a CesServer in-process, then shells out to the cesh binary
 * and checks exit codes and output.
 */

#include "test_e2e_common.h"

#include <ces/cesproxy.h>

#include <array>
#include <csignal>
#include <fstream>
#include <sys/wait.h>
#include <regex>

using namespace ces::e2e;

// Make `run()` an alias for runShell() so existing call sites keep working.
inline RunResult run(const std::string& cmd) { return runShell(cmd); }

// Ensure Ctrl+C kills the test runner, not just the child process
static struct E2ESignalSetup {
  E2ESignalSetup() {
    std::signal(SIGINT, [](int) { _exit(130); });
  }
} e2eSignalSetup_;

// ============================================================================
// Fixture: starts a CES server for the test suite
// ============================================================================

struct E2EFixture : public E2EServerFixture {
  E2EFixture() : E2EServerFixture("cesh_e2e") {}

  /// Shorthand: build a command with both keys in the wallet.
  std::string cmdBoth(const std::string& args) const {
    return inTempDir(
      ceshCmd(serverPort, fundedWalletHex + ":" + secondWalletHex, ceshBin) +
      " " + args);
  }

  /// Shorthand: build a command with no wallet.
  std::string cmdNoWallet(const std::string& args) const {
    return inTempDir(ceshCmd(serverPort, "", ceshBin) + " " + args);
  }

  std::string fundedPubHex() const { return fundedKey.getPublicKeyHexStr(); }
  std::string secondPubHex() const { return secondKey.getPublicKeyHexStr(); }
};

// ============================================================================
// Tests
// ============================================================================

BOOST_FIXTURE_TEST_SUITE(CeshE2E, E2EFixture)

// ===========================================================================
// Help / CLI structure
// ===========================================================================

BOOST_AUTO_TEST_CASE(TopLevelHelp) {
  auto r = run(cmd("--help"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "keys");
  assertContains(r.out, "query");
  assertContains(r.out, "transfer");
  assertContains(r.out, "asset");
  assertContains(r.out, "server-info");
  assertContains(r.out, "mine");
}

BOOST_AUTO_TEST_CASE(HelpAll) {
  auto r = run(cmd("--help-all"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  // Should show everything recursively
  assertContains(r.out, "gen");
  assertContains(r.out, "list");
  assertContains(r.out, "create");
  assertContains(r.out, "fund");
  assertContains(r.out, "buy");
  assertContains(r.out, "give");
}

BOOST_AUTO_TEST_CASE(BareKeysShowsHelp) {
  auto r = run(cmd("keys"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "gen");
  assertContains(r.out, "list");
  assertContains(r.out, "add");
  assertContains(r.out, "export");
}

BOOST_AUTO_TEST_CASE(BareAssetShowsHelp) {
  auto r = run(cmd("asset"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "create");
  assertContains(r.out, "update");
  assertContains(r.out, "meta");
  assertContains(r.out, "fast");
  assertContains(r.out, "fund");
  assertContains(r.out, "buy");
  assertContains(r.out, "give");
  assertContains(r.out, "query");
}

BOOST_AUTO_TEST_CASE(BareQueryShowsHelp) {
  auto r = run(cmd("query"));
  BOOST_CHECK_EQUAL(r.exitCode, 1);
  assertContains(r.out, "account");
}

BOOST_AUTO_TEST_CASE(BareTransferShowsHelp) {
  auto r = run(cmd("transfer"));
  BOOST_CHECK_EQUAL(r.exitCode, 1);
  assertContains(r.out, "dest");
  assertContains(r.out, "amount");
}

BOOST_AUTO_TEST_CASE(BareSqueryShowsHelp) {
  auto r = run(cmd("squery"));
  BOOST_CHECK_EQUAL(r.exitCode, 1);
  assertContains(r.out, "account");
}

BOOST_AUTO_TEST_CASE(InvalidSubcommand) {
  auto r = run(cmd("notacommand"));
  BOOST_CHECK_NE(r.exitCode, 0);
}

// ===========================================================================
// Key management
// ===========================================================================

BOOST_AUTO_TEST_CASE(KeysGen) {
  auto r = run(cmd("keys gen"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "Generated 1 ed25519");
  // Should print only the new key ([@1] since wallet has funded key at [@0])
  assertContains(r.out, "[@1]");
  assertNotContains(r.out, "[@0]", "should not print pre-loaded keys");
}

BOOST_AUTO_TEST_CASE(KeysGenMultiple) {
  auto r = run(cmd("keys gen 3"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "Generated 3 ed25519");
}

BOOST_AUTO_TEST_CASE(KeysGenSecp) {
  auto r = run(cmd("--secp keys gen"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "secp256k1");
}

BOOST_AUTO_TEST_CASE(KeysList) {
  auto r = run(cmd("keys list"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "[@0]");
  assertContains(r.out, "[ED  ]");
}

BOOST_AUTO_TEST_CASE(KeysListPublic) {
  auto r = run(cmd("keys list -p"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, fundedPubHex());
}

BOOST_AUTO_TEST_CASE(KeysListMultiple) {
  // Wallet has two keys
  auto r = run(cmdBoth("keys list -p"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "[@0]");
  assertContains(r.out, "[@1]");
  assertContains(r.out, fundedPubHex());
  assertContains(r.out, secondPubHex());
}

BOOST_AUTO_TEST_CASE(KeysExport) {
  auto r = run(cmd("keys export"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "export CESH_WALLET=");
  assertContains(r.out, fundedWalletHex);
}

BOOST_AUTO_TEST_CASE(KeysExportMultiple) {
  auto r = run(cmdBoth("keys export"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, fundedWalletHex);
  assertContains(r.out, secondWalletHex);
  // Colon-separated
  assertContains(r.out, ":");
}

BOOST_AUTO_TEST_CASE(KeysAdd) {
  // Add a known private key (raw 64 hex chars) and verify it shows in list
  KeyPair extra;
  std::string rawPriv = extra.getPrivateKeyHexStr();
  auto r = run(cmd("keys add " + rawPriv));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "Added");
  assertContains(r.out, "ed25519");
}

BOOST_AUTO_TEST_CASE(KeysAddQualified) {
  // Add a qualified key (66 hex chars, 01 prefix = secp)
  KeyPair extra(KeyAlgo::SECP256K1);
  std::string qualifiedHex = "01" + extra.getPrivateKeyHexStr();
  auto r = run(cmd("keys add " + qualifiedHex));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "Added");
}

BOOST_AUTO_TEST_CASE(KeysAddBadLength) {
  auto r = run(cmd("keys add abcd1234"));
  BOOST_CHECK_NE(r.exitCode, 0);
  assertContains(r.out, "64 hex");
}

BOOST_AUTO_TEST_CASE(KeysGenSaveAndLoad) {
  // Gen a key and save to a wallet file
  fs::path walletFile = tempDir / "test_wallet.dat";
  auto r = run(cmdNoWallet("keys gen -w " + walletFile.string()));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "Generated");
  assertContains(r.out, "Saved wallet to");
  BOOST_CHECK(fs::exists(walletFile));

  // Load it back and list
  auto r2 = run(cmdNoWallet("-r " + walletFile.string() + " keys list"));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);
  assertContains(r2.out, "[@0]");
}

// ===========================================================================
// Ping (unsigned handshake info)
// ===========================================================================

BOOST_AUTO_TEST_CASE(PingSucceeds) {
  auto r = run(cmdNoWallet("ping"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  // Plaintext, key=value, one per line — easy to parse with grep/awk.
  assertContains(r.out, "status=ok");
  assertContains(r.out, "server_key=");
  assertContains(r.out, "server_id=");
  assertContains(r.out, "min_difficulty=");
  assertContains(r.out, "min_secs_pow=");
  assertContains(r.out, "pending_pows=");
  assertContains(r.out, "tps=");
  // E2EServerFixture leaves rpcPort at the default (0).
  assertContains(r.out, "rpc_port=0");
}

BOOST_AUTO_TEST_CASE(PingUnreachableServerReportsError) {
  // Point at a (hopefully) closed loopback UDP port. cesh will time out
  // and emit the parseable error shape.
  std::string cmdline =
    inTempDir(std::string(ceshBin) +
              " --server 127.0.0.1:1 --tries 1 ping");
  auto r = run(cmdline);
  BOOST_CHECK_EQUAL(r.exitCode, 1);
  assertContains(r.out, "status=error");
  assertContains(r.out, "error=");
}

// ===========================================================================
// Unsigned account query
// ===========================================================================

BOOST_AUTO_TEST_CASE(QueryFundedAccount) {
  auto r = run(cmd("query " + fundedPubHex()));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "Account (Unsigned)");
  assertContains(r.out, "Balance");
  assertContains(r.out, "10000000000");
  assertContains(r.out, "Nonce");
  assertContains(r.out, "LastXferDest");
  assertContains(r.out, "LastXferAmount");
  assertContains(r.out, "LastXferTime");
}

BOOST_AUTO_TEST_CASE(QueryNonexistentAccount) {
  KeyPair nobody;
  auto r = run(cmd("query " + nobody.getPublicKeyHexStr()));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "Balance");
  assertContains(r.out, "0");
}

// --- Silent/pipe mode (-q): stdout is data only (JSON), no human chrome. ---

BOOST_AUTO_TEST_CASE(QuietQueryIsJsonOnly) {
  auto r = run(cmd("-q query " + fundedPubHex()));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "\"balance\":10000000000");
  assertContains(r.out, "\"nonce\":");
  // No human chrome on stdout.
  assertNotContains(r.out, "===", "quiet stdout must carry no header chrome");
  assertNotContains(r.out, "Account (Unsigned)", "no human title in quiet mode");
}

BOOST_AUTO_TEST_CASE(QuietServerInfoAdvertisesRpcPort) {
  auto r = run(cmd("-q server-info"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  // The omission we just fixed: rpcPort is in the paid KV, and as JSON here.
  assertContains(r.out, "\"rpcPort\":");
  assertContains(r.out, "\"serverPublicKey\":");
  assertNotContains(r.out, "===", "quiet stdout must carry no header chrome");
}

BOOST_AUTO_TEST_CASE(QuietPingHasRpcPort) {
  auto r = run(cmd("-q ping"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "\"status\":\"ok\"");
  assertContains(r.out, "\"rpcPort\":");
  assertNotContains(r.out, "status=ok", "quiet ping must be JSON, not key=value");
}

BOOST_AUTO_TEST_CASE(QueryViaWalletIndex) {
  // Query @0 (the funded key) via wallet index
  auto r = run(cmd("query @0"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "10000000000");
}

// ===========================================================================
// Signed account query
// ===========================================================================

BOOST_AUTO_TEST_CASE(SignedQuerySelf) {
  auto r = run(cmd("squery " + fundedPubHex()));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "Account (Signed)");
  assertContains(r.out, "Balance");
  assertContains(r.out, "Nonce");
  assertContains(r.out, "LastXferDest");
}

BOOST_AUTO_TEST_CASE(SignedQueryOther) {
  auto other = makeFunded(5'000'000);

  auto r = run(cmd("squery " + other.pubHex));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "Account (Signed)");
  assertContains(r.out, "5000000");
}

BOOST_AUTO_TEST_CASE(SignedQueryViaWalletIndex) {
  auto r = run(cmd("squery @0"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "Account (Signed)");
}

// ===========================================================================
// Transfer
// ===========================================================================

BOOST_AUTO_TEST_CASE(TransferBasic) {
  auto dest = makeUnfunded();

  auto r = run(cmd("transfer --open " + dest.pubHex + " 1000"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "Success");
  assertContains(r.out, "Rem. Bal");

  wait_net();

  auto r2 = run(cmd("query " + dest.pubHex));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);
  assertContains(r2.out, "1000");
}

BOOST_AUTO_TEST_CASE(TransferToSelf) {
  auto r = run(cmd("transfer " + fundedPubHex() + " 100"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "Success");
}

BOOST_AUTO_TEST_CASE(TransferViaWalletIndex) {
  // Use @1 as destination with both keys in wallet
  auto dest = makeUnfunded();
  std::string bothWallet = fundedWalletHex + ":" + dest.walletHex;

  auto r = run(cmdW(bothWallet, "transfer --open @1 5000"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "Success");

  wait_net();

  auto r2 = run(cmd("query " + dest.pubHex));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);
  assertContains(r2.out, "5000");
}

BOOST_AUTO_TEST_CASE(TransferInsufficientFunds) {
  auto broke = makeFunded(100);
  auto dest = makeUnfunded();

  auto r = run(cmdW(broke.walletHex, "transfer --open " + dest.pubHex + " 999999999"));
  BOOST_CHECK_NE(r.exitCode, 0);
  assertContains(r.out, "Failed");
}

BOOST_AUTO_TEST_CASE(TransferZeroAmount) {
  auto dest = makeUnfunded();
  auto r = run(cmd("transfer --open " + dest.pubHex + " 0"));
  // Zero transfer should either succeed (sending 0) or fail gracefully
  BOOST_CHECK(r.exitCode == 0 || r.exitCode == 1);
}

BOOST_AUTO_TEST_CASE(TransferMultipleSequential) {
  auto dest = makeUnfunded();
  // Multiple transfers in sequence — tests nonce advancement
  for (int i = 0; i < 3; i++) {
    auto r = run(cmd("transfer --open " + dest.pubHex + " 100"));
    BOOST_CHECK_EQUAL(r.exitCode, 0);
    assertContains(r.out, "Success");
    wait_net();
  }

  auto r2 = run(cmd("query " + dest.pubHex));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);
  assertContains(r2.out, "300");
}

BOOST_AUTO_TEST_CASE(SafeTransferRejectsNonexistent) {
  auto dest = makeUnfunded();

  // Safe transfer (default) to nonexistent account should fail
  auto r = run(cmd("transfer " + dest.pubHex + " 1000"));
  BOOST_CHECK_NE(r.exitCode, 0);
  assertContains(r.out, "CES_ERROR_TARGET_NOT_FOUND");
}

BOOST_AUTO_TEST_CASE(TransferWithPayment) {
  auto dest = makeUnfunded();

  auto r = run(cmd("payment " + dest.pubHex + " 50000 --days 5"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "Success");

  wait_net();

  auto r2 = run(cmd("query " + dest.pubHex));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);
  assertContains(r2.out, "Account (Unsigned)");
}

// ===========================================================================
// Server info
// ===========================================================================

BOOST_AUTO_TEST_CASE(ServerInfo) {
  auto r = run(cmd("server-info"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "Server Info");
  assertContains(r.out, "totalAccounts");
  assertContains(r.out, "totalAssets");
  assertContains(r.out, "totalCredits");
  assertContains(r.out, "feeTx");
  assertContains(r.out, "feeQuery");
  assertContains(r.out, "feeAccount");
  assertContains(r.out, "feeAsset");
  assertContains(r.out, "feeError");
  assertContains(r.out, "minAccounts");
  assertContains(r.out, "maxAccounts");
  assertContains(r.out, "minAssets");
  assertContains(r.out, "maxAssets");
  assertContains(r.out, "minDifficulty");
  assertContains(r.out, "spendSlotSize");
}

BOOST_AUTO_TEST_CASE(ServerInfoHelp) {
  auto r = run(cmd("server-info --help"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "server-info");
}

// ===========================================================================
// Asset operations — full lifecycle
// ===========================================================================

BOOST_AUTO_TEST_CASE(AssetCreateAndQuery) {
  auto r = run(cmd("asset create myasset --content hello --days 10"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "Asset Created");
  assertContains(r.out, "Success");

  wait_net();

  auto r2 = run(cmd("asset query myasset"));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);
  assertContains(r2.out, "Asset (Unsigned)");
  assertContains(r2.out, "hello");
  assertContains(r2.out, "Owner ID");
  assertContains(r2.out, "Balance");
  assertContains(r2.out, "Price");
  assertContains(r2.out, "Content");
}

BOOST_AUTO_TEST_CASE(AssetQueryNonexistent) {
  auto r = run(cmd("asset query doesnotexist"));
  BOOST_CHECK_NE(r.exitCode, 0);
  assertContains(r.out, "not found");
}

BOOST_AUTO_TEST_CASE(AssetCreateDuplicate) {
  auto r1 = run(cmd("asset create dupasset --content first --days 5"));
  BOOST_CHECK_EQUAL(r1.exitCode, 0);
  wait_net();

  // Creating same asset again should fail
  auto r2 = run(cmd("asset create dupasset --content second --days 5"));
  BOOST_CHECK_NE(r2.exitCode, 0);
  assertContains(r2.out, "Failed");
}

BOOST_AUTO_TEST_CASE(AssetUpdate) {
  // Create, then full update with new content and price
  auto r1 = run(cmd("asset create updasset --content original --days 10"));
  BOOST_CHECK_EQUAL(r1.exitCode, 0);
  wait_net();

  auto r2 = run(cmd("asset update updasset --content updated --price 2"));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);
  assertContains(r2.out, "Asset Updated");
  assertContains(r2.out, "Success");

  wait_net();

  // Verify content changed — price displayed in whole credits
  auto r3 = run(cmd("asset query updasset"));
  BOOST_CHECK_EQUAL(r3.exitCode, 0);
  assertContains(r3.out, "updated");
  assertContains(r3.out, "2 credits");
}

BOOST_AUTO_TEST_CASE(AssetMeta) {
  auto r1 = run(cmd("asset create metaasset --content stuff --days 10"));
  BOOST_CHECK_EQUAL(r1.exitCode, 0);
  wait_net();

  // Update only metadata (price), no content change
  // Price is now in whole credits: 1 = minimum non-zero price
  auto r2 = run(cmd("asset meta metaasset --price 1"));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);
  assertContains(r2.out, "Asset Meta Updated");
  assertContains(r2.out, "Success");

  wait_net();

  auto r3 = run(cmd("asset query metaasset"));
  BOOST_CHECK_EQUAL(r3.exitCode, 0);
  assertContains(r3.out, "1 credits");
  // Content should still be "stuff"
  assertContains(r3.out, "stuff");
}

BOOST_AUTO_TEST_CASE(AssetFast) {
  auto r1 = run(cmd("asset create fastasset --content before --days 10"));
  BOOST_CHECK_EQUAL(r1.exitCode, 0);
  wait_net();

  auto r2 = run(cmd("asset fast fastasset --content after"));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);
  assertContains(r2.out, "Asset Fast-Updated");
  assertContains(r2.out, "Success");

  wait_net();

  auto r3 = run(cmd("asset query fastasset"));
  BOOST_CHECK_EQUAL(r3.exitCode, 0);
  assertContains(r3.out, "after");
}

BOOST_AUTO_TEST_CASE(AssetFund) {
  auto r1 = run(cmd("asset create fundasset --content data --days 5"));
  BOOST_CHECK_EQUAL(r1.exitCode, 0);
  wait_net();

  auto r2 = run(cmd("asset fund fundasset --days 10"));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);
  assertContains(r2.out, "Asset Funded");
  assertContains(r2.out, "Days Added");
  assertContains(r2.out, "10");
  assertContains(r2.out, "Success");
}

BOOST_AUTO_TEST_CASE(AssetGive) {
  auto receiver = makeFunded();

  auto r1 = run(cmd("asset create giveasset --content gift --days 10"));
  BOOST_CHECK_EQUAL(r1.exitCode, 0);
  wait_net();

  auto r2 = run(cmd("asset give giveasset --target " + receiver.pubHex));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);
  assertContains(r2.out, "Asset Given");
  assertContains(r2.out, "Success");

  wait_net();

  auto r3 = run(cmd("asset query giveasset"));
  BOOST_CHECK_EQUAL(r3.exitCode, 0);
  assertContains(r3.out, "gift");
}

BOOST_AUTO_TEST_CASE(AssetBuy) {
  auto buyer = makeFunded(500'000'000);

  auto r1 = run(cmd("asset create buyable --content forsale --days 10"));
  BOOST_CHECK_EQUAL(r1.exitCode, 0);
  wait_net();

  auto r2 = run(cmd("asset meta buyable --price 1"));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);
  wait_net();

  auto r3 =
    run(cmdW(buyer.walletHex, "asset buy buyable --amount 1"));
  BOOST_CHECK_EQUAL(r3.exitCode, 0);
  assertContains(r3.out, "Asset Purchased");
  assertContains(r3.out, "Success");
}

BOOST_AUTO_TEST_CASE(AssetPriceTooHigh) {
  auto r = run(cmd("asset create cheapasset --content x --days 5"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  wait_net();

  // Price above UINT32_MAX should fail
  auto r2 = run(cmd("asset meta cheapasset --price 5000000000"));
  BOOST_CHECK_NE(r2.exitCode, 0);
  assertContains(r2.out, "Invalid price");
}

BOOST_AUTO_TEST_CASE(AssetPriceZeroIsValid) {
  auto r = run(cmd("asset create freeasset --content free --days 5"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  wait_net();

  // Price 0 means "not for sale" — should be valid
  auto r2 = run(cmd("asset meta freeasset --price 0"));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);
  assertContains(r2.out, "Success");
}

BOOST_AUTO_TEST_CASE(AssetUpdateByNonOwner) {
  auto intruder = makeFunded();

  auto r1 = run(cmd("asset create notown --content secret --days 10"));
  BOOST_CHECK_EQUAL(r1.exitCode, 0);
  wait_net();

  auto r2 =
    run(cmdW(intruder.walletHex, "asset update notown --content hacked"));
  BOOST_CHECK_NE(r2.exitCode, 0);
  assertContains(r2.out, "Failed");
}

BOOST_AUTO_TEST_CASE(AssetFundNonexistent) {
  auto r = run(cmd("asset fund phantom --days 10"));
  BOOST_CHECK_NE(r.exitCode, 0);
  assertContains(r.out, "Failed");
}

BOOST_AUTO_TEST_CASE(AssetRunNopProgram) {
  // Create an asset with a NOP+TERM program (hex: 00 01)
  auto r = run(cmd("asset create runtest1 --hexcontent 0001 --days 10"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  wait_net();

  auto r2 = run(cmd("asset run runtest1 --budget 10000000"));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);
  assertContains(r2.out, "Asset Executed");
  assertContains(r2.out, "Success");
  assertContains(r2.out, "Budget Used");
}

BOOST_AUTO_TEST_CASE(AssetRunNonexistent) {
  auto r = run(cmd("asset run nonexistent --budget 10000000"));
  BOOST_CHECK_NE(r.exitCode, 0);
  assertContains(r.out, "Failed");
}

BOOST_AUTO_TEST_CASE(AutoexecInstall) {
  // Create a simple TERM program
  auto r = run(cmd("asset create autoexec_prog --hexcontent 01 --days 30"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  wait_net();

  // Install autoexec
  auto r2 = run(cmd("autoexec install autoexec_prog --budget 10000000"));
  if (r2.exitCode != 0) {
    BOOST_TEST_MESSAGE("autoexec install output: " << r2.out);
  }
  BOOST_CHECK_EQUAL(r2.exitCode, 0);
  assertContains(r2.out, "Autoexec Installed");
  assertContains(r2.out, "Autoexec Key");
  assertContains(r2.out, "To disable");
}

// ===========================================================================
// File storage E2E
// ===========================================================================

BOOST_AUTO_TEST_CASE(FilePutGetWithData) {
  auto r = run(cmd("ramfile put testfile1 --in HelloWorld --days 10"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "File Uploaded");
  wait_net();

  auto r2 = run(cmd("ramfile get testfile1 /tmp/ces_e2e_testfile1.bin"));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);
  assertContains(r2.out, "File Downloaded");

  std::ifstream ifs("/tmp/ces_e2e_testfile1.bin");
  std::string content((std::istreambuf_iterator<char>(ifs)),
                       std::istreambuf_iterator<char>());
  BOOST_CHECK_EQUAL(content, "HelloWorld");
  std::remove("/tmp/ces_e2e_testfile1.bin");
}

BOOST_AUTO_TEST_CASE(FilePutWithHexdata) {
  auto r = run(cmd("ramfile put testfile2 --in hex:48454c4c4f --days 10"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  wait_net();

  auto r2 = run(cmd("ramfile get testfile2 /tmp/ces_e2e_testfile2.bin"));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);

  std::ifstream ifs("/tmp/ces_e2e_testfile2.bin");
  std::string content((std::istreambuf_iterator<char>(ifs)),
                       std::istreambuf_iterator<char>());
  BOOST_CHECK_EQUAL(content, "HELLO");
  std::remove("/tmp/ces_e2e_testfile2.bin");
}

BOOST_AUTO_TEST_CASE(FilePutComposed) {
  auto r = run(cmd("ramfile put testfile3 --in AB --in hex:4344 --in EF --days 10"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  wait_net();

  auto r2 = run(cmd("ramfile get testfile3 /tmp/ces_e2e_testfile3.bin"));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);

  std::ifstream ifs("/tmp/ces_e2e_testfile3.bin");
  std::string content((std::istreambuf_iterator<char>(ifs)),
                       std::istreambuf_iterator<char>());
  BOOST_CHECK_EQUAL(content, "ABCDEF");
  std::remove("/tmp/ces_e2e_testfile3.bin");
}

BOOST_AUTO_TEST_CASE(FilePutEmptyIsTouch) {
  auto r = run(cmd("ramfile put testfile4 --days 10"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "File Uploaded");
  assertContains(r.out, "0 bytes");
}

BOOST_AUTO_TEST_CASE(FileInfo) {
  auto r = run(cmd("ramfile put testfile5 --in infotest --days 10 --meta text/plain"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  wait_net();

  auto r2 = run(cmd("ramfile info testfile5"));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);
  assertContains(r2.out, "File Info");
  assertContains(r2.out, "8 bytes");
  assertContains(r2.out, "text/plain");
  assertContains(r2.out, "SHA256");
}

BOOST_AUTO_TEST_CASE(FileScanAndFund) {
  auto r = run(cmd("ramfile put testfile6 --in scanme --days 5"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  wait_net();

  auto r2 = run(cmd("ramfile scan testfile6"));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);
  assertContains(r2.out, "File Scanned");

  auto r3 = run(cmd("ramfile fund testfile6 --days 10"));
  BOOST_CHECK_EQUAL(r3.exitCode, 0);
  assertContains(r3.out, "File Funded");
}

BOOST_AUTO_TEST_CASE(FileTouch) {
  auto r = run(cmd("ramfile touch testfile7 --days 10"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "File Created");
}

BOOST_AUTO_TEST_CASE(FileGetNonexistent) {
  auto r = run(cmd("ramfile get nonexistent /tmp/ces_e2e_nofile.bin"));
  BOOST_CHECK_NE(r.exitCode, 0);
}

BOOST_AUTO_TEST_CASE(FilePutWithTextPrefix) {
  auto r = run(cmd("ramfile put testfile8 --in text:hex:notactuallyhex --days 10"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  wait_net();

  auto r2 = run(cmd("ramfile get testfile8 /tmp/ces_e2e_testfile8.bin"));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);

  std::ifstream ifs("/tmp/ces_e2e_testfile8.bin");
  std::string content((std::istreambuf_iterator<char>(ifs)),
                       std::istreambuf_iterator<char>());
  BOOST_CHECK_EQUAL(content, "hex:notactuallyhex");
  std::remove("/tmp/ces_e2e_testfile8.bin");
}

BOOST_AUTO_TEST_CASE(FilePutFromFile) {
  // Write a temp file then upload it
  {
    std::ofstream ofs("/tmp/ces_e2e_srcfile.txt");
    ofs << "fromfile";
  }
  auto r = run(cmd("ramfile put testfile9 --in file:/tmp/ces_e2e_srcfile.txt --days 10"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  wait_net();

  auto r2 = run(cmd("ramfile get testfile9 /tmp/ces_e2e_testfile9.bin"));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);

  std::ifstream ifs("/tmp/ces_e2e_testfile9.bin");
  std::string content((std::istreambuf_iterator<char>(ifs)),
                       std::istreambuf_iterator<char>());
  BOOST_CHECK_EQUAL(content, "fromfile");
  std::remove("/tmp/ces_e2e_srcfile.txt");
  std::remove("/tmp/ces_e2e_testfile9.bin");
}

// ===========================================================================
// Edge cases and error handling
// ===========================================================================

BOOST_AUTO_TEST_CASE(NoWalletTransferFails) {
  auto dest = makeUnfunded();
  auto r = run(cmdNoWallet("transfer " + dest.pubHex + " 100"));
  BOOST_CHECK_NE(r.exitCode, 0);
  assertContains(r.out, "No keys");
}

BOOST_AUTO_TEST_CASE(NoWalletQueryWorks) {
  // Unsigned query doesn't need a wallet
  auto r = run(cmdNoWallet("query " + fundedPubHex()));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "10000000000");
}

BOOST_AUTO_TEST_CASE(NoWalletSignedQueryFails) {
  auto r = run(cmdNoWallet("squery " + fundedPubHex()));
  BOOST_CHECK_NE(r.exitCode, 0);
  assertContains(r.out, "No keys");
}

BOOST_AUTO_TEST_CASE(ActorSelection) {
  auto actor = makeFunded();
  std::string bothWallet = fundedWalletHex + ":" + actor.walletHex;

  auto r = run(cmdW(bothWallet, "-a @1 squery " + actor.pubHex));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "Account (Signed)");
}

BOOST_AUTO_TEST_CASE(ActorSelectionByPubkey) {
  auto actor = makeFunded();
  std::string bothWallet = fundedWalletHex + ":" + actor.walletHex;

  auto r =
    run(cmdW(bothWallet, "-a " + actor.pubHex + " squery " + actor.pubHex));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "Account (Signed)");
}

BOOST_AUTO_TEST_CASE(ActorSelectionBadIndex) {
  auto r = run(cmd("-a @99 squery " + fundedPubHex()));
  BOOST_CHECK_NE(r.exitCode, 0);
}

BOOST_AUTO_TEST_CASE(TransferUpdatesLastXfer) {
  auto dest = makeUnfunded();
  // Use a fresh sender so the last xfer fields are known
  auto sender = makeFunded();

  auto r1 = run(cmdW(sender.walletHex, "transfer --open " + dest.pubHex + " 7777"));
  BOOST_CHECK_EQUAL(r1.exitCode, 0);
  wait_net();

  auto r2 = run(cmd("query " + sender.pubHex));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);
  assertContains(r2.out, "LastXferAmount");
  assertContains(r2.out, "7777");
}

BOOST_AUTO_TEST_CASE(SequentialOperationsMixedTypes) {
  auto dest = makeUnfunded();
  // Transfer, query, server-info — tests nonce tracking across different ops
  auto r1 = run(cmd("transfer --open " + dest.pubHex + " 500"));
  BOOST_CHECK_EQUAL(r1.exitCode, 0);
  wait_net();

  auto r2 = run(cmd("squery " + fundedPubHex()));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);
  wait_net();

  auto r3 = run(cmd("server-info"));
  BOOST_CHECK_EQUAL(r3.exitCode, 0);
  wait_net();

  auto r4 = run(cmd("transfer " + dest.pubHex + " 500")); // dest exists now
  BOOST_CHECK_EQUAL(r4.exitCode, 0);
}

BOOST_AUTO_TEST_CASE(AssetWithHexContent) {
  // Create asset with a hex-string content (32 bytes)
  std::string hexContent =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  auto r1 =
    run(cmd("asset create hexasset --hexcontent " + hexContent + " --days 5"));
  BOOST_CHECK_EQUAL(r1.exitCode, 0);
  wait_net();

  auto r2 = run(cmd("asset query hexasset"));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);
  // Hex content should be returned
  assertContains(r2.out, "0123456789abcdef");
}

BOOST_AUTO_TEST_CASE(AssetUpdateTransferOwnership) {
  auto newOwner = makeFunded();

  auto r1 =
    run(cmd("asset create xferasset --content owned --days 10"));
  BOOST_CHECK_EQUAL(r1.exitCode, 0);
  wait_net();

  auto r2 = run(
    cmd("asset update xferasset --content owned --target " + newOwner.pubHex));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);
  assertContains(r2.out, "Success");

  wait_net();

  auto r3 = run(
    cmdW(newOwner.walletHex, "asset fast xferasset --content newowner"));
  BOOST_CHECK_EQUAL(r3.exitCode, 0);
  assertContains(r3.out, "Success");
}

BOOST_AUTO_TEST_CASE(ThreePartyAssetScenario) {
  // A creates asset, sets price, B buys it, then gives it to C
  auto B = makeFunded(500'000'000);
  auto C = makeFunded();

  // A creates and prices asset at 1 whole credit
  auto r1 =
    run(cmd("asset create traded --content item --days 10"));
  BOOST_CHECK_EQUAL(r1.exitCode, 0);
  wait_net();

  auto r2 = run(cmd("asset meta traded --price 1"));
  BOOST_CHECK_EQUAL(r2.exitCode, 0);
  wait_net();

  // B buys it
  auto r3 =
    run(cmdW(B.walletHex, "asset buy traded --amount 1"));
  BOOST_CHECK_EQUAL(r3.exitCode, 0);
  wait_net();

  // B gives it to C
  auto r4 = run(
    cmdW(B.walletHex, "asset give traded --target " + C.pubHex));
  BOOST_CHECK_EQUAL(r4.exitCode, 0);
  wait_net();

  // C can now update it
  auto r5 =
    run(cmdW(C.walletHex, "asset fast traded --content cowned"));
  BOOST_CHECK_EQUAL(r5.exitCode, 0);

  wait_net();

  // Verify content
  auto r6 = run(cmd("asset query traded"));
  BOOST_CHECK_EQUAL(r6.exitCode, 0);
  assertContains(r6.out, "cowned");
}

// ---------------------------------------------------------------------------
// Mining
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(MineExistingAccount) {
  ensurePoWEngine();
  auto fk = makeFunded();
  // -c for cache-only (fast init), 30s timeout for mining
  auto mineCmd = ceshCmd(serverPort, fk.walletHex, ceshBin) + " -c mine";
  auto r = runExpect(mineCmd, 0);
  assertContains(r.out, "Success!", "mine existing account");
  assertContains(r.out, "Credit:", "mine should report credit");
}

// Mining a new account at minDiff=1 can't work: the reward (1000) is less
// than the account creation fee (BASE_FEE_ACCOUNT = 6,400,000), so the
// server silently rejects it. A higher difficulty would work but takes
// too long for a test — for reference, diff 14 is the first that covers
// the fee ((1<<13)*1000 = 8,192,000), and diff 14 on a test VM is slow.

// ---------------------------------------------------------------------------
// Gossip — the signed main-port producer (needs a real PoW ticket, hence the
// PoW engine). The lone server has no peers, so the flood reaches nobody, but
// the home server still accepts/charges/acks: exit 0 is the producer working.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(GossipBroadcast) {
  ensurePoWEngine();
  auto r = run(cmd("gossip hello 1000000"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "Gossip Sent");
  assertContains(r.out, "broadcast");
}

BOOST_AUTO_TEST_CASE(GossipTargeted) {
  ensurePoWEngine();
  auto r = run(cmd("gossip hi 500000 " + secondPubHex()));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "Gossip Sent");
}

BOOST_AUTO_TEST_CASE(GossipQuietJson) {
  ensurePoWEngine();
  auto r = run(cmd("-q gossip hi 1000"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "\"ok\":true");
}

BOOST_AUTO_TEST_CASE(BareGossipShowsHelp) {
  auto r = run(cmd("gossip"));
  BOOST_CHECK_EQUAL(r.exitCode, 1);
  assertContains(r.out, "msg");
  assertContains(r.out, "budget");
}

BOOST_AUTO_TEST_SUITE_END()

// ============================================================================
// Proxy E2E tests — cesh --proxy through CesProxy
// ============================================================================

struct ProxyE2EFixture : public E2EServerFixture {
  std::unique_ptr<CesProxy> proxy;
  uint16_t proxyPort = 0;

  ProxyE2EFixture() : E2EServerFixture("cesh_proxy_e2e") {
    // Start proxy
    boost::asio::ip::tcp::endpoint listenEp(
      boost::asio::ip::address::from_string("127.0.0.1"), 0);
    boost::asio::ip::udp::endpoint upstreamEp(
      boost::asio::ip::address_v6::loopback(), serverPort);

    minx::MinxProxyConfig proxyCfg;
    proxyCfg.numChannels = 4;
    proxyCfg.channelTimeout = std::chrono::seconds(5);
    proxyCfg.sweepInterval = std::chrono::seconds(1);

    proxy = std::make_unique<CesProxy>(listenEp, upstreamEp, proxyCfg);
    proxyPort = proxy->port();
    BOOST_REQUIRE(proxyPort > 0);

    // Wait for proxy handshake
    for (int i = 0; i < 50; ++i) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      if (proxy->hasCachedInfo() && proxy->readyChannelCount() > 0)
        break;
    }
    BOOST_REQUIRE(proxy->hasCachedInfo());
  }

  ~ProxyE2EFixture() {
    if (proxy)
      proxy->stop();
    proxy.reset();
    // Base destructor handles server, tempDir cleanup.
  }

  // Override to route through the proxy port instead of the server port.
  std::string cmd(const std::string& args) const {
    return inTempDir(ceshProxyCmd(proxyPort, fundedWalletHex, ceshBin) +
                     " " + args);
  }

  std::string cmdW(const std::string& wallet, const std::string& args) const {
    return inTempDir(ceshProxyCmd(proxyPort, wallet, ceshBin) + " " + args);
  }
};

BOOST_FIXTURE_TEST_SUITE(CeshProxyE2E, ProxyE2EFixture)

BOOST_AUTO_TEST_CASE(QueryAccountThroughProxy) {
  auto r = run(cmd("query " + fundedKey.getPublicKeyHexStr()));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "Balance");
}

BOOST_AUTO_TEST_CASE(UnsignedAssetQueryThroughProxy) {
  auto r = run(cmd("asset query proxytest"));
  // Asset doesn't exist — cesh returns 1 with "not found"
  BOOST_CHECK_EQUAL(r.exitCode, 1);
  assertContains(r.out, "not found", "unsigned asset query through proxy");
}

BOOST_AUTO_TEST_CASE(TransferThroughProxy) {
  auto receiver = makeFunded();

  auto r = run(cmd("transfer " + receiver.pubHex + " 1000"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "Transfer");
  assertContains(r.out, "Success");
}

BOOST_AUTO_TEST_CASE(SignedQueryThroughProxy) {
  auto r = run(cmd("squery " + fundedKey.getPublicKeyHexStr()));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "Balance");
}

BOOST_AUTO_TEST_CASE(AssetCreateThroughProxy) {
  auto r = run(cmd("asset create proxyasset --content hello --days 5"));
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "Created");
  assertContains(r.out, "Success");
}

BOOST_AUTO_TEST_SUITE_END()

// ============================================================================
// cesnetbot E2E: multi-server cross-transfer verification
// ============================================================================

struct CesnetBotFixture {
  std::string cesnetBin;
  std::string cesnetbotBin;
  fs::path workDir;

  CesnetBotFixture() {
    // Locate scripts relative to test binary (build/<type>/tests/ceshe2e)
    std::string self =
      boost::unit_test::framework::master_test_suite().argv[0];
    // build/<type>/tests/ceshe2e → 3 parent_path calls → build/, one more → project root
    fs::path projectRoot = fs::path(self).parent_path().parent_path().parent_path().parent_path();
    cesnetBin = (projectRoot / "cesnet").string();
    cesnetbotBin = (projectRoot / "cesnetbot").string();
    BOOST_REQUIRE_MESSAGE(fs::exists(cesnetBin), "cesnet not found at " + cesnetBin);
    BOOST_REQUIRE_MESSAGE(fs::exists(cesnetbotBin), "cesnetbot not found at " + cesnetbotBin);

    workDir = fs::temp_directory_path() / ("cesnetbot_e2e_" + std::to_string(getpid()));
  }

  ~CesnetBotFixture() {
    // Always try to destroy
    run(cesnetBin + " --home " + workDir.string() + " destroy");
  }
};

BOOST_FIXTURE_TEST_SUITE(CesnetBotE2E, CesnetBotFixture)

BOOST_AUTO_TEST_CASE(MultiServerTransfers) {
  std::string home = "--home " + workDir.string();

  run(cesnetBin + " nuke");

  auto r1 = run(cesnetBin + " " + home + " init 5");
  BOOST_REQUIRE_EQUAL(r1.exitCode, 0);
  BOOST_TEST_MESSAGE(r1.out);

  auto r2 = run(cesnetBin + " " + home + " up");
  BOOST_REQUIRE_EQUAL(r2.exitCode, 0);
  BOOST_TEST_MESSAGE(r2.out);

  auto r3 = run(cesnetbotBin + " run " + home + " --users 100 --rounds 10");
  BOOST_TEST_MESSAGE(r3.out);
  BOOST_CHECK_EQUAL(r3.exitCode, 0);
  assertContains(r3.out, "TEST PASS");
}

BOOST_AUTO_TEST_SUITE_END()

// ============================================================================
// SIGTERM graceful shutdown — data persistence test
// ============================================================================

BOOST_AUTO_TEST_SUITE(SigtermPersistence)

BOOST_AUTO_TEST_CASE(SigtermPreservesData) {
  // Out-of-process test: spawn ces + cesh as subprocesses and send real SIGTERM.
  // Uses the shared binary-lookup and tempDir helpers from test_e2e_common.h.
  std::string cesBin = findCesBinary();
  std::string ceshBin = findCeshBinary();
  auto tempDir = makeUniqueTempDir("sigterm_e2e");

  // Generate server key and test account key
  minx::Hash serverPriv;
  serverPriv.fill(0xAA);

  ces::KeyPair testKey;
  std::string testPubHex = testKey.getPublicKeyHexStr();
  std::string testWalletHex = "00" + testKey.getPrivateKeyHexStr();

  // Second key to receive a transfer
  ces::KeyPair destKey;
  std::string destPubHex = destKey.getPublicKeyHexStr();

  // Write minimal TOML config
  std::string tomlPath = (tempDir / "test.toml").string();
  {
    std::ofstream f(tomlPath);
    f << "data_dir = \"" << (tempDir / "data").string() << "\"\n"
      << "server_key = \"" << minx::hashToString(serverPriv) << "\"\n"
      << "port = 0\n"
      << "min_difficulty = 1\n"
      << "min_accounts = 100\n"
      << "max_accounts = 10000\n"
      << "min_assets = 100\n"
      << "max_assets = 10000\n"
      << "flush_value = 999999999999999\n"
      << "no_pow_engine = true\n"
      << "fee_account = 0\n"
      << "fee_asset = 0\n"
      << "fee_tx = 0\n"
      << "fee_query = 0\n";
  }

  // Credit the test account offline
  uint64_t initialCredit = 10'000'000'000ULL;
  {
    std::string creditCmd = cesBin + " --config " + tomlPath + " credit " +
                            std::to_string(initialCredit) + " " + testPubHex;
    BOOST_TEST_MESSAGE("Running: " + creditCmd);
    auto r = run(creditCmd);
    BOOST_TEST_MESSAGE("credit exit=" + std::to_string(r.exitCode) +
                       " out: " + r.out);
    BOOST_REQUIRE_EQUAL(r.exitCode, 0);
  }

  // Helper: start ces and extract the bound port from the log
  std::string logPath = (tempDir / "ces.log").string();
  auto startServer = [&]() -> std::pair<pid_t, uint16_t> {
    { std::ofstream(logPath, std::ios::trunc); }
    std::string cmd = cesBin + " --config " + tomlPath +
                      " -l info > " + logPath + " 2>&1 & echo $!";
    auto r = run(cmd);
    BOOST_REQUIRE_EQUAL(r.exitCode, 0);
    pid_t pid = std::stoi(r.out);
    BOOST_TEST_MESSAGE("Started ces pid=" + std::to_string(pid));

    // Poll log for "boundPort" followed by a port number.
    // Boost.Log inserts ANSI color codes, so we strip them first.
    uint16_t port = 0;
    std::regex ansiRe("\\x1b\\[[0-9;]*m");
    std::regex portRe("boundPort=(\\d+)");
    for (int i = 0; i < 100 && port == 0; ++i) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      std::ifstream logFile(logPath);
      std::string line;
      while (std::getline(logFile, line)) {
        std::string clean = std::regex_replace(line, ansiRe, "");
        std::smatch m;
        if (std::regex_search(clean, m, portRe))
          port = static_cast<uint16_t>(std::stoi(m[1].str()));
      }
    }
    BOOST_REQUIRE_MESSAGE(port > 0, "Server did not report bound port");
    BOOST_TEST_MESSAGE("Server bound to port " + std::to_string(port));
    return {pid, port};
  };

  // Helper: query balance via cesh
  auto queryBalance = [&](uint16_t port) -> int64_t {
    std::string cmd = "CESH_WALLET=\"" + testWalletHex + "\" " +
                      ceshBin + " --server localhost:" +
                      std::to_string(port) + " -l fatal query " + testPubHex;
    auto r = run(cmd);
    BOOST_REQUIRE_EQUAL(r.exitCode, 0);
    std::regex balRe("Balance:\\s+(\\d+)");
    std::smatch m;
    BOOST_REQUIRE_MESSAGE(std::regex_search(r.out, m, balRe),
                          "Could not parse balance from: " + r.out);
    return std::stoll(m[1].str());
  };

  // Helper: wait for server to respond to queries
  auto waitReady = [&](uint16_t port) {
    for (int i = 0; i < 50; ++i) {
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
      auto r = run(ceshBin + " --server localhost:" + std::to_string(port) +
                   " -l fatal query " + testPubHex);
      if (r.exitCode == 0) return;
    }
    BOOST_FAIL("Server not responsive on port " + std::to_string(port));
  };

  // Helper: SIGTERM a process and wait for exit
  auto killAndWait = [](pid_t pid) {
    kill(pid, SIGTERM);
    for (int i = 0; i < 100; ++i) {
      if (kill(pid, 0) != 0) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    BOOST_REQUIRE_MESSAGE(kill(pid, 0) != 0,
                          "Process did not exit after SIGTERM");
    waitpid(pid, nullptr, WNOHANG);
  };

  // --- Phase 1: start, transfer, verify ---
  auto [pid1, port1] = startServer();
  waitReady(port1);

  int64_t bal1 = queryBalance(port1);
  BOOST_CHECK_EQUAL(bal1, static_cast<int64_t>(initialCredit));
  BOOST_TEST_MESSAGE("Initial balance: " + std::to_string(bal1));

  // Open transfer to change in-RAM state
  {
    std::string cmd = "CESH_WALLET=\"" + testWalletHex + "\" " +
                      ceshBin + " --server localhost:" +
                      std::to_string(port1) +
                      " -l fatal -a @0 transfer " + destPubHex +
                      " 1000000000 --open";
    auto r = run(cmd);
    BOOST_REQUIRE_EQUAL(r.exitCode, 0);
    BOOST_TEST_MESSAGE("Transfer: " + r.out);
  }

  int64_t bal2 = queryBalance(port1);
  BOOST_TEST_MESSAGE("Post-transfer balance: " + std::to_string(bal2));
  BOOST_CHECK(bal2 < bal1);

  // --- Phase 2: SIGTERM, restart, verify data survived ---
  BOOST_TEST_MESSAGE("Sending SIGTERM...");
  killAndWait(pid1);
  BOOST_TEST_MESSAGE("Server exited. Restarting...");

  auto [pid2, port2] = startServer();
  waitReady(port2);

  int64_t bal3 = queryBalance(port2);
  BOOST_TEST_MESSAGE("Post-restart balance: " + std::to_string(bal3));
  BOOST_CHECK_EQUAL(bal3, bal2);

  // --- Phase 3: SIGTERM again, snapshot offline, restart, verify ---
  BOOST_TEST_MESSAGE("Sending SIGTERM (2nd)...");
  killAndWait(pid2);

  // Run snapshot command to absorb events into a snapshot
  {
    auto r = run(cesBin + " --config " + tomlPath + " snapshot");
    BOOST_TEST_MESSAGE("snapshot: " + r.out);
    BOOST_REQUIRE_EQUAL(r.exitCode, 0);
  }

  // Verify snapshot files exist and no non-empty event files remain
  for (const char* store : {"accounts", "assets"}) {
    fs::path storeDir = tempDir / "data" / store;
    bool hasSnapshot = false;
    bool hasNonEmptyEvents = false;
    for (auto& entry : fs::directory_iterator(storeDir)) {
      auto ext = entry.path().extension().string();
      auto size = fs::file_size(entry.path());
      BOOST_TEST_MESSAGE(std::string(store) + ": " +
        entry.path().filename().string() + " (" + std::to_string(size) + "B)");
      if (ext == ".snapshot")
        hasSnapshot = true;
      if (ext == ".events" && size > 0)
        hasNonEmptyEvents = true;
    }
    BOOST_CHECK_MESSAGE(hasSnapshot,
      std::string(store) + ": snapshot file missing");
    BOOST_CHECK_MESSAGE(!hasNonEmptyEvents,
      std::string(store) + ": non-empty event files remain after snapshot");
  }
  // Accounts snapshot must be non-empty (we have accounts in this test)
  {
    fs::path accDir = tempDir / "data" / "accounts";
    for (auto& entry : fs::directory_iterator(accDir)) {
      if (entry.path().extension() == ".snapshot")
        BOOST_CHECK_MESSAGE(fs::file_size(entry.path()) > 0,
          "accounts snapshot is empty but should contain data");
    }
  }

  // Restart and verify data survived the snapshot cycle
  auto [pid3, port3] = startServer();
  waitReady(port3);

  int64_t bal4 = queryBalance(port3);
  BOOST_TEST_MESSAGE("Post-snapshot-restart balance: " + std::to_string(bal4));
  BOOST_CHECK_EQUAL(bal4, bal2);

  // Cleanup
  killAndWait(pid3);
  boost::system::error_code ec;
  fs::remove_all(tempDir, ec);
}

BOOST_AUTO_TEST_CASE(CescoLiveSnapshot) {
  std::string cesBin = findCesBinary();
  std::string ceshBin = findCeshBinary();
  auto tempDir = makeUniqueTempDir("cesco_e2e");

  minx::Hash serverPriv;
  serverPriv.fill(0xBB);

  ces::KeyPair testKey;
  std::string testPubHex = testKey.getPublicKeyHexStr();
  std::string testWalletHex = "00" + testKey.getPrivateKeyHexStr();

  std::string sockPath = (tempDir / "admin.sock").string();

  // Write TOML config with admin_socket enabled
  std::string tomlPath = (tempDir / "test.toml").string();
  {
    std::ofstream f(tomlPath);
    f << "data_dir = \"" << (tempDir / "data").string() << "\"\n"
      << "server_key = \"" << minx::hashToString(serverPriv) << "\"\n"
      << "port = 0\n"
      << "min_difficulty = 1\n"
      << "min_accounts = 100\n"
      << "max_accounts = 10000\n"
      << "min_assets = 100\n"
      << "max_assets = 10000\n"
      << "flush_value = 999999999999999\n"
      << "no_pow_engine = true\n"
      << "fee_account = 0\n"
      << "fee_asset = 0\n"
      << "fee_tx = 0\n"
      << "fee_query = 0\n"
      << "admin_socket = \"" << sockPath << "\"\n";
  }

  // Credit an account offline
  uint64_t initialCredit = 5'000'000'000ULL;
  {
    auto r = run(cesBin + " --config " + tomlPath + " credit " +
                 std::to_string(initialCredit) + " " + testPubHex);
    BOOST_REQUIRE_EQUAL(r.exitCode, 0);
  }

  // Start server
  std::string logPath = (tempDir / "ces.log").string();
  auto startCesco = [&]() -> pid_t {
    { std::ofstream(logPath, std::ios::trunc); }
    std::string cmd = cesBin + " --config " + tomlPath +
                      " -l info > " + logPath + " 2>&1 & echo $!";
    auto r = run(cmd);
    BOOST_REQUIRE_EQUAL(r.exitCode, 0);
    return std::stoi(r.out);
  };

  pid_t pid = startCesco();
  BOOST_TEST_MESSAGE("Started ces pid=" + std::to_string(pid));

  // Wait for admin socket to appear
  bool sockReady = false;
  for (int i = 0; i < 100 && !sockReady; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    sockReady = fs::exists(sockPath);
  }
  BOOST_REQUIRE_MESSAGE(sockReady, "Admin socket did not appear: " + sockPath);

  // Send "snapshot" via the admin socket using socat
  {
    auto r = run("echo 'snapshot' | socat - UNIX-CONNECT:" + sockPath);
    BOOST_TEST_MESSAGE("cesco snapshot: " + r.out);
    BOOST_CHECK_EQUAL(r.exitCode, 0);
    assertContains(r.out, "Snapshot");
  }

  // Give the async forkSave a moment to complete
  std::this_thread::sleep_for(std::chrono::milliseconds(500));

  // Verify snapshot files exist for accounts
  {
    fs::path accDir = tempDir / "data" / "accounts";
    bool hasSnapshot = false;
    for (auto& entry : fs::directory_iterator(accDir)) {
      if (entry.path().extension() == ".snapshot" &&
          fs::file_size(entry.path()) > 0)
        hasSnapshot = true;
    }
    BOOST_CHECK_MESSAGE(hasSnapshot,
      "No non-empty accounts snapshot after cesco snapshot command");
  }

  // Send "help" and verify response
  {
    auto r = run("echo 'h' | socat - UNIX-CONNECT:" + sockPath);
    BOOST_TEST_MESSAGE("cesco help: " + r.out);
    BOOST_CHECK_EQUAL(r.exitCode, 0);
    assertContains(r.out, "snapshot");
    assertContains(r.out, "help");
    assertContains(r.out, "quit");
  }

  // Send "quit" and verify clean disconnect
  {
    auto r = run("echo 'quit' | socat - UNIX-CONNECT:" + sockPath);
    BOOST_TEST_MESSAGE("cesco quit: " + r.out);
    BOOST_CHECK_EQUAL(r.exitCode, 0);
    assertContains(r.out, "bye");
  }

  // Ctrl+D (EOT, 0x04) takes the other close path and must flush "bye" too
  {
    auto r = run("printf '\\004' | socat - UNIX-CONNECT:" + sockPath);
    BOOST_TEST_MESSAGE("cesco eot: " + r.out);
    BOOST_CHECK_EQUAL(r.exitCode, 0);
    assertContains(r.out, "bye");
  }

  // Cleanup
  kill(pid, SIGTERM);
  for (int i = 0; i < 100; ++i) {
    if (kill(pid, 0) != 0) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  waitpid(pid, nullptr, WNOHANG);

  boost::system::error_code ec2;
  fs::remove_all(tempDir, ec2);
}

BOOST_AUTO_TEST_SUITE_END()

// ===========================================================================
// L2 file data-pipe (CesPlex + file store enabled): the file-scope gateway
// path — `file get` streams raw bytes to stdout, `-q file stat` is JSON only.
// ===========================================================================

struct RpcFileE2EFixture {
  std::unique_ptr<CesServer> server;
  fs::path tempDir;
  uint16_t serverPort = 0;
  uint16_t rpcPort = 0;
  std::string ceshBin;
  KeyPair fundedKey;
  std::string fundedWalletHex;

  RpcFileE2EFixture() {
    blog::init();
    blog::set_level(blog::fatal);
    tempDir = makeUniqueTempDir("cesh_file_e2e");
    minx::Hash serverPriv;
    serverPriv.fill(0xEE);
    CesConfig cfg = makeTestConfig(tempDir, serverPriv,
                                   std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = {{"/ces/file/1", "builtin:file"}};
    cfg.cesFileStoreMaxBytes = 16ull * 1024 * 1024;
    cfg.feeFileRent = 1;
    server = std::make_unique<CesServer>(cfg);
    serverPort = server->start(0);
    BOOST_REQUIRE_MESSAGE(serverPort > 0, "server bind failed");
    rpcPort = server->_rpcBoundPort();
    BOOST_REQUIRE_MESSAGE(rpcPort > 0, "rpc bind failed");
    ceshBin = findCeshBinary();
    fundedWalletHex = "00" + fundedKey.getPrivateKeyHexStr();
    server->_brr(fundedKey.getPublicKeyAsHash(), 10'000'000'000);
    wait_net();
  }

  ~RpcFileE2EFixture() {
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }

  std::string cmd(const std::string& args) const {
    return "cd " + tempDir.string() + " && " +
           ceshCmd(serverPort, fundedWalletHex, ceshBin) +
           " --rpc-port " + std::to_string(rpcPort) + " " + args;
  }
};

BOOST_FIXTURE_TEST_SUITE(CeshFilePipeE2E, RpcFileE2EFixture)

BOOST_AUTO_TEST_CASE(FileGetStreamsRawBytesToStdout) {
  const std::string body = "<html><body>hi ces</body></html>";
  {
    std::ofstream f((tempDir / "src.html").string(), std::ios::binary);
    f << body;
  }
  auto put = run(cmd("file put src.html /p/test.html --deposit 1000000"));
  BOOST_REQUIRE_MESSAGE(put.exitCode == 0, "put failed: " << put.out);

  // No local path → raw bytes to stdout, and ONLY those bytes (no chrome).
  auto get = run(cmd("file get /p/test.html"));
  BOOST_CHECK_EQUAL(get.exitCode, 0);
  BOOST_CHECK_EQUAL(get.out.size(), body.size());
  assertContains(get.out, body);
  assertNotContains(get.out, "===", "file get to stdout must be data-only");
  assertNotContains(get.out, "Downloaded", "no human chrome on stdout");
}

BOOST_AUTO_TEST_CASE(FileStatQuietIsJsonOnly) {
  const std::string body = "abcdef";
  {
    std::ofstream f((tempDir / "s.bin").string(), std::ios::binary);
    f << body;
  }
  BOOST_REQUIRE_EQUAL(
    run(cmd("file put s.bin /p/s.bin --deposit 1000000")).exitCode, 0);

  auto st = run(cmd("-q file stat /p/s.bin"));
  BOOST_CHECK_EQUAL(st.exitCode, 0);
  assertContains(st.out, "\"size\":6");
  assertContains(st.out, "\"pricePerKb\":");
  assertNotContains(st.out, "===", "quiet stat must be JSON only");
}

BOOST_AUTO_TEST_SUITE_END()
