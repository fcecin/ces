// ===========================================================================
// `cesh compute call` end-to-end — drive the real cesh binary as a subprocess.
// ===========================================================================
//
// In-process server with /ces/file/1, /ces/compute/1 mounted. Uploads a Lua
// program whose on_l2call echoes its memo, launches an instance, then runs
// `cesh compute call <pid> <value> --in ...` as a subprocess and checks the
// reply on stdout (raw, --hex, and --out file) plus the error exit for a dead
// pid. The escrow money path itself is pinned in test_l2call_compute.cpp; this
// is the CLI plumbing.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"
#include "test_e2e_common.h"

#include <ces/l2/compute_client.h>
#include <ces/l2/file_client.h>
#include <ces/cesplex/mux.h>
#include <ces/l2/compute_handler.h>
#include <ces/l2/file_handler.h>
#include <ces/server.h>
#include <ces/keys.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <iterator>
#include <limits>
#include <string>
#include <thread>

using namespace ces;
using namespace ces::e2e;

namespace {

struct CeshComputeFixture {
  std::unique_ptr<CesServer> server;
  fs::path tempDir;
  uint16_t mainPort = 0;
  uint16_t rpcPort = 0;
  std::string ceshBin;
  KeyPair ownerKey;

  CeshComputeFixture() {
    blog::init();
    blog::set_level(blog::fatal);

    tempDir = makeUniqueTempDir("cesh_compute_e2e");
    ceshBin = ces::e2e::findCeshBinary();

    minx::Hash serverPriv;
    serverPriv.fill(0xC1);
    CesConfig cfg = makeTestConfig(
      tempDir, serverPriv, std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = {
      {"/ces/file/1",    "builtin:file"},
      {"/ces/compute/1", "builtin:compute"},
    };
    cfg.cesFileStoreMaxBytes = 16ull * 1024 * 1024;
    cfg.feeFileRent = 1;
    cfg.computeMaxInstances = 4;
    cfg.feeComputeSlotSec = 1;
    cfg.cesComputeChildBinary = ces::e2e::findBinary("cesluajitd");
    cfg.cesComputeUser = "";
    cfg.cesComputeWorkDir = (tempDir / "cescompute").string();

    server = std::make_unique<CesServer>(cfg);
    mainPort = server->start(0);
    BOOST_REQUIRE(mainPort > 0);
    rpcPort = server->_rpcBoundPort();
    BOOST_REQUIRE(rpcPort > 0);
    server->_brr(ownerKey.getPublicKeyAsHash(), 10'000'000'000);
  }

  ~CeshComputeFixture() {
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }

  void uploadScript(const std::string& path, const std::string& source) {
    CesFileClient fc;
    fc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(fc.connect("localhost", rpcPort, ownerKey));
    uint64_t bal = 0, cost = 0;
    CES_REQUIRE_OK(fc.create(path, source.size(), 0, 100'000'000ULL, bal, cost));
    ces::Bytes content(source.begin(), source.end());
    CES_REQUIRE_OK(fc.write(path, 0, content, bal));
    fc.disconnect();
  }

  uint64_t launchScript(const std::string& path) {
    CesComputeClient cc;
    cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));
    uint64_t instId = 0, startedAt = 0;
    CES_REQUIRE_OK(cc.launch(path, instId, startedAt));
    cc.disconnect();
    return instId;
  }

  std::string ownerHex() { return ownerKey.getPublicKeyHexStr(); }

  // `cesh --server localhost --rpc-port <rpc> -l fatal compute call <args>`
  // with the owner wallet inline via CESH_WALLET.
  RunResult ceshCall(const std::string& args) {
    std::string wallet = "00" + ownerKey.getPrivateKeyHexStr();
    std::string cmd = "CESH_WALLET=\"" + wallet + "\" " + ceshBin +
                      " --server localhost:" + std::to_string(mainPort) +
                      " --rpc-port " + std::to_string(rpcPort) +
                      " -l fatal compute call " + args;
    return runShell(cmd);
  }

  // Deploy the memo-echo program and launch it. on_l2call returns "pong:<memo>".
  uint64_t launchEcho(const std::string& leaf) {
    std::string path = "/h/" + ownerHex() + "/" + leaf;
    uploadScript(path,
      "function on_l2call(memo, ctx) return 'pong:'..memo end\nces.run()\n");
    uint64_t pid = launchScript(path);
    std::this_thread::sleep_for(std::chrono::milliseconds(800));  // child loop
    return pid;
  }
};

}  // namespace

BOOST_FIXTURE_TEST_SUITE(CeshComputeE2E, CeshComputeFixture)

// Raw reply on stdout: the program echoes the memo, so the reply is "pong:hi".
BOOST_AUTO_TEST_CASE(CallReplyRaw) {
  uint64_t pid = launchEcho("echo.lua");
  RunResult r = ceshCall(std::to_string(pid) + " 1000000 --in text:hi");
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "pong:hi", "raw reply");
}

// --hex prints the reply as a hex string. hex("pong:hi") = 706f6e673a6869.
BOOST_AUTO_TEST_CASE(CallReplyHex) {
  uint64_t pid = launchEcho("echo_hex.lua");
  RunResult r = ceshCall(std::to_string(pid) + " 0 --in text:hi --hex");
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "706f6e673a6869", "hex reply");
}

// --out writes the raw reply bytes to a file (binary-safe).
BOOST_AUTO_TEST_CASE(CallReplyToFile) {
  uint64_t pid = launchEcho("echo_file.lua");
  std::string outPath = (tempDir / "reply.bin").string();
  RunResult r = ceshCall(std::to_string(pid) + " 0 --in text:hi --out " + outPath);
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  std::ifstream ifs(outPath, std::ios::binary);
  std::string got((std::istreambuf_iterator<char>(ifs)),
                  std::istreambuf_iterator<char>());
  BOOST_CHECK_EQUAL(got, "pong:hi");
}

// Memo assembled from multiple --in tokens in CLI order.
BOOST_AUTO_TEST_CASE(CallMemoComposesInOrder) {
  uint64_t pid = launchEcho("echo_compose.lua");
  RunResult r = ceshCall(std::to_string(pid) + " 0 --in text:ab --in hex:4344");
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  assertContains(r.out, "pong:abCD", "composed memo");  // 0x43 0x44 = "CD"
}

// A dead pid fails the verb with a nonzero exit and a diagnostic on stderr.
BOOST_AUTO_TEST_CASE(CallUnknownPidFails) {
  launchEcho("echo_live.lua");   // a live instance exists, but we call another
  RunResult r = ceshCall("999999 0 --in text:x");
  BOOST_CHECK_NE(r.exitCode, 0);
  assertContains(r.out, "Failed", "error diagnostic");
}

BOOST_AUTO_TEST_SUITE_END()
