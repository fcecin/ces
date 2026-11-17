// The fixture of test_loadable.cpp and test_vs1.cpp, a server with the file,
// compute and lua mounts and the real cesluajitd.

#pragma once

#include "test_common.h"
#include "test_compute_wait.h"
#include "test_e2e_common.h"

#include <ces/keys.h>
#include <ces/l2/compute_client.h>
#include <ces/l2/file_client.h>
#include <ces/server.h>

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <fstream>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <thread>

namespace ces::loadtest {

inline std::string readBytes(const fs::path& p) {
  std::ifstream f(p.string(), std::ios::binary);
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

inline void writeBytes(const fs::path& p, const std::string& bytes) {
  fs::create_directories(p.parent_path());
  std::ofstream f(p.string(), std::ios::binary | std::ios::trunc);
  f.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

struct LoadableFixture {
  std::unique_ptr<CesServer> server;
  fs::path tempDir;
  uint16_t rpcPort = 0;
  minx::Hash serverPriv;
  KeyPair serverKey;   // signs as the server, for files in /s/
  KeyPair ownerKey;    // owns the programs
  int dials = 0;

  LoadableFixture()
      : serverPriv([] { minx::Hash h; h.fill(0xD7); return h; }()),
        serverKey(serverPriv) {
    blog::init();
    blog::set_level(blog::fatal);
    blog::set_level("plex", blog::fatal);
    tempDir = makeUniqueTempDir("loadable");

    CesConfig cfg = makeTestConfig(tempDir, serverPriv, std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = {
      {"/ces/file/1",    "builtin:file"},
      {"/ces/compute/1", "builtin:compute"},
      {"/ces/lua/1",     "builtin:lua"},
    };
    cfg.cesFileStoreMaxBytes = 16ull * 1024 * 1024;
    cfg.feeFileRent = 1;
    cfg.computeMaxInstances = 8;
    cfg.feeComputeSlotSec = 1;
    cfg.cesComputeChildBinary = ces::e2e::findBinary("cesluajitd");
    cfg.cesComputeUser = "";
    cfg.cesComputeWorkDir = (tempDir / "cescompute").string();

    server = std::make_unique<CesServer>(cfg);
    BOOST_REQUIRE(server->start(0) > 0);
    rpcPort = server->_rpcBoundPort();
    BOOST_REQUIRE(rpcPort > 0);
    server->_brr(ownerKey.getPublicKeyAsHash(), 10'000'000'000);
    server->_brr(serverKey.getPublicKeyAsHash(), 10'000'000'000);
  }

  ~LoadableFixture() {
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }

  fs::path storeDir() const { return fs::path(server->_config().cesFileStoreDir); }

  fs::path treeFile(const std::string& rel) const {
    return storeDir() / "s" / "loadables" / rel;
  }

  void deploy(const std::string& rel, const std::string& text) {
    writeBytes(treeFile(rel), text);
  }

  void deployFromRepo(const std::string& rel) {
    const fs::path src = fs::path(CES_SOURCE_DIR) / "loadables" / rel;
    BOOST_REQUIRE_MESSAGE(fs::exists(src), "no " << src.string());
    deploy(rel, readBytes(src));
  }

  std::unique_ptr<CesFileClient> fileClient(const KeyPair& signer) {
    auto fc = std::make_unique<CesFileClient>();
    fc->setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(fc->connect("localhost", rpcPort, signer));
    return fc;
  }

  uint64_t launch(const std::string& name, const std::string& src) {
    const std::string path = "/h/" + ownerKey.getPublicKeyHexStr() + "/" + name;
    auto fc = fileClient(ownerKey);
    uint64_t bal = 0, cost = 0;
    CES_REQUIRE_OK(fc->create(path, src.size(), 0, 100'000'000ULL, bal, cost));
    CES_REQUIRE_OK(fc->write(path, 0, ces::Bytes(src.begin(), src.end()), bal));
    fc->disconnect();
    CesComputeClient cc;
    cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));
    uint64_t pid = 0, startedAt = 0;
    CES_REQUIRE_OK(cc.launch(path, pid, startedAt));
    cc.disconnect();
    BOOST_REQUIRE(pid > 0);
    return pid;
  }

  void kill(uint64_t pid) {
    CesComputeClient cc;
    cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));
    CES_REQUIRE_OK(cc.kill(pid));
    cc.disconnect();
  }

  // What a dial of `pid` gets after it sends `in`. Files carry the bytes,
  // since runShell reads text.
  std::string dial(uint64_t pid, const std::string& in = "", int secs = 4) {
    const std::string n = std::to_string(++dials);
    const fs::path inFile = tempDir / ("dial" + n + ".in");
    const fs::path outFile = tempDir / ("dial" + n + ".out");
    writeBytes(inFile, in);
    ces::e2e::runShell("CESH_WALLET=00" + ownerKey.getPrivateKeyHexStr() + " timeout -k 1 " +
                       std::to_string(secs) + " " + ces::e2e::findCeshBinary() +
                       " -l fatal --server localhost --rpc-port " + std::to_string(rpcPort) +
                       " dial " + std::to_string(pid) + " < " + inFile.string() + " > " +
                       outFile.string(), 30);
    return readBytes(outFile);
  }
};

}  // namespace ces::loadtest
