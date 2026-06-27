// test_ext_common.h -- shared harness for in-process Boost smoke tests of the
// shipped /s/ extensions (discovery, peerfunder, ...). Each test stands up real
// rpc-enabled CesServers running the real cesluajitd child, deploys an extension
// from extensions/<name>.lua via the production loader (cfg.extensions + a /s/
// drop), and asserts on ground-truth server state. These are smoke tests: enough
// to catch fundamental breakage (the extension launches, runs, and does its core
// job), not the exhaustive coverage a dedicated suite would add.

#pragma once

#include "test_common.h"
#include "test_e2e_common.h"   // ces::e2e::findBinary

#include <ces/account.h>
#include <ces/keys.h>
#include <ces/server.h>

#include <boost/asio/ip/address.hpp>
#include <boost/test/unit_test.hpp>

#include <chrono>
#include <fstream>
#include <memory>
#include <set>
#include <string>
#include <thread>

namespace ces {
namespace exttest {

struct ExtNode {
  fs::path dir;
  std::unique_ptr<CesServer> server;
  uint16_t mainPort = 0;
  uint16_t rpcPort = 0;
  minx::Hash pub;
};

inline std::string readExtSource(const std::string& name) {
  const std::string path =
    std::string(CES_SOURCE_DIR) + "/extensions/" + name + ".lua";
  std::ifstream f(path, std::ios::binary);
  BOOST_REQUIRE_MESSAGE(f.good(), "cannot open extension " + path);
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

inline void writeFile(const fs::path& p, const std::string& content) {
  fs::create_directories(p.parent_path());
  std::ofstream f(p, std::ios::binary | std::ios::trunc);
  f << content;
}

// Bring up a node running extension `name` (deployed from extensions/<name>.lua)
// with the given /s/<name>.conf contents. Full L2 stack + real cesluajitd. Pass
// name="" to start a plain server (e.g. a ping/peer target with no extension).
// computePorts > 0 leases the instance a UDP port range so it can do outbound
// client networking (ces.ping / ces.file_client); 0 = local-only (no ports).
inline void startExtNode(ExtNode& n, int idx, const std::string& childBin,
                         const std::string& name, const std::string& conf,
                         uint16_t computePorts = 0) {
  n.dir = makeUniqueTempDir("ext_" + std::to_string(idx));
  minx::Hash priv;
  priv.fill(static_cast<uint8_t>(0x41 + idx));

  CesConfig cfg =
    makeTestConfig(n.dir, priv, std::numeric_limits<uint64_t>::max());
  cfg.rpcPort = 0;
  cfg.rpcAutoPort = true;
  cfg.cesplexMounts = {
    {"/ces/file/1",    "builtin:file"},
    {"/ces/compute/1", "builtin:compute"},
    {"/ces/lua/1",     "builtin:lua"},
    {"/ces/peer/1",    "builtin:peer"},
  };
  cfg.cesFileStoreDir = (n.dir / "cesfilestore").string();
  cfg.cesFileStoreMaxBytes = 64ull * 1024 * 1024;
  cfg.feeFileRent = 0;
  cfg.feeFileWrite = 0;
  cfg.feeFileRead = 0;
  cfg.feeQuery = 0;
  cfg.feeDiscountEnabled = false;
  cfg.computeMaxInstances = 4;
  cfg.feeComputeSlotSec = 0;
  if (computePorts > 0) {
    cfg.computePortBase = findFreeUdpPortRange(computePorts);
    cfg.computePortCount = computePorts;
  } else {
    cfg.computePortBase = 0;
    cfg.computePortCount = 0;
  }
  cfg.cesComputeChildBinary = childBin;
  cfg.cesComputeWorkDir = (n.dir / "cescompute").string();

  if (!name.empty()) {
    cfg.extensions = { name };
    writeFile(fs::path(cfg.cesFileStoreDir) / "s" / (name + ".lua"),
              readExtSource(name));
    writeFile(fs::path(cfg.cesFileStoreDir) / "s" / (name + ".conf"), conf);
  }

  n.server = std::make_unique<CesServer>(cfg);
  n.mainPort = n.server->start(0);
  BOOST_REQUIRE_MESSAGE(n.mainPort > 0, "node " << idx << " main bind failed");
  n.rpcPort = n.server->_rpcBoundPort();
  BOOST_REQUIRE_MESSAGE(n.rpcPort > 0, "node " << idx << " rpc bind failed");
  n.pub = n.server->_serverKeyPair().getPublicKeyAsHash();
}

inline std::set<minx::Hash> peerSet(CesServer* s) {
  std::set<minx::Hash> out;
  for (const auto& p : s->_peerSnapshot()) out.insert(p.ckey);
  return out;
}

inline int64_t balanceOnLedger(CesServer* s, const minx::Hash& pubkey) {
  int64_t bal = 0;
  uint32_t nonce = 0;
  uint64_t lastAmt = 0;
  uint32_t lastTime = 0;
  HashPrefix dest{};
  s->unsignedQueryAccount(Account::getMapKey(pubkey), bal, nonce, dest,
                          lastAmt, lastTime);
  return bal;
}

inline void stopExt(ExtNode& n) {
  if (n.server) n.server->stop();
  std::this_thread::sleep_for(std::chrono::milliseconds(120));
  boost::system::error_code ec;
  fs::remove_all(n.dir, ec);
}

}  // namespace exttest
}  // namespace ces
