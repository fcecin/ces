// SYS_L2_CALL end-to-end through builtin:compute into a LIVE cesluajitd
// instance's on_l2call. Deploys a Lua program that defines on_l2call, launches
// it, fires SYS_L2_CALL from a gateway VM program at its pid, and asserts the
// delivery settles `value` into the instance's program account. A second case
// proves a program without on_l2call refunds (its account stays uncredited).
//
// Real child process (needs the cesluajitd binary), so this is an E2E suite.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"
#include "test_e2e_common.h"   // ces::e2e::findBinary

#include <ces/account.h>
#include <ces/buffer.h>
#include <ces/cesvm.h>
#include <ces/client.h>
#include <ces/keys.h>
#include <ces/ramfilestore.h>          // ces::sha256
#include <ces/server.h>
#include <ces/l2/compute_client.h>
#include <ces/l2/compute_handler.h>
#include <ces/l2/file_client.h>
#include <ces/l2/file_handler.h>       // FileHandler::readProgramPubkey
#include <ces/util/vmprogram.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>

using namespace ces;

namespace {

std::array<uint8_t, 8> discOf(const std::string& name) {
  minx::Hash h =
    ces::sha256(reinterpret_cast<const uint8_t*>(name.data()), name.size());
  std::array<uint8_t, 8> d{};
  std::memcpy(d.data(), h.data(), 8);
  return d;
}

std::string hexOf(const minx::Hash& k) {
  static const char* H = "0123456789abcdef";
  std::string s;
  s.reserve(64);
  for (uint8_t b : k) { s.push_back(H[b >> 4]); s.push_back(H[b & 0xF]); }
  return s;
}

// Gateway VM program: SYS_L2_CALL at builtin:compute with blob = [u64 pid BE]
// (empty payload), `value` baked in, fire-and-forget. Copies S to output[0].
AssetData buildComputeL2CallProgram(uint64_t value, uint64_t pid) {
  VmProgram pgm;
  const uint64_t DISC_CELL = 32, BLOB_CELL = 40, FU_CELL = 48;
  auto disc = discOf("builtin:compute");
  pgm.writeBytesToIo(DISC_CELL, disc.data(), 8);
  uint8_t blob[9];
  blob[0] = 0;   // mode 0 = address by pid
  for (int i = 0; i < 8; ++i) blob[1 + i] = uint8_t((pid >> (56 - 8 * i)) & 0xFF);
  pgm.writeBytesToIo(BLOB_CELL, blob, 9);   // [mode=0][pid BE]
  pgm.hostv(SYS_L2_CALL, {
    Imm(DISC_CELL), Imm(value), Imm(BLOB_CELL), Imm(9),
    Imm(FU_CELL), Imm(0), Imm(0),
  });
  pgm.set(Imm(CESVM_IO_OUTPUT_LEN), Imm(1));
  pgm.stb(Imm(CESVM_IO_OUTPUT * 8), Ref(CESVM_CELL_S));
  pgm.term();
  return pgm.buildBootBlock();
}

struct L2ComputeFixture {
  fs::path dir;
  std::unique_ptr<CesServer> server;
  std::unique_ptr<CesClient> client;
  uint16_t mainPort = 0, rpcPort = 0;
  KeyPair ownerKey;

  L2ComputeFixture() {
    blog::init();
    blog::set_level(blog::fatal);
    dir = makeUniqueTempDir("l2compute");
    minx::Hash priv;
    priv.fill(0xD7);
    CesConfig cfg = makeTestConfig(dir, priv,
                                   std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = {
      {"/ces/file/1", "builtin:file"},
      {"/ces/compute/1", "builtin:compute"},
    };
    cfg.cesFileStoreMaxBytes = 16ull * 1024 * 1024;
    cfg.feeFileRent = 1;
    cfg.computeMaxInstances = 8;
    cfg.computePortBase = findFreeUdpPortRange(16);
    cfg.computePortCount = 16;
    cfg.feeComputeSlotSec = 1;
    cfg.cesComputeChildBinary = ces::e2e::findBinary("cesluajitd");
    cfg.cesComputeWorkDir = (dir / "cescompute").string();
    server = std::make_unique<CesServer>(cfg);
    mainPort = server->start(0);
    rpcPort = server->_rpcBoundPort();
    server->_brr(ownerKey.getPublicKeyAsHash(), 100'000'000'000);
    boost::asio::ip::udp::endpoint ep(
      boost::asio::ip::address_v6::loopback(), mainPort);
    client = std::make_unique<CesClient>(ep, false);
    client->start(0);
    client->setKey(ownerKey);
    client->connect();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
  ~L2ComputeFixture() {
    if (client) client->stop();
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    boost::system::error_code ec;
    fs::remove_all(dir, ec);
  }

  std::array<uint8_t, 32> deploy(const std::string& path,
                                 const std::string& src) {
    CesFileClient fc;
    fc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(fc.connect("localhost", rpcPort, ownerKey));
    uint64_t fb = 0, cost = 0;
    CES_REQUIRE_OK(fc.create(path, src.size(), 0, 10'000'000'000, fb, cost));
    ces::Bytes content(src.begin(), src.end());
    CES_REQUIRE_OK(fc.write(path, 0, content, fb));
    fc.disconnect();
    std::array<uint8_t, 32> pk{};
    BOOST_REQUIRE(server->fileHandler()->readProgramPubkey(path, pk));
    return pk;
  }
  uint64_t launch(const std::string& path) {
    CesComputeClient cc;
    cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));
    uint64_t id = 0, st = 0;
    CES_REQUIRE_OK(cc.launch(path, id, st));
    cc.disconnect();
    return id;
  }
  int64_t balanceOf(const std::array<uint8_t, 32>& pk) {
    minx::Hash h;
    std::memcpy(h.data(), pk.data(), 32);
    int64_t bal = 0;
    uint32_t nonce = 0;
    client->queryAccount(Account::getMapKey(h), bal, nonce);
    return bal;
  }
  // Deploy + run the gateway program that fires SYS_L2_CALL at `pid`. Returns
  // the synchronous S (CES_OK once accepted + burned).
  uint8_t runGateway(uint64_t pid, uint64_t value) {
    minx::Hash gwKey;
    gwKey.fill(0);
    gwKey[0] = 0xB0;
    gwKey[1] = uint8_t(pid);
    AssetData gw = buildComputeL2CallProgram(value, pid);
    CES_REQUIRE_OK(client->createAsset(gwKey, gw, 1));
    uint64_t vmErr = 0, used = 0;
    ces::Bytes out;
    uint8_t rc = client->runAsset(gwKey, 10'000'000, {}, vmErr, used, out);
    BOOST_REQUIRE_EQUAL(rc, CES_OK);
    BOOST_REQUIRE_EQUAL(vmErr, CESVM_OK);
    BOOST_REQUIRE(!out.empty());
    return out[0];
  }
  std::string myHex() { return hexOf(ownerKey.getPublicKeyAsHash()); }
};

const uint64_t V = 1'000'000;

}  // namespace

BOOST_FIXTURE_TEST_SUITE(L2ComputeTests, L2ComputeFixture)

// A live instance that defines on_l2call receives the paid call; the delivery
// settles `value` into its program account.
BOOST_AUTO_TEST_CASE(Delivered_CreditsProgramAccount) {
  std::string path = "/h/" + myHex() + "/svc.lua";
  auto progPk = deploy(path, "function on_l2call(p, c) end\nces.run()\n");
  uint64_t pid = launch(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(800));  // child run loop

  int64_t before = balanceOf(progPk);
  uint8_t s = runGateway(pid, V);
  BOOST_CHECK_EQUAL(s, CES_OK);   // accepted synchronously => value burned

  bool ok = false;
  for (int i = 0; i < 100; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    if (balanceOf(progPk) == before + (int64_t)V) { ok = true; break; }
  }
  BOOST_CHECK_MESSAGE(ok, "program account not credited V; got "
                          << balanceOf(progPk) << " want " << before + (int64_t)V);
}

// A live instance WITHOUT on_l2call acks no-handler; the value is refunded and
// the program account is never credited.
BOOST_AUTO_TEST_CASE(NoHandler_LeavesProgramUncredited) {
  std::string path = "/h/" + myHex() + "/nohandler.lua";
  auto progPk = deploy(path, "ces.run()\n");   // alive, but no on_l2call
  uint64_t pid = launch(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(800));

  int64_t progBefore = balanceOf(progPk);
  uint8_t s = runGateway(pid, V);
  BOOST_CHECK_EQUAL(s, CES_OK);   // instance exists => accepted + burned

  // Give the no-handler ack + refund time to land, then confirm the program
  // account never received the value.
  std::this_thread::sleep_for(std::chrono::milliseconds(1200));
  BOOST_CHECK_EQUAL(balanceOf(progPk), progBefore);
}

BOOST_AUTO_TEST_SUITE_END()
