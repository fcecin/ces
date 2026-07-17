// E2E: the shipped /s/dice2.lua paid via SYS_L2_CALL. Deploys dice2.lua,
// launches it, funds the house, and fires paid bets -- a gateway VM program
// issues SYS_L2_CALL at the instance's pid with value = bet and payload = the
// better's pubkey. Each round the house settles to exactly +bet (tails) or
// -bet (heads, 2x paid out); both outcomes must occur cleanly and the house
// conserves. This is the practical proof that SYS_L2_CALL carries a payment,
// routes into on_l2call, and the winnings transfer back out.
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
#include <ces/l2/file_client.h>
#include <ces/l2/file_handler.h>       // FileHandler::readProgramPubkey
#include <ces/util/vmprogram.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
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

// Read the shipped dice2.lua so the test pins the real program. CES_SOURCE_DIR
// is the repo root (set by tests/CMakeLists.txt).
std::string slurpDice2() {
  std::string path = std::string(CES_SOURCE_DIR) + "/extensions/dice2.lua";
  std::ifstream f(path, std::ios::binary);
  BOOST_REQUIRE_MESSAGE(f.good(), "cannot open dice2.lua at " + path);
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

// Test-only gateway VM program (the "tiny caller AI can write"): SYS_L2_CALL at
// builtin:compute, blob = the run input [u64 pid BE], `value` baked. The pid
// picks the target instance. Copies S to output[0].
AssetData buildDiceGateway(uint64_t value) {
  VmProgram pgm;
  const uint64_t DISC_CELL = 32, FU_CELL = 40;
  auto disc = discOf("builtin:compute");
  pgm.writeBytesToIo(DISC_CELL, disc.data(), 8);
  pgm.hostv(SYS_L2_CALL, {
    Imm(DISC_CELL), Imm(value), Imm(CESVM_IO_INPUT), Imm(8),
    Imm(FU_CELL), Imm(0), Imm(0),
  });
  pgm.set(Imm(CESVM_IO_OUTPUT_LEN), Imm(1));
  pgm.stb(Imm(CESVM_IO_OUTPUT * 8), Ref(CESVM_CELL_S));
  pgm.term();
  return pgm.buildBootBlock();
}

struct Dice2Fixture {
  fs::path dir;
  std::unique_ptr<CesServer> server;
  std::unique_ptr<CesClient> client;
  uint16_t mainPort = 0, rpcPort = 0;
  KeyPair ownerKey;

  Dice2Fixture() {
    blog::init();
    blog::set_level(blog::fatal);
    dir = makeUniqueTempDir("dice2");
    minx::Hash priv;
    priv.fill(0xD2);
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
  ~Dice2Fixture() {
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
  int64_t balanceOf(const minx::Hash& h) {
    int64_t bal = 0;
    uint32_t nonce = 0;
    client->queryAccount(Account::getMapKey(h), bal, nonce);
    return bal;
  }
};

const uint64_t BET = 1'000'000;

}  // namespace

BOOST_FIXTURE_TEST_SUITE(Dice2E2ETests, Dice2Fixture)

BOOST_AUTO_TEST_CASE(PaysBothOutcomesAndConserves) {
  std::string path = "/h/" + hexOf(ownerKey.getPublicKeyAsHash()) + "/dice2.lua";
  auto housePk = deploy(path, slurpDice2());
  uint64_t pid = launch(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));  // child boot

  minx::Hash houseH;
  std::memcpy(houseH.data(), housePk.data(), 32);
  minx::Hash betterH = ownerKey.getPublicKeyAsHash();

  const int64_t bankroll = 500 * (int64_t)BET;
  server->_brr(houseH, bankroll);   // cover 2x the bet many times over

  // One gateway asset fires the paid call; the [mode][pid] blob rides the input.
  minx::Hash gwKey;
  gwKey.fill(0);
  gwKey[0] = 0xD2;
  gwKey[1] = 0xCE;
  CES_REQUIRE_OK(client->createAsset(gwKey, buildDiceGateway(BET), 1));

  ces::Bytes input(8, 0);   // blob = [u64 pid BE]
  for (int i = 0; i < 8; ++i) input[i] = uint8_t((pid >> (56 - 8 * i)) & 0xFF);

  int heads = 0, tails = 0;
  int64_t housePrev = balanceOf(houseH);
  int64_t betterStart = balanceOf(betterH);

  const int N = 24;
  for (int r = 0; r < N; ++r) {
    uint64_t vmErr = 0, used = 0;
    ces::Bytes out;
    uint8_t rc = client->runAsset(gwKey, 10'000'000, input, vmErr, used, out);
    BOOST_REQUIRE_EQUAL(rc, CES_OK);
    BOOST_REQUIRE_EQUAL(vmErr, CESVM_OK);
    BOOST_REQUIRE(!out.empty());
    BOOST_REQUIRE_EQUAL(out[0], CES_OK);   // accepted synchronously => burned

    // Delivery always mints +bet into the house. A tails ends there; a heads
    // then pays 2*bet + feeTx back out, so it transiently visits +bet before
    // settling below the start. Wait for the balance to stop moving, then
    // classify by direction so a pending payout is not mistaken for a tails.
    bool ok = false, moved = false;
    int64_t settled = housePrev, last = housePrev, stable = 0;
    for (int i = 0; i < 200; ++i) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      int64_t cur = balanceOf(houseH);
      if (cur != housePrev) moved = true;
      if (cur == last) ++stable; else { stable = 0; last = cur; }
      if (moved && stable >= 10) { settled = cur; ok = true; break; }
    }
    BOOST_REQUIRE_MESSAGE(ok, "round " << r << ": house did not settle"
                              << " (prev=" << housePrev << " last=" << last << ")");
    int64_t d = settled - housePrev;
    if (d > 0) {
      BOOST_CHECK_EQUAL(d, (int64_t)BET);   // tails: exactly the bet, minted in
      ++tails;
    } else {
      BOOST_CHECK_LT(d, 0);                 // heads: 2x paid out -> net down
      ++heads;
    }
    housePrev = settled;
  }

  BOOST_TEST_MESSAGE("dice2 over " << N << " rounds: heads=" << heads
                     << " tails=" << tails);

  // Both branches must execute cleanly; with 24 fair flips both are ~certain.
  BOOST_CHECK_GT(heads, 0);
  BOOST_CHECK_GT(tails, 0);

  // The winnings reached the better: had every round lost, the better would be
  // down N*bet; heads payouts put money back, so the net loss is strictly less.
  int64_t betterNet = balanceOf(betterH) - betterStart;
  BOOST_CHECK_GT(betterNet, -(int64_t)N * (int64_t)BET);
}

BOOST_AUTO_TEST_SUITE_END()
