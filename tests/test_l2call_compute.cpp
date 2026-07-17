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

#include <algorithm>
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
  uint8_t blob[8];
  for (int i = 0; i < 8; ++i) blob[i] = uint8_t((pid >> (56 - 8 * i)) & 0xFF);
  pgm.writeBytesToIo(BLOB_CELL, blob, 8);   // [pid BE]
  pgm.hostv(SYS_L2_CALL, {
    Imm(DISC_CELL), Imm(value), Imm(BLOB_CELL), Imm(8),
    Imm(FU_CELL), Imm(0), Imm(0),
  });
  pgm.set(Imm(CESVM_IO_OUTPUT_LEN), Imm(1));
  pgm.stb(Imm(CESVM_IO_OUTPUT * 8), Ref(CESVM_CELL_S));
  pgm.term();
  return pgm.buildBootBlock();
}

// INVOKE_L2_RETURN followup program: input is io[INPUT]=tag, io[INPUT+1]=outcome
// (0 delivered, 1 no-handler, 2 timeout). Transfers outcome+1 to `marker`, so a
// delivered resolution credits 1 and a no-handler credits 2 -- both non-zero, so
// firing and the outcome value are observable.
AssetData buildL2Followup(const minx::Hash& marker) {
  VmProgram pgm;
  const uint64_t DEST_CELL = 32, AMT_CELL = 60;
  pgm.writeBytesToIo(DEST_CELL, marker.data(), 32);
  pgm.set(Imm(AMT_CELL), Ref(CESVM_IO_INPUT + 1));   // io[AMT_CELL] = outcome
  pgm.inc(Imm(AMT_CELL));                            // + 1
  pgm.hostv(SYS_TRANSFER, { Imm(DEST_CELL), Ref(AMT_CELL) });   // amount = outcome+1
  pgm.term();
  return pgm.buildBootBlock();
}

// Gateway that fires SYS_L2_CALL with a followup set. The blob and the followup
// key ride the run input: input[0..31] = followup key, input[32..39] =
// [u64 pid BE]. `value`, budget, and tag are baked.
AssetData buildL2CallWithFollowup(uint64_t value, uint64_t budget, uint32_t tag) {
  VmProgram pgm;
  const uint64_t DISC_CELL = 32;
  const uint64_t FU_CELL   = CESVM_IO_INPUT;       // input[0..31]  = followup key
  const uint64_t BLOB_CELL = CESVM_IO_INPUT + 4;   // input[32..39] = [pid]
  auto disc = discOf("builtin:compute");
  pgm.writeBytesToIo(DISC_CELL, disc.data(), 8);
  pgm.hostv(SYS_L2_CALL, {
    Imm(DISC_CELL), Imm(value), Imm(BLOB_CELL), Imm(8),
    Imm(FU_CELL), Imm(budget), Imm(tag),
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
  // Paid CALL verb from a client: charges ownerKey -> the instance program
  // account and returns the on_l2call reply bytes.
  uint8_t callVerb(uint64_t pid, uint64_t amount, const std::string& memo,
                   ces::Bytes& reply) {
    CesComputeClient cc;
    cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));
    ces::Bytes m(memo.begin(), memo.end());
    uint8_t rc = cc.call(pid, amount, m, reply);
    cc.disconnect();
    return rc;
  }
  int64_t balanceOf(const std::array<uint8_t, 32>& pk) {
    minx::Hash h;
    std::memcpy(h.data(), pk.data(), 32);
    int64_t bal = 0;
    uint32_t nonce = 0;
    client->queryAccount(Account::getMapKey(h), bal, nonce);
    return bal;
  }
  int64_t signerBalance() {
    std::array<uint8_t, 32> pk{};
    std::memcpy(pk.data(), ownerKey.getPublicKeyAsHash().data(), 32);
    return balanceOf(pk);
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

// The INVOKE_L2_RETURN followup fires on resolution and receives the outcome: a
// delivered call credits the marker 1 (outcome 0 + 1), then a no-handler call
// credits 2 more (outcome 1 + 1), leaving the marker at 3.
BOOST_AUTO_TEST_CASE(FollowupNotifiesOutcome) {
  std::string okPath = "/h/" + myHex() + "/svc2.lua";
  deploy(okPath, "function on_l2call(p, c) end\nces.run()\n");
  uint64_t pidOk = launch(okPath);
  std::string noPath = "/h/" + myHex() + "/nofu.lua";
  deploy(noPath, "ces.run()\n");
  uint64_t pidNo = launch(noPath);
  std::this_thread::sleep_for(std::chrono::milliseconds(900));

  minx::Hash marker; marker.fill(0); marker[0] = 0xF0; marker[1] = 0x11;
  minx::Hash fuKey;  fuKey.fill(0);  fuKey[0] = 0xF0; fuKey[1] = 0x22;
  CES_REQUIRE_OK(client->createAsset(fuKey, buildL2Followup(marker), 1));
  server->_brr(marker, 1000);   // seed so the payout transfer has a live dest

  auto markerBal = [&]() {
    int64_t b = 0; uint32_t n = 0;
    client->queryAccount(Account::getMapKey(marker), b, n);
    return b;
  };
  auto fireAt = [&](uint64_t pid, uint8_t tag) {
    minx::Hash gwKey; gwKey.fill(0); gwKey[0] = 0xF0; gwKey[1] = 0x33; gwKey[2] = tag;
    CES_REQUIRE_OK(client->createAsset(
      gwKey, buildL2CallWithFollowup(V, 10'000'000, tag), 1));
    ces::Bytes input(40, 0);
    std::memcpy(input.data(), fuKey.data(), 32);
    for (int i = 0; i < 8; ++i) input[32 + i] = uint8_t((pid >> (56 - 8 * i)) & 0xFF);
    uint64_t vmErr = 0, used = 0;
    ces::Bytes out;
    uint8_t rc = client->runAsset(gwKey, 10'000'000, input, vmErr, used, out);
    BOOST_REQUIRE_EQUAL(rc, CES_OK);
    BOOST_REQUIRE_EQUAL(vmErr, CESVM_OK);
    BOOST_REQUIRE(!out.empty());
    BOOST_REQUIRE_EQUAL(out[0], CES_OK);   // SYS_L2_CALL accepted + burned
  };
  auto waitMarker = [&](int64_t want) {
    for (int i = 0; i < 100; ++i) {
      if (markerBal() == want) return true;
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
  };

  fireAt(pidOk, 1);   // delivered -> outcome 0 -> marker += 1
  BOOST_CHECK_MESSAGE(waitMarker(1001),
                      "delivered followup wrong; got " << markerBal());
  fireAt(pidNo, 2);   // no-handler -> outcome 1 -> marker += 2
  BOOST_CHECK_MESSAGE(waitMarker(1003),
                      "no-handler followup wrong; got " << markerBal());
}

// The client-facing CALL verb: a bound client pays a live instance, its
// on_l2call returns bytes, and the reply rides the RUDP channel back. The
// charge (signer -> program account) lands and the reply matches.
BOOST_AUTO_TEST_CASE(CallVerb_Delivered_RepliesAndPays) {
  std::string path = "/h/" + myHex() + "/echo.lua";
  auto progPk = deploy(path,
    "function on_l2call(memo, ctx) return 'pong:'..memo end\nces.run()\n");
  uint64_t pid = launch(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(800));

  int64_t before = balanceOf(progPk);
  ces::Bytes reply;
  uint8_t rc = callVerb(pid, V, "hi", reply);
  BOOST_CHECK_EQUAL(rc, CES_OK);
  std::string rs(reply.begin(), reply.end());
  BOOST_CHECK_EQUAL(rs, "pong:hi");
  BOOST_CHECK_EQUAL(balanceOf(progPk), before + (int64_t)V);
}

// A CALL into a live instance WITHOUT on_l2call fails the verb and refunds the
// up-front charge; the program account ends where it began.
BOOST_AUTO_TEST_CASE(CallVerb_NoHandler_RefundsAndErrors) {
  std::string path = "/h/" + myHex() + "/nohc.lua";
  auto progPk = deploy(path, "ces.run()\n");
  uint64_t pid = launch(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(800));

  int64_t before = balanceOf(progPk);
  ces::Bytes reply;
  uint8_t rc = callVerb(pid, V, "hi", reply);
  BOOST_CHECK_EQUAL(rc, CES_ERROR_UNSUPPORTED);
  BOOST_CHECK(reply.empty());
  // Refund is posted async; poll for the program account to return to `before`.
  bool refunded = false;
  for (int i = 0; i < 100; ++i) {
    if (balanceOf(progPk) == before) { refunded = true; break; }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_CHECK_MESSAGE(refunded, "charge not refunded; got " << balanceOf(progPk));
}

// A CALL naming a pid that is not running is rejected before any charge.
BOOST_AUTO_TEST_CASE(CallVerb_UnknownPid_NotFound) {
  ces::Bytes reply;
  uint8_t rc = callVerb(0xDEADBEEFull, V, "hi", reply);
  BOOST_CHECK_EQUAL(rc, CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND);
  BOOST_CHECK(reply.empty());
}

// A large memo and a large reply both ride RUDP intact -- neither is packet
// bounded. The program echoes the memo, so the reply equals the request.
BOOST_AUTO_TEST_CASE(CallVerb_LargeMemoAndReply_RoundTrip) {
  std::string path = "/h/" + myHex() + "/echo2.lua";
  deploy(path, "function on_l2call(memo, ctx) return memo end\nces.run()\n");
  uint64_t pid = launch(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(800));

  std::string big(40000, 'x');
  for (size_t i = 0; i < big.size(); ++i) big[i] = char('A' + (i % 26));
  ces::Bytes reply;
  uint8_t rc = callVerb(pid, 0, big, reply);
  BOOST_CHECK_EQUAL(rc, CES_OK);
  BOOST_REQUIRE_EQUAL(reply.size(), big.size());
  BOOST_CHECK(std::equal(reply.begin(), reply.end(), big.begin()));
}

// Escrow money: a delivered call moves exactly `value` plus the per-op fee
// (burned) from the signer; the payee gets the full `value` -- the payment is
// never drawn back and the fee never reaches it.
BOOST_AUTO_TEST_CASE(CallVerb_Escrow_SignerPaysPayeeGetsFull) {
  std::string path = "/h/" + myHex() + "/echo3.lua";
  auto progPk = deploy(path, "function on_l2call(m,c) return 'ok' end\nces.run()\n");
  uint64_t pid = launch(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(800));

  int64_t sBefore = signerBalance();
  int64_t pBefore = balanceOf(progPk);
  int64_t fee = (int64_t)server->_config().feeQuery;   // undiscounted in tests
  ces::Bytes reply;
  uint8_t rc = callVerb(pid, V, "x", reply);
  BOOST_CHECK_EQUAL(rc, CES_OK);
  bool ok = false;
  for (int i = 0; i < 100; ++i) {
    if (balanceOf(progPk) == pBefore + (int64_t)V &&
        signerBalance() == sBefore - (int64_t)V - fee) { ok = true; break; }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_CHECK_MESSAGE(ok, "escrow settle wrong: signer " << signerBalance()
                          << " want " << (sBefore - (int64_t)V - fee) << ", payee "
                          << balanceOf(progPk) << " want " << (pBefore + (int64_t)V));
}

// Escrow refund: a call into an instance without on_l2call never credits the
// payee (the payment is never routed through it) and refunds the escrowed
// value; only the per-op fee (burned, nonrefundable) leaves the signer.
BOOST_AUTO_TEST_CASE(CallVerb_NoHandler_PayeeNeverCredited_EscrowRefunded) {
  std::string path = "/h/" + myHex() + "/nohc2.lua";
  auto progPk = deploy(path, "ces.run()\n");
  uint64_t pid = launch(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(800));

  int64_t sBefore = signerBalance();
  int64_t pBefore = balanceOf(progPk);
  int64_t fee = (int64_t)server->_config().feeQuery;   // undiscounted in tests
  ces::Bytes reply;
  uint8_t rc = callVerb(pid, V, "x", reply);
  BOOST_CHECK_EQUAL(rc, CES_ERROR_UNSUPPORTED);
  bool ok = false;
  for (int i = 0; i < 100; ++i) {
    if (balanceOf(progPk) == pBefore && signerBalance() == sBefore - fee) {
      ok = true; break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_CHECK_MESSAGE(ok, "escrow refund wrong: signer " << signerBalance()
                          << " want " << (sBefore - fee) << ", payee "
                          << balanceOf(progPk) << " want " << pBefore);
}

BOOST_AUTO_TEST_SUITE_END()
