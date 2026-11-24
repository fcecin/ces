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
#include <ces/cesplex/session.h>
#include <ces/l2/compute_client.h>
#include <ces/l2/compute_handler.h>
#include <ces/l2/file_client.h>
#include <ces/l2/file_handler.h>       // FileHandler::readProgramPubkey
#include <ces/util/sync_call.h>
#include <ces/util/vmprogram.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <span>
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
// (0 delivered, 1 no-handler, 2 timeout), io[INPUT+2..]=reply. Transfers
// outcome + 1 + the first cell of the reply to `marker`, so a delivered
// resolution with no reply credits 1 and a no-handler credits 2 -- both
// non-zero, so firing, the outcome value and the reply are observable.
AssetData buildL2Followup(const minx::Hash& marker) {
  VmProgram pgm;
  const uint64_t DEST_CELL = 32, AMT_CELL = 60;
  pgm.writeBytesToIo(DEST_CELL, marker.data(), 32);
  pgm.add(Ref(CESVM_IO_INPUT + 1), Ref(CESVM_IO_INPUT + 2));   // R = outcome + reply
  pgm.set(Imm(AMT_CELL), Ref(CESVM_CELL_R));
  pgm.inc(Imm(AMT_CELL));                                      // + 1
  pgm.hostv(SYS_TRANSFER, { Imm(DEST_CELL), Ref(AMT_CELL) });
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

  // With `idleSecs`, the server drops a connection that is idle for that long.
  explicit L2ComputeFixture(uint32_t idleSecs = 0) {
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
    if (idleSecs > 0) cfg.rpcRudpChannelIdleSecs = idleSecs;
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
  // Credit the account of `pk` until it has room for only `room` more.
  void fillAccount(const std::array<uint8_t, 32>& pk, uint64_t room) {
    minx::Hash h;
    std::memcpy(h.data(), pk.data(), 32);
    server->_brr(h, BALANCE_MAX - balanceOf(pk) - (int64_t)room);
    server->_drainLogic();
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

// The INVOKE_L2_RETURN followup fires on resolution and receives the outcome and
// the reply: a delivered call with the reply 'd' (100) credits the marker 101
// (outcome 0 + 1 + 100), then a no-handler call credits 2 more (outcome 1 + 1).
// A call whose payment the program's account cannot take is refunded, so its
// followup gets outcome 1 and no reply, and credits 2 more.
BOOST_AUTO_TEST_CASE(FollowupNotifiesOutcome) {
  const std::string okSrc = "function on_l2call(p, c) return 'd' end\nces.run()\n";
  std::string okPath = "/h/" + myHex() + "/svc2.lua";
  deploy(okPath, okSrc);
  uint64_t pidOk = launch(okPath);
  std::string noPath = "/h/" + myHex() + "/nofu.lua";
  deploy(noPath, "ces.run()\n");
  uint64_t pidNo = launch(noPath);
  std::string fullPath = "/h/" + myHex() + "/full.lua";
  const auto fullPk = deploy(fullPath, okSrc);
  uint64_t pidFull = launch(fullPath);
  std::this_thread::sleep_for(std::chrono::milliseconds(900));
  fillAccount(fullPk, V / 2);   // no room for V

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
  // The balance of the marker, as soon as it is `want`, or after 5 s.
  auto waitMarker = [&](int64_t want) {
    int64_t b = 0;
    for (int i = 0; i < 100 && (b = markerBal()) != want; ++i)
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    return b;
  };

  fireAt(pidOk, 1);   // delivered -> outcome 0, reply 'd' -> marker += 101
  BOOST_CHECK_EQUAL(waitMarker(1101), 1101);
  fireAt(pidNo, 2);   // no-handler -> outcome 1 -> marker += 2
  BOOST_CHECK_EQUAL(waitMarker(1103), 1103);
  fireAt(pidFull, 3);   // refunded -> outcome 1, no reply -> marker += 2
  BOOST_CHECK_EQUAL(waitMarker(1105), 1105);
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

// A paid call that gets no answer ends at once when its program ends. A program that
// started the call keeps the payment, and its caller has an empty reply.
BOOST_AUTO_TEST_CASE(CallVerb_NoAnswer_EndsWithTheProgram) {
  using clock = std::chrono::steady_clock;
  struct Case {
    const char* name;
    std::string src;
    bool kill;          // the owner kills the program during the call
  };
  const std::vector<Case> cases = {
    {"error", "function on_l2call() error('no') end\nces.run()\n", false},
    {"exit", "function on_l2call() ces.exit() end\nces.run()\n", false},
    {"killed", "local taken\nfunction on_l2call(m)\n"
               "  if m == 'taken?' then return taken and 'yes' or 'no' end\n"
               "  taken = true ces.sleep(120000)\nend\nces.run()\n", true},
  };
  const int64_t fee = (int64_t)server->_config().feeQuery;
  const KeyPair pollKey;
  server->_brr(pollKey.getPublicKeyAsHash(), 1'000'000'000);
  for (const auto& c : cases) {
    BOOST_TEST_CONTEXT(c.name) {
      const std::string path = "/h/" + myHex() + "/" + c.name + ".lua";
      const auto progPk = deploy(path, c.src);
      const uint64_t pid = launch(path);
      std::this_thread::sleep_for(std::chrono::milliseconds(800));
      const int64_t sBefore = signerBalance(), pBefore = balanceOf(progPk);
      std::thread killer([&] {
        if (!c.kill) return;
        CesComputeClient poll, cc;   // the polls pay from their own key
        for (auto* k : {&poll, &cc})
          k->setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
        if (poll.connect("localhost", rpcPort, pollKey) != CES_OK ||
            cc.connect("localhost", rpcPort, ownerKey) != CES_OK)
          return;
        const std::string ask = "taken?", yes = "yes";
        ces::Bytes got;
        for (int i = 0; i < 100 && got != ces::Bytes(yes.begin(), yes.end()); ++i)
          if (poll.call(pid, 0, ces::Bytes(ask.begin(), ask.end()), got) != CES_OK) got.clear();
        cc.kill(pid);
      });
      const auto t0 = clock::now();
      ces::Bytes reply;
      const uint8_t rc = callVerb(pid, V, "x", reply);
      const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(clock::now() - t0).count();
      killer.join();
      BOOST_CHECK_LT(ms, 10'000);
      BOOST_CHECK_EQUAL(rc, CES_OK);
      BOOST_CHECK(reply.empty());
      const int64_t sWant = sBefore - (int64_t)V;
      bool ok = false;
      for (int i = 0; i < 100 && !ok; ++i) {
        // Less the fees of the caller, and the rent of the program.
        ok = signerBalance() <= sWant && signerBalance() >= sWant - 10 * fee &&
             balanceOf(progPk) >= pBefore + (int64_t)V - 100'000;
        if (!ok) std::this_thread::sleep_for(std::chrono::milliseconds(50));
      }
      BOOST_CHECK_MESSAGE(ok, "signer " << signerBalance() << " want " << sWant << ", program "
                              << balanceOf(progPk) << " before " << pBefore);
    }
  }
}

// A call over a connection has no deadline, so a slow program answers. The deadline
// of the calls of VM runs does not touch it.
BOOST_AUTO_TEST_CASE(CallVerb_HasNoTimeLimit) {
  const std::string path = "/h/" + myHex() + "/slow.lua";
  deploy(path, "function on_l2call() ces.sleep(4000) return 'late' end\nces.run()\n");
  const uint64_t pid = launch(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(800));
  runSync(server->_rpcTaskIOExecutor(),
          [&] { server->computeHandler()->testSetL2CallTimeout(std::chrono::seconds(1)); });
  ces::Bytes reply;
  BOOST_CHECK_EQUAL(callVerb(pid, V, "x", reply), CES_OK);
  BOOST_CHECK_EQUAL(std::string(reply.begin(), reply.end()), "late");
}

// A program that is busy for 5 s before it takes calls. "ran?" tells how many other
// calls it ran.
const char* const kBusyThenTakes =
  "local t = ces.now()\nwhile ces.now() - t < 5000000 do end\n"
  "local ran = 0\nfunction on_l2call(m)\n"
  "  if m == 'ran?' then return tostring(ran) end\n"
  "  ran = ran + 1\n  return 'ok'\nend\nces.run()\n";

template <class F> bool waitUntil(F&& done) {
  for (int i = 0; i < 200; ++i) {
    if (done()) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  return false;
}

// A call of V credits on its own thread, with the client to hang up on.
struct HangUpCall {
  CesComputeClient cc;
  std::thread t;
  uint8_t rc = 0xff;
  ces::Bytes reply;
  void start(L2ComputeFixture& f, uint64_t pid, const std::string& memo) {
    start(f, pid, memo, f.ownerKey);
  }
  void start(L2ComputeFixture& f, uint64_t pid, const std::string& memo, const KeyPair& payer) {
    cc.setServerPubkey(f.server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(cc.connect("localhost", f.rpcPort, payer));
    t = std::thread([this, pid, memo] {
      rc = cc.call(pid, V, ces::Bytes(memo.begin(), memo.end()), reply);
    });
  }
  ~HangUpCall() {
    cc.cancel();
    if (t.joinable()) t.join();
  }
};

// Asks a program, as another account than the owner's.
struct Asker {
  KeyPair key;
  CesComputeClient cc;
  uint64_t pid;
  Asker(L2ComputeFixture& f, uint64_t pid) : pid(pid) {
    f.server->_brr(key.getPublicKeyAsHash(), 1'000'000'000);
    cc.setServerPubkey(f.server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(cc.connect("localhost", f.rpcPort, key));
  }
  std::string ask(const std::string& memo) {
    ces::Bytes reply;
    if (cc.call(pid, 0, ces::Bytes(memo.begin(), memo.end()), reply) != CES_OK) return "error";
    return std::string(reply.begin(), reply.end());
  }
  bool becomes(const std::string& memo, const std::string& want) {
    return waitUntil([&] { return ask(memo) == want; });
  }
};

// A caller that hangs up before the program starts its call gets its credits back,
// and the program never runs the call, also when it takes calls later.
BOOST_AUTO_TEST_CASE(CallVerb_HangUpBeforeTheProgramStarts_Refunds) {
  const std::string path = "/h/" + myHex() + "/busy.lua";
  const auto progPk = deploy(path, kBusyThenTakes);
  const uint64_t pid = launch(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(300));   // its busy time began
  const int64_t sBefore = signerBalance(), pBefore = balanceOf(progPk);
  const int64_t fee = (int64_t)server->_config().feeQuery;
  HangUpCall h;
  h.start(*this, pid, "x");
  std::this_thread::sleep_for(std::chrono::milliseconds(700));
  h.cc.cancel();
  h.t.join();
  BOOST_CHECK_EQUAL(h.rc, CES_ERROR_CONNECTION_LOST);
  bool ok = false;
  for (int i = 0; i < 100 && !ok; ++i) {
    // Less the fee of the call, which stays.
    ok = signerBalance() <= sBefore && signerBalance() >= sBefore - 10 * fee;
    if (!ok) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_CHECK_MESSAGE(ok, "signer " << signerBalance() << " before " << sBefore);
  BOOST_CHECK_LE(balanceOf(progPk), pBefore);

  // The program goes on and takes calls. The ended one did not run.
  ces::Bytes reply;
  std::string got = "none";
  for (int i = 0; i < 100 && got != "0"; ++i) {
    if (callVerb(pid, 0, "ran?", reply) == CES_OK) got = std::string(reply.begin(), reply.end());
    if (got != "0" && got != "none" && got != "1") break;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  BOOST_CHECK_EQUAL(got, "0");
}

// A program that starts a call and holds it until a call "go" comes. "started?" and
// "finished?" tell how far it is.
const char* const kHoldsACall =
  "local started, finished, go = 'no', 'no', false\n"
  "function on_l2call(m)\n"
  "  if m == 'started?' then return started end\n"
  "  if m == 'finished?' then return finished end\n"
  "  if m == 'go' then go = true return 'ok' end\n"
  "  started = 'yes'\n  while not go do ces.sleep(20) end\n"
  "  finished = 'yes'\n  return 'done'\nend\nces.run()\n";

// A caller that hangs up on a call that the program started does not get its credits
// back. The program is paid then, and goes on with the call. It is not paid again when
// it finishes, with nobody to answer.
BOOST_AUTO_TEST_CASE(CallVerb_HangUpAfterTheProgramStarts_PaysTheProgram) {
  const std::string path = "/h/" + myHex() + "/started.lua";
  const auto progPk = deploy(path, kHoldsACall);
  const uint64_t pid = launch(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(800));
  const int64_t sBefore = signerBalance(), pBefore = balanceOf(progPk);
  const int64_t fee = (int64_t)server->_config().feeQuery;
  Asker asker(*this, pid);
  HangUpCall h;
  h.start(*this, pid, "x");
  BOOST_REQUIRE(asker.becomes("started?", "yes"));
  h.cc.cancel();
  h.t.join();
  BOOST_CHECK_EQUAL(h.rc, CES_ERROR_CONNECTION_LOST);
  // The program holds the call still, and has its payment, less its rent.
  BOOST_CHECK(waitUntil([&] { return balanceOf(progPk) >= pBefore + (int64_t)V - 100'000; }));
  BOOST_CHECK_EQUAL(asker.ask("finished?"), "no");
  BOOST_CHECK_LE(signerBalance(), sBefore - (int64_t)V);
  BOOST_CHECK_GE(signerBalance(), sBefore - (int64_t)V - 10 * fee);
  BOOST_CHECK_EQUAL(asker.ask("go"), "ok");
  BOOST_CHECK(asker.becomes("finished?", "yes"));
  std::this_thread::sleep_for(std::chrono::milliseconds(300));   // its late reply came
  BOOST_CHECK_LE(balanceOf(progPk), pBefore + (int64_t)V);
  BOOST_CHECK_GE(signerBalance(), sBefore - (int64_t)V - 10 * fee);
}

// A server that stops settles the calls in flight. One that the program started pays
// it, and one that the program did not start gives the credits back.
BOOST_AUTO_TEST_CASE(ServerStop_SettlesTheCallsInFlight) {
  const std::string held = "/h/" + myHex() + "/held.lua", busy = "/h/" + myHex() + "/neverruns.lua";
  const auto heldPk = deploy(held, kHoldsACall);
  const auto busyPk = deploy(busy, "while true do end\n");
  const uint64_t heldPid = launch(held), busyPid = launch(busy);
  std::this_thread::sleep_for(std::chrono::milliseconds(800));
  const int64_t funds = 1'000'000'000;
  const KeyPair a, b;
  for (const KeyPair* k : {&a, &b}) server->_brr(k->getPublicKeyAsHash(), funds);
  auto hashOf = [](const std::array<uint8_t, 32>& pk) {
    minx::Hash h;
    std::memcpy(h.data(), pk.data(), 32);
    return h;
  };
  auto arrayOf = [](const KeyPair& k) {
    std::array<uint8_t, 32> pk{};
    std::memcpy(pk.data(), k.getPublicKeyAsHash().data(), 32);
    return pk;
  };
  const int64_t pHeld = balanceOf(heldPk), pBusy = balanceOf(busyPk);
  HangUpCall started, waits;
  started.start(*this, heldPid, "x", a);
  waits.start(*this, busyPid, "x", b);
  Asker asker(*this, heldPid);
  BOOST_REQUIRE(asker.becomes("started?", "yes"));
  // The other one is escrowed too, and waits.
  BOOST_REQUIRE(waitUntil([&] { return balanceOf(arrayOf(b)) <= funds - (int64_t)V; }));
  asker.cc.disconnect();
  client->stop();
  client.reset();
  server->stop();
  const int64_t fees = 10 * (int64_t)server->_config().feeQuery;
  const int64_t aLeft = server->_balanceOf(a.getPublicKeyAsHash());
  const int64_t bLeft = server->_balanceOf(b.getPublicKeyAsHash());
  BOOST_CHECK_LE(aLeft, funds - (int64_t)V);
  BOOST_CHECK_GE(aLeft, funds - (int64_t)V - fees);
  BOOST_CHECK_GE(bLeft, funds - fees);   // the credits came back
  BOOST_CHECK_GE(server->_balanceOf(hashOf(heldPk)), pHeld + (int64_t)V - 100'000);
  BOOST_CHECK_LE(server->_balanceOf(hashOf(busyPk)), pBusy);
  // The server is gone, so a caller with no answer ends when it hangs up.
  started.cc.cancel();
  waits.cc.cancel();
}

// A caller that hung up before the server had the call takes nothing to the program:
// the call is refused, and the server gives the credits back.
BOOST_AUTO_TEST_CASE(CallVerb_HungUpBeforeHandOver_IsRefused) {
  const std::string path = "/h/" + myHex() + "/handover.lua";
  deploy(path, "local ran = 0\nfunction on_l2call(m)\n"
               "  if m == 'ran?' then return tostring(ran) end\n  ran = ran + 1\nend\nces.run()\n");
  const uint64_t pid = launch(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(800));
  // The token of a connection that ended, and the one of a connection that ended before
  // the server read the call (0).
  for (uint64_t token : {42, 0}) {
    uint8_t rc = CES_OK;
    bool reported = false;
    runSync(server->_rpcTaskIOExecutor(), [&] {
      L2CallRequest req;
      req.callId = 999'999;
      std::memcpy(req.payer.data(), ownerKey.getPublicKeyAsHash().data(), req.payer.size());
      req.value = V;
      ces::Buffer::put<uint64_t>(req.blob, pid);
      req.caller = L2CallerChannel{{}, 7, token};
      rc = server->computeHandler()->cesplexL2Call(
        req, [&](uint64_t, L2CallOutcome, const minx::Hash&, const ces::Bytes&) { reported = true; });
    });
    BOOST_CHECK_EQUAL(rc, CES_ERROR_CONNECTION_LOST);
    BOOST_CHECK(!reported);
  }
  ces::Bytes reply;
  CES_REQUIRE_OK(callVerb(pid, 0, "ran?", reply));
  BOOST_CHECK_EQUAL(std::string(reply.begin(), reply.end()), "0");
}

// A hang-up that comes before the call ends it before it is sent, so it costs nothing.
BOOST_AUTO_TEST_CASE(CallVerb_HungUpBeforeItIsSent_IsNotSent) {
  const std::string path = "/h/" + myHex() + "/notsent.lua";
  const auto progPk = deploy(path, "function on_l2call(m) return m end\nces.run()\n");
  const uint64_t pid = launch(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(800));
  CesComputeClient cc;
  cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));
  const int64_t sBefore = signerBalance(), pBefore = balanceOf(progPk);
  const std::string memo = "x";
  ces::Bytes reply;
  cc.cancel();
  BOOST_CHECK_EQUAL(cc.call(pid, V, ces::Bytes(memo.begin(), memo.end()), reply), CES_ERROR_CONNECTION_LOST);
  BOOST_CHECK_GT(signerBalance(), sBefore - (int64_t)V);
  BOOST_CHECK_LE(balanceOf(progPk), pBefore);
  BOOST_CHECK_EQUAL(cc.call(pid, 0, ces::Bytes(memo.begin(), memo.end()), reply), CES_OK);   // the next one goes
  BOOST_CHECK_EQUAL(std::string(reply.begin(), reply.end()), "x");
  cc.disconnect();
}

// A server that does not know a verb ends the connection, so its client does not wait
// on a connection that nobody reads.
BOOST_AUTO_TEST_CASE(AVerbThatTheServerDoesNotKnowEndsTheConnection) {
  CesPlexClient pc;
  pc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(pc.connect("localhost", rpcPort, "/ces/compute/1", ownerKey));
  const std::string pre = "x";
  auto env = pc.buildEnvelope(0x55, std::span<const uint8_t>(
                                      reinterpret_cast<const uint8_t*>(pre.data()), pre.size()));
  ces::Bytes out;
  const auto t0 = std::chrono::steady_clock::now();
  BOOST_CHECK_EQUAL(pc.driveVerb(0x55, env, 0, nullptr, out), CES_ERROR_CONNECTION_LOST);
  BOOST_CHECK_LT(std::chrono::steady_clock::now() - t0, std::chrono::seconds(10));
  pc.disconnect();
}

struct ShortIdleFixture : L2ComputeFixture {
  ShortIdleFixture() : L2ComputeFixture(2) {}
};

// A call that lasts longer than the idle time of the connection stays, because the
// waiting client tells the server that it is there. The bytes that it sends do not
// disturb the next call on the same connection.
BOOST_FIXTURE_TEST_CASE(CallVerb_ALongWaitKeepsItsConnection, ShortIdleFixture) {
  const std::string path = "/h/" + myHex() + "/longwait.lua";
  deploy(path, "function on_l2call(m)\n  if m == 'long' then ces.sleep(5000) end\n"
               "  return m .. '!'\nend\nces.run()\n");
  const uint64_t pid = launch(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(800));
  CesComputeClient cc;
  cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));
  cc._testSetNopEvery(std::chrono::milliseconds(300));
  ces::Bytes reply;
  const std::string longMemo = "long", shortMemo = "short";
  BOOST_CHECK_EQUAL(cc.call(pid, 0, ces::Bytes(longMemo.begin(), longMemo.end()), reply), CES_OK);
  BOOST_CHECK_EQUAL(std::string(reply.begin(), reply.end()), "long!");
  BOOST_CHECK_EQUAL(cc.call(pid, 0, ces::Bytes(shortMemo.begin(), shortMemo.end()), reply), CES_OK);
  BOOST_CHECK_EQUAL(std::string(reply.begin(), reply.end()), "short!");
  cc.disconnect();
}

// A call of a VM run has no connection, so it keeps its deadline. A program that does
// not start it by then gives the credits back, and does not run it later.
BOOST_AUTO_TEST_CASE(VmCall_NotStartedByItsDeadline_Refunds) {
  const std::string path = "/h/" + myHex() + "/vmbusy.lua";
  deploy(path, kBusyThenTakes);
  const uint64_t pid = launch(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  runSync(server->_rpcTaskIOExecutor(),
          [&] { server->computeHandler()->testSetL2CallTimeout(std::chrono::milliseconds(700)); });
  const int64_t sBefore = signerBalance();
  const int64_t fee = (int64_t)server->_config().feeQuery;
  BOOST_REQUIRE_EQUAL(runGateway(pid, V), CES_OK);
  // The gas of the run and of the gateway's make stays; the amount of the call comes back.
  const int64_t gone = sBefore - signerBalance();
  BOOST_CHECK_GT(gone, (int64_t)V - 1);
  bool ok = false;
  for (int i = 0; i < 100 && !ok; ++i) {
    ok = signerBalance() >= sBefore - gone + (int64_t)V - 10 * fee &&
         signerBalance() <= sBefore - gone + (int64_t)V + 1;
    if (!ok) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_CHECK_MESSAGE(ok, "signer " << signerBalance() << " before " << sBefore << " gone " << gone);
  // It takes calls again after its busy time, and the ended one did not run.
  ces::Bytes reply;
  std::string got = "none";
  for (int i = 0; i < 100 && got != "0"; ++i) {
    if (callVerb(pid, 0, "ran?", reply) == CES_OK) got = std::string(reply.begin(), reply.end());
    if (got != "0" && got != "none" && got != "1") break;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  BOOST_CHECK_EQUAL(got, "0");
}

// A payment that the program's account cannot take goes back to the payer, and
// the call fails with the reason. A reply with no payment is no success.
BOOST_AUTO_TEST_CASE(CallVerb_PayeeAtTheBalanceCap_RefundsAndErrors) {
  const std::string path = "/h/" + myHex() + "/rich.lua";
  const auto progPk = deploy(path, "function on_l2call() return 'ok' end\nces.run()\n");
  const uint64_t pid = launch(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(800));
  fillAccount(progPk, V / 2);   // no room for V

  const int64_t sBefore = signerBalance(), fee = (int64_t)server->_config().feeQuery;
  ces::Bytes reply;
  BOOST_CHECK_EQUAL(callVerb(pid, V, "x", reply), CES_ERROR_BALANCE_OVERFLOW);
  BOOST_CHECK(reply.empty());
  bool ok = false;
  for (int i = 0; i < 100 && !ok; ++i) {
    ok = signerBalance() <= sBefore && signerBalance() >= sBefore - 10 * fee;
    if (!ok) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_CHECK_MESSAGE(ok, "signer " << signerBalance() << " before " << sBefore);
  // A call that fits is paid.
  BOOST_CHECK_EQUAL(callVerb(pid, V / 10, "x", reply), CES_OK);
  BOOST_CHECK_EQUAL(std::string(reply.begin(), reply.end()), "ok");
}

// A call that pays 0 moves nothing, so it works with a program whose account
// takes no transfer of 0. A payment account takes only its own amount. Another
// amount goes back to the payer, and the call fails with the reason.
BOOST_AUTO_TEST_CASE(CallVerb_PayeeIsAPaymentAccount_TakesItsAmountOrNothing) {
  const std::string path = "/h/" + myHex() + "/payment.lua";
  const auto progPk = deploy(path, "function on_l2call() return 'ok' end\nces.run()\n");
  const uint64_t pid = launch(path);
  std::this_thread::sleep_for(std::chrono::milliseconds(800));
  minx::Hash pk;
  std::memcpy(pk.data(), progPk.data(), pk.size());
  server->_burn(pk, BALANCE_MAX);   // ends the account, so the key can get a new one
  server->_drainLogic();
  int64_t left = 0;
  CES_REQUIRE_OK(client->createPayment(pk, 1000, 5, left));
  BOOST_REQUIRE_EQUAL(balanceOf(progPk), -1000);

  ces::Bytes reply;
  BOOST_CHECK_EQUAL(callVerb(pid, 0, "x", reply), CES_OK);
  BOOST_CHECK_EQUAL(std::string(reply.begin(), reply.end()), "ok");
  BOOST_CHECK_EQUAL(balanceOf(progPk), -1000);

  const int64_t sBefore = signerBalance(), fee = (int64_t)server->_config().feeQuery;
  BOOST_CHECK_EQUAL(callVerb(pid, V, "x", reply), CES_ERROR_WRONG_PAYMENT_AMOUNT);
  BOOST_CHECK(reply.empty());
  bool ok = false;
  for (int i = 0; i < 100 && !ok; ++i) {
    ok = signerBalance() <= sBefore && signerBalance() >= sBefore - 10 * fee;
    if (!ok) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  BOOST_CHECK_MESSAGE(ok, "signer " << signerBalance() << " before " << sBefore);

  BOOST_CHECK_EQUAL(callVerb(pid, 1000, "x", reply), CES_OK);
  BOOST_CHECK_EQUAL(std::string(reply.begin(), reply.end()), "ok");
  BOOST_CHECK_EQUAL(balanceOf(progPk), 1000);
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
