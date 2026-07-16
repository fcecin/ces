// SYS_L2_CALL — core mechanism tests
//
// Exercises the VM->L2 paid-call primitive independent of any real built-in:
// a mock CesPlexHandler is registered in the L2 registry, a gateway VM program
// fires SYS_L2_CALL at it, and the tests assert the burn (caller -> self via
// the undo log), the delivery settlement (self -> payee), the failure refund
// (self -> caller), and the synchronous reject paths (nothing burned). The
// caller-drop cross-check (delivered costs exactly `value` more than a refund)
// pins conservation without depending on the run's gas cost.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"

#include <ces/buffer.h>
#include <ces/cesplex/mux.h>
#include <ces/cesvm.h>
#include <ces/client.h>
#include <ces/keys.h>
#include <ces/ramfilestore.h>
#include <ces/server.h>
#include <ces/util/vmprogram.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>

using namespace ces;

namespace {

// Mock L2 handler: configurable to refuse synchronously, or accept and report
// a given outcome immediately (the report itself hops to the logic strand).
// serve() is unused — SYS_L2_CALL delivery bypasses the channel path.
class MockL2Handler : public CesPlexHandler {
public:
  enum class Mode { SyncRefuse, Deliver, Timeout };
  Mode mode = Mode::Deliver;
  minx::Hash payee{};                 // credited on Deliver
  std::atomic<int> calls{0};

  void serve(std::shared_ptr<minx::RudpStream>, BoundChannelContext) override {}

  uint8_t cesplexL2Call(const L2CallRequest& req, L2CallReport report) override {
    calls.fetch_add(1);
    if (mode == Mode::SyncRefuse)
      return CES_ERROR_UNSUPPORTED;   // synchronous refuse -> host refunds
    L2CallOutcome oc = (mode == Mode::Deliver) ? L2CallOutcome::Delivered
                                               : L2CallOutcome::Timeout;
    minx::Hash p = (mode == Mode::Deliver) ? payee : minx::Hash{};
    report(req.callId, oc, p);
    return CES_OK;                     // accepted; reported above
  }
};

// 8-byte discriminator for a mount name (must match _testRegisterL2Handler:
// first 8 bytes of sha256(name)).
std::array<uint8_t, 8> discOf(const std::string& name) {
  minx::Hash h =
    ces::sha256(reinterpret_cast<const uint8_t*>(name.data()), name.size());
  std::array<uint8_t, 8> d{};
  std::memcpy(d.data(), h.data(), 8);
  return d;
}

// Gateway program: writes the 8-byte discriminator into a cell, fires
// SYS_L2_CALL for `value` (fire-and-forget: followup cell points at an
// untouched zero region), and copies the syscall's S return into output[0].
// Uses raw hostv so a nonzero S does not hard-abort the run.
AssetData buildL2CallProgram(const std::array<uint8_t, 8>& disc,
                             uint64_t value) {
  VmProgram pgm;
  const uint64_t DISC_CELL = 32;
  const uint64_t BLOB_CELL = 40;
  const uint64_t FU_CELL   = 48;   // untouched -> 32 zero bytes -> no followup
  pgm.writeBytesToIo(DISC_CELL, disc.data(), 8);
  pgm.hostv(SYS_L2_CALL, {
    Imm(DISC_CELL),   // io[4]  = discriminator cell
    Imm(value),       // io[5]  = value
    Imm(BLOB_CELL),   // io[6]  = blob cell
    Imm(0),           // io[7]  = blob len (none)
    Imm(FU_CELL),     // io[8]  = followup cell (zero region => fire-and-forget)
    Imm(0),           // io[9]  = followup budget
    Imm(0),           // io[10] = followup tag
  });
  pgm.set(Imm(CESVM_IO_OUTPUT_LEN), Imm(1));
  pgm.stb(Imm(CESVM_IO_OUTPUT * 8), Ref(CESVM_CELL_S));
  pgm.term();
  return pgm.buildBootBlock();
}

struct L2CallFixture {
  std::unique_ptr<CesServer> server;
  std::unique_ptr<CesClient> client;
  fs::path tempDir;
  KeyPair clientKey;
  KeyPair payeeKey;
  MockL2Handler mock;
  const std::string handlerName = "builtin:mockl2";

  L2CallFixture() : L2CallFixture(nullptr) {}
  explicit L2CallFixture(std::function<void(CesConfig&)> cfgMod) {
    blog::init();
    blog::set_level(blog::info);
    tempDir = makeUniqueTempDir("ces_l2call_test");
    minx::Hash serverPriv;
    serverPriv.fill(0xEE);
    CesConfig cfg = makeTestConfig(tempDir, serverPriv,
                                   std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;          // OS-allocated; rpcAutoPort spins up rpcTaskIO_
    cfg.rpcAutoPort = true;   // so the async drain runs
    if (cfgMod) cfgMod(cfg);
    server = std::make_unique<CesServer>(cfg);
    uint16_t port = server->start(0);
    BOOST_REQUIRE_MESSAGE(port > 0, "server failed to bind");
    boost::asio::ip::udp::endpoint ep(
      boost::asio::ip::address_v6::loopback(), port);
    client = std::make_unique<CesClient>(ep, false);
    client->start(0);
    client->setKey(clientKey);
    BOOST_REQUIRE(client->connect());
    server->_brr(clientKey.getPublicKeyAsHash(), 10'000'000'000);
    // Seed the payee so it exists (isolates the settle delta from account
    // creation) with a distinctive base.
    server->_brr(payeeKey.getPublicKeyAsHash(), 5'000'000);
    server->_drainLogic();
    server->_testRegisterL2Handler(handlerName, &mock);
  }
  ~L2CallFixture() {
    if (client) client->stop();
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }

  int64_t bal(const minx::Hash& k) {
    return server->_l2ProgramAccountBalanceSync(k);
  }
  minx::Hash me()    { return clientKey.getPublicKeyAsHash(); }
  minx::Hash payee() { return payeeKey.getPublicKeyAsHash(); }

  // Run a program asset and return the synchronous S (output[0]).
  uint8_t run(const minx::Hash& pgmKey) {
    uint64_t vmError = 0, budgetUsed = 0;
    ces::Bytes output;
    uint8_t rc = client->runAsset(pgmKey, 10'000'000, {},
                                  vmError, budgetUsed, output);
    BOOST_REQUIRE_EQUAL(rc, CES_OK);
    BOOST_REQUIRE_EQUAL(vmError, CESVM_OK);
    BOOST_REQUIRE(!output.empty());
    return output[0];
  }

  // Wait until `k`'s balance equals `want`, or fail after ~6s.
  bool waitBal(const minx::Hash& k, int64_t want) {
    for (int i = 0; i < 60; ++i) {
      if (bal(k) == want) return true;
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
  }
};

const uint64_t V = 1'000'000;  // burned value under test

}  // namespace

BOOST_FIXTURE_TEST_SUITE(L2CallTests, L2CallFixture)

// Delivered: the settle mints exactly `value` to the payee.
BOOST_AUTO_TEST_CASE(Delivered_MintsExactlyValue) {
  mock.mode = MockL2Handler::Mode::Deliver;
  mock.payee = payee();
  int64_t payeeBefore = bal(payee());

  minx::Hash pgmKey; pgmKey.fill(0); pgmKey[0] = 0xA0;
  AssetData pgm = buildL2CallProgram(discOf(handlerName), V);
  BOOST_REQUIRE_EQUAL(client->createAsset(pgmKey, pgm, 1), CES_OK);

  uint8_t s = run(pgmKey);
  BOOST_CHECK_EQUAL(s, CES_OK);   // accepted synchronously => burned

  BOOST_CHECK_MESSAGE(waitBal(payee(), payeeBefore + (int64_t)V),
                      "payee not credited exactly V; got "
                          << bal(payee()) << " want " << payeeBefore + (int64_t)V);
}

// Refund + conservation: a refunded call costs the caller exactly `value` less
// than a delivered one (that `value` is what reaches the payee on delivery),
// and a refund credits the payee nothing. Gas cancels since both runs use the
// identical program.
BOOST_AUTO_TEST_CASE(Refund_ReturnsExactlyValue_And_Conserves) {
  minx::Hash pgmKey; pgmKey.fill(0); pgmKey[0] = 0xA1;
  AssetData pgm = buildL2CallProgram(discOf(handlerName), V);
  BOOST_REQUIRE_EQUAL(client->createAsset(pgmKey, pgm, 1), CES_OK);

  // Delivered run.
  mock.mode = MockL2Handler::Mode::Deliver;
  mock.payee = payee();
  int64_t callerB0 = bal(me());
  int64_t payeeB0 = bal(payee());
  BOOST_CHECK_EQUAL(run(pgmKey), CES_OK);
  BOOST_REQUIRE(waitBal(payee(), payeeB0 + (int64_t)V));   // delivered V
  int64_t dropDelivered = callerB0 - bal(me());

  // Refund run (handler times out): payee unchanged, value comes back.
  mock.mode = MockL2Handler::Mode::Timeout;
  int64_t callerB1 = bal(me());
  int64_t payeeB1 = bal(payee());
  BOOST_CHECK_EQUAL(run(pgmKey), CES_OK);   // accepted => burned, then refunded
  // Let the async refund settle: caller drop stabilizes to gas-only.
  int64_t dropRefund = 0;
  bool stable = false;
  for (int i = 0; i < 60; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    dropRefund = callerB1 - bal(me());
    if (dropRefund == dropDelivered - (int64_t)V) { stable = true; break; }
  }
  BOOST_CHECK_MESSAGE(stable,
      "refund did not return exactly V: dropDelivered=" << dropDelivered
      << " dropRefund=" << dropRefund << " V=" << V);
  BOOST_CHECK_EQUAL(bal(payee()), payeeB1);   // payee untouched on refund
}

// Unmounted discriminator: synchronous reject, nothing burned, no settle.
BOOST_AUTO_TEST_CASE(UnmountedDiscriminator_RejectsSync) {
  minx::Hash pgmKey; pgmKey.fill(0); pgmKey[0] = 0xA2;
  AssetData pgm = buildL2CallProgram(discOf("builtin:does-not-exist"), V);
  BOOST_REQUIRE_EQUAL(client->createAsset(pgmKey, pgm, 1), CES_OK);

  int64_t payeeBefore = bal(payee());
  BOOST_CHECK_EQUAL(run(pgmKey), CES_ERROR_UNSUPPORTED);
  // No enqueue, so no settle ever touches the payee.
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  BOOST_CHECK_EQUAL(bal(payee()), payeeBefore);
  BOOST_CHECK_EQUAL(mock.calls.load(), 0);   // handler never invoked
}

BOOST_AUTO_TEST_SUITE_END()

// Backpressure: with the pending cap at zero, every call is rejected
// synchronously with QUEUE_FULL and nothing is burned.
struct L2CallQueueFullFixture : L2CallFixture {
  L2CallQueueFullFixture()
      : L2CallFixture([](CesConfig& c) { c.l2MaxPending = 0; }) {}
};

BOOST_FIXTURE_TEST_SUITE(L2CallBackpressureTests, L2CallQueueFullFixture)

BOOST_AUTO_TEST_CASE(QueueFull_RejectsSync) {
  mock.mode = MockL2Handler::Mode::Deliver;
  mock.payee = payee();
  minx::Hash pgmKey; pgmKey.fill(0); pgmKey[0] = 0xA3;
  AssetData pgm = buildL2CallProgram(discOf(handlerName), V);
  BOOST_REQUIRE_EQUAL(client->createAsset(pgmKey, pgm, 1), CES_OK);

  int64_t payeeBefore = bal(payee());
  BOOST_CHECK_EQUAL(run(pgmKey), CES_ERROR_QUEUE_FULL);
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  BOOST_CHECK_EQUAL(bal(payee()), payeeBefore);
  BOOST_CHECK_EQUAL(mock.calls.load(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
