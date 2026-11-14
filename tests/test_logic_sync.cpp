// The blocking hops to the logic strand (_l2Transact and the *Sync helpers).
// postLogic catches a throw so the strand keeps serving. A blocking caller
// waits for the result of its task, so a throw in the task must reach the
// caller as an exception. If it does not, the caller waits for ever, and on
// rpcTaskIO that stops every CesPlex verb.
//
// Each call runs on its own thread and the test waits for it with a time
// limit, so a call that never returns fails the test and does not stop it.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"

#include <ces/account.h>
#include <ces/keys.h>
#include <ces/server.h>
#include <ces/l2/ledger_txn.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

using namespace ces;

namespace {

struct LogicSyncFixture {
  fs::path dir;
  std::unique_ptr<CesServer> server;

  LogicSyncFixture() {
    blog::init();
    blog::set_level(blog::fatal);
    dir = makeUniqueTempDir("logicsync");
    minx::Hash priv;
    priv.fill(0xA7);
    CesConfig cfg = makeTestConfig(dir, priv,
                                   std::numeric_limits<uint64_t>::max());
    server = std::make_unique<CesServer>(cfg);
    server->start(0);
  }
  ~LogicSyncFixture() {
    if (server) server->stop();
    boost::system::error_code ec;
    fs::remove_all(dir, ec);
  }
};

// What a call on another thread did: 0 = still waiting, 1 = threw the
// body's exception, 2 = returned, 3 = threw something else.
struct Outcome {
  std::atomic<int> state{0};
  std::string what;
};

// Run `call` on a detached thread. Wait at most `limit` for it.
template <class F>
int runWithLimit(F call, std::shared_ptr<Outcome> out,
                 std::chrono::milliseconds limit) {
  std::thread([call, out]() mutable {
    try {
      call();
      out->state = 2;
    } catch (const std::runtime_error& e) {
      out->what = e.what();
      out->state = 1;
    } catch (...) {
      out->state = 3;
    }
  }).detach();
  const auto end = std::chrono::steady_clock::now() + limit;
  while (out->state.load() == 0 && std::chrono::steady_clock::now() < end)
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  return out->state.load();
}

}  // namespace

BOOST_FIXTURE_TEST_SUITE(LogicSyncTests, LogicSyncFixture)

// A body that throws gives its exception to the _l2Transact caller.
BOOST_AUTO_TEST_CASE(L2Transact_BodyThrows_CallerGetsTheException) {
  auto out = std::make_shared<Outcome>();
  CesServer* s = server.get();
  const int st = runWithLimit(
      [s]() {
        s->_l2Transact([](LedgerTxn&) {
          throw std::runtime_error("body failed");
        });
      },
      out, std::chrono::seconds(5));
  BOOST_REQUIRE_EQUAL(st, 1);
  BOOST_CHECK_EQUAL(out->what, "body failed");
}

// After a throw the strand still runs tasks, and _l2Transact still works.
BOOST_AUTO_TEST_CASE(L2Transact_StrandServesAfterAThrow) {
  auto first = std::make_shared<Outcome>();
  CesServer* s = server.get();
  BOOST_REQUIRE_EQUAL(
      runWithLimit([s]() {
        s->_l2Transact([](LedgerTxn&) { throw std::runtime_error("x"); });
      }, first, std::chrono::seconds(5)),
      1);
  KeyPair who;
  const minx::Hash pk = who.getPublicKeyAsHash();
  auto second = std::make_shared<Outcome>();
  BOOST_REQUIRE_EQUAL(
      runWithLimit([s, pk]() {
        s->_l2Transact([&](LedgerTxn& t) { t.credit(pk, 1234); });
      }, second, std::chrono::seconds(5)),
      2);
  BOOST_CHECK_EQUAL(s->_l2ProgramAccountBalanceSync(pk), 1234);
}

BOOST_AUTO_TEST_SUITE_END()
