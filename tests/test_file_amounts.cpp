// The amounts that callers choose in the file verbs: a price, a deposit. A sum
// that does not fit in 64 bits is one that nobody can pay, and no verb makes
// credits that nobody paid.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"

#include <ces/keys.h>
#include <ces/l2/file_client.h>
#include <ces/l2/file_handler.h>
#include <ces/server.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <future>
#include <string>
#include <vector>

using namespace ces;

namespace {

constexpr uint8_t kRead     = 0x03;
constexpr uint8_t kKvCreate = 0x0b;
constexpr uint8_t kKvPut    = 0x0c;

constexpr uint64_t kTop = std::numeric_limits<int64_t>::max();

struct FileAmountsFixture {
  fs::path dir;
  std::unique_ptr<CesServer> server;
  uint16_t rpcPort = 0;
  KeyPair owner, other;
  CesFileClient mine, theirs;
  std::string home;

  FileAmountsFixture() {
    blog::init();
    blog::set_level(blog::fatal);
    dir = makeUniqueTempDir("fileamounts");
    minx::Hash priv;
    priv.fill(0xED);
    CesConfig cfg = makeTestConfig(dir, priv, std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = {{"/ces/file/1", "builtin:file"}};
    cfg.cesFileStoreDir = (dir / "cesfilestore").string();
    cfg.cesFileStoreMaxBytes = 16ull * 1024 * 1024;
    cfg.feeFileRent = 1;
    cfg.feeFileWrite = 1000;
    cfg.feeQuery = 20'000;
    cfg.feeDiscountEnabled = false;
    server = std::make_unique<CesServer>(cfg);
    server->start(0);
    rpcPort = server->_rpcBoundPort();
    server->_brr(owner.getPublicKeyAsHash(), 10'000'000'000);
    server->_brr(other.getPublicKeyAsHash(), 10'000'000'000);
    server->_drainLogic();
    home = "/h/" + owner.getPublicKeyHexStr() + "/";
    for (auto [c, key] : {std::pair{&mine, &owner}, std::pair{&theirs, &other}}) {
      c->setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
      CES_REQUIRE_OK(c->connect("localhost", rpcPort, *key));
    }
  }
  ~FileAmountsFixture() {
    mine.disconnect();
    theirs.disconnect();
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    boost::system::error_code ec;
    fs::remove_all(dir, ec);
  }

  uint64_t make(const std::string& name) {
    uint64_t balance = 0, cost = 0;
    CES_REQUIRE_OK(mine.create(name, 1, 0, 100'000'000, balance, cost));
    return balance;
  }
  uint64_t balanceOf(const std::string& name) {
    CesFileClient::StatInfo st{};
    CES_REQUIRE_OK(mine.stat(name, st));
    return st.fileBalance;
  }
  // One verb in the server, for a program of `key` or for an account that pays.
  FileExecReq req(uint8_t verb, const std::string& name, const KeyPair& key) {
    FileExecReq r;
    const minx::Hash pk = key.getPublicKeyAsHash();
    std::memcpy(r.ownerPubkey.data(), pk.data(), pk.size());
    r.payerAccount = r.ownerPubkey;
    r.verb = verb;
    r.name = name;
    r.length = 1;
    return r;
  }
  uint8_t exec(const FileExecReq& r) {
    auto pr = std::make_shared<std::promise<uint8_t>>();
    auto fut = pr->get_future();
    boost::asio::post(server->_rpcTaskIOExecutor(), [&, pr] {
      server->fileHandler()->exec(r, [pr](FileExecResp out) { pr->set_value(out.status); },
                                  server->_rpcTaskIOExecutor());
    });
    return fut.get();
  }
};

}  // namespace

BOOST_FIXTURE_TEST_SUITE(FileAmountTests, FileAmountsFixture)

// A price above all that an account can hold refuses the read, for a reader on
// the wire, for an account in the server (builtin:think) and for a program. The
// file gets nothing.
BOOST_AUTO_TEST_CASE(APriceNobodyCanPay) {
  const std::string name = home + "priced.txt";
  make(name);
  const std::string source = "/h/" + other.getPublicKeyHexStr() + "/prog.lua";
  for (uint64_t price : {kTop - 1, kTop, kTop + 1, kTop + 2, 2 * kTop, 2 * kTop + 1, uint64_t(1) << 47}) {
    BOOST_TEST_CONTEXT(price) {
      uint64_t set = 0, a = 0, b = 0;
      CES_REQUIRE_OK(mine.setPrice(name, price, set));
      const uint64_t before = balanceOf(name);
      ces::Bytes out;
      minx::Hash h;
      BOOST_CHECK_EQUAL(theirs.read(name, 0, 1, out, h), CES_ERROR_INSUFFICIENT_BALANCE);
      FileExecReq r = req(kRead, name, other);
      r.payByAccount = true;
      BOOST_CHECK_EQUAL(exec(r), CES_ERROR_INSUFFICIENT_BALANCE);
      CES_REQUIRE_OK(theirs.create(source, 1, 0, 100'000'000, a, b));
      r.payByAccount = false;
      r.sourceName = source;
      BOOST_CHECK_EQUAL(exec(r), CES_ERROR_INSUFFICIENT_BALANCE);   // which ends the source
      BOOST_CHECK_LE(balanceOf(name), before);
    }
  }
  // The owner reads at no price.
  ces::Bytes out;
  minx::Hash h;
  CES_CHECK_OK(mine.read(name, 0, 1, out, h));
}

// The price of many KB does not fit either.
BOOST_AUTO_TEST_CASE(APriceThatWrapsOverTheLength) {
  const std::string name = home + "long.txt";
  uint64_t balance = 0, cost = 0, set = 0;
  CES_REQUIRE_OK(mine.create(name, 4096, 0, 100'000'000, balance, cost));
  for (uint64_t price : {uint64_t(1) << 62, uint64_t(1) << 63, (uint64_t(1) << 62) + 1}) {
    BOOST_TEST_CONTEXT(price) {
      CES_REQUIRE_OK(mine.setPrice(name, price, set));
      const uint64_t before = balanceOf(name);
      ces::Bytes out;
      minx::Hash h;
      BOOST_CHECK_EQUAL(theirs.read(name, 0, 4096, out, h), CES_ERROR_INSUFFICIENT_BALANCE);
      BOOST_CHECK_LE(balanceOf(name), before);
    }
  }
}

// A deposit above all that an account can hold makes no file, and adds nothing
// to one.
BOOST_AUTO_TEST_CASE(ADepositNobodyCanPay) {
  const std::string name = home + "a.txt", kv = home + "a.kv";
  make(name);
  FileExecReq r = req(kKvCreate, kv, owner);
  r.sourceName = name;
  CES_REQUIRE_OK(exec(r));
  r = req(kKvPut, kv, owner);
  r.sourceName = name;
  r.key = {'k'};
  r.value = {'v'};
  r.amount = 1000;
  CES_REQUIRE_OK(exec(r));
  const uint64_t all = 2 * kTop + 1;
  // all + 1 - fee pays nothing when the sum wraps.
  for (uint64_t amount : {all, all - 999, all - 19'999, all - 20'000, all - 20'999, kTop, kTop + 1}) {
    BOOST_TEST_CONTEXT(amount) {
      uint64_t a = 0, b = 0;
      BOOST_CHECK_EQUAL(mine.create(home + "b.txt", 1, 0, amount, a, b), CES_ERROR_INSUFFICIENT_BALANCE);
      CesFileClient::StatInfo st{};
      BOOST_CHECK_EQUAL(mine.stat(home + "b.txt", st), CES_ERROR_FILE_NOT_FOUND);
      const uint64_t before = balanceOf(name);
      BOOST_CHECK_EQUAL(mine.deposit(name, amount, a), CES_ERROR_INSUFFICIENT_BALANCE);
      BOOST_CHECK_LE(balanceOf(name), before);
      BOOST_CHECK_EQUAL(mine.kvDeposit(kv, {'k'}, amount, a), CES_ERROR_INSUFFICIENT_BALANCE);
      // A program puts a key with that deposit. The source that cannot pay ends.
      const std::string source = home + "prog.lua";
      make(source);
      FileExecReq put = req(kKvPut, kv, owner);
      put.sourceName = source;
      put.key = {'n'};
      put.value = {'v'};
      put.amount = amount;
      BOOST_CHECK_EQUAL(exec(put), CES_ERROR_INSUFFICIENT_BALANCE);
      CES_REQUIRE_OK(mine.kvDeposit(kv, {'k'}, 1, a));
      BOOST_CHECK_LE(a, 2000u);
    }
  }
}

// A program of /s/ pays nothing, so a file that it reads gets no price.
BOOST_AUTO_TEST_CASE(AnUnmeteredReadPaysNobody) {
  const std::string name = home + "priced.txt";
  make(name);
  uint64_t set = 0;
  CES_REQUIRE_OK(mine.setPrice(name, 1'000'000, set));
  const uint64_t before = balanceOf(name);
  FileExecReq r = req(kRead, name, other);
  r.sourceName = "/s/x.lua";
  CES_CHECK_OK(exec(r));
  BOOST_CHECK_LE(balanceOf(name), before);
  ces::Bytes out;
  minx::Hash h;
  CES_CHECK_OK(theirs.read(name, 0, 1, out, h));
  BOOST_CHECK_GT(balanceOf(name), before);   // a paid read pays the price
}

BOOST_AUTO_TEST_SUITE_END()
