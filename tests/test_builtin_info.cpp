// test_builtin_info.cpp — CES_QUERY_BUILTIN_INFO, the `builtin` list of
// CES_QUERY_SERVER_INFO, and the compute payout of the network bill.

#include "test_common.h"
#include <ces/util/sync_call.h>
#include <ces/account.h>
#include <ces/client.h>
#include <ces/keys.h>
#include <ces/protocol.h>
#include <ces/server.h>
#include <minx/minx.h>
#include <boost/test/unit_test.hpp>

#include <boost/asio/ip/udp.hpp>
#include <boost/asio/io_context.hpp>

#include <fstream>
#include <functional>
#include <iterator>
#include <limits>
#include <string>
#include <vector>

using namespace ces;

namespace {

// A server that mounts file, compute and lua (compute is inert here: it has
// no child binary), at a compute payout factor of 1.5, and a funded client.
struct BuiltinInfoFixture {
  fs::path dir;
  std::unique_ptr<CesServer> server;
  std::unique_ptr<CesClient> client;
  KeyPair clientKey;

  explicit BuiltinInfoFixture(std::function<void(CesConfig&)> tweak = {}) {
    blog::init();
    blog::set_level(blog::fatal);
    dir = makeUniqueTempDir("builtin_info");
    minx::Hash priv;
    priv.fill(0xB1);
    CesConfig cfg =
      makeTestConfig(dir, priv, std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = {
      {"/ces/file/1",    "builtin:file"},
      {"/ces/compute/1", "builtin:compute"},
      {"/ces/lua/1",     "builtin:lua"},
    };
    cfg.cesFileStoreMaxBytes = 16ull * 1024 * 1024;
    cfg.computePayoutFactorBp = 15000;
    if (tweak) tweak(cfg);
    server = std::make_unique<CesServer>(cfg);
    const uint16_t port = server->start(0);
    server->_brr(clientKey.getPublicKeyAsHash(), 10'000'000'000);

    boost::asio::ip::udp::endpoint ep(boost::asio::ip::address_v6::loopback(), port);
    client = std::make_unique<CesClient>(ep, false);
    client->start(0);
    client->setKey(clientKey);
    client->connect();
    wait_net();
  }

  ~BuiltinInfoFixture() {
    if (client) client->stop();
    if (server) server->stop();
    boost::system::error_code ec;
    fs::remove_all(dir, ec);
  }

  int64_t bal(const minx::Hash& k) { return server->_balanceOf(k); }
};

bool has(const std::vector<ServerInfoEntry>& es, const std::string& key) {
  for (const auto& e : es)
    if (e.key == key) return true;
  return false;
}

std::string get(const std::vector<ServerInfoEntry>& es, const std::string& key) {
  for (const auto& e : es)
    if (e.key == key) return e.value;
  return "";
}

}  // namespace

BOOST_FIXTURE_TEST_SUITE(BuiltinInfoTests, BuiltinInfoFixture)

// server-info lists the mounted builtins, and no longer carries their facts.
BOOST_AUTO_TEST_CASE(ServerInfoListsTheBuiltins) {
  std::vector<ServerInfoEntry> es;
  CES_REQUIRE_OK(client->queryServerInfo(es));
  BOOST_CHECK_EQUAL(get(es, "builtin"), "compute,file,lua");
  BOOST_CHECK(!has(es, "feeFileRent"));
  BOOST_CHECK(!has(es, "cesFileStoreMaxBytes"));
}

// A server-info reply is one datagram. With the longest hello it stays under
// kMaxInfoReplyBytes: with the MINX header, the UDP payload that fits the
// minimum IPv6 MTU.
BOOST_AUTO_TEST_CASE(ServerInfoFitsOneDatagram) {
  server->_setHello(std::string(CesServer::HELLO_MAX_BYTES, 'h'));
  std::vector<ServerInfoEntry> es;
  CES_REQUIRE_OK(client->queryServerInfo(es));
  CesQueryServerInfoResult r;
  r.rcode = CES_OK;
  r.entries = es;
  const size_t bytes = 1 + r.getPayloadSize() + sizeof(Signature);
  BOOST_TEST_MESSAGE("server-info reply: " << bytes << " bytes");
  BOOST_CHECK_LE(bytes, kMaxInfoReplyBytes);
}

BOOST_AUTO_TEST_CASE(FileInfoHasTheFileFeesAndTheNetworkRates) {
  std::vector<ServerInfoEntry> es;
  CES_REQUIRE_OK(client->queryBuiltinInfo("file", es));
  const CesConfig& c = server->_config();
  BOOST_CHECK_EQUAL(get(es, "mounts"), "/ces/file/1");
  BOOST_CHECK_EQUAL(get(es, "feeFileRent"), std::to_string(c.feeFileRent));
  BOOST_CHECK_EQUAL(get(es, "feeFileWrite"), std::to_string(c.feeFileWrite));
  BOOST_CHECK_EQUAL(get(es, "feeFileRead"), std::to_string(c.feeFileRead));
  BOOST_CHECK_EQUAL(get(es, "cesFileStoreMaxBytes"),
                    std::to_string(c.cesFileStoreMaxBytes));
  BOOST_CHECK_EQUAL(get(es, "feeNetKiBSent"), std::to_string(c.feeNetKiBSent));
  BOOST_CHECK_EQUAL(get(es, "feeNetChannelSec"), std::to_string(c.feeNetChannelSec));
  BOOST_CHECK(!has(es, "computePayoutFactor"));
}

BOOST_AUTO_TEST_CASE(ComputeInfoHasTheInstanceFeesAndThePayoutFactor) {
  std::vector<ServerInfoEntry> es;
  CES_REQUIRE_OK(client->queryBuiltinInfo("compute", es));
  const CesConfig& c = server->_config();
  BOOST_CHECK_EQUAL(get(es, "mounts"), "/ces/compute/1");
  BOOST_CHECK_EQUAL(get(es, "feeComputeCpuSec"), std::to_string(c.feeComputeCpuSec));
  BOOST_CHECK_EQUAL(get(es, "feeComputeSlotSec"), std::to_string(c.feeComputeSlotSec));
  BOOST_CHECK_EQUAL(get(es, "computePayoutFactor"), "1.5");
  BOOST_CHECK(has(es, "feeNetKiBReceived"));
}

// A builtin that the server does not mount costs the error fee and tells
// nothing.
BOOST_AUTO_TEST_CASE(AnUnknownBuiltinIsNotFound) {
  const auto k = clientKey.getPublicKeyAsHash();
  server->_drainLogic();
  const int64_t before = bal(k);
  std::vector<ServerInfoEntry> es{{"stale", "x"}};
  CES_REQUIRE_RC_EQ(client->queryBuiltinInfo("think", es), CES_ERROR_TARGET_NOT_FOUND);
  BOOST_CHECK(es.empty());
  server->_drainLogic();
  BOOST_CHECK_LT(bal(k), before);
}

// The payout: the payer pays the price times the factor, the payee gets the
// part above the price, and the server keeps the price (it leaves
// circulation, as any fee).
BOOST_AUTO_TEST_CASE(ThePayeeGetsThePartAboveThePrice) {
  KeyPair payer, payee;
  const auto pk = payer.getPublicKeyAsHash(), ek = payee.getPublicKeyAsHash();
  server->_brr(pk, 10'000);
  server->_brr(ek, 1);
  server->_drainLogic();
  const int64_t circ = server->_getTotalCredits();

  server->debitNetworkBill(Account::getMapKey(pk), Account::getMapKey(ek), 1000);
  server->_drainLogic();
  BOOST_CHECK_EQUAL(bal(pk), 10'000 - 1500);
  BOOST_CHECK_EQUAL(bal(ek), 1 + 500);
  BOOST_CHECK_EQUAL(server->_getTotalCredits(), circ - 1000);
}

// No payee, or a payee that pays itself: the plain price, no payout.
BOOST_AUTO_TEST_CASE(NoPayeeMeansThePlainPrice) {
  KeyPair payer;
  const auto pk = payer.getPublicKeyAsHash();
  server->_brr(pk, 10'000);
  server->_drainLogic();

  server->debitNetworkBill(Account::getMapKey(pk), HashPrefix{}, 1000);
  server->_drainLogic();
  BOOST_CHECK_EQUAL(bal(pk), 9000);

  server->debitNetworkBill(Account::getMapKey(pk), Account::getMapKey(pk), 1000);
  server->_drainLogic();
  BOOST_CHECK_EQUAL(bal(pk), 8000);
}

// A payee with no account gets nothing, no account is made for it, and the
// payer pays the plain price: nobody gets a surcharge.
BOOST_AUTO_TEST_CASE(AMissingPayeeGetsNoAccount) {
  KeyPair payer, payee;
  const auto pk = payer.getPublicKeyAsHash(), ek = payee.getPublicKeyAsHash();
  server->_brr(pk, 10'000);
  server->_drainLogic();

  server->debitNetworkBill(Account::getMapKey(pk), Account::getMapKey(ek), 1000);
  server->_drainLogic();
  BOOST_CHECK_EQUAL(bal(pk), 9000);
  BOOST_CHECK(!server->_accountExists(ek));
}

// A payment record (a negative balance: a payment that someone owes) is not
// a payee. The payer pays the plain price, and the record stays as it was.
BOOST_AUTO_TEST_CASE(APaymentRecordGetsNoPayout) {
  KeyPair payer, record;
  const auto pk = payer.getPublicKeyAsHash(), rk = record.getPublicKeyAsHash();
  server->_brr(pk, 10'000);
  int64_t bal0 = 0;
  CES_REQUIRE_OK(client->createPayment(rk, 777, 1, bal0));
  server->_drainLogic();
  const int64_t due = bal(rk);
  BOOST_REQUIRE_LT(due, 0);

  server->debitNetworkBill(Account::getMapKey(pk), Account::getMapKey(rk), 1000);
  server->_drainLogic();
  BOOST_CHECK_EQUAL(bal(pk), 9000);
  BOOST_CHECK_EQUAL(bal(rk), due);
}

// The payee gets no more than the room under BALANCE_MAX, and the payer pays
// only the part that the payee gets.
BOOST_AUTO_TEST_CASE(AFullPayeeGetsOnlyItsRoom) {
  KeyPair payer, payee;
  const auto pk = payer.getPublicKeyAsHash(), ek = payee.getPublicKeyAsHash();
  server->_brr(pk, 10'000);
  server->_brr(ek, BALANCE_MAX - 100);
  server->_drainLogic();

  server->debitNetworkBill(Account::getMapKey(pk), Account::getMapKey(ek), 1000);
  server->_drainLogic();
  BOOST_CHECK_EQUAL(bal(pk), 10'000 - 1100);
  BOOST_CHECK_EQUAL(bal(ek), BALANCE_MAX);
}

// A payer short of the charge pays what it has: the server's price first,
// then the payout. At zero the account goes, as for any debit.
BOOST_AUTO_TEST_CASE(APayerShortOfTheChargePaysWhatItHas) {
  KeyPair payer, payee, poor;
  const auto pk = payer.getPublicKeyAsHash(), ek = payee.getPublicKeyAsHash();
  const auto qk = poor.getPublicKeyAsHash();
  server->_brr(pk, 1400);
  server->_brr(qk, 600);
  server->_brr(ek, 1);
  server->_drainLogic();
  const int64_t circ = server->_getTotalCredits();

  server->debitNetworkBill(Account::getMapKey(pk), Account::getMapKey(ek), 1000);
  server->_drainLogic();
  BOOST_CHECK(!server->_accountExists(pk));
  BOOST_CHECK_EQUAL(bal(ek), 1 + 400);
  BOOST_CHECK_EQUAL(server->_getTotalCredits(), circ - 1000);

  server->debitNetworkBill(Account::getMapKey(qk), Account::getMapKey(ek), 1000);
  server->_drainLogic();
  BOOST_CHECK(!server->_accountExists(qk));
  BOOST_CHECK_EQUAL(bal(ek), 1 + 400);
  BOOST_CHECK_EQUAL(server->_getTotalCredits(), circ - 1000 - 600);
}

// A network bill is the server's own, so it leaves the payer's nonce: a signed
// op that the payer runs at the same time keeps the nonce that it expects.
BOOST_AUTO_TEST_CASE(ABillLeavesTheNonce) {
  KeyPair payer;
  const auto pk = payer.getPublicKeyAsHash();
  server->_brr(pk, 10'000);
  server->_drainLogic();
  const uint32_t nonce = server->_nonceOf(pk);
  server->debitNetworkBill(Account::getMapKey(pk), HashPrefix{}, 1000);
  server->_drainLogic();
  BOOST_CHECK_EQUAL(bal(pk), 9000);
  BOOST_CHECK_EQUAL(server->_nonceOf(pk), nonce);
}

// A charge beyond int64 (the price times the factor) moves nothing and mints
// nothing, even when the price alone would fit.
BOOST_AUTO_TEST_CASE(AChargeBeyondInt64NeverMints) {
  KeyPair payer, payee;
  const auto pk = payer.getPublicKeyAsHash(), ek = payee.getPublicKeyAsHash();
  server->_brr(pk, 1000);
  server->_brr(ek, 1);
  server->_drainLogic();
  const int64_t circ = server->_getTotalCredits();

  for (uint64_t amount : {uint64_t{7'000'000'000'000'000'000ULL},
                          std::numeric_limits<uint64_t>::max()}) {
    server->debitNetworkBill(Account::getMapKey(pk), Account::getMapKey(ek), amount);
    server->_drainLogic();
    BOOST_CHECK_EQUAL(bal(pk), 1000);
    BOOST_CHECK_EQUAL(bal(ek), 1);
    BOOST_CHECK_EQUAL(server->_getTotalCredits(), circ);
  }
}

// The bus report pays the payee the same way, at the price of the usage.
BOOST_AUTO_TEST_CASE(TheBusReportPaysThePayee) {
  KeyPair payer, payee;
  const auto pk = payer.getPublicKeyAsHash(), ek = payee.getPublicKeyAsHash();
  server->_brr(pk, 10'000'000);
  server->_brr(ek, 1);
  server->_drainLogic();
  const CesPlexUsage usage{.bytesSent = 64 * 1024, .bytesReceived = 8 * 1024,
                           .memByteSeconds = 0, .ageSeconds = 1};
  const uint64_t price = server->priceNetUsage(usage);
  BOOST_REQUIRE_GT(price, 0u);

  // On the rpc thread, where the meter reports.
  runSync(server->_rpcTaskIOExecutor(), [&] {
    server->cesplexReportUsage(Account::getMapKey(pk), Account::getMapKey(ek),
                               minx::SockAddr{}, 1, usage);
  });
  server->_drainLogic();
  const uint64_t charge = price * 15000 / 10000;
  BOOST_CHECK_EQUAL(bal(pk), static_cast<int64_t>(10'000'000 - charge));
  BOOST_CHECK_EQUAL(bal(ek), static_cast<int64_t>(1 + charge - price));
}

// builtin-info gives the prices that billing charges now: the live fee
// multipliers apply, and a slot fee of 0 shows the derived price.
BOOST_AUTO_TEST_CASE(BuiltinInfoGivesThePricesOfNow) {
  const CesConfig& c = server->_config();
  server->_testSetFeeMult(FeeKind::Net, 5000);
  server->_testSetFeeMult(FeeKind::ComputeCpu, 2500);
  BOOST_REQUIRE(server->_setConfigKnob("fee_compute_slot_sec", 0));
  std::vector<ServerInfoEntry> es;
  CES_REQUIRE_OK(client->queryBuiltinInfo("compute", es));
  BOOST_CHECK_EQUAL(get(es, "feeNetKiBSent"), std::to_string(c.feeNetKiBSent / 2));
  BOOST_CHECK_EQUAL(get(es, "feeComputeCpuSec"),
                    std::to_string(c.feeComputeCpuSec / 4));
  BOOST_CHECK_NE(get(es, "feeComputeSlotSec"), "0");
  BOOST_CHECK(!get(es, "feeComputeSlotSec").empty());

  CES_REQUIRE_OK(client->queryBuiltinInfo("file", es));
  BOOST_CHECK(has(es, "fileRentBp"));
}

// The config export keeps the factor, as the decimal that the config reads.
BOOST_AUTO_TEST_CASE(TheExportKeepsTheFactor) {
  const std::string path = server->_exportConfig();
  BOOST_REQUIRE(!path.empty());
  std::ifstream f(path);
  const std::string toml((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  BOOST_CHECK(toml.find("compute_payout_factor = 1.5\n") != std::string::npos);
}

// A fee multiplied in 64 bits would wrap above 2^64 / 10000.
BOOST_AUTO_TEST_CASE(ADiscountOfABigFeeDoesNotWrap) {
  const uint64_t big = uint64_t{1} << 60;
  BOOST_CHECK_EQUAL(server->discountFee(FeeKind::Net, big), big);
  server->_testSetFeeMult(FeeKind::Net, 5000);
  BOOST_CHECK_EQUAL(server->discountFee(FeeKind::Net, big), big / 2);
}

BOOST_AUTO_TEST_SUITE_END()

// A factor below 1x would charge less than the price. The server clamps the
// factor to 1x .. 10000x, also when a program builds its config.
BOOST_AUTO_TEST_CASE(TheServerClampsTheFactor) {
  blog::init();
  blog::set_level(blog::fatal);
  for (const auto& [given, want] :
       {std::pair<uint32_t, uint32_t>{0, 10000},
        {9999, 10000},
        {CesConfig::kComputePayoutFactorMaxBp + 1, CesConfig::kComputePayoutFactorMaxBp}}) {
    auto dir = makeUniqueTempDir("payout_clamp");
    minx::Hash priv;
    priv.fill(0xB2);
    CesConfig cfg = makeTestConfig(dir, priv, std::numeric_limits<uint64_t>::max());
    cfg.computePayoutFactorBp = given;
    CesServer server(cfg);
    BOOST_CHECK_EQUAL(server._config().computePayoutFactorBp, want);
    boost::system::error_code ec;
    fs::remove_all(dir, ec);
  }
}

// A builtin-info reply that would not fit one datagram fails, and costs
// nothing. Here the operator mounts file under many long protocol names.
struct LongMountsFixture : BuiltinInfoFixture {
  LongMountsFixture() : BuiltinInfoFixture([](CesConfig& c) {
    for (int i = 0; i < 8; ++i)
      c.cesplexMounts["/ces/file/" + std::to_string(i) + "/" + std::string(150, 'x')] =
        "builtin:file";
  }) {}
};

BOOST_FIXTURE_TEST_CASE(AReplyTooBigForADatagramCostsNothing, LongMountsFixture) {
  const auto k = clientKey.getPublicKeyAsHash();
  server->_drainLogic();
  const int64_t before = bal(k);
  std::vector<ServerInfoEntry> es;
  CES_REQUIRE_RC_EQ(client->queryBuiltinInfo("file", es), CES_ERROR_INTERNAL);
  server->_drainLogic();
  BOOST_CHECK_EQUAL(bal(k), before);
  CES_REQUIRE_OK(client->queryBuiltinInfo("compute", es));
}

// When the rpc socket cannot bind, the server destroys the L2 handlers and
// keeps the main port. Its builtin lists must then be empty, so no query
// reaches a destroyed handler.
struct RpcBindFailsFixture : BuiltinInfoFixture {
  static uint16_t takenPort() {
    static boost::asio::io_context io;
    static boost::asio::ip::udp::socket sock(
      io, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v6(), 0));
    return sock.local_endpoint().port();
  }
  RpcBindFailsFixture() : BuiltinInfoFixture([](CesConfig& c) {
    c.rpcPort = takenPort();
    c.rpcAutoPort = false;
  }) {}
};

BOOST_FIXTURE_TEST_CASE(AFailedRpcBindLeavesNoBuiltins, RpcBindFailsFixture) {
  BOOST_REQUIRE_EQUAL(server->_rpcBoundPort(), 0);
  std::vector<ServerInfoEntry> es;
  CES_REQUIRE_OK(client->queryServerInfo(es));
  BOOST_CHECK_EQUAL(get(es, "builtin"), "");
  CES_REQUIRE_RC_EQ(client->queryBuiltinInfo("file", es), CES_ERROR_TARGET_NOT_FOUND);
}
