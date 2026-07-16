// builtin:mail tests. Exercises MailHandler::mailSubmit directly (the shared
// charge-and-send core): the per-MB fee burn, the max-size gate, can't-pay
// denial, the private /m/ owner check, and that /m/ is not wire-readable.
// Delivery is captured by a recording mail sink (no real SMTP).

#ifdef CES_MAIL

#define BOOST_TEST_DYN_LINK
#include "test_common.h"

#include <ces/account.h>
#include <ces/buffer.h>
#include <ces/client.h>
#include <ces/keys.h>
#include <ces/server.h>
#include <ces/l2/file_client.h>
#include <ces/l2/mail_handler.h>

#include <boost/test/unit_test.hpp>

#include <mutex>
#include <string>
#include <thread>

using namespace ces;

namespace {

std::string hexOf(const minx::Hash& k) {
  static const char* H = "0123456789abcdef";
  std::string s;
  s.reserve(64);
  for (uint8_t b : k) { s.push_back(H[b >> 4]); s.push_back(H[b & 0xF]); }
  return s;
}

struct RecordedMail {
  std::mutex mu;
  bool got = false;
  CesServer::MailMessage last;
};

struct MailFixture {
  fs::path dir;
  std::unique_ptr<CesServer> server;
  std::unique_ptr<CesClient> client;
  uint16_t mainPort = 0, rpcPort = 0;
  KeyPair ownerKey;
  RecordedMail rec;

  MailFixture() : MailFixture(1'000'000, 20ull * 1024 * 1024, 10'000'000'000ull) {}
  MailFixture(uint64_t feePerMB, uint64_t maxEncoded, uint64_t fund) {
    blog::init();
    blog::set_level(blog::fatal);
    dir = makeUniqueTempDir("mailh");
    minx::Hash priv;
    priv.fill(0xE7);
    CesConfig cfg = makeTestConfig(dir, priv,
                                   std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = {
      {"/ces/file/1", "builtin:file"},
      {"/ces/mail/1", "builtin:mail"},
    };
    cfg.cesFileStoreDir = (dir / "cesfilestore").string();
    cfg.cesFileStoreMaxBytes = 16ull * 1024 * 1024;
    cfg.feeFileRent = 0;
    cfg.feeFileWrite = 0;
    cfg.feeQuery = 0;
    cfg.mailFeePerMB = feePerMB;
    cfg.mailMaxEncodedBytes = maxEncoded;
    server = std::make_unique<CesServer>(cfg);
    server->_testSetMailSink([this](const CesServer::MailMessage& m) {
      std::lock_guard<std::mutex> lk(rec.mu);
      rec.last = m;
      rec.got = true;
    });
    mainPort = server->start(0);
    rpcPort = server->_rpcBoundPort();
    server->_brr(ownerKey.getPublicKeyAsHash(), fund);
    boost::asio::ip::udp::endpoint ep(
      boost::asio::ip::address_v6::loopback(), mainPort);
    client = std::make_unique<CesClient>(ep, false);
    client->start(0);
    client->setKey(ownerKey);
    client->connect();
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
  }
  ~MailFixture() {
    if (client) client->stop();
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    boost::system::error_code ec;
    fs::remove_all(dir, ec);
  }

  void putFile(const std::string& path, const std::string& data) {
    CesFileClient fc;
    fc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(fc.connect("localhost", rpcPort, ownerKey));
    uint64_t fb = 0, cost = 0;
    CES_REQUIRE_OK(fc.create(path, data.size(), 0, 100'000ull, fb, cost));
    ces::Bytes content(data.begin(), data.end());
    CES_REQUIRE_OK(fc.write(path, 0, content, fb));
    fc.disconnect();
  }
  int64_t balance() {
    int64_t bal = 0;
    uint32_t nonce = 0;
    client->queryAccount(Account::getMapKey(ownerKey.getPublicKeyAsHash()),
                         bal, nonce);
    return bal;
  }
  MailHandler* mail() { return server->mailHandler(); }
  minx::Hash me() { return ownerKey.getPublicKeyAsHash(); }
  std::string myHex() { return hexOf(ownerKey.getPublicKeyAsHash()); }
};

struct MailTinyMaxFixture : MailFixture {
  MailTinyMaxFixture() : MailFixture(1'000'000, 100, 10'000'000'000ull) {}
};
struct MailBrokeFixture : MailFixture {
  MailBrokeFixture() : MailFixture(1'000'000, 20ull * 1024 * 1024, 500'000ull) {}
};

}  // namespace

BOOST_FIXTURE_TEST_SUITE(MailTests, MailFixture)

// A small message with a private /m/ attachment: charged exactly one MB
// (burned) and delivered, attachment intact.
BOOST_AUTO_TEST_CASE(Submit_BurnsFee_AndDelivers) {
  BOOST_REQUIRE(mail() != nullptr);
  const std::string path = "/m/" + myHex() + "/att.bin";
  putFile(path, "ATTACH-DATA");
  int64_t before = balance();
  uint8_t rc = mail()->mailSubmit(me(), "u@example.com", "Hi", "Body text",
                                  path);
  BOOST_CHECK_EQUAL(rc, CES_OK);
  BOOST_CHECK_EQUAL(before - balance(), 1'000'000);   // one MB burned
  std::lock_guard<std::mutex> lk(rec.mu);
  BOOST_CHECK(rec.got);
  BOOST_CHECK_EQUAL(rec.last.to, "u@example.com");
  BOOST_CHECK_EQUAL(rec.last.body, "Body text");
  BOOST_CHECK_EQUAL(rec.last.attachmentName, "att.bin");
  BOOST_CHECK_EQUAL(rec.last.attachmentData, "ATTACH-DATA");
}

// A private /m/ attachment owned by someone else can't be sent.
BOOST_AUTO_TEST_CASE(Submit_MailZone_OwnerGated) {
  const std::string otherHex(64, 'a');
  const std::string path = "/m/" + otherHex + "/x.bin";
  uint8_t rc = mail()->mailSubmit(me(), "u@example.com", "Hi", "Body", path);
  BOOST_CHECK_EQUAL(rc, CES_ERROR_NOT_OWNER);
  std::lock_guard<std::mutex> lk(rec.mu);
  BOOST_CHECK(!rec.got);
}

// The /m/ zone is not readable over the wire -- even by its owner.
BOOST_AUTO_TEST_CASE(MailZone_NotWireReadable) {
  const std::string path = "/m/" + myHex() + "/secret.bin";
  putFile(path, "SECRET");
  CesFileClient fc;
  fc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(fc.connect("localhost", rpcPort, ownerKey));
  ces::Bytes out;
  minx::Hash h;
  uint8_t rc = fc.read(path, 0, 6, out, h);
  BOOST_CHECK(rc != CES_OK);
  fc.disconnect();
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(MailTooBigTests, MailTinyMaxFixture)
BOOST_AUTO_TEST_CASE(Submit_TooBig_RejectedBeforeCharge) {
  int64_t before = balance();
  uint8_t rc = mail()->mailSubmit(me(), "u@example.com", "Hi", "Body", "");
  BOOST_CHECK_EQUAL(rc, CES_ERROR_BAD_INPUT);   // encoded > max
  BOOST_CHECK_EQUAL(before, balance());          // nothing burned
  std::lock_guard<std::mutex> lk(rec.mu);
  BOOST_CHECK(!rec.got);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(MailBrokeTests, MailBrokeFixture)
BOOST_AUTO_TEST_CASE(Submit_CantPay_Denied) {
  int64_t before = balance();
  uint8_t rc = mail()->mailSubmit(me(), "u@example.com", "Hi", "Body", "");
  BOOST_CHECK_EQUAL(rc, CES_ERROR_INSUFFICIENT_BALANCE);
  BOOST_CHECK_EQUAL(before, balance());          // nothing burned
  std::lock_guard<std::mutex> lk(rec.mu);
  BOOST_CHECK(!rec.got);
}
BOOST_AUTO_TEST_SUITE_END()

#endif  // CES_MAIL
