// ===========================================================================
// `cesh mail send` end-to-end — drive the real cesh binary as a subprocess.
// ===========================================================================
//
// In-process server with /ces/file/1 + /ces/mail/1 mounted and a recording
// mail sink (no real SMTP). Runs `cesh mail send ...` and asserts the sink
// captured the relayed message. This is also the first end-to-end exercise of
// the SEND verb's wire path (dispatchSend); test_mail.cpp only calls
// mailSubmit directly.

#ifdef CES_MAIL

#define BOOST_TEST_DYN_LINK
#include "test_common.h"
#include "test_e2e_common.h"

#include <ces/l2/file_client.h>
#include <ces/cesplex/mux.h>
#include <ces/l2/file_handler.h>
#include <ces/l2/mail_handler.h>
#include <ces/server.h>
#include <ces/keys.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <limits>
#include <mutex>
#include <string>
#include <thread>

using namespace ces;
using namespace ces::e2e;

namespace {

struct RecordedMail {
  std::mutex mu;
  bool got = false;
  CesServer::MailMessage last;
};

struct CeshMailFixture {
  std::unique_ptr<CesServer> server;
  fs::path tempDir;
  uint16_t mainPort = 0;
  uint16_t rpcPort = 0;
  std::string ceshBin;
  KeyPair ownerKey;
  RecordedMail rec;

  CeshMailFixture() {
    blog::init();
    blog::set_level(blog::fatal);

    tempDir = makeUniqueTempDir("cesh_mail_e2e");
    ceshBin = ces::e2e::findCeshBinary();

    minx::Hash serverPriv;
    serverPriv.fill(0xE5);
    CesConfig cfg = makeTestConfig(
      tempDir, serverPriv, std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = {
      {"/ces/file/1", "builtin:file"},
      {"/ces/mail/1", "builtin:mail"},
    };
    cfg.cesFileStoreDir = (tempDir / "cesfilestore").string();
    cfg.cesFileStoreMaxBytes = 16ull * 1024 * 1024;
    cfg.feeFileRent = 0;
    cfg.feeFileWrite = 0;
    cfg.mailFeePerMB = 1'000'000;
    cfg.mailMaxEncodedBytes = 20ull * 1024 * 1024;

    server = std::make_unique<CesServer>(cfg);
    server->_testSetMailSink([this](const CesServer::MailMessage& m) {
      std::lock_guard<std::mutex> lk(rec.mu);
      rec.last = m;
      rec.got = true;
    });
    mainPort = server->start(0);
    BOOST_REQUIRE(mainPort > 0);
    rpcPort = server->_rpcBoundPort();
    BOOST_REQUIRE(rpcPort > 0);
    server->_brr(ownerKey.getPublicKeyAsHash(), 10'000'000'000);
  }

  ~CeshMailFixture() {
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }

  std::string ownerHex() { return ownerKey.getPublicKeyHexStr(); }

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

  RunResult ceshMail(const std::string& args) {
    std::string wallet = "00" + ownerKey.getPrivateKeyHexStr();
    std::string cmd = "CESH_WALLET=\"" + wallet + "\" " + ceshBin +
                      " --server localhost:" + std::to_string(mainPort) +
                      " --rpc-port " + std::to_string(rpcPort) +
                      " -l fatal mail send " + args;
    return runShell(cmd);
  }

  bool waitGot() {
    for (int i = 0; i < 60; ++i) {
      { std::lock_guard<std::mutex> lk(rec.mu); if (rec.got) return true; }
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
  }
};

}  // namespace

BOOST_FIXTURE_TEST_SUITE(CeshMailE2E, CeshMailFixture)

// A plain message relays: the sink captures to / subject / body.
BOOST_AUTO_TEST_CASE(SendPlain) {
  RunResult r = ceshMail(
    "--to u@example.com --subject Hi --in text:BodyLine");
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  BOOST_REQUIRE(waitGot());
  std::lock_guard<std::mutex> lk(rec.mu);
  BOOST_CHECK_EQUAL(rec.last.to, "u@example.com");
  BOOST_CHECK_EQUAL(rec.last.subject, "Hi");
  BOOST_CHECK_EQUAL(rec.last.body, "BodyLine");
  BOOST_CHECK(rec.last.attachmentData.empty());
}

// A large body (100 KB) streams as the hash-committed request body; the
// envelope carries only the headers, so the body is not envelope-bounded.
BOOST_AUTO_TEST_CASE(SendLargeBody) {
  std::string big(100 * 1024, '\0');
  for (size_t i = 0; i < big.size(); ++i) big[i] = char('a' + (i % 26));
  fs::path bodyPath = tempDir / "bigbody.txt";
  { std::ofstream ofs(bodyPath, std::ios::binary); ofs << big; }
  RunResult r = ceshMail(
    "--to u@example.com --subject Big --in file:" + bodyPath.string());
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  BOOST_REQUIRE(waitGot());
  std::lock_guard<std::mutex> lk(rec.mu);
  BOOST_CHECK_EQUAL(rec.last.body.size(), big.size());
  BOOST_CHECK(rec.last.body == big);
}

// A private /m/ attachment owned by the signer relays with the file intact.
BOOST_AUTO_TEST_CASE(SendWithAttachment) {
  std::string path = "/m/" + ownerHex() + "/note.txt";
  putFile(path, "ATTACH-DATA");
  RunResult r = ceshMail(
    "--to u@example.com --subject WithAtt --in text:seeattached --attach " +
    path);
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  BOOST_REQUIRE(waitGot());
  std::lock_guard<std::mutex> lk(rec.mu);
  BOOST_CHECK_EQUAL(rec.last.attachmentName, "note.txt");
  BOOST_CHECK_EQUAL(rec.last.attachmentData, "ATTACH-DATA");
}

// A private /m/ attachment owned by someone else is refused; nothing relays.
BOOST_AUTO_TEST_CASE(SendForeignAttachmentFails) {
  std::string foreign = "/m/" + std::string(64, 'a') + "/x.bin";
  RunResult r = ceshMail(
    "--to u@example.com --subject Nope --in text:x --attach " + foreign);
  BOOST_CHECK_NE(r.exitCode, 0);
  assertContains(r.out, "Failed", "error diagnostic");
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  std::lock_guard<std::mutex> lk(rec.mu);
  BOOST_CHECK(!rec.got);
}

BOOST_AUTO_TEST_SUITE_END()

#endif  // CES_MAIL
