// builtin:think with a conversation file: the server sends the backend the
// file's content plus the new text, returns only the reply, and appends the
// text and the reply to the file when the signer owns it. The reply's file
// status is the APPEND's status code. A scripted backend (no network)
// records what it was sent.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"

#include <ces/keys.h>
#include <ces/server.h>
#include <ces/l2/file_client.h>
#include <ces/l2/think_backend.h>
#include <ces/l2/think_client.h>
#include <ces/l2/think_handler.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>

using namespace ces;

namespace {

// Replies with a fixed text; records each input; can block until released.
// With `blockIf` set, only an input that ends with it blocks.
struct EchoBackend : ThinkBackend {
  std::string reply = "Hello there!";
  bool block = false;
  std::string blockIf;
  std::atomic<bool> release{false};
  std::atomic<bool> entered{false};
  std::atomic<int> calls{0};
  std::mutex mu;
  std::string lastInput;

  ThinkOutcome run(const std::string& input, uint32_t,
                   const std::atomic<bool>& stop,
                   const std::function<bool(std::string_view)>& onText)
      override {
    ++calls;
    {
      std::lock_guard<std::mutex> lk(mu);
      lastInput = input;
    }
    entered = true;
    const bool blocks =
        block && (blockIf.empty() ||
                  (input.size() >= blockIf.size() &&
                   input.compare(input.size() - blockIf.size(),
                                 blockIf.size(), blockIf) == 0));
    while (blocks && !stop.load() && !release.load())
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    ThinkOutcome o;
    if (stop.load()) { o.status = CES_ERROR_INTERNAL; return o; }
    onText(reply);
    o.status = CES_OK;
    o.billing = ThinkOutcome::kUsage;
    o.usage = ThinkUsage{10, 0, 3};
    return o;
  }
  std::string input() {
    std::lock_guard<std::mutex> lk(mu);
    return lastInput;
  }
};

struct ThinkFileFixture {
  fs::path dir;
  std::unique_ptr<CesServer> server;
  uint16_t rpcPort = 0;
  KeyPair owner, other;
  std::shared_ptr<EchoBackend> backend = std::make_shared<EchoBackend>();

  ThinkFileFixture() {
    blog::init();
    blog::set_level(blog::fatal);
    dir = makeUniqueTempDir("thinkfile");
    minx::Hash priv;
    priv.fill(0xEB);
    CesConfig cfg = makeTestConfig(dir, priv,
                                   std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = {{"/ces/file/1", "builtin:file"},
                         {"/ces/think/1", "builtin:think"}};
    cfg.cesFileStoreDir = (dir / "cesfilestore").string();
    cfg.cesFileStoreMaxBytes = 16ull * 1024 * 1024;
    cfg.feeQuery = 0;
    cfg.thinkFeeIn = 1'000'000;
    cfg.thinkFeeOut = 2'000'000;
    cfg.thinkMaxOutTokens = 100;
    server = std::make_unique<CesServer>(cfg);
    server->start(0);
    rpcPort = server->_rpcBoundPort();
    server->thinkHandler()->_testSetBackend(backend);
    server->_brr(owner.getPublicKeyAsHash(), 10'000'000'000);
    server->_brr(other.getPublicKeyAsHash(), 10'000'000'000);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  ~ThinkFileFixture() {
    backend->release = true;
    if (server) server->stop();
    boost::system::error_code ec;
    fs::remove_all(dir, ec);
  }

  std::string chat() { return "/h/" + owner.getPublicKeyHexStr() + "/chat.txt"; }

  void putFile(const std::string& path, const std::string& data) {
    CesFileClient fc;
    fc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(fc.connect("localhost", rpcPort, owner));
    uint64_t fb = 0, cost = 0;
    CES_REQUIRE_OK(fc.create(path, data.size(), 0, 100'000'000, fb, cost));
    CES_REQUIRE_OK(fc.write(path, 0, ces::Bytes(data.begin(), data.end()), fb));
    fc.disconnect();
  }
  std::string getFile(const std::string& path) {
    CesFileClient fc;
    fc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    if (fc.connect("localhost", rpcPort, owner) != CES_OK) return "<err>";
    CesFileClient::StatInfo st{};
    if (fc.stat(path, st) != CES_OK) return "<err>";
    ces::Bytes out;
    minx::Hash h;
    if (st.size > 0 &&
        fc.read(path, 0, static_cast<uint32_t>(st.size), out, h) != CES_OK)
      return "<err>";
    fc.disconnect();
    return std::string(out.begin(), out.end());
  }
  uint8_t think(const KeyPair& who, const std::string& text,
                const std::string& file, std::string& reply,
                uint8_t& appendError) {
    CesThinkClient tc;
    tc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    if (tc.connect("localhost", rpcPort, who) != CES_OK)
      return CES_ERROR_INTERNAL;
    uint64_t charged = 0;
    return tc.think(text, nullptr, reply, charged, file, &appendError);
  }
};

}  // namespace

BOOST_FIXTURE_TEST_SUITE(ThinkFileTests, ThinkFileFixture)

// ("hi!", file) sends file + "hi!", returns only the reply, and the file
// grows by "hi!" + reply. The next turn sends the whole transcript.
BOOST_AUTO_TEST_CASE(File_IsContext_AndGrowsByEachTurn) {
  putFile(chat(), "og|");
  std::string reply;
  uint8_t appendError = 0xFF;
  CES_REQUIRE_OK(think(owner, "hi!", chat(), reply, appendError));
  BOOST_CHECK_EQUAL(reply, "Hello there!");
  BOOST_CHECK_EQUAL(appendError, CES_OK);
  BOOST_CHECK_EQUAL(backend->input(), "og|hi!");
  BOOST_CHECK_EQUAL(getFile(chat()), "og|hi!Hello there!");

  backend->reply = "nothing new";
  CES_REQUIRE_OK(think(owner, "so whazap?", chat(), reply, appendError));
  BOOST_CHECK_EQUAL(reply, "nothing new");
  BOOST_CHECK_EQUAL(appendError, CES_OK);
  BOOST_CHECK_EQUAL(backend->input(), "og|hi!Hello there!so whazap?");
  BOOST_CHECK_EQUAL(getFile(chat()),
                    "og|hi!Hello there!so whazap?nothing new");
}

// A signer who does not own the file uses it as context only.
BOOST_AUTO_TEST_CASE(NotOwner_ContextOnly) {
  putFile(chat(), "shared|");
  std::string reply;
  uint8_t appendError = 0xFF;
  CES_REQUIRE_OK(think(other, "hi!", chat(), reply, appendError));
  BOOST_CHECK_EQUAL(appendError, CES_ERROR_NOT_OWNER);
  BOOST_CHECK_EQUAL(backend->input(), "shared|hi!");
  BOOST_CHECK_EQUAL(getFile(chat()), "shared|");
}

// A file whose balance cannot pay the append: the reply comes back, the
// file does not change, and the file status says why.
BOOST_AUTO_TEST_CASE(UnfundedFile_ReplyButNoAppend) {
  putFile(chat(), "og|");
  {
    CesFileClient fc;
    fc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(fc.connect("localhost", rpcPort, owner));
    CesFileClient::StatInfo st{};
    CES_REQUIRE_OK(fc.stat(chat(), st));
    BOOST_REQUIRE_GT(st.fileBalance, 1u);
    uint64_t fb = 0;
    CES_REQUIRE_OK(fc.withdraw(chat(), st.fileBalance - 1, fb));
    BOOST_REQUIRE_EQUAL(fb, 1u);
  }
  std::string reply;
  uint8_t appendError = 0xFF;
  CES_REQUIRE_OK(think(owner, "hi!", chat(), reply, appendError));
  BOOST_CHECK_EQUAL(reply, "Hello there!");
  BOOST_CHECK_EQUAL(appendError, CES_ERROR_INSUFFICIENT_BALANCE);
  BOOST_CHECK_EQUAL(getFile(chat()), "og|");
}

// A missing file refuses the call before the backend runs.
BOOST_AUTO_TEST_CASE(MissingFile_Refused) {
  std::string reply;
  uint8_t appendError = 0xFF;
  BOOST_CHECK_EQUAL(think(owner, "hi!", chat(), reply, appendError),
                    CES_ERROR_FILE_NOT_FOUND);
  BOOST_CHECK_EQUAL(backend->calls.load(), 0);
}

// No file: the call is plain text in, text out.
BOOST_AUTO_TEST_CASE(NoFile_PlainCall) {
  std::string reply;
  uint8_t appendError = 0xFF;
  CES_REQUIRE_OK(think(owner, "hi!", "", reply, appendError));
  BOOST_CHECK_EQUAL(appendError, CES_OK);   // the normal outcome: no file
  BOOST_CHECK_EQUAL(backend->input(), "hi!");
}

// One call at a time per file: a second call on the same path is refused,
// so two turns never answer the same transcript.
BOOST_AUTO_TEST_CASE(SameFile_OneCallAtATime) {
  putFile(chat(), "og|");
  backend->block = true;
  uint8_t rc1 = CES_ERROR_INTERNAL;
  std::thread first([&] {
    std::string reply;
    uint8_t appendError = 0xFF;
    rc1 = think(owner, "one", chat(), reply, appendError);
  });
  for (int i = 0; i < 400 && !backend->entered.load(); ++i)
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  BOOST_REQUIRE(backend->entered.load());
  std::string reply;
  uint8_t appendError = 0xFF;
  BOOST_CHECK_EQUAL(think(owner, "two", chat(), reply, appendError),
                    CES_ERROR_QUEUE_FULL);
  backend->release = true;
  first.join();
  BOOST_CHECK_EQUAL(rc1, CES_OK);
  BOOST_CHECK_EQUAL(getFile(chat()), "og|oneHello there!");
}

// A signer who does not own the file cannot append to it, so its call does
// not lock the file. The owner's turn runs while that call waits.
BOOST_AUTO_TEST_CASE(NotOwner_DoesNotLockTheFile) {
  putFile(chat(), "og|");
  backend->block = true;
  backend->blockIf = "peek";
  uint8_t rcOther = CES_ERROR_INTERNAL;
  std::thread first([&] {
    std::string reply;
    uint8_t appendError = 0xFF;
    rcOther = think(other, "peek", chat(), reply, appendError);
  });
  for (int i = 0; i < 400 && !backend->entered.load(); ++i)
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  BOOST_REQUIRE(backend->entered.load());
  std::string reply;
  uint8_t appendError = 0xFF;
  BOOST_CHECK_EQUAL(think(owner, "mine", chat(), reply, appendError), CES_OK);
  BOOST_CHECK_EQUAL(appendError, CES_OK);
  backend->release = true;
  first.join();
  BOOST_CHECK_EQUAL(rcOther, CES_OK);
  BOOST_CHECK_EQUAL(getFile(chat()), "og|mineHello there!");
}

// The file is free again before the reply ends, so the next turn on the
// same channel never gets QUEUE_FULL.
BOOST_AUTO_TEST_CASE(SameFile_NextTurnRightAway) {
  putFile(chat(), "og|");
  CesThinkClient tc;
  tc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
  CES_REQUIRE_OK(tc.connect("localhost", rpcPort, owner));
  for (int i = 0; i < 20; ++i) {
    std::string reply;
    uint64_t charged = 0;
    uint8_t appendError = 0xFF;
    CES_REQUIRE_OK(tc.think("t", nullptr, reply, charged, chat(),
                            &appendError));
    BOOST_CHECK_EQUAL(appendError, CES_OK);
  }
}

// The /m/ mail zone is private. A THINK on a /m/ path gets NOT_OWNER
// whether the file exists or not, so the status tells nothing about it.
BOOST_AUTO_TEST_CASE(MailZone_Refused) {
  std::string reply;
  uint8_t appendError = 0xFF;
  BOOST_CHECK_EQUAL(think(owner, "hi!", "/m/" + other.getPublicKeyHexStr() +
                                            "/inbox/x",
                          reply, appendError),
                    CES_ERROR_NOT_OWNER);
  BOOST_CHECK_EQUAL(backend->calls.load(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
