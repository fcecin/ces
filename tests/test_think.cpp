// builtin:think tests. The pure helpers (request JSON, SSE parser, base URL,
// UTF-8 check, prices), then the verb end to end over a real CesPlex channel
// with a scripted backend (no network): the streamed reply, the hold and the
// refund, the refusals, the concurrency cap, and stop with a call in flight.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"
#include "test_compute_wait.h"

#include <ces/account.h>
#include <ces/client.h>
#include <ces/keys.h>
#include <ces/server.h>
#include <ces/l2/think_backend.h>
#include <ces/l2/think_client.h>
#include <ces/l2/think_handler.h>
#ifdef CES_THINK
#include <ces/l2/think_https.h>
#endif

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>
#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace ces;

namespace {

// ---------------------------------------------------------------------------
// A scripted backend.
// ---------------------------------------------------------------------------
struct ScriptBackend : ThinkBackend {
  std::vector<std::string> pieces{"Hel", "lo, ", "world."};
  ThinkUsage usage{100, 40, 3};
  ThinkOutcome::Billing billing = ThinkOutcome::kUsage;
  uint8_t status = CES_OK;
  bool block = false;              // wait for `stop` or `release`
  int gapMs = 0;                   // silence after the first piece
  bool throwOdd = false;           // throw a value that is no std::exception
  uint64_t outBytes = 0;           // ThinkOutcome::outBytes to report
  std::atomic<bool> release{false};
  std::atomic<bool> entered{false};
  std::atomic<int> calls{0};
  std::mutex mu;
  std::string lastPrompt;
  uint32_t lastMaxOut = 0;
  uint32_t window = 0;             // what contextWindow() states

  uint32_t contextWindow() override { return window; }

  ThinkOutcome run(const std::string& prompt, uint32_t maxOut,
                   const std::atomic<bool>& stop,
                   const std::function<bool(std::string_view)>& onText)
      override {
    ++calls;
    {
      std::lock_guard<std::mutex> lk(mu);
      lastPrompt = prompt;
      lastMaxOut = maxOut;
    }
    entered = true;
    if (throwOdd) throw 42;
    ThinkOutcome o;
    o.outBytes = outBytes;
    if (block) {
      while (!stop.load() && !release.load())
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
      if (stop.load()) {
        o.status = CES_ERROR_INTERNAL;
        o.billing = ThinkOutcome::kNone;
        return o;
      }
    }
    for (size_t i = 0; i < pieces.size(); ++i) {
      if (!onText(pieces[i])) {
        o.status = CES_ERROR_INTERNAL;
        o.billing = ThinkOutcome::kEstimate;
        return o;
      }
      if (i == 0 && gapMs > 0) {
        auto end = std::chrono::steady_clock::now() +
                   std::chrono::milliseconds(gapMs);
        while (!stop.load() && std::chrono::steady_clock::now() < end)
          std::this_thread::sleep_for(std::chrono::milliseconds(5));
      }
    }
    o.status = status;
    o.billing = billing;
    o.usage = usage;
    return o;
  }
};

// Fees: 1 raw unit per uncached input token, 0.1 per cached input token,
// 2 per output token.
constexpr uint64_t kFeeIn = 1'000'000;
constexpr uint64_t kFeeCachedIn = 100'000;
constexpr uint64_t kFeeOut = 2'000'000;
constexpr uint32_t kMaxOut = 1000;
constexpr uint32_t kMaxInput = 4096;

struct ThinkFixture {
  fs::path dir;
  std::unique_ptr<CesServer> server;
  std::unique_ptr<CesClient> client;
  uint16_t rpcPort = 0;
  KeyPair ownerKey;
  std::shared_ptr<ScriptBackend> backend = std::make_shared<ScriptBackend>();

  ThinkFixture() : ThinkFixture(10'000'000, kFeeIn, kFeeOut, 8, true) {}
  ThinkFixture(int64_t fund, uint64_t feeIn, uint64_t feeOut,
               uint32_t maxConcurrent, bool withBackend,
               uint64_t subsidyBudget = 0, uint32_t idleSecs = 0,
               int64_t feeQuery = 0) {
    blog::init();
    blog::set_level(blog::fatal);
    dir = makeUniqueTempDir("thinkh");
    minx::Hash priv;
    priv.fill(0xE9);
    CesConfig cfg = makeTestConfig(dir, priv,
                                   std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = {{"/ces/think/1", "builtin:think"}};
    cfg.feeQuery = feeQuery;
    cfg.thinkFeeIn = feeIn;
    cfg.thinkFeeCachedIn = kFeeCachedIn;
    cfg.thinkFeeOut = feeOut;
    cfg.thinkMaxOutTokens = kMaxOut;
    cfg.thinkMaxInputBytes = kMaxInput;
    cfg.thinkMaxConcurrent = maxConcurrent;
    cfg.thinkSubsidyBudget = subsidyBudget;
    cfg.thinkSubsidyTauSecs = 3600;
    cfg.thinkSubsidyFloorBp = 1;
    if (idleSecs > 0) cfg.rpcRudpChannelIdleSecs = idleSecs;
    server = std::make_unique<CesServer>(cfg);
    uint16_t mainPort = server->start(0);
    rpcPort = server->_rpcBoundPort();
    BOOST_REQUIRE(server->thinkHandler() != nullptr);
    if (withBackend) server->thinkHandler()->_testSetBackend(backend);
    server->_brr(ownerKey.getPublicKeyAsHash(), fund);
    boost::asio::ip::udp::endpoint ep(
      boost::asio::ip::address_v6::loopback(), mainPort);
    client = std::make_unique<CesClient>(ep, false);
    client->start(0);
    client->setKey(ownerKey);
    client->connect();
    // _brr lands on the logic strand; wait for the fund.
    BOOST_REQUIRE(waitUntil([&] { return balance() == fund; }));
  }
  ~ThinkFixture() {
    backend->release = true;
    if (client) client->stop();
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    boost::system::error_code ec;
    fs::remove_all(dir, ec);
  }

  void open(CesThinkClient& tc) {
    tc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(tc.connect("localhost", rpcPort, ownerKey));
  }
  int64_t balance() {
    int64_t bal = 0;
    uint32_t nonce = 0;
    client->queryAccount(Account::getMapKey(ownerKey.getPublicKeyAsHash()),
                         bal, nonce);
    return bal;
  }
  // Wait for the balance to reach `want` (the fee_query and the settle
  // land on the logic strand).
  bool waitBalance(int64_t want) {
    return waitUntil([&] { return balance() == want; });
  }
  ThinkFees fees() const { return ThinkFees{kFeeIn, kFeeCachedIn, kFeeOut}; }
};

struct ThinkBrokeFixture : ThinkFixture {
  ThinkBrokeFixture() : ThinkFixture(1000, kFeeIn, kFeeOut, 8, true) {}
};
struct ThinkNoBackendFixture : ThinkFixture {
  ThinkNoBackendFixture() : ThinkFixture(10'000'000, kFeeIn, kFeeOut, 8, false) {}
};
struct ThinkFreeFixture : ThinkFixture {
  ThinkFreeFixture() : ThinkFixture(10'000'000, 0, 0, 8, true) {}
};
// Subsidy on, at rest. The fund (1000) is below the full hold (2066).
struct ThinkSubsidyFixture : ThinkFixture {
  ThinkSubsidyFixture()
      : ThinkFixture(1000, kFeeIn, kFeeOut, 8, true, 1'000'000'000) {}
};
// The server drops a channel after 1 s with no traffic.
struct ThinkShortIdleFixture : ThinkFixture {
  ThinkShortIdleFixture()
      : ThinkFixture(10'000'000, kFeeIn, kFeeOut, 8, true, 0, 1) {}
};
// Each THINK pays fee_query 5.
struct ThinkFeeQueryFixture : ThinkFixture {
  ThinkFeeQueryFixture()
      : ThinkFixture(10'000'000, kFeeIn, kFeeOut, 8, true, 0, 0, 5) {}
};
// Subsidy on, at rest, with a budget of 4000: more than the expected cost
// of a 3000-byte prompt (3064), less than its hold (5064).
struct ThinkSmallBudgetFixture : ThinkFixture {
  ThinkSmallBudgetFixture()
      : ThinkFixture(10'000'000, kFeeIn, kFeeOut, 8, true, 4000) {}
};
struct ThinkOneSlotFixture : ThinkFixture {
  ThinkOneSlotFixture() : ThinkFixture(10'000'000, kFeeIn, kFeeOut, 1, true) {}
};

// A DeepSeek stream as the API sends it: a role chunk, reasoning deltas,
// content deltas, a usage chunk, [DONE].
const std::string kSse =
  "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\","
  "\"content\":null,\"reasoning_content\":\"\"},\"finish_reason\":null}],"
  "\"usage\":null}\n\n"
  ": keep-alive\n\n"
  "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":null,"
  "\"reasoning_content\":\"We need\"},\"finish_reason\":null}],"
  "\"usage\":null}\n\n"
  "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hi\","
  "\"reasoning_content\":null},\"finish_reason\":null}],\"usage\":null}\n\n"
  "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\" th\\u00e9re\\n\","
  "\"reasoning_content\":null},\"finish_reason\":null}],\"usage\":null}\n\n"
  "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"\","
  "\"reasoning_content\":null},\"finish_reason\":\"stop\"}],\"usage\":"
  "{\"prompt_tokens\":36,\"completion_tokens\":57,\"total_tokens\":93,"
  "\"prompt_tokens_details\":{\"cached_tokens\":0},"
  "\"completion_tokens_details\":{\"reasoning_tokens\":53},"
  "\"prompt_cache_hit_tokens\":32,\"prompt_cache_miss_tokens\":4}}\n\n"
  "data: [DONE]\n\n";

}  // namespace

// ===========================================================================
// Pure helpers
// ===========================================================================

BOOST_AUTO_TEST_SUITE(ThinkHelperTests)

BOOST_AUTO_TEST_CASE(Sse_WholeAndEveryByteSplit) {
  for (size_t step : {kSse.size(), size_t(1), size_t(7), size_t(64)}) {
    ThinkSseParser p;
    std::string text;
    for (size_t i = 0; i < kSse.size(); i += step) {
      BOOST_REQUIRE(p.feed(std::string_view(kSse).substr(i, step),
                           [&](std::string_view t) {
                             text.append(t);
                             return true;
                           }));
    }
    BOOST_CHECK_EQUAL(text, "Hi th\xc3\xa9re\n");   // reasoning skipped
    BOOST_CHECK(p.done());
    BOOST_CHECK(p.hasUsage());
    BOOST_CHECK_EQUAL(p.usage().promptTokens, 36u);
    BOOST_CHECK_EQUAL(p.usage().cachedTokens, 32u);
    BOOST_CHECK_EQUAL(p.usage().outputTokens, 57u);
    BOOST_CHECK(p.error().empty());
  }
}

BOOST_AUTO_TEST_CASE(Sse_CrlfAndCachedTokensDetail) {
  const std::string s =
    "data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\r\n\r\n"
    "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":10,"
    "\"completion_tokens\":2,\"prompt_tokens_details\":{\"cached_tokens\":6}}}"
    "\r\n\r\ndata: [DONE]\r\n\r\n";
  ThinkSseParser p;
  std::string text;
  BOOST_REQUIRE(p.feed(s, [&](std::string_view t) { text.append(t); return true; }));
  BOOST_CHECK_EQUAL(text, "a");
  BOOST_CHECK(p.done());
  BOOST_CHECK_EQUAL(p.usage().cachedTokens, 6u);
}

BOOST_AUTO_TEST_CASE(Sse_StopAndErrorAndMalformed) {
  ThinkSseParser stopP;
  int n = 0;
  BOOST_REQUIRE(stopP.feed(kSse, [&](std::string_view) { ++n; return false; }));
  BOOST_CHECK_EQUAL(n, 1);
  BOOST_CHECK(stopP.stopped());

  ThinkSseParser errP;
  BOOST_REQUIRE(errP.feed("data: {\"error\":{\"message\":\"overloaded\"}}\n\n",
                          [](std::string_view) { return true; }));
  BOOST_CHECK_EQUAL(errP.error(), "overloaded");

  ThinkSseParser badP;
  BOOST_CHECK(!badP.feed("data: {not json\n\n",
                         [](std::string_view) { return true; }));
}

// After onText says stop, the parser sends no more text, but it still reads
// the usage and the end of the stream, so the call is billed by usage.
BOOST_AUTO_TEST_CASE(Sse_StoppedReaderStillReadsUsage) {
  for (size_t step : {kSse.size(), size_t(1), size_t(13)}) {
    ThinkSseParser p;
    int n = 0;
    for (size_t i = 0; i < kSse.size(); i += step)
      BOOST_REQUIRE(p.feed(std::string_view(kSse).substr(i, step),
                           [&](std::string_view) { ++n; return false; }));
    BOOST_CHECK_EQUAL(n, 1);
    BOOST_CHECK(p.stopped());
    BOOST_CHECK(p.done());
    BOOST_REQUIRE(p.hasUsage());
    BOOST_CHECK_EQUAL(p.usage().promptTokens, 36u);
    BOOST_CHECK_EQUAL(p.usage().outputTokens, 57u);
  }
}

// Reasoning text is counted for the estimate, and is not reply text.
BOOST_AUTO_TEST_CASE(Sse_CountsReasoningBytes) {
  ThinkSseParser p;
  std::string text;
  BOOST_REQUIRE(p.feed(kSse, [&](std::string_view t) { text.append(t); return true; }));
  BOOST_CHECK_EQUAL(p.reasoningBytes(), 7u);   // "We need"
  BOOST_CHECK_EQUAL(p.textBytes(), text.size());
}

// Bytes with no event end are not buffered without bound.
BOOST_AUTO_TEST_CASE(Sse_UnboundedEventIsMalformed) {
  ThinkSseParser p;
  const std::string junk(256 * 1024, 'x');
  bool ok = true;
  for (int i = 0; i < 5 && ok; ++i)
    ok = p.feed(junk, [](std::string_view) { return true; });
  BOOST_CHECK(!ok);
}

BOOST_AUTO_TEST_CASE(RequestJson_FieldsAndEscapes) {
  std::string j = thinkRequestJson("deepseek-flash", "say \"hi\"\n", 77, false);
  BOOST_CHECK(j.find("\"model\":\"deepseek-flash\"") != std::string::npos);
  BOOST_CHECK(j.find("\"role\":\"user\"") != std::string::npos);
  BOOST_CHECK(j.find("\"content\":\"say \\\"hi\\\"\\n\"") != std::string::npos);
  BOOST_CHECK(j.find("\"max_tokens\":77") != std::string::npos);
  BOOST_CHECK(j.find("\"stream\":true") != std::string::npos);
  BOOST_CHECK(j.find("\"include_usage\":true") != std::string::npos);
  BOOST_CHECK(j.find("\"type\":\"disabled\"") != std::string::npos);
  BOOST_CHECK(thinkRequestJson("m", "x", 1, true).find("\"type\":\"enabled\"") !=
              std::string::npos);
}

BOOST_AUTO_TEST_CASE(ErrorMessage_JsonOrRaw) {
  BOOST_CHECK_EQUAL(
    thinkErrorMessage("{\"error\":{\"message\":\"bad key\",\"type\":\"x\"}}"),
    "bad key");
  BOOST_CHECK_EQUAL(thinkErrorMessage("plain text"), "plain text");
}

BOOST_AUTO_TEST_CASE(BaseUrl_Parse) {
  bool tls = false;
  std::string h, p, pre;
  BOOST_REQUIRE(thinkParseBaseUrl("https://api.deepseek.com", tls, h, p, pre));
  BOOST_CHECK(tls);
  BOOST_CHECK_EQUAL(h, "api.deepseek.com");
  BOOST_CHECK_EQUAL(p, "443");
  BOOST_CHECK_EQUAL(pre, "");
  BOOST_REQUIRE(thinkParseBaseUrl("http://localhost:8080/v1/", tls, h, p, pre));
  BOOST_CHECK(!tls);
  BOOST_CHECK_EQUAL(h, "localhost");
  BOOST_CHECK_EQUAL(p, "8080");
  BOOST_CHECK_EQUAL(pre, "/v1");
  BOOST_CHECK(!thinkParseBaseUrl("ftp://x", tls, h, p, pre));
  BOOST_CHECK(!thinkParseBaseUrl("https://", tls, h, p, pre));
  BOOST_CHECK(!thinkParseBaseUrl("https://h:x1/", tls, h, p, pre));
}

// The model list of DeepSeek's API (its documented example): the window of
// the configured model. There is no standard field; other lists give 0.
BOOST_AUTO_TEST_CASE(ModelWindow_FromTheModelList) {
  const std::string list = R"({"object":"list","data":[
    {"id":"deepseek-flash","object":"model","owned_by":"deepseek",
     "context_window":1048576,"max_output_tokens":393216},
    {"id":"deepseek-v4-pro","object":"model","owned_by":"deepseek",
     "context_window":1048576,"max_output_tokens":393216}]})";
  BOOST_CHECK_EQUAL(thinkModelWindow(list, "deepseek-flash"), 1048576u);
  BOOST_CHECK_EQUAL(thinkModelWindow(list, "other-model"), 0u);
  BOOST_CHECK_EQUAL(thinkModelWindow(R"({"data":[{"id":"gpt-x","object":"model"}]})", "gpt-x"), 0u);
  BOOST_CHECK_EQUAL(thinkModelWindow("not json", "deepseek-flash"), 0u);
  BOOST_CHECK_EQUAL(thinkModelWindow(R"({"data":{}})", "deepseek-flash"), 0u);
}

// The operator's ceiling only lowers the API's window, and stands in for it
// when the API states none.
BOOST_AUTO_TEST_CASE(ModelWindow_CeilingOnlyLowers) {
  BOOST_CHECK_EQUAL(thinkWindow(0, 0), 0u);
  BOOST_CHECK_EQUAL(thinkWindow(0, 1048576), 1048576u);
  BOOST_CHECK_EQUAL(thinkWindow(200000, 1048576), 200000u);
  BOOST_CHECK_EQUAL(thinkWindow(2000000, 1048576), 1048576u);
  BOOST_CHECK_EQUAL(thinkWindow(200000, 0), 200000u);
}

BOOST_AUTO_TEST_CASE(Utf8_Check) {
  BOOST_CHECK(thinkValidUtf8("plain"));
  BOOST_CHECK(thinkValidUtf8("ol\xc3\xa1 \xe2\x82\xac \xf0\x9f\x9a\x80"));
  BOOST_CHECK(!thinkValidUtf8("\xff"));
  BOOST_CHECK(!thinkValidUtf8("\xc3"));               // cut short
  BOOST_CHECK(!thinkValidUtf8("\xc0\xaf"));           // overlong
  BOOST_CHECK(!thinkValidUtf8("\xed\xa0\x80"));       // surrogate
  BOOST_CHECK(!thinkValidUtf8("\xf4\x90\x80\x80"));   // past U+10FFFF
}

BOOST_AUTO_TEST_CASE(Prices_RoundUpAndHoldCoversUsage) {
  ThinkFees f{kFeeIn, kFeeCachedIn, kFeeOut};
  // 60 uncached + 40 cached * 0.1 + 3 out * 2 = 60 + 4 + 6.
  BOOST_CHECK_EQUAL(thinkCost(f, ThinkUsage{100, 40, 3}), 70u);
  // 0.1 rounds up to 1.
  BOOST_CHECK_EQUAL(thinkCost(f, ThinkUsage{1, 1, 0}), 1u);
  BOOST_CHECK_EQUAL(thinkCost(f, ThinkUsage{0, 0, 0}), 0u);
  // Cached never counts above the prompt.
  BOOST_CHECK_EQUAL(thinkCost(f, ThinkUsage{10, 50, 0}), 1u);
  BOOST_CHECK_EQUAL(thinkHold(f, 8, 1000), (8 + kThinkPromptOverhead) + 2000);
  // The estimate counts each prompt byte as a token, as the hold does: a
  // caller can make text that is one token per byte. The reply counts one
  // token per 3 bytes.
  BOOST_CHECK_EQUAL(thinkEstimate(f, 30, 9),
                    (30 + kThinkPromptOverhead) + 2 * 4);
  // Huge values clamp, never wrap.
  ThinkFees big{UINT64_MAX, UINT64_MAX, UINT64_MAX};
  BOOST_CHECK_EQUAL(thinkHold(big, UINT32_MAX, UINT32_MAX), UINT64_MAX);
}

BOOST_AUTO_TEST_SUITE_END()

// ===========================================================================
// The verb, end to end
// ===========================================================================

BOOST_FIXTURE_TEST_SUITE(ThinkTests, ThinkFixture)

// The reply streams piece by piece, the server signs its hash, and the
// signer pays the cost of the reported usage, no more.
BOOST_AUTO_TEST_CASE(Think_StreamsAndChargesUsage) {
  CesThinkClient tc;
  open(tc);
  const int64_t before = balance();
  std::vector<std::string> got;
  std::string reply;
  uint64_t charged = 0;
  uint8_t rc = tc.think("hi there",
                        [&](std::string_view t) { got.emplace_back(t); },
                        reply, charged);
  CES_REQUIRE_OK(rc);
  BOOST_CHECK_EQUAL(reply, "Hello, world.");
  BOOST_REQUIRE_EQUAL(got.size(), 3u);
  BOOST_CHECK_EQUAL(got[0], "Hel");
  BOOST_CHECK_EQUAL(got[2], "world.");
  BOOST_CHECK_EQUAL(charged, thinkCost(fees(), backend->usage));
  BOOST_CHECK(waitBalance(before - static_cast<int64_t>(charged)));
  std::lock_guard<std::mutex> lk(backend->mu);
  BOOST_CHECK_EQUAL(backend->lastPrompt, "hi there");
  BOOST_CHECK_EQUAL(backend->lastMaxOut, kMaxOut);
}

// A caller that asks gets the report: what the call used, and the limits of
// the server. A caller that does not ask gets the old reply, on the same
// channel.
BOOST_AUTO_TEST_CASE(Think_ReportsUsageAndLimits) {
  CesThinkClient tc;
  open(tc);
  std::string reply;
  uint64_t charged = 0;
  ThinkReport rep;
  CES_REQUIRE_OK(tc.think("hi there", nullptr, reply, charged, {}, nullptr, &rep));
  BOOST_CHECK_EQUAL(reply, "Hello, world.");
  BOOST_CHECK_EQUAL(charged, thinkCost(fees(), backend->usage));
  BOOST_CHECK(rep.usageKnown);
  BOOST_CHECK_EQUAL(rep.usage.promptTokens, 100u);
  BOOST_CHECK_EQUAL(rep.usage.cachedTokens, 40u);
  BOOST_CHECK_EQUAL(rep.usage.outputTokens, 3u);
  BOOST_CHECK_EQUAL(rep.maxInputBytes, kMaxInput);
  BOOST_CHECK_EQUAL(rep.maxOutTokens, kMaxOut);
  BOOST_CHECK_EQUAL(rep.contextTokens, 0u);   // the API states none, no ceiling

  // The window that the model API states reaches the caller.
  backend->window = 1048576;
  CES_REQUIRE_OK(tc.think("window", nullptr, reply, charged, {}, nullptr, &rep));
  BOOST_CHECK_EQUAL(rep.contextTokens, 1048576u);

  uint8_t appendError = 0xff;
  CES_REQUIRE_OK(tc.think("again", nullptr, reply, charged, {}, &appendError));
  BOOST_CHECK_EQUAL(appendError, CES_OK);   // no report bit leaks into it

  // A call with no usage report from the backend: the limits, no usage.
  backend->billing = ThinkOutcome::kEstimate;
  CES_REQUIRE_OK(tc.think("estimate", nullptr, reply, charged, {}, nullptr, &rep));
  BOOST_CHECK(!rep.usageKnown);
  BOOST_CHECK_EQUAL(rep.maxOutTokens, kMaxOut);
}

// One channel serves many calls.
BOOST_AUTO_TEST_CASE(Think_ChannelLoops) {
  CesThinkClient tc;
  open(tc);
  for (int i = 0; i < 3; ++i) {
    std::string reply;
    uint64_t charged = 0;
    CES_REQUIRE_OK(tc.think("again", nullptr, reply, charged));
    BOOST_CHECK_EQUAL(reply, "Hello, world.");
  }
  BOOST_CHECK_EQUAL(backend->calls.load(), 3);
}

// A backend failure before billable work: an error status, a partial reply,
// and the whole hold back.
BOOST_AUTO_TEST_CASE(Think_FailureWithNoWorkIsFree) {
  backend->pieces = {"part"};
  backend->status = CES_ERROR_TIMEOUT;
  backend->billing = ThinkOutcome::kNone;
  CesThinkClient tc;
  open(tc);
  const int64_t before = balance();
  std::string reply;
  uint64_t charged = 0;
  uint8_t rc = tc.think("hello", nullptr, reply, charged);
  BOOST_CHECK_EQUAL(rc, CES_ERROR_TIMEOUT);
  BOOST_CHECK_EQUAL(reply, "part");
  BOOST_CHECK(waitBalance(before));
}

// A failure with no usage report is charged the size estimate.
BOOST_AUTO_TEST_CASE(Think_FailureWithoutUsageIsEstimated) {
  backend->status = CES_ERROR_INTERNAL;
  backend->billing = ThinkOutcome::kEstimate;
  CesThinkClient tc;
  open(tc);
  const int64_t before = balance();
  std::string reply;
  uint64_t charged = 0;
  const std::string prompt = "a prompt of thirty bytes......";
  BOOST_REQUIRE_EQUAL(prompt.size(), 30u);
  uint8_t rc = tc.think(prompt, nullptr, reply, charged);
  BOOST_CHECK_EQUAL(rc, CES_ERROR_INTERNAL);
  BOOST_CHECK_EQUAL(reply, "Hello, world.");
  const int64_t est =
      static_cast<int64_t>(thinkEstimate(fees(), prompt.size(), reply.size()));
  BOOST_CHECK(waitBalance(before - est));
}

// The estimate counts the reasoning text that the backend reports in
// outBytes, not only the reply text that reached the caller.
BOOST_AUTO_TEST_CASE(Think_EstimateCountsReasoning) {
  backend->status = CES_ERROR_INTERNAL;
  backend->billing = ThinkOutcome::kEstimate;
  backend->outBytes = 1500;   // 501 tokens: under the hold
  CesThinkClient tc;
  open(tc);
  const int64_t before = balance();
  std::string reply;
  uint64_t charged = 0;
  BOOST_CHECK_EQUAL(tc.think("hello", nullptr, reply, charged),
                    CES_ERROR_INTERNAL);
  const int64_t est =
      static_cast<int64_t>(thinkEstimate(fees(), 5, 1500));
  BOOST_CHECK(waitBalance(before - est));
}

// A backend that throws a value that is no std::exception ends the call
// with INTERNAL. The server keeps running.
BOOST_AUTO_TEST_CASE(Think_BackendThrowingAnythingIsInternal) {
  backend->throwOdd = true;
  CesThinkClient tc;
  open(tc);
  std::string reply;
  uint64_t charged = 0;
  BOOST_CHECK_EQUAL(tc.think("hello", nullptr, reply, charged),
                    CES_ERROR_INTERNAL);
  backend->throwOdd = false;
  CES_CHECK_OK(tc.think("again", nullptr, reply, charged));
}

// Bad prompts are refused before the backend runs, and the client still
// works after a refusal that closed the channel.
BOOST_AUTO_TEST_CASE(Think_BadInput) {
  CesThinkClient tc;
  open(tc);
  std::string reply;
  uint64_t charged = 0;
  BOOST_CHECK_EQUAL(tc.think("\xff\xfe", nullptr, reply, charged),
                    CES_ERROR_BAD_INPUT);
  BOOST_CHECK_EQUAL(tc.think(std::string(kMaxInput + 1, 'x'), nullptr, reply,
                             charged),
                    CES_ERROR_BAD_INPUT);
  BOOST_CHECK_EQUAL(tc.think("", nullptr, reply, charged), CES_ERROR_BAD_INPUT);
  BOOST_CHECK_EQUAL(backend->calls.load(), 0);
  CES_REQUIRE_OK(tc.think("fine", nullptr, reply, charged));
  BOOST_CHECK_EQUAL(backend->calls.load(), 1);
}

// stop() with a call in flight ends the call, returns the hold, and joins.
BOOST_AUTO_TEST_CASE(Think_StopWithCallInFlight) {
  backend->block = true;
  CesThinkClient tc;
  open(tc);
  const int64_t before = balance();
  uint8_t rc = CES_OK;
  std::thread caller([&] {
    std::string reply;
    uint64_t charged = 0;
    rc = tc.think("wait", nullptr, reply, charged);
  });
  BOOST_REQUIRE(waitUntil([&] { return backend->entered.load(); }));
  BOOST_CHECK_EQUAL(server->thinkHandler()->active(), 1u);
  server->thinkHandler()->stop();
  BOOST_CHECK_EQUAL(server->thinkHandler()->active(), 0u);
  caller.join();
  BOOST_CHECK_EQUAL(rc, CES_ERROR_INTERNAL);
  BOOST_CHECK(waitBalance(before));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(ThinkBrokeTests, ThinkBrokeFixture)

// A signer that cannot cover the hold is refused, and pays nothing.
BOOST_AUTO_TEST_CASE(Think_InsufficientBalance) {
  CesThinkClient tc;
  open(tc);
  std::string reply;
  uint64_t charged = 0;
  BOOST_CHECK_EQUAL(tc.think("hi", nullptr, reply, charged),
                    CES_ERROR_INSUFFICIENT_BALANCE);
  BOOST_CHECK_EQUAL(backend->calls.load(), 0);
  BOOST_CHECK_EQUAL(balance(), 1000);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(ThinkNoBackendTests, ThinkNoBackendFixture)

BOOST_AUTO_TEST_CASE(Think_NoBackendIsDisabled) {
  BOOST_CHECK(!server->thinkHandler()->enabled());
  CesThinkClient tc;
  open(tc);
  std::string reply;
  uint64_t charged = 0;
  BOOST_CHECK_EQUAL(tc.think("hi", nullptr, reply, charged),
                    CES_ERROR_DISABLED);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(ThinkFreeTests, ThinkFreeFixture)

// With no prices set THINK is off, so the operator never pays for free calls.
BOOST_AUTO_TEST_CASE(Think_ZeroFeesIsDisabled) {
  BOOST_CHECK(!server->thinkHandler()->enabled());
  CesThinkClient tc;
  open(tc);
  std::string reply;
  uint64_t charged = 0;
  BOOST_CHECK_EQUAL(tc.think("hi", nullptr, reply, charged),
                    CES_ERROR_DISABLED);
  BOOST_CHECK_EQUAL(backend->calls.load(), 0);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(ThinkShortIdleTests, ThinkShortIdleFixture)

// A gap between pieces that is longer than the channel idle time does not
// drop the channel: the server sends keepalive frames while the call runs.
BOOST_AUTO_TEST_CASE(Think_LongGapKeepsTheChannel) {
  backend->gapMs = 2500;
  CesThinkClient tc;
  open(tc);
  std::string reply;
  uint64_t charged = 0;
  std::vector<std::string> got;
  CES_REQUIRE_OK(tc.think("hi",
                          [&](std::string_view t) { got.emplace_back(t); },
                          reply, charged));
  BOOST_CHECK_EQUAL(reply, "Hello, world.");
  BOOST_CHECK_EQUAL(got.size(), 3u);   // keepalives are not pieces
  BOOST_CHECK_EQUAL(charged, thinkCost(fees(), backend->usage));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(ThinkFeeQueryTests, ThinkFeeQueryFixture)

// A THINK pays fee_query, as every signed verb does, on top of its charge.
BOOST_AUTO_TEST_CASE(Think_PaysFeeQuery) {
  CesThinkClient tc;
  open(tc);
  const int64_t before = balance();
  std::string reply;
  uint64_t charged = 0;
  CES_REQUIRE_OK(tc.think("hi", nullptr, reply, charged));
  BOOST_CHECK(waitBalance(before - static_cast<int64_t>(charged) - 5));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(ThinkSmallBudgetTests, ThinkSmallBudgetFixture)

// The subsidy reservation is sized on the expected cost of the call, not on
// its worst case. A long prompt in a cool service gets the full discount
// when its expected cost fits the budget.
BOOST_AUTO_TEST_CASE(Think_LongPromptGetsTheFullDiscount) {
  CesThinkClient tc;
  open(tc);
  std::string reply;
  uint64_t charged = 0;
  CES_REQUIRE_OK(tc.think(std::string(3000, 'x'), nullptr, reply, charged));
  const uint64_t full = thinkCost(fees(), backend->usage);   // 70
  BOOST_CHECK_EQUAL(charged, full - full * 9999 / 10000);    // 1
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(ThinkOneSlotTests, ThinkOneSlotFixture)

// Past think_max_concurrent a call is refused with QUEUE_FULL, and the
// refused signer pays nothing for it.
BOOST_AUTO_TEST_CASE(Think_ConcurrencyCap) {
  backend->block = true;
  CesThinkClient first;
  open(first);
  uint8_t rc1 = CES_ERROR_INTERNAL;
  std::thread caller([&] {
    std::string reply;
    uint64_t charged = 0;
    rc1 = first.think("one", nullptr, reply, charged);
  });
  BOOST_REQUIRE(waitUntil([&] { return backend->entered.load(); }));

  CesThinkClient second;
  open(second);
  std::string reply;
  uint64_t charged = 0;
  BOOST_CHECK_EQUAL(second.think("two", nullptr, reply, charged),
                    CES_ERROR_QUEUE_FULL);
  BOOST_CHECK_EQUAL(backend->calls.load(), 1);

  backend->release = true;
  caller.join();
  BOOST_CHECK_EQUAL(rc1, CES_OK);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(ThinkSubsidyTests, ThinkSubsidyFixture)

// A cool service gives 99.99% off the hold and the charge, so an account
// with too little for the full hold can think. The subsidy it got stays in
// the heat; the unused reservation goes back.
BOOST_AUTO_TEST_CASE(Think_CoolServiceIsNearlyFree) {
  HeatSubsidy* sub = server->thinkHandler()->subsidy();
  BOOST_REQUIRE(sub->enabled());
  BOOST_REQUIRE_EQUAL(sub->multBp(), 1);   // at rest: 1 bp of the price
  CesThinkClient tc;
  open(tc);
  std::string reply;
  uint64_t charged = 0;
  CES_REQUIRE_OK(tc.think("hi there", nullptr, reply, charged));
  const uint64_t full = thinkCost(fees(), backend->usage);   // 70
  const uint64_t subsidized = full * 9999 / 10000;           // 69
  BOOST_CHECK_EQUAL(charged, full - subsidized);
  BOOST_CHECK(waitBalance(1000 - static_cast<int64_t>(charged)));
  // The heat holds what was given (less a little cooling since).
  BOOST_CHECK_LE(sub->heat(), subsidized);
  BOOST_CHECK_GE(sub->heat(), subsidized - 1);
}

BOOST_AUTO_TEST_SUITE_END()

#ifdef CES_THINK
// ===========================================================================
// ThinkHttpsBackend against a local plain-HTTP server (no network)
// ===========================================================================

namespace {

// Accepts connections on loopback. For each one it reads one request, counts
// it, and sends a 200 event-stream reply as chunks, one per entry of
// `parts`, with `gapMs` between them.
struct FakeChatServer {
  boost::asio::io_context ioc;
  boost::asio::ip::tcp::acceptor acc{
      ioc, boost::asio::ip::tcp::endpoint(
               boost::asio::ip::address_v4::loopback(), 0)};
  std::vector<std::string> parts;
  int gapMs = 0;
  std::atomic<int> requests{0};
  std::atomic<bool> stopping{false};
  std::thread th;

  void start() { th = std::thread([this] { serve(); }); }
  uint16_t port() const { return acc.local_endpoint().port(); }
  std::string url() const { return "http://127.0.0.1:" + std::to_string(port()); }
  ~FakeChatServer() {
    stopping = true;
    boost::system::error_code ec;
    boost::asio::ip::tcp::socket poke(ioc);
    poke.connect(acc.local_endpoint(), ec);   // ends the blocking accept
    if (th.joinable()) th.join();
  }

  void serve() {
    namespace asio = boost::asio;
    for (;;) {
      asio::ip::tcp::socket s(ioc);
      boost::system::error_code ec;
      acc.accept(s, ec);
      if (ec || stopping.load()) return;
      asio::streambuf in;
      size_t n = asio::read_until(s, in, "\r\n\r\n", ec);
      if (ec) continue;
      std::string head(asio::buffers_begin(in.data()),
                       asio::buffers_begin(in.data()) + n);
      in.consume(n);
      size_t len = 0;
      auto cl = head.find("Content-Length: ");
      if (cl != std::string::npos) len = std::stoul(head.substr(cl + 16));
      if (in.size() < len) asio::read(s, in, asio::transfer_exactly(len - in.size()), ec);
      ++requests;
      std::string resp =
          "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
          "Transfer-Encoding: chunked\r\n\r\n";
      asio::write(s, asio::buffer(resp), ec);
      for (const auto& p : parts) {
        if (gapMs > 0)
          std::this_thread::sleep_for(std::chrono::milliseconds(gapMs));
        char hex[16];
        std::snprintf(hex, sizeof(hex), "%zx\r\n", p.size());
        std::string chunk = hex + p + "\r\n";
        asio::write(s, asio::buffer(chunk), ec);
        if (ec) break;
      }
      asio::write(s, asio::buffer(std::string("0\r\n\r\n")), ec);
      s.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    }
  }
};

// kSse split at its event ends, one chunk per event.
std::vector<std::string> sseEvents(const std::string& sse) {
  std::vector<std::string> out;
  size_t pos = 0;
  while (pos < sse.size()) {
    size_t e = sse.find("\n\n", pos);
    size_t end = e == std::string::npos ? sse.size() : e + 2;
    out.push_back(sse.substr(pos, end - pos));
    pos = end;
  }
  return out;
}

ThinkHttpsBackend makeBackend(const FakeChatServer& srv) {
  ThinkHttpsConfig c;
  c.baseUrl = srv.url();
  c.apiKey = "test-key";
  c.model = "m";
  c.timeout = std::chrono::seconds(20);
  return ThinkHttpsBackend(c);
}

}  // namespace

BOOST_AUTO_TEST_SUITE(ThinkHttpsTests)

// A whole stream: the text, the usage, OK.
BOOST_AUTO_TEST_CASE(Https_CompleteStream) {
  FakeChatServer srv;
  srv.parts = sseEvents(kSse);
  srv.start();
  auto b = makeBackend(srv);
  BOOST_REQUIRE(b.valid());
  std::atomic<bool> stop{false};
  std::string text;
  ThinkOutcome o = b.run("hi", 10, stop, [&](std::string_view t) {
    text.append(t);
    return true;
  });
  CES_CHECK_OK(o.status);
  BOOST_CHECK_EQUAL(text, "Hi th\xc3\xa9re\n");
  BOOST_CHECK_EQUAL(o.billing, ThinkOutcome::kUsage);
  BOOST_CHECK_EQUAL(o.usage.promptTokens, 36u);
  BOOST_CHECK_EQUAL(srv.requests.load(), 1);
}

// A stream that ends without "[DONE]" is not a complete reply.
BOOST_AUTO_TEST_CASE(Https_NoDoneIsNotSuccess) {
  FakeChatServer srv;
  auto ev = sseEvents(kSse);
  ev.pop_back();   // the [DONE] event
  srv.parts = ev;
  srv.start();
  auto b = makeBackend(srv);
  std::atomic<bool> stop{false};
  ThinkOutcome o = b.run("hi", 10, stop,
                         [](std::string_view) { return true; });
  BOOST_CHECK_NE(o.status, CES_OK);
  BOOST_CHECK_EQUAL(o.billing, ThinkOutcome::kUsage);   // still billed by usage
}

// When the reader stops taking text (its client left), the backend still
// reads to the usage report, so the call is billed by usage.
BOOST_AUTO_TEST_CASE(Https_ClosedSinkStillReadsUsage) {
  FakeChatServer srv;
  srv.parts = sseEvents(kSse);
  srv.gapMs = 20;
  srv.start();
  auto b = makeBackend(srv);
  std::atomic<bool> stop{false};
  int n = 0;
  ThinkOutcome o = b.run("hi", 10, stop, [&](std::string_view) {
    ++n;
    return false;
  });
  BOOST_CHECK_EQUAL(n, 1);
  BOOST_CHECK_NE(o.status, CES_OK);
  BOOST_CHECK_EQUAL(o.billing, ThinkOutcome::kUsage);
  BOOST_CHECK_EQUAL(o.usage.promptTokens, 36u);
}

// A stop that is set before the call sends no request.
BOOST_AUTO_TEST_CASE(Https_StopBeforeStartSendsNothing) {
  FakeChatServer srv;
  srv.parts = sseEvents(kSse);
  srv.start();
  auto b = makeBackend(srv);
  std::atomic<bool> stop{true};
  ThinkOutcome o = b.run("hi", 10, stop,
                         [](std::string_view) { return true; });
  BOOST_CHECK_NE(o.status, CES_OK);
  BOOST_CHECK_EQUAL(o.billing, ThinkOutcome::kNone);
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  BOOST_CHECK_EQUAL(srv.requests.load(), 0);
}

// A stop while the reply streams ends the call soon, with no use of the
// finished stream.
BOOST_AUTO_TEST_CASE(Https_StopWhileStreaming) {
  FakeChatServer srv;
  srv.parts = sseEvents(kSse);
  srv.gapMs = 300;
  srv.start();
  auto b = makeBackend(srv);
  std::atomic<bool> stop{false};
  const auto t0 = std::chrono::steady_clock::now();
  ThinkOutcome o = b.run("hi", 10, stop, [&](std::string_view) {
    stop = true;
    return true;
  });
  const auto took = std::chrono::steady_clock::now() - t0;
  BOOST_CHECK_NE(o.status, CES_OK);
  BOOST_CHECK(took < std::chrono::seconds(3));
}

BOOST_AUTO_TEST_SUITE_END()
#endif  // CES_THINK
