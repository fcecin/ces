// builtin:think tests. The pure helpers (request JSON, SSE parser, base URL,
// UTF-8 check, prices), then the verb end to end over a real CesPlex channel
// with a scripted backend (no network): the streamed reply, the hold and the
// refund, the refusals, the concurrency cap, and stop with a call in flight.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"

#include <ces/account.h>
#include <ces/client.h>
#include <ces/keys.h>
#include <ces/server.h>
#include <ces/l2/think_backend.h>
#include <ces/l2/think_client.h>
#include <ces/l2/think_handler.h>

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
  std::atomic<bool> release{false};
  std::atomic<bool> entered{false};
  std::atomic<int> calls{0};
  std::mutex mu;
  std::string lastPrompt;
  uint32_t lastMaxOut = 0;

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
    ThinkOutcome o;
    if (block) {
      while (!stop.load() && !release.load())
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
      if (stop.load()) {
        o.status = CES_ERROR_INTERNAL;
        o.billing = ThinkOutcome::kNone;
        return o;
      }
    }
    for (const auto& p : pieces) {
      if (!onText(p)) {
        o.status = CES_ERROR_INTERNAL;
        o.billing = ThinkOutcome::kEstimate;
        return o;
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
               uint64_t subsidyBudget = 0) {
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
    cfg.feeQuery = 0;
    cfg.thinkFeeIn = feeIn;
    cfg.thinkFeeCachedIn = kFeeCachedIn;
    cfg.thinkFeeOut = feeOut;
    cfg.thinkMaxOutTokens = kMaxOut;
    cfg.thinkMaxInputBytes = kMaxInput;
    cfg.thinkMaxConcurrent = maxConcurrent;
    cfg.thinkSubsidyBudget = subsidyBudget;
    cfg.thinkSubsidyTauSecs = 3600;
    cfg.thinkSubsidyFloorBp = 1;
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
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
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
  // The refund is posted to the logic strand, so wait for it.
  bool waitBalance(int64_t want) {
    for (int i = 0; i < 200; ++i) {
      if (balance() == want) return true;
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
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
  BOOST_CHECK_EQUAL(thinkEstimate(f, 30, 9),
                    (10 + kThinkPromptOverhead) + 2 * 4);
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
  for (int i = 0; i < 400 && !backend->entered.load(); ++i)
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  BOOST_REQUIRE(backend->entered.load());
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
  for (int i = 0; i < 400 && !backend->entered.load(); ++i)
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  BOOST_REQUIRE(backend->entered.load());

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
