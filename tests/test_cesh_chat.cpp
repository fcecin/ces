// cesh chat (src/cesh/chat/): the command table, line splitting, the tool
// calls and the chat request, the note file, and the turn loop with scripted
// hooks.
// `CeshChatE2ETests` runs the real `cesh chat` binary against a server whose
// think backend is a script, so the model's commands run through cesh.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"
#include "test_compute_wait.h"
#include "test_e2e_common.h"

#include "chat/chat.h"
#include "chat/socket.h"

#include <ces/client.h>
#include <ces/keys.h>
#include <ces/l2/think_backend.h>
#include <ces/l2/think_handler.h>
#include <ces/server.h>

#include <boost/json.hpp>
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <fstream>
#include <mutex>
#include <thread>

using namespace ces::chat;

namespace {

bool has(const std::string& s, const std::string& t) { return s.find(t) != std::string::npos; }

Kind kindOf(const std::string& line) {
  std::vector<std::string> a;
  BOOST_REQUIRE(splitLine(line, a));
  return classify(a);
}

// A scripted reply of the model: its words, and the commands that it runs,
// each with the content of a write ("" for the others).
struct Say {
  Say(const char* t) : text(t) {}
  Say(std::string t) : text(std::move(t)) {}
  Say(std::string t, const std::vector<std::string>& commands) : text(std::move(t)) {
    for (auto& c : commands) calls.push_back({c, ""});
  }
  std::string text;
  std::vector<std::pair<std::string, std::string>> calls;
};

// A reply that writes `content` to the scratch file `name`.
Say writes(std::string text, const std::string& name, const std::string& content) {
  Say s(std::move(text));
  s.calls.push_back({"write " + name, content});
  return s;
}

namespace json = boost::json;

// A chat request as text: "ROLE: content" for each message, and a "RAN:"
// line for each tool call. `system` gets the system message.
std::string asText(const std::string& request, std::string* system = nullptr) {
  std::string t;
  const json::value req = json::parse(request);
  for (const json::value& m : req.at("messages").as_array()) {
    const json::object& o = m.as_object();
    std::string role(o.at("role").as_string());
    const json::value& c = o.at("content");
    std::string content = c.is_string() ? std::string(c.as_string()) : "";
    if (role == "system" && system) *system = content;
    for (auto& ch : role) ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    t += role + ": " + content;
    if (const json::value* calls = o.if_contains("tool_calls"))
      for (const json::value& call : calls->as_array())
        t += "\nRAN: " + std::string(call.at("function").at("arguments").as_string());
    t += "\n\n";
  }
  return t;
}

// The messages of `next` start with all the messages of `prev`, so the model's
// prompt cache serves them.
bool grows(const std::string& prev, const std::string& next) {
  const json::value p = json::parse(prev), n = json::parse(next);
  const json::array& a = p.at("messages").as_array();
  const json::array& b = n.at("messages").as_array();
  if (b.size() < a.size()) return false;
  for (size_t i = 0; i < a.size(); ++i)
    if (a[i] != b[i]) return false;
  return true;
}

// Hooks that follow a script: the model's replies in order, and the user's
// answers to the confirm questions.
struct Script {
  std::vector<Say> replies;
  std::vector<bool> answers;
  size_t thinks = 0, asks = 0;
  std::vector<std::vector<std::string>> ran;
  std::vector<std::string> shown;
  std::vector<std::string> prompts;    // the requests as text (asText)
  std::vector<std::string> requests;   // as JSON
  size_t calls = 0;                    // tool calls made
  bool badSyntax = false;
  size_t badParses = 0;   // the first N syntax checks fail
  std::string out = "Balance: 42\n";   // what each command prints
  int code = 0;                         // and its exit code
  // The server's report: with `report`, each answer says it used one token
  // for each 4 prompt bytes, a quarter of them from the cache.
  bool report = false;
  uint32_t window = 0, maxOut = 0;
  // A request to fold the older turns gets `summary`, or fails.
  std::string summary = "SUMMARY";
  bool foldFails = false;
  size_t folds = 0;
  std::vector<std::string> events;

  Hooks hooks() {
    Hooks h;
    h.think = [this](const std::string& req) {
      ThinkReply r;
      if (report) {
        r.promptTokens = static_cast<int64_t>(req.size() / 4);
        r.cachedTokens = r.promptTokens / 4;
        r.contextTokens = window;
        r.maxOutTokens = maxOut;
        r.maxInputBytes = 1024 * 1024;
      }
      std::string system;
      std::string text = asText(req, &system);
      if (system.rfind("You fold the older part", 0) == 0) {
        ++folds;
        r.ok = !foldFails;
        r.text = foldFails ? "" : summary;
        r.error = foldFails ? "the model is away" : "";
        r.charged = 5;
        return r;
      }
      prompts.push_back(text);
      requests.push_back(req);
      r.ok = true;
      const Say& say = replies[std::min(thinks, replies.size() - 1)];
      r.text = say.text;
      json::array a;
      for (auto& [command, content] : say.calls) {
        json::object args{{"command", command}};
        if (!content.empty()) args["content"] = content;
        a.push_back(json::object{{"id", "c" + std::to_string(++calls)}, {"type", "function"},
                                 {"function", json::object{{"name", "cesh"},
                                                           {"arguments", json::serialize(args)}}}});
      }
      if (!a.empty()) r.toolCalls = json::serialize(a);
      ++thinks;
      return r;
    };
    h.event = [this](const std::string& type, const std::string& text) {
      events.push_back(type + " " + text);
    };
    h.run = [this](const std::vector<std::string>& a) {
      CeshResult r;
      if (!a.empty() && a[0] == "--parse-only") {   // the chat's syntax check
        bool bad = badSyntax || badParses > 0;
        if (badParses > 0) --badParses;
        r.code = bad ? 1 : 0;
        r.err = bad ? "The following argument was not expected: --to" : "";
        return r;
      }
      ran.push_back(a);
      r.out = out;
      r.code = a.empty() || a[0] != "man" ? code : 0;
      return r;
    };
    h.readLine = [](std::string&) { return false; };
    h.show = [this](const std::string& t) { shown.push_back(t); };
    h.confirm = [this](const std::string&) {
      bool a = asks < answers.size() ? answers[asks] : false;
      ++asks;
      return a;
    };
    return h;
  }
};

bool shows(const Script& s, const std::string& t) {
  return std::find(s.shown.begin(), s.shown.end(), t) != s.shown.end();
}

// The commands that ran, without the manual reads of a syntax error's help.
size_t commandsRun(const Script& s) {
  size_t n = 0;
  for (auto& a : s.ran) n += a.empty() || a[0] != "man";
  return n;
}

Options testOptions() {
  Options o;
  o.manualIndex = "index  Start\n  money/transfer  Send credits\n";
  o.context = "Server: test";
  o.globals = {{{"--server"}, "localhost:1"}, {{"--rpc-port"}, "2"}};
  return o;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(CeshChatTests)

BOOST_AUTO_TEST_CASE(Classify_Table) {
  BOOST_CHECK(kindOf("query @0") == Kind::Read);
  BOOST_CHECK(kindOf("man rent") == Kind::Read);
  BOOST_CHECK(kindOf("man --search hold") == Kind::Read);
  BOOST_CHECK(kindOf("file stat note.txt") == Kind::Read);
  BOOST_CHECK(kindOf("file get note.txt") == Kind::Read);
  BOOST_CHECK(kindOf("file get note.txt -") == Kind::Read);
  BOOST_CHECK(kindOf("--server x:1 compute ps") == Kind::Read);
  BOOST_CHECK(kindOf("transfer --help") == Kind::Read);

  BOOST_CHECK(kindOf("transfer @1 100 --open") == Kind::Action);
  BOOST_CHECK(kindOf("-a @1 transfer @0 5") == Kind::Action);
  BOOST_CHECK(kindOf("file put a b") == Kind::Action);
  BOOST_CHECK(kindOf("file get note.txt /etc/x") == Kind::Action);
  BOOST_CHECK(kindOf("compute launch p.lua") == Kind::Action);
  BOOST_CHECK(kindOf("think hi") == Kind::Action);
  BOOST_CHECK(kindOf("some-new-verb x") == Kind::Action);   // unknown: ask

  // Key commands run; the chat keeps private keys out of the transcript.
  BOOST_CHECK(kindOf("keys list") == Kind::Read);
  BOOST_CHECK(kindOf("keys gen 1") == Kind::Action);
  BOOST_CHECK(kindOf("keys add") == Kind::Action);
  BOOST_CHECK(kindOf("keys export") == Kind::Action);
  BOOST_CHECK(kindOf("keys list --secrets") == Kind::Action);
  BOOST_CHECK(kindOf("keys list -s") == Kind::Action);       // the short form of --secrets
  BOOST_CHECK(kindOf("man -s hold") == Kind::Read);          // -s takes a value on man
  std::string why;
  std::vector<std::string> a = {"keys", "add", "00abcdef"};
  BOOST_CHECK(classify(a, &why) == Kind::Refused);   // a key on the line
  BOOST_CHECK(has(why, "private key"));
  BOOST_CHECK(kindOf("dial 3") == Kind::Refused);                 // the interactive stream
  BOOST_CHECK(kindOf("dial 3 --line hello") == Kind::Action);     // one exchange
  BOOST_CHECK(kindOf("mine") == Kind::Action);                    // one solution, then it ends
  BOOST_CHECK(kindOf("chat") == Kind::Refused);
  BOOST_CHECK(kindOf("bootstrap") == Kind::Refused);
  BOOST_CHECK(kindOf("man --serve 8080") == Kind::Refused);
  BOOST_CHECK(classify({}, &why) == Kind::Refused);
}

BOOST_AUTO_TEST_CASE(DescribeAction_InCreditsAndShortKeys) {
  const std::string k = "0056a1f5011af1f7f0cdc2cf7de9a6787bfa48d41027ad0c4dfcda0b7040ca68";
  BOOST_CHECK_EQUAL(describeAction({"--server", "x:1", "transfer", "--open", k, "200000000"}),
                    "Send 2 credits from @0 to 0056a1f5…ca68, opening its account if it has none");
  BOOST_CHECK_EQUAL(describeAction({"-a", "@1", "transfer", "@0", "100000000"}),
                    "Send 1 credit from @1 to @0");
  // An option's value is not an argument: the deposit is not the local file.
  BOOST_CHECK_EQUAL(describeAction({"file", "put", "--deposit", "5", "a.txt", "b.txt"}),
                    "Upload a.txt to b.txt, paid by @0");
  // A global option after the command is still the signer, not the destination.
  BOOST_CHECK_EQUAL(describeAction({"transfer", "-a", "@1", "fabi", "500000000"}),
                    "Send 5 credits from @1 to fabi");
  BOOST_CHECK_EQUAL(describeAction({"file", "put", "a.txt", "notes/a.txt", "--deposit", "5"}),
                    "Upload a.txt to notes/a.txt, paid by @0");
  BOOST_CHECK_EQUAL(describeAction({"file", "deposit", "n.txt", "50000000"}),
                    "Put 0.5 credits from @0 into n.txt");
  BOOST_CHECK_EQUAL(describeAction({"dial", "3", "--line", "hi there"}),
                    "Send \"hi there\" to program 3 and read one reply");
  BOOST_CHECK(describeAction({"some-new-verb"}).empty());
  {
    std::vector<std::string> a;
    BOOST_REQUIRE(splitLine("compute call 10 10000 --in world", a));
    BOOST_CHECK_EQUAL(describeAction(a), "Call program 10 with \"world\", paying it 0.0001 credits from @0");
  }
}

BOOST_AUTO_TEST_CASE(SplitLine_QuotesAndEscapes) {
  std::vector<std::string> a;
  BOOST_REQUIRE(splitLine("think 'hello there' \"a \\\"b\\\"\" c\\ d", a));
  std::vector<std::string> want = {"think", "hello there", "a \"b\"", "c d"};
  BOOST_CHECK_EQUAL_COLLECTIONS(a.begin(), a.end(), want.begin(), want.end());
  BOOST_CHECK(!splitLine("think 'open", a));
  BOOST_REQUIRE(splitLine("x ''", a));
  BOOST_CHECK_EQUAL(a.size(), 2u);
  BOOST_CHECK(a[1].empty());
}

BOOST_AUTO_TEST_CASE(ToolCalls_TheCommandAndItsContent) {
  auto calls = toolCallsOf(R"([
    {"id":"a","type":"function","function":{"name":"cesh","arguments":"{\"command\":\"cesh query @0\"}"}},
    {"id":"b","type":"function","function":{"name":"cesh","arguments":"{\"command\":\"write a.lua\",\"content\":\"ces.run()\\n\"}"}},
    {"id":"c","type":"function","function":{"name":"shell","arguments":"{\"command\":\"ls\"}"}},
    {"id":"d","type":"function","function":{"name":"cesh","arguments":"not json"}},
    {"id":"e","type":"function","function":{"name":"cesh","arguments":"{\"cmd\":\"ping\"}"}},
    {"type":"function","function":{"name":"cesh","arguments":"{\"command\":\"ping\"}"}}])");
  BOOST_REQUIRE_EQUAL(calls.size(), 5u);   // the call with no id cannot get its result
  BOOST_CHECK_EQUAL(calls[0].command, "query @0");
  BOOST_CHECK(calls[0].error.empty());
  BOOST_CHECK_EQUAL(calls[1].command, "write a.lua");
  BOOST_CHECK_EQUAL(calls[1].content, "ces.run()\n");
  BOOST_CHECK_EQUAL(calls[2].error, "there is no tool \"shell\": the one tool is cesh");
  BOOST_CHECK_EQUAL(calls[3].error, "the arguments are not a JSON object");
  BOOST_CHECK_EQUAL(calls[4].error, "the arguments have no command");
  BOOST_CHECK(toolCallsOf("").empty());
  BOOST_CHECK(toolCallsOf("{}").empty());
}

// chatRequest makes requests that the model API accepts. User messages in a
// row become one, a result with no call (folded or cut) becomes a note, and a
// call with no result gets one.
BOOST_AUTO_TEST_CASE(ChatRequest_IsAlwaysWellFormed) {
  const std::string call = R"([{"id":"x","type":"function","function":{"name":"cesh","arguments":"{}"}}])";
  std::vector<Message> ms = {{"tool", "RESULT of an old call", "", "", "gone"},
                             {"user", "hi", "", "", ""},
                             {"user", "[chat] a note", "", "", ""},
                             {"assistant", "", call, "r", ""},
                             {"user", "next", "", "", ""}};
  json::value v = json::parse(chatRequest("SYS", ms));
  json::array want = {
    json::object{{"role", "system"}, {"content", "SYS"}},
    json::object{{"role", "user"}, {"content", "[chat] RESULT of an old call\n\nhi\n\n[chat] a note"}},
    json::object{{"role", "assistant"}, {"content", ""}, {"reasoning_content", "r"},
                 {"tool_calls", json::parse(call)}},
    json::object{{"role", "tool"}, {"tool_call_id", "x"}, {"content", "did not run"}},
    json::object{{"role", "user"}, {"content", "next"}}};
  BOOST_CHECK_EQUAL(json::serialize(v.at("messages")), json::serialize(want));
  BOOST_CHECK_EQUAL(v.at("tools").as_array().size(), 1u);
  BOOST_CHECK_EQUAL(v.at("tools").at(0).at("function").at("name").as_string(), "cesh");
  BOOST_CHECK(!json::parse(chatRequest("SYS", ms, false)).as_object().contains("tools"));
  // ces's own check takes it.
  std::string clean;
  BOOST_CHECK(ces::thinkChatCheck(chatRequest("SYS", ms), clean));
}

BOOST_AUTO_TEST_CASE(Memory_SaveLoadSetErase) {
  auto dir = makeUniqueTempDir("chatmem");
  std::string path = (dir / "m.md").string();
  {
    Memory m(path);
    BOOST_CHECK(m.load());   // no file yet
    m.set("box", "ces.pubcom.org:53830");
    m.set("ana", "a1d9\nline");
    BOOST_CHECK(m.save());
  }
  // The note file is owner-only, as the wallet.
  BOOST_CHECK(fs::status(path).permissions() == (fs::perms::owner_read | fs::perms::owner_write));
  Memory m(path);
  BOOST_REQUIRE(m.load());
  BOOST_CHECK_EQUAL(m.notes().at("box"), "ces.pubcom.org:53830");
  BOOST_CHECK_EQUAL(m.notes().at("ana"), "a1d9 line");
  BOOST_CHECK(m.erase("box"));
  BOOST_CHECK(!m.erase("box"));
  BOOST_CHECK_EQUAL(m.text(), "# cesh chat notes\n- ana: a1d9 line\n");
}

BOOST_AUTO_TEST_CASE(Turn_ReadRunsAtOnceWithGlobals) {
  Script s;
  s.replies = {Say("Let me look.", {"query @0"}), "You have 42."};
  Chat chat(testOptions(), s.hooks(), Memory());
  chat.turn("what is my balance?");
  BOOST_CHECK_EQUAL(s.thinks, 2u);
  BOOST_CHECK_EQUAL(s.asks, 0u);
  BOOST_REQUIRE_EQUAL(s.ran.size(), 1u);
  std::vector<std::string> want = {"--server", "localhost:1", "--rpc-port", "2", "query", "@0"};
  BOOST_CHECK_EQUAL_COLLECTIONS(s.ran[0].begin(), s.ran[0].end(), want.begin(), want.end());
  // The second model call sees the result.
  BOOST_CHECK(has(s.prompts[1], "RESULT of `query @0`: exit 0\nBalance: 42"));
  BOOST_CHECK(has(chat.transcript(), "ASSISTANT: You have 42."));
  BOOST_CHECK(std::find(s.shown.begin(), s.shown.end(), "You have 42.") != s.shown.end());
}

BOOST_AUTO_TEST_CASE(Turn_GlobalsNotRepeated) {
  Script s;
  s.replies = {Say("", {"--server other:9 query @0"}), "ok"};
  Chat chat(testOptions(), s.hooks(), Memory());
  chat.turn("x");
  BOOST_REQUIRE_EQUAL(s.ran.size(), 1u);
  int servers = 0;
  for (auto& a : s.ran[0]) servers += a == "--server";
  BOOST_CHECK_EQUAL(servers, 1);
  BOOST_CHECK(has(s.ran[0][2] + s.ran[0][3], "other:9") ||
              std::find(s.ran[0].begin(), s.ran[0].end(), "other:9") != s.ran[0].end());
}

BOOST_AUTO_TEST_CASE(Turn_ActionNeedsYes) {
  Script s;
  s.replies = {Say("Sending.", {"transfer @1 100"}), "Not sent."};
  s.answers = {false};
  Chat chat(testOptions(), s.hooks(), Memory());
  chat.turn("send 100 raw to @1");
  BOOST_CHECK_EQUAL(s.asks, 1u);
  BOOST_CHECK(s.ran.empty());
  BOOST_CHECK(has(chat.transcript(), "not run; the user said no"));

  Script y;
  y.replies = {Say("", {"transfer @1 100"}), "Sent."};
  y.answers = {true};
  Chat chat2(testOptions(), y.hooks(), Memory());
  chat2.turn("send it");
  BOOST_REQUIRE_EQUAL(y.ran.size(), 1u);
  BOOST_CHECK_EQUAL(y.ran[0][4], "transfer");
}

// An action that does not parse goes back to the model before the user is
// asked: the user never approves a command that can only fail.
BOOST_AUTO_TEST_CASE(Turn_BadSyntaxNeverReachesTheUser) {
  Script s;
  s.badSyntax = true;
  s.replies = {Say("", {"transfer 2 --to @1"}), "Let me read the manual."};
  s.answers = {true};
  Chat chat(testOptions(), s.hooks(), Memory());
  chat.turn("send 2 to @1");
  BOOST_CHECK_EQUAL(s.asks, 0u);
  for (auto& r : s.ran) BOOST_CHECK_EQUAL(r[0], "man");   // only the help lookup ran
  BOOST_CHECK(has(s.prompts[1], "not run; the command does not parse"));
  BOOST_CHECK(has(s.prompts[1], "not expected: --to"));
  BOOST_CHECK(has(s.prompts[1], "The syntax (`man transfer"));   // the help comes with it
}

// The user's no ends the turn: the model is not asked again, so it cannot ask
// the same question in a loop.
BOOST_AUTO_TEST_CASE(Turn_NoEndsTheTurn) {
  Script s;
  s.replies = {Say("", {"transfer @1 100"})};   // it would ask again and again
  s.answers = {false, false, false};
  Chat chat(testOptions(), s.hooks(), Memory());
  chat.turn("send 100 raw to @1");
  BOOST_CHECK_EQUAL(s.thinks, 1u);
  BOOST_CHECK_EQUAL(s.asks, 1u);
  BOOST_CHECK(has(chat.transcript(), "[chat] the user said no, so the turn ended"));
}

// A stop (the user quit) ends the turn at once.
BOOST_AUTO_TEST_CASE(Turn_StopEndsAtOnce) {
  Script s;
  s.replies = {Say("", {"ping", "ping"})};
  bool stop = false;
  Hooks h = s.hooks();
  h.stopped = [&] { return stop; };
  h.run = [&](const std::vector<std::string>& a) {
    if (!a.empty() && a[0] == "--parse-only") return CeshResult{};   // the syntax check
    s.ran.push_back(a);
    stop = true;   // the user quits while the first command runs
    return CeshResult{};
  };
  Chat chat(testOptions(), h, Memory());
  chat.turn("ping twice");
  BOOST_CHECK_EQUAL(s.ran.size(), 1u);
  BOOST_CHECK_EQUAL(s.thinks, 1u);
}

// The chat sees one directory, its scratch (~/.cesh/scratch). No command of
// the model may name a local file outside it: not the wallet (an upload would
// publish the private keys), not the notes, not any other file. Server paths
// (/h/ /f/ /p/ /s/ /m/) are not local and pass.
BOOST_AUTO_TEST_CASE(Scratch_IsTheOnlyLocalPlace) {
  auto home = makeUniqueTempDir("chathome");
  const std::string cesh = (home / ".cesh").string();
  const std::string scratch = cesh + "/scratch";
  fs::create_directories(scratch);
  std::ofstream(cesh + "/CESH_WALLET") << "00ab\n";
  auto out = [&](const std::string& line) {
    std::vector<std::string> a;
    BOOST_REQUIRE(splitLine(line, a));
    return outsideScratch(a, scratch);
  };
  BOOST_CHECK(!out("file put " + cesh + "/CESH_WALLET notes.txt").empty());
  BOOST_CHECK(!out("file put ../CESH_WALLET notes.txt").empty());             // .. out of scratch
  BOOST_CHECK(!out("think --in file:../memory.md").empty());
  BOOST_CHECK(!out("compute call 3 --out=/tmp/x").empty());
  BOOST_CHECK(!out("file put /etc/passwd p").empty());
  BOOST_CHECK(!out("file put ~/notes.txt n").empty());
  BOOST_CHECK(!out("-r /other/wallet query @0").empty());
  BOOST_CHECK(out("file put hello.lua hello.lua --deposit 100000000").empty());
  BOOST_CHECK(out("transfer fabi 500000000 --open").empty());
  BOOST_CHECK(out("file stat /h/" + std::string(64, 'a') + "/x").empty());      // a server path
  BOOST_CHECK(out("file get /p/shared.txt copy.txt").empty());
  BOOST_CHECK(out("keys gen 1 -w " + cesh + "/CESH_WALLET").empty());           // the chat's own -w
  // Free text is not a path.
  BOOST_CHECK(out("think what is in /etc/hosts").empty());
  BOOST_CHECK(out("dial 3 --line /status").empty());
  BOOST_CHECK(!out("think --in file:/etc/hosts").empty());                      // a file is a file
  // A symlink in scratch that points out is outside.
  fs::create_symlink(cesh + "/CESH_WALLET", scratch + "/w");
  BOOST_CHECK(!out("file put w backup").empty());

  Script s;
  s.replies = {Say("", {"file put " + cesh + "/CESH_WALLET backup.txt"}), "ok"};
  s.answers = {true};
  Options o = testOptions();
  o.scratchDir = scratch;
  Chat chat(o, s.hooks(), Memory());
  chat.turn("back up my wallet online");
  BOOST_CHECK_EQUAL(s.asks, 0u);
  BOOST_CHECK(s.ran.empty() || s.ran[0][0] == "man");
  BOOST_CHECK(has(chat.transcript(), "outside the scratch"));
}

BOOST_AUTO_TEST_CASE(Files_WriteReadLs) {
  auto dir = makeUniqueTempDir("chatscratch");
  const std::string scratch = dir.string();
  Script s;
  Say look("I will look.", {"read hello.lua", "ls", "read ../x"});
  look.calls.push_back({"write sub/x.lua", "x\n"});
  s.replies = {writes("I will write it.", "hello.lua", "local a = 1\nces.run()\n"), "Written.", look, "Done."};
  s.answers = {true};
  Options o = testOptions();
  o.scratchDir = scratch;
  Chat chat(o, s.hooks(), Memory());
  chat.turn("write a lua program");
  BOOST_CHECK_EQUAL(s.asks, 1u);
  std::ifstream f(scratch + "/hello.lua");
  std::string content((std::istreambuf_iterator<char>(f)), {});
  BOOST_CHECK_EQUAL(content, "local a = 1\nces.run()\n");
  BOOST_CHECK(fs::status(scratch + "/hello.lua").permissions() ==
              (fs::perms::owner_read | fs::perms::owner_write));
  chat.turn("show it");
  const std::string t = chat.transcript();
  BOOST_CHECK(has(t, "RESULT of `read hello.lua`: 2 lines\nlocal a = 1\nces.run()"));
  BOOST_CHECK(has(t, "hello.lua  22 bytes"));
  BOOST_CHECK(has(t, "RESULT of `read ../x`: not run; a file name"));     // no paths
  BOOST_CHECK(has(t, "RESULT of `write sub/x.lua`: not run; a file name"));
  BOOST_CHECK_EQUAL(s.asks, 1u);   // the refused write did not ask
}

BOOST_AUTO_TEST_CASE(Turn_RefusedNeverRunsOrAsks) {
  Script s;
  s.replies = {Say("", {"dial 3"}), "Run it yourself."};
  s.answers = {true};
  Chat chat(testOptions(), s.hooks(), Memory());
  chat.turn("dial my program");
  BOOST_CHECK(s.ran.empty());
  BOOST_CHECK_EQUAL(s.asks, 0u);
  BOOST_CHECK(has(chat.transcript(), "the chat does not run it"));
}

// A fake cesh for the key commands: `keys list --public` shows a masked
// private key and the public key, as the real one does; `keys gen` and
// `keys export` print private keys.
const std::string kPriv = "00e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0011";
const std::string kPub = "a1d948985b95b286ad167505a6c224e0a7eace3d61d503a499478a4d93e79525";

Hooks keyHooks(Script& s) {
  Hooks h = s.hooks();
  h.run = [&s](const std::vector<std::string>& a) {
    s.ran.push_back(a);
    CeshResult r;
    bool list = std::find(a.begin(), a.end(), "list") != a.end();
    bool pub = std::find(a.begin(), a.end(), "--public") != a.end();
    if (list && pub) r.out = "[@0] [ED  ] 00e1e2...0011 (" + kPub + ")\n";
    else r.out = "[@0] " + kPriv + "\n";   // gen, export, list --secrets
    return r;
  };
  h.secret = [](const std::string&) { return kPriv; };
  return h;
}

bool transcriptLeaks(const Chat& c) {
  return has(c.transcript(), kPriv) || has(c.transcript(), "00e1e2...0011");
}

BOOST_AUTO_TEST_CASE(Keys_ListGivesPublicKeysOnly) {
  Script s;
  s.replies = {Say("", {"keys list"}), "You have one key."};
  Chat chat(testOptions(), keyHooks(s), Memory());
  chat.turn("what keys do I have?");
  BOOST_CHECK_EQUAL(s.asks, 0u);
  BOOST_CHECK(has(chat.transcript(), "@0 " + kPub));
  BOOST_CHECK(!transcriptLeaks(chat));
  for (auto& t : s.shown) BOOST_CHECK(!has(t, kPriv));
}

BOOST_AUTO_TEST_CASE(Keys_GenSavesToTheWalletFile) {
  Script s;
  s.replies = {Say("", {"keys gen 1"}), "Done."};
  s.answers = {true};
  Options o = testOptions();
  o.walletPath = "/home/u/.cesh/CESH_WALLET";
  Chat chat(o, keyHooks(s), Memory());
  chat.turn("make me a key");
  BOOST_REQUIRE_GE(s.ran.size(), 1u);
  auto& gen = s.ran[0];
  auto w = std::find(gen.begin(), gen.end(), "-w");
  BOOST_REQUIRE(w != gen.end());
  BOOST_CHECK_EQUAL(*(w + 1), "/home/u/.cesh/CESH_WALLET");
  BOOST_CHECK(has(chat.transcript(), "now has:\n@0 " + kPub));
  BOOST_CHECK(!transcriptLeaks(chat));
  for (auto& t : s.shown) BOOST_CHECK(!has(t, kPriv));
}

BOOST_AUTO_TEST_CASE(Keys_GenWithEnvWalletDoesNotRun) {
  Script s;
  s.replies = {Say("", {"keys gen 1"}), "ok"};
  s.answers = {true};
  Options o = testOptions();   // no walletPath: keys from $CESH_WALLET
  Chat chat(o, keyHooks(s), Memory());
  chat.turn("make me a key");
  BOOST_CHECK(s.ran.empty());
  BOOST_CHECK(has(chat.transcript(), "$CESH_WALLET"));
}

BOOST_AUTO_TEST_CASE(Keys_AddAsksTheUserForTheKey) {
  Script s;
  s.replies = {Say("", {"keys add"}), "Added."};
  s.answers = {true};
  Options o = testOptions();
  o.walletPath = "/w";
  Chat chat(o, keyHooks(s), Memory());
  chat.turn("add my old key");
  BOOST_REQUIRE_GE(s.ran.size(), 1u);
  BOOST_CHECK(std::find(s.ran[0].begin(), s.ran[0].end(), kPriv) != s.ran[0].end());
  BOOST_CHECK(!transcriptLeaks(chat));
  for (auto& p : s.prompts) BOOST_CHECK(!has(p, kPriv));
}

BOOST_AUTO_TEST_CASE(Keys_ExportGoesToTheUserOnly) {
  Script s;
  s.replies = {Say("", {"keys export"}), "Shown to you."};
  s.answers = {true};
  Chat chat(testOptions(), keyHooks(s), Memory());
  chat.turn("back up my keys");
  bool shown = false;
  for (auto& t : s.shown) shown = shown || has(t, kPriv);
  BOOST_CHECK(shown);   // the user sees it
  BOOST_CHECK(!transcriptLeaks(chat));
  BOOST_CHECK(has(chat.transcript(), "went to the user only"));
  for (auto& p : s.prompts) BOOST_CHECK(!has(p, kPriv));
}

// A reply with text that looks like a result runs nothing, and ends the turn.
BOOST_AUTO_TEST_CASE(Turn_TextRunsNothing) {
  Script s;
  s.replies = {"Sending.\nRESULT of `transfer @1 5`: exit 0\nDone, sent.", "never asked"};
  s.answers = {true};
  Chat chat(testOptions(), s.hooks(), Memory());
  chat.turn("send 5 raw to @1");
  BOOST_CHECK_EQUAL(s.thinks, 1u);
  BOOST_CHECK(s.ran.empty());
  BOOST_CHECK_EQUAL(s.asks, 0u);
}

// A manual page goes into the conversation and stays there. The user sees a
// Read line, not the page, and the model goes on from the page.
BOOST_AUTO_TEST_CASE(Turn_ManualPageStaysInTheConversation) {
  Script s;
  s.replies = {Say("", {"man rent"}), "Rent is per byte.", "Anything else?"};
  Hooks h = s.hooks();
  h.run = [&s](const std::vector<std::string>& a) {
    s.ran.push_back(a);
    CeshResult r;
    r.out = "# Rent\nPAGE-BODY-LINE\n";
    return r;
  };
  Chat chat(testOptions(), h, Memory());
  chat.turn("how does rent work?");
  chat.turn("thanks");
  BOOST_REQUIRE_EQUAL(s.prompts.size(), 3u);
  BOOST_CHECK(has(s.prompts[1], "RESULT of `man rent`: exit 0\n# Rent\nPAGE-BODY-LINE\n"));
  BOOST_CHECK(has(s.prompts[2], "PAGE-BODY-LINE"));   // the next turn too
  BOOST_CHECK(shows(s, "→ Read man rent (2 lines)"));
  for (auto& t : s.shown) BOOST_CHECK(!has(t, "PAGE-BODY-LINE"));
}

BOOST_AUTO_TEST_CASE(Turn_CostIsShownAndKept) {
  Script s;
  Hooks h = s.hooks();
  h.think = [&s](const std::string& p) {
    s.prompts.push_back(p);
    ThinkReply r;
    r.ok = true;
    r.text = "Hello.";
    r.charged = 25000000;
    return r;
  };
  Chat chat(testOptions(), h, Memory());
  chat.turn("hi");
  chat.turn("hi again");
  // The cost, then how full the model's window is (an estimate here: this
  // backend reports no usage).
  BOOST_CHECK(std::any_of(s.shown.begin(), s.shown.end(), [](const std::string& t) {
    return t.rfind("(0.25 credits for this answer, 0.5 for this chat · context ~", 0) == 0;
  }));
  BOOST_CHECK(has(chat.transcript(), "this chat has cost 0.5 credits"));
}

// The user sees each command's output; the model has it too.
BOOST_AUTO_TEST_CASE(Turn_ReadOutputIsShown) {
  Script s;
  s.replies = {Say("I will read it.", {"query @0"}), "You have 42."};
  Chat chat(testOptions(), s.hooks(), Memory());
  chat.turn("balance?");
  BOOST_CHECK(std::find(s.shown.begin(), s.shown.end(), "Balance: 42") != s.shown.end());
  BOOST_CHECK(has(chat.transcript(), "Balance: 42"));   // the model has it
}

// A command that prints nothing says so, to the user and to the model, so the
// model does not make up a reason for the empty result.
BOOST_AUTO_TEST_CASE(Turn_EmptyOutputIsSaid) {
  Script s;
  s.out = "";
  s.replies = {Say("", {"compute call 8 0 --in text:hi"}), "It replied with nothing."};
  s.answers = {true};
  Chat chat(testOptions(), s.hooks(), Memory());
  chat.turn("call it");
  BOOST_CHECK(std::find(s.shown.begin(), s.shown.end(), "(no output)") != s.shown.end());
  BOOST_CHECK(has(chat.transcript(), "exit 0\n(no output: the command printed nothing)"));
}


// A reply of commands with no words is the answer: the user sees each
// command and its output, and when they succeed, the turn ends with no
// reply from the model.
BOOST_AUTO_TEST_CASE(Turn_CommandsWithNoWordsAreTheAnswer) {
  Script s;
  s.replies = {Say("", {"query @0"}), "this reply must not come"};
  Chat chat(testOptions(), s.hooks(), Memory());
  chat.turn("my balance");
  BOOST_CHECK_EQUAL(s.thinks, 1u);
  BOOST_REQUIRE_EQUAL(s.ran.size(), 1u);
  BOOST_CHECK_EQUAL(s.ran[0].back(), "@0");
  BOOST_CHECK(shows(s, "→ cesh query @0"));
  BOOST_CHECK(shows(s, "Balance: 42"));
  BOOST_CHECK(has(chat.transcript(), "the turn ended"));

  // An action still asks first.
  Script a;
  a.replies = {Say("", {"transfer @0 bob 5"})};
  a.answers = {true};
  Chat chat2(testOptions(), a.hooks(), Memory());
  chat2.turn("send bob 5 raw");
  BOOST_CHECK_EQUAL(a.asks, 1u);
  BOOST_CHECK_EQUAL(a.ran.size(), 1u);
  BOOST_CHECK_EQUAL(a.thinks, 1u);
}

// The results go back to the model when it said it has more to do, when a
// command failed, and after a manual page.
BOOST_AUTO_TEST_CASE(Turn_ResultsGoBackWhenTheModelGoesOn) {
  Script w;
  w.replies = {Say("I will check it first.", {"query @0"}), "You have 42."};
  Chat chat(testOptions(), w.hooks(), Memory());
  chat.turn("can I pay 40?");
  BOOST_CHECK_EQUAL(w.thinks, 2u);
  BOOST_CHECK(shows(w, "You have 42."));

  // A task goes on after a later step with no words, until the model ends it.
  Script t;
  t.replies = {Say("I will upload it, then launch it.", {"file put a.lua a.lua"}),
               Say("", {"compute launch a.lua"}), Say("", {"compute call 1 0 --in bob"}), ""};
  t.answers = {true, true, true};
  Chat chatT(testOptions(), t.hooks(), Memory());
  chatT.turn("upload, launch and call it");
  BOOST_CHECK_EQUAL(t.thinks, 4u);
  BOOST_CHECK_EQUAL(t.ran.size(), 3u);

  Script f;
  f.code = 1;
  f.replies = {Say("", {"query @9"}), "There is no key @9."};
  Chat chatF(testOptions(), f.hooks(), Memory());
  chatF.turn("balance of @9");
  BOOST_CHECK_EQUAL(f.thinks, 2u);

  Script m;
  m.replies = {Say("", {"man compute"}), Say("", {"compute ps"})};
  Chat chatM(testOptions(), m.hooks(), Memory());
  chatM.turn("my programs");
  BOOST_CHECK_EQUAL(m.thinks, 2u);
  BOOST_CHECK(shows(m, "→ Read man compute (1 line)"));
  for (auto& t : m.shown) BOOST_CHECK(t != "Balance: 42" || m.ran.size() == 2);
}

// A command that does not parse never reaches the user: the model gets the
// error and writes the line again.
BOOST_AUTO_TEST_CASE(Turn_BadSyntaxGoesBackToTheModel) {
  Script s;
  s.badParses = 1;
  s.replies = {Say("", {"query --to @0"}), Say("", {"query @0"})};
  Chat chat(testOptions(), s.hooks(), Memory());
  chat.turn("my balance");
  BOOST_CHECK_EQUAL(s.thinks, 2u);
  BOOST_CHECK_EQUAL(commandsRun(s), 1u);
  BOOST_CHECK(!shows(s, "→ cesh query --to @0"));
  BOOST_CHECK(shows(s, "→ cesh query @0"));
}

// The user's own command ("$ ..." or "cesh ...") runs as it is, with no
// model call. One that does not parse goes to the model.
BOOST_AUTO_TEST_CASE(Turn_UserCommandRunsWithNoModelCall) {
  for (const char* line : {"$ query @0", "cesh query @0", "$cesh query @0"}) {
    Script s;
    s.replies = {"no model call is expected"};
    Chat chat(testOptions(), s.hooks(), Memory());
    chat.turn(line);
    BOOST_CHECK_EQUAL(s.thinks, 0u);
    BOOST_REQUIRE_EQUAL(s.ran.size(), 1u);
    BOOST_CHECK(shows(s, "→ cesh query @0"));
    BOOST_CHECK(shows(s, "Balance: 42"));
  }
  Script e;
  e.badParses = 1;
  e.replies = {"It is."};
  Chat chat(testOptions(), e.hooks(), Memory());
  chat.turn("cesh is fun");
  BOOST_CHECK_EQUAL(e.thinks, 1u);
  BOOST_CHECK_EQUAL(commandsRun(e), 0u);
  BOOST_CHECK(shows(e, "It is."));

  // A file command that shows the user nothing (no such file) goes to the
  // model too, so the user never gets silence.
  Script f;
  f.replies = {"There is no file missing.txt in the scratch."};
  Options fo = testOptions();
  fo.scratchDir = ".";
  Chat chatF(fo, f.hooks(), Memory());
  chatF.turn("$ read missing-file-for-this-test.txt");
  BOOST_CHECK_EQUAL(f.thinks, 1u);
  BOOST_CHECK(shows(f, "There is no file missing.txt in the scratch."));

  // A plain line is the model's to read, also when it looks like a command.
  Script p;
  p.replies = {Say("", {"query @0"})};
  Chat chat3(testOptions(), p.hooks(), Memory());
  chat3.turn("query @0");
  BOOST_CHECK_EQUAL(p.thinks, 1u);

  std::string own;
  BOOST_CHECK(!userCommand("send 5 to bob", own));
  BOOST_CHECK(!userCommand("$", own));
  BOOST_CHECK(userCommand("  $ cesh ping ", own));
  BOOST_CHECK_EQUAL(own, "$ ping");
}

// A remote program's reply bytes reach the terminal with no control
// characters: no escape sequence, no carriage return, no C1 control.
BOOST_AUTO_TEST_CASE(Output_HasNoControlCharacters) {
  BOOST_CHECK_EQUAL(printable("a\x1b[2Jb\r\nc\td\x7f"), "a?[2Jb?\nc\td?");
  BOOST_CHECK_EQUAL(printable("x\xc2\x9b" "31my"), "x?31my");   // C1 CSI
  BOOST_CHECK_EQUAL(printable("ç€ ok"), "ç€ ok");             // UTF-8 stays
  Script s;
  s.out = "hi\x1b]0;owned\x07\n";
  s.replies = {Say("", {"compute call 8 0 --in text:x"})};
  s.answers = {true};
  Chat chat(testOptions(), s.hooks(), Memory());
  chat.turn("call 8");
  for (auto& t : s.shown) BOOST_CHECK(t.find('\x1b') == std::string::npos);
  BOOST_CHECK(shows(s, "hi?]0;owned?"));
}

BOOST_AUTO_TEST_CASE(Turn_StopsAfterMaxThinks) {
  Script s;
  s.replies = {Say("Once more.", {"ping"})};   // the model asks again and again
  Options o = testOptions();
  o.maxThinks = 3;
  Chat chat(o, s.hooks(), Memory());
  chat.turn("loop");
  BOOST_CHECK_EQUAL(s.thinks, 3u);
  BOOST_CHECK_EQUAL(s.ran.size(), 3u);
  BOOST_CHECK(has(s.shown.back(), "stopped after 3 model calls"));
}

BOOST_AUTO_TEST_CASE(Turn_RememberAndForget) {
  auto dir = makeUniqueTempDir("chatmem2");
  std::string path = (dir / "m.md").string();
  Script s;
  s.replies = {Say("I will save it.", {"remember box: ces.pubcom.org:53830"}), "Saved.",
               Say("I will drop it.", {"forget box"}), "Gone."};
  s.answers = {true, true};
  Chat chat(testOptions(), s.hooks(), Memory(path));
  chat.turn("remember my box");
  BOOST_CHECK(s.ran.empty());   // a note is not a cesh command
  BOOST_CHECK_EQUAL(chat.memory().notes().at("box"), "ces.pubcom.org:53830");
  // The start of the request keeps the notes it began with; the change is in
  // the conversation.
  BOOST_CHECK(has(s.prompts.back(), "## The user's notes\n\n(none)"));
  BOOST_CHECK(has(s.prompts.back(), "saved; the notes now have box: ces.pubcom.org:53830"));
  std::ifstream f(path);
  std::string text((std::istreambuf_iterator<char>(f)), {});
  BOOST_CHECK(has(text, "- box: ces.pubcom.org:53830"));
  chat.turn("forget it");
  BOOST_CHECK(chat.memory().notes().empty());
  BOOST_CHECK_EQUAL(s.asks, 2u);
}

// A note is free text: an apostrophe or a quote must not stop it.
BOOST_AUTO_TEST_CASE(Turn_RememberTakesFreeText) {
  auto dir = makeUniqueTempDir("chatmem3");
  Script s;
  s.replies = {Say("", {"remember ana: ana's key is \"a1d9\": the one from the meetup"}), "Saved."};
  s.answers = {true};
  Chat chat(testOptions(), s.hooks(), Memory((dir / "m.md").string()));
  chat.turn("remember ana");
  BOOST_CHECK_EQUAL(chat.memory().notes().at("ana"), "ana's key is \"a1d9\": the one from the meetup");
}

BOOST_AUTO_TEST_CASE(Turn_ThinkFailureIsShown) {
  Script s;
  Hooks h = s.hooks();
  h.think = [](const std::string&) {
    ThinkReply r;
    r.error = "THINK Failed: CES_ERROR_INSUFFICIENT_BALANCE";
    return r;
  };
  Chat chat(testOptions(), h, Memory());
  chat.turn("hi");
  BOOST_REQUIRE(!s.shown.empty());
  BOOST_CHECK(has(s.shown.back(), "think failed: THINK Failed: CES_ERROR_INSUFFICIENT_BALANCE"));
}

BOOST_AUTO_TEST_CASE(Request_HasRulesManualNotesContextAndTheTool) {
  Script s;
  Chat chat(testOptions(), s.hooks(), Memory());
  std::string system;
  asText(chat.request(), &system);
  BOOST_CHECK(has(system, "You are cesh chat"));
  BOOST_CHECK(has(system, "money/transfer  Send credits"));
  BOOST_CHECK(has(system, "## The user's notes\n\n(none)"));
  BOOST_CHECK(has(system, "Server: test"));
  BOOST_CHECK(has(chat.request(), R"("tools":[{"type":"function","function":{"name":"cesh")"));
}

// The request only grows at its end within a turn and across turns, so the
// model's prompt cache serves its start: nothing trims it a little at a time.
BOOST_AUTO_TEST_CASE(Request_GrowsOnlyAtItsEnd) {
  Script s;
  s.replies = {Say("I will read it.", {"query @0"}), "You have 42.", std::string(300, 'x')};
  Chat chat(testOptions(), s.hooks(), Memory());
  chat.turn("balance?");
  for (int i = 0; i < 20; ++i) chat.turn("more " + std::to_string(i));
  BOOST_REQUIRE_GE(s.requests.size(), 3u);
  for (size_t i = 1; i < s.requests.size(); ++i)
    BOOST_CHECK_MESSAGE(grows(s.requests[i - 1], s.requests[i]), "request " << i);
  BOOST_CHECK_EQUAL(s.folds, 0u);   // far from the window: nothing folds
}

// The history is linear: a manual page, a file read and a saved note go
// into the conversation and stay; no part of the request is edited or taken
// out. Each request starts with the one before it, so the cache serves it.
BOOST_AUTO_TEST_CASE(Prompt_IsLinearThroughPagesFilesAndNotes) {
  auto dir = makeUniqueTempDir("chatlinear");
  {
    std::ofstream f((dir / "notes.txt").string());
    f << "a file line\n";
  }
  Script s;
  s.replies = {Say("I will read the page.", {"man rent"}),
               Say("I will read the file.", {"read notes.txt"}),
               Say("I will save it.", {"remember box: x1"}),
               "Done.", "Fine."};
  s.answers = {true};
  Options o = testOptions();
  o.scratchDir = dir.string();
  Chat chat(o, s.hooks(), Memory((dir / "m.md").string()));
  chat.turn("read, then save");
  chat.turn("and now?");
  BOOST_REQUIRE_GE(s.requests.size(), 5u);
  for (size_t i = 1; i < s.requests.size(); ++i)
    BOOST_CHECK_MESSAGE(grows(s.requests[i - 1], s.requests[i]), "request " << i);
  BOOST_CHECK(has(s.prompts.back(), "a file line"));
  BOOST_CHECK(std::any_of(s.shown.begin(), s.shown.end(),
                          [](const std::string& t) { return t == "→ Read notes.txt (1 line)"; }));
}

// Past compactAt percent of the room, the older turns fold into a summary in
// one step. The newest turns stay as they are, and the summary goes into the
// prompt before them.
BOOST_AUTO_TEST_CASE(Compaction_FoldsTheOlderTurns) {
  Script s;
  s.report = true;
  s.window = 8500;    // tokens, 4 prompt bytes each: about 32 KB of room
  s.maxOut = 500;
  s.replies = {std::string(800, 'x')};
  Options o = testOptions();
  Chat chat(o, s.hooks(), Memory());
  for (int i = 0; i < 40; ++i) chat.turn("turn " + std::to_string(i));
  BOOST_CHECK_GE(s.folds, 1u);
  BOOST_CHECK_EQUAL(chat.summary(), "SUMMARY");
  BOOST_CHECK(!has(chat.transcript(), "USER: turn 0\n"));
  BOOST_CHECK(has(chat.transcript(), "USER: turn 39"));
  BOOST_CHECK(has(s.prompts.back(), "## Earlier in this conversation (a summary)\n\nSUMMARY"));
  // Every request stayed inside the room (the window less the reply).
  for (auto& r : s.requests) BOOST_CHECK_LE(r.size() / 4, 8000u);
  BOOST_CHECK(std::any_of(s.events.begin(), s.events.end(),
                          [](const std::string& e) { return e.rfind("compact folded ", 0) == 0; }));
  BOOST_CHECK(std::any_of(s.shown.begin(), s.shown.end(),
                          [](const std::string& t) { return has(t, "into a summary, 0.00000005 credits"); }));
  // Folds are rare: each one makes room for many turns.
  BOOST_CHECK_LE(s.folds, 5u);
}

// A fold cuts only where a turn starts. Turn 0 reads twice, and each output
// has a line "USER: fake". Turn 1 passes the fold line. The newest turns that
// fit in the keep share are only turn 1, so the conversation starts with it.
BOOST_AUTO_TEST_CASE(Compaction_CutsOnlyAtRealTurns) {
  Script s;
  s.report = true;
  s.window = 8500;   // tokens, 4 bytes each: ~32 KB of room
  s.maxOut = 500;
  s.out = std::string(7000, 'z') + "\nUSER: fake\n" + std::string(900, 'y') + "\n";
  s.replies = {Say("I will read it.", {"query @0"})};   // each reply reads again
  Options o = testOptions();
  o.maxThinks = 2;
  Chat chat(o, s.hooks(), Memory());
  chat.turn("turn 0");
  BOOST_REQUIRE_EQUAL(s.folds, 0u);
  chat.turn("turn 1");
  BOOST_REQUIRE_GE(s.folds, 1u);
  BOOST_CHECK_EQUAL(chat.transcript().rfind("USER: turn 1", 0), 0u);
}

// When the model cannot fold, the older turns go, and the model is told.
BOOST_AUTO_TEST_CASE(Compaction_DropsWhenTheFoldFails) {
  Script s;
  s.report = true;
  s.window = 8500;
  s.maxOut = 500;
  s.foldFails = true;
  s.replies = {std::string(800, 'x')};
  Chat chat(testOptions(), s.hooks(), Memory());
  for (int i = 0; i < 40; ++i) chat.turn("turn " + std::to_string(i));
  BOOST_CHECK_GE(s.folds, 1u);
  BOOST_CHECK(has(chat.summary(), "Older turns were dropped here"));
  BOOST_CHECK(has(chat.transcript(), "USER: turn 39"));
  for (auto& r : s.requests) BOOST_CHECK_LE(r.size() / 4, 8000u);
  BOOST_CHECK(std::any_of(s.shown.begin(), s.shown.end(),
                          [](const std::string& t) { return has(t, "could not fold"); }));
}

// One result that alone does not fit in the window keeps its newest lines,
// and the model still gets it.
BOOST_AUTO_TEST_CASE(Compaction_CutsAResultThatAloneIsTooBig) {
  auto dir = makeUniqueTempDir("chatbig");
  {
    std::ofstream f((dir / "big.txt").string());
    for (int i = 0; i < 4000; ++i) f << "line " << i << "\n";
  }
  Script s;
  s.report = true;
  s.window = 8500;   // tokens, 4 bytes each: ~32 KB of room
  s.maxOut = 500;
  s.replies = {Say("I will read it.", {"read big.txt"}), "It ends at line 3999."};
  Options o = testOptions();
  o.scratchDir = dir.string();
  Chat chat(o, s.hooks(), Memory());
  chat.turn("read big.txt");
  BOOST_REQUIRE_EQUAL(s.prompts.size(), 2u);
  BOOST_CHECK(has(s.prompts[1], "[chat] the older part of this turn was cut"));
  BOOST_CHECK(has(s.prompts[1], "[... the start was cut]\nline "));
  BOOST_CHECK(has(s.prompts[1], "line 3999\n"));
  BOOST_CHECK(!has(s.prompts[1], "line 0\n"));
  for (auto& r : s.requests) BOOST_CHECK_LE(r.size() / 4, 8000u);
}

// The status numbers: the last prompt's tokens as the server counted them,
// the room, and the share from the cache.
BOOST_AUTO_TEST_CASE(Context_FromTheReport) {
  Script s;
  s.report = true;
  s.window = 100000;
  s.maxOut = 1000;
  s.replies = {"hello"};
  Chat chat(testOptions(), s.hooks(), Memory());
  chat.turn("hi");
  ContextUse u = chat.context();
  BOOST_CHECK(!u.estimated);
  BOOST_CHECK_EQUAL(u.promptTokens, s.requests.back().size() / 4);
  BOOST_CHECK_EQUAL(u.windowTokens, 99000u);
  BOOST_CHECK_EQUAL(u.cachedPercent, 24);   // a quarter, rounded down
  BOOST_CHECK(std::any_of(s.events.begin(), s.events.end(), [&](const std::string& e) {
    return e == "context " + std::to_string(u.promptTokens) + " 99000 24";
  }));
  // A server that does not report: an estimate against the default room.
  Script q;
  q.replies = {"hello"};
  Chat chat2(testOptions(), q.hooks(), Memory());
  chat2.turn("hi");
  BOOST_CHECK(chat2.context().estimated);
  BOOST_CHECK_EQUAL(chat2.context().windowTokens, 65536u - 8192u);
}

BOOST_AUTO_TEST_CASE(Context_Text) {
  ContextUse u;
  u.promptTokens = 15300;
  u.windowTokens = 122880;
  u.cachedPercent = 80;
  u.estimated = false;
  BOOST_CHECK_EQUAL(contextText(u), "context 15k of 122k (12%) · cache 80%");
  u.promptTokens = 1234;
  u.cachedPercent = -1;
  u.estimated = true;
  BOOST_CHECK_EQUAL(contextText(u), "context ~1.2k of 122k (1%)");
}

// A chat that closes the connection before the end of the turn is an error
// for the client: a program that drives the chat must not take it as done.
BOOST_AUTO_TEST_CASE(Socket_ClientFailsWhenTheChatLeaves) {
  auto dir = makeUniqueTempDir("chatsock");
  const std::string path = (dir / "c.sock").string();
  std::thread server([&] {
    ChatSocket sock;
    std::string err;
    BOOST_REQUIRE(sock.listen(path, err));
    std::string m;
    BOOST_CHECK(sock.next(m));
    BOOST_CHECK_EQUAL(m, "say hi");
    sock.send("show", "half a turn");
    // The socket goes away here, with no done.
  });
  BOOST_REQUIRE(ces::waitUntil([&] { return fs::exists(path); }));
  BOOST_CHECK_EQUAL(chatClient(path, "say hi"), 1);
  server.join();
}

BOOST_AUTO_TEST_CASE(Socket_EventEscaping) {
  std::string t = "a\\b\nc\r\nd";
  BOOST_CHECK_EQUAL(escapeEvent(t), "a\\\\b\\nc\\nd");
  BOOST_CHECK_EQUAL(unescapeEvent(escapeEvent("x\\y\nz")), "x\\y\nz");
  BOOST_CHECK(escapeEvent("one\ntwo").find('\n') == std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()

// ---------------------------------------------------------------------------
// End to end: the cesh binary, a real server, a scripted model.
// ---------------------------------------------------------------------------

namespace {

// A model that answers each call with the next reply of its script.
struct SeqBackend : ces::ThinkBackend {
  // The replies in order: the words, and the cesh commands that each runs.
  std::vector<std::pair<std::string, std::vector<std::string>>> replies;
  ces::ThinkChatEnd chat;          // the end of a reply that runs no command
  std::mutex mu;
  std::vector<std::string> prompts;
  std::vector<bool> chats;         // which calls were chat requests

  ces::ThinkOutcome run(const ces::ThinkInput& input, uint32_t,
                        const std::atomic<bool>&,
                        const std::function<bool(std::string_view)>& onText) override {
    const std::string& prompt = input.text;
    std::pair<std::string, std::vector<std::string>> reply;
    {
      std::lock_guard<std::mutex> lk(mu);
      reply = replies[std::min(prompts.size(), replies.size() - 1)];
      prompts.push_back(prompt);
      chats.push_back(input.chat);
    }
    ces::ThinkOutcome o;
    o.chat = chat;
    if (!reply.second.empty()) {
      json::array calls;
      for (auto& c : reply.second)
        calls.push_back(json::object{
            {"id", "c" + std::to_string(calls.size() + 1)}, {"type", "function"},
            {"function", json::object{{"name", "cesh"},
                                      {"arguments", json::serialize(json::object{{"command", c}})}}}});
      o.chat.toolCalls = json::serialize(calls);
      o.chat.finishReason = "tool_calls";
    }
    if (!reply.first.empty()) onText(reply.first);
    o.status = ces::CES_OK;
    o.billing = ces::ThinkOutcome::kUsage;
    o.usage = ces::ThinkUsage{100, 0, 10};
    return o;
  }
};

}  // namespace

// A server with think on a scripted model, and a funded key.
struct ChatServerFixture {
  fs::path dir;
  std::unique_ptr<ces::CesServer> server;
  uint16_t mainPort = 0;
  std::shared_ptr<SeqBackend> backend = std::make_shared<SeqBackend>();
  ces::KeyPair key;

  ChatServerFixture() {
    blog::init();
    blog::set_level(blog::fatal);
    dir = makeUniqueTempDir("chate2e");
    minx::Hash priv;
    priv.fill(0xC7);
    ces::CesConfig cfg = makeTestConfig(dir, priv, std::numeric_limits<uint64_t>::max());
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = {{"/ces/think/1", "builtin:think"}};
    cfg.thinkFeeIn = 1'000'000;
    cfg.thinkFeeCachedIn = 100'000;
    cfg.thinkFeeOut = 2'000'000;
    cfg.thinkMaxOutTokens = 1000;
    cfg.thinkMaxInputBytes = 256 * 1024;
    server = std::make_unique<ces::CesServer>(cfg);
    mainPort = server->start(0);
    BOOST_REQUIRE(server->thinkHandler() != nullptr);
    backend->replies = {{"I will read your balance.", {"query @0"}},
                        {"Your account is there. Done.", {}}};
    server->thinkHandler()->_testSetBackend(backend);
    server->_brr(key.getPublicKeyAsHash(), 10'000'000'000);
    BOOST_REQUIRE(ces::waitUntil([&] {
      return ces::e2e::runShell(ceshPrefix() + " query @0", 30).exitCode == 0;
    }));
  }
  ~ChatServerFixture() {
    if (server) server->stop();
    boost::system::error_code ec;
    fs::remove_all(dir, ec);
  }
  std::string ceshPrefix() const {
    return "HOME=" + dir.string() + "/home CESH_WALLET=\"00" + key.getPrivateKeyHexStr() + "\" " +
           ces::e2e::findCeshBinary() +
           " -l fatal --server localhost:" + std::to_string(mainPort);
  }
};

BOOST_FIXTURE_TEST_SUITE(CeshChatE2ETests, ChatServerFixture)

BOOST_AUTO_TEST_CASE(Chat_RunsAReadAndAnswers) {
  // No --rpc-port: the chat finds it with ping.
  std::string cmd = "printf 'what is my balance?\\n' | " + ceshPrefix() +
                    " chat --memory " + (dir / "m.md").string();
  auto r = ces::e2e::runShell(cmd, 60);
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  BOOST_CHECK_MESSAGE(has(r.out, "I will read your balance."), r.out);
  BOOST_CHECK_MESSAGE(has(r.out, "→ cesh query @0"), r.out);
  BOOST_CHECK_MESSAGE(has(r.out, "Your account is there. Done."), r.out);

  std::lock_guard<std::mutex> lk(backend->mu);
  BOOST_REQUIRE_EQUAL(backend->prompts.size(), 2u);
  BOOST_CHECK(has(backend->prompts[0], R"({"role":"user","content":"what is my balance?"})"));
  BOOST_CHECK(has(backend->prompts[0], "money/transfer  "));       // the manual index
  BOOST_CHECK(has(backend->prompts[0], "Wallet keys (label and public key):\\n@0 " +
                                        key.getPublicKeyHexStr()));
  // No part of the private key goes to the model.
  const std::string privHex = "00" + key.getPrivateKeyHexStr();
  BOOST_CHECK(!has(backend->prompts[0], privHex.substr(0, 6) + "..."));
  BOOST_CHECK(!has(backend->prompts[0], key.getPrivateKeyHexStr().substr(0, 16)));
  BOOST_CHECK(has(backend->prompts[1], "RESULT of `query @0`: exit 0"));
}

// Ctrl+C ends a chat that waits for the user's next line. ceslib's SIGINT
// handler only sets a flag, and a chat that waits in getline never reads it.
// The chat's stdin is a FIFO that stays open, so the chat waits; the script
// sends SIGINT after the chat prints its banner. The loops only bound a
// failure.
BOOST_AUTO_TEST_CASE(Chat_CtrlC_EndsIt) {
  const std::string d = dir.string();
  std::string script =
    "mkfifo " + d + "/in; sleep 600 > " + d + "/in & hold=$!; " +
    ceshPrefix() + " chat --memory " + d + "/m.md < " + d + "/in > " + d + "/out 2>&1 & pid=$!; "
    "i=0; while [ $i -lt 600 ] && ! grep -q 'Type exit to end' " + d + "/out; do sleep 0.1; i=$((i+1)); done; "
    "kill -INT $pid; "
    "i=0; while [ $i -lt 100 ] && kill -0 $pid 2>/dev/null; do sleep 0.1; i=$((i+1)); done; "
    "if kill -0 $pid 2>/dev/null; then echo STILL_RUNNING; kill -9 $pid; fi; "
    "kill $hold; wait $pid; echo status=$?";
  auto r = ces::e2e::runShell(script, 120);
  BOOST_CHECK_MESSAGE(!has(r.out, "STILL_RUNNING"), r.out);
  BOOST_CHECK_MESSAGE(has(r.out, "status=130"), r.out);
}

// A program uses the chat over its socket: a say that leads to an action,
// the ask, a yes on a new connection, then quit. The chat runs in its own
// process; each client call is one message.
BOOST_AUTO_TEST_CASE(Socket_SayAskYesQuit) {
  ces::KeyPair dest;
  backend->replies = {{"Sending one credit.", {"transfer " + dest.getPublicKeyHexStr() + " 100000000 --open"}},
                      {"Sent.", {}}};
  const std::string sock = (dir / "chat.sock").string();
  ces::e2e::RunResult server{};
  std::thread t([&] {
    server = ces::e2e::runShell(ceshPrefix() + " chat --trace --memory " + (dir / "m.md").string() +
                                " --listen " + sock + " < /dev/null", 120);
  });
  BOOST_REQUIRE(ces::waitUntil([&] { return fs::exists(sock); }));
  const std::string client = ces::e2e::findCeshBinary() + " chat --connect " + sock + " ";

  auto r1 = ces::e2e::runShell(client + "say send one credit", 60);
  BOOST_CHECK_EQUAL(r1.exitCode, 0);
  BOOST_CHECK_MESSAGE(has(r1.out, "prompt "), r1.out);                     // --trace
  BOOST_CHECK_MESSAGE(has(r1.out, R"({"role":"user","content":"send one credit"})"), r1.out);
  BOOST_CHECK_MESSAGE(has(r1.out, "reply Sending one credit."), r1.out);
  BOOST_CHECK_MESSAGE(has(r1.out, "cost "), r1.out);
  BOOST_CHECK_MESSAGE(has(r1.out, "run action transfer " + dest.getPublicKeyHexStr()), r1.out);
  BOOST_CHECK_MESSAGE(has(r1.out, "\nask Send 1 credit from @0 to "), r1.out);
  BOOST_CHECK_MESSAGE(has(r1.out, ", opening its account if it has none. Run it?\n"), r1.out);

  auto r2 = ces::e2e::runShell(client + "yes", 60);
  BOOST_CHECK_EQUAL(r2.exitCode, 0);
  BOOST_CHECK_MESSAGE(has(r2.out, "result 0"), r2.out);
  BOOST_CHECK_MESSAGE(has(r2.out, "show Sent."), r2.out);
  BOOST_CHECK_MESSAGE(has(r2.out, "\ndone\n"), r2.out);

  auto r3 = ces::e2e::runShell(client + "yes", 60);   // nothing waits
  BOOST_CHECK_EQUAL(r3.exitCode, 1);
  BOOST_CHECK_MESSAGE(has(r3.out, "error no question waits"), r3.out);

  auto r4 = ces::e2e::runShell(client + "quit", 60);
  BOOST_CHECK_MESSAGE(has(r4.out, "bye"), r4.out);
  t.join();
  BOOST_CHECK_EQUAL(server.exitCode, 0);
  BOOST_CHECK(!fs::exists(sock));   // the chat removes its socket

  auto r5 = ces::e2e::runShell(client + "say hi", 30);
  BOOST_CHECK_EQUAL(r5.exitCode, 1);
  BOOST_CHECK_MESSAGE(has(r5.out, "no chat listens on"), r5.out);
}

// --yolo: an action runs with no question, and the user still sees it.
BOOST_AUTO_TEST_CASE(Socket_YoloSkipsTheQuestion) {
  ces::KeyPair dest;
  backend->replies = {{"", {"transfer " + dest.getPublicKeyHexStr() + " 100000000 --open"}},
                      {"Sent.", {}}};
  const std::string sock = (dir / "y.sock").string();
  ces::e2e::RunResult server{};
  std::thread t([&] {
    server = ces::e2e::runShell(ceshPrefix() + " chat --yolo --memory " + (dir / "m.md").string() +
                                " --listen " + sock + " < /dev/null", 120);
  });
  BOOST_REQUIRE(ces::waitUntil([&] { return fs::exists(sock); }));
  const std::string client = ces::e2e::findCeshBinary() + " chat --connect " + sock + " ";
  auto r = ces::e2e::runShell(client + "say send one credit", 60);
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  BOOST_CHECK_MESSAGE(!has(r.out, "\nask "), r.out);
  BOOST_CHECK_MESSAGE(has(r.out, "show ✓ yes  Send 1 credit from @0 to "), r.out);
  BOOST_CHECK_MESSAGE(has(r.out, "result 0"), r.out);
  BOOST_CHECK_MESSAGE(has(r.out, "\ndone\n"), r.out);
  ces::e2e::runShell(client + "quit", 30);
  t.join();
}

// The user's own command runs with no model call, and its output reaches the
// socket (not the chat's own stdout).
BOOST_AUTO_TEST_CASE(Socket_OwnCommandShowsItsOutput) {
  backend->replies = {{"no model call is expected", {}}};
  size_t callsBefore;
  {
    std::lock_guard<std::mutex> lk(backend->mu);
    callsBefore = backend->prompts.size();
  }
  const std::string sock = (dir / "o.sock").string();
  ces::e2e::RunResult server{};
  std::thread t([&] {
    server = ces::e2e::runShell(ceshPrefix() + " chat --memory " + (dir / "m.md").string() +
                                " --listen " + sock + " < /dev/null", 120);
  });
  BOOST_REQUIRE(ces::waitUntil([&] { return fs::exists(sock); }));
  const std::string client = ces::e2e::findCeshBinary() + " chat --connect " + sock + " ";
  auto r = ces::e2e::runShell(client + "say '$ ping'", 60);
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  BOOST_CHECK_MESSAGE(has(r.out, "show → cesh ping\n"), r.out);
  BOOST_CHECK_MESSAGE(has(r.out, "status=ok") || has(r.out, "Status"), r.out);
  BOOST_CHECK_MESSAGE(has(r.out, "\ndone\n"), r.out);
  {
    std::lock_guard<std::mutex> lk(backend->mu);
    BOOST_CHECK_EQUAL(backend->prompts.size(), callsBefore);
  }
  ces::e2e::runShell(client + "quit", 30);
  t.join();
  BOOST_CHECK_MESSAGE(!has(server.out, "status=ok"), server.out);
}

// cesh think --chat sends a chat request and prints the answer as one JSON
// object on stdout, from --in or from stdin.
BOOST_AUTO_TEST_CASE(Think_ChatPrintsOneJsonObject) {
  backend->replies = {{"Looking.", {}}};
  backend->chat.toolCalls =
      R"([{"id":"c1","type":"function","function":{"name":"shell","arguments":"{\"command\":\"ls\"}"}}])";
  backend->chat.finishReason = "tool_calls";
  const std::string req =
      R"({"messages":[{"role":"user","content":"what is here?"}],)"
      R"("tools":[{"type":"function","function":{"name":"shell"}}]})";
  {
    std::ofstream f(dir / "req.json");
    f << req;
  }
  const std::string want =
      R"({"content":"Looking.","tool_calls":[{"id":"c1","type":"function","function":)"
      R"({"name":"shell","arguments":"{\"command\":\"ls\"}"}}],"finish_reason":"tool_calls"})"
      "\n";
  auto r = ces::e2e::runShell(ceshPrefix() + " think --chat --in file:" +
                                  (dir / "req.json").string() + " 2>/dev/null", 60);
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  BOOST_CHECK_EQUAL(r.out, want);
  r = ces::e2e::runShell(ceshPrefix() + " think --chat < " + (dir / "req.json").string() +
                             " 2>/dev/null", 60);
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  BOOST_CHECK_EQUAL(r.out, want);
  std::lock_guard<std::mutex> lk(backend->mu);
  BOOST_REQUIRE_EQUAL(backend->chats.size(), 2u);
  BOOST_CHECK(backend->chats[0] && backend->chats[1]);
  BOOST_CHECK(has(backend->prompts[0], R"("content":"what is here?")"));
}

// A wrong request gets its reason, and nothing goes to the server.
BOOST_AUTO_TEST_CASE(Think_ChatRefusesABadRequest) {
  auto r = ces::e2e::runShell(ceshPrefix() + " think --chat --in 'text:{\"messages\":[]}'", 60);
  BOOST_CHECK_EQUAL(r.exitCode, 1);
  BOOST_CHECK_MESSAGE(has(r.out, "not a chat request: the request has no messages"), r.out);
  r = ces::e2e::runShell(ceshPrefix() + " think --chat --file /h/x --in 'text:{}'", 60);
  BOOST_CHECK_EQUAL(r.exitCode, 1);
  BOOST_CHECK_MESSAGE(has(r.out, "--chat takes no --file"), r.out);
  std::lock_guard<std::mutex> lk(backend->mu);
  BOOST_CHECK(backend->prompts.empty());
}

BOOST_AUTO_TEST_SUITE_END()
