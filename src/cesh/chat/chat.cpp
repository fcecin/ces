#include "chat/chat.h"

#include <ces/util/fileperm.h>

#include <boost/json.hpp>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <regex>
#include <set>
#include <sstream>

namespace ces::chat {

namespace {

std::string trim(const std::string& s) {
  size_t a = 0, b = s.size();
  while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
  while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
  return s.substr(a, b - a);
}

// cesh global options that take a value, so their value is not a command.
const std::set<std::string> kGlobalWithValue = {
  "-l", "--log", "--server", "--tries", "--port", "--proxy", "--rpc-port",
  "--server-key", "-a", "--actor", "-r", "--wallet"};

// Commands that have subcommands, so the table needs two words.
const std::set<std::string> kGroups = {
  "keys", "keyname", "alias", "file", "compute", "asset", "ramfile", "mail",
  "autoexec"};

const std::set<std::string> kReads = {
  "man", "query", "squery", "ping", "peer-info", "server-info", "builtin-info",
  "keys list",
  "keyname query", "keyname resolve", "alias read",
  "file stat", "file get", "compute ps", "compute stat", "compute instances",
  "asset query", "asset squery"};

const std::map<std::string, std::string> kRefused = {
  {"chat", "a chat inside the chat"},
  {"bootstrap", "it mines until stopped and starts a shell; run it outside the chat"}};

std::string oneLine(std::string s) {
  for (auto& c : s)
    if (c == '\n' || c == '\r') c = ' ';
  return trim(s);
}

std::string cap(const std::string& s, size_t n) {
  if (s.size() <= n) return s;
  return s.substr(0, n) + "\n[... " + std::to_string(s.size() - n) + " more bytes]\n";
}

}  // namespace

// The cesh options that take no value. Every other option takes one, so its
// value is not a command word. (`-s` is a flag on `keys list` and takes a
// value on `man`: see isFlag.)
const std::set<std::string> kFlags = {
  "-c", "--cache-only", "--extsign", "--hex", "--immutable", "--nonceless", "--off", "--open",
  "--owner-pays", "-p", "--parse-only", "--private", "--public", "-q", "--quiet", "--secp",
  "--secrets", "--trace", "-v", "--verbose", "--wait", "-h", "--help", "--help-all", "--version"};

bool isFlag(const std::string& a, const std::vector<std::string>& wordsSoFar) {
  if (a == "-s") return !wordsSoFar.empty() && wordsSoFar[0] == "keys";
  return kFlags.count(a) > 0;
}

std::vector<std::string> commandWords(const std::vector<std::string>& args) {
  std::vector<std::string> words;
  for (size_t i = 0; i < args.size(); ++i) {
    const std::string& a = args[i];
    if (a.empty() || a[0] != '-') {
      words.push_back(a);
      continue;
    }
    // An option's value is not a command word: `file put --deposit 5 a b`
    // uploads a, and `transfer -a @1 x 5` signs with @1.
    if (a.find('=') == std::string::npos && !isFlag(a, words)) ++i;
  }
  return words;
}

// `keys list -s` and `--secrets` print private keys too.
bool asksSecrets(const std::vector<std::string>& args) {
  auto words = commandWords(args);
  for (auto& a : args)
    if (a == "--secrets" || a.rfind("--secrets=", 0) == 0 ||
        (a == "-s" && words.size() >= 2 && words[0] == "keys")) return true;
  return false;
}

std::string publicKeysOf(const std::string& keysListPublicOut) {
  static const std::regex row(R"(^\[(@[0-9]+)\].*\(([0-9a-f]{64})\)\s*$)");
  std::string out;
  std::istringstream in(keysListPublicOut);
  std::string line;
  std::smatch m;
  while (std::getline(in, line))
    if (std::regex_match(line, m, row)) out += m[1].str() + " " + m[2].str() + "\n";
  return out.empty() ? "(no keys)\n" : out;
}

namespace {

// "0056a1f5…ca68" for a 64-hex key; anything else as it is.
std::string shortKey(const std::string& k) {
  if (k.size() == 64) return k.substr(0, 8) + "…" + k.substr(60);
  return k;
}

std::string creditsOf(const std::string& raw) {
  char* end = nullptr;
  unsigned long long v = std::strtoull(raw.c_str(), &end, 10);
  if (raw.empty() || !end || *end) return raw + " raw";
  char buf[48];
  std::snprintf(buf, sizeof buf, "%.8f", static_cast<double>(v) / 1e8);
  std::string s = buf;
  while (s.size() > 1 && s.back() == '0') s.pop_back();
  if (!s.empty() && s.back() == '.') s.pop_back();
  return s + (s == "1" ? " credit" : " credits");
}

}  // namespace

std::string outsideScratch(const std::vector<std::string>& args, const std::string& scratch) {
  if (scratch.empty()) return "";
  std::error_code ec;
  const std::string root = std::filesystem::weakly_canonical(scratch, ec).string();
  auto words = commandWords(args);
  const bool keysSave = words.size() >= 2 && words[0] == "keys" && (words[1] == "gen" || words[1] == "add");
  const char* home = std::getenv("HOME");
  // Free text is not a path: the words of a `think` prompt, and the line of
  // `dial --line`. (`think --in file:...` still names a file, and is checked.)
  const bool thinkWords = !words.empty() && words[0] == "think";
  bool pastCommand = false;
  for (size_t i = 0; i < args.size(); ++i) {
    if (keysSave && args[i] == "-w") { ++i; continue; }
    if (args[i] == "--line") { ++i; continue; }
    if (args[i].rfind("--line=", 0) == 0) continue;
    // A word of the prompt: not after an option that takes a value (that is
    // the option's value, as in `--in file:x`, and is checked).
    const bool optionValue = i > 0 && !args[i - 1].empty() && args[i - 1][0] == '-' &&
                             args[i - 1].find('=') == std::string::npos &&
                             !isFlag(args[i - 1], {});
    if (thinkWords && !optionValue && !args[i].empty() && args[i][0] != '-') {
      if (pastCommand) continue;
      if (args[i] == "think") { pastCommand = true; continue; }
    }
    std::string p = args[i];
    if (p.rfind("--", 0) == 0) {
      auto eq = p.find('=');
      if (eq == std::string::npos) continue;   // its value is the next argument
      p = p.substr(eq + 1);
    } else if (!p.empty() && p[0] == '-') {
      continue;                                 // a short option; its value comes next
    }
    if (p.rfind("file:", 0) == 0) p = p.substr(5);
    if (p.empty()) continue;
    bool server = false;
    for (const char* z : {"/h/", "/f/", "/p/", "/s/", "/m/"})
      if (p.rfind(z, 0) == 0) server = true;
    if (server) continue;
    if (p[0] == '~' && home && (p.size() == 1 || p[1] == '/')) p = std::string(home) + p.substr(1);
    std::filesystem::path full = std::filesystem::path(p).is_absolute()
                                     ? std::filesystem::path(p)
                                     : std::filesystem::path(root) / p;
    std::string c = std::filesystem::weakly_canonical(full, ec).string();
    if (ec || !(c == root || c.rfind(root + "/", 0) == 0)) return args[i];
  }
  return "";
}

std::string describeAction(const std::vector<std::string>& args) {
  std::string actor = "@0";
  bool open = false;
  for (size_t i = 0; i < args.size(); ++i) {
    if ((args[i] == "-a" || args[i] == "--actor") && i + 1 < args.size()) actor = args[i + 1];
    if (args[i] == "--open") open = true;
  }
  auto w = commandWords(args);
  auto at = [&](size_t i) { return i < w.size() ? w[i] : std::string("?"); };
  if (w.empty()) return "";
  const std::string& c = w[0];
  if (c == "transfer")
    return "Send " + creditsOf(at(2)) + " from " + actor + " to " + shortKey(at(1)) +
           (open ? ", opening its account if it has none" : "");
  if (c == "mine") return "Mine one proof-of-work solution on the server (it uses the CPU for a while)";
  if (c == "dial") {
    std::string line;
    for (size_t i = 0; i < args.size(); ++i) {
      if (args[i] == "--line" && i + 1 < args.size()) line = args[i + 1];
      else if (args[i].rfind("--line=", 0) == 0) line = args[i].substr(7);
    }
    return "Send \"" + line + "\" to program " + at(1) + " and read one reply";
  }
  if (c == "cross")
    return "Send " + creditsOf(at(2)) + " from " + actor + " here to " + shortKey(at(1)) +
           " on the server " + at(3);
  const std::string sub = w.size() > 1 ? w[1] : "";
  if (c == "file" && sub == "put") return "Upload " + at(2) + " to " + at(3) + ", paid by " + actor;
  if (c == "file" && sub == "deposit") return "Put " + creditsOf(at(3)) + " from " + actor + " into " + at(2);
  if (c == "file" && sub == "withdraw") return "Take " + creditsOf(at(3)) + " out of " + at(2) + " to " + actor;
  if (c == "file" && sub == "rm") return "Delete the file " + at(2);
  if (c == "compute" && sub == "launch") return "Start the program " + at(2);
  if (c == "compute" && sub == "call") {
    std::string memo;
    for (size_t i = 0; i + 1 < args.size(); ++i)
      if (args[i] == "--in") memo += (memo.empty() ? "" : " ") + args[i + 1];
    if (memo.size() > 60) memo = memo.substr(0, 57) + "...";
    return "Call program " + at(2) + (memo.empty() ? "" : " with \"" + memo + "\"") + ", paying it " +
           creditsOf(at(3)) + " from " + actor;
  }
  if (c == "compute" && sub == "kill") return "Stop the program with pid " + at(2);
  if (c == "keyname" && sub == "register") return "Give " + actor + " the name " + at(2);
  if (c == "keyname" && sub == "clear") return "Remove the name of " + actor;
  if (c == "keys" && sub == "gen") return "Make a new key and save it in the wallet file";
  if (c == "keys" && sub == "add") return "Add a key that you type next to the wallet file";
  return "";
}

Kind classify(const std::vector<std::string>& args, std::string* why) {
  auto refuse = [&](const std::string& w) {
    if (why) *why = w;
    return Kind::Refused;
  };
  bool help = false;
  for (auto& a : args)
    if (a == "-h" || a == "--help" || a == "--help-all") help = true;
  std::vector<std::string> words = commandWords(args);
  if (words.empty()) return help ? Kind::Read : refuse("no command");

  std::string cmd = words[0];
  if (kGroups.count(cmd) && words.size() >= 2) cmd += " " + words[1];

  auto r = kRefused.find(cmd);
  if (r != kRefused.end()) return refuse(r->second);
  if (cmd == "man") {
    for (auto& a : args)
      if (a == "--serve" || a.rfind("--serve=", 0) == 0)
        return refuse("a web server runs until stopped; run it outside the chat");
  }
  if (cmd == "dial") {
    // The plain dial streams stdin and stdout until the program closes; the
    // chat has neither. `dial <pid> --line <text>` is one exchange.
    bool line = false;
    for (auto& a : args) line = line || a == "--line" || a.rfind("--line=", 0) == 0;
    if (!line) return refuse("a plain dial is an interactive stream; use dial <pid> --line <text>");
  }
  if (help) return Kind::Read;
  if (cmd == "keys add" && words.size() > 2)
    return refuse("a private key must not be in the chat; the chat asks the user for it");
  if (asksSecrets(args)) return Kind::Action;   // private keys, shown to the user only
  if (cmd == "file get") {
    // `file get <remote> <local>` writes a local file.
    size_t positionals = words.size() - 2;
    if (positionals >= 2 && words[3] != "-") return Kind::Action;
  }
  return kReads.count(cmd) ? Kind::Read : Kind::Action;
}

bool splitLine(const std::string& line, std::vector<std::string>& out) {
  out.clear();
  std::string cur;
  bool inWord = false;
  char quote = 0;
  for (size_t i = 0; i < line.size(); ++i) {
    char c = line[i];
    if (quote == '\'') {
      if (c == '\'') quote = 0;
      else cur += c;
      continue;
    }
    if (c == '\\' && i + 1 < line.size()) {
      cur += line[++i];
      inWord = true;
      continue;
    }
    if (quote == '"') {
      if (c == '"') quote = 0;
      else cur += c;
      continue;
    }
    if (c == '\'' || c == '"') {
      quote = c;
      inWord = true;
      continue;
    }
    if (std::isspace(static_cast<unsigned char>(c))) {
      if (inWord) out.push_back(cur);
      cur.clear();
      inWord = false;
      continue;
    }
    cur += c;
    inWord = true;
  }
  if (quote) return false;
  if (inWord) out.push_back(cur);
  return true;
}

std::string printable(const std::string& text) {
  std::string o;
  o.reserve(text.size());
  for (size_t i = 0; i < text.size(); ++i) {
    const auto c = static_cast<unsigned char>(text[i]);
    if (c == '\n' || c == '\t') {
      o += text[i];
    } else if (c < 0x20 || c == 0x7f) {
      o += '?';
    } else if (c == 0xc2 && i + 1 < text.size() && static_cast<unsigned char>(text[i + 1]) >= 0x80 &&
               static_cast<unsigned char>(text[i + 1]) <= 0x9f) {
      o += '?';   // a C1 control in UTF-8
      ++i;
    } else {
      o += text[i];
    }
  }
  return o;
}

bool shellCommand(std::string& command) {
  std::string t = trim(command);
  if (t.empty() || t[0] != '$') return false;
  t = trim(t.substr(1));
  if (t.rfind("cesh ", 0) == 0) t = trim(t.substr(5));
  command = t;
  return true;
}

bool userCommand(const std::string& userLine, std::string& line) {
  std::string t = trim(userLine);
  if (t.empty() || (t[0] != '$' && t.rfind("cesh ", 0) != 0)) return false;
  std::string c = t[0] == '$' ? t : "$ " + t;
  if (!shellCommand(c) || c.empty()) return false;
  line = "$ " + c;
  return true;
}

namespace {

// Credits from raw units, with the trailing zeros cut.
std::string credits(int64_t raw) {
  char buf[48];
  std::snprintf(buf, sizeof buf, "%.8f", static_cast<double>(raw) / 1e8);
  std::string s = buf;
  while (s.size() > 1 && s.back() == '0') s.pop_back();
  if (!s.empty() && s.back() == '.') s.pop_back();
  return s;
}

}  // namespace

// ---- Memory ----

Memory::Memory(std::string path) : path_(std::move(path)) {}

bool Memory::load() {
  notes_.clear();
  if (path_.empty()) return true;
  std::ifstream f(path_);
  if (!f) return true;   // no file yet: no notes
  std::string line;
  while (std::getline(f, line)) {
    if (line.rfind("- ", 0) != 0) continue;
    auto colon = line.find(':', 2);
    if (colon == std::string::npos) continue;
    std::string name = trim(line.substr(2, colon - 2));
    if (!name.empty()) notes_[name] = trim(line.substr(colon + 1));
  }
  return !f.bad();
}

bool Memory::save() const {
  if (path_.empty()) return true;
  {
    std::ofstream f(path_, std::ios::trunc);
    if (!f) return false;
    f << text();
    if (!f) return false;
  }
  // The notes are the user's (names, keys, servers): owner-only, as the wallet.
  return ces::setSecurePermission(path_).empty();
}

void Memory::set(const std::string& name, const std::string& text) {
  notes_[oneLine(name)] = oneLine(text);
}

bool Memory::erase(const std::string& name) { return notes_.erase(trim(name)) > 0; }

std::string Memory::text() const {
  std::string o = "# cesh chat notes\n";
  for (auto& [k, v] : notes_) o += "- " + k + ": " + v + "\n";
  return o;
}

// ---- Tool calls ----

namespace json = boost::json;

// The one tool of the model.
const char* const kTool = R"({"type":"function","function":{"name":"cesh",
"description":"Run one cesh command, or one of the chat's own commands: ls, read <name>, write <name> (with content), remember <name>: <text>, forget <name>. You get what it printed.",
"parameters":{"type":"object","properties":{
"command":{"type":"string","description":"The command, without the word cesh, such as: query @0"},
"content":{"type":"string","description":"For write: the text of the file."}},
"required":["command"]}}})";

std::vector<ToolCall> toolCallsOf(const std::string& text) {
  std::vector<ToolCall> out;
  boost::system::error_code ec;
  json::value v = json::parse(text, ec);
  if (ec || !v.is_array()) return out;
  for (const json::value& c : v.as_array()) {
    if (!c.is_object()) continue;
    ToolCall t;
    const json::object& o = c.as_object();
    if (const json::value* id = o.if_contains("id"); id && id->is_string()) t.id = std::string(id->as_string());
    if (t.id.empty()) continue;   // a call with no id cannot get its result
    const json::value* fn = o.if_contains("function");
    const json::object* f = fn && fn->is_object() ? &fn->as_object() : nullptr;
    const json::value* name = f ? f->if_contains("name") : nullptr;
    const json::value* args = f ? f->if_contains("arguments") : nullptr;
    json::value a;
    if (!name || !name->is_string() || name->as_string() != "cesh") {
      t.error = "there is no tool " +
                (name && name->is_string() ? "\"" + std::string(name->as_string()) + "\"" : std::string("of that name")) +
                ": the one tool is cesh";
    } else if (!args || !args->is_string() || (a = json::parse(args->as_string(), ec), ec) || !a.is_object()) {
      t.error = "the arguments are not a JSON object";
    } else {
      const json::value* cmd = a.as_object().if_contains("command");
      const json::value* content = a.as_object().if_contains("content");
      if (cmd && cmd->is_string()) t.command = trim(std::string(cmd->as_string()));
      if (t.command.rfind("cesh ", 0) == 0) t.command = trim(t.command.substr(5));
      if (content && content->is_string()) t.content = std::string(content->as_string());
      if (t.command.empty()) t.error = "the arguments have no command";
    }
    out.push_back(std::move(t));
  }
  return out;
}

std::string chatRequest(const std::string& system, const std::vector<Message>& messages, bool tools) {
  json::array ms;
  ms.push_back(json::object{{"role", "system"}, {"content", system}});
  std::vector<std::string> waiting;   // the calls that have no result yet
  auto close = [&] {
    for (auto& id : waiting)
      ms.push_back(json::object{{"role", "tool"}, {"tool_call_id", id}, {"content", "did not run"}});
    waiting.clear();
  };
  auto user = [&](const std::string& content) {
    json::object& last = ms.back().as_object();
    if (last.at("role").as_string() == "user")
      last["content"] = std::string(last.at("content").as_string()) + "\n\n" + content;
    else
      ms.push_back(json::object{{"role", "user"}, {"content", content}});
  };
  for (const Message& m : messages) {
    if (m.role == "tool") {
      auto it = std::find(waiting.begin(), waiting.end(), m.toolCallId);
      if (it != waiting.end()) {
        waiting.erase(it);
        ms.push_back(json::object{{"role", "tool"}, {"tool_call_id", m.toolCallId}, {"content", m.content}});
      } else {
        close();
        user("[chat] " + m.content);   // its call was folded or cut
      }
      continue;
    }
    close();
    if (m.role == "assistant") {
      json::object a{{"role", "assistant"}, {"content", m.content}};
      if (!m.reasoning.empty()) a["reasoning_content"] = m.reasoning;
      boost::system::error_code ec;
      json::value calls = m.toolCalls.empty() ? json::value() : json::parse(m.toolCalls, ec);
      if (!ec && calls.is_array() && !calls.as_array().empty()) {
        for (const json::value& c : calls.as_array())
          if (c.is_object() && c.as_object().if_contains("id"))
            waiting.push_back(std::string(c.as_object().at("id").as_string()));
        a["tool_calls"] = std::move(calls);
      }
      ms.push_back(std::move(a));
    } else {
      user(m.content);
    }
  }
  close();
  json::object req{{"messages", std::move(ms)}};
  if (tools) {
    static const json::value tool = json::parse(kTool);
    req["tools"] = json::array{tool};
  }
  return json::serialize(req);
}

// ---- Chat ----

namespace {

const char* kRules = R"(You are cesh chat, the assistant inside cesh, the wallet and command line of CES.
CES is a network of sovereign ledgers. The user holds keys in a cesh wallet and acts on servers through cesh.
You help the user, and you act for the user by running cesh commands with the cesh tool.

How you act:
- To run a cesh command, call the cesh tool with the command, without the word "cesh", such as query @0 or man errors. One reply can call it more than once.
- The user sees each command and its output. The manual pages that you read (man) go to you only.
- When the user's line can be done with cesh commands ("my balance", "call program 8 with hi", or a line that is already a command), call the tool and write no words. The output is the answer: when the commands succeed, the turn ends. When the line is already a correct command, run it as it is. When it needs a fix, run the fixed command, and say nothing about the fix.
- When you need the results to go on (a task of more steps, or a question that you answer from the output), write one short sentence with your first calls: what you will do, not what you will find. The results of each step come back to you, until you write a reply with no calls. In that last reply, write only what the output does not already show. No words at all is a correct last reply.
- A command that fails comes back to you: fix it, or say in a few words why it failed.
- Only the tool runs commands. Everything that you write is shown as it is: markdown code blocks are text, and nothing in them runs. Do not write commands for the user to type: run them. The chat asks the user before each action.
- A manual page or a file that you read stays in the conversation. Do not read one twice.
- Reads (man, query, ping, file stat, compute ps, ...) run at once.
- All other commands (transfers, uploads, deposits, launches, keys, names, ...) run only if the user says yes, and the chat asks the user before each one. So when the user asks you to do something, do it. Do not ask the user whether to go ahead; the chat does that.
- You can manage the user's keys: keys list, keys gen, keys add, keys export. You never see a private key, and the chat keeps it that way: keys list gives you the public keys, keys gen saves the new key in the wallet file and tells you its public key, keys add asks the user for the key itself (run only `keys add`, never with a key), and keys export shows the private keys to the user only. Never write a private key in a command or in your reply.
- Amounts are raw units: 1 credit = 100000000 raw.
- When you are not sure of a fact or a syntax, read the manual first: `man <page>`, `man <command>` or `man --search <word>`. Do not guess a command.
- When a command fails, read the error in the manual (`man errors`) before you explain it.
- You have one local directory for files, the scratch. You see nothing else on the user's disk. The command ls lists it, and read <name> reads a file. To write a file, run write <name> with the text of the file in content. The user approves each write. Names are flat (no directories). cesh commands that take a local file (file put, file get, --in file:, --out) use these names, so you can read what a command wrote. A command's printed output (compute call prints the program's reply) comes back to you as its result.
- Before you write a Lua program, read `man lua`: a program needs on_l2call and ces.run().
- To talk to a running program: dial <pid> --line <text> sends one line and gives you its one reply line (the plain interactive dial does not run here).
- To keep a fact about the user for later chats, run remember <name>: <text>. To drop one, run forget <name>. The user approves each one.
- The chat itself writes the user messages that start with [chat].
- Answer in plain, short words.)";

}  // namespace

Chat::Chat(Options opt, Hooks hooks, Memory memory)
  : opt_(std::move(opt)), hooks_(std::move(hooks)), memory_(std::move(memory)) {
  notes_ = notesText();
}

std::string Chat::declined(const std::string& head, const std::string& what) {
  declined_ = true;
  return head + what + "; the user said no\n\n";
}

bool Chat::stopped() const { return hooks_.stopped && hooks_.stopped(); }

void Chat::emit(const std::string& type, const std::string& text) {
  if (hooks_.event) hooks_.event(type, text);
}

std::string Chat::notesText() const {
  std::string notes;
  for (auto& [k, v] : memory_.notes()) notes += "- " + k + ": " + v + "\n";
  return notes.empty() ? "(none)\n" : notes;
}

std::string Chat::system() const {
  // The notes as they were when the chat started (or at the last fold): a
  // note saved or dropped since is in the conversation, so the start of the
  // request does not change and the model's cache keeps serving it.
  const std::string& notes = notes_;
  return std::string(kRules) +
         "\n\n## The manual (open a page with `man <path>`)\n\n" + opt_.manualIndex +
         "\n## The user's notes\n\n" + notes +
         "\n## This session\n\n" + opt_.context +
         (summary_.empty() ? std::string()
                           : "\n\n## Earlier in this conversation (a summary)\n\n" + summary_);
}

std::string Chat::request() const { return chatRequest(system(), messages_); }

namespace {

// The first `n` messages as text, one "ROLE: content" block each.
std::string textOf(const std::vector<Message>& messages, size_t n) {
  std::string t;
  for (size_t i = 0; i < n && i < messages.size(); ++i) {
    const Message& m = messages[i];
    std::string role = m.role;
    for (auto& ch : role) ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    t += role + ": " + m.content;
    for (const ToolCall& c : toolCallsOf(m.toolCalls)) {
      t += "\nRAN: " + (c.error.empty() ? c.command : "(" + c.error + ")");
      if (!c.content.empty()) t += "\n" + c.content;
    }
    t += "\n\n";
  }
  return t;
}

}  // namespace

std::string Chat::transcript() const { return textOf(messages_, messages_.size()); }

void Chat::note(const std::string& text) { messages_.push_back({"user", "[chat] " + text, "", "", ""}); }

size_t Chat::messageBytes(size_t from) const {
  size_t n = 0;
  for (size_t i = from; i < messages_.size(); ++i) {
    const Message& m = messages_[i];
    n += m.content.size() + m.toolCalls.size() + m.reasoning.size() + m.toolCallId.size() + 40;
  }
  return n;
}

std::vector<std::string> Chat::withGlobals(const std::vector<std::string>& args) const {
  std::vector<std::string> out;
  for (auto& [names, value] : opt_.globals) {
    bool named = false;
    for (auto& a : args)
      for (auto& n : names)
        if (a == n || a.rfind(n + "=", 0) == 0) named = true;
    if (!named && !value.empty()) {
      out.push_back(names.back());
      out.push_back(value);
    }
  }
  out.insert(out.end(), args.begin(), args.end());
  return out;
}

std::string Chat::runMemory(const std::vector<std::string>& args, const std::string& line) {
  const std::string head = "RESULT of `" + line + "`: ";
  if (args[0] == "remember") {
    std::string rest = trim(line.substr(line.find("remember") + 8));
    auto colon = rest.find(':');
    if (colon == std::string::npos || trim(rest.substr(0, colon)).empty())
      return head + "not saved; write `remember <name>: <text>`\n\n";
    std::string name = trim(rest.substr(0, colon));
    std::string text = trim(rest.substr(colon + 1));
    if (!confirm("Save the note \"" + name + ": " + text + "\"?"))
      return declined(head, "not saved");
    memory_.set(name, text);
    if (!memory_.save()) return head + "the note file could not be written\n\n";
    ok_ = true;
    return head + "saved; the notes now have " + name + ": " + text + "\n\n";
  }
  if (args.size() < 2) return head + "write `forget <name>`\n\n";
  std::string name = trim(line.substr(line.find("forget") + 6));
  if (!memory_.notes().count(name)) return head + "no note named " + name + "\n\n";
  if (!confirm("Forget the note \"" + name + "\"?"))
    return declined(head, "kept");
  memory_.erase(name);
  if (!memory_.save()) return head + "the note file could not be written\n\n";
  ok_ = true;
  return head + "forgotten; the notes no longer have " + name + "\n\n";
}

std::string Chat::runKeys(const std::vector<std::string>& args, const std::string& line) {
  const std::string head = "RESULT of `" + line + "`: ";
  emit("run", std::string(classify(args) == Kind::Read ? "read" : "action") + " " + line);
  auto words = commandWords(args);
  const std::string sub = words.size() >= 2 ? words[1] : "";
  bool secrets = sub == "export" || asksSecrets(args);
  auto listPublic = [&] {
    return publicKeysOf(hooks_.run(withGlobals({"keys", "list", "--public"})).out);
  };

  if (secrets) {
    show(echo("cesh " + line));
    if (!confirm("This prints your private keys, on your screen only. Run it?"))
      return declined(head);
    CeshResult r = hooks_.run(withGlobals(args));
    emit("result", std::to_string(r.code));
    output(trim(r.out + r.err));
    ok_ = r.code == 0;
    return head + "exit " + std::to_string(r.code) +
           "; the output has private keys, so it went to the user only\n\n";
  }
  if (sub == "list") {
    show(echo("cesh " + line));
    std::string keys = listPublic();
    output(trim(keys));
    ok_ = true;
    return head + "exit 0\n" + keys + "\n";
  }
  if (sub == "gen" || sub == "add") {
    if (opt_.walletPath.empty())
      return head + "not run; the keys come from $CESH_WALLET, which has no file to save a "
                    "new key to. The user can keep keys in a wallet file instead "
                    "(cesh keys gen 1 -w ~/.cesh/CESH_WALLET, then unset CESH_WALLET)\n\n";
    std::vector<std::string> a = args;
    bool hasW = false;
    for (auto& x : a) hasW = hasW || x == "-w" || x.rfind("-w=", 0) == 0;
    if (!hasW) { a.push_back("-w"); a.push_back(opt_.walletPath); }
    show(echo("cesh " + line + (hasW ? "" : " -w " + opt_.walletPath)));
    if (!confirm(describeAction(a) + ". Run it?")) return declined(head);
    if (sub == "add") {
      std::string key = hooks_.secret
        ? trim(hooks_.secret("Paste the private key to add (it does not go to the model): "))
        : std::string();
      if (key.empty()) return head + "not run; the user gave no key\n\n";
      a.push_back(key);
    }
    CeshResult r = hooks_.run(withGlobals(a));
    emit("result", std::to_string(r.code));
    if (r.code != 0) {
      show("(the key command failed, exit " + std::to_string(r.code) + ")");
      return head + "exit " + std::to_string(r.code) + "; the key command failed\n\n";
    }
    std::string keys = listPublic();
    output("saved in " + opt_.walletPath + "\n" + trim(keys));
    ok_ = true;
    return head + "exit 0; the wallet file " + opt_.walletPath + " now has:\n" + keys + "\n";
  }
  return "";   // another keys command: the usual path
}

std::string Chat::runFile(const std::string& verb, const std::string& name, const std::string& line,
                          const std::string& body) {
  namespace fs = std::filesystem;
  const std::string head = "RESULT of `" + line + "`: ";
  constexpr size_t kMaxFile = 256 * 1024;
  if (opt_.scratchDir.empty()) return head + "not run; this chat has no scratch directory\n\n";
  const fs::path dir(opt_.scratchDir);
  auto count = [](const std::string& t) {
    size_t n = static_cast<size_t>(std::count(t.begin(), t.end(), '\n'));
    return n + (!t.empty() && t.back() != '\n' ? 1 : 0);
  };

  if (verb == "ls") {
    emit("run", "read " + line);
    std::vector<std::string> rows;
    std::error_code ec;
    for (auto& e : fs::directory_iterator(dir, ec))
      if (e.is_regular_file(ec) && !e.is_symlink(ec))
        rows.push_back(e.path().filename().string() + "  " + std::to_string(e.file_size(ec)) + " bytes");
    std::sort(rows.begin(), rows.end());
    emit("result", "0");
    show(echo("ls"));
    std::string all;
    for (auto& r : rows) all += r + "\n";
    output(all.empty() ? "(no files)" : trim(all));
    ok_ = true;
    std::string o = head + std::to_string(rows.size()) + " files\n";
    for (auto& r : rows) o += r + "\n";
    return o + "\n";
  }

  // One flat name in the scratch: no directories, no path.
  static const std::regex okName("^[A-Za-z0-9_-][A-Za-z0-9._-]{0,99}$");
  if (!std::regex_match(name, okName))
    return head + "not run; a file name has letters, digits, '.', '_' and '-' only, with no '/' "
                  "and no leading '.' (the scratch has no directories)\n\n";
  const fs::path file = dir / name;
  std::error_code ec;
  const bool exists = fs::exists(fs::symlink_status(file, ec));
  if (exists && fs::is_symlink(fs::symlink_status(file, ec)))
    return head + "not run; " + name + " is a link, and the chat follows no links\n\n";

  if (verb == "read") {
    emit("run", "read " + line);
    if (!exists) return head + "not run; no file " + name + " in the scratch (ls lists the files)\n\n";
    if (fs::file_size(file, ec) > kMaxFile) return head + "not run; the file is over 256 KB\n\n";
    std::ifstream f(file);
    std::string t((std::istreambuf_iterator<char>(f)), {});
    emit("result", "0");
    // The file goes into the conversation for the model, and stays. The user
    // sees what went in. The model goes on from it.
    show(readLine(name, t));
    return head + std::to_string(count(t)) + " lines\n" + t + (t.empty() || t.back() == '\n' ? "" : "\n") + "\n";
  }

  // write
  emit("run", "action " + line);
  if (body.size() > kMaxFile) return head + "not run; the content is over 256 KB\n\n";
  std::string what = "Write " + name + " (" + std::to_string(count(body)) + " lines, " +
                     std::to_string(body.size()) + " bytes), ";
  if (exists) {
    std::ifstream f(file);
    std::string old((std::istreambuf_iterator<char>(f)), {});
    what += "replacing " + std::to_string(count(old)) + " lines";
  } else {
    what += "a new file";
  }
  show(echo("write " + name));
  show("```\n" + body + "```");
  if (!confirm(what + ". Run it?")) return declined(head);
  const fs::path tmp = dir / ("." + name + ".tmp");
  {
    std::ofstream f(tmp, std::ios::trunc | std::ios::binary);
    f << body;
    if (!f) return head + "the file could not be written\n\n";
  }
  ces::setSecurePermission(tmp.string());
  fs::rename(tmp, file, ec);
  if (ec) return head + "the file could not be written: " + ec.message() + "\n\n";
  emit("result", "0");
  ok_ = true;
  return head + "written, " + std::to_string(count(body)) + " lines\n\n";
}

void Chat::show(const std::string& text) {
  ++seen_;
  hooks_.show(text);
}

void Chat::output(const std::string& text) {
  ++seen_;
  if (hooks_.output) hooks_.output(printable(text));
  else hooks_.show(printable(text));
}

bool Chat::confirm(const std::string& question) {
  ++seen_;
  return hooks_.confirm(question);
}

std::string Chat::echo(const std::string& command) const { return "→ " + command; }

std::string Chat::readLine(const std::string& what, const std::string& text) const {
  size_t n = static_cast<size_t>(std::count(text.begin(), text.end(), '\n'));
  if (!text.empty() && text.back() != '\n') ++n;
  return "→ Read " + trim(what) + " (" + std::to_string(n) + (n == 1 ? " line)" : " lines)");
}

std::string Chat::runLine(const std::string& raw, const std::string& body) {
  std::string line = raw;
  shellCommand(line);   // a "$ " in front (the user's own command) goes
  ok_ = false;
  const std::string head = "RESULT of `" + raw + "`: ";
  // A note is free text (quotes, colons, apostrophes), so the memory commands
  // read the raw line, before any word splitting.
  {
    std::istringstream w(line);
    std::string first, rest;
    w >> first;
    std::getline(w, rest);
    if (first == "remember" || first == "forget") {
      std::vector<std::string> args = {first};
      if (!trim(rest).empty()) args.push_back(trim(rest));
      return runMemory(args, line);
    }
    if (first == "ls" || first == "read" || first == "write") return runFile(first, trim(rest), line, body);
  }
  std::vector<std::string> args;
  if (!splitLine(line, args) || args.empty()) return head + "not run; the line does not parse\n\n";
  {
    // The scratch is the only local place: no command names a file elsewhere
    // (the wallet, the notes, any other file).
    std::string bad = outsideScratch(args, opt_.scratchDir);
    if (!bad.empty()) {
      emit("run", "refused " + line);
      show("(not run: cesh " + line + " — " + bad + " is outside the scratch directory)");
      return head + "not run; " + bad + " is outside the scratch directory, the only local place "
                    "the chat sees. Use a file name in the scratch (ls lists them).\n\n";
    }
  }
  {
    auto words = commandWords(args);
    std::string why;
    if (!words.empty() && words[0] == "keys" && classify(args, &why) != Kind::Refused) {
      std::string r = runKeys(args, line);
      if (!r.empty()) return r;
    }
  }

  std::string why;
  Kind kind = classify(args, &why);
  emit("run", std::string(kind == Kind::Read ? "read" : kind == Kind::Action ? "action" : "refused") +
                  " " + line);
  if (kind == Kind::Refused) {
    show("(not run: cesh " + line + " — " + why + ")");
    return head + "not run; the chat does not run it: " + why + "\n\n";
  }
  if (commandWords(args).empty() || commandWords(args)[0] != "man") {
    // A command that does not parse would fail (an action after the user's
    // yes). Check it first; the parse error goes back to the model with the
    // command's help, and the user does not see it.
    std::vector<std::string> check = withGlobals(args);
    check.insert(check.begin(), "--parse-only");
    CeshResult p = hooks_.run(check);
    if (p.code != 0) {
      emit("result", std::to_string(p.code));
      // Give the model the command's own help with the error, so it can fix
      // the line in its next reply without a separate manual read.
      std::vector<std::string> words = commandWords(args);
      std::vector<std::string> help = {"man"};
      for (size_t i = 0; i < words.size() && i < 2; ++i) help.push_back(words[i]);
      CeshResult h = hooks_.run(help);
      if (h.code != 0 && help.size() > 2) {   // "transfer @1": the first word only
        help.resize(2);
        h = hooks_.run(help);
      }
      return head + "not run; the command does not parse:\n" + cap(trim(p.err + "\n" + p.out), 600) +
             "\nThe syntax (`" + std::string("man") + (help.size() > 1 ? " " + help[1] : "") +
             (help.size() > 2 ? " " + help[2] : "") + "`):\n" +
             cap(trim(h.out), 2500) + "\n\n";
    }
  }
  const bool manual = !commandWords(args).empty() && commandWords(args)[0] == "man";
  if (!manual) show(echo("cesh " + line));
  if (kind == Kind::Action) {
    std::string what = describeAction(withGlobals(args));
    if (!confirm(what.empty() ? "Run it?" : what + ". Run it?"))
      return declined(head);
  }

  CeshResult r = hooks_.run(withGlobals(args));
  emit("result", std::to_string(r.code));
  std::string shown = trim(r.out + r.err);
  if (manual && r.code == 0) {
    // A manual page goes into the conversation for the model, and stays. The
    // user sees what went in. The model goes on from it.
    show(readLine("man " + trim(line.substr(line.find("man") + 3)), shown));
  } else {
    if (manual) show(echo("cesh " + line));   // a page that failed: show the command
    // Say so when a command prints nothing. Else the model makes up a reason
    // for the empty result ("the reply went to stdout").
    output(shown.empty() ? "(no output)" : shown);
    ok_ = r.code == 0;
  }
  std::string o = head + "exit " + std::to_string(r.code) + "\n";
  // A manual page goes in whole (the pages are built in and short).
  if (r.code == 0 && manual) return o + r.out + (r.out.empty() || r.out.back() == '\n' ? "" : "\n") + "\n";
  if (!r.out.empty()) o += cap(r.out, opt_.maxResult);
  if (!r.err.empty()) o += "[stderr]\n" + cap(r.err, opt_.maxResult);
  if (r.out.empty() && r.err.empty()) o += "(no output: the command printed nothing)\n";
  return o + "\n";
}

// ---- The model's window ----
//
// The prompt grows by its end only (the rules, the notes and the summary
// stay as they are, the turns are added after them), so the model's prompt
// cache serves the start of each prompt. When the prompt passes compactAt
// percent of the room, the older turns fold into the summary in one step,
// and the cache starts again from there. Room is the model's window less the
// longest reply, in tokens, and not more than the largest prompt, in bytes.

ThinkReply Chat::think(const std::string& p, bool answer) {
  ThinkReply r = hooks_.think(p);
  if (r.contextTokens) window_ = r.contextTokens;
  if (r.maxInputBytes) inputMax_ = r.maxInputBytes;
  if (r.maxOutTokens) outMax_ = r.maxOutTokens;
  if (r.ok && r.promptTokens > 0)
    bytesPerToken_ = static_cast<double>(p.size()) / static_cast<double>(r.promptTokens);
  if (!answer) return r;
  lastPromptTokens_ = r.ok ? r.promptTokens : -1;
  lastCachedTokens_ = r.ok ? r.cachedTokens : -1;
  ContextUse u = context();
  emit("context", (u.estimated ? "~" : "") + std::to_string(u.promptTokens) + " " +
                      std::to_string(u.windowTokens) + " " + std::to_string(u.cachedPercent));
  return r;
}

uint64_t Chat::tokensOf(size_t bytes) const {
  // The bytes per token of the last reported prompt; else 3, which counts
  // more tokens than most text has, so the estimate errs on the safe side.
  return static_cast<uint64_t>(static_cast<double>(bytes) / bytesPerTokenOr3()) + 1;
}

uint64_t Chat::roomTokens() const {
  const uint64_t window = window_ ? window_ : opt_.contextTokens;
  const uint64_t out = outMax_ ? outMax_ : opt_.maxOutTokens;
  uint64_t room = window > out ? window - out : window / 2;
  // The largest prompt, in bytes, as tokens.
  const uint64_t inBytes = inputMax_ ? inputMax_ : opt_.maxInputBytes;
  return std::min<uint64_t>(room, tokensOf(inBytes));
}

ContextUse Chat::context() const {
  ContextUse u;
  u.windowTokens = roomTokens();
  if (lastPromptTokens_ > 0) {
    u.promptTokens = static_cast<uint64_t>(lastPromptTokens_);
    u.estimated = false;
    if (lastCachedTokens_ >= 0)
      u.cachedPercent = static_cast<int>(lastCachedTokens_ * 100 / lastPromptTokens_);
  } else {
    u.promptTokens = tokensOf(request().size());
  }
  return u;
}

std::string contextText(const ContextUse& u) {
  auto k = [](uint64_t n) {
    return n >= 10000 ? std::to_string(n / 1000) + "k"
                      : n >= 1000 ? std::to_string(n / 1000) + "." + std::to_string(n % 1000 / 100) + "k"
                                  : std::to_string(n);
  };
  std::string s = "context " + std::string(u.estimated ? "~" : "") + k(u.promptTokens) + " of " +
                  k(u.windowTokens) + " (" + std::to_string(u.percent()) + "%)";
  if (u.cachedPercent >= 0) s += " · cache " + std::to_string(u.cachedPercent) + "%";
  return s;
}

bool Chat::fit() {
  const uint64_t room = roomTokens();
  if (tokensOf(request().size()) * 100 <= room * static_cast<uint64_t>(opt_.compactAt)) return true;
  compact();
  if (tokensOf(request().size()) <= room) return true;
  // One turn alone is too big to fold: cut its oldest part, so the newest
  // results still reach the model.
  const size_t head = chatRequest(system(), {}).size();
  const size_t roomBytes = static_cast<size_t>(static_cast<double>(room) * bytesPerTokenOr3());
  if (roomBytes <= head + 1024) return false;   // the start alone fills it
  cutOldest((roomBytes - head) * opt_.keepPercent / 100);
  return tokensOf(request().size()) <= room;
}

namespace {

const char* kCompactRules = R"(You fold the older part of a conversation between a user and cesh chat (the assistant inside cesh, the command line of CES) into a summary. The summary replaces that part: the assistant will see only the summary and the newer turns.
Keep what the rest of the conversation needs: what the user wants and prefers, the facts that were found (keys, names, pids, file paths, amounts, balances), what was done and how it ended, what is still open, and the errors met. Keep exact values. Drop greetings, chatter and text that was only shown.
Write plain, short sentences, at most 400 words, with no title and no preamble.)";

}  // namespace

bool Chat::compact() {
  const std::vector<size_t>& starts = turns_;
  if (starts.size() < 2) return false;
  // Keep the newest turns, up to keepPercent of the room that the start of
  // the prompt (the rules, the notes, the summary) leaves for them; the
  // current turn (the last one) always stays.
  const double roomBytes = static_cast<double>(roomTokens()) * bytesPerTokenOr3();
  const double headBytes = static_cast<double>(chatRequest(system(), {}).size());
  const size_t keepBytes = roomBytes > headBytes
                               ? static_cast<size_t>((roomBytes - headBytes) * opt_.keepPercent / 100)
                               : 0;
  size_t cut = starts.back();
  for (size_t k = starts.size() - 1; k-- > 0;) {
    if (messageBytes(starts[k]) > keepBytes) break;
    cut = starts[k];
  }
  if (cut == 0) return false;
  const std::string folded = textOf(messages_, cut);

  emit("compact", "start");
  std::string ask;
  if (!summary_.empty()) ask += "## The summary so far\n\n" + summary_ + "\n\n";
  ask += "## The part to fold\n\n" + folded;
  ThinkReply r = think(chatRequest(kCompactRules, {{"user", ask, "", "", ""}}, false), false);
  if (r.charged >= 0) {
    spent_ += r.charged;
    emit("cost", std::to_string(r.charged));
  }
  const std::string kb = std::to_string((folded.size() + 1023) / 1024);
  if (!r.ok || trim(r.text).empty()) {
    // The floor: the older turns go, and the model knows that they went.
    summary_ += (summary_.empty() ? "" : "\n") + std::string("(Older turns were dropped here; they are lost.)");
    dropFront(cut);
    notes_ = notesText();
    show("(could not fold " + kb + " KB of older conversation: " + oneLine(r.ok ? "empty summary" : r.error) +
         "; those turns were dropped)");
    emit("compact", "dropped " + std::to_string(folded.size()));
    return true;
  }
  summary_ = trim(r.text);
  dropFront(cut);
  notes_ = notesText();   // the start of the prompt changes here anyway
  show("(folded " + kb + " KB of older conversation into a summary" +
       (r.charged >= 0 ? ", " + credits(r.charged) + " credits" : std::string()) + ")");
  emit("compact", "folded " + std::to_string(folded.size()));
  return true;
}

void Chat::cutOldest(size_t keepBytes) {
  // Drop the oldest messages until the rest fits, and keep the newest one.
  size_t cut = 0;
  while (cut + 1 < messages_.size() && messageBytes(cut) > keepBytes) ++cut;
  const bool tooBig = messageBytes(cut) > keepBytes;
  if (tooBig) {
    // When the newest one alone is too big, keep its last lines.
    std::string& t = messages_[cut].content;
    size_t nl = t.find('\n', t.size() > keepBytes ? t.size() - keepBytes : 0);
    t = "[... the start was cut]\n" + (nl == std::string::npos ? std::string() : t.substr(nl + 1));
  }
  if (cut == 0 && !tooBig) return;
  dropFront(cut);
  // The turn that was cut goes on from the note.
  messages_.insert(messages_.begin(),
                   Message{"user", "[chat] the older part of this turn was cut; it did not fit in the "
                                   "model's window", "", "", ""});
  for (auto& t : turns_) ++t;
  turns_.insert(turns_.begin(), 0);
}

void Chat::dropFront(size_t n) {
  messages_.erase(messages_.begin(), messages_.begin() + static_cast<std::ptrdiff_t>(n));
  std::vector<size_t> kept;
  for (size_t t : turns_)
    if (t >= n) kept.push_back(t - n);
  turns_ = std::move(kept);
}

void Chat::turn(const std::string& userLine) {
  turns_.push_back(messages_.size());
  messages_.push_back({"user", userLine, "", "", ""});
  declined_ = false;
  {
    // The user's own command runs as it is, as in a terminal, with no model
    // call. When it does not parse, the model gets the error and goes on.
    std::string own;
    if (userCommand(userLine, own)) {
      const size_t before = seen_;
      note(trim(runLine(own)));
      if (seen_ != before) {
        note("the user ran that command; the user saw it and its output");
        return;
      }
    }
  }
  bool task = false;   // a reply of this turn had words: the model works in steps
  for (int i = 0; i < opt_.maxThinks; ++i) {
    if (stopped()) return;
    if (!fit()) {
      show("(the conversation does not fit in the model's window; start a new chat)");
      return;
    }
    const std::string req = request();
    emit("prompt", req);
    ThinkReply r = think(req);
    if (r.ok) emit("reply", r.text);
    if (r.charged >= 0) {
      spent_ += r.charged;
      emit("cost", std::to_string(r.charged));
    }
    if (!r.ok) {
      show("(think failed: " + trim(r.error) + ")");
      note("the model call failed: " + oneLine(r.error));
      return;
    }
    const std::string prose = trim(r.text);
    std::vector<ToolCall> calls = toolCallsOf(r.toolCalls);
    messages_.push_back({"assistant", prose, calls.empty() ? "" : r.toolCalls, r.reasoning, ""});
    if (!prose.empty()) show(prose);
    // A reply of commands with no words is the answer: when each command
    // succeeds, the user has the output, and the turn ends. A turn where the
    // model said what it will do is a task of steps: it goes on until the
    // model ends it.
    if (!calls.empty()) task = task || !prose.empty();
    bool settled = !task;
    // The results go right after the reply, and the chat's notes after them.
    for (size_t k = 0; k < calls.size(); ++k) {
      const ToolCall& c = calls[k];
      std::string result;
      if (!c.error.empty()) {
        result = "not run; " + c.error;
        settled = false;
      } else if (k >= opt_.maxCommands) {
        result = "not run; only the first " + std::to_string(opt_.maxCommands) + " commands of a reply run";
        settled = false;
      } else if (stopped()) {
        result = "not run; the user stopped the chat";
      } else {
        result = trim(runLine(c.command, c.content));
        settled = settled && ok_;
      }
      messages_.push_back({"tool", result, "", "", c.id});
    }
    if (r.charged >= 0) {
      if (opt_.showCost)
        show("(" + credits(r.charged) + " credits for this answer, " + credits(spent_) +
             " for this chat · " + contextText(context()) + ")");
      note("that answer cost the signer " + credits(r.charged) + " credits; this chat has cost " +
           credits(spent_) + " credits");
    }
    if (calls.empty() || stopped()) return;
    if (declined_) {
      // The user's no ends the turn: the model waits for the next line
      // instead of asking again.
      note("the user said no, so the turn ended. Wait for the user's next line, "
           "and do not run the declined command again unless the user asks.");
      return;
    }
    if (settled) {
      note("your commands succeeded and the user saw their output, so the turn ended");
      return;
    }
  }
  show("(stopped after " + std::to_string(opt_.maxThinks) +
              " model calls; say more to go on)");
}


int Chat::run() {
  std::string line;
  while (hooks_.readLine(line)) {
    std::string t = trim(line);
    if (t.empty()) continue;
    if (t == "exit" || t == "quit") break;
    turn(t);
  }
  return 0;
}

}  // namespace ces::chat
