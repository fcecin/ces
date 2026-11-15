#include "chat/command.h"

#include "cesh_run.h"
#include "chat/chat.h"
#include "chat/socket.h"
#include "chat/tui.h"

#include <ces/util/fileperm.h>
#include "man/manual.h"
#include "man/markdown.h"

#include <termios.h>
#include <unistd.h>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <iostream>
#include <regex>
#include <sstream>

namespace fs = std::filesystem;
using namespace ces::chat;

namespace {

std::string defaultMemoryPath() {
  const char* home = std::getenv("HOME");
  return home ? std::string(home) + "/.cesh/memory.md" : std::string(".cesh-memory.md");
}

// The rpc port from `cesh -q ping`, or 0.
uint16_t discoverRpcPort(const std::vector<std::string>& prefix) {
  std::vector<std::string> args = prefix;
  args.insert(args.begin(), "-q");
  args.push_back("ping");
  CeshResult r = ceshCapture(args);
  std::smatch m;
  static const std::regex re("\"rpcPort\":([0-9]+)");
  if (r.code == 0 && std::regex_search(r.out, m, re)) {
    long v = std::strtol(m[1].str().c_str(), nullptr, 10);
    if (v > 0 && v < 65536) return static_cast<uint16_t>(v);
  }
  return 0;
}

}  // namespace

CLI::App* addChatCommand(CLI::App& app, ChatArgs& args) {
  auto* cmd = app.add_subcommand(
    "chat", "Talk to cesh in plain words");
  cmd->footer("The chat uses builtin:think (via --rpc-port). Reads run at once. Other commands "
              "wait for your yes (--yolo runs them without a question).");
  cmd->add_option("--memory", args.memoryPath,
                  "File for the notes that the chat keeps (default ~/.cesh/memory.md)");
  cmd->add_option("--max-thinks", args.maxThinks,
                  "Model calls for one line of yours (default 10)")
    ->check(CLI::Range(1, 50));
  cmd->add_option("--listen", args.listen,
                  "Serve the chat on this Unix socket, for a program that uses it "
                  "(see --connect)");
  cmd->add_option("--connect", args.connect,
                  "Send one message to the chat on this socket and print its events: "
                  "say <text> | yes | no | secret <text> | quit");
  cmd->add_flag("--trace", args.trace,
                "With --listen: also send each prompt and model reply as events");
  cmd->add_flag("--yolo", args.yolo,
                "Run every action without asking. The chat still refuses what it always "
                "refuses (files outside the scratch, private keys on a line, a plain dial)");
  cmd->add_option("message", args.message, "With --connect: the message");
  return cmd;
}

int runChat(const ChatArgs& args, ChatGlobals g) {
  // ceslib's SIGINT/SIGTERM handler (util/ctrlc) only sets a flag, and the
  // chat waits in getline, which never reads it. Ctrl+C ends the chat.
  std::signal(SIGINT, SIG_DFL);
  std::signal(SIGTERM, SIG_DFL);

  if (!args.connect.empty()) {
    std::string m;
    for (auto& w : args.message) m += (m.empty() ? "" : " ") + w;
    if (m.empty()) {
      std::cerr << "Error: give a message: say <text> | yes | no | secret <text> | quit\n";
      return 1;
    }
    return chatClient(args.connect, m);
  }

  const bool socketMode = !args.listen.empty();
  // `styled`: stdout is a terminal, so colors and live lines are fine.
  // `tty`: stdin is a terminal too, so a prompt line makes sense.
  const bool styled = !socketMode && ::isatty(STDOUT_FILENO);
  const bool tty = styled && ::isatty(STDIN_FILENO);

  // The chat works from its scratch directory (~/.cesh/scratch), the only
  // local place it sees. Paths the user gave are made absolute first.
  std::error_code aec;
  if (!g.wallet.empty()) g.wallet = fs::absolute(g.wallet, aec).string();
  const std::string memoryArg =
    args.memoryPath.empty() ? std::string() : fs::absolute(args.memoryPath, aec).string();
  const std::string listenPath =
    args.listen.empty() ? std::string() : fs::absolute(args.listen, aec).string();
  std::string scratch;
  if (const char* home = std::getenv("HOME")) {
    fs::path sp = fs::path(home) / ".cesh" / "scratch";
    std::error_code sec;
    fs::create_directories(sp, sec);
    ces::setSecurePermission(sp.parent_path().string());
    ces::setSecurePermission(sp.string());
    if (!sec && ::chdir(sp.c_str()) == 0) scratch = fs::weakly_canonical(sp, sec).string();
  }
  if (scratch.empty()) {
    std::cerr << "Error: cannot use the scratch directory ~/.cesh/scratch\n";
    return 1;
  }

  // The options that every command of the chat gets.
  Options opt;
  opt.scratchDir = scratch;
  auto addGlobal = [&](std::vector<std::string> names, const std::string& v) {
    if (!v.empty()) opt.globals.push_back({std::move(names), v});
  };
  addGlobal({"--server"}, g.server);
  addGlobal({"--proxy"}, g.proxy);
  addGlobal({"--server-key"}, g.serverKey);
  addGlobal({"-r", "--wallet"}, g.wallet);
  addGlobal({"-a", "--actor"}, g.actor);
  addGlobal({"--tries"}, std::to_string(g.tries));
  auto prefix = [&] {
    std::vector<std::string> p;
    for (auto& [names, v] : opt.globals) { p.push_back(names.back()); p.push_back(v); }
    return p;
  };

  if (g.rpcPort == 0) {
    if (styled) std::cout << "\x1b[2mcontacting " << (g.server.empty() ? "localhost:53830" : g.server)
                       << " …\x1b[0m" << std::flush;
    g.rpcPort = discoverRpcPort(prefix());
    if (styled) std::cout << "\r\x1b[2K" << std::flush;
  }
  if (g.rpcPort == 0) {
    std::cerr << "Error: cesh chat needs the server's rpc port. Give --rpc-port, "
                 "or check the server with `cesh ping`.\n";
    return 1;
  }
  addGlobal({"--rpc-port"}, std::to_string(g.rpcPort));

  // The public keys of the wallet, and nothing of the private keys
  // (publicKeysOf drops the masked part of each private key).
  CeshResult keys = ceshCapture([&] {
    auto p = prefix();
    p.insert(p.end(), {"keys", "list", "--public"});
    return p;
  }());
  std::string publicKeys = publicKeysOf(keys.out);
  opt.manualIndex = ces::man::Manual::builtin().index();
  opt.context = "Server: " + (g.proxy.empty() ? (g.server.empty() ? "localhost:53830" : g.server)
                                              : "proxy " + g.proxy) +
                ", rpc port " + std::to_string(g.rpcPort) + ".\n" +
                "Signer: " + (g.actor.empty() ? "@0" : g.actor) +
                " (a command can name another key with -a @N).\n" +
                "Wallet keys (label and public key):\n" + publicKeys +
                "Local files: the scratch directory " + scratch +
                " is the only local place you see. A bare name in a command (file put hello.lua "
                "hello.lua) is a file there. Use ls, read and write for the files.\n";
  opt.maxThinks = args.maxThinks;
  // The wallet file that keys gen and keys add save to. Keys from $CESH_WALLET
  // have no file.
  if (!g.wallet.empty()) {
    fs::path wp(g.wallet);
    if (fs::is_directory(wp)) wp /= "CESH_WALLET";
    opt.walletPath = wp.string();
  } else if (!std::getenv("CESH_WALLET")) {
    const char* home = std::getenv("HOME");
    if (home) opt.walletPath = (fs::path(home) / ".cesh" / "CESH_WALLET").string();
  }

  std::string memPath = memoryArg.empty() ? defaultMemoryPath() : memoryArg;
  std::error_code ec;
  fs::create_directories(fs::path(memPath).parent_path(), ec);
  Memory memory(memPath);
  if (!memory.load()) {
    std::cerr << "Error: cannot read " << memPath << "\n";
    return 1;
  }

  const char* dim = styled ? "\x1b[2m" : "";
  const char* bold = styled ? "\x1b[1m" : "";
  const char* off = styled ? "\x1b[0m" : "";

  // The hooks keep their own copy: `opt` moves into the Chat below.
  const std::vector<std::string> globalArgs = prefix();
  ChatSocket sock;
  if (socketMode) {
    std::string err;
    if (!sock.listen(listenPath, err)) {
      std::cerr << "Error: " << err << "\n";
      return 1;
    }
  }
  Hooks hooks;
  // When the terminal UI runs, it shows the activity; the plain mode shows "…".
  auto uiOn = std::make_shared<bool>(false);
  hooks.think = [=](const std::string& prompt) {
    if (styled && !*uiOn) std::cout << dim << "…" << off << "\r" << std::flush;
    auto a = globalArgs;
    a.push_back("think");
    a.push_back("-v");   // the charge goes to stderr as "charged N"
    a.push_back("--in");
    a.push_back("text:" + prompt);
    CeshResult r = ceshCapture(a);
    if (styled && !*uiOn) std::cout << "\x1b[2K\r" << std::flush;
    static const std::regex charged("charged ([0-9]+)");
    static const std::regex tokens("tokens prompt ([0-9]+) cached ([0-9]+) output ([0-9]+)");
    static const std::regex limits("limits context ([0-9]+) tokens, input ([0-9]+) bytes, output ([0-9]+) tokens");
    std::smatch m;
    ThinkReply t;
    if (std::regex_search(r.err, m, charged)) t.charged = std::strtoll(m[1].str().c_str(), nullptr, 10);
    if (std::regex_search(r.err, m, tokens)) {
      t.promptTokens = std::strtoll(m[1].str().c_str(), nullptr, 10);
      t.cachedTokens = std::strtoll(m[2].str().c_str(), nullptr, 10);
    }
    if (std::regex_search(r.err, m, limits)) {
      t.contextTokens = static_cast<uint32_t>(std::strtoul(m[1].str().c_str(), nullptr, 10));
      t.maxInputBytes = static_cast<uint32_t>(std::strtoul(m[2].str().c_str(), nullptr, 10));
      t.maxOutTokens = static_cast<uint32_t>(std::strtoul(m[3].str().c_str(), nullptr, 10));
    }
    t.ok = r.code == 0;
    t.text = r.out;
    t.error = r.err.empty() ? "exit " + std::to_string(r.code) : r.err;
    return t;
  };
  hooks.run = [](const std::vector<std::string>& a) { return ceshCapture(a); };
  const std::string prompt = (g.actor.empty() ? std::string("@0") : g.actor) + " › ";
  hooks.readLine = [&](std::string& line) {
    // The prompt names the signer: each line can spend that key's credits.
    if (tty) std::cout << "\n" << bold << prompt << off << std::flush;
    return static_cast<bool>(std::getline(std::cin, line));
  };
  hooks.show = [&](const std::string& text) {
    if (text.rfind("→ ", 0) == 0) std::cout << bold << text << off << "\n";
    else if (text.rfind("(", 0) == 0) std::cout << dim << text << off << "\n";
    else std::cout << (styled ? ces::man::markdownToTerminal(text) : text) << "\n";
    std::cout.flush();
  };
  hooks.output = [&](const std::string& text) {
    std::cout << (styled ? outputBlock(text, true) : text) << "\n" << std::flush;
  };
  hooks.secret = [&](const std::string& prompt) {
    std::cout << prompt << std::flush;
    termios old{};
    const bool hide = ::isatty(STDIN_FILENO) && ::tcgetattr(STDIN_FILENO, &old) == 0;
    if (hide) {
      termios quiet = old;
      quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
      ::tcsetattr(STDIN_FILENO, TCSANOW, &quiet);
    }
    std::string v;
    std::getline(std::cin, v);
    if (hide) {
      ::tcsetattr(STDIN_FILENO, TCSANOW, &old);
      std::cout << "\n";
    }
    return v;
  };
  hooks.confirm = [&](const std::string& question) {
    std::cout << question << " [y/N] " << std::flush;
    std::string a;
    if (!std::getline(std::cin, a)) return false;
    return !a.empty() && (a[0] == 'y' || a[0] == 'Y');
  };

  const std::string serverName = g.server.empty() ? "localhost:53830" : g.server;
  if (!socketMode) {
    // Who signs, and what that key has.
    const std::string signer = g.actor.empty() ? "@0" : g.actor;
    std::string signerKey;
    {
      std::istringstream in(publicKeys);
      std::string label, key;
      while (in >> label >> key)
        if (label == signer) signerKey = key;
    }
    // The signer's balance in credits, or "" when the query fails.
    auto readBalance = [&]() -> std::string {
      auto a = globalArgs;
      a.insert(a.begin(), "-q");
      a.insert(a.end(), {"query", signer});
      CeshResult q = ceshCapture(a);
      static const std::regex bal("\"balance\":(-?[0-9]+)");
      std::smatch m;
      if (q.code != 0 || !std::regex_search(q.out, m, bal)) return "";
      char buf[48];
      std::snprintf(buf, sizeof buf, "%.8f", std::strtod(m[1].str().c_str(), nullptr) / 1e8);
      std::string b = buf;
      while (b.size() > 1 && b.back() == '0') b.pop_back();
      if (b.back() == '.') b.pop_back();
      return b;
    };
    std::string balance = readBalance();

    // On a terminal: the full UI, with an input box and a status bar.
    Tui tui;
    if (tty && tui.start()) {
      *uiOn = true;
      Status status;
      status.server = serverName;
      status.signer = signer;
      status.signerKey = signerKey;
      status.balance = balance;
      status.chatCost = "0";
      if (args.yolo) status.server += " · yolo";
      int64_t spent = 0;
      auto creditsOf = [](int64_t raw) {
        char buf[48];
        std::snprintf(buf, sizeof buf, "%.8f", static_cast<double>(raw) / 1e8);
        std::string b = buf;
        while (b.size() > 1 && b.back() == '0') b.pop_back();
        if (b.back() == '.') b.pop_back();
        return b;
      };
      tui.setStatus(status);
      tui.print(std::string("\x1b[1mcesh chat\x1b[0m\x1b[2m · what you type goes to ") + serverName +
                " and its model provider, and each answer costs the signer credits.\x1b[0m" +
                (args.yolo ? "\n\x1b[33m--yolo: actions run without asking.\x1b[0m" : ""));
      opt.showCost = false;   // the status bar has it

      auto innerThink = hooks.think;
      auto folding = std::make_shared<bool>(false);   // a compaction call runs
      hooks.think = [&, innerThink, folding](const std::string& p) {
        tui.busy(*folding ? "folding the older conversation" : "thinking");
        ThinkReply r = innerThink(p);
        tui.busy("");
        return r;
      };
      hooks.run = [&](const std::vector<std::string>& a) {
        auto words = commandWords(a);
        std::string label = "running";
        for (size_t i = 0; i < words.size() && i < 2; ++i) label += " " + words[i];
        tui.busy(label);
        CeshResult r = ceshCapture(a);
        tui.busy("");
        return r;
      };
      hooks.readLine = [&](std::string& line) {
        tui.busy("checking the balance");   // a network read: never a silent wait
        std::string b = readBalance();
        tui.busy("");
        if (!b.empty()) status.balance = b;
        tui.setStatus(status);
        if (!tui.readLine(line)) return false;
        tui.printWords("\n\x1b[1m\x1b[38;5;45m❯ \x1b[0m\x1b[1m" + line + "\x1b[0m");
        return true;
      };
      hooks.show = [&](const std::string& text) {
        if (text.rfind("→ ", 0) == 0) tui.print("\x1b[36m" + text + "\x1b[0m");
        else if (text.rfind("(", 0) == 0) tui.print("\x1b[2m" + text + "\x1b[0m");
        else tui.printWords(ces::man::markdownToTerminal(text));
      };
      hooks.output = [&](const std::string& text) { tui.print(outputBlock(text, true)); };
      hooks.confirm = [&](const std::string& q) { return tui.confirm(q); };
      hooks.secret = [&](const std::string& p) { return tui.secret(p); };
      hooks.event = [&, folding](const std::string& type, const std::string& text) {
        if (type == "compact") {
          *folding = text == "start";
          return;
        }
        if (type == "context") {
          ContextUse u;
          u.estimated = !text.empty() && text[0] == '~';
          std::istringstream in(u.estimated ? text.substr(1) : text);
          long long prompt = 0, room = 0, cached = -1;
          in >> prompt >> room >> cached;
          u.promptTokens = static_cast<uint64_t>(prompt);
          u.windowTokens = static_cast<uint64_t>(room);
          u.cachedPercent = static_cast<int>(cached);
          status.context = contextText(u);
          tui.setStatus(status);
          return;
        }
        if (type != "cost") return;
        spent += std::strtoll(text.c_str(), nullptr, 10);
        status.chatCost = creditsOf(spent);
        tui.setStatus(status);
      };
      if (args.yolo) {
        hooks.confirm = [&](const std::string& q) {
          tui.answered(true, q);   // as if the user pressed y
          return true;
        };
      }
      Chat chat(std::move(opt), std::move(hooks), std::move(memory));
      chat.run();
      tui.stop();
      return 0;
    }

    std::cout << bold << "cesh chat" << off << " on " << serverName << " · signer " << signer
              << (signerKey.size() == 64 ? " (" + signerKey.substr(0, 8) + "…" + signerKey.substr(60) + ")" : "")
              << (balance.empty() ? "" : " · " + balance + " credits") << "\n"
              << dim << "What you type goes to that server and its model provider. Each answer "
                 "costs the signer credits. Type exit to end." << off << "\n"
              << (args.yolo ? "--yolo: actions run without asking.\n" : "");
    if (args.yolo) {
      hooks.confirm = [&](const std::string& q) {
        std::cout << "  " << (styled ? "\x1b[32m✓ yes\x1b[0m" : "✓ yes") << dim << "  " << q << off
                  << "\n" << std::flush;
        return true;
      };
    }
    Chat chat(std::move(opt), std::move(hooks), std::move(memory));
    return chat.run();
  }

  // ---- Socket mode: the same chat, with its input and output on the socket ----
  bool quit = false;
  hooks.show = [&](const std::string& text) { sock.send("show", text); };
  hooks.output = [&](const std::string& text) { sock.send("show", text); };
  hooks.confirm = [&](const std::string& question) {
    sock.send("ask", question);
    std::string m;
    while (sock.next(m)) {
      if (m == "yes") return true;
      if (m == "no") return false;
      if (m == "quit") { quit = true; return false; }
      sock.send("error", "a question waits: answer yes or no");
      sock.send("ask", question);
    }
    return false;
  };
  hooks.secret = [&](const std::string& prompt) {
    sock.send("ask-secret", prompt);
    std::string m;
    while (sock.next(m)) {
      if (m.rfind("secret ", 0) == 0) return unescapeEvent(m.substr(7));
      if (m == "quit") { quit = true; return std::string(); }
      sock.send("error", "a secret waits: send secret <text>");
      sock.send("ask-secret", prompt);
    }
    return std::string();
  };
  hooks.stopped = [&] { return quit; };
  const bool trace = args.trace;
  hooks.event = [&](const std::string& type, const std::string& text) {
    if ((type == "prompt" || type == "reply") && !trace) return;
    sock.send(type, text);
  };
  if (args.yolo) {
    hooks.confirm = [&](const std::string& q) {
      sock.send("show", "✓ yes  " + q);
      return true;
    };
  }
  std::cout << "cesh chat on " << serverName << " listens on " << listenPath
            << (args.yolo ? " (--yolo: actions run without asking)" : "") << "\n" << std::flush;
  Chat chat(std::move(opt), std::move(hooks), std::move(memory));
  std::string m;
  while (!quit && sock.next(m)) {
    if (m.rfind("say ", 0) == 0) {
      chat.turn(unescapeEvent(m.substr(4)));
      sock.send(quit ? "bye" : "done");
    } else if (m == "quit") {
      sock.send("bye");
      break;
    } else if (m == "yes" || m == "no" || m.rfind("secret ", 0) == 0) {
      sock.send("error", "no question waits");
    } else {
      sock.send("error", "send say <text>, yes, no, secret <text> or quit");
    }
  }
  return 0;
}
