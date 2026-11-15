#include "bootstrap_command.h"

#include <ces/account.h>
#include <ces/client.h>
#include <ces/util/ctrlc.h>
#include <ces/util/resolver.h>

#include <minx/minx.h>

#include <unistd.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <thread>

namespace {

const char* kPublicServer = "ces.pubcom.org:53830";
constexpr uint64_t kPowRewardBase = 1000;   // server.cpp POW_REWARD_BASE

// Credits from raw units, with the trailing zeros cut: 16384000 -> "0.16384",
// 10000000000 -> "100".
std::string credits(int64_t raw) {
  char buf[48];
  std::snprintf(buf, sizeof buf, "%.8f", static_cast<double>(raw) / 1e8);
  std::string s = buf;
  while (s.size() > 1 && s.back() == '0') s.pop_back();
  if (!s.empty() && s.back() == '.') s.pop_back();
  return s;
}

std::string clock(std::chrono::steady_clock::duration d) {
  auto s = std::chrono::duration_cast<std::chrono::seconds>(d).count();
  char buf[32];
  if (s >= 3600)
    std::snprintf(buf, sizeof buf, "%lld:%02lld:%02lld", static_cast<long long>(s / 3600),
                  static_cast<long long>(s / 60 % 60), static_cast<long long>(s % 60));
  else
    std::snprintf(buf, sizeof buf, "%02lld:%02lld", static_cast<long long>(s / 60),
                  static_cast<long long>(s % 60));
  return buf;
}

std::string rate(double hashesPerSec) {
  char buf[32];
  if (hashesPerSec >= 1e6) std::snprintf(buf, sizeof buf, "%.2f MH/s", hashesPerSec / 1e6);
  else if (hashesPerSec >= 1e3) std::snprintf(buf, sizeof buf, "%.2f kH/s", hashesPerSec / 1e3);
  else std::snprintf(buf, sizeof buf, "%.0f H/s", hashesPerSec);
  return buf;
}

std::string grouped(uint64_t n) {
  std::string s = std::to_string(n);
  for (int i = static_cast<int>(s.size()) - 3; i > 0; i -= 3) s.insert(static_cast<size_t>(i), ",");
  return s;
}

// Set ceslib's interrupt flag, as its own handler does.
void onInterrupt(int) { ces::internal::g_interrupted = ces::internal::g_interrupted + 1; }

struct Style {
  bool tty;
  std::string b(const std::string& t) const { return tty ? "\x1b[1m" + t + "\x1b[0m" : t; }
  std::string d(const std::string& t) const { return tty ? "\x1b[2m" + t + "\x1b[0m" : t; }
  std::string g(const std::string& t) const { return tty ? "\x1b[32m" + t + "\x1b[0m" : t; }
  std::string y(const std::string& t) const { return tty ? "\x1b[33m" + t + "\x1b[0m" : t; }
  std::string r(const std::string& t) const { return tty ? "\x1b[31m" + t + "\x1b[0m" : t; }
  // "  wallet   text"
  void row(const std::string& label, const std::string& text) const {
    std::string l = label;
    l.resize(9, ' ');
    std::cout << "  " << b(l) << text << "\n" << std::flush;
  }
  void clearLine() const {
    if (tty) std::cout << "\r\x1b[2K" << std::flush;
  }
};

}  // namespace

CLI::App* addBootstrapCommand(CLI::App& app, BootstrapArgs& args) {
  auto* cmd = app.add_subcommand(
    "bootstrap", "Set up for ces.pubcom.org");
  cmd->footer("Makes a wallet, finds the server, shows your balance, then mines until Ctrl+C. "
              "Then it starts a shell with CESH_SERVER set. --server picks another server.");
  cmd->add_option("-t,--threads", args.threads,
                  "Mining threads (default: half the cores)");
  cmd->add_option("--solutions", args.solutions,
                  "Stop mining after this many solutions")->group("");
  return cmd;
}

int runBootstrap(const BootstrapArgs& args, BootstrapEnv env) {
  // Ctrl+C ends bootstrap at once, except in the mining loop, which stops on
  // ceslib's interrupt flag (util/ctrlc) and then prints its summary.
  std::signal(SIGINT, SIG_DFL);
  std::signal(SIGTERM, SIG_DFL);
  const Style s{::isatty(STDOUT_FILENO) != 0};
  const bool interactive = ::isatty(STDIN_FILENO) && ::isatty(STDOUT_FILENO);
  std::cout << s.b("cesh bootstrap") << "\n\n";

  // ---- 1. Wallet ----
  bool created = false;
  if (env.wallet->size() == 0) {
    if (env.walletFromEnv) {
      s.row("wallet", s.r("$CESH_WALLET has no keys"));
      return 1;
    }
    std::cout << "  No wallet yet. Make " << env.walletPath.string()
              << " with one new key? [Y/n] " << std::flush;
    std::string a;
    std::getline(std::cin, a);
    if (!a.empty() && (a[0] == 'n' || a[0] == 'N')) {
      s.row("wallet", "none; cesh needs a key to act");
      return 1;
    }
    try {
      env.wallet->generate(1);
      std::error_code ec;
      std::filesystem::create_directories(env.walletPath.parent_path(), ec);
      env.wallet->saveToFile(env.walletPath);
      created = true;
    } catch (const std::exception& e) {
      s.row("wallet", s.r(std::string("cannot make the wallet: ") + e.what()));
      return 1;
    }
  }
  ces::KeyPair key;
  try {
    key = env.wallet->resolveActor(env.actor);
  } catch (const std::exception& e) {
    s.row("wallet", s.r(e.what()));
    return 1;
  }
  const std::string who = env.actor.empty() ? "@0" : env.actor;
  std::string where = env.walletFromEnv ? std::string("$CESH_WALLET") : env.walletPath.string();
  s.row("wallet", where + " · " + std::to_string(env.wallet->size()) +
                  (env.wallet->size() == 1 ? " key" : " keys") + (created ? s.g(" (new)") : ""));
  s.row("key", who + " " + key.getPublicKeyHexStr());

  // ---- 2. Server ----
  const std::string server = env.server.empty() ? kPublicServer : env.server;
  boost::asio::ip::udp::endpoint ep;
  try {
    ep = ces::Resolver::resolveUdp(server);
  } catch (const std::exception& e) {
    s.row("server", s.r(server + ": " + e.what()));
    return 1;
  }
  if (s.tty) std::cout << "  " << s.b("server   ") << s.d("contacting " + server + " …") << std::flush;
  ces::CesClient client(ep, !env.cacheOnly);
  client.start(0);
  client.setKey(key);
  client.setTries(env.tries);
  bool up = client.connect();
  s.clearLine();
  if (!up) {
    s.row("server", s.r(server + " does not answer"));
    client.stop();
    return 1;
  }
  const int diff = client.getMinDifficulty();
  s.row("server", server + " · rpc port " + std::to_string(client.getServerRpcPort()) +
                  " · difficulty " + std::to_string(diff));
  s.row("", s.d("server key " + minx::hashToString(client.getServerKey())));

  // ---- 3. Account ----
  const auto mapKey = ces::Account::getMapKey(key.getPublicKeyAsHash());
  int64_t balance = 0;
  // A key with no account reads as balance 0 and nonce 0.
  bool queried = false;
  auto hasAccount = [&](int64_t& bal) {
    uint32_t n = 0;
    queried = client.queryAccount(mapKey, bal, n) == ces::CES_OK;
    return queried && (bal != 0 || n != 0);
  };
  bool exists = hasAccount(balance);
  if (exists) s.row("account", credits(balance) + " credits");
  else if (!queried) s.row("account", s.r("the server did not answer the balance query"));
  else s.row("account", "none yet; mining opens it, or anyone can send you credits");

  // ---- 4. Mining ----
  int found = 0;
  int64_t earned = 0;
  const auto startAll = std::chrono::steady_clock::now();
  if (args.solutions != 0) {
    if (client.getServerPowEngine() != 1) {
      s.row("mining", "this server takes no proof of work");
    } else {
      const unsigned hw = std::max(1u, std::thread::hardware_concurrency());
      unsigned threads = args.threads ? std::min(args.threads, hw) : std::max(1u, hw / 2);
      const uint64_t reward = (1ULL << (diff > 0 ? diff - 1 : 0)) * kPowRewardBase;
      s.row("mining", "difficulty " + std::to_string(diff) + " · " + credits(static_cast<int64_t>(reward)) +
                      " credits a solution · " + std::to_string(threads) +
                      (threads == 1 ? " thread" : " threads") + " · " + s.b("Ctrl+C") + " to stop");
      std::cout << "\n";

      // Until the first hashes come back, the engine prepares (seconds, or a
      // minute for the full dataset). A spinner shows that it is alive.
      std::mutex outMu;
      std::atomic<bool> engineReady{false}, waiterDone{false};
      std::thread waiter;
      if (s.tty) {
        waiter = std::thread([&] {
          static const char* kWait[] = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
          for (int i = 0; !waiterDone && !engineReady; ++i) {
            {
              std::lock_guard<std::mutex> lk(outMu);
              if (engineReady) break;
              s.clearLine();
              std::cout << "  " << s.y(kWait[i % 10]) << " " << clock(std::chrono::steady_clock::now() - startAll)
                        << s.d("  preparing the proof-of-work engine (it takes a while the first time) …")
                        << std::flush;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
          }
        });
      }

      std::signal(SIGINT, onInterrupt);
      std::signal(SIGTERM, onInterrupt);
      static const char* kSpin[] = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
      int spin = 0, failures = 0;
      while (ces::notInterrupted() && (args.solutions < 0 || found < args.solutions)) {
        // The rate counts from the first hashes of this solution, not from the
        // start of the call (which can include the engine's preparation).
        bool first = true;
        uint64_t h0 = 0;
        auto t0 = std::chrono::steady_clock::now();
        auto progress = [&](uint64_t hashes) {
          engineReady = true;
          if (!s.tty) return;
          auto now = std::chrono::steady_clock::now();
          if (first) { first = false; h0 = hashes; t0 = now; }
          double secs = std::chrono::duration<double>(now - t0).count();
          std::lock_guard<std::mutex> lk(outMu);
          s.clearLine();
          std::cout << "  " << s.y(kSpin[spin++ % 10]) << " " << clock(now - startAll)
                    << "  solution " << (found + 1) << "  " << grouped(hashes) << " hashes  "
                    << (secs > 0 ? rate((hashes - h0) / secs) : std::string("…")) << std::flush;
        };
        auto submitted = [&](int) {
          engineReady = true;
          if (!s.tty) return;
          std::lock_guard<std::mutex> lk(outMu);
          s.clearLine();
          std::cout << "  " << s.y("↑") << " " << clock(std::chrono::steady_clock::now() - startAll)
                    << "  solution " << (found + 1) << " found; the server checks it …" << std::flush;
        };
        ces::MineResult m = ces::mineOnce(client, 0, {}, static_cast<int>(threads), submitted,
                                          progress, 256ULL * threads);
        engineReady = true;
        {
          std::lock_guard<std::mutex> lk(outMu);
          s.clearLine();
        }
        if (ces::interrupted()) break;
        const std::string at = clock(std::chrono::steady_clock::now() - startAll);
        if (m.success) {
          ++found;
          failures = 0;
          int64_t before = exists ? balance : 0;
          int64_t now = balance;
          // The credit lands on the server's logic strand; read until it shows.
          for (int i = 0; i < 20 && ces::notInterrupted(); ++i) {
            if (hasAccount(now) && (!exists || now != balance)) break;
            ces::sleep(250);
          }
          int64_t gained = now - before;
          if (gained <= 0) gained = static_cast<int64_t>(m.credit);
          earned += gained;
          balance = now;
          const bool opened = !exists;
          exists = true;
          std::cout << "  " << s.g("✓") << " " << at << "  solution " << found << "  "
                    << s.g("+" + credits(gained)) << (opened ? s.d(" (after the fee that opened the account)") : "")
                    << "   balance " << s.b(credits(balance)) << "\n" << std::flush;
        } else if (m.status == minx::MINX_SOLUTION_UNTIMELY) {
          std::cout << "  " << s.y("✗") << " " << at << "  the server did not take this proof in time; next one\n";
        } else if (m.status == minx::MINX_SOLUTION_UNKNOWN) {
          std::cout << "  " << s.y("?") << " " << at << "  the server did not confirm this proof; next one\n";
        } else if (++failures >= 3) {
          std::cout << "  " << s.r("✗") << " " << at << "  mining does not work with this server; stopping\n";
          break;
        }
        std::cout << std::flush;
      }
      waiterDone = true;
      if (waiter.joinable()) waiter.join();
      std::cout << "\n";
      s.row("stopped", std::to_string(found) + (found == 1 ? " solution" : " solutions") + " · +" +
                       credits(earned) + " credits in " + clock(std::chrono::steady_clock::now() - startAll) +
                       " · balance " + (exists ? credits(balance) : std::string("none")));
    }
  }
  client.stop();

  // ---- 5. The shell ----
  const char* current = std::getenv("CESH_SERVER");
  if (current && server == current) {
    s.row("shell", "CESH_SERVER is already " + server);
    return 0;
  }
  if (!interactive) {
    std::cout << "export CESH_SERVER=" << server << "\n";
    return 0;
  }
  const char* shellEnv = std::getenv("SHELL");
  std::string shell = (shellEnv && *shellEnv) ? shellEnv : "/bin/sh";
  s.row("shell", "a new " + shell + " with CESH_SERVER=" + server + s.d(" · exit to leave it"));
  std::cout << std::flush;
  std::cerr << std::flush;
  ::setenv("CESH_SERVER", server.c_str(), 1);
  ::execl(shell.c_str(), shell.c_str(), static_cast<char*>(nullptr));
  std::cerr << "Error: cannot start " << shell << ". In this terminal, run:\n"
            << "  export CESH_SERVER=" << server << "\n";
  return 1;
}
