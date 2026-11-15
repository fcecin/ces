// `cesh bootstrap`: make cesh ready to use on ces.pubcom.org in this terminal.
//
// 1. Wallet: keep the one that cesh loads, or make one with a new key.
// 2. Server: ces.pubcom.org:53830 (or the --server of the command line).
// 3. Account: show the balance of the signer there.
// 4. Mine at the server's minimum difficulty, with live progress, until
//    Ctrl+C.
// 5. Start $SHELL with CESH_SERVER set to that server, so the commands of
//    this terminal use it. A program cannot set its parent shell's
//    environment, so bootstrap becomes the shell (exec). `exit` goes back.

#pragma once

#include <ces/util/wallet.h>

#include <CLI/CLI.hpp>

#include <filesystem>
#include <string>

struct BootstrapArgs {
  unsigned threads = 0;   // 0 = half the cores
  int solutions = -1;     // stop after this many solutions; -1 = until Ctrl+C (hidden, for tests)
};

struct BootstrapEnv {
  ces::Wallet* wallet = nullptr;
  std::filesystem::path walletPath;   // where the wallet is, or where a new one goes
  bool walletFromEnv = false;         // keys came from $CESH_WALLET
  std::string actor;                  // -a, or empty for @0
  std::string server;                 // --server of the command line, or empty
  bool cacheOnly = false;             // -c: light PoW engine
  int tries = 3;
};

CLI::App* addBootstrapCommand(CLI::App& app, BootstrapArgs& args);

int runBootstrap(const BootstrapArgs& args, BootstrapEnv env);
