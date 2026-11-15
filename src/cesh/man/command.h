// `cesh man`: print, search and serve the manual that is built into cesh.

#pragma once

#include <CLI/CLI.hpp>

#include <cstdint>
#include <string>
#include <vector>

struct ManArgs {
  std::vector<std::string> words;   // a page, or a command ("file put")
  std::string search;               // --search WORD
  bool serve = false;               // --serve PORT given
  uint16_t servePort = 0;
  std::string bind = "127.0.0.1";   // --bind ADDR (with --serve)
};

// Add the `man` subcommand to `app`, with its options bound to `args`.
CLI::App* addManCommand(CLI::App& app, ManArgs& args);

// Run `cesh man`. `app` is the whole cesh command tree, for command help.
int runMan(CLI::App& app, const ManArgs& args);
