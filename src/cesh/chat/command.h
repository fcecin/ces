// `cesh chat`: the command line of the chat (terminal, --listen, --connect). The
// engine is chat/chat.h; the socket protocol is chat/socket.h.

#pragma once

#include <CLI/CLI.hpp>

#include <cstdint>
#include <string>
#include <vector>

struct ChatArgs {
  std::string memoryPath;   // default: ~/.cesh/memory.md
  int maxThinks = 10;
  std::string listen;       // --listen SOCK: serve the chat on a Unix socket (chat/socket.h)
  std::string connect;      // --connect SOCK: send `message` to a listening chat
  bool trace = false;       // --trace: with --listen, also send the prompts and replies
  bool yolo = false;        // --yolo: run actions without asking (refusals still hold)
  std::vector<std::string> message;   // with --connect: say <text> | yes | no | secret <text> | quit
};

// The cesh global options of this run. Each command of the chat gets them,
// unless the command names its own.
struct ChatGlobals {
  std::string server;
  std::string proxy;
  std::string serverKey;
  std::string wallet;
  std::string actor;
  uint16_t rpcPort = 0;
  int tries = 3;
};

CLI::App* addChatCommand(CLI::App& app, ChatArgs& args);

int runChat(const ChatArgs& args, ChatGlobals g);
