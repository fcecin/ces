// cesh chat: a conversation that also operates cesh.
//
// The user talks, and the chat sends the conversation to builtin:think as a
// chat request. The rules are the system message. The lines of the user, the
// replies of the model and the results follow it as messages. The model runs
// a command with its one tool, `cesh`. The chat runs the command through
// cesh, in this process, and sends the result back as the tool message of
// the call. Nothing that the model writes as text runs. The model learns cesh
// from the built-in manual (`man`), and keeps the notes of the user in a
// local memory file.
//
// The chat, not the model, decides what runs: a fixed table classifies each
// command (classify). Reads run at once. All other commands run only after
// the user says yes. The chat handles the key commands itself (runKeys), so
// that no private key goes into the transcript: the model sees public keys,
// `keys add` asks the user for the key, and `keys export` goes to the user
// only.
//
// Chat takes its effects as hooks (think, run, the user's input and output),
// so the tests drive it with scripts.

#pragma once

#include "cesh_run.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace ces::chat {

enum class Kind { Read, Action, Refused };

// Classify `cesh <args...>` (no "cesh" in args). `why` gets the reason for a
// refusal. A command that the table does not know is an Action.
Kind classify(const std::vector<std::string>& args, std::string* why = nullptr);

// The command words of `cesh <args...>`, after the global options.
std::vector<std::string> commandWords(const std::vector<std::string>& args);

// The first argument of `cesh <args...>` that names a local file outside the
// scratch directory (canonical), or "" when there is none. The scratch is the
// only local place the chat sees. An argument may be a path, "file:<path>",
// or "--opt=<path>"; a relative path is under the scratch, "~" is $HOME, and
// a symlink counts where it points. A server path (/h/ /f/ /p/ /s/ /m/) is not
// local. The `-w` of `keys gen` / `keys add` is the chat's own.
std::string outsideScratch(const std::vector<std::string>& args, const std::string& scratch);

// What an action will do, in words, for the confirm question: "Send 2 credits
// from @0 to 0056a1f5…ca68, opening its account". Empty when the chat has no
// words for the command. `args` is the command with the chat's global options.
std::string describeAction(const std::vector<std::string>& args);

// "@N <public key>" lines from the output of `keys list --public`. Nothing of
// the private keys.
std::string publicKeysOf(const std::string& keysListPublicOut);

// Split a command line as a shell does for words and quotes: spaces separate
// words; '...' and "..." group; a backslash escapes the next character
// (except inside '...'). Returns false on an open quote.
bool splitLine(const std::string& line, std::vector<std::string>& out);

// Text that is safe to print on a terminal: each control character (C0, DEL,
// C1) except a line break and a tab becomes '?'. A command's output can have
// bytes from a remote program (compute call), and an escape sequence must not
// reach the user's terminal.
std::string printable(const std::string& text);

// Take a "$" and a "cesh " off the front of `command` ("$ cesh query @0"
// becomes "query @0"). Returns true when there was a "$".
bool shellCommand(std::string& command);

// The user's own command is a line that starts with "$" or "cesh ". It runs
// as it is, with no model call. This puts "$ <command>" in `line`.
bool userCommand(const std::string& userLine, std::string& line);

// The user's notes: one "- name: text" line each, in a markdown file.
class Memory {
public:
  explicit Memory(std::string path = "");
  bool load();                       // false only when the file exists and cannot be read
  bool save() const;
  void set(const std::string& name, const std::string& text);
  bool erase(const std::string& name);
  std::string text() const;          // the file's content
  const std::map<std::string, std::string>& notes() const { return notes_; }

private:
  std::string path_;
  std::map<std::string, std::string> notes_;
};

// One message of the conversation, as the model API takes it.
struct Message {
  std::string role;         // "user", "assistant" or "tool"
  std::string content;
  std::string toolCalls;    // the JSON array of the tool calls of an assistant message, or ""
  std::string reasoning;    // the reasoning of an assistant message, which the API needs back
  std::string toolCallId;   // the call that a tool message answers
};

// One tool call of a reply, with its command and the content of a `write`.
struct ToolCall {
  std::string id;
  std::string command;   // without "cesh " in front
  std::string content;
  std::string error;     // why it cannot run, or "" when it can
};

// The tool calls of a reply, from the JSON array that the server sent.
std::vector<ToolCall> toolCallsOf(const std::string& json);

// The chat request of `system` and `messages` as JSON {"messages","tools"},
// with the `cesh` tool when `tools` is true. Two user messages in a row
// become one. A tool message with no call before it becomes a user message.
// A call with no tool message gets one that says "did not run". So the model
// API accepts every request.
std::string chatRequest(const std::string& system, const std::vector<Message>& messages,
                        bool tools = true);

struct ThinkReply {
  bool ok = false;
  std::string text;
  std::string toolCalls;   // the JSON array of the tool calls of the reply, or "" for none
  std::string reasoning;   // the reasoning of the reply, or "" for none
  std::string error;
  int64_t charged = -1;   // raw units that the call cost the signer; -1 = not known
  // What the call used, when the server reports it (-1 = not known).
  int64_t promptTokens = -1;
  int64_t cachedTokens = -1;
  // The limits of the server, when it states them (0 = not known).
  uint32_t contextTokens = 0;   // the model's window
  uint32_t maxInputBytes = 0;   // the largest prompt
  uint32_t maxOutTokens = 0;    // the longest reply
};

// How full the model's window is, for the status bar.
struct ContextUse {
  uint64_t promptTokens = 0;    // the last prompt (reported, else estimated)
  uint64_t windowTokens = 0;    // the room for a prompt: the window less the reply
  int cachedPercent = -1;       // of the last prompt, from the cache; -1 = not known
  bool estimated = true;        // promptTokens is an estimate
  int percent() const {
    return windowTokens ? static_cast<int>(promptTokens * 100 / windowTokens) : 0;
  }
};

// "context 15k of 120k (12%) · cache 80%", for the status bar and the cost
// line. A "~" marks an estimate.
std::string contextText(const ContextUse& u);

struct Hooks {
  // One model call with a chat request (chatRequest).
  std::function<ThinkReply(const std::string& request)> think;
  std::function<CeshResult(const std::vector<std::string>& args)> run;
  std::function<bool(std::string& line)> readLine;       // false at the end of input
  std::function<void(const std::string& text)> show;     // to the user
  // Optional: a command's output, to the user as it is (no markdown). When
  // it is not set, the output goes to `show`.
  std::function<void(const std::string& text)> output;
  std::function<bool(const std::string& question)> confirm;
  // Input that must not echo or reach the model (a private key).
  std::function<std::string(const std::string& prompt)> secret;
  // Optional: true when the chat must stop at once (the user quit).
  std::function<bool()> stopped;
  // Optional: what the chat does, for a program that drives it (chat/socket.h).
  // Types: prompt, reply, run ("<read|action|refused> <command>"), result.
  std::function<void(const std::string& type, const std::string& text)> event;
};

struct Options {
  std::string manualIndex;   // Manual::index(): the pages the model can open
  std::string context;       // facts about the session: server, wallet keys
  // The only local directory the chat sees (~/.cesh/scratch): its own read,
  // write and ls, and the local files of cesh commands. Empty: no file work.
  std::string scratchDir;
  std::string walletPath;    // the wallet file for new keys; empty when keys come from $CESH_WALLET
  // Global options that each command gets unless it names them itself:
  // ({"--server"}, "host:port"), ({"-r", "--wallet"}, "path"), ...
  std::vector<std::pair<std::vector<std::string>, std::string>> globals;
  bool showCost = true;   // show each answer's cost as a line (the terminal UI uses its status bar)
  int maxThinks = 10;                    // model calls for one user line
  size_t maxCommands = 8;                // commands run from one reply
  size_t maxResult = 8 * 1024;           // output kept from one command
  // The model's limits until the server states them (a server that does
  // not send the report keeps these).
  uint32_t contextTokens = 65536;
  uint32_t maxInputBytes = 1024 * 1024;
  uint32_t maxOutTokens = 8192;
  // Compaction: when the next prompt passes compactAt percent of the room,
  // the older turns fold into a summary, and the newest turns stay as they
  // are, up to keepPercent of the room.
  int compactAt = 70;
  int keepPercent = 25;
};

class Chat {
public:
  Chat(Options opt, Hooks hooks, Memory memory);

  // Read lines until the end of input, or "exit" or "quit".
  int run();

  // One line from the user, and every model call and command it leads to.
  void turn(const std::string& userLine);

  // The chat request for the next model call, and its system message.
  std::string request() const;
  std::string system() const;

  const std::vector<Message>& messages() const { return messages_; }
  // The messages as text, one "ROLE: content" block each, as the fold reads them.
  std::string transcript() const;
  const std::string& summary() const { return summary_; }
  const Memory& memory() const { return memory_; }
  ContextUse context() const;

private:
  // `line` is a command of a reply, with "$ " in front for a shell line.
  std::string runLine(const std::string& line, const std::string& body = "");
  std::string echo(const std::string& command) const;
  // "→ Read man compute (77 lines)": what went into the conversation.
  std::string readLine(const std::string& what, const std::string& text) const;
  std::string notesText() const;
  void show(const std::string& text);
  void output(const std::string& text);
  bool confirm(const std::string& question);
  std::string runFile(const std::string& verb, const std::string& name, const std::string& line,
                      const std::string& body);
  void emit(const std::string& type, const std::string& text);
  std::string declined(const std::string& head, const std::string& what = "not run");
  bool stopped() const;
  std::string runKeys(const std::vector<std::string>& args, const std::string& line);
  std::string runMemory(const std::vector<std::string>& args, const std::string& line);
  std::vector<std::string> withGlobals(const std::vector<std::string>& args) const;
  // One model call: the usage and the limits go into the chat. `answer`:
  // the call answers the conversation, so the status shows its size.
  ThinkReply think(const std::string& request, bool answer = true);
  // A user message from the chat itself, which starts with "[chat]".
  void note(const std::string& text);
  // About the bytes of the messages from `from` on, in the request.
  size_t messageBytes(size_t from = 0) const;
  uint64_t tokensOf(size_t bytes) const;   // an estimate from the last call
  double bytesPerTokenOr3() const { return bytesPerToken_ > 0 ? bytesPerToken_ : 3.0; }
  uint64_t roomTokens() const;
  // Make room for the next prompt: fold the older turns into the summary
  // when the prompt passes compactAt. False only when it still does not fit.
  bool fit();
  bool compact();
  void cutOldest(size_t keepBytes);   // the floor when the model cannot fold
  // Take the first `n` messages off, and the turns that start in them.
  void dropFront(size_t n);

  Options opt_;
  Hooks hooks_;
  Memory memory_;
  std::vector<Message> messages_;
  int64_t spent_ = 0;   // raw units of the model calls of this chat
  bool declined_ = false;   // the user said no in this turn
  // The last line ran and succeeded, and its output went to the user (not a
  // manual page): a reply of such lines, with no words, ends the turn.
  bool ok_ = false;
  // Each line, question and output that the user sees. A line that shows the
  // user nothing (it does not parse, or names no file) goes back to the
  // model, also when it is a shell line.
  size_t seen_ = 0;
  // The notes at the start of the prompt: as they were when the chat began,
  // or at the last fold. A change since is in the conversation.
  std::string notes_;
  std::string summary_;   // the older turns, folded by compaction
  // The message where each turn starts.
  std::vector<size_t> turns_;
  // The window, as the last call reported it, and how the last prompt went.
  uint32_t window_ = 0, inputMax_ = 0, outMax_ = 0;
  double bytesPerToken_ = 0;   // of the last reported prompt; 0 = not known
  int64_t lastPromptTokens_ = -1, lastCachedTokens_ = -1;   // of the last answer
};

}  // namespace ces::chat
