// cesh chat: a conversation that also operates cesh.
//
// The user talks, and the chat sends the conversation to builtin:think (text
// in, text out). When a line of the reply starts with the execution marker
// (kExecMarker, "%%CESH-EXEC%%"), the chat runs the cesh command after it,
// through cesh itself, in this process, and gives the results back to the
// model in the next turn. The marker is in no other language, so markdown
// stays text for the user. The model learns cesh from the manual
// that is built into cesh (`man`), and keeps the user's notes in a local
// memory file.
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

// The line prefix that runs a command. Nothing else runs.
extern const char* const kExecMarker;

// The commands of the marker lines of a reply, in order. A "cesh " after the
// marker is removed.
std::vector<std::string> commandLines(const std::string& reply);

// The reply without its marker lines, for the user. All else stays.
std::string proseOf(const std::string& reply);

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

struct ThinkReply {
  bool ok = false;
  std::string text;
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

// A model reply, split for the user and the transcript (cleanReply).
struct CleanReply {
  std::string prose;                    // what the user sees: the text before the first command
  std::vector<std::string> commands;    // the commands to run
  std::string kept;                     // the reply as the transcript keeps it
  std::vector<std::string> bodies;      // per command: the content of a `write`, or ""
  std::string dropped;                  // text that the chat removed, if any
  bool fabricated = false;              // the reply imitated the chat's own entries
  bool unterminated = false;            // a `write` had no end marker: it does not run
};

// Split a reply. Text after the first command line is dropped: the model
// must stop and wait for the results. A line that starts as the chat's own
// entries do ("RESULT of", "YOU:", "USER:", "CHAT:") is an imitation: the
// reply is cut there, and nothing after it runs. A `write <name>` takes the
// lines after it, up to a line "%%CESH-END%%", as its content.
CleanReply cleanReply(const std::string& reply);

struct Hooks {
  std::function<ThinkReply(const std::string& prompt)> think;
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

  // The full prompt for the next model call.
  std::string prompt() const;

  const std::string& transcript() const { return transcript_; }
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
  // the call answers the conversation, so the status shows its prompt.
  ThinkReply think(const std::string& prompt, bool answer = true);
  uint64_t tokensOf(size_t bytes) const;   // an estimate from the last call
  double bytesPerTokenOr3() const { return bytesPerToken_ > 0 ? bytesPerToken_ : 3.0; }
  uint64_t roomTokens() const;
  // Make room for the next prompt: fold the older turns into the summary
  // when the prompt passes compactAt. False only when it still does not fit.
  bool fit();
  bool compact();
  void cutOldest(size_t keepBytes);   // the floor when the model cannot fold
  // Take the first `n` bytes off the transcript, and the turns that start in them.
  void dropFront(size_t n);

  Options opt_;
  Hooks hooks_;
  Memory memory_;
  std::string transcript_;
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
  // Where each turn starts in the transcript. Kept here, not searched for:
  // a command's output can hold a line that starts "USER: ".
  std::vector<size_t> turns_;
  // The window, as the last call reported it, and how the last prompt went.
  uint32_t window_ = 0, inputMax_ = 0, outMax_ = 0;
  double bytesPerToken_ = 0;   // of the last reported prompt; 0 = not known
  int64_t lastPromptTokens_ = -1, lastCachedTokens_ = -1;   // of the last answer
};

}  // namespace ces::chat
