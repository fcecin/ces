// cesh chat over a Unix domain socket, for a program (or an AI) that uses the
// chat as a user: `cesh chat --listen SOCK` runs the chat, and
// `cesh chat --connect SOCK <message>` sends one message and prints the
// events until the chat wants the next one.
//
// Each line is one message or one event: a type word, a space, and a payload
// in which "\" is "\\" and a newline is "\n".
//
//   to the chat:    say <text> | yes | no | secret <text> | quit
//   from the chat:  show <text>          what a person would see
//                   run <kind> <command> kind: read, action or refused
//                   result <exit code>
//                   cost <raw units>      what a model call charged
//                   context <prompt> <room> <cached %>
//                                         tokens of the last prompt ("~" in
//                                         front: an estimate), the room for a
//                                         prompt, and the share that the cache
//                                         served (-1 = not known)
//                   compact <start | folded N | dropped N>
//                                         the older turns (N bytes) fold
//                                         into the summary
//                   drop <text>           reply text that the chat removed
//                   prompt <text>         with --trace: the prompt sent
//                   reply <text>          with --trace: the model's reply
//                   ask <question>        wait for yes or no
//                   ask-secret <prompt>   wait for secret <text>
//                   done                  the turn is over; wait for say
//                   error <text> | bye
//
// The messages form one stream over many connections: the chat keeps its
// state, and a client may send `yes` on a new connection. One client at a
// time.

#pragma once

#include <string>

namespace ces::chat {

std::string escapeEvent(const std::string& s);
std::string unescapeEvent(const std::string& s);

class ChatSocket {
public:
  ChatSocket() = default;
  ~ChatSocket();
  ChatSocket(const ChatSocket&) = delete;
  ChatSocket& operator=(const ChatSocket&) = delete;

  // Bind and listen at `path` (mode 0600). A socket file that no process
  // serves is removed first. Returns false with `err` set.
  bool listen(const std::string& path, std::string& err);

  // The next message line, from the current client or the next one.
  // Returns false only when the socket fails.
  bool next(std::string& line);

  // Send one event to the current client (dropped when there is none).
  void send(const std::string& type, const std::string& payload = "");

private:
  int listenFd_ = -1;
  int conn_ = -1;
  std::string path_;
  std::string in_;
};

// Send one message to the chat at `path`, print the events until the chat
// waits for the next message, and return 0 (1 on an error event or when the
// chat is not there).
int chatClient(const std::string& path, const std::string& message);

}  // namespace ces::chat
