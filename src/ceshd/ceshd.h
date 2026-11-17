// ceshd runs cesh commands for many people.
//
// A client connects to the ceshd Unix socket (SOCK_SEQPACKET) and sends one
// request: one message that holds the fields below, and the stdin, stdout
// and stderr of the command as three file descriptors (SCM_RIGHTS). ceshd
// forks a child. The child uses the three descriptors as fds 0, 1 and 2,
// confines itself (src/ceshd/jail.h) and runs the command with ceshRun, as if
// a person typed it. The output goes directly to the client. When the child
// ends, ceshd sends one reply message and closes the connection.
//
// Request fields, each followed by a NUL byte:
//   "ceshd/1"         the version of the wire
//   NAME=value ...    the environment of the command, zero or more fields.
//                     The names are the client variables of cesh:
//                     CESH_WALLET (keys), CESH_SERVER and CESH_PROXY.
//   ""                an empty field: the end of the environment
//   arg, arg, ...     the cesh arguments, without the program name
//
// Reply: "exit N", "signal N", "timeout", or "error TEXT".
//
// A client that closes the connection before the reply stops the command.

#pragma once

#include <cstddef>
#include <map>
#include <string>
#include <vector>

namespace ceshd {

inline constexpr const char* kVersion = "ceshd/1";
inline constexpr size_t kMaxRequest = 64 * 1024;
inline constexpr size_t kMaxReply = 1024;

// The names that the environment of a request can hold.
inline constexpr const char* kEnvNames[] = {"CESH_WALLET", "CESH_SERVER", "CESH_PROXY"};

struct Request {
  std::map<std::string, std::string> env;
  std::vector<std::string> args;
};

std::string encode(const Request& req);

// Decodes a request. Returns false and sets `why` for a bad request.
bool decode(const std::string& data, Request& out, std::string& why);

// The client side. send() connects to the ceshd at `socketPath` and sends
// `req` with the three descriptors. It returns the connection, or -1 and
// sets `error`. The caller then closes its own copies of the descriptors
// (else it never reads the end of the output), reads the output, and calls
// wait(), which reads the reply and closes the connection. A failure on the
// client side gives "error TEXT".
int send(const std::string& socketPath, const Request& req,
         int stdinFd, int stdoutFd, int stderrFd, std::string& error);
std::string wait(int conn);

}  // namespace ceshd
