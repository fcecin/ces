#pragma once

/**
 * Cesco — CES Console
 *
 * A Unix domain socket server that provides a bidirectional byte stream
 * per connection with a replaceable interpreter. The default interpreter
 * is a line-based REPL with built-in commands.
 *
 * Enable in server config:
 *   admin_socket = "./admin.sock"
 *
 * Connect:
 *   rlwrap socat - UNIX-CONNECT:./admin.sock
 *   socat READLINE UNIX-CONNECT:./admin.sock  (if socat has readline support)
 *
 * Architecture:
 *   - The socket layer reads/writes raw bytes.
 *   - Each connection has its own Interpreter.
 *   - The default interpreter line-buffers input and dispatches commands.
 *   - A future interpreter (e.g. Lua) can replace the default and take
 *     full control of the byte stream, including terminal escape sequences.
 */

#include <boost/asio.hpp>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ces {

class CesServer;

class CescoSession : public std::enable_shared_from_this<CescoSession> {
public:
  using Socket = boost::asio::local::stream_protocol::socket;
  using SendFn = std::function<void(const std::string&)>;

  // Interpreter: processes raw input bytes. Default is the builtin REPL.
  // Can be replaced at runtime (e.g. by a "load lua" command).
  using Interpreter = std::function<void(const uint8_t* data, size_t len)>;

  CescoSession(Socket socket, CesServer& server);
  void start();
  void send(const std::string& data);

private:
  void doRead();
  void builtinInterpreter(const uint8_t* data, size_t len);
  std::string dispatchCommand(const std::string& line);

  Socket socket_;
  CesServer& server_;
  Interpreter interpreter_;
  std::string lineBuffer_;
  std::array<uint8_t, 4096> readBuf_;
};

class Cesco {
public:
  Cesco(boost::asio::io_context& io, CesServer& server);
  ~Cesco();

  // Start listening. Returns true on success.
  bool listen(const std::string& socketPath);

  // Stop accepting and close all sessions.
  void stop();

private:
  void doAccept();

  boost::asio::io_context& io_;
  CesServer& server_;
  std::unique_ptr<boost::asio::local::stream_protocol::acceptor> acceptor_;
  std::string socketPath_;
};

} // namespace ces
