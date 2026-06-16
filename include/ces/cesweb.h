#pragma once

/**
 * CesWeb — the CES server's localhost web dashboard.
 *
 * A small, single-connection-at-a-time HTTP/1.1 server embedded in the
 * `ces` server binary. It is the operator's "experience center": peering,
 * minting, ledger lookups, billing, and a live log tail — the things you'd
 * otherwise reach for cesh/cesqt to do while a server is running.
 *
 * SECURITY MODEL: there is NO authentication. The dashboard binds to a
 * loopback address by design; reach it by SSH-tunneling into the host
 * (e.g. `ssh -L 8080:127.0.0.1:8080 host`). Never bind it to a public
 * interface.
 *
 * Enable in server config:
 *   web_port = 8080            # 0 = disabled (default)
 *   web_bind = "127.0.0.1"     # loopback only
 *
 * Architecture mirrors Cesco: one acceptor + a per-connection session, on
 * its own io_context/thread. Fast endpoints answer on that thread; the two
 * blocking operations (remote inspect / mine) run on an ephemeral worker
 * thread and post their response back, so the UI never freezes.
 */

#include <boost/asio.hpp>

#include <array>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace ces {

class CesServer;

// Bounded in-memory ring of recent server log lines. A Boost.Log sink that
// CesWeb installs on the logging core pushes finished lines here; the web
// thread reads them for the live "Logs" tab. Thread-safe. Each line carries
// a monotonic sequence number and a unix timestamp (seconds).
class LogRing {
public:
  struct Line {
    uint64_t seq = 0;
    uint64_t ts = 0;  // unix seconds
    std::string text;
  };

  static LogRing& instance();

  // Append one finished log line (already formatted). Called from logging
  // threads under the sink's serialization plus this ring's own mutex.
  void push(std::string text);

  // Return the lines with seq > sinceSeq (oldest first) and report the
  // current high-water sequence in outHi. A sinceSeq of 0 returns the whole
  // retained window.
  std::vector<Line> since(uint64_t sinceSeq, uint64_t& outHi) const;

private:
  mutable std::mutex mu_;
  std::deque<Line> lines_;
  uint64_t nextSeq_ = 1;
  static constexpr size_t kCap = 2000;
};

class CesWebSession : public std::enable_shared_from_this<CesWebSession> {
public:
  using Socket = boost::asio::ip::tcp::socket;

  CesWebSession(Socket socket, CesServer& server);
  void start();

private:
  void doRead();
  bool requestComplete();
  void handleRequest();
  void route(const std::string& method, const std::string& path,
             const std::string& query, const std::string& body);
  void respond(int status, const std::string& contentType,
               const std::string& body);
  void respondJson(const std::string& json);
  // Run blocking work (remote inspect/mine) off the io thread; the result
  // string is posted back and sent as the JSON response.
  void runAsync(std::function<std::string()> work);

  Socket socket_;
  CesServer& server_;
  std::array<char, 8192> readChunk_;
  std::string request_;
  size_t headerEnd_ = 0;        // index just past "\r\n\r\n" (0 = not found yet)
  size_t contentLength_ = 0;
  bool responded_ = false;
};

class CesWeb {
public:
  CesWeb(boost::asio::io_context& io, CesServer& server);
  ~CesWeb();

  // Bind + start accepting. Returns true on success. Installs the log sink.
  bool listen(const std::string& bindAddr, uint16_t port);

  // Stop accepting, close the acceptor, remove the log sink.
  void stop();

  // The TCP port actually bound. Equals the requested port, or the
  // OS-assigned one when listen() was called with port 0 (tests). 0 if not
  // listening.
  uint16_t boundPort() const { return boundPort_; }

private:
  void doAccept();

  boost::asio::io_context& io_;
  CesServer& server_;
  std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor_;
  uint16_t boundPort_ = 0;
  bool logSinkInstalled_ = false;
};

} // namespace ces
