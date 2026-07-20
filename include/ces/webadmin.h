#pragma once

/**
 * WebAdmin — the CES server's localhost web dashboard.
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
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace ces {

class CesServer;
class WebAdmin;

// Bounded in-memory ring of recent server log lines. A Boost.Log sink that
// WebAdmin installs on the logging core pushes finished lines here; the web
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

class WebAdminSession : public std::enable_shared_from_this<WebAdminSession> {
public:
  using Socket = boost::asio::ip::tcp::socket;

  WebAdminSession(Socket socket, CesServer& server, WebAdmin& admin);
  void start();

  // ---- WebSocket mode (after a GET /ws upgrade) ----
  // Queue one TEXT frame for delivery. io thread only.
  void wsSend(const std::string& text);
  // Close the socket and unregister (idempotent). io thread only.
  void wsClose();
  bool isWs() const { return ws_; }
  std::set<std::string>& wsSubs() { return wsSubs_; }
  // Push new log lines (> the client's last seq) if this client subscribed
  // with logs-on. Called from WebAdmin's 1s tick; sends only when there is
  // something new. io thread only.
  void wsPushLogs();
  // View-table subscriptions (peers/billing/compute tabs). A subscribed view's
  // payload is pushed when its hash changed for this client. io thread only.
  bool wsWatchesView(const std::string& v) const { return wsViews_.count(v) > 0; }
  void wsPushView(const std::string& view, const std::string& msg, size_t hash);

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

  // ---- WebSocket internals (RFC 6455, TEXT frames) ----
  // Upgrade the parsed GET /ws request; leftover buffered bytes become the
  // start of the WS stream.
  void wsUpgrade();
  void wsRead();
  // Consume complete frames from wsIn_; false = protocol error (close).
  bool wsProcessBuffer();
  void wsHandleMessage(const std::string& text);
  void wsWriteNext();

  Socket socket_;
  CesServer& server_;
  WebAdmin& admin_;
  std::array<char, 8192> readChunk_;
  std::string request_;
  size_t headerEnd_ = 0;        // index just past "\r\n\r\n" (0 = not found yet)
  size_t contentLength_ = 0;
  bool responded_ = false;

  bool ws_ = false;             // session upgraded to WebSocket
  bool wsClosed_ = false;
  std::string wsIn_;            // raw bytes not yet framed
  std::string wsFrag_;          // fragmented-message assembly
  uint8_t wsFragOp_ = 1;
  std::deque<std::string> wsOutQ_;
  bool wsWriting_ = false;
  std::set<std::string> wsSubs_;  // extension panels this client watches
  bool wsLogsSub_ = false;        // logs-on: push new log lines each tick
  uint64_t wsLogsSeq_ = 0;        // last log seq delivered to this client
  std::set<std::string> wsViews_;             // view-on subscriptions
  std::map<std::string, size_t> wsViewHash_;  // last pushed payload per view
};

class WebAdmin {
public:
  WebAdmin(boost::asio::io_context& io, CesServer& server);
  ~WebAdmin();

  // Bind + start accepting. Returns true on success. Installs the log sink
  // and registers as the server's extension-panel push sink. A non-loopback
  // bindAddr is REFUSED (returns false) unless allowPublic is true: the
  // dashboard has no auth, so exposing it must be an explicit operator choice.
  bool listen(const std::string& bindAddr, uint16_t port, bool allowPublic = false);

  // Stop accepting, close the acceptor and any WebSocket sessions, remove
  // the log sink and the push sink.
  void stop();

  // The TCP port actually bound. Equals the requested port, or the
  // OS-assigned one when listen() was called with port 0 (tests). 0 if not
  // listening.
  uint16_t boundPort() const { return boundPort_; }

  // ---- WebSocket push lane (sessions call these on the io thread) ----
  void wsRegister(const std::shared_ptr<WebAdminSession>& s);
  void wsUnregister(WebAdminSession* s);
  // hello/bye for one extension's panel; drives per-extension watch counts
  // (0 <-> >0 transitions toggle the child's change-detect tick).
  void wsSubscribe(WebAdminSession* s, const std::string& ext);
  void wsUnsubscribe(WebAdminSession* s, const std::string& ext);

  // Relay an unsolicited panel frame to subscribed clients. Any thread
  // (posts onto the io thread).
  void panelPush(const std::string& name, const std::string& frame);

  // Payload for a pushed tab view ("peers"/"billing"/"compute"; "" = unknown).
  // io thread only (same builders the GET endpoints run on this thread).
  std::string viewData(const std::string& view);

private:
  void doAccept();
  // 1s cadence while at least one WS client is connected: push a status
  // frame (replaces the browser heartbeat poll), log/view deltas to their
  // subscribers, and re-assert panel watches (idempotent; heals a relaunched
  // extension child).
  void armStatusTimer();
  void statusTick();
  // Build each subscribed-anywhere view once, push to sessions whose hash
  // changed.
  void viewsTick();

  boost::asio::io_context& io_;
  CesServer& server_;
  std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor_;
  uint16_t boundPort_ = 0;
  bool logSinkInstalled_ = false;

  // WS state. io thread only (sessions live on the one io_context).
  std::map<WebAdminSession*, std::weak_ptr<WebAdminSession>> wsSessions_;
  std::map<std::string, int> wsWatch_;   // ext -> subscriber count
  std::unique_ptr<boost::asio::steady_timer> statusTimer_;
  bool stopping_ = false;
};

} // namespace ces
