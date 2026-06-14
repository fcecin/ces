/**
 * cesco.cpp — CES Console implementation
 */

#include <ces/cesco.h>
#include <ces/cesplex/meter.h>
#include <ces/server.h>
#include <minx/blog.h>

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <iomanip>
#include <sstream>

LOG_MODULE("cesco");

namespace ces {

// =============================================================================
// CescoSession
// =============================================================================

CescoSession::CescoSession(Socket socket, CesServer& server)
  : socket_(std::move(socket)), server_(server) {
  interpreter_ = [this](const uint8_t* data, size_t len) {
    builtinInterpreter(data, len);
  };
}

void CescoSession::start() {
  enqueue("cesco> ");
  doRead();
}

void CescoSession::send(const std::string& data) {
  // Cross-thread entry: marshal onto the session's executor so all socket
  // I/O happens on the cesco strand (e.g. the logic-strand snapshot callback
  // routes its reply here).
  auto self = shared_from_this();
  boost::asio::post(socket_.get_executor(),
                    [this, self, data]() { enqueue(data); });
}

void CescoSession::enqueue(const std::string& data) {
  // Cesco-strand only. One async_write in flight at a time; the rest queue.
  writeQueue_.push_back(data);
  if (!writing_)
    doWrite();
}

void CescoSession::doWrite() {
  writing_ = true;
  auto self = shared_from_this();
  boost::asio::async_write(socket_, boost::asio::buffer(writeQueue_.front()),
    [this, self](boost::system::error_code ec, size_t) {
      if (ec) {
        if (ec != boost::asio::error::operation_aborted) {
          LOGDEBUG << "cesco send error" << SVAR(ec);
        }
        writing_ = false;
        return;
      }
      writeQueue_.pop_front();
      if (!writeQueue_.empty()) {
        doWrite();
      } else {
        writing_ = false;
        if (closing_) {
          boost::system::error_code ic;
          socket_.close(ic);
        }
      }
    });
}

void CescoSession::doRead() {
  auto self = shared_from_this();
  socket_.async_read_some(boost::asio::buffer(readBuf_),
    [this, self](boost::system::error_code ec, size_t len) {
      if (ec) {
        if (ec != boost::asio::error::eof &&
            ec != boost::asio::error::operation_aborted) {
          LOGDEBUG << "cesco read error" << SVAR(ec);
        }
        return;
      }
      interpreter_(readBuf_.data(), len);
      doRead();
    });
}

void CescoSession::builtinInterpreter(const uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    uint8_t b = data[i];

    // Ctrl+C (ETX) or Ctrl+D (EOT) → close after the farewell flushes
    if (b == 0x03 || b == 0x04) {
      closing_ = true;
      enqueue("bye\n");
      return;
    }

    // Backspace / DEL
    if (b == 0x08 || b == 0x7F) {
      if (!lineBuffer_.empty())
        lineBuffer_.pop_back();
      continue;
    }

    if (b == '\r')
      continue;

    if (b == '\n') {
      // Trim whitespace
      auto line = lineBuffer_;
      lineBuffer_.clear();
      while (!line.empty() && line.back() == ' ') line.pop_back();
      while (!line.empty() && line.front() == ' ') line.erase(line.begin());

      if (!line.empty()) {
        std::string response = dispatchCommand(line);
        if (!response.empty())
          enqueue(response);
        if (closing_)
          return;
      }
      enqueue("cesco> ");
      continue;
    }

    lineBuffer_ += static_cast<char>(b);
  }
}

// Parse a decimal non-negative integer. Returns false on empty,
// leading sign, non-digit, or overflow. Writes result into `out`.
static bool parseU64(const std::string& s, uint64_t& out) {
  if (s.empty()) return false;
  uint64_t v = 0;
  for (char c : s) {
    if (c < '0' || c > '9') return false;
    if (v > (std::numeric_limits<uint64_t>::max() - (c - '0')) / 10)
      return false;
    v = v * 10 + (c - '0');
  }
  out = v;
  return true;
}

// Parse a 64-char lowercase-hex pubkey. Returns false on bad length
// or non-hex chars.
static bool parsePubkeyHex(const std::string& s, minx::Hash& out) {
  if (s.size() != 64) return false;
  auto nib = [](char c, uint8_t& v) -> bool {
    if (c >= '0' && c <= '9') { v = c - '0'; return true; }
    if (c >= 'a' && c <= 'f') { v = c - 'a' + 10; return true; }
    if (c >= 'A' && c <= 'F') { v = c - 'A' + 10; return true; }
    return false;
  };
  for (size_t i = 0; i < 32; ++i) {
    uint8_t hi, lo;
    if (!nib(s[i * 2], hi) || !nib(s[i * 2 + 1], lo)) return false;
    out[i] = (hi << 4) | lo;
  }
  return true;
}

std::string CescoSession::dispatchCommand(const std::string& line) {
  if (line == "h" || line == "help") {
    return
      "Commands:\n"
      "  snapshot                    Write a snapshot of accounts and assets\n"
      "  credit <amount> <pubkey>    Mint credits into an account (creates if missing)\n"
      "  debit  <amount> <pubkey>    Burn credits from an account (clamped to balance)\n"
      "  netbill                     Show per-channel RUDP billing snapshot\n"
      "  h, help                     Show this help\n"
      "  q, quit, exit               Close this session\n"
      "  Ctrl+C                      Close this session\n"
      "\n"
      "pubkey is 64 lowercase hex chars (the account's full public key).\n"
      "\n";
  }

  if (line == "netbill") {
    auto* nb = server_._channelMeter();
    if (!nb) {
      return "netbill: ChannelMeter not active (rpc port disabled).\n";
    }
    auto rows = nb->snapshot();
    std::ostringstream oss;
    oss << "RUDP per-channel billing snapshot (" << rows.size()
        << " channel(s)):\n";
    if (rows.empty()) {
      return oss.str();
    }
    static const char* kHex = "0123456789abcdef";
    auto hexPfx = [&](const HashPrefix& p) {
      std::string s;
      s.reserve(16);
      for (auto b : p) {
        s.push_back(kHex[(b >> 4) & 0xF]);
        s.push_back(kHex[b & 0xF]);
      }
      return s;
    };
    oss << std::left
        << std::setw(28) << "peer"
        << std::setw(8)  << "cid"
        << std::setw(28) << "tag"
        << std::setw(18) << "payer"
        << std::right
        << std::setw(10) << "bs-tot"
        << std::setw(10) << "br-tot"
        << std::setw(12) << "mem-bs-tot"
        << std::setw(8)  << "d-snd"
        << std::setw(8)  << "d-rcv"
        << std::setw(10) << "d-mem-bs"
        << std::setw(8)  << "d-age"
        << "\n";
    for (const auto& r : rows) {
      std::ostringstream peerStr;
      peerStr << r.peer;
      oss << std::left
          << std::setw(28) << peerStr.str()
          << std::setw(8)  << r.channelId
          << std::setw(28) << r.tag
          << std::setw(18) << hexPfx(r.payerPfx)
          << std::right
          << std::setw(10) << r.metrics.bytesSent
          << std::setw(10) << r.metrics.bytesReceived
          << std::setw(12) << r.metrics.memoryByteSeconds
          << std::setw(8)  << r.deltaBytesSent
          << std::setw(8)  << r.deltaBytesReceived
          << std::setw(10) << r.deltaMemByteSeconds
          << std::setw(8)  << r.deltaAgeSec
          << "\n";
    }
    return oss.str();
  }

  if (line == "q" || line == "quit" || line == "exit") {
    closing_ = true;
    enqueue("bye\n");
    return "";
  }

  if (line == "snapshot") {
    auto self = shared_from_this();
    server_.liveSnapshot([self](bool /*ok*/, std::string msg) {
      self->send(msg + "\ncesco> ");
    });
    return "Snapshot requested...\n";
  }

  // credit / debit: "verb <amount> <pubkey>"
  {
    std::istringstream iss(line);
    std::string verb, amountStr, pubkeyStr, extra;
    iss >> verb >> amountStr >> pubkeyStr;
    bool isCredit = (verb == "credit");
    bool isDebit  = (verb == "debit");
    if (isCredit || isDebit) {
      if (amountStr.empty() || pubkeyStr.empty() || (iss >> extra)) {
        return std::string("Usage: ") + verb +
               " <amount> <pubkey-64hex>\n";
      }
      uint64_t amount = 0;
      if (!parseU64(amountStr, amount) || amount == 0) {
        return "Bad amount: " + amountStr +
               " (must be a positive decimal integer)\n";
      }
      if (amount > static_cast<uint64_t>(
            std::numeric_limits<int64_t>::max())) {
        return "Amount too large (exceeds int64_t range).\n";
      }
      minx::Hash key;
      if (!parsePubkeyHex(pubkeyStr, key)) {
        return "Bad pubkey: " + pubkeyStr +
               " (must be exactly 64 lowercase hex chars)\n";
      }
      int64_t signedAmount = static_cast<int64_t>(amount);
      if (isCredit) {
        server_._brr(key, signedAmount);
        LOGINFO << "cesco credit" << VAR(signedAmount) << SVAR(pubkeyStr);
        return "Credited " + amountStr + " to " + pubkeyStr + "\n";
      } else {
        server_._burn(key, signedAmount);
        LOGINFO << "cesco debit" << VAR(signedAmount) << SVAR(pubkeyStr);
        return "Debited " + amountStr + " from " + pubkeyStr + "\n";
      }
    }
  }

  return "Unknown command: " + line + "\nType 'h' for help.\n";
}

// =============================================================================
// Cesco
// =============================================================================

Cesco::Cesco(boost::asio::io_context& io, CesServer& server)
  : io_(io), server_(server) {}

Cesco::~Cesco() {
  stop();
}

bool Cesco::listen(const std::string& socketPath) {
  socketPath_ = socketPath;

  // Remove stale socket file if it exists
  std::error_code fec;
  std::filesystem::remove(socketPath_, fec);

  try {
    boost::asio::local::stream_protocol::endpoint ep(socketPath_);
    acceptor_ = std::make_unique<boost::asio::local::stream_protocol::acceptor>(
      io_, ep);
    LOGINFO << "cesco listening" << SVAR(socketPath_);
    doAccept();
    return true;
  } catch (std::exception& e) {
    LOGERROR << "cesco listen failed" << SVAR(socketPath_) << SVAR(e.what());
    return false;
  }
}

void Cesco::stop() {
  if (acceptor_) {
    boost::system::error_code ec;
    acceptor_->close(ec);
    acceptor_.reset();
  }
  if (!socketPath_.empty()) {
    std::error_code fec;
    std::filesystem::remove(socketPath_, fec);
    socketPath_.clear();
  }
}

void Cesco::doAccept() {
  acceptor_->async_accept(
    [this](boost::system::error_code ec,
           boost::asio::local::stream_protocol::socket socket) {
      if (ec) {
        if (ec != boost::asio::error::operation_aborted) {
          LOGDEBUG << "cesco accept error" << SVAR(ec);
        }
        return;
      }
      LOGDEBUG << "cesco new connection";
      auto session = std::make_shared<CescoSession>(
        std::move(socket), server_);
      session->start();
      doAccept();
    });
}

} // namespace ces
