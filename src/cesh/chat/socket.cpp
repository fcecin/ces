#include "chat/socket.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iostream>

namespace ces::chat {

std::string escapeEvent(const std::string& s) {
  std::string o;
  o.reserve(s.size());
  for (char c : s) {
    if (c == '\\') o += "\\\\";
    else if (c == '\n') o += "\\n";
    else if (c == '\r') continue;
    else o += c;
  }
  return o;
}

std::string unescapeEvent(const std::string& s) {
  std::string o;
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '\\' && i + 1 < s.size()) {
      char n = s[++i];
      o += n == 'n' ? '\n' : n;
    } else {
      o += s[i];
    }
  }
  return o;
}

namespace {

bool socketAddress(const std::string& path, sockaddr_un& a, std::string& err) {
  std::memset(&a, 0, sizeof a);
  a.sun_family = AF_UNIX;
  if (path.empty() || path.size() >= sizeof(a.sun_path)) {
    err = "socket path is empty or too long: " + path;
    return false;
  }
  std::memcpy(a.sun_path, path.c_str(), path.size());
  return true;
}

int connectTo(const std::string& path) {
  sockaddr_un a;
  std::string err;
  if (!socketAddress(path, a, err)) return -1;
  int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return -1;
  if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) {
    ::close(fd);
    return -1;
  }
  return fd;
}

bool writeAll(int fd, const std::string& s) {
  size_t off = 0;
  while (off < s.size()) {
    ssize_t n = ::send(fd, s.data() + off, s.size() - off, MSG_NOSIGNAL);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    off += static_cast<size_t>(n);
  }
  return true;
}

}  // namespace

ChatSocket::~ChatSocket() {
  if (conn_ >= 0) ::close(conn_);
  if (listenFd_ >= 0) {
    ::close(listenFd_);
    ::unlink(path_.c_str());
  }
}

bool ChatSocket::listen(const std::string& path, std::string& err) {
  sockaddr_un a;
  if (!socketAddress(path, a, err)) return false;
  struct stat st {};
  if (::lstat(path.c_str(), &st) == 0) {
    if (!S_ISSOCK(st.st_mode)) {
      err = path + " exists and is not a socket";
      return false;
    }
    int probe = connectTo(path);
    if (probe >= 0) {
      ::close(probe);
      err = "a chat already listens on " + path;
      return false;
    }
    ::unlink(path.c_str());   // stale: no process serves it
  }
  listenFd_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listenFd_ < 0) {
    err = std::string("socket: ") + std::strerror(errno);
    return false;
  }
  mode_t old = ::umask(0177);   // the socket file is owner-only from birth
  int rc = ::bind(listenFd_, reinterpret_cast<sockaddr*>(&a), sizeof a);
  ::umask(old);
  if (rc != 0 || ::listen(listenFd_, 4) != 0) {
    err = std::string("cannot listen on ") + path + ": " + std::strerror(errno);
    ::close(listenFd_);
    listenFd_ = -1;
    return false;
  }
  ::chmod(path.c_str(), 0600);
  path_ = path;
  return true;
}

bool ChatSocket::next(std::string& line) {
  for (;;) {
    auto nl = in_.find('\n');
    if (nl != std::string::npos) {
      line = in_.substr(0, nl);
      if (!line.empty() && line.back() == '\r') line.pop_back();
      in_.erase(0, nl + 1);
      return true;
    }
    if (conn_ < 0) {
      conn_ = ::accept4(listenFd_, nullptr, nullptr, SOCK_CLOEXEC);
      if (conn_ < 0) {
        if (errno == EINTR) continue;
        return false;
      }
      in_.clear();
      continue;
    }
    char buf[4096];
    ssize_t n = ::read(conn_, buf, sizeof buf);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) {   // the client left; a message without a newline still counts
      ::close(conn_);
      conn_ = -1;
      if (!in_.empty()) {
        line = in_;
        in_.clear();
        return true;
      }
      continue;
    }
    in_.append(buf, static_cast<size_t>(n));
  }
}

void ChatSocket::send(const std::string& type, const std::string& payload) {
  if (conn_ < 0) return;
  std::string l = type;
  if (!payload.empty()) l += " " + escapeEvent(payload);
  l += "\n";
  if (!writeAll(conn_, l)) {
    ::close(conn_);
    conn_ = -1;
  }
}

int chatClient(const std::string& path, const std::string& message) {
  int fd = connectTo(path);
  if (fd < 0) {
    std::cerr << "Error: no chat listens on " << path << " (start one with cesh chat --listen "
              << path << ")\n";
    return 1;
  }
  if (!writeAll(fd, message + "\n")) {
    ::close(fd);
    std::cerr << "Error: cannot send to " << path << "\n";
    return 1;
  }
  std::string in;
  char buf[4096];
  int rc = 0;
  bool finished = false;   // saw an event after which the chat waits
  for (;;) {
    auto nl = in.find('\n');
    if (nl == std::string::npos) {
      ssize_t n = ::read(fd, buf, sizeof buf);
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) break;
      in.append(buf, static_cast<size_t>(n));
      continue;
    }
    std::string line = in.substr(0, nl);
    in.erase(0, nl + 1);
    std::cout << line << "\n" << std::flush;
    std::string type = line.substr(0, line.find(' '));
    if (type == "error") rc = 1;
    if (type == "done" || type == "ask" || type == "ask-secret" || type == "bye" || type == "error") {
      finished = true;
      break;
    }
  }
  ::close(fd);
  if (!finished) {
    std::cerr << "Error: the chat closed the connection before the end of the turn\n";
    return 1;
  }
  return rc;
}

}  // namespace ces::chat
