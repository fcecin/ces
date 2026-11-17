#include "ceshd.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace ceshd {

namespace {

bool knownName(const std::string& name) {
  for (const char* n : kEnvNames)
    if (name == n)
      return true;
  return false;
}

}  // namespace

std::string encode(const Request& req) {
  std::string out;
  out.append(kVersion).push_back('\0');
  for (const auto& [name, value] : req.env)
    out.append(name).append("=").append(value).push_back('\0');
  out.push_back('\0');
  for (const auto& a : req.args)
    out.append(a).push_back('\0');
  return out;
}

bool decode(const std::string& data, Request& out, std::string& why) {
  if (data.empty() || data.back() != '\0') {
    why = "a field is not ended by NUL";
    return false;
  }
  std::vector<std::string> fields;
  size_t start = 0;
  for (size_t i = 0; i < data.size(); ++i) {
    if (data[i] == '\0') {
      fields.emplace_back(data, start, i - start);
      start = i + 1;
    }
  }
  if (fields.empty() || fields[0] != kVersion) {
    why = std::string("not a ") + kVersion + " request";
    return false;
  }
  out.env.clear();
  size_t i = 1;
  for (; i < fields.size() && !fields[i].empty(); ++i) {
    const std::string& f = fields[i];
    size_t eq = f.find('=');
    std::string name = eq == std::string::npos ? f : f.substr(0, eq);
    if (eq == std::string::npos || !knownName(name)) {
      why = "the environment can hold only CESH_WALLET, CESH_SERVER and CESH_PROXY";
      return false;
    }
    if (!out.env.emplace(name, f.substr(eq + 1)).second) {
      why = "the environment names " + name + " twice";
      return false;
    }
  }
  if (i == fields.size()) {
    why = "the environment has no end (an empty field)";
    return false;
  }
  out.args.assign(fields.begin() + static_cast<std::ptrdiff_t>(i) + 1, fields.end());
  return true;
}

int send(const std::string& socketPath, const Request& req,
         int stdinFd, int stdoutFd, int stderrFd, std::string& error) {
  int s = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  if (s < 0) {
    error = std::string("error socket: ") + std::strerror(errno);
    return -1;
  }
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (socketPath.size() >= sizeof(addr.sun_path)) {
    ::close(s);
    error = "error socket path too long";
    return -1;
  }
  std::memcpy(addr.sun_path, socketPath.c_str(), socketPath.size() + 1);
  if (::connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    error = std::string("error connect: ") + std::strerror(errno);
    ::close(s);
    return -1;
  }

  std::string data = encode(req);
  int fds[3] = {stdinFd, stdoutFd, stderrFd};
  alignas(cmsghdr) char ctl[CMSG_SPACE(sizeof(fds))];
  std::memset(ctl, 0, sizeof(ctl));
  iovec iov{data.data(), data.size()};
  msghdr msg{};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = ctl;
  msg.msg_controllen = sizeof(ctl);
  cmsghdr* c = CMSG_FIRSTHDR(&msg);
  c->cmsg_level = SOL_SOCKET;
  c->cmsg_type = SCM_RIGHTS;
  c->cmsg_len = CMSG_LEN(sizeof(fds));
  std::memcpy(CMSG_DATA(c), fds, sizeof(fds));
  if (::sendmsg(s, &msg, MSG_NOSIGNAL) < 0) {
    error = std::string("error send: ") + std::strerror(errno);
    ::close(s);
    return -1;
  }
  return s;
}

std::string wait(int conn) {
  char buf[kMaxReply];
  ssize_t n;
  do {
    n = ::recv(conn, buf, sizeof(buf), 0);
  } while (n < 0 && errno == EINTR);
  ::close(conn);
  if (n <= 0)
    return "error no reply";
  return std::string(buf, static_cast<size_t>(n));
}

}  // namespace ceshd
