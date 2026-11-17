// ceshd: runs cesh commands for many people (the wire is in ceshd.h).
//
// The parent never starts a thread. It waits in poll() for a request, a
// child that ends, a deadline, or a client that leaves. For each request it
// forks a child. The child is a copy of the parent: it starts at once, and
// it shares the pages of the parent until it writes them. Each child runs
// one command, and ends. Nothing stays in memory between commands.
//
// A child works in one directory. With --homes, a request with a wallet
// works in the home of its first key, and the home stays between commands
// (~/.cesh of cesh chat, files that a command gets). Else the child works
// in a new scratch directory, which goes when the command ends.
//
// ceslib catches SIGINT and SIGTERM (ces/util/ctrlc.h): they set a flag, and
// poll() returns EINTR. Then ceshd stops its children and ends. A child
// keeps the handlers of cesh, as a cesh that a person starts.

#include "ceshd.h"
#include "jail.h"
#include "cesh_run.h"

#include <ces/util/ctrlc.h>
#include <ces/util/wallet.h>

#include <CLI/CLI.hpp>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <map>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

namespace {

struct Child {
  pid_t pid = 0;
  int conn = -1;           // the client; -1 after the client left
  fs::path scratch;        // empty for a command in a home
  Clock::time_point start;
  Clock::time_point deadline;
  bool timedOut = false;
};

// Each file or directory of a home counts at least one block, so many small
// files also fill a home.
constexpr uint64_t kEntryBytes = 4096;

// The hex public key of the first key of a CESH_WALLET value, or "" when
// that key is not valid.
std::string firstPublicKey(const std::string& wallet) {
  std::string first = wallet.substr(0, wallet.find(':'));
  if (first.size() != 64 && first.size() != 66)
    return "";
  for (char c : first)
    if (!std::isxdigit(static_cast<unsigned char>(c)))
      return "";
  try {
    return ces::Wallet::loadKey(first).getPublicKeyHexStr();
  } catch (const std::exception&) {
    return "";
  }
}

// The bytes in a home, to `cap` at most. Symlinks are not followed.
uint64_t homeBytes(const fs::path& home, uint64_t cap) {
  uint64_t used = 0;
  std::error_code ec;
  for (fs::recursive_directory_iterator it(home, ec), end; !ec && it != end && used < cap;
       it.increment(ec)) {
    struct stat st{};
    if (::lstat(it->path().c_str(), &st) != 0)
      continue;
    used += std::max<uint64_t>(static_cast<uint64_t>(st.st_blocks) * 512, kEntryBytes);
  }
  return used;
}

int pidfdOpen(pid_t pid) {
  return static_cast<int>(::syscall(SYS_pidfd_open, pid, 0));
}

void reply(int conn, const std::string& text) {
  if (conn >= 0)
    ::send(conn, text.data(), text.size(), MSG_NOSIGNAL);
}

void closeAll(const std::vector<int>& fds) {
  for (int fd : fds)
    ::close(fd);
}

size_t threadCount() {
  size_t n = 0;
  std::error_code ec;
  for (fs::directory_iterator it("/proc/self/task", ec), end; !ec && it != end;
       it.increment(ec))
    ++n;
  return n;
}

void writeErr(const std::string& text) {
  ssize_t ignored = ::write(STDERR_FILENO, text.data(), text.size());
  (void)ignored;
}

// The child: runs one command in `dir`, and never returns. A home (`homeMax`
// is not 0) is made when it is not there, and a file can grow only into the
// room that the home has left.
[[noreturn]] void runChild(const ceshd::Request& req, const std::vector<int>& fds,
                           const fs::path& dir, uint64_t homeMax, ceshd::Limits limits,
                           pid_t parent) {
  // The child ends with the parent.
  ::prctl(PR_SET_PDEATHSIG, SIGKILL);
  if (::getppid() != parent)
    ::_exit(126);
  for (int i = 0; i < 3; ++i)
    if (::dup2(fds[i], i) < 0)
      ::_exit(126);
  // The listening socket, the connections of other clients and the received
  // descriptors are not for this child.
  ::syscall(SYS_close_range, 3, ~0U, 0);
  // A terminal on stdin (a pty from the client) becomes the controlling
  // terminal, for the commands that draw on it.
  ::setsid();
  if (::isatty(STDIN_FILENO))
    ::ioctl(STDIN_FILENO, TIOCSCTTY, 0);

  if (homeMax > 0) {
    if (::mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST) {
      writeErr("ceshd: home: " + std::string(std::strerror(errno)) + "\n");
      ::_exit(126);
    }
    uint64_t used = homeBytes(dir, homeMax);
    limits.fileBytes = std::min(limits.fileBytes, used < homeMax ? homeMax - used : 0);
  }

  ::clearenv();
  ::setenv("HOME", dir.c_str(), 1);
  ::setenv("PATH", "/usr/bin:/bin", 1);
  for (const auto& [name, value] : req.env)
    ::setenv(name.c_str(), value.c_str(), 1);
  if (::chdir(dir.c_str()) != 0) {
    writeErr("ceshd: chdir: " + std::string(std::strerror(errno)) + "\n");
    ::_exit(126);
  }
  std::string e = ceshd::confine(dir.string(), limits);
  if (!e.empty()) {
    writeErr("ceshd: " + e + "\n");
    ::_exit(126);
  }

  std::vector<std::string> args{"cesh"};
  args.insert(args.end(), req.args.begin(), req.args.end());
  std::vector<char*> argv;
  for (auto& a : args)
    argv.push_back(a.data());
  argv.push_back(nullptr);
  int rc = 1;
  try {
    rc = ceshRun(static_cast<int>(args.size()), argv.data());
  } catch (const std::exception& ex) {
    std::cerr << "Error: " << ex.what() << "\n";
  }
  std::cout.flush();
  std::cerr.flush();
  std::fflush(nullptr);
  ::_exit(rc & 0xff);
}

// Reads one request and its three descriptors from a new connection.
// Returns false, after a reply, for a bad request.
bool readRequest(int conn, ceshd::Request& req, std::vector<int>& fds) {
  timeval tv{2, 0};
  ::setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  std::string data(ceshd::kMaxRequest + 1, '\0');
  alignas(cmsghdr) char ctl[CMSG_SPACE(sizeof(int) * 3)];
  iovec iov{data.data(), data.size()};
  msghdr msg{};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = ctl;
  msg.msg_controllen = sizeof(ctl);
  ssize_t n;
  do {
    n = ::recvmsg(conn, &msg, MSG_CMSG_CLOEXEC);
  } while (n < 0 && errno == EINTR);
  if (n <= 0) {
    reply(conn, "error no request");
    return false;
  }
  for (cmsghdr* c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
    if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS)
      continue;
    size_t count = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
    for (size_t i = 0; i < count; ++i) {
      int fd;
      std::memcpy(&fd, CMSG_DATA(c) + i * sizeof(int), sizeof(int));
      fds.push_back(fd);
    }
  }
  if ((msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0) {
    reply(conn, "error the request is too large");
    closeAll(fds);
    return false;
  }
  if (fds.size() != 3) {
    reply(conn, "error a request needs 3 descriptors: stdin, stdout, stderr");
    closeAll(fds);
    return false;
  }
  data.resize(static_cast<size_t>(n));
  std::string why;
  if (!ceshd::decode(data, req, why)) {
    reply(conn, "error " + why);
    closeAll(fds);
    return false;
  }
  return true;
}

std::string outcome(const Child& c, int status) {
  if (c.timedOut)
    return "timeout";
  if (WIFEXITED(status))
    return "exit " + std::to_string(WEXITSTATUS(status));
  if (WIFSIGNALED(status))
    return "signal " + std::to_string(WTERMSIG(status));
  return "error unknown status";
}

}  // namespace

int main(int argc, char* argv[]) {
  CLI::App app{"ceshd: runs cesh commands for many people, each in a confined child"};
  std::string socketPath;
  std::string socketMode = "600";
  std::string scratchRoot = "/tmp";
  std::string homesRoot;
  uint64_t homeMb = 64;
  size_t maxRunning = 32;
  uint64_t timeoutSecs = 300;
  uint64_t memMb = 1024;
  uint64_t fileMb = 64;
  ceshd::Limits limits;
  app.add_option("--socket", socketPath, "Path of the Unix socket")->required();
  app.add_option("--socket-mode", socketMode, "Mode of the socket file, in octal")
    ->capture_default_str();
  app.add_option("--scratch", scratchRoot,
                 "Directory for the scratch directory of each command")
    ->capture_default_str();
  app.add_option("--homes", homesRoot,
                 "Directory for the homes: a request with a wallet works in the home of its "
                 "first key, and the home stays between commands");
  app.add_option("--home-mb", homeMb, "The most that a home holds, in MB")
    ->capture_default_str();
  app.add_option("--max-running", maxRunning, "Commands that run at the same time, at most")
    ->capture_default_str();
  app.add_option("--timeout", timeoutSecs, "Seconds that a command can run")
    ->capture_default_str();
  app.add_option("--cpu", limits.cpuSecs, "CPU seconds of each command")
    ->capture_default_str();
  app.add_option("--mem-mb", memMb, "Address space of each command, in MB")
    ->capture_default_str();
  app.add_option("--file-mb", fileMb, "Largest file that a command can write, in MB")
    ->capture_default_str();
  CLI11_PARSE(app, argc, argv);
  limits.memBytes = memMb << 20;
  limits.fileBytes = fileMb << 20;

  // fork() copies only the calling thread. With one thread, no lock is held
  // by a thread that the child does not have.
  if (threadCount() != 1) {
    std::cerr << "ceshd: the process has more than one thread, so it cannot fork safely\n";
    return 1;
  }
  int abi = ceshd::landlockAbi();
  if (abi < ceshd::kMinLandlockAbi) {
    std::cerr << "ceshd: the kernel has Landlock ABI " << abi << "; ceshd needs "
              << ceshd::kMinLandlockAbi << " (Linux 6.7) to confine commands\n";
    return 1;
  }
  std::error_code ec;
  for (const std::string& d : {scratchRoot, homesRoot}) {
    if (!d.empty() && !fs::is_directory(d, ec)) {
      std::cerr << "ceshd: no directory " << d << "\n";
      return 1;
    }
  }
  const uint64_t homeMax = std::max<uint64_t>(homeMb, 1) << 20;

  int lsn = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (lsn < 0 || socketPath.size() >= sizeof(addr.sun_path)) {
    std::cerr << "ceshd: cannot make the socket " << socketPath << "\n";
    return 1;
  }
  std::memcpy(addr.sun_path, socketPath.c_str(), socketPath.size() + 1);
  ::unlink(socketPath.c_str());
  if (::bind(lsn, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
      ::chmod(socketPath.c_str(), static_cast<mode_t>(std::stoul(socketMode, nullptr, 8))) != 0 ||
      ::listen(lsn, 64) != 0) {
    std::cerr << "ceshd: socket " << socketPath << ": " << std::strerror(errno) << "\n";
    return 1;
  }
  std::cerr << "ceshd: ready on " << socketPath << "\n";

  const pid_t self = ::getpid();
  std::map<int, Child> children;  // by pidfd
  while (ces::notInterrupted()) {
    std::vector<pollfd> pfds{{lsn, POLLIN, 0}};
    auto wait = std::chrono::milliseconds(-1);
    const auto now = Clock::now();
    for (auto& [pidfd, c] : children) {
      pfds.push_back({pidfd, POLLIN, 0});
      if (c.conn >= 0)
        pfds.push_back({c.conn, POLLIN | POLLRDHUP, 0});
      auto left = std::chrono::duration_cast<std::chrono::milliseconds>(c.deadline - now);
      if (!c.timedOut && (wait.count() < 0 || left < wait))
        wait = std::max(left, std::chrono::milliseconds(0));
    }
    int n = ::poll(pfds.data(), pfds.size(), static_cast<int>(wait.count()));
    if (n < 0) {
      if (errno == EINTR)
        continue;
      std::cerr << "ceshd: poll: " << std::strerror(errno) << "\n";
      break;
    }

    // A deadline: the command ends with SIGKILL.
    for (auto& [pidfd, c] : children) {
      if (!c.timedOut && Clock::now() >= c.deadline) {
        c.timedOut = true;
        ::kill(c.pid, SIGKILL);
      }
    }

    for (size_t i = 1; i < pfds.size(); ++i) {
      if (pfds[i].revents == 0)
        continue;
      auto it = children.find(pfds[i].fd);
      if (it != children.end()) {
        // The child ended.
        Child& c = it->second;
        int status = 0;
        ::waitpid(c.pid, &status, 0);
        std::string out = outcome(c, status);
        // The scratch directory goes before the reply, so a client never
        // sees it after the reply.
        if (!c.scratch.empty())
          fs::remove_all(c.scratch, ec);
        reply(c.conn, out);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - c.start);
        std::cerr << "ceshd: pid " << c.pid << " " << out << " (" << ms.count() << " ms)\n";
        if (c.conn >= 0)
          ::close(c.conn);
        ::close(it->first);
        children.erase(it);
        continue;
      }
      // A client left (or sent more than its request): stop its command.
      for (auto& [pidfd, c] : children) {
        if (c.conn == pfds[i].fd) {
          ::kill(c.pid, SIGKILL);
          ::close(c.conn);
          c.conn = -1;
          break;
        }
      }
    }

    if ((pfds[0].revents & POLLIN) == 0)
      continue;
    int conn = ::accept4(lsn, nullptr, nullptr, SOCK_CLOEXEC);
    if (conn < 0)
      continue;
    ceshd::Request req;
    std::vector<int> fds;
    if (!readRequest(conn, req, fds)) {
      ::close(conn);
      continue;
    }
    if (children.size() >= maxRunning) {
      reply(conn, "error busy: " + std::to_string(maxRunning) + " commands run now");
      closeAll(fds);
      ::close(conn);
      continue;
    }
    // The directory of the command: the home of its key, or a new scratch.
    fs::path dir, scratch;
    auto wallet = req.env.find("CESH_WALLET");
    if (!homesRoot.empty() && wallet != req.env.end() && !wallet->second.empty()) {
      std::string key = firstPublicKey(wallet->second);
      if (key.empty()) {
        reply(conn, "error the first key of the wallet is not valid");
        closeAll(fds);
        ::close(conn);
        continue;
      }
      dir = fs::path(homesRoot) / key;
    } else {
      std::string tmpl = (fs::path(scratchRoot) / "ceshd.XXXXXX").string();
      if (::mkdtemp(tmpl.data()) == nullptr) {
        reply(conn, "error scratch: " + std::string(std::strerror(errno)));
        closeAll(fds);
        ::close(conn);
        continue;
      }
      dir = scratch = tmpl;
    }

    // Nothing buffered in the parent may come out of the child.
    std::cout.flush();
    std::cerr.flush();
    std::fflush(nullptr);
    pid_t pid = ::fork();
    if (pid == 0)
      runChild(req, fds, dir, scratch.empty() ? homeMax : 0, limits, self);
    closeAll(fds);
    if (pid < 0) {
      reply(conn, "error fork: " + std::string(std::strerror(errno)));
      ::close(conn);
      if (!scratch.empty())
        fs::remove_all(scratch, ec);
      continue;
    }
    int pidfd = pidfdOpen(pid);
    if (pidfd < 0) {
      ::kill(pid, SIGKILL);
      ::waitpid(pid, nullptr, 0);
      reply(conn, "error pidfd: " + std::string(std::strerror(errno)));
      ::close(conn);
      if (!scratch.empty())
        fs::remove_all(scratch, ec);
      continue;
    }
    Child c;
    c.pid = pid;
    c.conn = conn;
    c.scratch = scratch;
    c.start = Clock::now();
    c.deadline = c.start + std::chrono::seconds(timeoutSecs);
    children.emplace(pidfd, std::move(c));
  }

  // Stop: each running command ends with SIGKILL.
  for (auto& [pidfd, c] : children) {
    ::kill(c.pid, SIGKILL);
    ::waitpid(c.pid, nullptr, 0);
    if (!c.scratch.empty())
      fs::remove_all(c.scratch, ec);
    reply(c.conn, "error ceshd stopped");
    if (c.conn >= 0)
      ::close(c.conn);
    ::close(pidfd);
  }
  ::close(lsn);
  ::unlink(socketPath.c_str());
  std::cerr << "ceshd: stopped\n";
  return 0;
}
