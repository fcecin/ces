// ceshd (src/ceshd/): a request runs one cesh command in a confined child,
// with the descriptors of the client as its stdin, stdout and stderr. The
// tests start the ceshd binary, next to a CES server in this process.

#ifdef __linux__

#define BOOST_TEST_DYN_LINK
#include "test_common.h"
#include "test_compute_wait.h"   // waitUntil
#include "test_e2e_common.h"

#include "ceshd.h"
#ifdef CES_CESHD
#include "jail.h"
#endif

#include <boost/test/unit_test.hpp>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <spawn.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <thread>
#include <vector>

using namespace ces;
using namespace ces::e2e;
using Clock = std::chrono::steady_clock;

namespace {

bool contains(const std::string& s, const std::string& part) {
  return s.find(part) != std::string::npos;
}

// Fields as the wire has them: each one followed by a NUL byte.
std::string wire(std::initializer_list<std::string> fields) {
  std::string out;
  for (const auto& f : fields)
    out.append(f).push_back('\0');
  return out;
}

}  // namespace

// The E2E tests start ceshd, which builds only with the Landlock TCP rules
// in the kernel headers (CES_CESHD).
#ifdef CES_CESHD
namespace {

struct Daemon {
  pid_t pid = -1;
  std::string sock;
  fs::path scratch;
  fs::path log;
};

std::string readFile(const fs::path& p) {
  std::ifstream f(p);
  std::stringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

// The environment of a request that signs with `k`.
std::map<std::string, std::string> wallet(const KeyPair& k) {
  return {{"CESH_WALLET", "00" + k.getPrivateKeyHexStr()}};
}

// The last 64-hex key in parentheses in `text` ("... (<public key>)").
std::string lastKeyInParens(const std::string& text) {
  std::string found;
  for (size_t i = text.find('('); i != std::string::npos; i = text.find('(', i + 1))
    if (i + 65 < text.size() && text[i + 65] == ')')
      found = text.substr(i + 1, 64);
  return found;
}

struct Result {
  std::string reply;
  std::string out;
  std::string err;
};

// Reads two pipes until both end, or until the deadline.
void drain(int outFd, int errFd, std::string& out, std::string& err, int secs = 60) {
  const auto deadline = Clock::now() + std::chrono::seconds(secs);
  bool outOpen = true, errOpen = true;
  char buf[4096];
  while ((outOpen || errOpen) && Clock::now() < deadline) {
    pollfd p[2] = {{outOpen ? outFd : -1, POLLIN, 0}, {errOpen ? errFd : -1, POLLIN, 0}};
    if (::poll(p, 2, 200) <= 0)
      continue;
    for (int i = 0; i < 2; ++i) {
      if (p[i].revents == 0)
        continue;
      ssize_t n = ::read(p[i].fd, buf, sizeof(buf));
      if (n <= 0) {
        (i == 0 ? outOpen : errOpen) = false;
        continue;
      }
      (i == 0 ? out : err).append(buf, static_cast<size_t>(n));
    }
  }
  ::close(outFd);
  ::close(errFd);
}

// One request with pipes for stdin, stdout and stderr. It uses no Boost.Test
// macro, because some tests call it from several threads.
Result request(const std::string& sock, const ceshd::Request& req) {
  Result r;
  int in[2], out[2], err[2];
  if (::pipe2(in, O_CLOEXEC) != 0 || ::pipe2(out, O_CLOEXEC) != 0 ||
      ::pipe2(err, O_CLOEXEC) != 0) {
    r.reply = "error pipe";
    return r;
  }
  ::close(in[1]);
  std::string e;
  int conn = ceshd::send(sock, req, in[0], out[1], err[1], e);
  // Only the child keeps the write ends now, so its exit ends the output.
  ::close(in[0]);
  ::close(out[1]);
  ::close(err[1]);
  if (conn < 0) {
    ::close(out[0]);
    ::close(err[0]);
    r.reply = e;
    return r;
  }
  drain(out[0], err[0], r.out, r.err);
  r.reply = ceshd::wait(conn);
  return r;
}

// A raw message to the socket, with `fds` (for the requests that ceshd
// must refuse).
std::string raw(const std::string& sock, const std::string& data, const std::vector<int>& fds) {
  int s = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::memcpy(addr.sun_path, sock.c_str(), sock.size() + 1);
  BOOST_REQUIRE(::connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
  iovec iov{const_cast<char*>(data.data()), data.size()};
  msghdr msg{};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  std::vector<char> ctl(CMSG_SPACE(sizeof(int) * fds.size()));
  if (!fds.empty()) {
    msg.msg_control = ctl.data();
    msg.msg_controllen = ctl.size();
    cmsghdr* c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int) * fds.size());
    std::memcpy(CMSG_DATA(c), fds.data(), sizeof(int) * fds.size());
  }
  BOOST_REQUIRE(::sendmsg(s, &msg, MSG_NOSIGNAL) >= 0);
  return ceshd::wait(s);
}

struct CeshdFixture : E2EServerFixture {
  Daemon d;

  CeshdFixture() : E2EServerFixture("ceshd_e2e") { d = start({}, "d"); }

  ~CeshdFixture() { stop(d); }

  Daemon start(const std::vector<std::string>& extra, const std::string& name) {
    Daemon x;
    x.sock = (tempDir / (name + ".sock")).string();
    x.scratch = tempDir / (name + "-scratch");
    x.log = tempDir / (name + ".log");
    fs::create_directories(x.scratch);
    std::vector<std::string> args{findBinary("ceshd"), "--socket", x.sock,
                                  "--scratch", x.scratch.string()};
    args.insert(args.end(), extra.begin(), extra.end());
    std::vector<char*> argv;
    for (auto& a : args)
      argv.push_back(a.data());
    argv.push_back(nullptr);
    char* envp[] = {nullptr};
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 1, x.log.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    posix_spawn_file_actions_adddup2(&fa, 1, 2);
    int rc = ::posix_spawn(&x.pid, argv[0], &fa, nullptr, argv.data(), envp);
    posix_spawn_file_actions_destroy(&fa);
    BOOST_REQUIRE_EQUAL(rc, 0);
    const bool ready =
        waitUntil([&] { return contains(readFile(x.log), "ceshd: ready"); });
    BOOST_REQUIRE_MESSAGE(ready, "ceshd did not start: " + readFile(x.log));
    return x;
  }

  // SIGTERM, and SIGKILL after 3 s. Returns true if ceshd ended on SIGTERM.
  bool stop(Daemon& x) {
    if (x.pid <= 0)
      return true;
    ::kill(x.pid, SIGTERM);
    bool ended = false;
    for (int i = 0; i < 300 && !ended; ++i) {
      ended = ::waitpid(x.pid, nullptr, WNOHANG) == x.pid;
      if (!ended)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!ended) {
      ::kill(x.pid, SIGKILL);
      ::waitpid(x.pid, nullptr, 0);
    }
    x.pid = -1;
    return ended;
  }

  std::string server() const { return "localhost:" + std::to_string(serverPort); }
};

}  // namespace
#endif  // CES_CESHD

BOOST_AUTO_TEST_SUITE(CeshdWire)

// A request decodes to what was encoded, with an empty argument kept.
BOOST_AUTO_TEST_CASE(RoundTrip) {
  ceshd::Request a{{{"CESH_WALLET", "00ab"}, {"CESH_SERVER", "h:1"}}, {"query", "", "x=y"}};
  ceshd::Request b;
  std::string why;
  BOOST_REQUIRE(ceshd::decode(ceshd::encode(a), b, why));
  BOOST_CHECK(b.env == a.env);
  BOOST_CHECK(b.args == a.args);

  ceshd::Request none{{}, {}};
  BOOST_REQUIRE(ceshd::decode(ceshd::encode(none), b, why));
  BOOST_CHECK(b.env.empty());
  BOOST_CHECK(b.args.empty());
}

// The environment holds only the client variables of cesh, each once, and
// it ends with an empty field.
BOOST_AUTO_TEST_CASE(Refusals) {
  ceshd::Request r;
  std::string why;
  auto bad = [&](const std::string& data) { return !ceshd::decode(data, r, why); };
  BOOST_CHECK(bad(wire({"ceshd/1", "LD_PRELOAD=x", "", "man"})));
  BOOST_CHECK(contains(why, "only CESH_WALLET, CESH_SERVER and CESH_PROXY"));
  BOOST_CHECK(bad(wire({"ceshd/1", "CESH_SERVER", "", "man"})));
  BOOST_CHECK(bad(wire({"ceshd/1", "CESH_SERVER=a", "CESH_SERVER=b", ""})));
  BOOST_CHECK(contains(why, "twice"));
  BOOST_CHECK(bad(wire({"ceshd/1", "CESH_SERVER=a"})));
  BOOST_CHECK(contains(why, "no end"));
  BOOST_CHECK(bad(wire({"ceshd/1", "", "man"}).substr(0, 12)));
  BOOST_CHECK(contains(why, "not ended by NUL"));
  BOOST_CHECK(bad(wire({"ceshd/2", "", "man"})));
}

BOOST_AUTO_TEST_SUITE_END()

#ifdef CES_CESHD

namespace {

// ceshd does not start on a kernel with no Landlock ABI 4 (Linux 6.7), so
// the E2E suite is skipped there.
boost::test_tools::assertion_result landlockReady(boost::unit_test::test_unit_id) {
  const int abi = ceshd::landlockAbi();
  boost::test_tools::assertion_result r(abi >= ceshd::kMinLandlockAbi);
  r.message() << "the kernel has Landlock ABI " << abi << ", ceshd needs " << ceshd::kMinLandlockAbi;
  return r;
}

}  // namespace

BOOST_FIXTURE_TEST_SUITE(CeshdE2E, CeshdFixture, *boost::unit_test::precondition(landlockReady))

// A command runs, its output reaches the descriptors of the client, and the
// reply gives its exit code. Its scratch directory is gone after the reply.
BOOST_AUTO_TEST_CASE(RunsACommand) {
  auto r = request(d.sock, {{}, {"man"}});
  BOOST_CHECK_EQUAL(r.reply, "exit 0");
  BOOST_CHECK_MESSAGE(contains(r.out, "basics"), r.out + r.err);
  BOOST_CHECK(fs::is_empty(d.scratch));

  auto bad = request(d.sock, {{}, {"no-such-command"}});
  BOOST_CHECK_NE(bad.reply, "exit 0");
  BOOST_CHECK(contains(bad.reply, "exit "));
}

// A command reaches a CES server over UDP, and the name localhost resolves
// inside the jail.
BOOST_AUTO_TEST_CASE(QueriesAServer) {
  auto r = request(d.sock, {{{"CESH_WALLET", fundedWalletHex}},
                            {"--server", server(), "query", fundedKey.getPublicKeyHexStr()}});
  BOOST_CHECK_EQUAL(r.reply, "exit 0");
  BOOST_CHECK_MESSAGE(contains(r.out, "10000000000"), r.out + r.err);
}

// The environment of the request reaches cesh: CESH_SERVER is the server
// of a command that names none.
BOOST_AUTO_TEST_CASE(ServerFromTheEnvironment) {
  auto r = request(d.sock, {{{"CESH_SERVER", server()}}, {"query", fundedKey.getPublicKeyHexStr()}});
  BOOST_CHECK_EQUAL(r.reply, "exit 0");
  BOOST_CHECK_MESSAGE(contains(r.out, "10000000000"), r.out + r.err);
}

// With --homes, the home of a key stays between commands: a file that one
// command writes is there for the next command of that key, and not for
// another key. A request with no wallet still gets a new scratch.
BOOST_AUTO_TEST_CASE(HomeStaysForItsKey) {
  fs::path homes = tempDir / "homes";
  fs::create_directories(homes);
  Daemon h = start({"--homes", homes.string()}, "h");
  KeyPair a, b;
  auto gen = request(h.sock, {wallet(a), {"keys", "gen", "-w", "kept.txt"}});
  BOOST_CHECK_EQUAL(gen.reply, "exit 0");
  std::string made = lastKeyInParens(gen.out);
  BOOST_REQUIRE_MESSAGE(made.size() == 64, gen.out + gen.err);
  BOOST_CHECK(fs::exists(homes / a.getPublicKeyHexStr() / "kept.txt"));

  auto again = request(h.sock, {wallet(a), {"-r", "kept.txt", "keys", "list", "--public"}});
  BOOST_CHECK_EQUAL(again.reply, "exit 0");
  BOOST_CHECK_MESSAGE(contains(again.out, made), again.out + again.err);
  auto other = request(h.sock, {wallet(b), {"-r", "kept.txt", "keys", "list", "--public"}});
  BOOST_CHECK(!contains(other.out, made));

  auto anon = request(h.sock, {{}, {"man"}});
  BOOST_CHECK_EQUAL(anon.reply, "exit 0");
  BOOST_CHECK(fs::is_empty(h.scratch));
  BOOST_CHECK_EQUAL(request(h.sock, {{{"CESH_WALLET", "00zz"}}, {"man"}}).reply,
                    "error the first key of the wallet is not valid");
  stop(h);
}

// A home holds --home-mb at most: in a full home, a command that writes a
// file ends on SIGXFSZ. Other commands still run.
BOOST_AUTO_TEST_CASE(HomeHasAQuota) {
  fs::path homes = tempDir / "qhomes";
  fs::create_directories(homes);
  Daemon q = start({"--homes", homes.string(), "--home-mb", "1"}, "q");
  KeyPair a;
  BOOST_CHECK_EQUAL(request(q.sock, {wallet(a), {"keys", "gen", "-w", "one.txt"}}).reply, "exit 0");
  {
    std::ofstream big(homes / a.getPublicKeyHexStr() / "big.bin", std::ios::binary);
    std::string mb(1 << 20, 'x');
    big << mb;
  }
  BOOST_CHECK_EQUAL(request(q.sock, {wallet(a), {"keys", "gen", "-w", "two.txt"}}).reply,
                    "signal " + std::to_string(SIGXFSZ));
  BOOST_CHECK_EQUAL(request(q.sock, {wallet(a), {"man"}}).reply, "exit 0");
  stop(q);
}

// A pty as the three descriptors: the command gets a terminal (cesh man
// draws in color), and Ctrl+C on the terminal stops the command, because
// the terminal is its controlling terminal.
BOOST_AUTO_TEST_CASE(RunsOnATerminal) {
  auto onPty = [&](const std::vector<std::string>& args, bool interrupt, std::string& reply) {
    int master = -1, slave = -1;
    winsize ws{30, 100, 0, 0};
    BOOST_REQUIRE(::openpty(&master, &slave, nullptr, nullptr, &ws) == 0);
    std::string e;
    int conn = ceshd::send(d.sock, {{}, args}, slave, slave, slave, e);
    ::close(slave);
    BOOST_REQUIRE_MESSAGE(conn >= 0, e);
    std::string out;
    char buf[4096];
    const auto t0 = Clock::now();
    bool sent = false;
    while (Clock::now() - t0 < std::chrono::seconds(30)) {
      if (interrupt && !sent && Clock::now() - t0 > std::chrono::milliseconds(500)) {
        BOOST_REQUIRE(::write(master, "\x03", 1) == 1);
        sent = true;
      }
      pollfd p{master, POLLIN, 0};
      if (::poll(&p, 1, 100) <= 0)
        continue;
      ssize_t n = ::read(master, buf, sizeof(buf));
      if (n <= 0)
        break;   // EIO: the command closed the terminal
      out.append(buf, static_cast<size_t>(n));
    }
    ::close(master);
    reply = ceshd::wait(conn);
    return std::make_pair(out, std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - t0).count());
  };
  std::string reply;
  auto page = onPty({"man", "basics"}, false, reply);
  BOOST_CHECK_EQUAL(reply, "exit 0");
  BOOST_CHECK_MESSAGE(contains(page.first, "\x1b["), page.first);
  auto plain = request(d.sock, {{}, {"man", "basics"}});
  BOOST_CHECK(!contains(plain.out, "\x1b["));

  auto stopped = onPty({"--server", "127.0.0.1:9", "--tries", "16", "ping"}, true, reply);
  BOOST_CHECK_NE(reply, "timeout");
  BOOST_CHECK(contains(reply, "exit ") || contains(reply, "signal "));
  BOOST_CHECK_LT(stopped.second, 8);
}

// The wallet of a request is for that request only.
BOOST_AUTO_TEST_CASE(EachRequestHasItsWallet) {
  KeyPair a, b;
  auto ra = request(d.sock, {wallet(a), {"keys", "list", "--public"}});
  auto rb = request(d.sock, {wallet(b), {"keys", "list", "--public"}});
  auto rn = request(d.sock, {{}, {"keys", "list", "--public"}});
  BOOST_CHECK_EQUAL(ra.reply, "exit 0");
  BOOST_CHECK_EQUAL(rb.reply, "exit 0");
  BOOST_CHECK(contains(ra.out, a.getPublicKeyHexStr()));
  BOOST_CHECK(!contains(ra.out, b.getPublicKeyHexStr()));
  BOOST_CHECK(contains(rb.out, b.getPublicKeyHexStr()));
  BOOST_CHECK(!contains(rb.out, a.getPublicKeyHexStr()));
  BOOST_CHECK(!contains(rn.out, a.getPublicKeyHexStr()));
  BOOST_CHECK(!contains(rn.out, b.getPublicKeyHexStr()));
}

// The jail hides the files of the host: a command cannot read a wallet file
// outside its scratch directory. Without the jail, cesh reads it.
BOOST_AUTO_TEST_CASE(JailHidesHostFiles) {
  KeyPair k;
  fs::path w = tempDir / "wallet.txt";
  {
    std::ofstream f(w);
    f << "00" << k.getPrivateKeyHexStr() << "\n";
  }
  auto plain = runShell("HOME=" + tempDir.string() + " " + ceshBin + " -r " + w.string() +
                        " keys list --public");
  BOOST_CHECK_MESSAGE(contains(plain.out, k.getPublicKeyHexStr()), plain.out);

  auto r = request(d.sock, {{}, {"-r", w.string(), "keys", "list", "--public"}});
  BOOST_CHECK(!contains(r.out, k.getPublicKeyHexStr()));
  BOOST_CHECK_NE(r.reply, "exit 0");
}

// The jail blocks TCP, so --proxy cannot reach a local TCP service.
BOOST_AUTO_TEST_CASE(JailBlocksTcp) {
  int l = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  BOOST_REQUIRE(::bind(l, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0);
  BOOST_REQUIRE(::listen(l, 4) == 0);
  socklen_t len = sizeof(a);
  ::getsockname(l, reinterpret_cast<sockaddr*>(&a), &len);
  std::string port = std::to_string(ntohs(a.sin_port));

  auto r = request(d.sock, {{}, {"--proxy", "127.0.0.1:" + port, "--tries", "1", "ping"}});
  BOOST_CHECK_NE(r.reply, "exit 0");
  int c = ::accept4(l, nullptr, nullptr, SOCK_NONBLOCK);
  BOOST_CHECK_MESSAGE(c < 0, "a TCP connection reached the listener");
  if (c >= 0)
    ::close(c);
  ::close(l);
}

// The jail lets a command start no program. On a terminal, cesh bootstrap
// starts a shell at its end (/bin/sh: the child has no $SHELL), when
// CESH_SERVER is not its server. --solutions 0 skips the mining. In the
// jail the shell does not start, so the line that waits on the terminal
// is not run. Without the jail, the shell runs it and prints X42X.
BOOST_AUTO_TEST_CASE(JailStartsNoProgram) {
  KeyPair k;
  int master = -1, slave = -1;
  winsize ws{30, 100, 0, 0};
  BOOST_REQUIRE(::openpty(&master, &slave, nullptr, nullptr, &ws) == 0);
  std::string e;
  int conn = ceshd::send(d.sock, {wallet(k), {"bootstrap", "--solutions", "0", "--server", server()}},
                         slave, slave, slave, e);
  ::close(slave);
  BOOST_REQUIRE_MESSAGE(conn >= 0, e);
  const std::string line = "echo X$((40+2))X; exit 7\n";
  BOOST_REQUIRE(::write(master, line.data(), line.size()) == static_cast<ssize_t>(line.size()));
  std::string out;
  char buf[4096];
  const auto t0 = Clock::now();
  while (Clock::now() - t0 < std::chrono::seconds(30)) {
    pollfd p{master, POLLIN, 0};
    if (::poll(&p, 1, 100) <= 0)
      continue;
    ssize_t n = ::read(master, buf, sizeof(buf));
    if (n <= 0)
      break;   // EIO: the command closed the terminal
    out.append(buf, static_cast<size_t>(n));
  }
  ::close(master);
  std::string reply = ceshd::wait(conn);
  BOOST_CHECK_MESSAGE(!contains(out, "X42X"), out);
  BOOST_CHECK_MESSAGE(contains(out, "cannot start /bin/sh"), out);
  BOOST_CHECK_EQUAL(reply, "exit 1");
}

// A command that runs past the timeout ends, and the reply says so.
BOOST_AUTO_TEST_CASE(TimeoutStopsACommand) {
  Daemon t = start({"--timeout", "1"}, "t");
  const auto t0 = Clock::now();
  auto r = request(t.sock, {{}, {"--server", "127.0.0.1:9", "--tries", "16", "ping"}});
  auto secs = std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - t0).count();
  BOOST_CHECK_EQUAL(r.reply, "timeout");
  BOOST_CHECK_LT(secs, 10);
  BOOST_CHECK(fs::is_empty(t.scratch));
  stop(t);
}

// A client that leaves stops its command: the output ends, and the scratch
// directory goes.
BOOST_AUTO_TEST_CASE(ClientLeavingStopsTheCommand) {
  int in[2], out[2], err[2];
  BOOST_REQUIRE(::pipe2(in, O_CLOEXEC) == 0 && ::pipe2(out, O_CLOEXEC) == 0 &&
                ::pipe2(err, O_CLOEXEC) == 0);
  ::close(in[1]);
  std::string e;
  int conn = ceshd::send(d.sock, {{}, {"--server", "127.0.0.1:9", "--tries", "16", "ping"}},
                         in[0], out[1], err[1], e);
  BOOST_REQUIRE(conn >= 0);
  ::close(in[0]);
  ::close(out[1]);
  ::close(err[1]);
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  ::close(conn);
  const auto t0 = Clock::now();
  std::string o, er;
  drain(out[0], err[0], o, er, 10);
  BOOST_CHECK_LT(std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - t0).count(), 5);
  const bool gone = waitUntil([&] { return fs::is_empty(d.scratch); });
  BOOST_CHECK(gone);
}

// ceshd refuses a request with no descriptors, or with another wire version.
BOOST_AUTO_TEST_CASE(RefusesBadRequests) {
  std::string good = ceshd::encode({{}, {"man"}});
  BOOST_CHECK_EQUAL(raw(d.sock, good, {}),
                    "error a request needs 3 descriptors: stdin, stdout, stderr");
  int n = ::open("/dev/null", O_RDWR | O_CLOEXEC);
  BOOST_CHECK_EQUAL(raw(d.sock, wire({"ceshd/0", "", "man"}), {n, n, n}),
                    "error not a ceshd/1 request");
  BOOST_CHECK_EQUAL(raw(d.sock, wire({"ceshd/1", "HOME=/", "", "man"}), {n, n, n}),
                    "error the environment can hold only CESH_WALLET, CESH_SERVER and CESH_PROXY");
  ::close(n);
}

// SIGTERM stops ceshd: a running command ends, its client gets a reply, and
// the socket file goes.
BOOST_AUTO_TEST_CASE(StopsOnSigterm) {
  Daemon s = start({}, "s");
  int in[2], out[2], err[2];
  BOOST_REQUIRE(::pipe2(in, O_CLOEXEC) == 0 && ::pipe2(out, O_CLOEXEC) == 0 &&
                ::pipe2(err, O_CLOEXEC) == 0);
  ::close(in[1]);
  std::string e;
  int conn = ceshd::send(s.sock, {{}, {"--server", "127.0.0.1:9", "--tries", "16", "ping"}},
                         in[0], out[1], err[1], e);
  BOOST_REQUIRE(conn >= 0);
  ::close(in[0]);
  ::close(out[1]);
  ::close(err[1]);
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  BOOST_CHECK(stop(s));
  BOOST_CHECK_EQUAL(ceshd::wait(conn), "error ceshd stopped");
  BOOST_CHECK(!fs::exists(s.sock));
  BOOST_CHECK(fs::is_empty(s.scratch));
  ::close(out[0]);
  ::close(err[0]);
}

// Commands run at the same time, each in its own child.
BOOST_AUTO_TEST_CASE(ManyAtOnce) {
  std::vector<std::thread> ts;
  std::atomic<int> ok{0};
  for (int i = 0; i < 8; ++i)
    ts.emplace_back([&] {
      auto r = request(d.sock, {{}, {"man"}});
      if (r.reply == "exit 0" && contains(r.out, "basics"))
        ++ok;
    });
  for (auto& t : ts)
    t.join();
  BOOST_CHECK_EQUAL(ok.load(), 8);
}

BOOST_AUTO_TEST_SUITE_END()

#endif  // CES_CESHD

#endif  // __linux__
