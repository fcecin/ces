// ===========================================================================
// `cesh dial` end-to-end — drive the real cesh binary as a subprocess.
// ===========================================================================
//
// In-process server with /ces/file/1, /ces/compute/1, /ces/lua/1 mounted.
// Uploads a one-shot echo Lua program, launches an instance, then forks a
// `cesh dial <instId>` subprocess wired to fresh stdin/stdout/stderr pipes.
// Verifies the byte round-trip and the SIGTERM/error-path exit codes per the
// dial spec (0 / 2 / 143).
//
// We don't try to assert "stdin EOF → drain → 0" here — the existing
// echo program never closes its conn, so half-close cleanly is something
// the program owns. The program-driven close path is exercised in
// test_lua_conn.cpp at the wire level.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"
#include "test_compute_wait.h"
#include "test_e2e_common.h"

#include <ces/l2/compute_client.h>
#include <ces/l2/file_client.h>
#include <ces/cesplex/mux.h>
#include <ces/l2/compute_handler.h>
#include <ces/l2/file_handler.h>
#include <ces/l2/compute_lua_handler.h>
#include <ces/server.h>
#include <ces/cesplex/wire.h>     // computeBindRequestDigest / signPerOp (extsign)
#include <ces/buffer.h>
#include <ces/keys.h>

#include <boost/test/unit_test.hpp>

#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <span>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace ces;
using namespace ces::e2e;

namespace {

struct DialChild {
  pid_t pid = -1;
  int stdinW  = -1;
  int stdoutR = -1;
  int stderrR = -1;

  ~DialChild() {
    if (stdinW  >= 0) ::close(stdinW);
    if (stdoutR >= 0) ::close(stdoutR);
    if (stderrR >= 0) ::close(stderrR);
    if (pid > 0) {
      // Best-effort reap. Tests should waitForExit() before destruction;
      // this is just a safety net.
      ::kill(pid, SIGKILL);
      int s; ::waitpid(pid, &s, 0);
    }
  }
};

// Spawn `cesh dial <instId>` with the given wallet inline-key + rpc port,
// connected to fresh pipes for all three std streams. Returns a DialChild
// owning the pipe fds + child pid. cesh's $CESH_WALLET inherits via
// fork(), so the env-var path of cesh's wallet loader is exercised end-to-
// end.
DialChild spawnCeshDial(const std::string& ceshBin,
                        const std::string& walletInline,
                        uint16_t rpcPort,
                        uint64_t instId,
                        bool verbose) {
  int sin[2]{-1, -1}, sout[2]{-1, -1}, serr[2]{-1, -1};
  BOOST_REQUIRE_EQUAL(::pipe(sin),  0);
  BOOST_REQUIRE_EQUAL(::pipe(sout), 0);
  BOOST_REQUIRE_EQUAL(::pipe(serr), 0);

  pid_t pid = ::fork();
  BOOST_REQUIRE(pid >= 0);

  if (pid == 0) {
    // Child. Wire pipes onto the standard fds.
    ::dup2(sin[0],  STDIN_FILENO);
    ::dup2(sout[1], STDOUT_FILENO);
    ::dup2(serr[1], STDERR_FILENO);
    ::close(sin[0]);  ::close(sin[1]);
    ::close(sout[0]); ::close(sout[1]);
    ::close(serr[0]); ::close(serr[1]);
    ::setenv("CESH_WALLET", walletInline.c_str(), 1);

    std::string portStr = std::to_string(rpcPort);
    std::string idStr   = std::to_string(instId);
    std::vector<const char*> argv;
    argv.push_back("cesh");
    argv.push_back("--server");
    argv.push_back("localhost");
    argv.push_back("--rpc-port");
    argv.push_back(portStr.c_str());
    argv.push_back("-l"); argv.push_back("fatal");
    argv.push_back("dial");
    if (verbose) argv.push_back("-v");
    argv.push_back(idStr.c_str());
    argv.push_back(nullptr);

    ::execvp(ceshBin.c_str(),
             const_cast<char* const*>(argv.data()));
    // execvp only returns on failure.
    ::_exit(127);
  }

  // Parent. Close the child-side ends and return read/write ends.
  ::close(sin[0]);
  ::close(sout[1]);
  ::close(serr[1]);
  DialChild ch;
  ch.pid     = pid;
  ch.stdinW  = sin[1];
  ch.stdoutR = sout[0];
  ch.stderrR = serr[1] = -1; // already closed; keep stderrR
  ch.stderrR = serr[0];
  return ch;
}

// Read `n` bytes from `fd` into `out`, with a hard wall-clock cap. Returns
// number of bytes actually read (may be < n on timeout / EOF).
size_t readUpTo(int fd, void* buf, size_t n,
                std::chrono::milliseconds timeout) {
  auto deadline = std::chrono::steady_clock::now() + timeout;
  size_t got = 0;
  while (got < n) {
    auto remaining = deadline - std::chrono::steady_clock::now();
    if (remaining <= std::chrono::milliseconds(0)) break;
    fd_set rs; FD_ZERO(&rs); FD_SET(fd, &rs);
    timeval tv{};
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(remaining)
                .count();
    tv.tv_sec  = static_cast<long>(us / 1'000'000);
    tv.tv_usec = static_cast<long>(us % 1'000'000);
    int sr = ::select(fd + 1, &rs, nullptr, nullptr, &tv);
    if (sr <= 0) break;
    ssize_t r = ::read(fd, static_cast<uint8_t*>(buf) + got, n - got);
    if (r <= 0) break;
    got += static_cast<size_t>(r);
  }
  return got;
}

bool writeAll(int fd, const void* buf, size_t n) {
  size_t sent = 0;
  while (sent < n) {
    ssize_t w = ::write(fd, static_cast<const uint8_t*>(buf) + sent, n - sent);
    if (w < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    sent += static_cast<size_t>(w);
  }
  return true;
}

std::string toHex(const uint8_t* p, size_t n) {
  static const char* h = "0123456789abcdef";
  std::string s; s.reserve(n * 2);
  for (size_t i = 0; i < n; i++) { s.push_back(h[p[i] >> 4]); s.push_back(h[p[i] & 0xf]); }
  return s;
}

// Read one '\n'-terminated line (newline stripped) from a pipe, byte-by-byte so
// we don't consume past it into the raw byte pipe that follows the handshake.
std::string readLine(int fd, std::chrono::milliseconds timeout) {
  std::string s;
  auto deadline = std::chrono::steady_clock::now() + timeout;
  for (;;) {
    auto rem = deadline - std::chrono::steady_clock::now();
    if (rem <= std::chrono::milliseconds(0)) break;
    char c;
    size_t got = readUpTo(fd, &c, 1,
                          std::chrono::duration_cast<std::chrono::milliseconds>(rem));
    if (got == 0) break;
    if (c == '\n') break;
    if (c != '\r') s.push_back(c);
  }
  return s;
}

// Like spawnCeshDial, but external-signing: no CESH_WALLET; pass --extsign +
// --pubkey. The caller drives the BIND/ATTACH control handshake on the pipes.
DialChild spawnCeshDialExt(const std::string& ceshBin,
                           const std::string& pubkeyHex,
                           uint16_t rpcPort,
                           uint64_t instId,
                           const std::string& serverKeyHex = "") {
  int sin[2]{-1, -1}, sout[2]{-1, -1}, serr[2]{-1, -1};
  BOOST_REQUIRE_EQUAL(::pipe(sin),  0);
  BOOST_REQUIRE_EQUAL(::pipe(sout), 0);
  BOOST_REQUIRE_EQUAL(::pipe(serr), 0);

  pid_t pid = ::fork();
  BOOST_REQUIRE(pid >= 0);
  if (pid == 0) {
    ::dup2(sin[0],  STDIN_FILENO);
    ::dup2(sout[1], STDOUT_FILENO);
    ::dup2(serr[1], STDERR_FILENO);
    ::close(sin[0]);  ::close(sin[1]);
    ::close(sout[0]); ::close(sout[1]);
    ::close(serr[0]); ::close(serr[1]);
    ::unsetenv("CESH_WALLET");   // no key in this process — that's the point

    std::string portStr = std::to_string(rpcPort);
    std::string idStr   = std::to_string(instId);
    std::vector<const char*> argv;
    argv.push_back("cesh");
    argv.push_back("--server");   argv.push_back("localhost");
    argv.push_back("--rpc-port"); argv.push_back(portStr.c_str());
    argv.push_back("-l");         argv.push_back("fatal");
    if (!serverKeyHex.empty()) {
      argv.push_back("--server-key"); argv.push_back(serverKeyHex.c_str());
    }
    argv.push_back("dial");
    argv.push_back("--extsign");
    argv.push_back("--pubkey");   argv.push_back(pubkeyHex.c_str());
    argv.push_back(idStr.c_str());
    argv.push_back(nullptr);
    ::execvp(ceshBin.c_str(), const_cast<char* const*>(argv.data()));
    ::_exit(127);
  }
  ::close(sin[0]); ::close(sout[1]); ::close(serr[1]);
  DialChild ch;
  ch.pid = pid; ch.stdinW = sin[1]; ch.stdoutR = sout[0]; ch.stderrR = serr[0];
  return ch;
}

// waitpid with a deadline. Returns true if reaped, fills `status`.
bool waitForExit(pid_t pid, int& status,
                 std::chrono::milliseconds timeout) {
  auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    pid_t r = ::waitpid(pid, &status, WNOHANG);
    if (r == pid) return true;
    if (r < 0) return false;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  return false;
}

// Same compute+lua fixture used in test_lua_conn.cpp / test_compute_lua.cpp,
// but stripped to the minimum we need: server up with all three handlers
// mounted, an owner key prefunded, helpers to upload + launch a Lua source.
struct DialFixture {
  std::unique_ptr<CesServer> server;
  fs::path tempDir;
  uint16_t rpcPort = 0;
  uint16_t mainPort = 0;
  std::string luajitBin;
  KeyPair ownerKey;

  DialFixture() {
    blog::init();
    blog::set_level(blog::fatal);
    blog::set_level("plex", blog::fatal);

    tempDir = makeUniqueTempDir("cesh_dial_e2e");

    minx::Hash serverPriv;
    serverPriv.fill(0xDD);

    CesConfig cfg = makeTestConfig(
      tempDir, serverPriv, std::numeric_limits<uint64_t>::max());
    // OS-allocated rpc port; read back via _rpcBoundPort() below.
    cfg.rpcPort = 0;
    cfg.rpcAutoPort = true;
    cfg.cesplexMounts = {
      {"/ces/file/1",    "builtin:file"},
      {"/ces/compute/1", "builtin:compute"},
      {"/ces/lua/1",     "builtin:lua"},
    };
    cfg.cesFileStoreMaxBytes = 16ull * 1024 * 1024;
    cfg.feeFileRent = 1;

    cfg.computeMaxInstances = 4;
    cfg.feeComputeSlotSec = 1;
    luajitBin = ces::e2e::findBinary("cesluajitd");
    cfg.cesComputeChildBinary = luajitBin;
    cfg.cesComputeUser = "";
    cfg.cesComputeWorkDir = (tempDir / "cescompute").string();

    server = std::make_unique<CesServer>(cfg);
    mainPort = server->start(0);
    BOOST_REQUIRE(mainPort > 0);
    rpcPort = server->_rpcBoundPort();
    BOOST_REQUIRE(rpcPort > 0);

    server->_brr(ownerKey.getPublicKeyAsHash(), 10'000'000'000);
  }

  ~DialFixture() {
    if (server) server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }

  void uploadScript(const std::string& path,
                    const std::string& source) {
    CesFileClient fc;
    fc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(fc.connect("localhost", rpcPort, ownerKey));
    uint64_t bal = 0, cost = 0;
    CES_REQUIRE_OK(fc.create(
      path, source.size(), 0, 100'000'000ULL, bal, cost));
    ces::Bytes content(source.begin(), source.end());
    CES_REQUIRE_OK(fc.write(path, 0, content, bal));
    fc.disconnect();
  }

  uint64_t launchScript(const std::string& path) {
    CesComputeClient cc;
    cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));
    uint64_t instId = 0, startedAt = 0;
    CES_REQUIRE_OK(cc.launch(path, instId, startedAt));
    cc.disconnect();
    return instId;
  }

  void killScript(uint64_t pid) {
    CesComputeClient cc;
    cc.setServerPubkey(server->_serverKeyPair().getPublicKeyAsHash());
    CES_REQUIRE_OK(cc.connect("localhost", rpcPort, ownerKey));
    CES_REQUIRE_OK(cc.kill(pid));
    cc.disconnect();
  }
};

std::string ownerWalletInline(const KeyPair& k) {
  return "00" + k.getPrivateKeyHexStr();
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(CeshDialE2E, DialFixture)

// Happy path: dial → echo round-trip → SIGTERM → exit 143.
BOOST_AUTO_TEST_CASE(EchoThenSigterm) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string scriptPath = "/h/" + ownerHex + "/echo_dial.lua";
  const std::string src =
    "ces.conn.set_listener({\n"
    "  on_data = function(conn, data) conn:write(data) end,\n"
    "})\n"
    "ces.conn.run()\n";

  uploadScript(scriptPath, src);
  uint64_t instId = launchScript(scriptPath);
  BOOST_REQUIRE(instId > 0);
  // Let the child install set_listener (TAG_LISTEN_ON IPC).
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  std::string ceshBin = ces::e2e::findCeshBinary();
  DialChild ch = spawnCeshDial(
    ceshBin, ownerWalletInline(ownerKey), rpcPort, instId, /*verbose=*/false);

  const std::string msg = "ping\n";
  BOOST_REQUIRE(writeAll(ch.stdinW, msg.data(), msg.size()));

  // Echo should land within a couple seconds on loopback.
  ces::Bytes got(msg.size(), 0);
  size_t n = readUpTo(ch.stdoutR, got.data(), got.size(),
                      std::chrono::seconds(3));
  std::string gotStr(got.begin(), got.begin() + n);
  if (gotStr != msg) {
    std::array<uint8_t, 4096> drain{};
    size_t en = readUpTo(ch.stderrR, drain.data(), drain.size(),
                         std::chrono::milliseconds(200));
    BOOST_TEST_MESSAGE("cesh stderr: "
                       + std::string(drain.begin(),
                                     drain.begin() + en));
  }
  BOOST_CHECK_EQUAL(gotStr, msg);

  // Active tear-down via SIGTERM → exit 143 per spec.
  ::kill(ch.pid, SIGTERM);
  int status = 0;
  BOOST_REQUIRE(waitForExit(ch.pid, status, std::chrono::seconds(5)));
  BOOST_CHECK(WIFEXITED(status));
  BOOST_CHECK_EQUAL(WEXITSTATUS(status), 143);
  ch.pid = -1; // already reaped
}

// Parse the HELLO line of `cesh dial --extsign`: "HELLO <keyHex> <challenge>".
bool parseExtHello(const std::string& line, ServerHello& hello) {
  std::istringstream is(line);
  std::string tag, keyHex, challenge;
  if (!(is >> tag >> keyHex >> challenge) || tag != "HELLO") return false;
  if (keyHex.size() != 64) return false;
  minx::stringToHash(hello.serverPubkey, keyHex);
  hello.challenge = std::stoull(challenge);
  return true;
}

// The BIND line that a tunneler writes for `hello`, signed here. `outDigest`
// gets the digest of this bind, which the ATTACH signs.
std::string extBindLine(const KeyPair& key, const ServerHello& hello,
                        BindDigest& outDigest) {
  const std::string name = "/ces/lua/1";
  const uint64_t t = ces::getMicrosSinceEpoch();
  const auto& pk = key.getPublicKeyAsHash();
  auto digest = computeBindRequestDigest(
    std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(name.data()), name.size()),
    t, std::span<const uint8_t>(pk.data(), pk.size()), hello);
  outDigest = digest;
  Signature sig = key.signData(std::span<const uint8_t>(digest.data(), digest.size()));
  return "BIND " + std::to_string(t) + " " + toHex(sig.data(), sig.size()) + "\n";
}

// The ATTACH line for `pid`, signed over the bind digest `bindDigest`.
std::string extAttachLine(const KeyPair& key, uint64_t pid,
                          const BindDigest& bindDigest) {
  ces::Bytes preamble;
  ces::Buffer::put<uint64_t>(preamble, pid);
  Signature sig = signPerOp(key, 0x01,
    std::span<const uint8_t>(preamble.data(), preamble.size()), bindDigest);
  return "ATTACH " + toHex(sig.data(), sig.size()) + "\n";
}

// An echo program for the extsign tests, with a greeting. Returns its pid.
constexpr const char* kExtGreeting = "EXT GREETING\n";
uint64_t launchEchoExt(DialFixture& fx, const std::string& ownerHex) {
  const std::string scriptPath = "/h/" + ownerHex + "/echo_ext.lua";
  const std::string src =
    "ces.conn.set_listener({\n"
    "  hello = 'EXT GREETING\\n',\n"
    "  on_data = function(conn, data) conn:write(data) end,\n"
    "})\n"
    "ces.conn.run()\n";
  fx.uploadScript(scriptPath, src);
  uint64_t instId = fx.launchScript(scriptPath);
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  return instId;
}

// External-signing dial: the bind + ATTACH signatures are produced HERE (no key
// in cesh) and fed over the stdio control handshake; the server cryptographically
// verifies them. Exercises `cesh dial --extsign` / bindExt / attachExt /
// buildBindRequestSigned end to end — the path cesweb uses so the key never
// reaches the tunnel.
BOOST_AUTO_TEST_CASE(ExtSignEchoRoundtrip) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  uint64_t instId = launchEchoExt(*this, ownerHex);
  BOOST_REQUIRE(instId > 0);

  std::string ceshBin = ces::e2e::findCeshBinary();
  DialChild ch = spawnCeshDialExt(ceshBin, ownerHex, rpcPort, instId);

  // cesh reads the server hello and hands it over first.
  std::string helloLine = readLine(ch.stdoutR, std::chrono::seconds(5));
  ServerHello hello;
  BOOST_REQUIRE_MESSAGE(parseExtHello(helloLine, hello),
                        "expected HELLO, got: " + helloLine);
  BOOST_CHECK(hello.serverPubkey == server->_serverKeyPair().getPublicKeyAsHash());

  // Both signatures need only the hello, so both lines go at once.
  BindDigest d{};
  std::string lines = extBindLine(ownerKey, hello, d);
  lines += extAttachLine(ownerKey, instId, d);
  BOOST_REQUIRE(writeAll(ch.stdinW, lines.data(), lines.size()));

  std::string readyLine = readLine(ch.stdoutR, std::chrono::seconds(5));
  BOOST_REQUIRE_EQUAL(readyLine, "READY");

  // The greeting rode the ATTACH reply: it is the first bytes after READY.
  const std::string greeting = kExtGreeting;
  ces::Bytes first(greeting.size(), 0);
  size_t g = readUpTo(ch.stdoutR, first.data(), first.size(), std::chrono::seconds(3));
  BOOST_CHECK_EQUAL(std::string(first.begin(), first.begin() + g), greeting);

  // Raw byte pipe now — echo round-trip.
  const std::string msg = "ping\n";
  BOOST_REQUIRE(writeAll(ch.stdinW, msg.data(), msg.size()));
  ces::Bytes got(msg.size(), 0);
  size_t n = readUpTo(ch.stdoutR, got.data(), got.size(), std::chrono::seconds(3));
  BOOST_CHECK_EQUAL(std::string(got.begin(), got.begin() + n), msg);

  ::kill(ch.pid, SIGTERM);
  int status = 0;
  BOOST_REQUIRE(waitForExit(ch.pid, status, std::chrono::seconds(5)));
  BOOST_CHECK(WIFEXITED(status));
  BOOST_CHECK_EQUAL(WEXITSTATUS(status), 143);
  ch.pid = -1;
}

// A bind signed for another challenge fails: `ERR bind:` and exit 4.
BOOST_AUTO_TEST_CASE(ExtSignBindForOtherChallengeFails) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  uint64_t instId = launchEchoExt(*this, ownerHex);
  BOOST_REQUIRE(instId > 0);

  DialChild ch = spawnCeshDialExt(ces::e2e::findCeshBinary(), ownerHex, rpcPort, instId);
  std::string helloLine = readLine(ch.stdoutR, std::chrono::seconds(5));
  ServerHello hello;
  BOOST_REQUIRE_MESSAGE(parseExtHello(helloLine, hello),
                        "expected HELLO, got: " + helloLine);
  ServerHello other = hello;
  other.challenge += 1;
  BindDigest d{};
  std::string lines = extBindLine(ownerKey, other, d);
  lines += extAttachLine(ownerKey, instId, d);
  BOOST_REQUIRE(writeAll(ch.stdinW, lines.data(), lines.size()));

  std::string errLine = readLine(ch.stdoutR, std::chrono::seconds(5));
  BOOST_CHECK_MESSAGE(errLine.rfind("ERR bind:", 0) == 0, "got: " + errLine);
  int status = 0;
  BOOST_REQUIRE(waitForExit(ch.pid, status, std::chrono::seconds(5)));
  BOOST_CHECK(WIFEXITED(status));
  BOOST_CHECK_EQUAL(WEXITSTATUS(status), 4);
  ch.pid = -1;
}

// A --server-key of another server: `ERR connect:`, exit 4, and no HELLO line,
// so the tunneler signs nothing.
BOOST_AUTO_TEST_CASE(ExtSignWrongServerKeyFails) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  uint64_t instId = launchEchoExt(*this, ownerHex);
  BOOST_REQUIRE(instId > 0);

  const std::string otherKey = KeyPair().getPublicKeyHexStr();
  DialChild ch = spawnCeshDialExt(ces::e2e::findCeshBinary(), ownerHex, rpcPort,
                                  instId, otherKey);
  std::string line = readLine(ch.stdoutR, std::chrono::seconds(5));
  BOOST_CHECK_MESSAGE(line.rfind("ERR connect:", 0) == 0, "got: " + line);
  int status = 0;
  BOOST_REQUIRE(waitForExit(ch.pid, status, std::chrono::seconds(5)));
  BOOST_CHECK(WIFEXITED(status));
  BOOST_CHECK_EQUAL(WEXITSTATUS(status), 4);
  ch.pid = -1;
}

// dial against a bogus instance id → ATTACH returns INSTANCE_NOT_FOUND
// → cesh exits 2.
// `dial <pid> --line <text>`: one line out, one line back, then the end. No
// stdin stream, and a time limit: a program that does not answer fails the
// dial after --timeout instead of a wait with no end.
BOOST_AUTO_TEST_CASE(LineMode_OneExchange) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  const std::string echo = "/h/" + ownerHex + "/echo_line.lua";
  uploadScript(echo,
    "ces.conn.set_listener({\n"
    "  on_data = function(conn, data) conn:write(data) end,\n"
    "})\n"
    "ces.conn.run()\n");
  uint64_t pid = launchScript(echo);
  BOOST_REQUIRE(pid > 0);
  BOOST_REQUIRE(ces::waitInstanceListening(*server, pid));
  const std::string cesh = "CESH_WALLET=" + ownerWalletInline(ownerKey) + " timeout -k 3 60 " +
                           ces::e2e::findCeshBinary() + " -l fatal --server localhost --rpc-port " +
                           std::to_string(rpcPort) + " dial ";
  auto r = ces::e2e::runShell(cesh + std::to_string(pid) + " --line ping < /dev/null", 60);
  BOOST_CHECK_EQUAL(r.exitCode, 0);
  BOOST_CHECK_EQUAL(r.out, "ping\n");
  // With no --rpc-port, dial takes the port that the server announces.
  auto a = ces::e2e::runShell("CESH_WALLET=" + ownerWalletInline(ownerKey) + " timeout -k 3 60 " +
                              ces::e2e::findCeshBinary() + " -l fatal --server localhost:" +
                              std::to_string(mainPort) + " dial " + std::to_string(pid) +
                              " --line pong < /dev/null", 60);
  BOOST_CHECK_EQUAL(a.exitCode, 0);
  BOOST_CHECK_EQUAL(a.out, "pong\n");

  const std::string mute = "/h/" + ownerHex + "/mute_line.lua";
  uploadScript(mute,
    "ces.conn.set_listener({ on_data = function(conn, data) end })\n"
    "ces.conn.run()\n");
  uint64_t mpid = launchScript(mute);
  BOOST_REQUIRE(mpid > 0);
  BOOST_REQUIRE(ces::waitInstanceListening(*server, mpid));
  r = ces::e2e::runShell(cesh + std::to_string(mpid) + " --line ping --timeout 500 < /dev/null", 60);
  BOOST_CHECK_EQUAL(r.exitCode, 1);
  BOOST_CHECK_MESSAGE(r.out.find("Dial failed") != std::string::npos, r.out);
}

BOOST_AUTO_TEST_CASE(AHandlerKeepsAProgram) {
  const std::string ownerHex = ownerKey.getPublicKeyHexStr();
  auto launch = [&](const std::string& name, const std::string& src) {
    const std::string path = "/h/" + ownerHex + "/" + name;
    uploadScript(path, src);
    uint64_t pid = launchScript(path);
    BOOST_REQUIRE(pid > 0);
    return pid;
  };
  auto dial = [&](uint64_t pid, const std::string& in) {
    return ces::e2e::runShell("printf '" + in + "' | CESH_WALLET=" + ownerWalletInline(ownerKey) +
                              " timeout -k 1 4 " + ces::e2e::findCeshBinary() +
                              " -l fatal --server localhost --rpc-port " + std::to_string(rpcPort) +
                              " dial " + std::to_string(pid), 30).out;
  };
  auto has = [](const std::string& out, const std::string& what) {
    BOOST_CHECK_MESSAGE(out.find(what) != std::string::npos, "no [" << what << "] in [" << out << "]");
  };

  // With no handler, a compile error or a main chunk error ends the program.
  BOOST_CHECK(ces::waitInstanceGone(*server, launch("bad.lua", "local x = 1 // 2\n")));
  BOOST_CHECK(ces::waitInstanceGone(*server, launch("fails.lua", "local t = nil\nt.x = 1\n")));

  // A handler gets a main chunk error, and the loop runs.
  uint64_t pid = launch("caught.lua",
                        "ces.on_error(function(e) ces.conn.set_listener({ hello = 'caught: ' .. e .. '\\n' }) end)\n"
                        "error('boom')\n");
  BOOST_REQUIRE(ces::waitInstanceListening(*server, pid));
  has(dial(pid, ""), "caught: program:2: boom");
  killScript(pid);

  // With no handler, a task error ends the program.
  pid = launch("plain.lua",
               "ces.conn.set_listener({ on_data = function(c, d) error('bad ' .. d) end })\n"
               "ces.run()\n");
  BOOST_REQUIRE(ces::waitInstanceListening(*server, pid));
  dial(pid, "x");
  BOOST_CHECK(ces::waitInstanceGone(*server, pid));

  // A handler gets a task error, and the program goes on.
  pid = launch("task.lua",
    "local conns = {}\n"
    "ces.on_error(function(e) for _, c in pairs(conns) do c:write('caught: ' .. e .. '\\n') end end)\n"
    "ces.conn.set_listener({\n"
    "  on_open = function(c) conns[c.id] = c end,\n"
    "  on_close = function(c) conns[c.id] = nil end,\n"
    "  on_data = function(c, d) if d:find('x') then error('bad ' .. d) end c:write('ok ' .. d .. '\\n') end,\n"
    "})\n"
    "ces.run()\n");
  BOOST_REQUIRE(ces::waitInstanceListening(*server, pid));
  has(dial(pid, "x"), "caught: program:6: bad x");
  has(dial(pid, "y"), "ok y");
  killScript(pid);

  // Out of memory ends the program, also with a handler.
  BOOST_CHECK(ces::waitInstanceGone(*server, launch("bomb.lua",
    "ces.on_error(function(e) ces.conn.set_listener({ hello = 'kept' }) end)\n"
    "_G.big = string.rep('X', 1024 * 1024 * 1024)\n")));
  pid = launch("taskbomb.lua",
    "ces.on_error(function(e) end)\n"
    "ces.conn.set_listener({ on_data = function(c, d) _G.big = string.rep('X', 1024 * 1024 * 1024) end })\n"
    "ces.run()\n");
  BOOST_REQUIRE(ces::waitInstanceListening(*server, pid));
  dial(pid, "x");
  BOOST_CHECK(ces::waitInstanceGone(*server, pid));

  // An error in the handler ends the program after one run of the handler.
  pid = launch("again.lua",
    "local conns = {}\n"
    "ces.on_error(function(e) for _, c in pairs(conns) do c:write('h\\n') end error('again') end)\n"
    "ces.conn.set_listener({\n"
    "  on_open = function(c) conns[c.id] = c end,\n"
    "  on_data = function(c, d) error('bad') end,\n"
    "})\n"
    "ces.run()\n");
  BOOST_REQUIRE(ces::waitInstanceListening(*server, pid));
  std::string out = dial(pid, "x");
  size_t runs = 0;
  for (size_t at = out.find("h\n"); at != std::string::npos; at = out.find("h\n", at + 2)) runs++;
  BOOST_CHECK_MESSAGE(runs == 1, "the handler ran " << runs << " times");
  BOOST_CHECK(ces::waitInstanceGone(*server, pid));
}

// On a terminal, a plain dial sends a line at Enter, and --raw sends each key
// at once, with no echo and Enter as "\r". The terminal comes back as it was.
BOOST_AUTO_TEST_CASE(RawSendsEachKeyAtOnce) {
  const std::string path = "/h/" + ownerKey.getPublicKeyHexStr() + "/keys.lua";
  uploadScript(path, "ces.conn.set_listener({ hello = 'ready\\n',\n"
                     "  on_data = function(c, d) c:write('got [' .. d .. ']\\n') end })\nces.run()\n");
  uint64_t pid = launchScript(path);
  BOOST_REQUIRE(ces::waitInstanceListening(*server, pid));
  const std::string cesh = ces::e2e::findCeshBinary();
  const std::string wallet = ownerWalletInline(ownerKey);
  const std::string port = std::to_string(rpcPort), id = std::to_string(pid);

  struct Dial { pid_t pid; int master; int slave; };
  auto dial = [&](bool raw) {
    int master = -1, slave = -1;
    BOOST_REQUIRE_EQUAL(::openpty(&master, &slave, nullptr, nullptr, nullptr), 0);
    pid_t child = ::fork();
    BOOST_REQUIRE(child >= 0);
    if (child == 0) {
      ::setsid();
      ::ioctl(slave, TIOCSCTTY, 0);
      ::dup2(slave, 0); ::dup2(slave, 1); ::dup2(slave, 2);
      ::close(master);
      if (slave > 2) ::close(slave);
      ::setenv("CESH_WALLET", wallet.c_str(), 1);
      std::vector<const char*> argv{"cesh", "-l", "fatal", "--server", "localhost", "--rpc-port",
                                    port.c_str(), "dial", id.c_str()};
      if (raw) argv.push_back("--raw");
      argv.push_back(nullptr);
      ::execv(cesh.c_str(), const_cast<char* const*>(argv.data()));
      ::_exit(127);
    }
    return Dial{child, master, slave};
  };
  // What the terminal shows within `ms`, up to `want`.
  auto read = [](int fd, const std::string& want, int ms) {
    std::string got;
    auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    while (got.find(want) == std::string::npos && std::chrono::steady_clock::now() < end) {
      pollfd p{fd, POLLIN, 0};
      if (::poll(&p, 1, 50) > 0) {
        char buf[256];
        ssize_t n = ::read(fd, buf, sizeof buf);
        if (n > 0) got.append(buf, static_cast<size_t>(n));
      }
    }
    return got;
  };
  auto lflag = [](int fd) { termios t{}; ::tcgetattr(fd, &t); return t.c_lflag; };
  auto end = [](Dial& d) {
    BOOST_REQUIRE_EQUAL(::write(d.master, "\x03", 1), 1);     // Ctrl+C
    int st = 0;
    ::waitpid(d.pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
  };

  Dial raw = dial(true);
  BOOST_REQUIRE(read(raw.master, "ready\r\n", 10000).find("ready\r\n") != std::string::npos);
  waitUntil([&] { return !(lflag(raw.slave) & ICANON); });
  BOOST_CHECK_EQUAL(lflag(raw.slave) & (ICANON | ECHO), 0u);
  BOOST_REQUIRE_EQUAL(::write(raw.master, "q", 1), 1);
  BOOST_CHECK_EQUAL(read(raw.master, "]\r\n", 3000), "got [q]\r\n");     // at once, with no echo
  BOOST_REQUIRE_EQUAL(::write(raw.master, "\r", 1), 1);
  BOOST_CHECK_EQUAL(read(raw.master, "]\r\n", 3000), "got [\r]\r\n");
  BOOST_CHECK_EQUAL(end(raw), 130);
  BOOST_CHECK_EQUAL(lflag(raw.slave) & (ICANON | ECHO), static_cast<tcflag_t>(ICANON | ECHO));
  ::close(raw.master);
  ::close(raw.slave);

  Dial line = dial(false);
  BOOST_REQUIRE(read(line.master, "ready\r\n", 10000).find("ready\r\n") != std::string::npos);
  BOOST_REQUIRE_EQUAL(::write(line.master, "q", 1), 1);
  BOOST_CHECK_EQUAL(read(line.master, "got", 1000), "q");          // the echo only
  BOOST_REQUIRE_EQUAL(::write(line.master, "\r", 1), 1);
  BOOST_CHECK(read(line.master, "]\r\n", 3000).find("got [q\r\n]") != std::string::npos);  // the line, at Enter
  BOOST_CHECK_EQUAL(end(line), 130);
  ::close(line.master);
  ::close(line.slave);
  killScript(pid);
}

BOOST_AUTO_TEST_CASE(UnknownInstanceExits2) {
  std::string ceshBin = ces::e2e::findCeshBinary();
  DialChild ch = spawnCeshDial(
    ceshBin, ownerWalletInline(ownerKey), rpcPort,
    /*bogus*/ 99999ULL, /*verbose=*/false);

  // Drain stderr so the pipe doesn't fill — we don't assert content.
  std::array<uint8_t, 4096> drain{};
  size_t en = readUpTo(ch.stderrR, drain.data(), drain.size(),
                       std::chrono::seconds(3));

  int status = 0;
  BOOST_REQUIRE(waitForExit(ch.pid, status, std::chrono::seconds(5)));
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 2) {
    BOOST_TEST_MESSAGE("cesh stderr: "
                       + std::string(drain.begin(),
                                     drain.begin() + en));
  }
  BOOST_CHECK(WIFEXITED(status));
  BOOST_CHECK_EQUAL(WEXITSTATUS(status), 2);
  ch.pid = -1;
}

BOOST_AUTO_TEST_SUITE_END()
