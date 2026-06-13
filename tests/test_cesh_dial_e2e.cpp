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
#include "test_e2e_common.h"

#include <ces/l2/compute_client.h>
#include <ces/l2/file_client.h>
#include <ces/l2/net_multiplexer.h>
#include <ces/l2/compute_handler.h>
#include <ces/l2/file_handler.h>
#include <ces/l2/compute_lua_handler.h>
#include <ces/server.h>

#include <boost/test/unit_test.hpp>

#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
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
    BOOST_REQUIRE(server->start(0) > 0);
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
      path, source.size(), 0, 100'000'000ULL, "text/x-lua", bal, cost));
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

// dial against a bogus instance id → ATTACH returns INSTANCE_NOT_FOUND
// → cesh exits 2.
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
