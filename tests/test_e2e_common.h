#pragma once

/**
 * Shared infrastructure for E2E tests that shell out to cesh/ces binaries.
 *
 * Provides:
 *   - RunResult / runShell() — popen wrapper
 *   - findCeshBinary() / findCesBinary() — locate binaries relative to test
 *   - makeUniqueTempDir() — temp directory creation
 *   - assertContains() / assertNotContains() — output matchers
 *   - ceshCmd() / ceshProxyCmd() — env-wrapped command builders
 *   - E2EServerFixture — base class that starts an in-process server,
 *     locates cesh (absolute path), creates a tempDir, and funds a key.
 *     Every cesh invocation via cmd() runs with cwd = tempDir so stray
 *     files (like .scan files) get cleaned up with the tempDir.
 */

#include "test_common.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace ces::e2e {

struct RunResult {
  int exitCode;
  std::string out; // combined stdout+stderr
};

/// Run a shell command via /bin/sh -c. Returns exit code and combined output.
inline RunResult runShell(const std::string& cmd) {
  std::string full = cmd + " 2>&1";
  FILE* fp = popen(full.c_str(), "r");
  if (!fp)
    throw std::runtime_error("popen failed");

  std::string output;
  char buf[4096];
  while (fgets(buf, sizeof(buf), fp))
    output += buf;

  int status = pclose(fp);
  int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  return {code, output};
}

/// Run a command and dump output to stderr if it fails (for debugging).
inline RunResult runExpect(const std::string& cmd, int expectedExit = 0) {
  auto r = runShell(cmd);
  if (r.exitCode != expectedExit) {
    std::cerr << "--- SHELL OUTPUT (exit=" << r.exitCode << ") ---\n"
              << r.out
              << "--- END SHELL OUTPUT ---\n";
  }
  return r;
}

/// Check that output contains a substring.
inline void assertContains(const std::string& output,
                           const std::string& needle,
                           const std::string& context = "") {
  BOOST_CHECK_MESSAGE(output.find(needle) != std::string::npos,
                      "Expected output to contain \"" + needle + "\"" +
                        (context.empty() ? "" : " [" + context + "]") +
                        "\nActual output:\n" + output);
}

/// Check that output does NOT contain a substring.
inline void assertNotContains(const std::string& output,
                              const std::string& needle,
                              const std::string& context = "") {
  BOOST_CHECK_MESSAGE(output.find(needle) == std::string::npos,
                      "Expected output NOT to contain \"" + needle + "\"" +
                        (context.empty() ? "" : " [" + context + "]") +
                        "\nActual output:\n" + output);
}

/// Locate a binary in the build directory, relative to the test binary path.
/// Returns the absolute path (so it survives a cwd change).
inline std::string findBinary(const std::string& name) {
  std::string self =
    boost::unit_test::framework::master_test_suite().argv[0];
  fs::path selfPath(self);
  fs::path buildDir = selfPath.parent_path().parent_path(); // up from tests/
  fs::path candidate = buildDir / name;
  if (!fs::exists(candidate))
    candidate = name;
  boost::system::error_code ec;
  fs::path absPath = fs::absolute(candidate, ec);
  BOOST_REQUIRE_MESSAGE(fs::exists(absPath),
                        name + " binary not found at " + absPath.string());
  return absPath.string();
}

inline std::string findCeshBinary() { return findBinary("cesh"); }
inline std::string findCesBinary()  { return findBinary("ces"); }

/// Build the cesh command prefix with CESH_WALLET + CESH_SERVER env vars.
inline std::string ceshCmd(uint16_t port, const std::string& walletEnv,
                           const std::string& ceshBin,
                           int timeoutSecs = 120,
                           const std::string& logLevel = "fatal") {
  return "CESH_WALLET=\"" + walletEnv + "\" CESH_SERVER=localhost:" +
         std::to_string(port) + " timeout -k 3 " +
         std::to_string(timeoutSecs) + " " + ceshBin + " -l " + logLevel;
}

/// Build the cesh command prefix with CESH_WALLET + CESH_PROXY env vars.
inline std::string ceshProxyCmd(uint16_t proxyPort,
                                const std::string& walletEnv,
                                const std::string& ceshBin,
                                const std::string& logLevel = "fatal") {
  return "CESH_WALLET=\"" + walletEnv + "\" CESH_PROXY=localhost:" +
         std::to_string(proxyPort) + " timeout -k 3 30 " + ceshBin +
         " -l " + logLevel;
}

/// Base fixture: starts an in-process CesServer, creates a tempDir,
/// locates the cesh binary (absolute path), funds a primary key.
///
/// Subclasses can override the temp dir prefix or add extra setup.
/// Every cesh command built via cmd()/cmdW() runs with cwd = tempDir,
/// so stray files (like .scan files) land in the tempdir and get
/// cleaned up by the destructor.
struct E2EServerFixture {
  std::unique_ptr<CesServer> server;
  fs::path tempDir;
  uint16_t serverPort = 0;
  std::string ceshBin;

  KeyPair fundedKey;
  std::string fundedWalletHex;

  KeyPair secondKey;
  std::string secondWalletHex;

  explicit E2EServerFixture(const std::string& tempPrefix = "cesh_e2e") {
    blog::init();
    blog::set_level(blog::fatal);

    tempDir = makeUniqueTempDir(tempPrefix);

    minx::Hash serverPriv;
    serverPriv.fill(0xEE);

    CesConfig cfg =
      makeTestConfig(tempDir, serverPriv, std::numeric_limits<uint64_t>::max());
    server = std::make_unique<CesServer>(cfg);
    serverPort = server->start(0);
    BOOST_REQUIRE_MESSAGE(serverPort > 0, "Server bind failed");

    ceshBin = findCeshBinary();

    fundedWalletHex = "00" + fundedKey.getPrivateKeyHexStr();
    server->_brr(fundedKey.getPublicKeyAsHash(), 10'000'000'000);

    secondWalletHex = "00" + secondKey.getPrivateKeyHexStr();

    wait_net();
  }

  ~E2EServerFixture() {
    if (server)
      server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }

  /// Prepend `cd tempDir && ` to any command so cesh runs with
  /// the temp dir as its cwd.
  std::string inTempDir(const std::string& c) const {
    return "cd " + tempDir.string() + " && " + c;
  }

  /// Shorthand: build a command with the funded wallet, run in tempDir.
  std::string cmd(const std::string& args) const {
    return inTempDir(ceshCmd(serverPort, fundedWalletHex, ceshBin) +
                     " " + args);
  }

  /// Build a command with a specific wallet, run in tempDir.
  std::string cmdW(const std::string& wallet, const std::string& args) const {
    return inTempDir(ceshCmd(serverPort, wallet, ceshBin) + " " + args);
  }

  /// A freshly generated key with cached wallet/pub hex strings.
  /// Useful for tests that need an isolated account.
  struct FreshKey {
    KeyPair kp;
    std::string walletHex;
    std::string pubHex;
    FreshKey() : walletHex("00" + kp.getPrivateKeyHexStr()),
                 pubHex(kp.getPublicKeyHexStr()) {}
  };

  /// Create a fresh key and fund it with the given amount.
  FreshKey makeFunded(int64_t amount = 1'000'000'000) {
    FreshKey fk;
    server->_brr(fk.kp.getPublicKeyAsHash(), amount);
    wait_net();
    return fk;
  }

  /// Create a fresh key with no funding.
  FreshKey makeUnfunded() { return FreshKey(); }

  /// Ensure the server's PoW engine is initialized (for tests that mine).
  void ensurePoWEngine() {
    if (!server->isPoWEngineReady()) {
      server->createPoWEngine(false);
      while (!server->isPoWEngineReady())
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
  }
};

} // namespace ces::e2e
