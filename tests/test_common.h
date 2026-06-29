#pragma once

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

#include <ces/client.h>
#include <ces/keys.h>
#include <ces/server.h>
#include <ces/types.h>
#include <minx/blog.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <iostream>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace ces;
namespace fs = boost::filesystem;

inline void wait_net() {
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

// CES return codes are uint8_t. BOOST_CHECK_EQUAL(rc, CES_OK) prints
// them as opaque integers that don't explain what went wrong; casting to
// int at every site is boilerplate. These macros are the standard way to
// assert on a CES return code — use them in preference to hand-rolled
// BOOST_CHECK_EQUAL((int)rc, (int)expected) patterns.
#define CES_CHECK_RC_EQ(rc, expected)                                        \
  BOOST_CHECK_EQUAL(static_cast<int>(rc), static_cast<int>(expected))
#define CES_REQUIRE_RC_EQ(rc, expected)                                      \
  BOOST_REQUIRE_EQUAL(static_cast<int>(rc), static_cast<int>(expected))
#define CES_CHECK_OK(rc)     CES_CHECK_RC_EQ((rc), CES_OK)
#define CES_REQUIRE_OK(rc)   CES_REQUIRE_RC_EQ((rc), CES_OK)

// Helper: create a UDP endpoint to the test server on loopback.
inline boost::asio::ip::udp::endpoint testServerEp(uint16_t port) {
  return {boost::asio::ip::address_v6::loopback(), port};
}

// Base of `count` contiguous free UDP ports for a feature needing a fixed RANGE
// (compute_port_base): bind(0) yields one port, not a contiguous block. Scans
// below the Linux ephemeral floor (16384..32768) so the OS won't hand the range
// out, bind-probing each candidate (dual-stack v6, as the server binds) and
// releasing it. A fixed range in the ephemeral band collides under load ->
// instance can't lease its port -> g_program_port=0 -> "networking permanently
// disabled". count==0 -> 0 (the deliberate "no range" config). Mirrors cesdk
// scan_free_region (src/cestest_cli.lua).
inline uint16_t findFreeUdpPortRange(uint16_t count, uint16_t regionLo = 16384,
                                     uint16_t regionHi = 32768) {
  if (count == 0) return 0;
  auto portFree = [](uint16_t port) -> bool {
    int fd = ::socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    int off = 0;
    ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
    sockaddr_in6 a{};
    a.sin6_family = AF_INET6;
    a.sin6_port = htons(port);
    bool ok = ::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0;
    ::close(fd);
    return ok;
  };
  for (uint32_t base = regionLo; base + count <= regionHi;) {
    bool all = true;
    for (uint32_t p = base; p < base + count; ++p) {
      if (!portFree(static_cast<uint16_t>(p))) { all = false; base = p + 1; break; }
    }
    if (all) return static_cast<uint16_t>(base);
  }
  throw std::runtime_error("findFreeUdpPortRange: no free " +
                           std::to_string(count) + "-port range");
}


/// Create a fresh unique temp directory with the given prefix.
/// Caller is responsible for cleanup (use fs::remove_all).
inline fs::path makeUniqueTempDir(const std::string& prefix) {
  auto dir = fs::temp_directory_path() /
             fs::unique_path(prefix + "_%%%%-%%%%");
  fs::create_directories(dir);
  return dir;
}

inline minx::Hash makeHash(const std::string& s) {
  minx::Hash h;
  h.fill(0);
  size_t len = std::min(s.size(), h.size());
  std::memcpy(h.data(), s.data(), len);
  return h;
}

inline CesConfig makeTestConfig(const fs::path& dir, const minx::Hash& key,
                                uint64_t flushVal) {
  CesConfig cfg;
  cfg.dataDir = dir;
  cfg.serverPrivKey = key;
  cfg.minAcc = 100;
  cfg.maxAcc = 100000;
  cfg.minDiff = 1;
  cfg.spendSlotSize = 10;
  cfg.minProveWorkTimestamp = 0;
  cfg.taskThreads = 2;
  cfg.minAsset = 100;
  cfg.maxAsset = 100000;
  cfg.flushValue = flushVal;
  // Pin every fee multiplier to 10000 — tests assert on static fee
  // values; the discount system is exercised in MetricsTests where it
  // matters.
  cfg.feeDiscountEnabled = false;
  // The compiled default peer target is now 5 credits (servers mine reserves on
  // peers by default). Pin tests to 0 so no test starts the RandomX peer miner;
  // tests that exercise mining set peerTarget explicitly.
  cfg.peerTarget = 0;
  return cfg;
}

struct CesFixture {
  std::unique_ptr<CesServer> server;
  std::unique_ptr<CesClient> client;
  fs::path tempDir;
  KeyPair clientKey;
  uint16_t serverPort;

  CesFixture() {
    blog::init();
    blog::set_level(blog::trace);
    blog::set_level("minx", blog::trace);

    tempDir = makeUniqueTempDir("ces_test");

    minx::Hash serverPriv;
    serverPriv.fill(0xEE);

    // Use MAX flush value for memory-only speed in standard tests
    CesConfig cfg =
      makeTestConfig(tempDir, serverPriv, std::numeric_limits<uint64_t>::max());
    server = std::make_unique<CesServer>(cfg);

    serverPort = server->start(0);
    BOOST_REQUIRE_MESSAGE(serverPort > 0, "Server failed to bind to port 0");
    LOGINFO << "TEST: Server started on port " << serverPort;

    boost::asio::ip::udp::endpoint serverEp(
      boost::asio::ip::address_v6::loopback(), serverPort);
    client = std::make_unique<CesClient>(serverEp, false);
    client->start(0);
    client->setKey(clientKey);

    bool connected = client->connect();
    BOOST_REQUIRE_MESSAGE(connected, "Client failed to connect");

    // FUNDING: 10 Billion Credits for main client
    server->_brr(clientKey.getPublicKeyAsHash(), 10'000'000'000);
    server->_drainLogic();
  }

  ~CesFixture() {
    if (client)
      client->stop();
    if (server)
      server->stop();
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }

  HashPrefix getMyId() { return Account::getMapKey(clientKey.getPublicKeyAsHash()); }
};
