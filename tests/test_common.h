#pragma once

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

#include <ces/client.h>
#include <ces/keys.h>
#include <ces/server.h>
#include <ces/types.h>
#include <minx/blog.h>

#include <chrono>
#include <cstring>
#include <iostream>
#include <memory>
#include <set>
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
    wait_net();
  }

  ~CesFixture() {
    if (client)
      client->stop();
    if (server)
      server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }

  HashPrefix getMyId() { return Account::getMapKey(clientKey.getPublicKeyAsHash()); }
};
