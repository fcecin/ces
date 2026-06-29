/**
 * E2E tests for cesproxy — CES-aware TCP-to-UDP MINX proxy.
 *
 * Starts a CES server + CesProxy in-process, then connects TCP clients
 * and verifies that valid CES messages are forwarded and invalid ones
 * are dropped.
 */

#include "test_common.h"

#include <ces/cesproxy.h>
#include <ces/buffer.h>

#include <boost/asio.hpp>
#include <boost/endian/conversion.hpp>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

// =============================================================================
// TCP test client — speaks length-prefixed MINX over TCP
// =============================================================================

class TcpTestClient {
public:
  TcpTestClient(asio::io_context& io) : sock_(io) {}

  void connect(uint16_t port) {
    sock_.connect(
      tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), port));
  }

  void sendRaw(const uint8_t* data, size_t len) {
    uint8_t header[2];
    ces::Buffer::poke<uint16_t>(header, static_cast<uint16_t>(len));
    asio::write(sock_, asio::buffer(header, 2));
    asio::write(sock_, asio::buffer(data, len));
  }

  void sendGetInfo(uint64_t gpassword) {
    ces::Bytes buf;
    buf.push_back(minx::MINX_GET_INFO);
    buf.push_back(0); // version
    ces::Buffer::put<uint64_t>(buf, gpassword);
    sendRaw(buf.data(), buf.size());
  }

  void sendMessage(uint64_t gpassword, uint64_t spassword,
                   const ces::Bytes& payload) {
    ces::Bytes buf;
    buf.push_back(minx::MINX_MESSAGE);
    buf.push_back(0); // version
    ces::Buffer::put<uint64_t>(buf, gpassword);
    ces::Buffer::put<uint64_t>(buf, spassword);
    buf.insert(buf.end(), payload.begin(), payload.end());
    sendRaw(buf.data(), buf.size());
  }

  ces::Bytes recvMsg(int timeoutMs = 5000) {
    // Set a timeout via socket option
    struct timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    setsockopt(sock_.native_handle(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t header[2];
    boost::system::error_code ec;
    asio::read(sock_, asio::buffer(header, 2), ec);
    if (ec)
      return {};
    uint16_t len = ces::Buffer::peek<uint16_t>(header);
    ces::Bytes buf(len);
    asio::read(sock_, asio::buffer(buf), ec);
    if (ec)
      return {};
    return buf;
  }

  bool hasData() { return sock_.available() > 0; }

  void close() {
    boost::system::error_code ec;
    sock_.shutdown(tcp::socket::shutdown_both, ec);
    sock_.close(ec);
  }

  bool isOpen() const { return sock_.is_open(); }

private:
  tcp::socket sock_;
};

// =============================================================================
// Parse an INFO response from raw bytes
// =============================================================================

struct ParsedInfo {
  uint8_t version = 0;
  uint64_t gpassword = 0; // ticket from proxy
  uint64_t spassword = 0;
  minx::Hash skey{};
  uint8_t difficulty = 0;
};

static ParsedInfo parseInfo(const ces::Bytes& raw) {
  BOOST_REQUIRE(raw.size() >= 1 + 1 + 8 + 8 + 32 + 1);
  BOOST_REQUIRE_EQUAL(raw[0], minx::MINX_INFO);
  ParsedInfo info;
  size_t off = 1;
  info.version = raw[off++];
  info.gpassword = ces::Buffer::peek<uint64_t>(&raw[off]); off += 8;
  info.spassword = ces::Buffer::peek<uint64_t>(&raw[off]); off += 8;
  std::memcpy(info.skey.data(), &raw[off], 32);
  off += 32;
  info.difficulty = raw[off];
  return info;
}

// =============================================================================
// Fixture: CES server + CesProxy
// =============================================================================

struct ProxyFixture {
  std::unique_ptr<CesServer> server;
  std::unique_ptr<CesProxy> proxy;
  fs::path tempDir;
  uint16_t serverPort = 0;
  uint16_t proxyPort = 0;

  // Funded key for signed operations
  KeyPair fundedKey;

  ProxyFixture() {
    blog::init();
    blog::set_level(blog::fatal);

    tempDir = makeUniqueTempDir("cesproxy_test");

    // Start CES server
    minx::Hash serverPriv;
    serverPriv.fill(0xEE);
    CesConfig cfg =
      makeTestConfig(tempDir, serverPriv, std::numeric_limits<uint64_t>::max());
    server = std::make_unique<CesServer>(cfg);
    serverPort = server->start(0);
    BOOST_REQUIRE(serverPort > 0);

    // Fund the test key
    server->_brr(fundedKey.getPublicKeyAsHash(), 10'000'000'000LL);
    server->_drainLogic();

    // Start CesProxy (owns its own io_context and thread)
    tcp::endpoint listenEp(asio::ip::address::from_string("127.0.0.1"), 0);
    boost::asio::ip::udp::endpoint upstreamEp(
      boost::asio::ip::address_v6::loopback(), serverPort);

    minx::MinxProxyConfig proxyCfg;
    proxyCfg.numChannels = 4;
    proxyCfg.channelTimeout = std::chrono::seconds(5);
    proxyCfg.sweepInterval = std::chrono::seconds(1);

    proxy = std::make_unique<CesProxy>(listenEp, upstreamEp, proxyCfg);
    proxyPort = proxy->port();
    BOOST_REQUIRE(proxyPort > 0);

    // Wait for proxy to handshake with upstream
    for (int i = 0; i < 50; ++i) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      if (proxy->hasCachedInfo() && proxy->readyChannelCount() > 0)
        break;
    }
    BOOST_REQUIRE_MESSAGE(proxy->hasCachedInfo(),
                          "Proxy failed to get INFO from server");
    BOOST_REQUIRE_MESSAGE(proxy->readyChannelCount() > 0,
                          "Proxy has no ready channels");
  }

  ~ProxyFixture() {
    if (proxy)
      proxy->stop();
    proxy.reset();
    if (server)
      server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    boost::system::error_code ec;
    fs::remove_all(tempDir, ec);
  }
};

// =============================================================================
// Tests
// =============================================================================

BOOST_FIXTURE_TEST_SUITE(CesProxyTests, ProxyFixture)

// ---------------------------------------------------------------------------
// Test 1: GET_INFO through proxy returns valid INFO
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(GetInfoThroughProxy) {
  asio::io_context io;
  TcpTestClient client(io);
  client.connect(proxyPort);

  client.sendGetInfo(0x1234);

  auto raw = client.recvMsg();
  BOOST_REQUIRE(!raw.empty());
  BOOST_CHECK_EQUAL(raw[0], minx::MINX_INFO);

  auto info = parseInfo(raw);
  BOOST_CHECK(info.gpassword != 0); // proxy gives us a ticket
  BOOST_CHECK(info.difficulty > 0);

  client.close();
}

// ---------------------------------------------------------------------------
// Test 2: Unsigned server info query through proxy
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(UnsignedServerInfoThroughProxy) {
  asio::io_context io;
  TcpTestClient client(io);
  client.connect(proxyPort);

  // Get INFO first to obtain ticket
  client.sendGetInfo(0xAAAA);
  auto infoRaw = client.recvMsg();
  BOOST_REQUIRE(!infoRaw.empty());
  auto info = parseInfo(infoRaw);
  BOOST_REQUIRE(info.gpassword != 0);

  // Build CES_UNSIGNED_QUERY_ACCOUNT payload
  ces::HashPrefix mapKey = ces::Account::getMapKey(fundedKey.getPublicKeyAsHash());
  ces::Bytes cesPayload;
  cesPayload.push_back(ces::CES_UNSIGNED_QUERY_ACCOUNT);
  cesPayload.insert(cesPayload.end(),
    reinterpret_cast<const uint8_t*>(&mapKey),
    reinterpret_cast<const uint8_t*>(&mapKey) + sizeof(mapKey));

  // Send as MINX_MESSAGE: gpassword=fresh, spassword=our ticket
  client.sendMessage(0xBBBB, info.gpassword, cesPayload);

  auto resp = client.recvMsg();
  BOOST_REQUIRE(!resp.empty());
  BOOST_CHECK_EQUAL(resp[0], minx::MINX_MESSAGE);

  // Parse MINX_MESSAGE envelope: type(1) + version(1) + gpassword(8) +
  // spassword(8) + data
  BOOST_REQUIRE(resp.size() >= 18);
  // CES response starts at offset 18
  size_t cesOff = 18;
  BOOST_REQUIRE(resp.size() > cesOff);
  uint8_t respOpCode = resp[cesOff];
  BOOST_CHECK_EQUAL(respOpCode, ces::CES_UNSIGNED_QUERY_ACCOUNT_RESULT);

  // Response should contain account data after opcode
  BOOST_REQUIRE(resp.size() > cesOff + 1);

  client.close();
}

// ---------------------------------------------------------------------------
// Test 3: Signed transfer through proxy
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(SignedTransferThroughProxy) {
  asio::io_context io;
  TcpTestClient client(io);
  client.connect(proxyPort);

  // Get INFO / ticket
  client.sendGetInfo(0xCCCC);
  auto infoRaw = client.recvMsg();
  BOOST_REQUIRE(!infoRaw.empty());
  auto info = parseInfo(infoRaw);

  // Build a signed CES_TRANSFER message
  ces::KeyPair destKey;
  ces::CesTransfer req;
  req.originId = fundedKey.getPublicKeyAsHash();
  req.serverId = ces::Account::getMapKey(info.skey);
  req.reqNonce = 0;
  req.destKey = destKey.getPublicKeyAsHash();
  req.amount = 1000;
  auto cesBytes = req.toBytes(fundedKey);

  ces::Bytes payload(cesBytes.begin(), cesBytes.end());
  client.sendMessage(0xDDDD, info.gpassword, payload);

  auto resp = client.recvMsg();
  BOOST_REQUIRE(!resp.empty());
  BOOST_CHECK_EQUAL(resp[0], minx::MINX_MESSAGE);

  // Parse CES response
  BOOST_REQUIRE(resp.size() > 18);
  uint8_t respOpCode = resp[18];
  BOOST_CHECK_EQUAL(respOpCode, ces::CES_TRANSFER_RESULT);

  client.close();
}

// ---------------------------------------------------------------------------
// Test 4: Bad signature gets dropped (no response)
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(BadSignatureDropped) {
  asio::io_context io;
  TcpTestClient client(io);
  client.connect(proxyPort);

  // Get ticket
  client.sendGetInfo(0xEEEE);
  auto infoRaw = client.recvMsg();
  BOOST_REQUIRE(!infoRaw.empty());
  auto info = parseInfo(infoRaw);

  // Build a CES_TRANSFER but sign with wrong key
  ces::KeyPair wrongKey;
  ces::CesTransfer req;
  req.originId = fundedKey.getPublicKeyAsHash(); // claim to be fundedKey
  req.serverId = ces::Account::getMapKey(info.skey);
  req.reqNonce = 0;
  req.destKey = wrongKey.getPublicKeyAsHash();
  req.amount = 1000;
  auto cesBytes = req.toBytes(wrongKey); // signed with WRONG key

  ces::Bytes payload(cesBytes.begin(), cesBytes.end());
  client.sendMessage(0xFFFF, info.gpassword, payload);

  // The proxy should drop this and close the connection
  auto resp = client.recvMsg(2000);
  // Either empty (timeout/closed) or connection was closed
  BOOST_CHECK(resp.empty() || !client.isOpen());

  client.close();
}

// ---------------------------------------------------------------------------
// Test 5: Unknown opcode gets dropped
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(UnknownOpcodeDropped) {
  asio::io_context io;
  TcpTestClient client(io);
  client.connect(proxyPort);

  // Get ticket
  client.sendGetInfo(0x1111);
  auto infoRaw = client.recvMsg();
  BOOST_REQUIRE(!infoRaw.empty());
  auto info = parseInfo(infoRaw);

  // Send garbage CES opcode 0xFF
  ces::Bytes payload;
  payload.push_back(0xFF);
  payload.resize(64, 0x42); // pad with garbage

  client.sendMessage(0x2222, info.gpassword, payload);

  auto resp = client.recvMsg(2000);
  BOOST_CHECK(resp.empty() || !client.isOpen());

  client.close();
}

// ---------------------------------------------------------------------------
// Test 6: Multiple clients can query concurrently
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(MultipleClientsConcurrent) {
  constexpr int NUM_CLIENTS = 4;
  asio::io_context io;
  std::vector<std::unique_ptr<TcpTestClient>> clients;

  // Connect all clients and request INFO
  for (int i = 0; i < NUM_CLIENTS; ++i) {
    auto c = std::make_unique<TcpTestClient>(io);
    c->connect(proxyPort);
    c->sendGetInfo(0x5000 + i);
    clients.push_back(std::move(c));
  }

  // All should get valid INFO responses
  for (int i = 0; i < NUM_CLIENTS; ++i) {
    auto raw = clients[i]->recvMsg();
    BOOST_REQUIRE_MESSAGE(!raw.empty(),
                          "Client " << i << " got no INFO response");
    BOOST_CHECK_EQUAL(raw[0], minx::MINX_INFO);
    auto info = parseInfo(raw);
    BOOST_CHECK(info.gpassword != 0);
  }

  for (auto& c : clients)
    c->close();
}

// ---------------------------------------------------------------------------
// Test 7: Unsigned account query through proxy
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(UnsignedAccountQueryThroughProxy) {
  asio::io_context io;
  TcpTestClient client(io);
  client.connect(proxyPort);

  // Get ticket
  client.sendGetInfo(0x7777);
  auto infoRaw = client.recvMsg();
  BOOST_REQUIRE(!infoRaw.empty());
  auto info = parseInfo(infoRaw);

  // Build CES_UNSIGNED_QUERY_ACCOUNT payload
  // Fields: accountMapKey (HashPrefix = 8 bytes)
  ces::HashPrefix mapKey = Account::getMapKey(fundedKey.getPublicKeyAsHash());
  ces::Bytes cesPayload;
  cesPayload.push_back(ces::CES_UNSIGNED_QUERY_ACCOUNT);
  cesPayload.insert(cesPayload.end(), reinterpret_cast<const uint8_t*>(&mapKey),
                    reinterpret_cast<const uint8_t*>(&mapKey) + sizeof(mapKey));

  client.sendMessage(0x8888, info.gpassword, cesPayload);

  auto resp = client.recvMsg();
  BOOST_REQUIRE(!resp.empty());
  BOOST_CHECK_EQUAL(resp[0], minx::MINX_MESSAGE);
  BOOST_REQUIRE(resp.size() > 18);
  BOOST_CHECK_EQUAL(resp[18], ces::CES_UNSIGNED_QUERY_ACCOUNT_RESULT);

  client.close();
}

// ---------------------------------------------------------------------------
// Test 8: Multiple sequential operations on one connection
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(SequentialOperationsOneConnection) {
  asio::io_context io;
  TcpTestClient client(io);
  client.connect(proxyPort);

  // Get initial ticket
  client.sendGetInfo(0xA000);
  auto infoRaw = client.recvMsg();
  BOOST_REQUIRE(!infoRaw.empty());
  auto info = parseInfo(infoRaw);

  // Do 5 unsigned account queries in a row on the same connection
  for (int i = 0; i < 5; ++i) {
    ces::HashPrefix mk = ces::Account::getMapKey(fundedKey.getPublicKeyAsHash());
    ces::Bytes cesPayload;
    cesPayload.push_back(ces::CES_UNSIGNED_QUERY_ACCOUNT);
    cesPayload.insert(cesPayload.end(),
      reinterpret_cast<const uint8_t*>(&mk),
      reinterpret_cast<const uint8_t*>(&mk) + sizeof(mk));

    client.sendMessage(0xA100 + i, info.gpassword, cesPayload);

    auto resp = client.recvMsg();
    BOOST_REQUIRE_MESSAGE(!resp.empty(), "No response on iteration " << i);
    BOOST_CHECK_EQUAL(resp[0], minx::MINX_MESSAGE);
    BOOST_REQUIRE(resp.size() > 18);
    BOOST_CHECK_EQUAL(resp[18], ces::CES_UNSIGNED_QUERY_ACCOUNT_RESULT);

    // Extract new ticket from the response envelope for next request
    BOOST_REQUIRE(resp.size() >= 10);
    info.gpassword = ces::Buffer::peek<uint64_t>(&resp[2]);
  }

  client.close();
}

// ---------------------------------------------------------------------------
// Test 9: Truncated message gets dropped
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(TruncatedMessageDropped) {
  asio::io_context io;
  TcpTestClient client(io);
  client.connect(proxyPort);

  // Get ticket
  client.sendGetInfo(0xB000);
  auto infoRaw = client.recvMsg();
  BOOST_REQUIRE(!infoRaw.empty());
  auto info = parseInfo(infoRaw);

  // Send a CES_TRANSFER opcode but truncated (no fields after opcode)
  ces::Bytes payload;
  payload.push_back(ces::CES_TRANSFER);
  // Only 1 byte — way too short for a transfer message

  client.sendMessage(0xB001, info.gpassword, payload);

  auto resp = client.recvMsg(2000);
  BOOST_CHECK(resp.empty() || !client.isOpen());

  client.close();
}

// ---------------------------------------------------------------------------
// Test 10: Empty CES payload gets dropped
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(EmptyPayloadDropped) {
  asio::io_context io;
  TcpTestClient client(io);
  client.connect(proxyPort);

  client.sendGetInfo(0xC000);
  auto infoRaw = client.recvMsg();
  BOOST_REQUIRE(!infoRaw.empty());
  auto info = parseInfo(infoRaw);

  // Send MINX_MESSAGE with empty CES payload
  ces::Bytes emptyPayload;
  client.sendMessage(0xC001, info.gpassword, emptyPayload);

  auto resp = client.recvMsg(2000);
  BOOST_CHECK(resp.empty() || !client.isOpen());

  client.close();
}

// ---------------------------------------------------------------------------
// Test 11: Signed asset create through proxy
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(SignedAssetCreateThroughProxy) {
  asio::io_context io;
  TcpTestClient client(io);
  client.connect(proxyPort);

  client.sendGetInfo(0xD000);
  auto infoRaw = client.recvMsg();
  BOOST_REQUIRE(!infoRaw.empty());
  auto info = parseInfo(infoRaw);

  // Build a signed CES_CREATE_ASSET message
  ces::AssetData content;
  content.fill(0x42);
  minx::Hash assetId = makeHash("PROXY_ASSET");

  ces::CesCreateAsset req;
  req.ownerId = fundedKey.getPublicKeyAsHash();
  req.serverId = ces::Account::getMapKey(info.skey);
  req.assetId = assetId;
  req.content = content;
  req.amount = 10; // 10 days
  req.reqNonce = 0;
  req.price = 0;
  auto cesBytes = req.toBytes(fundedKey);

  ces::Bytes payload(cesBytes.begin(), cesBytes.end());
  client.sendMessage(0xD001, info.gpassword, payload);

  auto resp = client.recvMsg();
  BOOST_REQUIRE(!resp.empty());
  BOOST_CHECK_EQUAL(resp[0], minx::MINX_MESSAGE);
  BOOST_REQUIRE(resp.size() > 18);
  BOOST_CHECK_EQUAL(resp[18], ces::CES_CREATE_ASSET_RESULT);

  client.close();
}

// ---------------------------------------------------------------------------
// Test 12: Many concurrent clients doing real operations
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(ManyConcurrentClients) {
  constexpr int NUM_CLIENTS = 20;
  asio::io_context io;
  std::vector<std::unique_ptr<TcpTestClient>> clients;
  std::vector<ParsedInfo> infos;

  // Connect all clients and get tickets
  for (int i = 0; i < NUM_CLIENTS; ++i) {
    auto c = std::make_unique<TcpTestClient>(io);
    c->connect(proxyPort);
    c->sendGetInfo(0xE000 + i);
    clients.push_back(std::move(c));
  }

  for (int i = 0; i < NUM_CLIENTS; ++i) {
    auto raw = clients[i]->recvMsg();
    BOOST_REQUIRE_MESSAGE(!raw.empty(),
                          "Client " << i << " got no INFO response");
    infos.push_back(parseInfo(raw));
  }

  // All clients send unsigned account query simultaneously
  for (int i = 0; i < NUM_CLIENTS; ++i) {
    ces::HashPrefix mk = ces::Account::getMapKey(fundedKey.getPublicKeyAsHash());
    ces::Bytes cesPayload;
    cesPayload.push_back(ces::CES_UNSIGNED_QUERY_ACCOUNT);
    cesPayload.insert(cesPayload.end(),
      reinterpret_cast<const uint8_t*>(&mk),
      reinterpret_cast<const uint8_t*>(&mk) + sizeof(mk));
    clients[i]->sendMessage(0xF000 + i, infos[i].gpassword, cesPayload);
  }

  // All should get valid responses
  int successCount = 0;
  for (int i = 0; i < NUM_CLIENTS; ++i) {
    auto resp = clients[i]->recvMsg();
    if (!resp.empty() && resp[0] == minx::MINX_MESSAGE &&
        resp.size() > 18 &&
        resp[18] == ces::CES_UNSIGNED_QUERY_ACCOUNT_RESULT) {
      successCount++;
    }
  }
  // Allow some to fail due to channel contention, but most should succeed
  BOOST_CHECK_GE(successCount, NUM_CLIENTS / 2);

  for (auto& c : clients)
    c->close();
}

// ---------------------------------------------------------------------------
// Test 13: Signed query account through proxy
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(SignedQueryAccountThroughProxy) {
  asio::io_context io;
  TcpTestClient client(io);
  client.connect(proxyPort);

  client.sendGetInfo(0x1300);
  auto infoRaw = client.recvMsg();
  BOOST_REQUIRE(!infoRaw.empty());
  auto info = parseInfo(infoRaw);

  // Build signed CES_QUERY_ACCOUNT
  ces::CesQueryAccount req;
  req.originId = fundedKey.getPublicKeyAsHash();
  req.serverId = ces::Account::getMapKey(info.skey);
  req.reqNonce = 0;
  req.queryId = Account::getMapKey(fundedKey.getPublicKeyAsHash());
  req.items = 0;
  auto cesBytes = req.toBytes(fundedKey);

  ces::Bytes payload(cesBytes.begin(), cesBytes.end());
  client.sendMessage(0x1301, info.gpassword, payload);

  auto resp = client.recvMsg();
  BOOST_REQUIRE(!resp.empty());
  BOOST_CHECK_EQUAL(resp[0], minx::MINX_MESSAGE);
  BOOST_REQUIRE(resp.size() > 18);
  BOOST_CHECK_EQUAL(resp[18], ces::CES_QUERY_ACCOUNT_RESULT);

  client.close();
}

BOOST_AUTO_TEST_SUITE_END()
