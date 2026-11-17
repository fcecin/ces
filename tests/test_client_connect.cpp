// CesClient::connect against a server that never answers. getInfo already
// sends up to `tries` times, so connect must call it once: a dead server
// then costs `tries` waits, not `tries` squared. The test counts the
// datagrams that reach a silent UDP socket, so it does not depend on time.
//
// The default config of a CesClient has the small recv ring and the narrow
// spam filter of a client, so many clients in one process cost little.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"

#include <ces/client.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/test/unit_test.hpp>

#include <unistd.h>

#include <atomic>
#include <fstream>
#include <memory>
#include <thread>
#include <vector>

using namespace ces;
namespace asio = boost::asio;

BOOST_AUTO_TEST_SUITE(ClientConnectTests)

BOOST_AUTO_TEST_CASE(Connect_SilentServer_SendsTriesGetInfos) {
  blog::init();
  blog::set_level(blog::fatal);
  asio::io_context io;
  asio::ip::udp::socket silent(
      io, asio::ip::udp::endpoint(asio::ip::address_v6::loopback(), 0));
  const uint16_t port = silent.local_endpoint().port();

  // Count datagrams until the test's own end marker arrives. The client's
  // sends all happen before connect returns, so they arrive before it.
  std::atomic<int> got{0};
  std::thread reader([&] {
    char buf[2048];
    for (;;) {
      asio::ip::udp::endpoint from;
      boost::system::error_code ec;
      size_t n = silent.receive_from(asio::buffer(buf), from, 0, ec);
      if (ec) return;
      if (n == 3 && std::string(buf, 3) == "END") return;
      ++got;
    }
  });

  {
    CesClient c(asio::ip::udp::endpoint(asio::ip::address_v6::loopback(), port),
                false);
    c.start(0);
    c.setTries(3);
    c.setRetryIntervalMs(50);
    BOOST_CHECK(!c.connect());
    c.stop();
  }

  asio::ip::udp::socket marker(io, asio::ip::udp::v6());
  marker.send_to(asio::buffer("END", 3),
                 asio::ip::udp::endpoint(asio::ip::address_v6::loopback(), port));
  reader.join();
  BOOST_CHECK_EQUAL(got.load(), 3);
}

BOOST_AUTO_TEST_CASE(DefaultClient_HasSmallRecvRing) {
  BOOST_CHECK_LT(CesClient::clientConfig().recvBuffersSize,
                 minx::MinxConfig::DEFAULT_RECV_BUFFERS_SIZE);
  BOOST_CHECK_LT(CesClient::clientConfig().spamFilterWidth,
                 minx::MinxConfig::DEFAULT_SPAM_FILTER_WIDTH);
  auto rss = [] {
    std::ifstream f("/proc/self/statm");
    size_t pages = 0, resident = 0;
    f >> pages >> resident;
    return resident * static_cast<size_t>(sysconf(_SC_PAGESIZE));
  };
  // Minx writes each buffer of the ring and its spam filter tables when it
  // builds them. A server-sized ring is about 32MB, and a server-sized filter
  // about 12MB. A client with the small ring and the narrow filter grows
  // about 1MB (the ring, and the stacks of its threads).
  constexpr size_t kClients = 16;
  const size_t before = rss();
  std::vector<std::unique_ptr<CesClient>> clients;
  for (size_t i = 0; i < kClients; ++i)
    clients.push_back(std::make_unique<CesClient>(
      asio::ip::udp::endpoint(asio::ip::address_v6::loopback(), 9), false));
  const size_t after = rss();
  const size_t grew = after > before ? after - before : 0;
  BOOST_CHECK_LT(grew, kClients * 4 * 1024 * 1024);
}

BOOST_AUTO_TEST_SUITE_END()
