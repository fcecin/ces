// CesClient::connect against a server that never answers. getInfo already
// sends up to `tries` times, so connect must call it once: a dead server
// then costs `tries` waits, not `tries` squared. The test counts the
// datagrams that reach a silent UDP socket, so it does not depend on time.

#define BOOST_TEST_DYN_LINK
#include "test_common.h"

#include <ces/client.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/test/unit_test.hpp>

#include <atomic>
#include <thread>

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

BOOST_AUTO_TEST_SUITE_END()
