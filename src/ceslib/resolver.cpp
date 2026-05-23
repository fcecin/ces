#include <ces/util/resolver.h>

#include <ces/client.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>

#include <chrono>
#include <mutex>
#include <stdexcept>
#include <unordered_map>
#include <utility>

namespace ces {

namespace {

// Split "host:port" on the LAST ':' so unbracketed IPv6 literals with
// embedded colons are handled as the caller intends when they omit
// brackets. Callers that need strict IPv6-literal handling should pass
// bracketed syntax ("[::1]:80") and strip brackets before calling.
std::pair<std::string, std::string> splitHostPort(const std::string& hp) {
  auto pos = hp.find_last_of(':');
  if (pos == std::string::npos)
    throw std::runtime_error("Bad server format (expected host:port)");
  return {hp.substr(0, pos), hp.substr(pos + 1)};
}

// Thin wrapper around a one-shot asio resolver. Throws on empty result.
template <typename Resolver>
auto doResolve(const std::string& host, const std::string& port) {
  boost::asio::io_context ioc;
  Resolver res(ioc);
  auto results = res.resolve(host, port);
  if (results.empty())
    throw std::runtime_error("Host unresolved: " + host + ":" + port);
  return results;
}

} // namespace

boost::asio::ip::udp::endpoint
Resolver::resolveUdp(const std::string& hostPort) {
  auto [host, port] = splitHostPort(hostPort);
  return *doResolve<boost::asio::ip::udp::resolver>(host, port).begin();
}

boost::asio::ip::udp::endpoint
Resolver::resolveUdp(const std::string& host, uint16_t port) {
  return *doResolve<boost::asio::ip::udp::resolver>(
           host, std::to_string(port)).begin();
}

boost::asio::ip::tcp::endpoint
Resolver::resolveTcp(const std::string& hostPort) {
  auto [host, port] = splitHostPort(hostPort);
  return doResolve<boost::asio::ip::tcp::resolver>(host, port)
    .begin()->endpoint();
}

boost::asio::ip::tcp::endpoint
Resolver::resolveTcp(const std::string& host, uint16_t port) {
  return doResolve<boost::asio::ip::tcp::resolver>(
           host, std::to_string(port)).begin()->endpoint();
}

boost::asio::ip::address Resolver::parseIp(const std::string& ip) {
  return boost::asio::ip::make_address(ip);
}

boost::asio::ip::address
Resolver::parseIp(const std::string& ip, boost::system::error_code& ec) {
  return boost::asio::ip::make_address(ip, ec);
}

std::unique_ptr<CesClient>
Resolver::Probe::makeClient(bool useDataset) const {
  if (isTcp)
    return std::make_unique<CesClient>(tcpEp, useDataset);
  return std::make_unique<CesClient>(udpEp, useDataset);
}

Resolver::Probe Resolver::probe(const std::string& hostPort,
                                 std::function<void(const std::string&)> log) {
  // Cache successful probes for the process lifetime. Same serverStr
  // resolves to the same Probe every time, amortizing DNS + the TCP
  // connect test across all callers.
  static std::mutex cacheMutex;
  static std::unordered_map<std::string, Probe> cache;
  {
    std::lock_guard lock(cacheMutex);
    auto it = cache.find(hostPort);
    if (it != cache.end()) {
      if (log) log("Probe cache hit: " + hostPort + " -> " +
                   (it->second.isTcp ? "TCP" : "UDP"));
      return it->second;
    }
  }

  Probe result;

  if (log) log("Probing " + hostPort + " (TCP first, 500ms timeout)...");

  try {
    auto tcpEp = resolveTcp(hostPort);
    if (log) log("TCP resolve: " + tcpEp.address().to_string() + ":" +
                 std::to_string(tcpEp.port()));

    boost::asio::io_context ioc;
    boost::asio::ip::tcp::socket sock(ioc);
    boost::asio::steady_timer timer(ioc);
    timer.expires_after(std::chrono::milliseconds(500));

    bool connected = false;
    bool timed_out = false;
    boost::system::error_code connectEc;

    sock.async_connect(tcpEp, [&](boost::system::error_code ec) {
      connectEc = ec;
      if (!ec) {
        connected = true;
        timer.cancel();
      }
    });

    timer.async_wait([&](boost::system::error_code ec) {
      if (!ec) {
        timed_out = true;
        boost::system::error_code closeEc;
        sock.close(closeEc);
      }
    });

    ioc.run();

    if (connected && !timed_out) {
      boost::system::error_code ec;
      sock.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
      sock.close(ec);
      result.isTcp = true;
      result.tcpEp = tcpEp;
      if (log) log("Probe result: TCP (proxy detected)");
      {
        std::lock_guard lock(cacheMutex);
        cache[hostPort] = result;
      }
      return result;
    }

    if (log) {
      if (timed_out) log("TCP probe: timed out");
      else log("TCP probe: failed (" + connectEc.message() + ")");
    }
  } catch (std::exception& e) {
    if (log) log("TCP probe exception: " + std::string(e.what()));
  }

  // Fall back to UDP.
  result.udpEp = resolveUdp(hostPort);
  result.isTcp = false;
  if (log) log("Probe result: UDP (direct)");
  {
    std::lock_guard lock(cacheMutex);
    cache[hostPort] = result;
  }
  return result;
}

} // namespace ces
