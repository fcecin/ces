#pragma once

// Resolver — centralized text-to-endpoint conversion.
//
// Every place in CES that turns a string (DNS name, IP, "host:port") into a
// boost::asio endpoint goes through here, so IPv6 / bracketed-host / port-name
// quirks live in one code path. Callers should not use
// boost::asio::ip::{udp,tcp}::resolver or make_address directly.

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/system/error_code.hpp>

namespace ces {

class CesClient;

class Resolver {
public:
  // DNS-capable resolution of "host:port" to a UDP endpoint. The split
  // happens on the LAST ':' so unbracketed IPv6 addresses don't mis-parse
  // as long as the caller uses the accepted convention (see splitHostPort
  // in the implementation). Throws on empty resolver result or bad format.
  static boost::asio::ip::udp::endpoint resolveUdp(const std::string& hostPort);

  // Separate-args variant. Same semantics minus the split.
  static boost::asio::ip::udp::endpoint resolveUdp(const std::string& host,
                                                    uint16_t port);

  // TCP counterparts of the above.
  static boost::asio::ip::tcp::endpoint resolveTcp(const std::string& hostPort);
  static boost::asio::ip::tcp::endpoint resolveTcp(const std::string& host,
                                                    uint16_t port);

  // Parse a numeric IP (no DNS). Throws on invalid.
  static boost::asio::ip::address parseIp(const std::string& ip);
  // Non-throwing variant for hot paths that want to handle the failure.
  static boost::asio::ip::address parseIp(const std::string& ip,
                                           boost::system::error_code& ec);

  // Result of probe(): auto-detected TCP-vs-UDP with pre-resolved endpoints.
  struct Probe {
    bool isTcp = false;
    boost::asio::ip::udp::endpoint udpEp;
    boost::asio::ip::tcp::endpoint tcpEp;

    // Create a CesClient using the detected transport. Defined inline in
    // the .cpp (forward declaration of CesClient at the top of this header
    // keeps us from pulling client.h transitively everywhere).
    std::unique_ptr<CesClient> makeClient(bool useDataset = false) const;
  };

  // Try TCP connect first with a short timeout; fall back to UDP on
  // refusal / timeout. Results are cached for the process lifetime per
  // input string. Optional log callback for diagnostics.
  static Probe probe(const std::string& hostPort,
                     std::function<void(const std::string&)> log = nullptr);
};

} // namespace ces
