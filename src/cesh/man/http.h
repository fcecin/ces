// `cesh man --serve`: the manual as HTML pages over HTTP.
//
// Each page is complete in itself: the sidebar, the page and the CSS are in
// one HTML document, with no script, no font and no other file. The routes
// are "/" (the home page), "/<page path>", and "/search?q=<word>".

#pragma once

#include "man/manual.h"

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace ces::man {

struct HttpReply {
  int status = 200;
  std::string body;      // a complete HTML document
};

// The reply to one request. `target` is the request target, such as
// "/files/rent" or "/search?q=rent".
HttpReply respond(const Manual& m, std::string_view method, std::string_view target);

// The HTML document of a page, with the sidebar.
std::string pageHtml(const Manual& m, const Page& p);

// Serves the manual on `ep` until `io` stops. One request per connection;
// a request must arrive in 10 seconds and be at most 16 KB.
class HttpServer {
public:
  HttpServer(boost::asio::io_context& io, const Manual& m,
             const boost::asio::ip::tcp::endpoint& ep);
  ~HttpServer();
  uint16_t port() const;
  void close();

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ces::man
