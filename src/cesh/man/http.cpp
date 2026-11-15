#include "man/http.h"

#include "man/markdown.h"

#include <boost/asio/read_until.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>

#include <cctype>
#include <chrono>
#include <istream>

namespace ces::man {

namespace asio = boost::asio;
using asio::ip::tcp;

namespace {

constexpr size_t kMaxRequest = 16 * 1024;
constexpr auto kRequestTime = std::chrono::seconds(10);

const char* kCss = R"(
*{box-sizing:border-box}
body{margin:0;display:flex;font:16px/1.55 system-ui,sans-serif;color:#1d1d1f;background:#fbfbf8}
nav{width:19rem;flex:none;padding:1.2rem 1rem;border-right:1px solid #e2e2dc;background:#f3f3ee;min-height:100vh}
nav .home{display:block;font-weight:700;color:#1d1d1f;text-decoration:none;margin-bottom:.8rem}
nav form{margin-bottom:1rem}
nav input{width:100%;padding:.35rem .5rem;border:1px solid #cfcfc8;border-radius:4px;font:inherit}
nav ul{list-style:none;margin:0;padding:0}
nav li a{display:block;padding:.15rem .4rem;border-radius:4px;color:#333;text-decoration:none}
nav li a:hover{background:#e6e6df}
nav li.here a{background:#1d1d1f;color:#fbfbf8}
nav li.section a{font-weight:600;margin-top:.5rem}
main{max-width:52rem;padding:2rem 3rem}
h1{margin-top:0}
.summary{color:#666;margin-top:-.6rem}
code{font:.9em ui-monospace,monospace;background:#ecece6;padding:.05rem .3rem;border-radius:3px}
pre{background:#1d1d1f;color:#f3f3ee;padding:.8rem 1rem;border-radius:6px;overflow-x:auto}
pre code{background:none;padding:0;color:inherit}
table{border-collapse:collapse;margin:1rem 0}
th,td{border:1px solid #dcdcd4;padding:.35rem .6rem;text-align:left;vertical-align:top}
th{background:#efefe9}
blockquote{margin:0;padding:.2rem 1rem;border-left:3px solid #cfcfc8;color:#555}
a{color:#0b5cad}
.hit{margin:.6rem 0}
.hit .where{font-size:.85em;color:#666}
)";

std::string urlDecode(std::string_view s, bool plusIsSpace) {
  std::string o;
  for (size_t i = 0; i < s.size(); ++i) {
    char c = s[i];
    if (c == '+' && plusIsSpace) { o += ' '; continue; }
    if (c == '%' && i + 2 < s.size() &&
        std::isxdigit(static_cast<unsigned char>(s[i + 1])) &&
        std::isxdigit(static_cast<unsigned char>(s[i + 2]))) {
      o += static_cast<char>(std::stoi(std::string(s.substr(i + 1, 2)), nullptr, 16));
      i += 2;
      continue;
    }
    o += c;
  }
  return o;
}

std::string hrefOf(const Page& p) { return "/" + p.path; }

std::string document(const Manual& m, const Page* here, const std::string& title,
                     const std::string& query, const std::string& content) {
  std::string o = "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
                  "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                  "<title>" + escapeHtml(title) + " · cesh manual</title><style>" +
                  kCss + "</style></head>\n<body><nav><a class=\"home\" href=\"/\">cesh manual</a>"
                  "<form action=\"/search\"><input name=\"q\" placeholder=\"search\" value=\"" +
                  escapeHtml(query) + "\"></form><ul>\n";
  for (auto& p : m.pages()) {
    std::string cls;
    if (&p == here) cls = "here";
    else if (p.isIndex && !p.path.empty()) cls = "section";
    o += "<li" + (cls.empty() ? std::string() : " class=\"" + cls + "\"") +
         " style=\"padding-left:" + std::to_string(p.depth) + "rem\"><a href=\"" +
         escapeHtml(hrefOf(p)) + "\" title=\"" + escapeHtml(p.summary) + "\">" +
         escapeHtml(p.title) + "</a></li>\n";
  }
  o += "</ul></nav>\n<main>" + content + "</main></body></html>\n";
  return o;
}

}  // namespace

std::string pageHtml(const Manual& m, const Page& p) {
  LinkMap link = [&](std::string_view target) -> std::string {
    Link l = m.resolve(p, target);
    return l.found ? "/" + l.path : std::string(target);
  };
  std::string content = "<h1>" + escapeHtml(p.title) + "</h1>\n<p class=\"summary\">" +
                        escapeHtml(p.summary) + "</p>\n" + markdownToHtml(p.body, link);
  return document(m, &p, p.title, "", content);
}

HttpReply respond(const Manual& m, std::string_view method, std::string_view target) {
  if (method != "GET" && method != "HEAD") {
    return {405, document(m, nullptr, "Method not allowed", "",
                          "<h1>Method not allowed</h1><p>Use GET.</p>")};
  }
  std::string_view path = target;
  std::string_view query;
  auto q = target.find('?');
  if (q != std::string_view::npos) { path = target.substr(0, q); query = target.substr(q + 1); }

  if (path == "/search") {
    std::string word;
    size_t i = 0;
    while (i <= query.size()) {
      size_t amp = query.find('&', i);
      if (amp == std::string_view::npos) amp = query.size();
      std::string_view kv = query.substr(i, amp - i);
      if (kv.rfind("q=", 0) == 0) word = urlDecode(kv.substr(2), true);
      i = amp + 1;
    }
    std::string content = "<h1>Search</h1>\n";
    auto hits = m.search(word);
    if (word.empty()) content += "<p>Type a word in the box.</p>\n";
    else if (hits.empty()) content += "<p>No page has <code>" + escapeHtml(word) + "</code>.</p>\n";
    for (auto& h : hits) {
      content += "<div class=\"hit\"><a href=\"" + escapeHtml(hrefOf(*h.page)) + "\">" +
                 escapeHtml(h.page->title) + "</a> <span class=\"where\">" +
                 escapeHtml(h.page->path.empty() ? "index" : h.page->path) +
                 (h.line ? ":" + std::to_string(h.line) : std::string()) +
                 "</span><br>" + escapeHtml(h.text) + "</div>\n";
    }
    return {200, document(m, nullptr, "Search", word, content)};
  }

  std::string name = urlDecode(path, false);
  const Page* p = nullptr;
  if (name == "/" || name.empty()) {
    for (auto& pg : m.pages())
      if (pg.path.empty()) { p = &pg; break; }
  } else {
    p = m.find(name);
  }
  if (!p) {
    return {404, document(m, nullptr, "Not found", "",
                          "<h1>Not found</h1><p>No page <code>" + escapeHtml(name) +
                          "</code>. Use the list or the search.</p>")};
  }
  return {200, pageHtml(m, *p)};
}

// ---- the server ----

namespace {

const char* reasonOf(int status) {
  switch (status) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    default: return "Error";
  }
}

struct Session : std::enable_shared_from_this<Session> {
  Session(tcp::socket s, const Manual& m)
    : sock(std::move(s)), timer(sock.get_executor()), buf(kMaxRequest), manual(m) {}

  void start() {
    auto self = shared_from_this();
    timer.expires_after(kRequestTime);
    timer.async_wait([self](const boost::system::error_code& ec) {
      if (!ec) {
        boost::system::error_code ignore;
        self->sock.close(ignore);
      }
    });
    asio::async_read_until(sock, buf, "\r\n\r\n",
      [self](const boost::system::error_code& ec, size_t) {
        if (ec) { self->finish(); return; }
        self->answer();
      });
  }

  void answer() {
    std::istream in(&buf);
    std::string method, target, version;
    in >> method >> target >> version;
    HttpReply r;
    if (method.empty() || target.empty() || target.front() != '/') {
      r = {400, "<!doctype html><title>Bad request</title><h1>Bad request</h1>\n"};
    } else {
      r = respond(manual, method, target);
    }
    out = "HTTP/1.1 " + std::to_string(r.status) + " " + reasonOf(r.status) + "\r\n"
          "Content-Type: text/html; charset=utf-8\r\n"
          "Content-Length: " + std::to_string(r.body.size()) + "\r\n"
          "Connection: close\r\n"
          "Cache-Control: no-store\r\n"
          "X-Content-Type-Options: nosniff\r\n"
          "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'\r\n"
          "\r\n";
    if (method != "HEAD") out += r.body;
    auto self = shared_from_this();
    asio::async_write(sock, asio::buffer(out),
      [self](const boost::system::error_code&, size_t) { self->finish(); });
  }

  void finish() {
    boost::system::error_code ignore;
    timer.cancel();
    sock.shutdown(tcp::socket::shutdown_both, ignore);
    sock.close(ignore);
  }

  tcp::socket sock;
  asio::steady_timer timer;
  asio::streambuf buf;
  const Manual& manual;
  std::string out;
};

}  // namespace

struct HttpServer::Impl {
  Impl(asio::io_context& io, const Manual& m, const tcp::endpoint& ep)
    : acceptor(io, ep), manual(m) {}

  void accept() {
    acceptor.async_accept([this](const boost::system::error_code& ec, tcp::socket s) {
      if (ec == asio::error::operation_aborted || !acceptor.is_open()) return;
      if (!ec) std::make_shared<Session>(std::move(s), manual)->start();
      accept();
    });
  }

  tcp::acceptor acceptor;
  const Manual& manual;
};

HttpServer::HttpServer(asio::io_context& io, const Manual& m, const tcp::endpoint& ep)
  : impl_(std::make_unique<Impl>(io, m, ep)) {
  impl_->accept();
}

HttpServer::~HttpServer() { close(); }

uint16_t HttpServer::port() const {
  boost::system::error_code ec;
  auto ep = impl_->acceptor.local_endpoint(ec);
  return ec ? 0 : ep.port();
}

void HttpServer::close() {
  boost::system::error_code ignore;
  if (impl_ && impl_->acceptor.is_open()) impl_->acceptor.close(ignore);
}

}  // namespace ces::man
