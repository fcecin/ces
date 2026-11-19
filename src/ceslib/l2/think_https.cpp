// think_https.cpp - see think_https.h.

#ifdef CES_THINK

#include <ces/l2/think_https.h>

#include <ces/types.h>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>

#include <openssl/err.h>
#include <openssl/ssl.h>

namespace ces {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = asio::ip::tcp;

struct ThinkHttpsBackend::Impl {
  bool tls = true;
  std::string host, port, prefix, target;
  std::unique_ptr<asio::ssl::context> ctx;
};

namespace {

// The state of one call, shared by the coroutine and the run() loop. Both
// run on the caller's thread (one io_context, one thread).
struct Call {
  const std::atomic<bool>* stop = nullptr;
  const std::function<bool(std::string_view)>* onText = nullptr;
  // The stream to cancel on `stop`. It lives in the coroutine frame, so
  // callAsync clears it before that frame goes away.
  beast::tcp_stream* low = nullptr;
  ThinkSseParser parser;
  ThinkOutcome out;
  bool finished = false;
};

// Clears Call::low on every exit from callAsync, before the stream it
// points to is destroyed.
struct ClearLow {
  Call& c;
  ~ClearLow() { c.low = nullptr; }
};

// End the call before the next step when `stop` is set, so a stopped call
// sends no request.
void throwIfStopped(const Call& c) {
  if (c.stop->load())
    throw boost::system::system_error(asio::error::operation_aborted);
}

template <class Stream>
asio::awaitable<void> exchange(Stream& s, const ThinkHttpsBackend::Impl& im,
                               const std::string& auth,
                               const std::string& body, Call& c) {
  http::request<http::string_body> req{http::verb::post, im.target, 11};
  req.set(http::field::host, im.host);
  req.set(http::field::authorization, auth);
  req.set(http::field::content_type, "application/json");
  req.set(http::field::accept, "text/event-stream");
  req.set(http::field::user_agent, "ces-think");
  req.body() = body;
  req.prepare_payload();
  throwIfStopped(c);
  co_await http::async_write(s, req, asio::use_awaitable);

  beast::flat_buffer buf;
  http::response_parser<http::buffer_body> p;
  p.body_limit(boost::none);
  co_await http::async_read_header(s, buf, p, asio::use_awaitable);
  const unsigned code = p.get().result_int();

  char tmp[16384];
  if (code != 200) {
    // Read a bounded part of the error body for the log.
    std::string err;
    while (!p.is_done() && err.size() < 65536) {
      p.get().body().data = tmp;
      p.get().body().size = sizeof(tmp);
      auto [ec, n] = co_await http::async_read(
          s, buf, p, asio::as_tuple(asio::use_awaitable));
      if (ec == http::error::need_buffer) ec = {};
      if (ec) break;
      err.append(tmp, sizeof(tmp) - p.get().body().size);
    }
    c.out.status = code == 429 ? CES_ERROR_QUEUE_FULL : CES_ERROR_INTERNAL;
    c.out.billing = ThinkOutcome::kNone;
    c.out.detail = "http " + std::to_string(code) + ": " +
                   thinkErrorMessage(err);
    co_return;
  }

  // From here the backend did work that it can bill. When the reader
  // stops taking text (its client left), the loop still reads to the usage
  // report, so the call is billed by usage. Only `stop` (shutdown) or the
  // timeout ends it early.
  c.out.billing = ThinkOutcome::kEstimate;
  bool bad = false;
  while (!p.is_done()) {
    p.get().body().data = tmp;
    p.get().body().size = sizeof(tmp);
    auto [ec, n] = co_await http::async_read(
        s, buf, p, asio::as_tuple(asio::use_awaitable));
    if (ec == http::error::need_buffer) ec = {};
    if (ec) throw boost::system::system_error(ec);
    size_t got = sizeof(tmp) - p.get().body().size;
    if (!c.parser.feed(std::string_view(tmp, got), *c.onText)) {
      bad = true;
      break;
    }
    if (c.parser.done() || c.stop->load()) break;
  }
  c.out.outBytes = c.parser.textBytes() + c.parser.reasoningBytes() +
                   c.parser.toolBytes();
  c.out.chat = c.parser.chatEnd();
  if (c.parser.hasUsage()) {
    c.out.usage = c.parser.usage();
    c.out.billing = ThinkOutcome::kUsage;
  }
  if (bad) {
    c.out.status = CES_ERROR_INTERNAL;
    c.out.detail = "malformed stream";
  } else if (!c.parser.error().empty()) {
    c.out.status = CES_ERROR_INTERNAL;
    c.out.detail = c.parser.error();
  } else if (c.parser.stopped() || c.stop->load()) {
    c.out.status = CES_ERROR_INTERNAL;
    c.out.detail = "stopped";
  } else if (!c.parser.done()) {
    // A complete reply ends with "[DONE]". A body that ends before it may
    // have lost text.
    c.out.status = CES_ERROR_INTERNAL;
    c.out.detail = "stream ended early";
  } else {
    c.out.status = CES_OK;
  }
}

asio::awaitable<void> callAsync(const ThinkHttpsBackend::Impl& im,
                                asio::ssl::context* ctx,
                                std::chrono::steady_clock::time_point deadline,
                                std::string auth, std::string body, Call& c) {
  ClearLow clearLow{c};
  throwIfStopped(c);
  auto ex = co_await asio::this_coro::executor;
  tcp::resolver res(ex);
  beast::tcp_stream tcpStream(ex);
  c.low = &tcpStream;
  tcpStream.expires_at(deadline);
  auto eps = co_await res.async_resolve(im.host, im.port, asio::use_awaitable);
  throwIfStopped(c);
  co_await tcpStream.async_connect(eps, asio::use_awaitable);
  if (!im.tls) {
    co_await exchange(tcpStream, im, auth, body, c);
    co_return;
  }
  beast::ssl_stream<beast::tcp_stream> s(std::move(tcpStream), *ctx);
  c.low = &beast::get_lowest_layer(s);
  if (!SSL_set_tlsext_host_name(s.native_handle(), im.host.c_str()))
    throw boost::system::system_error(
        boost::system::error_code(static_cast<int>(::ERR_get_error()),
                                  asio::error::get_ssl_category()));
  s.set_verify_callback(asio::ssl::host_name_verification(im.host));
  throwIfStopped(c);
  co_await s.async_handshake(asio::ssl::stream_base::client,
                             asio::use_awaitable);
  co_await exchange(s, im, auth, body, c);
}

// One GET, the whole body into `out` (at most 1 MB). Throws on a network
// failure; `code` is the HTTP status.
template <class Stream>
asio::awaitable<void> getOn(Stream& s, const ThinkHttpsBackend::Impl& im,
                            const std::string& target, const std::string& auth,
                            unsigned& code, std::string& out) {
  http::request<http::empty_body> req{http::verb::get, target, 11};
  req.set(http::field::host, im.host);
  req.set(http::field::authorization, auth);
  req.set(http::field::accept, "application/json");
  req.set(http::field::user_agent, "ces-think");
  co_await http::async_write(s, req, asio::use_awaitable);
  beast::flat_buffer buf;
  http::response_parser<http::string_body> p;
  p.body_limit(1024 * 1024);
  co_await http::async_read(s, buf, p, asio::use_awaitable);
  code = p.get().result_int();
  out = std::move(p.get().body());
}

asio::awaitable<void> getAsync(const ThinkHttpsBackend::Impl& im,
                               asio::ssl::context* ctx,
                               std::chrono::steady_clock::time_point deadline,
                               std::string target, std::string auth,
                               unsigned& code, std::string& out) {
  auto ex = co_await asio::this_coro::executor;
  tcp::resolver res(ex);
  beast::tcp_stream tcpStream(ex);
  tcpStream.expires_at(deadline);
  auto eps = co_await res.async_resolve(im.host, im.port, asio::use_awaitable);
  co_await tcpStream.async_connect(eps, asio::use_awaitable);
  if (!im.tls) {
    co_await getOn(tcpStream, im, target, auth, code, out);
    co_return;
  }
  beast::ssl_stream<beast::tcp_stream> s(std::move(tcpStream), *ctx);
  if (!SSL_set_tlsext_host_name(s.native_handle(), im.host.c_str()))
    throw boost::system::system_error(
        boost::system::error_code(static_cast<int>(::ERR_get_error()),
                                  asio::error::get_ssl_category()));
  s.set_verify_callback(asio::ssl::host_name_verification(im.host));
  co_await s.async_handshake(asio::ssl::stream_base::client,
                             asio::use_awaitable);
  co_await getOn(s, im, target, auth, code, out);
}

}  // namespace

uint32_t ThinkHttpsBackend::contextWindow() {
  if (!valid_) return 0;
  std::lock_guard<std::mutex> g(windowMu_);
  const auto now = std::chrono::steady_clock::now();
  if (windowKnown_) return window_;
  if (windowAskedAt_ != std::chrono::steady_clock::time_point{} &&
      now - windowAskedAt_ < std::chrono::minutes(10))
    return 0;
  windowAskedAt_ = now;
  asio::io_context ioc;
  unsigned code = 0;
  std::string body;
  bool failed = false;
  asio::co_spawn(ioc,
                 getAsync(*impl_, impl_->ctx.get(), now + std::chrono::seconds(5),
                          impl_->prefix + "/models", "Bearer " + cfg_.apiKey, code,
                          body),
                 [&failed](std::exception_ptr e) { failed = e != nullptr; });
  ioc.run();
  if (failed || code != 200) return 0;   // ask again later
  window_ = thinkModelWindow(body, cfg_.model);
  windowKnown_ = true;
  return window_;
}

ThinkHttpsBackend::ThinkHttpsBackend(ThinkHttpsConfig cfg)
    : cfg_(std::move(cfg)), impl_(std::make_unique<Impl>()) {
  std::string prefix;
  if (!thinkParseBaseUrl(cfg_.baseUrl, impl_->tls, impl_->host, impl_->port,
                         prefix))
    return;
  impl_->prefix = prefix;
  impl_->target = prefix + "/chat/completions";
  if (impl_->tls) {
    try {
      impl_->ctx = std::make_unique<asio::ssl::context>(
          asio::ssl::context::tls_client);
      impl_->ctx->set_default_verify_paths();
      impl_->ctx->set_verify_mode(asio::ssl::verify_peer);
    } catch (const std::exception&) {
      return;
    }
  }
  valid_ = true;
}

ThinkHttpsBackend::~ThinkHttpsBackend() = default;

ThinkOutcome ThinkHttpsBackend::run(
    const ThinkInput& input, uint32_t maxOut, const std::atomic<bool>& stop,
    const std::function<bool(std::string_view)>& onText) {
  ThinkOutcome fail;
  fail.status = CES_ERROR_DISABLED;
  if (!valid_) return fail;

  const auto deadline = std::chrono::steady_clock::now() + cfg_.timeout;
  asio::io_context ioc;
  Call c;
  c.stop = &stop;
  c.onText = &onText;
  asio::co_spawn(
      ioc,
      callAsync(*impl_, impl_->ctx.get(), deadline,
                "Bearer " + cfg_.apiKey,
                thinkRequestJson(cfg_.model, input, maxOut, cfg_.reasoning),
                c),
      [&c, deadline](std::exception_ptr e) {
        c.finished = true;
        if (!e) return;
        try {
          std::rethrow_exception(e);
        } catch (const boost::system::system_error& se) {
          const bool late = std::chrono::steady_clock::now() >= deadline ||
                            se.code() == beast::error::timeout;
          c.out.status = late ? CES_ERROR_TIMEOUT : CES_ERROR_INTERNAL;
          c.out.detail = se.code().message();
        } catch (const std::exception& ex) {
          c.out.status = CES_ERROR_INTERNAL;
          c.out.detail = ex.what();
        }
        if (c.parser.hasUsage()) {
          c.out.usage = c.parser.usage();
          c.out.billing = ThinkOutcome::kUsage;
        }
      });
  bool cancelled = false;
  while (!c.finished) {
    ioc.run_for(std::chrono::milliseconds(100));
    if (ioc.stopped() && !c.finished) ioc.restart();
    if (!cancelled && stop.load() && !c.finished && c.low) {
      // This thread runs the io_context, so the socket is safe to touch.
      // c.low is set only while the coroutine that owns the stream lives.
      c.low->cancel();
      cancelled = true;
    }
  }
  return c.out;
}

}  // namespace ces

#endif  // CES_THINK
