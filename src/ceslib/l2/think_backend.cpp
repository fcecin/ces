// think_backend.cpp - see think_backend.h.
//
// Boost.JSON is used header-only: this is the one translation unit that
// compiles its implementation (boost/json/src.hpp), so no Boost.JSON library
// is linked. Other units must not include src.hpp.

#include <ces/l2/think_backend.h>

#include <boost/json/src.hpp>

#include <cstring>

namespace ces {

namespace json = boost::json;

std::string thinkRequestJson(const std::string& model,
                             const std::string& prompt, uint32_t maxOut,
                             bool reasoning) {
  json::object msg;
  msg["role"] = "user";
  msg["content"] = prompt;
  json::array messages;
  messages.push_back(std::move(msg));
  json::object req;
  req["model"] = model;
  req["messages"] = std::move(messages);
  req["max_tokens"] = maxOut;
  req["stream"] = true;
  req["stream_options"] = json::object{{"include_usage", true}};
  req["thinking"] = json::object{{"type", reasoning ? "enabled" : "disabled"}};
  return json::serialize(req);
}

namespace {

uint64_t u64At(const json::object& o, const char* key) {
  auto it = o.find(key);
  if (it == o.end()) return 0;
  if (it->value().is_uint64()) return it->value().as_uint64();
  if (it->value().is_int64() && it->value().as_int64() > 0)
    return static_cast<uint64_t>(it->value().as_int64());
  return 0;
}

std::string errorOf(const json::object& o) {
  auto it = o.find("error");
  if (it == o.end()) return {};
  const json::value& e = it->value();
  if (e.is_string()) return std::string(e.as_string());
  if (e.is_object()) {
    auto m = e.as_object().find("message");
    if (m != e.as_object().end() && m->value().is_string())
      return std::string(m->value().as_string());
  }
  return "error";
}

}  // namespace

bool ThinkSseParser::feed(std::string_view bytes,
                          const std::function<bool(std::string_view)>& onText) {
  buf_.append(bytes.data(), bytes.size());
  // One event is one small JSON chunk. A backend that sends this much with
  // no event end is broken; stop instead of buffering without bound.
  constexpr size_t kMaxPending = 1024 * 1024;
  if (buf_.size() > kMaxPending && buf_.find("\n\n") == std::string::npos &&
      buf_.find("\r\n\r\n") == std::string::npos)
    return false;
  // Events end at a blank line. Accept LF and CRLF line ends.
  for (;;) {
    if (done_) { buf_.clear(); return true; }
    size_t end = std::string::npos, skip = 0;
    size_t lf = buf_.find("\n\n");
    size_t crlf = buf_.find("\r\n\r\n");
    if (lf != std::string::npos && (crlf == std::string::npos || lf < crlf)) {
      end = lf; skip = 2;
    } else if (crlf != std::string::npos) {
      end = crlf; skip = 4;
    }
    if (end == std::string::npos) return true;
    std::string ev = buf_.substr(0, end);
    buf_.erase(0, end + skip);
    // Join the data lines of the event. Other fields and comments
    // (": keep-alive") carry no reply data.
    std::string data;
    size_t pos = 0;
    while (pos <= ev.size()) {
      size_t nl = ev.find('\n', pos);
      std::string_view line(ev.data() + pos,
                            (nl == std::string::npos ? ev.size() : nl) - pos);
      if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
      if (line.substr(0, 5) == "data:") {
        line.remove_prefix(5);
        if (!line.empty() && line.front() == ' ') line.remove_prefix(1);
        if (!data.empty()) data.push_back('\n');
        data.append(line.data(), line.size());
      }
      if (nl == std::string::npos) break;
      pos = nl + 1;
    }
    if (data.empty()) continue;
    if (!event(data, onText)) return false;
  }
}

bool ThinkSseParser::event(std::string_view data,
                           const std::function<bool(std::string_view)>& onText) {
  if (data == "[DONE]") { done_ = true; return true; }
  boost::system::error_code ec;
  json::value v = json::parse(data, ec);
  if (ec || !v.is_object()) return false;
  const json::object& o = v.as_object();
  std::string err = errorOf(o);
  if (!err.empty()) { error_ = err; return true; }
  auto u = o.find("usage");
  if (u != o.end() && u->value().is_object()) {
    const json::object& uo = u->value().as_object();
    usage_.promptTokens = u64At(uo, "prompt_tokens");
    usage_.outputTokens = u64At(uo, "completion_tokens");
    usage_.cachedTokens = u64At(uo, "prompt_cache_hit_tokens");
    if (usage_.cachedTokens == 0) {
      auto d = uo.find("prompt_tokens_details");
      if (d != uo.end() && d->value().is_object())
        usage_.cachedTokens = u64At(d->value().as_object(), "cached_tokens");
    }
    if (usage_.cachedTokens > usage_.promptTokens)
      usage_.cachedTokens = usage_.promptTokens;
    hasUsage_ = true;
  }
  auto c = o.find("choices");
  if (c == o.end() || !c->value().is_array()) return true;
  for (const json::value& ch : c->value().as_array()) {
    if (!ch.is_object()) continue;
    auto d = ch.as_object().find("delta");
    if (d == ch.as_object().end() || !d->value().is_object()) continue;
    const json::object& delta = d->value().as_object();
    auto r = delta.find("reasoning_content");
    if (r != delta.end() && r->value().is_string())
      reasoningBytes_ += r->value().as_string().size();
    auto t = delta.find("content");
    if (t == delta.end() || !t->value().is_string()) continue;
    const json::string& s = t->value().as_string();
    if (s.empty()) continue;
    textBytes_ += s.size();
    if (stopped_) continue;   // the reader left; count, do not forward
    if (!onText(std::string_view(s.data(), s.size()))) stopped_ = true;
  }
  return true;
}

std::string thinkErrorMessage(std::string_view body) {
  boost::system::error_code ec;
  json::value v = json::parse(body, ec);
  if (!ec && v.is_object()) {
    std::string err = errorOf(v.as_object());
    if (!err.empty()) return err;
  }
  return std::string(body.substr(0, 200));
}

bool thinkParseBaseUrl(const std::string& url, bool& tls, std::string& host,
                       std::string& port, std::string& prefix) {
  std::string rest;
  if (url.rfind("https://", 0) == 0) {
    tls = true;
    rest = url.substr(8);
  } else if (url.rfind("http://", 0) == 0) {
    tls = false;
    rest = url.substr(7);
  } else {
    return false;
  }
  size_t slash = rest.find('/');
  std::string hostPort = rest.substr(0, slash);
  prefix = slash == std::string::npos ? "" : rest.substr(slash);
  while (!prefix.empty() && prefix.back() == '/') prefix.pop_back();
  size_t colon = hostPort.rfind(':');
  if (colon != std::string::npos && hostPort.find(']') == std::string::npos) {
    host = hostPort.substr(0, colon);
    port = hostPort.substr(colon + 1);
    if (port.empty() || port.find_first_not_of("0123456789") != std::string::npos)
      return false;
  } else {
    host = hostPort;
    port = tls ? "443" : "80";
  }
  return !host.empty();
}

bool thinkValidUtf8(std::string_view s) {
  const auto* p = reinterpret_cast<const unsigned char*>(s.data());
  size_t n = s.size(), i = 0;
  while (i < n) {
    unsigned char c = p[i];
    if (c < 0x80) { ++i; continue; }
    size_t len;
    uint32_t cp;
    if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1F; }
    else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0F; }
    else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07; }
    else return false;
    if (i + len > n) return false;
    for (size_t k = 1; k < len; ++k) {
      if ((p[i + k] & 0xC0) != 0x80) return false;
      cp = (cp << 6) | (p[i + k] & 0x3F);
    }
    // Overlong forms, surrogates and values past U+10FFFF are not UTF-8.
    if ((len == 2 && cp < 0x80) || (len == 3 && cp < 0x800) ||
        (len == 4 && cp < 0x10000) || cp > 0x10FFFF ||
        (cp >= 0xD800 && cp <= 0xDFFF))
      return false;
    i += len;
  }
  return true;
}

uint32_t thinkModelWindow(std::string_view modelsJson, const std::string& model) {
  boost::system::error_code ec;
  json::value v = json::parse(modelsJson, ec);
  if (ec || !v.is_object()) return 0;
  auto d = v.as_object().find("data");
  if (d == v.as_object().end() || !d->value().is_array()) return 0;
  for (const json::value& m : d->value().as_array()) {
    if (!m.is_object()) continue;
    const json::object& o = m.as_object();
    auto id = o.find("id");
    if (id == o.end() || !id->value().is_string() || id->value().as_string() != model) continue;
    const uint64_t w = u64At(o, "context_window");
    return w > UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(w);
  }
  return 0;
}

uint32_t thinkWindow(uint32_t ceiling, uint32_t fromApi) {
  if (fromApi == 0) return ceiling;
  if (ceiling == 0) return fromApi;
  return ceiling < fromApi ? ceiling : fromApi;
}

}  // namespace ces
