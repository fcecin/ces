// think_backend.cpp - see think_backend.h.
//
// ceslib uses Boost.JSON header-only (see util/boost_json.cpp).

#include <ces/l2/think_backend.h>

#include <boost/json.hpp>

#include <cstring>
#include <initializer_list>

namespace ces {

namespace json = boost::json;

namespace {

// True for a function name of 1 to 64 letters, digits, '_' and '-'.
bool goodName(const json::value* v) {
  if (!v || !v->is_string()) return false;
  const json::string& s = v->as_string();
  if (s.empty() || s.size() > 64) return false;
  for (char c : s)
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '_' || c == '-'))
      return false;
  return true;
}

bool isString(const json::value* v) { return v && v->is_string(); }

// True when `o` has no key outside `keys`.
bool onlyKeys(const json::object& o, std::initializer_list<const char*> keys) {
  for (const auto& kv : o) {
    bool known = false;
    for (const char* k : keys) known = known || kv.key() == k;
    if (!known) return false;
  }
  return true;
}

// The checks of thinkChatCheck. Each returns "" when the value is good, and
// writes its clean form to `out`.
std::string checkToolCall(const json::value& v, json::object& out) {
  if (!v.is_object()) return "a tool call is not an object";
  const json::object& o = v.as_object();
  if (!onlyKeys(o, {"id", "type", "function"})) return "a tool call has an unknown field";
  const json::value* id = o.if_contains("id");
  const json::value* type = o.if_contains("type");
  const json::value* fn = o.if_contains("function");
  if (!isString(id) || id->as_string().empty()) return "a tool call has no id";
  if (type && !(type->is_string() && type->as_string() == "function"))
    return "a tool call's type is not \"function\"";
  if (!fn || !fn->is_object()) return "a tool call has no function";
  const json::object& f = fn->as_object();
  if (!onlyKeys(f, {"name", "arguments"})) return "a tool call's function has an unknown field";
  if (!goodName(f.if_contains("name"))) return "a tool call's function has a bad name";
  if (!isString(f.if_contains("arguments"))) return "a tool call's function has no arguments text";
  out["id"] = *id;
  out["type"] = "function";
  out["function"] = json::object{{"name", f.at("name")}, {"arguments", f.at("arguments")}};
  return {};
}

std::string checkMessage(const json::value& v, json::object& out) {
  if (!v.is_object()) return "a message is not an object";
  const json::object& o = v.as_object();
  const json::value* role = o.if_contains("role");
  if (!isString(role)) return "a message has no role";
  const json::string& r = role->as_string();
  const json::value* content = o.if_contains("content");
  out["role"] = r;
  if (r == "system" || r == "user") {
    if (!onlyKeys(o, {"role", "content"})) return "a " + std::string(r) + " message has an unknown field";
    if (!isString(content)) return "a " + std::string(r) + " message has no content text";
    out["content"] = *content;
    return {};
  }
  if (r == "tool") {
    if (!onlyKeys(o, {"role", "tool_call_id", "content"})) return "a tool message has an unknown field";
    const json::value* id = o.if_contains("tool_call_id");
    if (!isString(id) || id->as_string().empty()) return "a tool message has no tool_call_id";
    if (!isString(content)) return "a tool message has no content text";
    out["tool_call_id"] = *id;
    out["content"] = *content;
    return {};
  }
  if (r != "assistant") return "a message has the unknown role \"" + std::string(r) + "\"";
  if (!onlyKeys(o, {"role", "content", "reasoning_content", "tool_calls"}))
    return "an assistant message has an unknown field";
  if (content && !content->is_string() && !content->is_null())
    return "an assistant message's content is not text";
  const json::value* reasoning = o.if_contains("reasoning_content");
  if (reasoning && !reasoning->is_string() && !reasoning->is_null())
    return "an assistant message's reasoning_content is not text";
  const json::value* calls = o.if_contains("tool_calls");
  if (calls && !calls->is_array() && !calls->is_null())
    return "an assistant message's tool_calls is not an array";
  const bool hasCalls = calls && calls->is_array() && !calls->as_array().empty();
  if (!isString(content) && !hasCalls) return "an assistant message has no content and no tool calls";
  out["content"] = isString(content) ? *content : json::value(nullptr);
  if (isString(reasoning)) out["reasoning_content"] = *reasoning;
  if (hasCalls) {
    json::array a;
    for (const json::value& c : calls->as_array()) {
      json::object call;
      std::string e = checkToolCall(c, call);
      if (!e.empty()) return e;
      a.push_back(std::move(call));
    }
    out["tool_calls"] = std::move(a);
  }
  return {};
}

std::string checkTool(const json::value& v, json::object& out) {
  if (!v.is_object()) return "a tool is not an object";
  const json::object& o = v.as_object();
  if (!onlyKeys(o, {"type", "function"})) return "a tool has an unknown field";
  const json::value* type = o.if_contains("type");
  if (!(isString(type) && type->as_string() == "function")) return "a tool's type is not \"function\"";
  const json::value* fn = o.if_contains("function");
  if (!fn || !fn->is_object()) return "a tool has no function";
  const json::object& f = fn->as_object();
  if (!onlyKeys(f, {"name", "description", "parameters"})) return "a tool's function has an unknown field";
  if (!goodName(f.if_contains("name"))) return "a tool's function has a bad name";
  json::object g;
  g["name"] = f.at("name");
  if (const json::value* d = f.if_contains("description")) {
    if (!d->is_string()) return "a tool's description is not text";
    g["description"] = *d;
  }
  if (const json::value* p = f.if_contains("parameters")) {
    if (!p->is_object()) return "a tool's parameters is not an object";
    g["parameters"] = *p;
  }
  out["type"] = "function";
  out["function"] = std::move(g);
  return {};
}

std::string checkToolChoice(const json::value& v, json::value& out) {
  if (v.is_string()) {
    const json::string& s = v.as_string();
    if (s != "auto" && s != "none" && s != "required") return "tool_choice is not auto, none or required";
    out = v;
    return {};
  }
  if (!v.is_object()) return "tool_choice is not text or an object";
  const json::object& o = v.as_object();
  const json::value* type = o.if_contains("type");
  const json::value* fn = o.if_contains("function");
  if (!onlyKeys(o, {"type", "function"}) || !(isString(type) && type->as_string() == "function") ||
      !fn || !fn->is_object() || !onlyKeys(fn->as_object(), {"name"}) ||
      !goodName(fn->as_object().if_contains("name")))
    return "tool_choice names no function";
  out = json::object{{"type", "function"},
                     {"function", json::object{{"name", fn->as_object().at("name")}}}};
  return {};
}

}  // namespace

bool thinkChatCheck(std::string_view request, std::string& out,
                    std::string* why) {
  auto fail = [&](std::string e) {
    if (why) *why = std::move(e);
    return false;
  };
  boost::system::error_code ec;
  json::value v = json::parse(request, ec);
  if (ec) return fail("the request is not JSON (" + ec.message() + ")");
  if (!v.is_object()) return fail("the request is not a JSON object");
  const json::object& o = v.as_object();
  if (!onlyKeys(o, {"messages", "tools", "tool_choice"}))
    return fail("the request has a field other than messages, tools and tool_choice");
  const json::value* messages = o.if_contains("messages");
  if (!messages || !messages->is_array() || messages->as_array().empty())
    return fail("the request has no messages");
  json::object clean;
  json::array ms;
  for (const json::value& m : messages->as_array()) {
    json::object c;
    std::string e = checkMessage(m, c);
    if (!e.empty()) return fail(e);
    ms.push_back(std::move(c));
  }
  clean["messages"] = std::move(ms);
  if (const json::value* tools = o.if_contains("tools")) {
    if (!tools->is_array()) return fail("tools is not an array");
    json::array ts;
    for (const json::value& t : tools->as_array()) {
      json::object c;
      std::string e = checkTool(t, c);
      if (!e.empty()) return fail(e);
      ts.push_back(std::move(c));
    }
    if (!ts.empty()) clean["tools"] = std::move(ts);
  }
  if (const json::value* choice = o.if_contains("tool_choice")) {
    json::value c;
    std::string e = checkToolChoice(*choice, c);
    if (!e.empty()) return fail(e);
    clean["tool_choice"] = std::move(c);
  }
  out = json::serialize(clean);
  return true;
}

std::string thinkRequestJson(const std::string& model, const ThinkInput& input,
                             uint32_t maxOut, bool reasoning) {
  json::object req;
  req["model"] = model;
  if (input.chat) {
    // thinkChatCheck wrote this text, so it parses, and has only its fields.
    json::value chat = json::parse(input.text);
    for (auto& kv : chat.as_object()) req[kv.key()] = std::move(kv.value());
  } else {
    json::object msg;
    msg["role"] = "user";
    msg["content"] = input.text;
    req["messages"] = json::array{std::move(msg)};
  }
  req["max_tokens"] = maxOut;
  req["stream"] = true;
  req["stream_options"] = json::object{{"include_usage", true}};
  req["thinking"] = json::object{{"type", reasoning ? "enabled" : "disabled"}};
  return json::serialize(req);
}

namespace {

json::object chatEndObject(const ThinkChatEnd& end) {
  json::object o;
  json::value calls = json::array{};
  if (!end.toolCalls.empty()) {
    boost::system::error_code ec;
    json::value v = json::parse(end.toolCalls, ec);
    if (!ec && v.is_array()) calls = std::move(v);
  }
  o["tool_calls"] = std::move(calls);
  if (!end.reasoning.empty()) o["reasoning_content"] = end.reasoning;
  o["finish_reason"] = end.finishReason;
  return o;
}

}  // namespace

std::string thinkChatEndJson(const ThinkChatEnd& end) {
  return json::serialize(chatEndObject(end));
}

bool thinkChatEndParse(std::string_view text, ThinkChatEnd& end) {
  end = ThinkChatEnd{};
  boost::system::error_code ec;
  json::value v = json::parse(text, ec);
  if (ec || !v.is_object()) return false;
  const json::object& o = v.as_object();
  const json::value* fr = o.if_contains("finish_reason");
  const json::value* calls = o.if_contains("tool_calls");
  const json::value* reasoning = o.if_contains("reasoning_content");
  if ((fr && !fr->is_string()) || (calls && !calls->is_array()) ||
      (reasoning && !reasoning->is_string()))
    return false;
  if (fr) end.finishReason = std::string(fr->as_string());
  if (calls && !calls->as_array().empty()) end.toolCalls = json::serialize(*calls);
  if (reasoning) end.reasoning = std::string(reasoning->as_string());
  return true;
}

std::string thinkChatReplyJson(const std::string& content,
                               const ThinkChatEnd& end) {
  json::object o;
  o["content"] = content;
  for (auto& kv : chatEndObject(end)) o[kv.key()] = std::move(kv.value());
  return json::serialize(o);
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
    const json::value* fr = ch.as_object().if_contains("finish_reason");
    if (fr && fr->is_string()) finishReason_ = std::string(fr->as_string());
    auto d = ch.as_object().find("delta");
    if (d == ch.as_object().end() || !d->value().is_object()) continue;
    const json::object& delta = d->value().as_object();
    auto r = delta.find("reasoning_content");
    if (r != delta.end() && r->value().is_string()) {
      reasoningBytes_ += r->value().as_string().size();
      reasoning_.append(r->value().as_string().data(), r->value().as_string().size());
    }
    if (!toolDeltas(delta.if_contains("tool_calls"))) return false;
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

bool ThinkSseParser::toolDeltas(const json::value* v) {
  if (!v || v->is_null()) return true;
  if (!v->is_array()) return false;
  // The most calls in one reply. A backend that sends more is broken.
  constexpr uint64_t kMaxCalls = 128;
  for (const json::value& d : v->as_array()) {
    if (!d.is_object()) return false;
    const json::object& o = d.as_object();
    // A delta names its call by index. One with no index goes on the last.
    uint64_t i = calls_.empty() ? 0 : calls_.size() - 1;
    if (const json::value* ix = o.if_contains("index")) {
      if (ix->is_uint64()) i = ix->as_uint64();
      else if (ix->is_int64() && ix->as_int64() >= 0) i = static_cast<uint64_t>(ix->as_int64());
      else return false;
    }
    if (i >= kMaxCalls) return false;
    if (calls_.size() <= i) calls_.resize(i + 1);
    ToolCall& call = calls_[i];
    auto text = [](const json::object& from, const char* key) -> const json::string* {
      const json::value* x = from.if_contains(key);
      return x && x->is_string() ? &x->as_string() : nullptr;
    };
    if (auto id = text(o, "id"); id && !id->empty()) call.id = std::string(*id);
    if (auto type = text(o, "type"); type && !type->empty()) call.type = std::string(*type);
    const json::value* fn = o.if_contains("function");
    if (fn && fn->is_object()) {
      if (auto name = text(fn->as_object(), "name")) {
        call.name.append(name->data(), name->size());
        toolBytes_ += name->size();
      }
      if (auto args = text(fn->as_object(), "arguments")) {
        call.arguments.append(args->data(), args->size());
        toolBytes_ += args->size();
      }
    }
  }
  return true;
}

ThinkChatEnd ThinkSseParser::chatEnd() const {
  ThinkChatEnd end;
  end.reasoning = reasoning_;
  end.finishReason = finishReason_;
  json::array a;
  for (const ToolCall& c : calls_) {
    if (c.id.empty() && c.name.empty() && c.arguments.empty()) continue;   // an unused index
    a.push_back(json::object{
        {"id", c.id},
        {"type", c.type.empty() ? "function" : c.type},
        {"function", json::object{{"name", c.name}, {"arguments", c.arguments}}}});
  }
  if (!a.empty()) end.toolCalls = json::serialize(a);
  return end;
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
