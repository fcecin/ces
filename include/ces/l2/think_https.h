// think_https.h - the real backend of builtin:think: one OpenAI-format
// POST <base>/chat/completions per call, streamed (SSE), over HTTPS with
// certificate and host name checks (plain http:// is accepted for a local
// model server). Built only with CES_THINK (needs OpenSSL).
//
// Each call runs on the caller's thread with its own io_context. The
// configured timeout bounds the whole call. `stop` ends it within ~100 ms.

#pragma once

#ifdef CES_THINK

#include <ces/l2/think_backend.h>

#include <chrono>
#include <memory>
#include <string>

namespace ces {

struct ThinkHttpsConfig {
  std::string baseUrl;    // e.g. "https://api.deepseek.com"
  std::string apiKey;     // sent as "Authorization: Bearer <key>"
  std::string model;
  bool reasoning = false;
  std::chrono::seconds timeout{300};
};

class ThinkHttpsBackend : public ThinkBackend {
 public:
  explicit ThinkHttpsBackend(ThinkHttpsConfig cfg);
  ~ThinkHttpsBackend() override;
  // False when the base URL does not parse or TLS setup failed.
  bool valid() const { return valid_; }
  ThinkOutcome run(const std::string& prompt, uint32_t maxOut,
                   const std::atomic<bool>& stop,
                   const std::function<bool(std::string_view)>& onText)
      override;

  struct Impl;

 private:
  ThinkHttpsConfig cfg_;
  bool valid_ = false;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ces

#endif  // CES_THINK
