// think_https.h - the real backend of builtin:think: one OpenAI-format
// POST <base>/chat/completions per call, streamed (SSE), over HTTPS with
// certificate and host name checks (plain http:// is accepted for a local
// model server). Built only with CES_THINK (needs OpenSSL).
//
// The model's context window comes from GET <base>/models, asked once (see
// contextWindow).
//
// Each call runs on the caller's thread with its own io_context. The
// configured timeout bounds the whole call. `stop` ends it within ~100 ms.

#pragma once

#ifdef CES_THINK

#include <ces/l2/think_backend.h>

#include <chrono>
#include <memory>
#include <mutex>
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
  ThinkOutcome run(const ThinkInput& input, uint32_t maxOut,
                   const std::atomic<bool>& stop,
                   const std::function<bool(std::string_view)>& onText)
      override;
  // Asks GET <base>/models on the first use and keeps the answer (an API
  // that lists the model with no window gives 0 for good). When the API
  // does not answer, it asks again after 10 minutes. A call waits at most
  // 5 s for it.
  uint32_t contextWindow() override;

  struct Impl;

 private:
  ThinkHttpsConfig cfg_;
  bool valid_ = false;
  std::unique_ptr<Impl> impl_;
  std::mutex windowMu_;
  bool windowKnown_ = false;
  uint32_t window_ = 0;
  std::chrono::steady_clock::time_point windowAskedAt_{};
};

}  // namespace ces

#endif  // CES_THINK
