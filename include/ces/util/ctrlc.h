#pragma once

#include <chrono>
#include <csignal>
#include <thread>

namespace ces {
namespace internal {
extern volatile std::sig_atomic_t g_interrupted;
}
inline bool interrupted() { return internal::g_interrupted != 0; }
inline bool notInterrupted() { return internal::g_interrupted == 0; }
inline int interruptCount() { return internal::g_interrupted; }

enum class WaitResult {
  Success,
  Timeout,
  Interrupted
};

template <typename Predicate>
inline WaitResult waitFor(uint64_t millis, Predicate pred) {
  auto duration = std::chrono::milliseconds(millis);
  auto start = std::chrono::steady_clock::now();
  while (std::chrono::steady_clock::now() - start < duration) {
    if (ces::interrupted())
      return WaitResult::Interrupted;
    if (pred())
      return WaitResult::Success;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  return pred() ? WaitResult::Success : WaitResult::Timeout;
}

inline bool sleep(uint64_t millis) {
  return waitFor(millis, [] { return false; }) == WaitResult::Timeout;
}

} // namespace ces
