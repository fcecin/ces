#pragma once

#include <functional>

namespace ces {

// Invoke runFn (typically an io_context::run() call, or any worker-thread body)
// so that an exception escaping it is logged at ERROR and runFn is retried — a
// leaf/auxiliary thread must never let an uncaught exception std::terminate the
// whole process. Returns when runFn completes cleanly (e.g. the io_context was
// stopped). Use as the std::thread body:
//   std::thread([&]{ runGuardedThread([&]{ io.run(); }, "myIO"); })
void runGuardedThread(const std::function<void()>& runFn, const char* threadName);

}  // namespace ces
