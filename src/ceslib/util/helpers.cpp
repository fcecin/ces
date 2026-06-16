#include <ces/util/helpers.h>

#include <minx/blog.h>

LOG_MODULE("csv");

namespace ces {

void runGuardedThread(const std::function<void()>& runFn,
                      const char* threadName) {
  for (;;) {
    try {
      runFn();
      return;  // clean completion (e.g. the io_context was stopped)
    } catch (const std::exception& e) {
      LOGERROR << "worker thread escaped an exception; re-entering its run loop"
               << SVAR(threadName) << SVAR(e.what());
    } catch (...) {
      LOGERROR << "worker thread escaped an unknown exception; re-entering its"
                  " run loop" << SVAR(threadName);
    }
  }
}

}  // namespace ces
