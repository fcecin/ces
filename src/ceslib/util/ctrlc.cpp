/**
 * ctrlc.cpp
 */

#if defined(CES_HAVE_STACKTRACE)
#include <boost/stacktrace.hpp>
#endif
#include <ces/util/ctrlc.h>
#include <cstdlib>
#include <iostream>

namespace ces {
namespace internal {
volatile std::sig_atomic_t g_interrupted = 0;
}

extern "C" void interrupt_handler(int) { internal::g_interrupted += 1; }

// The stack trace rides libbacktrace (Linux only); elsewhere the handler
// still reports and exits, without a trace.
extern "C" void abrt_handler(int s) {
  std::cerr << "SIGABRT\n";
#if defined(CES_HAVE_STACKTRACE)
  std::cerr << boost::stacktrace::stacktrace() << std::endl;
#endif
  std::_Exit(s);
}

extern "C" void segv_handler(int s) {
  std::cerr << "SIGSEGV\n";
#if defined(CES_HAVE_STACKTRACE)
  std::cerr << boost::stacktrace::stacktrace() << std::endl;
#endif
  std::_Exit(s);
}

struct SignalInstaller {
  SignalInstaller() {
    std::signal(SIGINT, interrupt_handler);
    std::signal(SIGTERM, interrupt_handler);
    std::signal(SIGABRT, abrt_handler);
    std::signal(SIGSEGV, segv_handler);
  }
};

static SignalInstaller auto_installer;
} // namespace ces
