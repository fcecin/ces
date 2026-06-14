/**
 * ctrlc.cpp
 */

#include <boost/stacktrace.hpp>
#include <ces/util/ctrlc.h>
#include <iostream>

namespace ces {
namespace internal {
volatile std::sig_atomic_t g_interrupted = 0;
}

extern "C" void interrupt_handler(int) { internal::g_interrupted += 1; }

extern "C" void abrt_handler(int s) {
  std::cerr << "SIGABRT\n";
  std::cerr << boost::stacktrace::stacktrace() << std::endl;
  std::exit(s);
}

extern "C" void segv_handler(int s) {
  std::cerr << "SIGSEGV\n";
  std::cerr << boost::stacktrace::stacktrace() << std::endl;
  std::exit(s);
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