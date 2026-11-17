// The confinement of a ceshd child, before it runs a cesh command.
//
// The child can read the system files that cesh needs (libraries, the name
// resolver files, /dev/null and /dev/urandom), and it can read and write
// its directory (its home, or its scratch directory). It can see no other
// file of the host. It cannot start a program, not even from its directory.
// It cannot open or accept a TCP connection, so --proxy cannot reach a local
// service.
// UDP stays open, because CES runs on UDP. Resource limits bound its CPU
// time, memory and file sizes.
//
// The file and TCP rules use Landlock. TCP rules need Landlock ABI 4
// (Linux 6.7).

#pragma once

#include <cstdint>
#include <string>

namespace ceshd {

inline constexpr int kMinLandlockAbi = 4;

struct Limits {
  uint64_t cpuSecs = 60;
  uint64_t memBytes = 1024ull << 20;
  uint64_t fileBytes = 64ull << 20;   // the largest file that the child can write
};

// The Landlock ABI of the running kernel, or 0 when Landlock is off.
int landlockAbi();

// Confines the calling process to `dir` and the system files. Returns an
// empty string, or the reason of the failure. The process cannot undo the
// confinement.
std::string confine(const std::string& dir, const Limits& limits);

}  // namespace ceshd
