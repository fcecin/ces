// Waits for compute instance state in tests. A test waits for the event it
// needs, not for a guessed time: a loaded machine can take any time to start
// a child, and a fixed sleep then fails the test. The limit only bounds a
// failure, so it is generous.

#pragma once

#include <ces/server.h>
#include <ces/l2/compute_handler.h>
#include <ces/util/sync_call.h>

#include <chrono>
#include <thread>

namespace ces {

inline constexpr std::chrono::seconds kTestWaitLimit{60};

// Poll `cond` until it is true or `limit` passes.
template <class F>
bool waitUntil(F&& cond,
               std::chrono::steady_clock::duration limit = kTestWaitLimit) {
  const auto end = std::chrono::steady_clock::now() + limit;
  for (;;) {
    if (cond()) return true;
    if (std::chrono::steady_clock::now() >= end) return false;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}

// The child of `pid` has connected its IPC socket, so a deliver to it is no
// longer dropped.
inline bool waitInstanceConnected(CesServer& s, uint64_t pid) {
  return waitUntil([&] {
    return s.computeHandler()->testInstanceConnected(pid);
  });
}

// The program of `pid` called ces.conn.set_listener, so an ATTACH can land.
inline bool waitInstanceListening(CesServer& s, uint64_t pid) {
  return waitUntil([&] {
    return runSync(s._rpcTaskIOExecutor(), [&] {
      return s.computeHandler()->instanceAcceptsConnections(pid);
    });
  });
}

// The instance `pid` is gone from the supervisor.
inline bool waitInstanceGone(CesServer& s, uint64_t pid) {
  return waitUntil([&] {
    return !runSync(s._rpcTaskIOExecutor(), [&] {
      return s.computeHandler()->instanceExists(pid);
    });
  });
}

}  // namespace ces
