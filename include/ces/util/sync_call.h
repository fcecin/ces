// sync_call.h - run a task on another executor and wait for its result.
//
// A blocking hop posts a task and waits on a future. The task must set that
// future on every exit: with its value, or with the exception it throws.
// Else a throw leaves the caller waiting for ever. On rpcTaskIO, the thread
// of every CesPlex verb, that stops the whole service.
//
// makeSyncTask(f) returns the task to post and the future to wait on. The
// task runs f, and gives f's result or f's exception to the future. The
// promise lives in the task, so a task that is destroyed without running
// gives std::future_error (broken_promise) to the caller, not a hang.
// `f` must stay alive until the future is ready (the caller waits on it).

#pragma once

#include <exception>
#include <future>
#include <memory>
#include <type_traits>
#include <utility>

#include <boost/asio/post.hpp>

namespace ces {

template <class F>
auto makeSyncTask(F& f) {
  using R = std::invoke_result_t<F&>;
  auto pr = std::make_shared<std::promise<R>>();
  std::future<R> fut = pr->get_future();
  auto task = [pr, &f]() {
    try {
      if constexpr (std::is_void_v<R>) {
        f();
        pr->set_value();
      } else {
        pr->set_value(f());
      }
    } catch (...) {
      pr->set_exception(std::current_exception());
    }
  };
  return std::make_pair(std::move(task), std::move(fut));
}

// Run `f` on `ex` and wait. Returns f's result, or throws what f threw. The
// caller must not be on `ex` (that would deadlock).
template <class Executor, class F>
auto runSync(const Executor& ex, F&& f) {
  auto [task, fut] = makeSyncTask(f);
  boost::asio::post(ex, std::move(task));
  return fut.get();
}

}  // namespace ces
