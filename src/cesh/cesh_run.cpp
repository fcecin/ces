#include "cesh_run.h"

#include <exception>
#include <iostream>
#include <sstream>

namespace {

// Point a standard stream at a string buffer, and put it back at scope end.
class StreamSwap {
public:
  StreamSwap(std::ios& s, std::streambuf* to) : s_(s), old_(s.rdbuf(to)) {}
  ~StreamSwap() {
    s_.rdbuf(old_);
    s_.clear();
  }
  StreamSwap(const StreamSwap&) = delete;
  StreamSwap& operator=(const StreamSwap&) = delete;

private:
  std::ios& s_;
  std::streambuf* old_;
};

}  // namespace

CeshResult ceshCapture(const std::vector<std::string>& args, const std::string& input) {
  std::vector<std::string> store;
  store.reserve(args.size() + 1);
  store.push_back("cesh");
  store.insert(store.end(), args.begin(), args.end());
  std::vector<char*> argv;
  for (auto& a : store) argv.push_back(a.data());
  argv.push_back(nullptr);

  std::istringstream in(input);
  std::ostringstream out, err;
  CeshResult r;
  {
    StreamSwap si(std::cin, in.rdbuf());
    StreamSwap so(std::cout, out.rdbuf());
    StreamSwap se(std::cerr, err.rdbuf());
    try {
      r.code = ceshRun(static_cast<int>(store.size()), argv.data());
    } catch (const std::exception& e) {
      std::cerr << "Error: " << e.what() << "\n";
      r.code = 1;
    } catch (...) {
      std::cerr << "Error: unknown exception\n";
      r.code = 1;
    }
    std::cout.flush();
    std::cerr.flush();
  }
  r.out = out.str();
  r.err = err.str();
  return r;
}
