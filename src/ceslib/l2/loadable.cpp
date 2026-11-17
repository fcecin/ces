#include <ces/l2/loadable.h>

namespace ces {

bool isLoadablePath(std::string_view path) {
  if (path.empty() || path.size() > kLoadablePathMax) return false;
  size_t start = 0;
  for (;;) {
    size_t slash = path.find('/', start);
    std::string_view part = path.substr(start, slash == std::string_view::npos
                                                 ? std::string_view::npos
                                                 : slash - start);
    if (part.empty() || part.front() == '.') return false;
    for (char c : part) {
      bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
      if (!ok) return false;
    }
    if (slash == std::string_view::npos) return true;
    start = slash + 1;
  }
}

}  // namespace ces
