// The pages of the cesh manual, compiled into the binary.
//
// The build generates the definitions from src/cesh/docs/**/*.md
// (src/cesh/man/embed_docs.cmake). Each entry is one markdown file, with its path
// relative to src/cesh/docs/ and its exact bytes.

#pragma once

#include <cstddef>

namespace ces::man {

struct EmbeddedPage {
  const char* file;   // "files/rent.md"
  const char* data;   // the bytes of the file (not 0-terminated by contract)
  std::size_t size;
};

extern const EmbeddedPage kManualPages[];
extern const std::size_t kManualPageCount;

}  // namespace ces::man
