#pragma once

#include <cstdint>
#include <string_view>

namespace ces {

// Loadables are Lua files under /s/loadables/ that programs run with ces.load.
inline constexpr std::string_view kLoadablesDir = "s/loadables";  // in the file store

inline constexpr uint64_t kLoadableMaxBytes = 1024 * 1024;
inline constexpr size_t kLoadablePathMax = 200;

// Parts joined by "/", each of letters, digits, ".", "-" and "_", starting
// with a letter, a digit, "-" or "_".
bool isLoadablePath(std::string_view path);

}  // namespace ces
