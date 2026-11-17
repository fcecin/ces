#pragma once

#include <string>

namespace ces {

// The server key from a file: the 64 hex digits alone, or a TOML file with
// server_key = "<hex>". Returns the hex digits, or "" when the file cannot be
// read or holds neither. The caller checks the hex.
std::string readServerKeyFile(const std::string& path);

}  // namespace ces
