#include <ces/util/server_key_file.h>

#include <toml++/toml.hpp>

#include <fstream>
#include <sstream>

namespace ces {

std::string readServerKeyFile(const std::string& path) {
  std::ifstream f(path);
  if (!f) return {};
  std::stringstream ss;
  ss << f.rdbuf();
  const std::string text = ss.str();
  try {
    auto tbl = toml::parse(text);
    return tbl["server_key"].value_or(std::string{});
  } catch (const toml::parse_error&) {
    // Not TOML: the hex alone.
  }
  const char* ws = " \t\r\n";
  size_t a = text.find_first_not_of(ws);
  if (a == std::string::npos) return {};
  size_t b = text.find_last_not_of(ws);
  return text.substr(a, b - a + 1);
}

}  // namespace ces
