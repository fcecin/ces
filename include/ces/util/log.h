#pragma once

/**
 * Shared log-level parsing for CLI binaries.
 *
 * Accepts the first letter (trace/debug/info/warning/error/fatal or t/d/i/w/e/f)
 * case-insensitively. Throws std::runtime_error on unknown input.
 */

#include <minx/blog.h>

#include <cctype>
#include <stdexcept>
#include <string>

namespace ces {

inline void setupLogger(const std::string& logLevel) {
  if (logLevel.empty())
    throw std::invalid_argument("empty log level");

  switch (std::tolower(static_cast<unsigned char>(logLevel[0]))) {
  case 't': blog::set_level(blog::trace);   return;
  case 'd': blog::set_level(blog::debug);   return;
  case 'i': blog::set_level(blog::info);    return;
  case 'w': blog::set_level(blog::warning); return;
  case 'e': blog::set_level(blog::error);   return;
  case 'f': blog::set_level(blog::fatal);   return;
  }

  throw std::invalid_argument("unsupported log level: " + logLevel);
}

} // namespace ces
