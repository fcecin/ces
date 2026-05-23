#pragma once

// Hex encoding helpers (free functions).

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include <ces/types.h>

namespace ces {

// Parse an ASCII hex string into raw bytes. Two characters = one byte,
// interpreted as big-endian-per-byte (standard hex dump layout).
// - An odd trailing character is silently ignored (matches existing
//   cesh callsite behavior).
// - Throws std::invalid_argument on non-hex characters.
// - Empty input yields an empty vector.
ces::Bytes parseHex(std::string_view hex);

// Format raw bytes as a lowercase ASCII hex string (2 chars per byte,
// no separators). Inverse of parseHex on valid inputs.
std::string bytesToHex(std::span<const uint8_t> bytes);

} // namespace ces
