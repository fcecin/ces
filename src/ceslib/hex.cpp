#include <ces/util/hex.h>

#include <stdexcept>

namespace ces {

namespace {

// Returns 0..15 on valid hex char; throws on invalid.
uint8_t hexNibble(char c) {
  if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
  if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(10 + (c - 'a'));
  if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(10 + (c - 'A'));
  throw std::invalid_argument("parseHex: non-hex character");
}

} // namespace

ces::Bytes parseHex(std::string_view hex) {
  ces::Bytes out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    uint8_t hi = hexNibble(hex[i]);
    uint8_t lo = hexNibble(hex[i + 1]);
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return out;
}

std::string bytesToHex(std::span<const uint8_t> bytes) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.resize(bytes.size() * 2);
  for (size_t i = 0; i < bytes.size(); ++i) {
    uint8_t b = bytes[i];
    out[i * 2]     = kDigits[(b >> 4) & 0xF];
    out[i * 2 + 1] = kDigits[b & 0xF];
  }
  return out;
}

} // namespace ces
