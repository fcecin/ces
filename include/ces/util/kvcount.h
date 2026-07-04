#pragma once

// Count entries in a canonical length-prefixed KV dump by their key's first byte.

#include <cstdint>
#include <span>

namespace ces {

// Count entries whose key's first byte == prefix. Format is [u32 BE count] then per entry
// [u32 BE keylen][key][u32 BE vallen][val], all big-endian -- hyle State::canonical(). Used to
// split account ('a') vs entry ('e') cells for ces.hyle.solo. A truncated or malformed buffer
// stops the walk and returns the count so far; never reads out of bounds.
uint64_t countCanonicalKvKeyPrefix(std::span<const uint8_t> canon, uint8_t prefix);

}  // namespace ces
