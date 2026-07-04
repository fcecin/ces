#include <ces/util/kvcount.h>

#include <ces/buffer.h>

namespace ces {

uint64_t countCanonicalKvKeyPrefix(std::span<const uint8_t> canon, uint8_t prefix) {
  const size_t len = canon.size();
  if (len < 4) return 0;
  size_t off = 0;
  const uint32_t count = Buffer::peek<uint32_t>(canon, off);
  off += 4;
  uint64_t matched = 0;
  for (uint32_t i = 0; i < count && off + 4 <= len; ++i) {
    const uint32_t klen = Buffer::peek<uint32_t>(canon, off);
    off += 4;
    if (klen > len - off) break;
    if (klen > 0 && canon[off] == prefix) ++matched;
    off += klen;
    if (off + 4 > len) break;
    const uint32_t vlen = Buffer::peek<uint32_t>(canon, off);
    off += 4;
    if (vlen > len - off) break;
    off += vlen;
  }
  return matched;
}

}  // namespace ces
