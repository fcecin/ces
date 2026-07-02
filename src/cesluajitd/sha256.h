// SHA-256 for ces.sha256. Self-contained, no ceslib dependency, so cesluajitd
// stays small and independently debuggable. No crypto-strength claim needed:
// programs wanting real integrity already have CES signatures on the wire.
#ifndef CESLUAJITD_SHA256_H
#define CESLUAJITD_SHA256_H

#include <cstddef>
#include <cstdint>

namespace cesluajitd {

struct Sha256Ctx {
  uint32_t h[8];
  uint64_t len_bits;
  uint8_t  buf[64];
  size_t   buflen;
};

void sha256_init(Sha256Ctx& c);
void sha256_update(Sha256Ctx& c, const uint8_t* data, size_t len);
void sha256_final(Sha256Ctx& c, uint8_t out[32]);

}  // namespace cesluajitd

#endif  // CESLUAJITD_SHA256_H
