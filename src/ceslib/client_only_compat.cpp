// Compiled ONLY under CES_CLIENT_ONLY: the few free functions whose home
// translation unit is server-side (excluded from the client subset) but whose
// declaration is used by client code.

#include <cryptopp/sha.h>
#include <minx/types.h>

#include <cstddef>
#include <cstdint>

namespace ces {

// Home TU: ramfilestore.cpp (declared in ces/ramfilestore.h).
minx::Hash sha256(const uint8_t* data, size_t len) {
  minx::Hash h;
  CryptoPP::SHA256().CalculateDigest(h.data(), data, len);
  return h;
}

}  // namespace ces
