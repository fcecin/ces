#pragma once

// Hashing helpers.
//
// Hashing is provider-agnostic at this header: shaUpdate() is templated
// on the hasher type. Anything exposing `.Update(const uint8_t*, size_t)`
// fits (CryptoPP::SHA256 happens to). The crypto provider header is
// pulled in only at the .cpp site that actually constructs the hasher.

#include <array>
#include <cstdint>
#include <type_traits>

#include <logkv/serializer.h>

namespace ces {

// Feed an integer value into a streaming hasher, big-endian encoded.
// Avoids the inline `uint8_t buf[N]; ... h.Update(buf, N);` pattern at
// every digest-building site. For byte arrays/spans, call
// h.Update(arr.data(), arr.size()) directly — this helper is for
// integer scalars only.
template <typename Hasher, typename T>
inline void shaUpdate(Hasher& h, const T& val) {
  static_assert(std::is_integral_v<T>,
                "shaUpdate is for integer scalars; for byte arrays/"
                "spans use h.Update(arr.data(), arr.size()) directly");
  std::array<uint8_t, sizeof(T)> tmp;
  logkv::serializer<T>::write(
    reinterpret_cast<char*>(tmp.data()), tmp.size(), val);
  h.Update(tmp.data(), tmp.size());
}

} // namespace ces
