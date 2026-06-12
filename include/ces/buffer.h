#pragma once

/**
 * Vector-owning byte buffer for CES wire data. Auto-grows on put;
 * tracks separate read and write cursors so the same Buffer can be a
 * builder (sequence of puts) or a parser (sequence of gets).
 *
 * BE serialization delegates to logkv::serializer<T>; the LE family
 * uses boost::endian directly (CES wire format is BE except for VM
 * bytecode operands and a few proxy framing fields).
 *
 * The static helpers (Buffer::put, Buffer::peek, ...) operate on raw
 * pointers or external Bytes/minx::Bytes for sites that don't own a
 * Buffer instance.
 */

#include <ces/types.h>

#include <minx/buffer.h>
#include <logkv/autoser.h>

#include <boost/asio/buffer.hpp>

#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace ces {

class Buffer {
public:
  // ---- Construction ----

  Buffer() = default;

  // Pre-allocate `n` bytes (sized but uninitialized data is fine —
  // every put/poke writes before reading).
  explicit Buffer(size_t n) : v_(n) {}

  // Take ownership of an existing Bytes. Cursors start at 0 / 0;
  // useful for parsing (then call get<T>) or for chaining-build.
  explicit Buffer(Bytes v) : v_(std::move(v)) {}

  // ---- Storage access ----

  Bytes&       vec()       noexcept { return v_; }
  const Bytes& vec() const noexcept { return v_; }

  uint8_t*       data()       noexcept { return v_.data(); }
  const uint8_t* data() const noexcept { return v_.data(); }
  size_t size()  const noexcept { return v_.size(); }
  bool   empty() const noexcept { return v_.empty(); }

  // Move the underlying Bytes out. Use for
  // `return std::move(buf).take();` at end-of-build sites.
  Bytes take() && noexcept {
    return std::move(v_);
  }

  // ---- Cursors ----

  size_t writePos() const noexcept { return wPos_; }
  size_t readPos()  const noexcept { return rPos_; }
  void   setWritePos(size_t p) noexcept { wPos_ = p; }
  void   setReadPos (size_t p) noexcept { rPos_ = p; }

  // Bytes left between the read cursor and end-of-data.
  size_t remaining() const noexcept {
    return v_.size() > rPos_ ? v_.size() - rPos_ : 0;
  }

  // ---- Resize / clear ----

  void resize(size_t n)  { v_.resize(n); }
  void reserve(size_t n) { v_.reserve(n); }
  void clear() noexcept { v_.clear(); wPos_ = 0; rPos_ = 0; }

  // ---- BE put — auto-grow ----

  // Append a typed value at the write cursor; advance cursor by the
  // serialized size. Grows the underlying vector if needed.
  // Integers go BE; std::array<uint8_t, N> / std::span<uint8_t>
  // / minx::Hash / ces::PublicKey / ces::Signature go raw via their
  // logkv::serializer specializations.
  template <typename T>
  Buffer& put(const T& val) {
    const size_t needed = logkv::serializer<T>::get_size(val);
    if (wPos_ + needed > v_.size()) v_.resize(wPos_ + needed);
    logkv::serializer<T>::write(
      reinterpret_cast<char*>(v_.data() + wPos_), needed, val);
    wPos_ += needed;
    return *this;
  }

  // Convenience: append raw bytes (equivalent to put(span<const uint8_t>)
  // but doesn't require the explicit span construction).
  Buffer& putBytes(std::span<const uint8_t> bytes) {
    if (wPos_ + bytes.size() > v_.size()) v_.resize(wPos_ + bytes.size());
    if (!bytes.empty()) {
      std::memcpy(v_.data() + wPos_, bytes.data(), bytes.size());
    }
    wPos_ += bytes.size();
    return *this;
  }
  Buffer& putBytes(std::string_view s) {
    return putBytes(std::span<const uint8_t>(
      reinterpret_cast<const uint8_t*>(s.data()), s.size()));
  }

  // ---- BE get — advance read cursor; throws on short read ----

  template <typename T>
  T get() {
    T out{};
    const size_t available = (v_.size() > rPos_) ? (v_.size() - rPos_) : 0;
    const size_t consumed = logkv::serializer<T>::read(
      reinterpret_cast<const char*>(v_.data() + rPos_),
      available, out);
    if (consumed > available)
      throw std::out_of_range("ces::Buffer::get: short read");
    rPos_ += consumed;
    return out;
  }

  template <typename T>
  Buffer& get(T& out) {
    const size_t available = (v_.size() > rPos_) ? (v_.size() - rPos_) : 0;
    const size_t consumed = logkv::serializer<T>::read(
      reinterpret_cast<const char*>(v_.data() + rPos_),
      available, out);
    if (consumed > available)
      throw std::out_of_range("ces::Buffer::get: short read");
    rPos_ += consumed;
    return *this;
  }

  // ---- get raw byte ranges — advance read cursor ----
  //
  // The read counterpart to putBytes. getBytesSpan is zero-copy (the span
  // points into this Buffer — consume before any further mutation);
  // getBytes copies into a fresh R. Both throw on short read, so parsers
  // guard with remaining() first. Mirrors minx::Buffer::getBytesSpan/getBytes.

  std::span<const uint8_t> getBytesSpan(size_t n) {
    if (n > remaining())
      throw std::out_of_range("ces::Buffer::getBytesSpan: short read");
    std::span<const uint8_t> result(v_.data() + rPos_, n);
    rPos_ += n;
    return result;
  }

  template <typename R = Bytes>
  R getBytes(size_t n) {
    if (n > remaining())
      throw std::out_of_range("ces::Buffer::getBytes: short read");
    R result;
    result.resize(n);
    if (n > 0) {
      std::memcpy(result.data(), v_.data() + rPos_, n);
      rPos_ += n;
    }
    return result;
  }

  // ---- BE peek / poke (no cursor change) ----

  // Read at a specific offset without advancing the cursor.
  // Caller is responsible for offset + sizeof(T) being in bounds.
  template <typename T>
  T peek(size_t offset) const {
    T out{};
    logkv::serializer<T>::read(
      reinterpret_cast<const char*>(v_.data() + offset),
      v_.size() - offset, out);
    return out;
  }

  // Write at a specific offset without disturbing the write cursor.
  // Useful for patching header fields after the body length is known.
  template <typename T>
  Buffer& poke(size_t offset, const T& val) {
    if (offset + sizeof(T) > v_.size()) v_.resize(offset + sizeof(T));
    logkv::serializer<T>::write(
      reinterpret_cast<char*>(v_.data() + offset), sizeof(T), val);
    return *this;
  }

  // ---- LE family ----

  // CES wire format is BE except for VM bytecode operands and a few
  // proxy framing fields, which are little-endian. logkv::serializer
  // is BE-only; the LE methods here use boost::endian directly.

  template <typename T>
  Buffer& putLE(T val) {
    if (wPos_ + sizeof(T) > v_.size()) v_.resize(wPos_ + sizeof(T));
    pokeLE<T>(v_.data() + wPos_, val);
    wPos_ += sizeof(T);
    return *this;
  }

  template <typename T>
  T peekLE(size_t offset) const {
    return peekLE<T>(v_.data() + offset);
  }

  template <typename T>
  Buffer& pokeLE(size_t offset, T val) {
    if (offset + sizeof(T) > v_.size()) v_.resize(offset + sizeof(T));
    pokeLE<T>(v_.data() + offset, val);
    return *this;
  }

  // ---- Static raw-pointer helpers ----
  //
  // For sites that operate on an already-allocated byte region (e.g.
  // the result of a fixed-offset memcpy, an existing std::array<u8, N>,
  // or an external vector that ces::Buffer wouldn't own). Read at a
  // pointer / write at a pointer / append into an external vector —
  // all delegating to the same logkv::serializer<T> backend that the
  // instance methods use. No bounds checks; caller guarantees space.

  template <typename T>
  static T peek(const uint8_t* ptr) {
    T out{};
    logkv::serializer<T>::read(reinterpret_cast<const char*>(ptr),
                                sizeof(T), out);
    return out;
  }

  template <typename T>
  static T peek(std::span<const uint8_t> data, size_t offset) {
    T out{};
    logkv::serializer<T>::read(
      reinterpret_cast<const char*>(data.data() + offset),
      data.size() - offset, out);
    return out;
  }

  template <typename T>
  static void poke(uint8_t* ptr, const T& val) {
    logkv::serializer<T>::write(reinterpret_cast<char*>(ptr),
                                  sizeof(T), val);
  }

  template <typename T>
  static T peekLE(const uint8_t* ptr) {
    static_assert(std::is_integral_v<T>,
                  "peekLE is for integers only");
    T le{};
    std::memcpy(&le, ptr, sizeof(T));
    return boost::endian::little_to_native(le);
  }

  template <typename T>
  static T peekLE(std::span<const uint8_t> data, size_t offset) {
    return peekLE<T>(data.data() + offset);
  }

  template <typename T>
  static void pokeLE(uint8_t* ptr, T val) {
    static_assert(std::is_integral_v<T>,
                  "pokeLE is for integers only");
    T le = boost::endian::native_to_little(val);
    std::memcpy(ptr, &le, sizeof(T));
  }

  // Append a typed value at the end of an EXTERNAL ces::Bytes
  // (i.e. when the caller doesn't want to own a ces::Buffer at the
  // call site — typical for incremental builders working over their
  // own pre-existing vector). Same byte order rules as the instance
  // put<T>: BE for ints, raw for arrays/spans/PublicKey/Hash/etc.
  template <typename T>
  static void put(ces::Bytes& v, const T& val) {
    const size_t before = v.size();
    const size_t needed = logkv::serializer<T>::get_size(val);
    v.resize(before + needed);
    logkv::serializer<T>::write(
      reinterpret_cast<char*>(v.data() + before), needed, val);
  }

  template <typename T>
  static void putLE(ces::Bytes& v, T val) {
    static_assert(std::is_integral_v<T>,
                  "putLE is for integers only");
    const size_t before = v.size();
    v.resize(before + sizeof(T));
    T le = boost::endian::native_to_little(val);
    std::memcpy(v.data() + before, &le, sizeof(T));
  }

  // Runtime-width LE: append exactly `byteCount` low bytes of `val`,
  // 1..sizeof(T). For VM bytecode operand emission where the byte
  // count is decided by the value's magnitude, not by sizeof(T).
  template <typename T>
  static void putLE(ces::Bytes& v, T val, uint8_t byteCount) {
    static_assert(std::is_integral_v<T>,
                  "putLE is for integers only");
    if (byteCount < 1 || byteCount > sizeof(T))
      throw std::invalid_argument(
        "ces::Buffer::putLE: byteCount out of range [1, sizeof(T)]");
    const size_t before = v.size();
    v.resize(before + byteCount);
    T le = boost::endian::native_to_little(val);
    std::memcpy(v.data() + before, &le, byteCount);
  }

  static void putBytes(ces::Bytes& v,
                        std::span<const uint8_t> bytes) {
    v.insert(v.end(), bytes.begin(), bytes.end());
  }
  static void putBytes(ces::Bytes& v, const std::string& s) {
    v.insert(v.end(),
              reinterpret_cast<const uint8_t*>(s.data()),
              reinterpret_cast<const uint8_t*>(s.data() + s.size()));
  }

  // ---- minx::Bytes overloads ----
  // Same statics, but for minx::Bytes (boost::container::static_vector
  // <char, 1280>). Lets put<T>/putLE<T>/putBytes work uniformly across
  // the heap and the MTU-bounded byte containers.

  template <typename T>
  static void put(minx::Bytes& v, const T& val) {
    const size_t before = v.size();
    const size_t needed = logkv::serializer<T>::get_size(val);
    v.resize(before + needed);
    logkv::serializer<T>::write(v.data() + before, needed, val);
  }

  template <typename T>
  static void putLE(minx::Bytes& v, T val) {
    static_assert(std::is_integral_v<T>,
                  "putLE is for integers only");
    const size_t before = v.size();
    v.resize(before + sizeof(T));
    T le = boost::endian::native_to_little(val);
    std::memcpy(v.data() + before, &le, sizeof(T));
  }

  static void putBytes(minx::Bytes& v, std::span<const uint8_t> bytes) {
    v.insert(v.end(),
              reinterpret_cast<const char*>(bytes.data()),
              reinterpret_cast<const char*>(bytes.data() + bytes.size()));
  }
  static void putBytes(minx::Bytes& v, const std::string& s) {
    v.insert(v.end(), s.data(), s.data() + s.size());
  }

  // ---- Asio integration ----

  boost::asio::const_buffer asioConstBuffer() const noexcept {
    return boost::asio::buffer(v_);
  }
  boost::asio::mutable_buffer asioMutableBuffer() noexcept {
    return boost::asio::buffer(v_);
  }

private:
  Bytes  v_;
  size_t wPos_ = 0;
  size_t rPos_ = 0;
};

} // namespace ces
