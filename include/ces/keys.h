#pragma once

#include <cryptopp/osrng.h>
#include <cryptopp/xed25519.h>
#include <secp256k1.h>

#include <ces/types.h>

#include <logkv/autoser.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace ces {

static constexpr size_t KEY_SIZE = 32;
static constexpr size_t KEY_HEX_STRING_SIZE = KEY_SIZE * 2;
static constexpr size_t SIG_SIZE = 65;

using Signature = std::array<uint8_t, SIG_SIZE>;

enum class SigType : uint8_t {
  ED25519 = 0x00,
  SECP256K1_EVEN = 0x01,
  SECP256K1_ODD = 0x02
};

enum class KeyAlgo {
  ED25519,
  SECP256K1
};

inline CryptoPP::AutoSeededRandomPool& getThreadLocalPRNG() {
  thread_local CryptoPP::AutoSeededRandomPool prng;
  return prng;
}

// Prepare a 32-byte digest for signing/verification.
// If data is already 32 bytes, just copy it. Otherwise, SHA256 it.
inline std::array<uint8_t, 32> prepareDigest(std::span<const uint8_t> data) {
  std::array<uint8_t, 32> out;
  if (data.size() == 32) {
    std::memcpy(out.data(), data.data(), 32);
  } else {
    CryptoPP::SHA256().CalculateDigest(out.data(), data.data(), data.size());
  }
  return out;
}

// Thread-local secp256k1 context (one per thread, no locking).
inline secp256k1_context* getThreadLocalSecpContext() {
  thread_local struct ContextWrapper {
    secp256k1_context* ctx;
    ContextWrapper() {
      ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                     SECP256K1_CONTEXT_VERIFY);
      if (!ctx)
        throw std::runtime_error("secp256k1_context_create returned null");
    }
    ~ContextWrapper() {
      if (ctx)
        secp256k1_context_destroy(ctx);
    }
  } wrapper;
  return wrapper.ctx;
}

class PublicKey {
public:
  PublicKey() = default;

  explicit PublicKey(const Hash& publicKey) : key_(publicKey) {}

  explicit PublicKey(const std::string& hexStr) {
    if (hexStr.size() != KEY_HEX_STRING_SIZE) {
      throw std::runtime_error("Invalid public key hex string length");
    }
    minx::stringToHash(key_, hexStr);
  }

  bool verifySignature(std::span<const uint8_t> data,
                       const Signature& signature) const {
    SigType sigType = static_cast<SigType>(signature[0]);
    const uint8_t* rawSigData = signature.data() + 1;

    if (sigType == SigType::ED25519) {
      CryptoPP::ed25519::Verifier verifier(
        reinterpret_cast<const CryptoPP::byte*>(key_.data()));
      return verifier.VerifyMessage(
        reinterpret_cast<const CryptoPP::byte*>(data.data()), data.size(),
        reinterpret_cast<const CryptoPP::byte*>(rawSigData), 64);
    } else if (sigType == SigType::SECP256K1_EVEN ||
               sigType == SigType::SECP256K1_ODD) {
      auto* ctx = getThreadLocalSecpContext();

      // 1. Reconstruct the 33-byte compressed public key
      std::array<uint8_t, 33> compressed;
      compressed[0] = (sigType == SigType::SECP256K1_EVEN) ? 0x02 : 0x03;
      std::memcpy(compressed.data() + 1, key_.data(), 32);

      // 2. Parse the public key into secp internal format
      secp256k1_pubkey pubkey;
      if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, compressed.data(), 33)) {
        return false;
      }

      // 3. Parse the 64-byte signature (r, s)
      secp256k1_ecdsa_signature sig;
      if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, rawSigData)) {
        return false;
      }

      // 4. Hash if not already 32 bytes
      auto msgHash = prepareDigest(data);

      // 5. Verify
      return secp256k1_ecdsa_verify(ctx, &sig, msgHash.data(), &pubkey) == 1;
    }

    return false;
  }

  bool verifySignature(const char* data, size_t size,
                       const Signature& signature) const {
    return verifySignature(
      std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(data), size),
      signature);
  }

  bool verifySignature(const uint8_t* data, size_t size,
                       const Signature& signature) const {
    return verifySignature(std::span<const uint8_t>(data, size), signature);
  }

  const Hash& getHash() const { return key_; }

  // Hex form is computed on first call and cached. Verify-only call
  // paths (the hot path for inbound packets) never touch this and pay
  // nothing; display/logging/wallet-export paths pay one encode per
  // PublicKey instance lifetime.
  const std::string& getHexStr() const {
    if (hexStr_.empty()) {
      hexStr_.resize(KEY_HEX_STRING_SIZE);
      logkv::encodeHex(hexStr_.data(), hexStr_.size(),
                       reinterpret_cast<const char*>(key_.data()),
                       key_.size(), false);
    }
    return hexStr_;
  }

private:
  Hash key_{};
  mutable std::string hexStr_;
};

class KeyPair {
public:
  KeyPair(KeyAlgo algo = KeyAlgo::ED25519) : algo_(algo) {
    generateKeyPair({});
  }

  explicit KeyPair(const Hash& privateKey, KeyAlgo algo = KeyAlgo::ED25519)
      : algo_(algo) {
    generateKeyPair(privateKey);
  }

  explicit KeyPair(const std::string& hexStr, KeyAlgo algo = KeyAlgo::ED25519)
      : algo_(algo) {
    minx::Hash privateKey;
    minx::stringToHash(privateKey, hexStr);
    generateKeyPair(privateKey);
  }

  static KeyPair generate(KeyAlgo algo = KeyAlgo::ED25519) {
    return KeyPair(algo);
  }

  Signature signData(std::span<const uint8_t> data) const {
    Signature signature;
    signature[0] = static_cast<uint8_t>(decoratorByte_);

    if (algo_ == KeyAlgo::ED25519) {
      CryptoPP::ed25519::Signer edSigner(
        reinterpret_cast<const CryptoPP::byte*>(privateKey_.data()));
      edSigner.SignMessage(
        getThreadLocalPRNG(),
        reinterpret_cast<const CryptoPP::byte*>(data.data()), data.size(),
        reinterpret_cast<CryptoPP::byte*>(signature.data() + 1));
    } else {
      auto* ctx = getThreadLocalSecpContext();

      auto msgHash = prepareDigest(data);

      secp256k1_ecdsa_signature sig;
      if (secp256k1_ecdsa_sign(ctx, &sig, msgHash.data(), privateKey_.data(),
                               nullptr, nullptr) != 1) {
        throw std::runtime_error("secp256k1_ecdsa_sign failed");
      }

      secp256k1_ecdsa_signature_serialize_compact(ctx, signature.data() + 1,
                                                  &sig);
    }

    return signature;
  }

  Signature signData(const char* data, size_t size) const {
    return signData(
      std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(data), size));
  }

  bool verifySignature(std::span<const uint8_t> data,
                       const Signature& signature) const {
    return pubKey_.verifySignature(data, signature);
  }

  bool verifySignature(const char* data, size_t size,
                       const Signature& signature) const {
    return pubKey_.verifySignature(data, size, signature);
  }

  const PublicKey& getPublicKey() const { return pubKey_; }
  const minx::Hash& getPublicKeyAsHash() const { return pubKey_.getHash(); }
  const std::string& getPublicKeyHexStr() const { return pubKey_.getHexStr(); }
  const minx::Hash& getPrivateKey() const { return privateKey_; }
  const std::string& getPrivateKeyHexStr() const { return privateKeyHexStr_; }
  KeyAlgo getAlgorithm() const { return algo_; }
  SigType getDecoratorType() const { return decoratorByte_; }

private:
  void generateKeyPair(const Hash& privateKey) {
    bool isNewKey = std::all_of(privateKey.begin(), privateKey.end(),
                                [](uint8_t byte) { return byte == 0; });

    Hash pubHash;

    if (algo_ == KeyAlgo::ED25519) {
      decoratorByte_ = SigType::ED25519;
      if (isNewKey) {
        CryptoPP::ed25519::Signer edSigner(getThreadLocalPRNG());
        const auto& specificPriv =
          dynamic_cast<const CryptoPP::ed25519PrivateKey&>(
            edSigner.GetPrivateKey());
        std::memcpy(privateKey_.data(), specificPriv.GetPrivateKeyBytePtr(),
                    KEY_SIZE);
      } else {
        privateKey_ = privateKey;
      }

      CryptoPP::ed25519::Signer edSigner(
        reinterpret_cast<const CryptoPP::byte*>(privateKey_.data()));
      CryptoPP::ed25519::Verifier tempVerifier(edSigner);
      const auto& specificPub = dynamic_cast<const CryptoPP::ed25519PublicKey&>(
        tempVerifier.GetPublicKey());
      std::memcpy(pubHash.data(), specificPub.GetPublicKeyBytePtr(), KEY_SIZE);
    } else {
      auto* ctx = getThreadLocalSecpContext();
      if (isNewKey) {
        do {
          getThreadLocalPRNG().GenerateBlock(privateKey_.data(), KEY_SIZE);
        } while (!secp256k1_ec_seckey_verify(ctx, privateKey_.data()));
      } else {
        privateKey_ = privateKey;
      }

      secp256k1_pubkey pubkey;
      if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privateKey_.data())) {
        throw std::runtime_error("secp256k1_ec_pubkey_create failed");
      }

      std::array<uint8_t, 33> compressed;
      size_t clen = 33;
      secp256k1_ec_pubkey_serialize(ctx, compressed.data(), &clen, &pubkey,
                                    SECP256K1_EC_COMPRESSED);

      std::memcpy(pubHash.data(), compressed.data() + 1, 32);
      decoratorByte_ = (compressed[0] == 0x02) ? SigType::SECP256K1_EVEN
                                               : SigType::SECP256K1_ODD;
    }

    privateKeyHexStr_.resize(KEY_HEX_STRING_SIZE);
    logkv::encodeHex(privateKeyHexStr_.data(), privateKeyHexStr_.size(),
                     reinterpret_cast<const char*>(privateKey_.data()),
                     privateKey_.size(), false);

    pubKey_ = PublicKey(pubHash);
  }

  KeyAlgo algo_;
  SigType decoratorByte_;
  PublicKey pubKey_;
  minx::Hash privateKey_;
  std::string privateKeyHexStr_;
};

} // namespace ces

// ---------------------------------------------------------------------------
// logkv::serializer<ces::PublicKey> — wire form is the 32-byte pubkey hash.
// ---------------------------------------------------------------------------
//
// Thin delegation to serializer<ces::Hash>: a PublicKey is a Hash (plus a
// lazily-cached hex string), so the wire form is the same 32 raw bytes. The
// specialization lets `buf.put(pk)` / `buf.get<PublicKey>()` work on the
// PublicKey type directly instead of unwrapping to/from Hash at each call.

namespace logkv {

template <> struct serializer<ces::PublicKey> {
  static size_t get_size(const ces::PublicKey& pk) {
    return serializer<ces::Hash>::get_size(pk.getHash());
  }
  static bool is_empty(const ces::PublicKey& pk) {
    return serializer<ces::Hash>::is_empty(pk.getHash());
  }
  static size_t write(char* dest, size_t size, const ces::PublicKey& pk) {
    return serializer<ces::Hash>::write(dest, size, pk.getHash());
  }
  static size_t read(const char* src, size_t size, ces::PublicKey& pk) {
    ces::Hash h;
    const size_t n = serializer<ces::Hash>::read(src, size, h);
    if (n <= size) pk = ces::PublicKey(h);
    return n;
  }
};

} // namespace logkv