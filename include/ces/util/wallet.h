#pragma once

#include <ces/client.h>
#include <ces/util/ctrlc.h>
#include <ces/keys.h>
#include <ces/types.h>
#include <ces/util/resolver.h>

#include <minx/minx.h>

#include <boost/asio.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <functional>
#include <map>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace ces {

namespace fs = std::filesystem;

// =============================================================================
// Wallet — key management with file persistence
// =============================================================================

class Wallet {
public:
  Wallet() = default;

  // ---- Key loading ----

  // Load a key from its qualified hex string (66 chars = 2-char algo prefix +
  // 64-char private key, or 64 chars = raw ED25519 private key).
  static KeyPair loadKey(const std::string& hex);

  // Algo prefix string for a KeyAlgo.
  static std::string algoPrefix(KeyAlgo algo);

  // Human label for a KeyPair's algorithm.
  static const char* algoLabel(const KeyPair& kp);

  // ---- Wallet file I/O ----

  // Load keys from a wallet file (one qualified hex key per line).
  void loadFromFile(const fs::path& path);

  // Load keys from a string of colon-separated qualified hex keys.
  void loadFromString(const std::string& colonSeparated);

  // Save all keys to a wallet file (with secure permissions).
  void saveToFile(const fs::path& path) const;

  // ---- Key management ----

  // Generate count new keys of the given algorithm. Returns the index of the
  // first new key.
  int generate(int count = 1, KeyAlgo algo = KeyAlgo::ED25519,
               const std::string& label = "");

  // Add a key (raw 64-char hex or qualified 66-char hex). Returns true if
  // the key was new (not a duplicate).
  bool addKey(const std::string& hex, KeyAlgo defaultAlgo = KeyAlgo::ED25519,
              const std::string& label = "");

  // Number of keys in the wallet.
  int size() const { return static_cast<int>(keys_.size()); }

  // Check if empty.
  bool empty() const { return keys_.empty(); }

  // Get the qualified hex string at index.
  const std::string& keyHex(int index) const { return keys_.at(index); }

  // Get a KeyPair at index.
  KeyPair keyPair(int index) const { return loadKey(keys_.at(index)); }

  // All qualified hex strings.
  const std::vector<std::string>& keys() const { return keys_; }

  // ---- Labels ----

  // Get/set label for a key at index.
  const std::string& label(int index) const { return labels_.at(index); }
  void setLabel(int index, const std::string& label) { labels_.at(index) = label; }

  // Find first key index with the given label, or -1 if not found.
  int findByLabel(const std::string& label) const;

  // ---- Key resolution ----

  // Resolve a key reference: "@0" → public key hex of wallet key 0,
  // otherwise returns the input unchanged (assumed to be a public key hex).
  std::string resolveKey(const std::string& input) const;

  // Resolve an actor key: if actorArg is given, find it in the wallet and
  // return the KeyPair. If empty, return the first key. Throws if no keys.
  KeyPair resolveActor(const std::string& actorArg = "") const;

private:
  std::vector<std::string> keys_;
  std::vector<std::string> labels_;

  void addKeyUnique(const std::string& key, const std::string& label = "");
};

// =============================================================================
// Parsing helpers — hex, asset keys, asset content
// =============================================================================

// Check if a string is exactly 64 hex characters.
bool is32ByteHex(const std::string& s);

// Parse a string as a 32-byte asset key (hex or UTF-8 padded).
Hash parseAssetKey(const std::string& input);

// Parse a string as 210-byte asset content (hex or UTF-8 padded).
AssetData parseAssetContent(const std::string& input);

// Parse a hex string as 210-byte asset content (up to 420 hex chars = 210 bytes).
AssetData parseHexContent(const std::string& hexStr);

// Convert asset content to a display string (UTF-8 if printable, else hex).
std::string contentToDisplayString(const AssetData& data);

// =============================================================================
// Network helpers — resolveServer / resolveTcp / probeServer / ServerProbe
// have moved into ces/utils.h as ces::Resolver::resolveUdp /
// ces::Resolver::resolveTcp / ces::Resolver::probe / ces::Resolver::Probe.
// =============================================================================

// =============================================================================
// ClientSession — RAII wrapper for CesClient connect/disconnect
// =============================================================================

class ClientSession {
public:
  /** UDP mode: connect directly to server. `tries` is applied BEFORE the
   *  constructor's connect()/handshake — pass it here, not via a later
   *  setTries(), or the initial connect uses the default retry count. */
  ClientSession(bool cacheOnly, uint16_t port,
                const boost::asio::ip::udp::endpoint& ep,
                const KeyPair* kp = nullptr, int tries = 3);

  /** TCP proxy mode: connect through a MinxProxy. */
  ClientSession(bool cacheOnly,
                const boost::asio::ip::tcp::endpoint& proxyEp,
                const KeyPair* kp = nullptr, int tries = 3);

  /** Auto-detect mode: probe server, use TCP if proxy, UDP otherwise. */
  ClientSession(bool cacheOnly, const std::string& serverStr,
                const KeyPair* kp = nullptr, int tries = 3);

  ~ClientSession();

  // Non-copyable, non-movable.
  ClientSession(const ClientSession&) = delete;
  ClientSession& operator=(const ClientSession&) = delete;

  CesClient&       client()       { return *client_; }
  const CesClient& client() const { return *client_; }
  bool             isTcp = false;

private:
  std::optional<CesClient> client_;
};

// =============================================================================
// Mining helper
// =============================================================================

// Result of a single mine-and-submit cycle.
struct MineResult {
  bool success = false;
  uint64_t credit = 0;
  int status = 0;  // last proveWork return code
};

// Mine once: find a solution and submit it. Blocks until complete or
// interrupted (ces::notInterrupted). Calls statusCallback with the
// proveWork return code on each submission attempt (may be called
// from the same thread).
//
// If progressCallback is set and chunkIters > 0, the search runs in
// chunkIters-sized nonce windows and progressCallback(hashesTried) fires after
// each unsolved window, so a long solve can report live progress. With either
// unset the search is a single unbounded call (the default; no progress).
MineResult mineOnce(CesClient& client, int extraDifficulty = 1,
                    const std::map<std::string, std::string>& appData = {},
                    int numThreads = 1,
                    std::function<void(int)> statusCallback = nullptr,
                    std::function<void(uint64_t)> progressCallback = nullptr,
                    uint64_t chunkIters = 0);

} // namespace ces
