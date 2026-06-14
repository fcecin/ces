#include <ces/util/wallet.h>

#include <ces/util/hex.h>
#include <ces/util/resolver.h>
#include <ces/util/fileperm.h>

#include <fstream>
#include <functional>
#include <iomanip>

#include <minx/blog.h>

LOG_MODULE("ceslib");

namespace ces {

// mineOnce polling knobs. Kept local to this TU; the blocking client uses its
// own CesClient::kRetryIntervalMs for network retries.
static constexpr int MINE_POLL_INTERVAL_MS = 3000;
static constexpr int MINE_UNKNOWN_RESPONSE_RETRIES = 3;


// =============================================================================
// Wallet — key loading
// =============================================================================

KeyPair Wallet::loadKey(const std::string& hex) {
  if (hex.length() == 66) {
    uint8_t type =
      static_cast<uint8_t>(strtol(hex.substr(0, 2).c_str(), nullptr, 16));
    minx::Hash rawPriv;
    minx::stringToHash(rawPriv, hex.substr(2));
    if (type == 0x01)
      return KeyPair(rawPriv, KeyAlgo::SECP256K1);
    return KeyPair(rawPriv, KeyAlgo::ED25519);
  }
  minx::Hash rawPriv;
  minx::stringToHash(rawPriv, hex);
  return KeyPair(rawPriv, KeyAlgo::ED25519);
}

std::string Wallet::algoPrefix(KeyAlgo algo) {
  return (algo == KeyAlgo::SECP256K1) ? "01" : "00";
}

const char* Wallet::algoLabel(const KeyPair& kp) {
  return (kp.getAlgorithm() == KeyAlgo::SECP256K1) ? "[SECP]" : "[ED  ]";
}

// =============================================================================
// Wallet — file I/O
// =============================================================================

void Wallet::loadFromFile(const fs::path& path) {
  std::ifstream f(path);
  if (!f.is_open())
    throw std::runtime_error("Cannot open wallet file: " + path.string());
  std::string line;
  while (std::getline(f, line)) {
    if (line.empty()) continue;
    // Format: KEY [LABEL]  — label is everything after the first space
    auto sp = line.find(' ');
    if (sp != std::string::npos)
      addKeyUnique(line.substr(0, sp), line.substr(sp + 1));
    else
      addKeyUnique(line);
  }
}

void Wallet::loadFromString(const std::string& colonSeparated) {
  std::stringstream ss(colonSeparated);
  std::string s;
  while (std::getline(ss, s, ':'))
    if (!s.empty())
      addKeyUnique(s);  // no labels in colon-separated format
}

void Wallet::saveToFile(const fs::path& path) const {
  fs::create_directories(path.parent_path());
  std::ofstream f(path);
  if (!f.is_open())
    throw std::runtime_error("Cannot write wallet file: " + path.string());
  for (size_t i = 0; i < keys_.size(); ++i) {
    f << keys_[i];
    if (i < labels_.size() && !labels_[i].empty())
      f << " " << labels_[i];
    f << "\n";
  }
  f.flush();
  auto permErr = setSecurePermission(path);
  if (!permErr.empty())
    throw std::runtime_error("Failed to set wallet file permissions: " + permErr);
}

// =============================================================================
// Wallet — key management
// =============================================================================

int Wallet::generate(int count, KeyAlgo algo, const std::string& label) {
  if (count < 1)
    count = 1;
  int firstNew = size();
  std::string prefix = algoPrefix(algo);
  for (int i = 0; i < count; ++i) {
    KeyPair k(algo);
    addKeyUnique(prefix + k.getPrivateKeyHexStr(), label);
  }
  return firstNew;
}

bool Wallet::addKey(const std::string& hex, KeyAlgo defaultAlgo,
                    const std::string& label) {
  int before = size();
  if (hex.length() == 66) {
    addKeyUnique(hex, label);
  } else if (hex.length() == 64) {
    addKeyUnique(algoPrefix(defaultAlgo) + hex, label);
  } else {
    throw std::runtime_error(
      "Key must be 64 hex chars (raw) or 66 hex chars (qualified)");
  }
  return size() > before;
}

// =============================================================================
// Wallet — key resolution
// =============================================================================

std::string Wallet::resolveKey(const std::string& input) const {
  if (input.empty())
    return "";
  if (input[0] == '@') {
    if (input.size() == 1)
      throw std::runtime_error("Invalid wallet index: @");
    try {
      int index = std::stoi(input.substr(1));
      if (index < 0 || index >= size())
        throw std::runtime_error("Index bounds");
      return loadKey(keys_[index]).getPublicKeyHexStr();
    } catch (...) {
      throw std::runtime_error("Invalid wallet index: " + input);
    }
  }
  return input;
}

KeyPair Wallet::resolveActor(const std::string& actorArg) const {
  if (!actorArg.empty()) {
    std::string target = resolveKey(actorArg);
    for (auto& k : keys_) {
      KeyPair kp = loadKey(k);
      if (kp.getPublicKeyHexStr() == target)
        return kp;
    }
    throw std::runtime_error("Actor key not found in wallet");
  }
  if (!keys_.empty())
    return loadKey(keys_[0]);
  throw std::runtime_error("No keys in wallet. Use 'keys gen' first");
}

int Wallet::findByLabel(const std::string& label) const {
  for (size_t i = 0; i < labels_.size(); ++i)
    if (labels_[i] == label)
      return static_cast<int>(i);
  return -1;
}

void Wallet::addKeyUnique(const std::string& key, const std::string& label) {
  // Validate at insertion so callers get a clean error at load time,
  // not a terminate() from deep inside loadKey() during the first sign.
  try {
    (void)loadKey(key);
  } catch (const std::exception&) {
    throw std::runtime_error("invalid wallet key: \"" + key + "\"");
  }
  if (std::find(keys_.begin(), keys_.end(), key) == keys_.end()) {
    keys_.push_back(key);
    labels_.push_back(label);
  }
}

// =============================================================================
// Parsing helpers
// =============================================================================

bool is32ByteHex(const std::string& s) {
  if (s.length() != 64)
    return false;
  for (char c : s) {
    if (!std::isxdigit(static_cast<unsigned char>(c)))
      return false;
  }
  return true;
}

namespace {

// If `input` is exactly 64 hex chars, decode as a 32-byte hash.
std::optional<Hash> tryParseHashHex(const std::string& input) {
  if (!is32ByteHex(input)) return std::nullopt;
  Hash h{};
  auto bytes = parseHex(input);
  std::copy(bytes.begin(), bytes.end(), h.begin());
  return h;
}

// "Smart string" parser shared by asset-key (N=32) and asset-content
// (N=210): if input parses as a 32-byte hex hash, the output holds
// those 32 bytes followed by zeros; otherwise input is treated as
// raw bytes (capped at N) followed by zeros.
template <size_t N>
std::array<uint8_t, N> parseHashOrText(const std::string& input) {
  static_assert(N >= 32, "parseHashOrText assumes N can hold a hash");
  std::array<uint8_t, N> data{};
  if (input.empty()) return data;
  if (auto h = tryParseHashHex(input)) {
    std::copy(h->begin(), h->end(), data.begin());
    return data;
  }
  if (input.size() > N)
    throw std::runtime_error("Input string exceeds limit (" +
                             std::to_string(N) + " bytes)");
  std::copy(input.begin(), input.end(), data.begin());
  return data;
}

} // namespace

Hash parseAssetKey(const std::string& input) {
  return parseHashOrText<32>(input);
}

AssetData parseAssetContent(const std::string& input) {
  return parseHashOrText<210>(input);
}

AssetData parseHexContent(const std::string& hexStr) {
  auto bytes = parseHex(hexStr);
  if (bytes.size() > 210)
    throw std::runtime_error("Hex content exceeds 210 bytes (420 hex chars)");
  AssetData data;
  data.fill(0);
  std::copy(bytes.begin(), bytes.end(), data.begin());
  return data;
}

std::string contentToDisplayString(const AssetData& data) {
  // Heuristic: detect pure printable-ASCII with a NUL-terminator pattern
  // and render as text. Otherwise emit the full content as hex (210 bytes
  // = 420 chars), no truncation, so binary asset content round-trips
  // losslessly.
  bool isText = true;
  size_t len = 0;
  for (auto c : data) {
    if (c == 0)
      break;
    if (c < 32 || c > 126)
      isText = false;
    len++;
  }
  if (len > 0 && isText)
    return std::string(reinterpret_cast<const char*>(data.data()), len);

  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (size_t i = 0; i < data.size(); ++i)
    ss << std::setw(2) << static_cast<int>(data[i]);
  return ss.str();
}

// =============================================================================
// ClientSession
// =============================================================================

ClientSession::ClientSession(bool cacheOnly, uint16_t port,
                             const boost::asio::ip::udp::endpoint& ep,
                             const KeyPair* kp)
    : isTcp(false) {
  client_.emplace(ep, !cacheOnly);
  client_->start(port);
  if (kp)
    client_->setKey(*kp);
  if (!client_->connect())
    throw std::runtime_error("Connect failed");
}

ClientSession::ClientSession(bool cacheOnly,
                             const boost::asio::ip::tcp::endpoint& proxyEp,
                             const KeyPair* kp)
    : isTcp(true) {
  client_.emplace(proxyEp, !cacheOnly);
  client_->start(0);
  if (kp)
    client_->setKey(*kp);
  if (!client_->connect())
    throw std::runtime_error("Connect through proxy failed");
}

ClientSession::ClientSession(bool cacheOnly, const std::string& serverStr,
                             const KeyPair* kp) {
  // CesClient is non-movable, so we hold it inside an std::optional and
  // emplace it AFTER probing — no default-construct-then-replace dance.
  auto probe = Resolver::probe(serverStr);
  isTcp = probe.isTcp;
  if (probe.isTcp)
    client_.emplace(probe.tcpEp, !cacheOnly);
  else
    client_.emplace(probe.udpEp, !cacheOnly);

  client_->start(0);
  if (kp)
    client_->setKey(*kp);
  if (!client_->connect())
    throw std::runtime_error(
      std::string("Connect failed (") + (probe.isTcp ? "TCP" : "UDP") + ")");
}

ClientSession::~ClientSession() {
  if (client_) {
    client_->disconnect();
    client_->stop();
  }
}

// =============================================================================
// Mining helper
// =============================================================================

MineResult mineOnce(CesClient& client, int extraDifficulty,
                    const std::map<std::string, std::string>& appData,
                    int numThreads,
                    std::function<void(int)> statusCallback) {
  auto w = client.mine(extraDifficulty, appData, numThreads);
  if (!w)
    return {false, 0, -1};

  int attempts = 0;
  while (ces::notInterrupted()) {
    minx::Hash b;
    uint64_t credit, t;
    int r = client.proveWork(*w, b, credit, t);

    if (statusCallback)
      statusCallback(r);

    if (r == minx::MINX_SOLUTION_SPENT)
      return {true, credit, r};

    if (r == minx::MINX_SOLUTION_UNTIMELY)
      return {false, 0, r};

    if (r == minx::MINX_SOLUTION_UNKNOWN) {
      if (++attempts > MINE_UNKNOWN_RESPONSE_RETRIES)
        return {false, 0, r};
    }

    ces::sleep(MINE_POLL_INTERVAL_MS);
  }

  return {false, 0, 0};
}

} // namespace ces
