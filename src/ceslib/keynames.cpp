#include <ces/keynames.h>

#include <minx/blog.h>

#include <cstring>

LOG_MODULE("knm");

namespace ces {

KeyNames::KeyNames(const std::string& dataDir, uint64_t minKeyName,
                   uint64_t flushValue, size_t bufferSize)
    : store_(dataDir, logkv::StoreFlags::createDir, bufferSize),
      flushValue_(flushValue) {
  store_.getObjects().reserve(minKeyName);
  rebuildReverse();
}

KeyNameData KeyNames::normalize(const KeyNameData& name) {
  // Spaces and underscores are THE SAME character: both map to '_'. Leading and
  // trailing underscores (i.e. boundary spaces) are stripped, so a name can
  // neither begin nor end with one. The result is the filesystem-safe,
  // exact-match key stored in the ledger and used verbatim as the /f/<name>/
  // path segment; pretty renderers turn '_' back into ' '.
  size_t len = 0;
  while (len < name.size() && name[len] != 0) ++len;
  KeyNameData mapped{};
  for (size_t i = 0; i < len; ++i)
    mapped[i] = (name[i] == ' ') ? static_cast<uint8_t>('_') : name[i];
  size_t begin = 0, end = len;
  while (begin < end && mapped[begin] == '_') ++begin;
  while (end > begin && mapped[end - 1] == '_') --end;
  KeyNameData out{};
  for (size_t i = begin; i < end; ++i) out[i - begin] = mapped[i];
  return out;
}

bool KeyNames::validName(const KeyNameData& name) {
  if (name[0] == 0) return false;  // non-empty
  // A canonical (normalized) name never begins with these: '.'/'-' are hidden/
  // option-like on a filesystem; a leading '_' means a boundary space that
  // normalize() strips.
  if (name[0] == '.' || name[0] == '-' || name[0] == '_') return false;
  bool ended = false;
  for (size_t i = 0; i < name.size(); ++i) {
    const uint8_t b = name[i];
    if (b == 0) {  // zero-padding: only a trailing run is allowed
      ended = true;
      continue;
    }
    if (ended) return false;  // a byte after a NUL hole -> not a padded name
    if (b < 0x20) return false;  // ASCII control
    // Path/URL/filesystem breakers (ASCII). A canonical name carries no space
    // (normalize turned each into '_'); '_' itself is safe and allowed.
    static const char* bad = "/\\:*?\"<>|#%&{}[]^~;@=+,`'()$!";
    if (b < 0x80 && std::strchr(bad, static_cast<char>(b)) != nullptr)
      return false;
  }
  return true;
}

void KeyNames::rebuildReverse() {
  byName_.clear();
  byName_.reserve(store_.getObjects().size());
  for (const auto& [key, kn] : store_) {
    if (kn.getName() == KeyNameData{}) continue;  // erased
    byName_.emplace(normalize(kn.getName()), key);
  }
}

KeyNames::RegisterResult KeyNames::registerName(const Hash& key,
                                                const KeyNameData& name,
                                                uint64_t maxKeyName) {
  // The stored name IS the normalized form (spaces -> underscores, trimmed):
  // one canonical representation, so the forward store, the reverse index, and
  // the /f/<name>/ path all agree.
  const KeyNameData norm = normalize(name);
  if (!validName(norm)) return RegisterResult::BadName;

  // Name uniqueness: reject only if a DIFFERENT key holds it.
  if (auto it = byName_.find(norm); it != byName_.end() && it->second != key)
    return RegisterResult::NameTaken;

  auto existing = store_.find(key);
  const bool isNew = (existing == store_.end() ||
                      existing->second.getName() == KeyNameData{});
  if (isNew && maxKeyName != 0 &&
      store_.getObjects().size() >= maxKeyName)
    return RegisterResult::CapacityFull;

  // Free the old reverse entry if this key is renaming.
  if (existing != store_.end() &&
      existing->second.getName() != KeyNameData{}) {
    byName_.erase(normalize(existing->second.getName()));
  }

  KeyName kn(norm);
  store_.update(key, kn);
  byName_[norm] = key;
  return RegisterResult::Ok;
}

bool KeyNames::clearName(const Hash& key) {
  auto it = store_.find(key);
  if (it == store_.end() || it->second.getName() == KeyNameData{}) return false;
  byName_.erase(normalize(it->second.getName()));
  store_.erase(key);
  return true;
}

bool KeyNames::nameForKey(const Hash& key, KeyNameData& outName) const {
  auto it = store_.find(key);
  if (it == store_.end() || it->second.getName() == KeyNameData{}) return false;
  outName = it->second.getName();
  return true;
}

bool KeyNames::keyForName(const KeyNameData& name, Hash& outKey) const {
  auto it = byName_.find(name);
  if (it == byName_.end()) return false;
  outKey = it->second;
  return true;
}

void KeyNames::checkFlush(uint64_t amount) {
  flushAccumulator_ += amount;
  if (flushAccumulator_ > flushValue_) {
    flushAccumulator_ = 0;
    store_.flush();
  }
}

}  // namespace ces
