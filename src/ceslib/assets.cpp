#include <ces/assets.h>
#include <minx/blog.h>

LOG_MODULE("ast");

namespace ces {

Assets::Assets(const std::string& dataDir, uint64_t minAsset,
               uint64_t flushValue, size_t bufferSize)
    : store_(dataDir, logkv::StoreFlags::createDir, bufferSize),
      flushValue_(flushValue) {
  store_.getObjects().reserve(minAsset);
}

Assets::ActiveAsset Assets::get(const minx::Hash& assetId) {
  return ActiveAsset{*this, assetId, store_.find(assetId)};
}

Assets::ActiveAsset Assets::getFirst() {
  auto it = store_.begin();
  if (it != store_.end()) {
    return ActiveAsset{*this, it->first, it};
  }
  return ActiveAsset{*this, minx::Hash{}, it};
}

void Assets::checkFlush(uint64_t amount) {
  flushAccumulator_ += amount;
  if (flushAccumulator_ > flushValue_) {
    flushAccumulator_ = 0;
    store_.flush();
  }
}

bool Assets::ActiveAsset::exists() const { return it != parent.store_.end(); }

Asset& Assets::ActiveAsset::data() { return it->second; }
const Asset& Assets::ActiveAsset::data() const { return it->second; }

HashPrefix Assets::ActiveAsset::getOwnerId() const {
  return it->second.getOwnerId();
}
uint32_t Assets::ActiveAsset::getPrice() const { return it->second.getPrice(); }
uint16_t Assets::ActiveAsset::getBalance() const {
  return it->second.getBalance();
}
const AssetData& Assets::ActiveAsset::getContent() const {
  return it->second.getContent();
}

void Assets::ActiveAsset::setContent(const AssetData& content) {
  if (!exists())
    return;
  data().setContent(content);
  // RAM only — no WAL persist. Survives via snapshots.
  LOGTRACE << "setContent" << VAR(id);
}

void Assets::ActiveAsset::setPrice(uint32_t price) {
  persistWithMode(Asset::SerMode::Meta,
                  [&](Asset& a) { a.setPrice(price); });
  if (exists()) {
    LOGTRACE << "setPrice" << VAR(id) << VAR(price);
  }
}

void Assets::ActiveAsset::setOwner(const HashPrefix& newOwner) {
  persistWithMode(Asset::SerMode::Meta,
                  [&](Asset& a) { a.setOwnerId(newOwner); });
  if (exists()) {
    LOGTRACE << "setOwner" << VAR(id) << VAR(newOwner);
  }
}

void Assets::ActiveAsset::setBalance(uint16_t newBalance) {
  persistWithMode(Asset::SerMode::Balance,
                  [&](Asset& a) { a.setBalance(newBalance); });
  if (exists()) {
    LOGTRACE << "setBalance" << VAR(id) << VAR(newBalance);
  }
}

void Assets::ActiveAsset::updateFull(const HashPrefix& newOwner,
                                     const AssetData& content, uint32_t price) {
  persistWithMode(Asset::SerMode::Full, [&](Asset& a) {
    a.setOwnerId(newOwner);
    a.setContent(content);
    a.setPrice(price);
  });
  LOGTRACE << "updateFull" << VAR(id) << VAR(newOwner) << VAR(price);
}

void Assets::ActiveAsset::transferOwnership(const HashPrefix& newOwner) {
  persistWithMode(Asset::SerMode::Meta, [&](Asset& a) {
    a.setOwnerId(newOwner);
    a.setPrice(0);
  });
  if (exists()) {
    LOGTRACE << "transferOwnership" << VAR(id) << VAR(newOwner);
  }
}

} // namespace ces
