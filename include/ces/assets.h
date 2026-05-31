#pragma once

#include <ces/asset.h>
#include <ces/types.h>
#include <logkv/store.h>

#include <string>

#include <boost/unordered/unordered_flat_map.hpp>

namespace ces {

class Assets {
public:
  using AssetStore = logkv::Store<boost::unordered_flat_map, minx::Hash, Asset>;

  struct ActiveAsset {
    Assets& parent;
    minx::Hash id;
    AssetStore::iterator it;

    bool exists() const;
    Asset& data();
    const Asset& data() const;

    HashPrefix getOwnerId() const;
    uint32_t getPrice() const;
    uint16_t getBalance() const;
    const AssetData& getContent() const;

    void setContent(const AssetData& content);
    void setPrice(uint32_t price);
    void setOwner(const HashPrefix& newOwner);
    void setBalance(uint16_t newBalance);

    void updateFull(const HashPrefix& newOwner, const AssetData& content,
                    uint32_t price);
    void transferOwnership(const HashPrefix& newOwner);

  private:
    template <typename Mutator>
    void persistWithMode(Asset::SerMode mode, Mutator&& mutate) {
      if (!exists())
        return;
      mutate(data());
      Asset::SerModeGuard guard(mode);
      parent.store_.persist(it);
    }
  };

  Assets(const std::string& dataDir, uint64_t minAsset, uint64_t flushValue,
         size_t bufferSize = 1 << 19);

  AssetStore& getStore() { return store_; }
  AssetStore* operator->() { return &store_; }
  const AssetStore* operator->() const { return &store_; }
  AssetStore& operator*() { return store_; }
  const AssetStore& operator*() const { return store_; }

  ActiveAsset get(const minx::Hash& assetId);
  ActiveAsset getFirst();

  void checkFlush(uint64_t amount);

private:
  friend struct ActiveAsset;

  AssetStore store_;
  uint64_t flushValue_;
  uint64_t flushAccumulator_ = 0;
};

} // namespace ces