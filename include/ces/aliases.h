#pragma once

#include <ces/alias.h>
#include <ces/types.h>
#include <logkv/store.h>

#include <string>

#include <boost/unordered/unordered_flat_map.hpp>

namespace ces {

class Aliases {
public:
  using AliasStore = logkv::Store<boost::unordered_flat_map, uint32_t, Alias>;

  struct ActiveAlias {
    Aliases& parent;
    uint32_t id;
    AliasStore::iterator it;

    bool exists() const;
    Alias& data();
    const Alias& data() const;

    HashPrefix getOwner() const;
    HashPrefix getEditor() const;
    uint16_t getOp() const;
    const AliasData& getContent() const;

    void setOwner(const HashPrefix& owner);
    void setOp(uint16_t op);
    void setContent(const AliasData& content);
    void updateValue(const Alias& value);

  private:
    template <typename Mutator>
    void persistWithMode(Alias::SerMode mode, Mutator&& mutate) {
      if (!exists())
        return;
      mutate(data());
      Alias::SerModeGuard guard(mode);
      parent.store_.persist(it);
    }
  };

  Aliases(const std::string& dataDir, uint64_t minAlias, uint64_t flushValue,
          size_t bufferSize = 1 << 19);

  AliasStore& getStore() { return store_; }
  AliasStore* operator->() { return &store_; }
  const AliasStore* operator->() const { return &store_; }
  AliasStore& operator*() { return store_; }
  const AliasStore& operator*() const { return store_; }

  ActiveAlias get(uint32_t id);
  ActiveAlias getFirst();

  void checkFlush(uint64_t amount);

private:
  friend struct ActiveAlias;

  AliasStore store_;
  uint64_t flushValue_;
  uint64_t flushAccumulator_ = 0;
};

} // namespace ces
