#pragma once

#include <ces/keyname.h>
#include <ces/types.h>
#include <logkv/store.h>

#include <string>

#include <boost/unordered/unordered_flat_map.hpp>

namespace ces {

// The key_names table wrapper (see keyname.h). Owns the forward store
// (keyHash -> name) and a DERIVED reverse index (normalized-name -> keyHash)
// rebuilt from the forward store on load, so snapshot and WAL replay produce
// the same state. All mutations go through this class so both stay consistent.
//
// The username/name unification: a name's path form replaces spaces with
// underscores. Uniqueness is enforced on that normalized form, so "Ada
// Lovelace" and "Ada_Lovelace" cannot both exist (they would collide as /f/
// segments).
class KeyNames {
 public:
  using KeyNameStore = logkv::Store<boost::unordered_flat_map, Hash, KeyName>;

  enum class RegisterResult { Ok, NameTaken, CapacityFull, BadName };

  KeyNames(const std::string& dataDir, uint64_t minKeyName, uint64_t flushValue,
           size_t bufferSize = 1 << 19);

  KeyNameStore& getStore() { return store_; }
  KeyNameStore* operator->() { return &store_; }
  const KeyNameStore* operator->() const { return &store_; }
  KeyNameStore& operator*() { return store_; }
  const KeyNameStore& operator*() const { return store_; }

  // Register/update the caller's own name. `key` is the signer's full pubkey
  // (the entry's owner, by crypto). Enforces name uniqueness on the normalized
  // form and the capacity cap. Re-registering the same key with a new name
  // moves it (frees the old reverse entry).
  RegisterResult registerName(const Hash& key, const KeyNameData& name,
                              uint64_t maxKeyName);

  // Erase the caller's own entry (both maps). No-op if absent.
  bool clearName(const Hash& key);

  // key -> name ("" via outFound=false if absent).
  bool nameForKey(const Hash& key, KeyNameData& outName) const;
  // normalized name -> key (the reverse index). `name` is normalized here.
  bool keyForName(const KeyNameData& name, Hash& outKey) const;

  // The canonical form: spaces and underscores both map to '_', with leading
  // and trailing underscores stripped (a name cannot begin or end with one).
  // Deterministic, no locale. This is what is STORED and what /f/<name>/ uses;
  // registerName runs it on the input, so "Ada Lovelace" and "Ada_Lovelace"
  // are the same name.
  static KeyNameData normalize(const KeyNameData& name);
  // A valid (already-normalized) name: 1..32 bytes, no NUL-hole, no control
  // chars, no path breakers, no leading '.'/'-'. (UTF-8 validity is the
  // client's concern; the ledger only guards path/pathmap safety.)
  static bool validName(const KeyNameData& name);

  void checkFlush(uint64_t amount);
  const boost::unordered_flat_map<KeyNameData, Hash>& reverse() const {
    return byName_;
  }
  // Rebuild the reverse index from the forward store. Called on load, and by
  // the server after the daily rent sweep erases entries directly on the store
  // (which bypasses this wrapper's dual-map bookkeeping).
  void rebuildReverse();

 private:

  KeyNameStore store_;
  boost::unordered_flat_map<KeyNameData, Hash> byName_;  // normalized -> key
  uint64_t flushValue_;
  uint64_t flushAccumulator_ = 0;
};

}  // namespace ces
