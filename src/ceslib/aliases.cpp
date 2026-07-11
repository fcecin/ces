#include <ces/aliases.h>
#include <minx/blog.h>

LOG_MODULE("als");

namespace ces {

Aliases::Aliases(const std::string& dataDir, uint64_t minAlias,
                 uint64_t flushValue, size_t bufferSize)
    : store_(dataDir, logkv::StoreFlags::createDir, bufferSize),
      flushValue_(flushValue) {
  store_.getObjects().reserve(minAlias);
}

Aliases::ActiveAlias Aliases::get(uint32_t id) {
  return ActiveAlias{*this, id, store_.find(id)};
}

Aliases::ActiveAlias Aliases::getFirst() {
  auto it = store_.begin();
  if (it != store_.end()) {
    return ActiveAlias{*this, it->first, it};
  }
  return ActiveAlias{*this, 0u, it};
}

void Aliases::checkFlush(uint64_t amount) {
  flushAccumulator_ += amount;
  if (flushAccumulator_ > flushValue_) {
    flushAccumulator_ = 0;
    store_.flush();
  }
}

bool Aliases::ActiveAlias::exists() const { return it != parent.store_.end(); }

Alias& Aliases::ActiveAlias::data() { return it->second; }
const Alias& Aliases::ActiveAlias::data() const { return it->second; }

HashPrefix Aliases::ActiveAlias::getOwner() const {
  return exists() ? it->second.getOwner() : HashPrefix{};
}
HashPrefix Aliases::ActiveAlias::getEditor() const {
  return exists() ? it->second.getEditor() : HashPrefix{};
}
uint16_t Aliases::ActiveAlias::getOp() const {
  return exists() ? it->second.getOp() : 0;
}
const AliasData& Aliases::ActiveAlias::getContent() const {
  static const AliasData kEmpty{};
  return exists() ? it->second.getContent() : kEmpty;
}

void Aliases::ActiveAlias::setOwner(const HashPrefix& owner) {
  persistWithMode(Alias::SerMode::Full, [&](Alias& a) { a.setOwner(owner); });
}

void Aliases::ActiveAlias::setOp(uint16_t op) {
  persistWithMode(Alias::SerMode::Full, [&](Alias& a) { a.setOp(op); });
}

void Aliases::ActiveAlias::setContent(const AliasData& content) {
  persistWithMode(Alias::SerMode::Full, [&](Alias& a) { a.setContent(content); });
}

void Aliases::ActiveAlias::updateValue(const Alias& value) {
  persistWithMode(Alias::SerMode::Full, [&](Alias& a) { a = value; });
}

} // namespace ces
