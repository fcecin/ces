#pragma once

#define CES_PERSISTED_BOILERPLATE(DEFAULT_MODE)                                \
  static void _setSerMode(SerMode m) { serMode_ = m; }                         \
  static SerMode _getSerMode() { return serMode_; }                            \
  static void _logkvStoreSnapshot(bool s) { snapshotFlag_ = s; }               \
  static bool _logkvStoreSnapshot() { return snapshotFlag_; }                  \
                                                                               \
  struct SerModeGuard {                                                        \
    SerMode prev;                                                              \
    explicit SerModeGuard(SerMode m) : prev(_getSerMode()) { _setSerMode(m); } \
    ~SerModeGuard() { _setSerMode(prev); }                                     \
    SerModeGuard(const SerModeGuard&) = delete;                                \
    SerModeGuard& operator=(const SerModeGuard&) = delete;                     \
  };                                                                           \
                                                                               \
private:                                                                       \
  inline static thread_local SerMode serMode_ = DEFAULT_MODE;                  \
  inline static thread_local bool snapshotFlag_ = false;                       \
                                                                               \
public:
