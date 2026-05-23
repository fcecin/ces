#pragma once

#include <ces/types.h>

#include <QString>
#include <QStringList>
#include <QList>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QFile>
#include <QDir>
#include <QStandardPaths>
#include <QByteArray>

#include <algorithm>
#include <cstdint>

// =============================================================================
// Currency formatting — 8 decimal places (1 internal unit = 0.00000001)
// =============================================================================

inline QString formatAmount(int64_t raw) {
  bool negative = raw < 0;
  uint64_t abs = negative ? static_cast<uint64_t>(-raw)
                          : static_cast<uint64_t>(raw);
  uint64_t whole = abs / ces::PRICE_UNIT;
  uint64_t frac = abs % ces::PRICE_UNIT;
  return QString("%1%2.%3")
    .arg(negative ? "-" : "")
    .arg(whole)
    .arg(frac, 8, 10, QChar('0'));
}

inline QString formatAmount(uint64_t raw) {
  uint64_t whole = raw / ces::PRICE_UNIT;
  uint64_t frac = raw % ces::PRICE_UNIT;
  return QString("%1.%2")
    .arg(whole)
    .arg(frac, 8, 10, QChar('0'));
}

// =============================================================================
// TrackedAsset — persisted asset entry for the wallet
// =============================================================================

struct TrackedAsset {
  QString assetKey;       // 64-char hex (32 bytes)
  QString server;         // literal server string (part of identity)
  // Cached query result
  bool known = false;     // false = never queried / no data
  QString owner;          // HashPrefix hex (16 chars), if known
  QString contentHex;     // 210 bytes as hex (420 chars), if known
  uint16_t days = 0;
  uint32_t storedPrice = 0;  // whole credits (real = stored * 100,000,000)
  QString lastQueryTime;  // ISO timestamp
  QString lastQueryError; // empty = OK

  // Composite ID for display and lookup
  QString fullId() const { return assetKey + "@" + server; }

  static TrackedAsset fromJson(const QJsonObject& obj) {
    TrackedAsset a;
    a.assetKey = obj.value("assetKey").toString();
    a.server = obj.value("server").toString();
    a.known = obj.value("known").toBool(false);
    a.owner = obj.value("owner").toString();
    a.contentHex = obj.value("contentHex").toString();
    a.days = static_cast<uint16_t>(obj.value("days").toInt(0));
    a.storedPrice = static_cast<uint32_t>(
      obj.value("storedPrice").toString("0").toULongLong());
    a.lastQueryTime = obj.value("lastQueryTime").toString();
    a.lastQueryError = obj.value("lastQueryError").toString();
    return a;
  }

  QJsonObject toJson() const {
    QJsonObject obj;
    obj["assetKey"] = assetKey;
    obj["server"] = server;
    obj["known"] = known;
    obj["owner"] = owner;
    obj["contentHex"] = contentHex;
    obj["days"] = days;
    obj["storedPrice"] = QString::number(storedPrice);
    obj["lastQueryTime"] = lastQueryTime;
    obj["lastQueryError"] = lastQueryError;
    return obj;
  }

  // Try to display content as text, fall back to hex
  QString contentDisplay() const {
    if (contentHex.isEmpty()) return "(no data)";
    QByteArray raw = QByteArray::fromHex(contentHex.toLatin1());
    bool isText = true;
    int len = 0;
    for (int i = 0; i < raw.size(); ++i) {
      uint8_t c = static_cast<uint8_t>(raw[i]);
      if (c == 0) break;
      if (c < 32 || c > 126) { isText = false; break; }
      len++;
    }
    if (len > 0 && isText)
      return QString::fromLatin1(raw.data(), len);
    if (contentHex.size() > 64)
      return contentHex.left(64) + "...";
    return contentHex;
  }

  // Display asset key as text if valid printable ASCII, otherwise hex
  QString keyDisplay() const {
    QByteArray raw = QByteArray::fromHex(assetKey.toLatin1());
    int len = 0;
    bool isText = true;
    for (int i = 0; i < raw.size(); ++i) {
      uint8_t c = static_cast<uint8_t>(raw[i]);
      if (c == 0) break;
      if (c < 32 || c > 126) { isText = false; break; }
      len++;
    }
    if (len > 0 && isText)
      return QString::fromLatin1(raw.data(), len);
    return assetKey;
  }

  // Real price in internal units
  uint64_t realPrice() const {
    return ces::storedToRealPrice(storedPrice);
  }
};

// =============================================================================
// AppConfig — JSON configuration
// =============================================================================

struct AppConfig {
  static QString defaultEntry() {
    return "ces.pubcom.org:" + QString::number(ces::DEFAULT_PORT);
  }

  // LIFO cap on the "recent transfer destinations" dropdown.
  static constexpr int kMaxTransferHistory = 20;

  // Mine throttle max is 1 sleep microsecond / hash = effectively 1 hash/sec.
  static constexpr int kMaxMineThrottleUs = 1'000'000;

  QString currentServer;        // "" = none selected
  QStringList servers;          // address book
  QMap<QString, QJsonArray> serverInfo; // cached server info per server addr
  int defaultAccount = 0;       // last selected account index
  int mineThreads = 1;          // number of mining threads
  int mineThrottleUs = 1000;    // microseconds sleep between hash batches
  QStringList transferDestHistory;  // recent transfer destinations (max 20)
  QList<TrackedAsset> trackedAssets; // tracked assets across all servers

  QString dataDirOverride;

  QString configDir() const {
    if (!dataDirOverride.isEmpty()) return dataDirOverride;
    return QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
  }

  QString configPath() const {
    return configDir() + "/config.json";
  }

  void load() {
    QFile f(configPath());
    if (f.exists() && f.open(QIODevice::ReadOnly)) {
      QJsonParseError err;
      auto doc = QJsonDocument::fromJson(f.readAll(), &err);
      if (!doc.isNull()) {
        auto obj = doc.object();
        currentServer = obj.value("currentServer").toString();
        defaultAccount = obj.value("defaultAccount").toInt(0);
        mineThreads = std::clamp(obj.value("mineThreads").toInt(1), 1, 64);
        mineThrottleUs = std::clamp(
          obj.value("mineThrottleUs").toInt(1000), 0, kMaxMineThrottleUs);
        transferDestHistory.clear();
        for (auto v : obj.value("transferDestHistory").toArray())
          transferDestHistory.append(v.toString());
        if (transferDestHistory.size() > kMaxTransferHistory)
          transferDestHistory =
            transferDestHistory.mid(0, kMaxTransferHistory);
        trackedAssets.clear();
        for (auto v : obj.value("trackedAssets").toArray())
          trackedAssets.append(TrackedAsset::fromJson(v.toObject()));
        servers.clear();
        for (auto v : obj.value("servers").toArray())
          servers.append(v.toString());
        serverInfo.clear();
        auto siObj = obj.value("serverInfo").toObject();
        for (auto it = siObj.begin(); it != siObj.end(); ++it)
          serverInfo[it.key()] = it.value().toArray();
      }
    }
    const QString defEntry = defaultEntry();
    if (!servers.contains(defEntry))
      servers.prepend(defEntry);
  }

  void save() const {
    QDir().mkpath(configDir());
    QFile f(configPath());
    if (!f.open(QIODevice::WriteOnly)) return;

    QJsonObject obj;
    obj["currentServer"] = currentServer;
    obj["defaultAccount"] = defaultAccount;
    obj["mineThreads"] = mineThreads;
    obj["mineThrottleUs"] = mineThrottleUs;
    QJsonArray destArr;
    for (auto& d : transferDestHistory) destArr.append(d);
    obj["transferDestHistory"] = destArr;
    QJsonArray assetArr;
    for (auto& a : trackedAssets) assetArr.append(a.toJson());
    obj["trackedAssets"] = assetArr;
    QJsonArray arr;
    for (auto& s : servers) arr.append(s);
    obj["servers"] = arr;
    QJsonObject siObj;
    for (auto it = serverInfo.begin(); it != serverInfo.end(); ++it)
      siObj[it.key()] = it.value();
    obj["serverInfo"] = siObj;

    f.write(QJsonDocument(obj).toJson(QJsonDocument::Indented));
  }

  int findTrackedAsset(const QString& assetKey, const QString& server) const {
    for (int i = 0; i < trackedAssets.size(); ++i)
      if (trackedAssets[i].assetKey == assetKey &&
          trackedAssets[i].server == server)
        return i;
    return -1;
  }

  bool addTrackedAsset(const TrackedAsset& a) {
    if (findTrackedAsset(a.assetKey, a.server) >= 0)
      return false;
    trackedAssets.append(a);
    save();
    return true;
  }

  bool removeTrackedAsset(const QString& assetKey, const QString& server) {
    int idx = findTrackedAsset(assetKey, server);
    if (idx < 0) return false;
    trackedAssets.removeAt(idx);
    save();
    return true;
  }

  void updateTrackedAsset(int idx, const TrackedAsset& a) {
    if (idx >= 0 && idx < trackedAssets.size()) {
      trackedAssets[idx] = a;
      save();
    }
  }

  void pushTransferDest(const QString& dest) {
    transferDestHistory.removeAll(dest);
    transferDestHistory.prepend(dest);
    while (transferDestHistory.size() > kMaxTransferHistory)
      transferDestHistory.removeLast();
    save();
  }
};
