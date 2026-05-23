#include "rpcserver.h"

#include <ces/util/resolver.h>
#include <ces/util/wallet.h>

#include <QMessageBox>
#include <QJsonArray>

#include "console.h"

RpcServer::RpcServer(RpcWalletBridge bridge, ConsoleWidget* console,
                     bool autoApprove, QObject* parent)
  : QObject(parent), bridge_(std::move(bridge)), console_(console),
    autoApprove_(autoApprove) {}

bool RpcServer::start(uint16_t port) {
  server_ = new QTcpServer(this);
  connect(server_, &QTcpServer::newConnection,
    this, &RpcServer::onNewConnection);

  if (!server_->listen(QHostAddress::LocalHost, port)) {
    log("RPC: failed to listen on port " + QString::number(port));
    return false;
  }
  log("RPC: listening on localhost:" + QString::number(port));
  return true;
}

void RpcServer::stop() {
  if (server_) {
    server_->close();
    server_->deleteLater();
    server_ = nullptr;
  }
}

void RpcServer::onNewConnection() {
  while (auto* socket = server_->nextPendingConnection()) {
    connect(socket, &QTcpSocket::readyRead, this, &RpcServer::onReadyRead);
    connect(socket, &QTcpSocket::disconnected, this, &RpcServer::onDisconnected);
  }
}

void RpcServer::onReadyRead() {
  auto* socket = qobject_cast<QTcpSocket*>(sender());
  if (!socket) return;

  QByteArray data = socket->property("_buf").toByteArray();
  data += socket->readAll();
  socket->setProperty("_buf", data);

  int headerEnd = data.indexOf("\r\n\r\n");
  if (headerEnd < 0) return;

  int contentLength = 0;
  int clPos = data.indexOf("Content-Length:");
  if (clPos < 0) clPos = data.indexOf("content-length:");
  if (clPos >= 0) {
    int clEnd = data.indexOf("\r\n", clPos);
    contentLength = data.mid(clPos + 15, clEnd - clPos - 15).trimmed().toInt();
  }

  int bodyStart = headerEnd + 4;
  if (data.size() - bodyStart < contentLength) return;

  auto req = parseHttp(data);
  socket->setProperty("_buf", QByteArray());

  if (!req.valid) {
    sendResponse(socket, 400, R"({"error":"Bad request"})");
    return;
  }

  if (req.method == "OPTIONS") {
    sendCorsHeaders(socket, req.origin);
    return;
  }

  if (req.method != "POST") {
    sendResponse(socket, 405, R"({"error":"Method not allowed"})", req.origin);
    return;
  }

  QJsonParseError err;
  auto doc = QJsonDocument::fromJson(req.body, &err);
  if (doc.isNull() || !doc.isObject()) {
    sendResponse(socket, 400,
      R"({"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":null})",
      req.origin);
    return;
  }

  auto rpcReq = doc.object();
  auto id = rpcReq.value("id");

  int keyIndex = resolveOrigin(req.origin);
  if (keyIndex < 0) {
    QJsonObject errResp;
    errResp["jsonrpc"] = "2.0";
    errResp["error"] = QJsonObject{
      {"code", -32000}, {"message", "Origin denied by user"}};
    errResp["id"] = id;
    sendResponse(socket, 403,
      QJsonDocument(errResp).toJson(QJsonDocument::Compact), req.origin);
    return;
  }

  auto result = dispatch(rpcReq, keyIndex);
  result["id"] = id;
  result["jsonrpc"] = "2.0";

  sendResponse(socket, 200,
    QJsonDocument(result).toJson(QJsonDocument::Compact), req.origin);
}

void RpcServer::onDisconnected() {
  auto* socket = qobject_cast<QTcpSocket*>(sender());
  if (socket) socket->deleteLater();
}

RpcServer::HttpRequest RpcServer::parseHttp(const QByteArray& raw) {
  HttpRequest req;
  int firstLine = raw.indexOf("\r\n");
  if (firstLine < 0) return req;

  QString requestLine = QString::fromUtf8(raw.left(firstLine));
  auto parts = requestLine.split(' ');
  if (parts.size() < 2) return req;
  req.method = parts[0];

  int originPos = raw.indexOf("\r\nOrigin:");
  if (originPos < 0) originPos = raw.indexOf("\r\norigin:");
  if (originPos >= 0) {
    int originEnd = raw.indexOf("\r\n", originPos + 2);
    req.origin = QString::fromUtf8(
      raw.mid(originPos + 9, originEnd - originPos - 9)).trimmed();
  }

  int bodyStart = raw.indexOf("\r\n\r\n") + 4;
  if (bodyStart < raw.size())
    req.body = raw.mid(bodyStart);

  req.valid = true;
  return req;
}

void RpcServer::sendResponse(QTcpSocket* socket, int status,
                             const QByteArray& body, const QString& origin) {
  QByteArray resp = "HTTP/1.1 " + QByteArray::number(status) + " OK\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
  if (!origin.isEmpty()) {
    resp += "Access-Control-Allow-Origin: " + origin.toUtf8() + "\r\n";
    resp += "Access-Control-Allow-Methods: POST, OPTIONS\r\n";
    resp += "Access-Control-Allow-Headers: Content-Type\r\n";
  }
  resp += "\r\n";
  resp += body;
  socket->write(resp);
  socket->flush();
  socket->disconnectFromHost();
}

void RpcServer::sendCorsHeaders(QTcpSocket* socket, const QString& origin) {
  QByteArray resp = "HTTP/1.1 204 No Content\r\n"
    "Access-Control-Allow-Origin: " + origin.toUtf8() + "\r\n"
    "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
    "Access-Control-Allow-Headers: Content-Type\r\n"
    "Access-Control-Max-Age: 86400\r\n"
    "\r\n";
  socket->write(resp);
  socket->flush();
  socket->disconnectFromHost();
}

int RpcServer::resolveOrigin(const QString& origin) {
  if (origin.isEmpty())
    return -1;

  std::string label = origin.toStdString();
  int idx = bridge_.findByLabel(label);
  if (idx >= 0)
    return idx;

  if (!autoApprove_) {
    auto reply = QMessageBox::question(nullptr, "Wallet Access Request",
      QString("%1\n\nwants wallet access.\nA new account will be created for this app.\n\nAllow?")
        .arg(origin),
      QMessageBox::Yes | QMessageBox::No, QMessageBox::No);

    if (reply != QMessageBox::Yes) {
      log("RPC: denied origin " + origin);
      return -1;
    }
  } else {
    log("RPC: auto-approved origin " + origin);
  }

  idx = bridge_.generateKey(label);
  bridge_.saveAndRefresh();
  log("RPC: approved origin " + origin + " → @" + QString::number(idx));
  tryAutoFund(idx);
  return idx;
}

QJsonObject RpcServer::dispatch(const QJsonObject& request, int keyIndex) {
  QString method = request.value("method").toString();
  auto params = request.value("params").toObject();

  if (method == "ping") {
    return QJsonObject{{"result", "pong"}};
  }

  if (method == "getAccount") {
    return QJsonObject{{"result", QJsonObject{
      {"publicKey", QString::fromStdString(bridge_.pubKeyHex(keyIndex))},
      {"index", keyIndex},
      {"label", QString::fromStdString(bridge_.label(keyIndex))}
    }}};
  }

  // --- Unsigned: queryAsset (free, no key needed) ---
  if (method == "queryAsset") {
    QString assetKey = params.value("key").toString();
    if (assetKey.isEmpty())
      return errorResult(-32602, "Missing 'key' parameter");

    QString server = bridge_.currentServer();
    if (server.isEmpty())
      return errorResult(-32000, "No current server configured");

    try {
      auto probe = ces::Resolver::probe(server.toStdString());
      auto clientPtr = probe.makeClient(false);
      auto& client = *clientPtr;
      client.start(0);
      if (!client.connect()) {
        client.stop();
        return errorResult(-32000, "Connect failed");
      }

      minx::Hash aid = parseAssetKey(assetKey);

      ces::HashPrefix owner;
      ces::AssetData content;
      uint16_t balance = 0;
      uint32_t price = 0;
      client.queryAsset(aid, owner, content, balance, price);
      client.disconnect();
      client.stop();

      // Format content as text if printable, else hex
      QString contentStr = QString::fromStdString(
        ces::contentToDisplayString(content));
      QString ownerHex;
      for (auto b : owner) ownerHex += QString("%1").arg(b, 2, 16, QChar('0'));

      return QJsonObject{{"result", QJsonObject{
        {"owner", ownerHex},
        {"content", contentStr},
        {"days", ces::assetDays(balance)},
        {"private", ces::isAssetPrivate(balance)},
        {"assetOwned", ces::isAssetOwned(balance)},
        {"immutable", ces::isAssetImmutable(balance)},
        {"price", static_cast<int>(price)}
      }}};
    } catch (std::exception& e) {
      return errorResult(-32000, e.what());
    }
  }

  // --- Signed operations (require approved origin + key) ---

  if (method == "createAsset") {
    QString assetKey = params.value("key").toString();
    QString content = params.value("content").toString();
    int days = params.value("days").toInt(30);
    if (assetKey.isEmpty() || content.isEmpty())
      return errorResult(-32602, "Missing 'key' or 'content' parameter");

    return executeOnServer(keyIndex, [&](ces::CesClient& client) {
      minx::Hash aid = parseAssetKey(assetKey);

      ces::AssetData ad{};
      QByteArray contentUtf8 = content.toUtf8();
      memcpy(ad.data(), contentUtf8.data(), std::min<int>(contentUtf8.size(), 210));

      uint8_t rc = client.createAsset(aid, ad, static_cast<uint16_t>(days));
      if (rc == ces::CES_OK)
        return QJsonObject{{"result", "ok"}};
      return errorResult(-32000, ces::errorString(rc));
    });
  }

  if (method == "fundAsset") {
    QString assetKey = params.value("key").toString();
    int days = params.value("days").toInt(1);
    if (assetKey.isEmpty())
      return errorResult(-32602, "Missing 'key' parameter");

    return executeOnServer(keyIndex, [&](ces::CesClient& client) {
      minx::Hash aid = parseAssetKey(assetKey);

      uint8_t rc = client.fundAsset(aid, static_cast<uint16_t>(days));
      if (rc == ces::CES_OK)
        return QJsonObject{{"result", "ok"}};
      return errorResult(-32000, ces::errorString(rc));
    });
  }

  if (method == "transfer") {
    QString dest = params.value("dest").toString();
    double amount = params.value("amount").toDouble(0);
    bool open = params.value("open").toBool(false);
    if (dest.isEmpty() || amount <= 0)
      return errorResult(-32602, "Missing 'dest' or 'amount' parameter");

    uint64_t intAmount = static_cast<uint64_t>(
      amount * static_cast<double>(ces::PRICE_UNIT));

    return executeOnServer(keyIndex, [&](ces::CesClient& client) {
      minx::Hash destKey;
      if (dest.size() == 64)
        minx::stringToHash(destKey, dest.toStdString());
      else {
        // Try wallet resolution (@N)
        std::string resolved = dest.toStdString();
        destKey.fill(0);
        minx::stringToHash(destKey, resolved);
      }

      int64_t newBal = 0;
      uint8_t rc;
      if (open)
        rc = client.openTransfer(destKey, intAmount, newBal);
      else
        rc = client.transfer(destKey, intAmount, newBal);

      if (rc == ces::CES_OK)
        return QJsonObject{{"result", QJsonObject{
          {"newBalance", QString::number(newBal)},
          {"amount", QString::number(intAmount)}
        }}};
      return errorResult(-32000, ces::errorString(rc));
    });
  }

  if (method == "updateAsset") {
    QString assetKey = params.value("key").toString();
    QString content = params.value("content").toString();
    int price = params.value("price").toInt(0);
    if (assetKey.isEmpty() || content.isEmpty())
      return errorResult(-32602, "Missing 'key' or 'content' parameter");

    return executeOnServer(keyIndex, [&](ces::CesClient& client) {
      minx::Hash aid = parseAssetKey(assetKey);
      ces::AssetData ad{};
      QByteArray contentUtf8 = content.toUtf8();
      memcpy(ad.data(), contentUtf8.data(), std::min<int>(contentUtf8.size(), 210));
      ces::HashPrefix owner = ces::Account::getMapKey(bridge_.keyPair(keyIndex).getPublicKeyAsHash());
      uint8_t rc = client.updateAsset(aid, owner, ad, static_cast<uint32_t>(price));
      if (rc == ces::CES_OK) return QJsonObject{{"result", "ok"}};
      return errorResult(-32000, ces::errorString(rc));
    });
  }

  if (method == "updateAssetFast") {
    QString assetKey = params.value("key").toString();
    QString content = params.value("content").toString();
    if (assetKey.isEmpty() || content.isEmpty())
      return errorResult(-32602, "Missing 'key' or 'content' parameter");

    return executeOnServer(keyIndex, [&](ces::CesClient& client) {
      minx::Hash aid = parseAssetKey(assetKey);
      ces::AssetData ad{};
      QByteArray contentUtf8 = content.toUtf8();
      memcpy(ad.data(), contentUtf8.data(), std::min<int>(contentUtf8.size(), 210));
      uint8_t rc = client.updateAssetFast(aid, ad);
      if (rc == ces::CES_OK) return QJsonObject{{"result", "ok"}};
      return errorResult(-32000, ces::errorString(rc));
    });
  }

  if (method == "updateAssetMeta") {
    QString assetKey = params.value("key").toString();
    int price = params.value("price").toInt(0);
    if (assetKey.isEmpty())
      return errorResult(-32602, "Missing 'key' parameter");

    return executeOnServer(keyIndex, [&](ces::CesClient& client) {
      minx::Hash aid = parseAssetKey(assetKey);
      ces::HashPrefix owner = ces::Account::getMapKey(bridge_.keyPair(keyIndex).getPublicKeyAsHash());
      uint8_t rc = client.updateAssetMeta(aid, owner, static_cast<uint32_t>(price));
      if (rc == ces::CES_OK) return QJsonObject{{"result", "ok"}};
      return errorResult(-32000, ces::errorString(rc));
    });
  }

  if (method == "buyAsset") {
    QString assetKey = params.value("key").toString();
    double maxPrice = params.value("maxPrice").toDouble(0);
    if (assetKey.isEmpty() || maxPrice <= 0)
      return errorResult(-32602, "Missing 'key' or 'maxPrice' parameter");

    uint64_t intPrice = static_cast<uint64_t>(
      maxPrice * static_cast<double>(ces::PRICE_UNIT));

    return executeOnServer(keyIndex, [&](ces::CesClient& client) {
      minx::Hash aid = parseAssetKey(assetKey);
      uint8_t rc = client.buyAsset(aid, intPrice);
      if (rc == ces::CES_OK) return QJsonObject{{"result", "ok"}};
      return errorResult(-32000, ces::errorString(rc));
    });
  }

  if (method == "giveAsset") {
    QString assetKey = params.value("key").toString();
    QString newOwner = params.value("newOwner").toString();
    if (assetKey.isEmpty() || newOwner.isEmpty())
      return errorResult(-32602, "Missing 'key' or 'newOwner' parameter");

    return executeOnServer(keyIndex, [&](ces::CesClient& client) {
      minx::Hash aid = parseAssetKey(assetKey);
      minx::Hash ownerKey;
      minx::stringToHash(ownerKey, newOwner.toStdString());
      ces::HashPrefix ownerPrefix = ces::Account::getMapKey(ownerKey);
      uint8_t rc = client.giveAsset(aid, ownerPrefix);
      if (rc == ces::CES_OK) return QJsonObject{{"result", "ok"}};
      return errorResult(-32000, ces::errorString(rc));
    });
  }

  if (method == "crossTransfer") {
    QString dest = params.value("dest").toString();
    QString server = params.value("server").toString();
    double amount = params.value("amount").toDouble(0);
    if (dest.isEmpty() || server.isEmpty() || amount <= 0)
      return errorResult(-32602, "Missing 'dest', 'server', or 'amount'");

    uint64_t intAmount = static_cast<uint64_t>(
      amount * static_cast<double>(ces::PRICE_UNIT));

    return executeOnServer(keyIndex, [&](ces::CesClient& client) {
      minx::Hash destKey;
      minx::stringToHash(destKey, dest.toStdString());
      int64_t newBal = 0;
      uint8_t rc = client.crossTransfer(destKey, intAmount,
                                         server.toStdString(), newBal);
      if (rc == ces::CES_OK)
        return QJsonObject{{"result", QJsonObject{
          {"newBalance", QString::number(newBal)},
          {"amount", QString::number(intAmount)}
        }}};
      return errorResult(-32000, ces::errorString(rc));
    });
  }

  if (method == "queryBalance") {
    // Query the app's own account balance
    return executeOnServer(keyIndex, [&](ces::CesClient& client) {
      ces::HashPrefix myId = ces::Account::getMapKey(
        bridge_.keyPair(keyIndex).getPublicKeyAsHash());
      int64_t balance = 0;
      uint32_t nonce = 0;
      client.queryAccount(myId, balance, nonce);
      return QJsonObject{{"result", QJsonObject{
        {"balance", QString::number(balance)},
        {"nonce", static_cast<int>(nonce)}
      }}};
    });
  }

  return errorResult(-32601, "Method not found: " + method.toStdString());
}

minx::Hash RpcServer::parseAssetKey(const QString& key) {
  minx::Hash aid;
  if (key.size() == 64) {
    minx::stringToHash(aid, key.toStdString());
  } else {
    aid.fill(0);
    QByteArray utf8 = key.toUtf8();
    memcpy(aid.data(), utf8.data(), std::min<int>(utf8.size(), 32));
  }
  return aid;
}

QJsonObject RpcServer::errorResult(int code, const std::string& msg) {
  return QJsonObject{{"error", QJsonObject{
    {"code", code}, {"message", QString::fromStdString(msg)}}}};
}

QJsonObject RpcServer::executeOnServer(
    int keyIndex,
    std::function<QJsonObject(ces::CesClient&)> fn) {
  QString server = bridge_.currentServer();
  if (server.isEmpty())
    return errorResult(-32000, "No current server configured");

  try {
    auto probe = ces::Resolver::probe(server.toStdString());
    auto clientPtr = probe.makeClient(false);
    auto& client = *clientPtr;
    ces::KeyPair kp = bridge_.keyPair(keyIndex);
    client.setKey(kp);
    client.start(0);
    if (!client.connect()) {
      client.stop();
      return errorResult(-32000, "Connect failed");
    }
    auto result = fn(client);
    client.disconnect();
    client.stop();
    return result;
  } catch (std::exception& e) {
    return errorResult(-32000, e.what());
  }
}

void RpcServer::tryAutoFund(int newKeyIndex) {
  static constexpr int64_t FUND_AMOUNT = static_cast<int64_t>(ces::PRICE_UNIT);       // 1.0 credit
  static constexpr int64_t MIN_SOURCE  = 2 * static_cast<int64_t>(ces::PRICE_UNIT);   // 2.0 credits

  QString server = bridge_.currentServer();
  if (server.isEmpty()) return;

  auto accounts = bridge_.getAccounts();

  int sourceIndex = -1;
  for (auto& a : accounts) {
    if (a.exists && a.balance >= MIN_SOURCE && a.index != newKeyIndex) {
      sourceIndex = a.index;
      break;
    }
  }
  if (sourceIndex < 0) {
    log("RPC: auto-fund skipped (no account with >= 2.0 credits)");
    return;
  }

  try {
    auto probe = ces::Resolver::probe(server.toStdString());
    auto clientPtr = probe.makeClient(false);
    auto& client = *clientPtr;
    ces::KeyPair sourceKp = bridge_.keyPair(sourceIndex);
    client.setKey(sourceKp);
    client.start(0);
    if (!client.connect()) {
      log("RPC: auto-fund failed (connect)");
      client.stop();
      return;
    }
    ces::KeyPair destKp = bridge_.keyPair(newKeyIndex);
    int64_t newBal = 0;
    uint8_t rc = client.openTransfer(destKp.getPublicKeyAsHash(), FUND_AMOUNT, newBal);
    client.disconnect();
    client.stop();
    if (rc == ces::CES_OK) {
      log(QString("RPC: auto-funded @%1 with 1.0 credit from @%2")
        .arg(newKeyIndex).arg(sourceIndex));
    } else {
      log(QString("RPC: auto-fund failed: %1")
        .arg(QString::fromUtf8(ces::errorString(rc))));
    }
  } catch (std::exception& e) {
    log(QString("RPC: auto-fund error: %1").arg(e.what()));
  }
}

void RpcServer::log(const QString& msg) {
  if (console_) console_->appendLog(msg);
}
