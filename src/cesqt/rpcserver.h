#pragma once

/**
 * RPC Server — localhost HTTP JSON-RPC for browser wallet integration.
 *
 * Listens on localhost:21008. Websites call this to interact with the
 * wallet. Each origin gets its own keypair, approved via modal dialog.
 * The Origin header is the app identity — the browser enforces it.
 *
 * Auth model:
 *   - Unknown origin → modal approval dialog → generate keypair with
 *     label set to the origin URL in the wallet
 *   - Known origin (wallet has key labeled with that URL) → proceed
 */

#include <QTcpServer>
#include <QTcpSocket>
#include <QObject>
#include <QString>
#include <QJsonObject>
#include <QJsonDocument>
#include <QList>
#include <functional>
#include <string>

#include <ces/keys.h>
#include <ces/client.h>
#include <ces/account.h>

class ConsoleWidget;

struct CachedAccount {
  int index;
  int64_t balance;
  bool exists;
};

// Callbacks the RPC server uses to interact with the wallet.
struct RpcWalletBridge {
  // Find key index by label, or -1.
  std::function<int(const std::string& label)> findByLabel;
  // Generate a key with label. Returns new index.
  std::function<int(const std::string& label)> generateKey;
  // Get KeyPair at index.
  std::function<ces::KeyPair(int index)> keyPair;
  // Get public key hex at index.
  std::function<std::string(int index)> pubKeyHex;
  // Get label at index.
  std::function<std::string(int index)> label;
  // Save wallet and refresh UI.
  std::function<void()> saveAndRefresh;
  // Get cached account balances.
  std::function<QList<CachedAccount>()> getAccounts;
  // Get current server string.
  std::function<QString()> currentServer;
};

class RpcServer : public QObject {
  Q_OBJECT
public:
  static constexpr uint16_t DEFAULT_PORT = 21008;

  RpcServer(RpcWalletBridge bridge, ConsoleWidget* console,
            bool autoApprove = false, QObject* parent = nullptr);

  bool start(uint16_t port = DEFAULT_PORT);
  void stop();

private slots:
  void onNewConnection();
  void onReadyRead();
  void onDisconnected();

private:
  struct HttpRequest {
    QString method;   // GET, POST, OPTIONS
    QString origin;
    QByteArray body;
    bool valid = false;
  };

  HttpRequest parseHttp(const QByteArray& raw);
  void sendResponse(QTcpSocket* socket, int status, const QByteArray& body,
                    const QString& origin = "");
  void sendCorsHeaders(QTcpSocket* socket, const QString& origin);

  // Returns the wallet key index for this origin, or -1 if denied.
  // May block on a modal dialog for new origins.
  int resolveOrigin(const QString& origin);

  QJsonObject dispatch(const QJsonObject& request, int keyIndex);
  static minx::Hash parseAssetKey(const QString& key);
  static QJsonObject errorResult(int code, const std::string& msg);
  QJsonObject executeOnServer(int keyIndex,
    std::function<QJsonObject(ces::CesClient&)> fn);

  void log(const QString& msg);

  void tryAutoFund(int newKeyIndex);

  QTcpServer* server_ = nullptr;
  RpcWalletBridge bridge_;
  ConsoleWidget* console_;
  bool autoApprove_;
};
