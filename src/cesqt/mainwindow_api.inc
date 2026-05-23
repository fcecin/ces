// =============================================================================
// Programmatic API for console access
// #include'd inside MainWindow class body (public section)
// =============================================================================

// Sync helper: trigger an action, block until a signal fires, return result.
// Usage: auto r = syncCall<ResultType>(sender, &Class::signal, [&](auto... args) {
//          return ResultType{args...};
//        }, [&]() { trigger(); });
template <typename R, typename Sender, typename Signal, typename Capture, typename Trigger>
static std::optional<R> syncCall(Sender* sender, Signal signal,
                                  Capture capture, Trigger trigger,
                                  int timeoutMs = 10000) {
  std::optional<R> result;
  QEventLoop loop;
  auto conn = QObject::connect(sender, signal,
    [&](auto&&... args) {
      result = capture(std::forward<decltype(args)>(args)...);
      loop.quit();
    });
  QTimer::singleShot(timeoutMs, &loop, &QEventLoop::quit);
  trigger();
  loop.exec();
  QObject::disconnect(conn);
  return result;
}

// -- Wallet / Keys --
const ces::Wallet& wallet() const { return keyManager_->wallet(); }
int keyCount() const { return keyManager_->wallet().size(); }
ces::KeyPair keyPairAt(int idx) const {
  return keyManager_->wallet().keyPair(idx);
}
QString publicKeyHex(int idx) const {
  return QString::fromStdString(
    keyManager_->wallet().keyPair(idx).getPublicKeyHexStr());
}

// -- Config --
AppConfig& config() { return config_; }
const AppConfig& config() const { return config_; }
QString currentServer() const { return config_.currentServer; }

// -- Account --
int selectedAccount() const {
  return accountWidget_->selectedAccountIndex();
}
void querySelectedAccount() { accountWidget_->querySelected(); }
AccountWidget* accountWidget() { return accountWidget_; }

struct BalanceResult { int64_t balance = 0; };
std::optional<BalanceResult> queryBalanceSync() {
  return syncCall<BalanceResult>(
    accountWidget_, &AccountWidget::balanceUpdated,
    [](int, int64_t bal) { return BalanceResult{bal}; },
    [this]() { accountWidget_->querySelected(); });
}

// Query a specific account by index (doesn't change selection).
std::optional<BalanceResult> queryAccountSync(int idx) {
  if (idx < 0 || idx >= keyManager_->wallet().size())
    return std::nullopt;
  if (config_.currentServer.isEmpty())
    return std::nullopt;
  try {
    auto probe = ces::Resolver::probe(config_.currentServer.toStdString());
    auto client = probe.makeClient(false);
    client->start(0);
    if (!client->connect()) return std::nullopt;
    auto kp = keyManager_->wallet().keyPair(idx);
    auto mapKey = ces::Account::getMapKey(kp.getPublicKeyAsHash());
    int64_t balance = 0;
    uint32_t nonce = 0;
    uint8_t rc = client->queryAccount(mapKey, balance, nonce);
    client->disconnect();
    client->stop();
    if (rc != 0) return std::nullopt;
    return BalanceResult{balance};
  } catch (...) {
    return std::nullopt;
  }
}

// -- Wallet aggregate --
void refreshWalletBalance() { walletWidget_->queryAllFull(); }

struct WalletAccountInfo { int index; QString pubKey; QString fullPubKey;
                           int64_t balance; bool exists; };
struct WalletResult { int64_t total = 0; int count = 0;
                      QList<WalletAccountInfo> accounts; };
std::optional<WalletResult> queryWalletSync() {
  auto r = syncCall<WalletResult>(
    walletWidget_, &WalletWidget::walletQueryDone,
    [this](int64_t total, int count) {
      WalletResult wr;
      wr.total = total;
      wr.count = count;
      for (auto& a : walletWidget_->getAccounts()) {
        if (a.exists)
          wr.accounts.append({a.index, a.pubKey, a.fullPubKey, a.balance, a.exists});
      }
      return wr;
    },
    [this]() { walletWidget_->queryAllFull(); },
    15000);
  return r;
}

// -- Mining --
bool isMining() const { return miningWidget_->isMining(); }

// -- Servers --
void pingAllServers() { serverManager_->pingAll(); }

struct PingResults { QStringList servers; QStringList statuses; };
std::optional<PingResults> pingAllSync() {
  return syncCall<PingResults>(
    serverManager_, &ServerManagerWidget::allPingsDone,
    [this]() {
      PingResults r;
      r.servers = config_.servers;
      r.statuses = serverManager_->getStatuses();
      return r;
    },
    [this]() { serverManager_->pingAll(); },
    30000);
}

// -- Transfer (sync, blocking) --
struct TransferResult { int64_t newBalance = 0; uint8_t rc = 0; };
std::optional<TransferResult> transferSync(int fromIdx, const QString& destHex,
                                            uint64_t amount) {
  if (fromIdx < 0 || fromIdx >= keyManager_->wallet().size())
    return std::nullopt;
  if (config_.currentServer.isEmpty())
    return std::nullopt;
  try {
    auto probe = ces::Resolver::probe(config_.currentServer.toStdString());
    auto client = probe.makeClient(false);
    auto kp = keyManager_->wallet().keyPair(fromIdx);
    client->setKey(kp);
    client->start(0);
    if (!client->connect()) return std::nullopt;

    minx::Hash dest;
    minx::stringToHash(dest, destHex.toStdString());
    int64_t newBal = 0;
    uint8_t rc = client->transfer(dest, amount, newBal);

    client->disconnect();
    client->stop();

    TransferResult r;
    r.newBalance = newBal;
    r.rc = rc;
    return r;
  } catch (...) {
    return std::nullopt;
  }
}

// -- Console --
void consoleLog(const QString& msg) { console_->appendLog(msg); }
