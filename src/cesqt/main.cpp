#include <QApplication>
#include <QMainWindow>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QAction>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTabWidget>
#include <QTableWidget>
#include <QTreeWidget>
#include <QStackedWidget>
#include <QHeaderView>
#include <QPushButton>
#include <QLabel>
#include <QMessageBox>
#include <QInputDialog>
#include <QClipboard>
#include <QIcon>
#include <QStyle>
#include <QCloseEvent>
#include <QStatusBar>
#include <QPlainTextEdit>
#include <QDateTime>
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QThread>
#include <QTimer>
#include <QComboBox>
#include <QCheckBox>
#include <QLockFile>
#include <QStringConverter>

#include "appmodel.h"
#include "rpcserver.h"
#include "console.h"
#include "about.h"

#include <ces/util/wallet.h>
#include <ces/account.h>
#include <ces/server.h>
#include <ces/util/resolver.h>

#include <QSpinBox>
#include <QGroupBox>
#include <QGraphicsDropShadowEffect>
#include <QMouseEvent>
#include <QKeyEvent>
#include <QFrame>
#include <QLineEdit>

#include <iostream>
#include <filesystem>
#include <atomic>

#ifndef _WIN32
#include <unistd.h>
#include <csignal>
#include <QSocketNotifier>
#include <QShortcut>
#include <sys/file.h>
#endif

// ConsoleInput and ConsoleWidget are in console.h

// =============================================================================
// UI timer tuning (cesqt main.cpp only)
// =============================================================================
// Pure responsiveness knobs — not protocol-level. Grouped here so a reviewer
// can see all of them at once rather than hunting for scattered integer
// literals. Adjust freely; no test depends on exact values.

namespace cesqt_timing {

// MineWorker::sleepMs() poll granularity. Determines how quickly a running
// mining worker notices a stop request.
constexpr int kMineWorkerTickMs     = 100;

// Delay before retrying after a dropped mining connection.
constexpr int kMineReconnectMs      = 3000;

// Delay between successful mining rounds (throttle to avoid tripping the
// server's per-IP PoW rate limiter).
constexpr int kMineRoundDelayMs     = 1000;

// How long `stopAllWorkers()` waits for a worker thread to finish before
// considering it lost and returning.
constexpr int kWorkerJoinTimeoutMs  = 10000;

// Delay before `autoMineOnce()` fires on fresh-wallet startup (lets the
// rest of the UI settle first).
constexpr int kAutoMineStartDelayMs = 500;

// Delay for the initial wallet query on refreshKeyList().
constexpr int kWalletRefreshDelayMs = 100;

} // namespace cesqt_timing

// =============================================================================
// KeyComboBox — QComboBox that copies the public key hex on Ctrl+C
// =============================================================================

class CopyableComboBox : public QComboBox {
  Q_OBJECT
public:
  using QComboBox::QComboBox;
protected:
  void keyPressEvent(QKeyEvent* e) override {
    if (e->matches(QKeySequence::Copy)) {
      QApplication::clipboard()->setText(currentText());
      e->accept();
      return;
    }
    QComboBox::keyPressEvent(e);
  }
};

class KeyComboBox : public CopyableComboBox {
  Q_OBJECT
public:
  using CopyableComboBox::CopyableComboBox;
protected:
  void keyPressEvent(QKeyEvent* e) override {
    if (e->matches(QKeySequence::Copy)) {
      // Extract pubkey hex: last space-separated token in "@N algo PUBKEY"
      QString text = currentText();
      int lastSpace = text.lastIndexOf(' ');
      if (lastSpace >= 0) {
        QApplication::clipboard()->setText(text.mid(lastSpace + 1));
      } else {
        QApplication::clipboard()->setText(text);
      }
      e->accept();
      return;
    }
    CopyableComboBox::keyPressEvent(e);
  }
};

// Build a display string for a wallet key: "@N [algo] label pubkey..."
// If label is non-empty, it replaces the pubkey in the display.
static QString formatKeyLabel(int index, const ces::KeyPair& kp,
                              const std::string& label) {
  QString s = QString("@%1 %2 %3")
    .arg(index)
    .arg(QString::fromUtf8(ces::Wallet::algoLabel(kp)))
    .arg(QString::fromStdString(kp.getPublicKeyHexStr()));
  if (!label.empty())
    s += " " + QString::fromStdString(label);
  return s;
}

// =============================================================================
// KeyManagerWidget — wallet key management
// =============================================================================

class KeyManagerWidget : public QWidget {
  Q_OBJECT
public:
  explicit KeyManagerWidget(ConsoleWidget* console,
                           AppConfig& config,
                           QWidget* parent = nullptr)
    : QWidget(parent), console_(console), config_(config) {
    auto* layout = new QVBoxLayout(this);

    walletLabel_ = new QLabel("No wallet loaded");
    walletLabel_->setStyleSheet("color: #888; font-style: italic;");
    layout->addWidget(walletLabel_);

    table_ = new QTableWidget(0, 4);
    table_->setHorizontalHeaderLabels({"#", "Algorithm", "Label", "Public Key"});
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    layout->addWidget(table_);

    // Double-click label cell to edit
    connect(table_, &QTableWidget::cellDoubleClicked,
      this, [this](int row, int col) {
        if (col != 2 || row < 0 || row >= wallet_.size()) return;
        bool ok;
        QString current = QString::fromStdString(wallet_.label(row));
        QString label = QInputDialog::getText(this, "Edit Label",
          "Label for @" + QString::number(row) + ":",
          QLineEdit::Normal, current, &ok);
        if (!ok) return;
        wallet_.setLabel(row, label.toStdString());
        saveAndRefresh();
      });

    auto* btnRow = new QHBoxLayout;

    auto* btnGen = new QPushButton("Generate Key");
    connect(btnGen, &QPushButton::clicked, this, &KeyManagerWidget::generateKey);
    btnRow->addWidget(btnGen);

    auto* btnImport = new QPushButton("Import Key");
    connect(btnImport, &QPushButton::clicked, this, &KeyManagerWidget::importKey);
    btnRow->addWidget(btnImport);

    auto* btnCopyPub = new QPushButton("Copy Public Key");
    connect(btnCopyPub, &QPushButton::clicked, this, &KeyManagerWidget::copyPublicKey);
    btnRow->addWidget(btnCopyPub);

    auto* btnCopyPriv = new QPushButton("Export Private Key");
    connect(btnCopyPriv, &QPushButton::clicked, this, &KeyManagerWidget::exportPrivateKey);
    btnRow->addWidget(btnCopyPriv);

    auto* btnDelete = new QPushButton("Delete Key");
    connect(btnDelete, &QPushButton::clicked, this, &KeyManagerWidget::deleteKey);
    btnRow->addWidget(btnDelete);

    layout->addLayout(btnRow);
    loadWallet();
  }

  const ces::Wallet& wallet() const { return wallet_; }
  ces::Wallet& wallet() { return wallet_; }

signals:
  void statusMessage(const QString& msg, int timeout);
  void walletChanged();

private slots:
  void generateKey() {
    QStringList algos = {"ED25519", "SECP256K1"};
    bool ok;
    QString chosen = QInputDialog::getItem(this, "Generate Key",
      "Algorithm:", algos, 0, false, &ok);
    if (!ok) return;

    ces::KeyAlgo algo = (chosen == "SECP256K1")
      ? ces::KeyAlgo::SECP256K1 : ces::KeyAlgo::ED25519;
    wallet_.generate(1, algo);
    log("Generated new " + chosen + " key.");
    saveAndRefresh();
  }

  void importKey() {
    bool ok;
    QString hex = QInputDialog::getText(this, "Import Key",
      "Private key (64 or 66 hex chars):", QLineEdit::Normal, "", &ok);
    if (!ok || hex.isEmpty()) return;

    try {
      bool added = wallet_.addKey(hex.toStdString());
      if (!added) {
        log("Import: key already exists in wallet.");
        QMessageBox::information(this, "Import", "Key already exists in wallet.");
        return;
      }
      log("Imported key successfully.");
      saveAndRefresh();
    } catch (std::exception& e) {
      log(QString("Import error: %1").arg(e.what()));
      QMessageBox::warning(this, "Import Error", e.what());
    }
  }

  void copyPublicKey() {
    int row = selectedRow();
    if (row < 0) return;
    auto kp = wallet_.keyPair(row);
    QApplication::clipboard()->setText(
      QString::fromStdString(kp.getPublicKeyHexStr()));
    emit statusMessage("Public key copied to clipboard", 3000);
  }

  void exportPrivateKey() {
    int row = selectedRow();
    if (row < 0) return;

    auto reply = QMessageBox::warning(this, "Export Private Key",
      "This will copy the PRIVATE key to your clipboard.\n"
      "Anyone with this key can control the account.\n\n"
      "Continue?",
      QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (reply != QMessageBox::Yes) return;

    QApplication::clipboard()->setText(
      QString::fromStdString(wallet_.keyHex(row)));
    emit statusMessage("Private key copied to clipboard", 3000);
  }

  void deleteKey() {
    int row = selectedRow();
    if (row < 0) return;

    auto kp = wallet_.keyPair(row);
    auto reply = QMessageBox::question(this, "Delete Key",
      QString("Delete key @%1 (%2)?\n\nThis cannot be undone.")
        .arg(row)
        .arg(QString::fromStdString(kp.getPublicKeyHexStr()).left(16) + "..."),
      QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (reply != QMessageBox::Yes) return;

    ces::Wallet newWallet;
    for (int i = 0; i < wallet_.size(); ++i) {
      if (i != row)
        newWallet.addKey(wallet_.keyHex(i));
    }
    wallet_ = std::move(newWallet);
    log(QString("Deleted key @%1.").arg(row));
    saveAndRefresh();
  }

private:
  ces::Wallet wallet_;
  QTableWidget* table_ = nullptr;
  QLabel* walletLabel_ = nullptr;
  ConsoleWidget* console_ = nullptr;
  AppConfig& config_;
  std::string walletPath_;
  bool generatedDefaultKey_ = false;
public:
  bool didGenerateDefaultKey() const { return generatedDefaultKey_; }
private:

  void log(const QString& msg) {
    if (console_) console_->appendLog(msg);
  }

  int selectedRow() {
    auto sel = table_->selectionModel()->selectedRows();
    if (sel.isEmpty()) {
      emit statusMessage("No key selected", 3000);
      return -1;
    }
    return sel.first().row();
  }

  QString resolveWalletPath() {
    QString dataDir = config_.configDir();
    QDir().mkpath(dataDir);
    return dataDir + "/wallet";
  }

  void loadWallet() {
    try {
      log("Loading wallet...");
      walletPath_ = resolveWalletPath().toStdString();
      log(QString("Wallet path: %1").arg(QString::fromStdString(walletPath_)));

      if (std::filesystem::exists(walletPath_)) {
        wallet_.loadFromFile(walletPath_);
        log(QString("Loaded %1 key(s).").arg(wallet_.size()));
      }
      if (wallet_.empty()) {
        log("No keys found. Generating default ED25519 key...");
        wallet_.generate(1, ces::KeyAlgo::ED25519);
        wallet_.saveToFile(walletPath_);
        log("Created wallet with 1 ED25519 key.");
        generatedDefaultKey_ = true;
      }

      walletLabel_->setText(QString("Wallet: %1 (%2 keys)")
        .arg(QString::fromStdString(walletPath_))
        .arg(wallet_.size()));
      walletLabel_->setStyleSheet("color: #ccc;");
    } catch (std::exception& e) {
      log(QString("Error loading wallet: %1").arg(e.what()));
      walletLabel_->setText(QString("Error: %1").arg(e.what()));
    }
    refreshTable();
  }

public:
  void saveAndRefresh() {
    try {
      wallet_.saveToFile(walletPath_);
      walletLabel_->setText(QString("Wallet: %1 (%2 keys)")
        .arg(QString::fromStdString(walletPath_))
        .arg(wallet_.size()));
      log(QString("Wallet saved (%1 keys).").arg(wallet_.size()));
    } catch (std::exception& e) {
      log(QString("Save error: %1").arg(e.what()));
      QMessageBox::warning(this, "Save Error",
        QString("Failed to save wallet: %1").arg(e.what()));
    }
    refreshTable();
    emit walletChanged();
  }

  void refreshTable() {
    table_->setRowCount(wallet_.size());
    for (int i = 0; i < wallet_.size(); ++i) {
      auto kp = wallet_.keyPair(i);

      auto* idxItem = new QTableWidgetItem(QString("@%1").arg(i));
      idxItem->setTextAlignment(Qt::AlignCenter);
      table_->setItem(i, 0, idxItem);

      auto* algoItem = new QTableWidgetItem(
        QString::fromUtf8(ces::Wallet::algoLabel(kp)));
      algoItem->setTextAlignment(Qt::AlignCenter);
      table_->setItem(i, 1, algoItem);

      auto* labelItem = new QTableWidgetItem(
        QString::fromStdString(wallet_.label(i)));
      table_->setItem(i, 2, labelItem);

      auto* pubItem = new QTableWidgetItem(
        QString::fromStdString(kp.getPublicKeyHexStr()));
      table_->setItem(i, 3, pubItem);
    }
  }
};

// =============================================================================
// AccountQueryWorker — queries account balance on a background thread
// =============================================================================

class AccountQueryWorker : public QThread {
  Q_OBJECT
public:
  AccountQueryWorker(const QString& server, const std::string& pubKeyHex,
                     QObject* parent = nullptr)
    : QThread(parent), server_(server), pubKeyHex_(pubKeyHex) {}

signals:
  void queryResult(bool ok, int64_t balance, uint32_t nonce,
                   QString lastDest, uint64_t lastAmount, uint32_t lastTime,
                   QString error);

protected:
  void run() override {
    try {
      auto probe = ces::Resolver::probe(server_.toStdString(),
        [](const std::string& m) { ConsoleWidget::log(QString::fromStdString(m)); });
      auto clientPtr = probe.makeClient(false);
      auto& client = *clientPtr;
      client.start(0);

      if (!client.connect()) {
        emit queryResult(false, 0, 0, "", 0, 0,
          QString("Connect failed (%1)").arg(probe.isTcp ? "TCP" : "UDP"));
        client.stop();
        return;
      }

      minx::Hash h;
      minx::stringToHash(h, pubKeyHex_);
      auto mapKey = ces::Account::getMapKey(h);

      int64_t balance = 0;
      uint32_t nonce = 0;
      ces::HashPrefix lastDest{};
      uint64_t lastAmount = 0;
      uint32_t lastTime = 0;

      uint8_t rc = client.queryAccount(mapKey, balance, nonce,
                                       lastDest, lastAmount, lastTime);

      client.disconnect();
      client.stop();

      if (rc == ces::CES_OK) {
        QString notFound = (balance == 0 && nonce == 0) ? "not found" : "";
        emit queryResult(true, balance, nonce,
          QString::fromStdString(ces::hashPrefixToString(lastDest)),
          lastAmount, lastTime, notFound);
      } else {
        emit queryResult(false, 0, 0, "", 0, 0,
          QString::fromStdString(ces::errorString(rc)));
      }
    } catch (std::exception& e) {
      emit queryResult(false, 0, 0, "", 0, 0, e.what());
    }
  }

private:
  QString server_;
  std::string pubKeyHex_;
};

// =============================================================================
// AccountWidget — main wallet view with balance display
// =============================================================================

class AccountWidget : public QWidget {
  Q_OBJECT
public:
  explicit AccountWidget(const KeyManagerWidget& keyManager,
                         AppConfig& config, ConsoleWidget* console,
                         QWidget* parent = nullptr)
    : QWidget(parent), keyManager_(keyManager), config_(config),
      console_(console) {
    auto* layout = new QVBoxLayout(this);

    // Key selector row
    auto* selRow = new QHBoxLayout;
    selRow->addWidget(new QLabel("Account:"));
    keyCombo_ = new KeyComboBox;
    keyCombo_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    connect(keyCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged),
      this, &AccountWidget::onKeyChanged);
    selRow->addWidget(keyCombo_);

    auto* btnQuery = new QPushButton("Query");
    connect(btnQuery, &QPushButton::clicked, this, &AccountWidget::querySelected);
    selRow->addWidget(btnQuery);
    layout->addLayout(selRow);

    // Info display
    auto* infoGrid = new QVBoxLayout;

    balanceLabel_ = new QLabel("Balance: —");
    balanceLabel_->setStyleSheet("font-size: 18pt; font-weight: bold; color: #4ec9b0;");
    infoGrid->addWidget(balanceLabel_);

    nonceLabel_ = new QLabel("Nonce: —");
    nonceLabel_->setStyleSheet("color: #ccc;");
    infoGrid->addWidget(nonceLabel_);

    lastXferLabel_ = new QLabel("Last transfer: —");
    lastXferLabel_->setStyleSheet("color: #ccc;");
    infoGrid->addWidget(lastXferLabel_);

    statusLabel_ = new QLabel("");
    statusLabel_->setStyleSheet("color: #888; font-style: italic;");
    infoGrid->addWidget(statusLabel_);

    layout->addLayout(infoGrid);
    layout->addStretch();

    refreshKeyList();
  }

public slots:
  void refreshKeyList() { refreshKeyListImpl(true); }
  void refreshKeyListNoQuery() { refreshKeyListImpl(false); }
  void refreshKeyListImpl(bool autoQuery) {
    // Block signals to avoid triggering onKeyChanged during rebuild
    keyCombo_->blockSignals(true);
    keyCombo_->clear();
    auto& w = keyManager_.wallet();
    for (int i = 0; i < w.size(); ++i) {
      auto kp = w.keyPair(i);
      keyCombo_->addItem(formatKeyLabel(i, kp, w.label(i)), i);
    }
    if (w.empty()) {
      balanceLabel_->setText("Balance: —");
      nonceLabel_->setText("Nonce: —");
      lastXferLabel_->setText("Last transfer: —");
      statusLabel_->setText("No keys in wallet.");
    } else {
      // Restore saved selection (clamped to valid range)
      int sel = std::clamp(config_.defaultAccount, 0, w.size() - 1);
      keyCombo_->setCurrentIndex(sel);
    }
    keyCombo_->blockSignals(false);

    // Auto-query the selected account (unless suppressed)
    if (autoQuery && !w.empty())
      QTimer::singleShot(0, this, &AccountWidget::querySelected);
  }

  void addCredit(uint64_t credit) {
    currentBalance_ += static_cast<int64_t>(credit);
    balanceLabel_->setText(QString("Balance: %1").arg(formatAmount(currentBalance_)));
  }

  void setBalance(int64_t balance) {
    currentBalance_ = balance;
    balanceLabel_->setText(QString("Balance: %1").arg(formatAmount(currentBalance_)));
  }

  int selectedAccountIndex() const {
    if (keyCombo_->count() == 0) return -1;
    return keyCombo_->currentData().toInt();
  }

signals:
  void statusMessage(const QString& msg, int timeout);
  void balanceUpdated(int accountIndex, int64_t balance);

private slots:
  void onKeyChanged(int index) {
    if (index < 0) return;
    config_.defaultAccount = index;
    config_.save();
    querySelected();
  }

public:
  void querySelected() {
    if (keyCombo_->count() == 0) {
      statusLabel_->setText("No keys to query.");
      return;
    }
    if (config_.currentServer.isEmpty()) {
      statusLabel_->setText("No current server set.");
      log("Account query failed: no current server configured.");
      return;
    }
    if (querying_) return;

    int idx = keyCombo_->currentData().toInt();
    auto& w = keyManager_.wallet();
    if (idx < 0 || idx >= w.size()) return;

    auto kp = w.keyPair(idx);
    std::string pubHex = kp.getPublicKeyHexStr();

    querying_ = true;
    statusLabel_->setText("Querying...");
    statusLabel_->setStyleSheet("color: #dcdcaa; font-style: italic;");
    log(QString("Querying account @%1 on %2...")
      .arg(idx).arg(config_.currentServer));

    auto* worker = new AccountQueryWorker(config_.currentServer, pubHex, this);
    connect(worker, &AccountQueryWorker::queryResult,
      this, &AccountWidget::onQueryResult);
    connect(worker, &QThread::finished, worker, &QObject::deleteLater);
    worker->start();
  }

  void onQueryResult(bool ok, int64_t balance, uint32_t nonce,
                     QString lastDest, uint64_t lastAmount, uint32_t lastTime,
                     QString error) {
    querying_ = false;
    if (!ok) {
      statusLabel_->setText("Error: " + error);
      statusLabel_->setStyleSheet("color: #f44747; font-style: italic;");
      log("Account query error: " + error);
      return;
    }

    if (error == "not found") {
      balanceLabel_->setText("Balance: 0 (account not found)");
      nonceLabel_->setText("Nonce: —");
      lastXferLabel_->setText("Last transfer: —");
      statusLabel_->setText("Account does not exist on server yet.");
      statusLabel_->setStyleSheet("color: #888; font-style: italic;");
      log("Account not found on server.");
      return;
    }

    balanceLabel_->setText(QString("Balance: %1").arg(formatAmount(balance)));
    nonceLabel_->setText(QString("Nonce: %1").arg(nonce));

    if (lastAmount > 0) {
      lastXferLabel_->setText(
        QString("Last transfer: %1 to %2 (t=%3)")
          .arg(formatAmount(lastAmount)).arg(lastDest).arg(lastTime));
    } else {
      lastXferLabel_->setText("Last transfer: none");
    }

    currentBalance_ = balance;
    statusLabel_->setText("Queried successfully.");
    statusLabel_->setStyleSheet("color: #4ec9b0; font-style: italic;");
    log(QString("Account balance: %1, nonce: %2").arg(formatAmount(balance)).arg(nonce));

    emit balanceUpdated(selectedAccountIndex(), balance);
  }

private:
  const KeyManagerWidget& keyManager_;
  AppConfig& config_;
  ConsoleWidget* console_ = nullptr;
  QComboBox* keyCombo_ = nullptr;
  QLabel* balanceLabel_ = nullptr;
  QLabel* nonceLabel_ = nullptr;
  QLabel* lastXferLabel_ = nullptr;
  QLabel* statusLabel_ = nullptr;
  bool querying_ = false;
  int64_t currentBalance_ = 0;

  void log(const QString& msg) {
    if (console_) console_->appendLog(msg);
  }
};

// =============================================================================
// WalletQueryWorker — queries ALL accounts on a background thread
// =============================================================================

struct AccountBalance {
  int index;
  QString pubKey;        // truncated for display
  QString fullPubKey;
  int64_t balance = 0;
  bool exists = false;
};

class WalletQueryWorker : public QThread {
  Q_OBJECT
public:
  WalletQueryWorker(const QString& server,
                    const std::vector<std::string>& pubKeys,
                    QObject* parent = nullptr)
    : QThread(parent), server_(server), pubKeys_(pubKeys) {}

signals:
  void allQueried(bool ok, QList<AccountBalance> accounts, int64_t total,
                  QString error);

protected:
  void run() override {
    try {
      auto probe = ces::Resolver::probe(server_.toStdString(),
        [](const std::string& m) { ConsoleWidget::log(QString::fromStdString(m)); });
      auto clientPtr = probe.makeClient(false);
      auto& client = *clientPtr;
      client.start(0);

      if (!client.connect()) {
        emit allQueried(false, {}, 0,
          QString("Connect failed (%1)").arg(probe.isTcp ? "TCP" : "UDP"));
        client.stop();
        return;
      }

      QList<AccountBalance> results;
      int64_t total = 0;

      for (size_t i = 0; i < pubKeys_.size(); ++i) {
        minx::Hash h;
        minx::stringToHash(h, pubKeys_[i]);
        auto mapKey = ces::Account::getMapKey(h);

        int64_t balance = 0;
        uint32_t nonce = 0;
        ces::HashPrefix lastDest{};
        uint64_t lastAmount = 0;
        uint32_t lastTime = 0;

        uint8_t rc = client.queryAccount(mapKey, balance, nonce,
                                         lastDest, lastAmount, lastTime);

        AccountBalance ab;
        ab.index = static_cast<int>(i);
        ab.fullPubKey = QString::fromStdString(pubKeys_[i]);
        ab.pubKey = ab.fullPubKey.left(8) + "..." + ab.fullPubKey.right(8);

        if (rc == ces::CES_OK && !(balance == 0 && nonce == 0)) {
          ab.balance = balance;
          ab.exists = true;
          total += balance;
        }
        results.append(ab);
      }

      client.disconnect();
      client.stop();

      emit allQueried(true, results, total, "");
    } catch (std::exception& e) {
      emit allQueried(false, {}, 0, e.what());
    }
  }

private:
  QString server_;
  std::vector<std::string> pubKeys_;
};

// =============================================================================
// ClickableLabel — QLabel that emits clicked()
// =============================================================================

class ClickableLabel : public QLabel {
  Q_OBJECT
public:
  using QLabel::QLabel;
signals:
  void clicked();
protected:
  void mousePressEvent(QMouseEvent* e) override {
    emit clicked();
    QLabel::mousePressEvent(e);
  }
};

// =============================================================================
// WalletWidget — aggregate balance view with animated counter
// =============================================================================

class WalletWidget : public QWidget {
  Q_OBJECT
public:
  explicit WalletWidget(const KeyManagerWidget& keyManager,
                        AppConfig& config, ConsoleWidget* console,
                        QWidget* parent = nullptr)
    : QWidget(parent), keyManager_(keyManager), config_(config),
      console_(console) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 16, 16, 16);

    // --- Balance card ---
    balanceCard_ = new QFrame;
    balanceCard_->setStyleSheet(
      "QFrame {"
      "  background: qlineargradient(x1:0, y1:0, x2:1, y2:1,"
      "    stop:0 #1a2332, stop:1 #0d1520);"
      "  border-radius: 16px;"
      "}");
    balanceCard_->setFixedHeight(220);
    balanceCard_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    auto* shadow = new QGraphicsDropShadowEffect;
    shadow->setBlurRadius(30);
    shadow->setColor(QColor(0, 0, 0, 120));
    shadow->setOffset(0, 4);
    balanceCard_->setGraphicsEffect(shadow);

    auto* cardLayout = new QVBoxLayout(balanceCard_);
    cardLayout->setContentsMargins(24, 16, 24, 16);
    cardLayout->setSpacing(4);

    // Title row with refresh link
    auto* titleRow = new QHBoxLayout;
    auto* titleLabel = new QLabel("Total Balance");
    titleLabel->setStyleSheet(
      "color: #6b7b8d; font-size: 11pt; font-weight: bold;"
      " letter-spacing: 2px; background: transparent;");
    titleRow->addWidget(titleLabel);
    titleRow->addStretch();

    auto* refreshLink = new ClickableLabel("refresh");
    refreshLink->setStyleSheet(
      "color: #4a6a7a; font-size: 9pt; background: transparent;"
      " text-decoration: underline;");
    refreshLink->setCursor(Qt::PointingHandCursor);
    connect(refreshLink, &ClickableLabel::clicked,
      this, &WalletWidget::queryAllFull);
    titleRow->addWidget(refreshLink);
    cardLayout->addLayout(titleRow);

    balanceLabel_ = new QLabel("—");
    balanceLabel_->setStyleSheet(
      "color: #4ec9b0; font-size: 32pt; font-weight: bold;"
      " font-family: 'Courier New', monospace; background: transparent;");
    balanceLabel_->setMinimumHeight(50);
    cardLayout->addWidget(balanceLabel_);

    statusLabel_ = new QLabel("");
    statusLabel_->setStyleSheet(
      "color: #4a5568; font-size: 9pt; font-style: italic;"
      " background: transparent;");
    cardLayout->addWidget(statusLabel_);

    layout->addWidget(balanceCard_);

    // --- Per-key breakdown ---
    auto* breakdownLabel = new QLabel("Accounts");
    breakdownLabel->setStyleSheet(
      "color: #6b7b8d; font-size: 10pt; font-weight: bold;"
      " margin-top: 12px;");
    layout->addWidget(breakdownLabel);

    keyTable_ = new QTableWidget(0, 2);
    keyTable_->setHorizontalHeaderLabels({"Address", "Balance"});
    keyTable_->verticalHeader()->setVisible(false);
    keyTable_->horizontalHeader()->setSectionResizeMode(
      0, QHeaderView::Stretch);
    keyTable_->horizontalHeader()->setSectionResizeMode(
      1, QHeaderView::ResizeToContents);
    keyTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    keyTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    keyTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    keyTable_->setShowGrid(false);
    keyTable_->setStyleSheet(
      "QTableWidget { background: #1a1e26; color: #ccc;"
      " border: none; }"
      "QTableWidget::item { padding: 4px 8px; }"
      "QHeaderView::section { background: #1a1e26; color: #6b7b8d;"
      " border: none; padding: 4px 8px; }");
    layout->addWidget(keyTable_);

    // Animation timer (~30 fps)
    animTimer_ = new QTimer(this);
    animTimer_->setInterval(33);
    connect(animTimer_, &QTimer::timeout,
      this, &WalletWidget::animationTick);

    // Auto-refresh timer (3 minutes)
    autoRefreshTimer_ = new QTimer(this);
    autoRefreshTimer_->setInterval(180000);
    connect(autoRefreshTimer_, &QTimer::timeout,
      this, &WalletWidget::autoRefresh);
    autoRefreshTimer_->start();

    refreshKeyList();
  }

public slots:
  void refreshKeyList() {
    // Wallet changed — clear known-existing cache, query all
    knownExisting_.clear();
    QTimer::singleShot(cesqt_timing::kWalletRefreshDelayMs, this,
                       &WalletWidget::queryAllFull);
  }

  void addCredit(int accountIndex, uint64_t credit) {
    targetBalance_ += static_cast<int64_t>(credit);
    if (!animTimer_->isActive())
      animTimer_->start();

    // Update per-key table if this account is in it
    for (auto& a : accounts_) {
      if (a.index == accountIndex) {
        a.exists = true;
        a.balance += static_cast<int64_t>(credit);
        knownExisting_.insert(accountIndex);
        updateTable();
        break;
      }
    }
  }

  // Full query: all accounts (used on first load, refresh click, wallet change)
  void queryAllFull() {
    queryAccounts(false);
  }

signals:
  void statusMessage(const QString& msg, int timeout);
  void walletQueryDone(int64_t total, int existingCount);

private slots:
  // Incremental query: only known-existing accounts (used by auto-refresh)
  void queryAccounts(bool existingOnly) {
    auto& w = keyManager_.wallet();
    if (w.empty()) {
      balanceLabel_->setText("—");
      statusLabel_->setText("No keys in wallet.");
      setStatusStyle("#4a5568");
      keyTable_->setRowCount(0);
      return;
    }
    if (config_.currentServer.isEmpty()) {
      statusLabel_->setText("No current server configured.");
      setStatusStyle("#f44747");
      return;
    }
    if (querying_) return;

    // Build the list of keys to query
    std::vector<std::string> pubKeys;
    queryIndices_.clear();

    for (int i = 0; i < w.size(); ++i) {
      if (!existingOnly || knownExisting_.contains(i)) {
        pubKeys.push_back(w.keyPair(i).getPublicKeyHexStr());
        queryIndices_.push_back(i);
      }
    }

    if (pubKeys.empty()) {
      // No known accounts to refresh — nothing to do
      return;
    }

    querying_ = true;
    int total = w.size();
    int queried = static_cast<int>(pubKeys.size());
    if (existingOnly && queried < total)
      statusLabel_->setText(QString("Refreshing %1 account(s)...")
        .arg(queried));
    else
      statusLabel_->setText("Querying all accounts...");
    setStatusStyle("#dcdcaa");
    log(QString("Wallet: querying %1 account(s)...").arg(queried));

    auto* worker = new WalletQueryWorker(
      config_.currentServer, pubKeys, this);
    connect(worker, &WalletQueryWorker::allQueried,
      this, [this, existingOnly](bool ok, QList<AccountBalance> accounts,
                                  int64_t total, QString error) {
        onAllQueried(ok, accounts, total, error, existingOnly);
      });
    connect(worker, &QThread::finished, worker, &QObject::deleteLater);
    worker->start();
  }

  void onAllQueried(bool ok, QList<AccountBalance> accounts,
                    int64_t total, QString error, bool wasIncremental) {
    querying_ = false;

    if (!ok) {
      statusLabel_->setText("Error: " + error);
      setStatusStyle("#f44747");
      log("Wallet query error: " + error);
      return;
    }

    // Remap indices from worker results back to wallet indices
    for (int i = 0; i < accounts.size(); ++i)
      accounts[i].index = queryIndices_[i];

    if (wasIncremental) {
      // Merge results into existing accounts_ list
      for (auto& a : accounts) {
        for (auto& existing : accounts_) {
          if (existing.index == a.index) {
            existing.balance = a.balance;
            existing.exists = a.exists;
            break;
          }
        }
      }
      // Recalculate total from merged data
      total = 0;
      for (auto& a : accounts_)
        if (a.exists) total += a.balance;
    } else {
      // Full query — replace everything
      accounts_ = accounts;
      // Update known-existing cache
      knownExisting_.clear();
      for (auto& a : accounts_)
        if (a.exists) knownExisting_.insert(a.index);
    }

    updateTable();

    // Animate toward new total
    targetBalance_ = total;
    if (!animTimer_->isActive())
      animTimer_->start();

    QString ts = QDateTime::currentDateTime().toString("hh:mm:ss");
    int existCount = 0;
    for (auto& a : accounts_)
      if (a.exists) existCount++;
    statusLabel_->setText(QString("%1 account(s) | updated %2")
      .arg(existCount).arg(ts));
    setStatusStyle("#4a5568");
    log(QString("Wallet total: %1 (%2 accounts)")
      .arg(formatAmount(total)).arg(existCount));
    emit walletQueryDone(total, existCount);
  }

  void animationTick() {
    double diff = static_cast<double>(targetBalance_) - displayedBalance_;

    if (std::abs(diff) < 1.0) {
      displayedBalance_ = static_cast<double>(targetBalance_);
      animTimer_->stop();
    } else {
      // Exponential easing — fast start, slow approach
      displayedBalance_ += diff * 0.12;
    }

    balanceLabel_->setText(
      formatAmount(static_cast<int64_t>(std::round(displayedBalance_))));
  }

  void autoRefresh() {
    if (!isVisible()) return;
    QWidget* w = window();
    if (w && w->isMinimized()) return;
    // Auto-refresh only queries known-existing accounts
    queryAccounts(true);
  }

private:
  const KeyManagerWidget& keyManager_;
  AppConfig& config_;
  ConsoleWidget* console_ = nullptr;

  QFrame* balanceCard_ = nullptr;
  QLabel* balanceLabel_ = nullptr;
  QLabel* statusLabel_ = nullptr;
  QTableWidget* keyTable_ = nullptr;

  QTimer* animTimer_ = nullptr;
  QTimer* autoRefreshTimer_ = nullptr;

  bool querying_ = false;
  int64_t targetBalance_ = 0;
  double displayedBalance_ = 0.0;
public:
  const QList<AccountBalance>& getAccounts() const { return accounts_; }
private:
  QList<AccountBalance> accounts_;
  QSet<int> knownExisting_;
  std::vector<int> queryIndices_;

  void updateTable() {
    int rowCount = 0;
    for (auto& a : accounts_)
      if (a.exists) rowCount++;

    keyTable_->setRowCount(rowCount);
    int row = 0;
    for (auto& a : accounts_) {
      if (!a.exists) continue;

      auto* addrItem = new QTableWidgetItem(
        QString("@%1  %2").arg(a.index).arg(a.pubKey));
      addrItem->setToolTip(a.fullPubKey);
      keyTable_->setItem(row, 0, addrItem);

      auto* balItem = new QTableWidgetItem(formatAmount(a.balance));
      balItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
      balItem->setForeground(QColor("#4ec9b0"));
      keyTable_->setItem(row, 1, balItem);
      row++;
    }
  }

  void setStatusStyle(const char* color) {
    statusLabel_->setStyleSheet(
      QString("color: %1; font-size: 9pt; font-style: italic;"
              " background: transparent;").arg(color));
  }

  void log(const QString& msg) {
    if (console_) console_->appendLog(msg);
  }
};

// =============================================================================
// MineWorker — runs mining loop on a background thread
// =============================================================================

class MineWorker : public QThread {
  Q_OBJECT
public:
  MineWorker(const QString& server, const ces::KeyPair& keyPair,
             int extraDifficulty, int numThreads, int throttleUs,
             QObject* parent = nullptr)
    : QThread(parent), server_(server), keyPair_(keyPair),
      extraDiff_(extraDifficulty), numThreads_(numThreads),
      throttleUs_(throttleUs) {}

  void requestStop() { stop_.store(true); }

signals:
  void mineStatus(const QString& status);
  void solutionFound(uint64_t credit, int resultCode);
  void mineError(const QString& error);
  void mineFinished();

protected:
  void run() override {
    try {
      auto probe = ces::Resolver::probe(server_.toStdString(),
        [](const std::string& m) { ConsoleWidget::log(QString::fromStdString(m)); });
      auto clientPtr = probe.makeClient(true);  // need dataset for mining
      auto& client = *clientPtr;
      client.start(0);
      client.setKey(keyPair_);
      if (!client.connect()) {
        emit mineError(QString("Connect failed (%1)")
          .arg(probe.isTcp ? "TCP" : "UDP"));
        return;
      }

      emit mineStatus("Connected. Starting mining loop...");

      int round = 0;
      while (!stop_.load()) {
        round++;
        emit mineStatus(QString("Round %1: computing proof of work...").arg(round));

        // Always mine in batches so stop_ is checked frequently.
        // Each RandomX hash takes ~1ms, so BATCH_SIZE hashes ≈ BATCH_SIZE ms
        // between stop checks. With throttle, use batch of 1 for fine control.
        const uint64_t batchSize = (throttleUs_ > 0) ? 1 : 64;
        uint64_t nonce = 0;
        auto w = [&]() -> std::optional<minx::MinxProveWork> {
          while (!stop_.load()) {
            auto r = client.mine(extraDiff_, {}, numThreads_, nonce, batchSize);
            if (r) return r;
            nonce += batchSize * static_cast<uint64_t>(std::max(numThreads_, 1));
            if (throttleUs_ > 0)
              std::this_thread::sleep_for(std::chrono::microseconds(throttleUs_));
          }
          return {};
        }();

        if (!w) {
          if (stop_.load()) break;
          emit mineStatus(QString("Round %1: mine() returned no work. "
            "Reconnecting...").arg(round));
          client.disconnect();
          sleepMs(cesqt_timing::kMineReconnectMs);
          if (stop_.load()) break;
          if (!client.connect()) {
            emit mineError("Reconnect failed");
            break;
          }
          continue;
        }
        if (stop_.load()) break;

        emit mineStatus(QString("Round %1: solution found, submitting...")
          .arg(round));

        // Submit — proveWork already retries internally (3x send + 3x query)
        minx::Hash b;
        uint64_t credit = 0, t = 0;
        int r = client.proveWork(*w, b, credit, t);

        if (r == minx::MINX_SOLUTION_SPENT) {
          emit solutionFound(credit, r);
          emit mineStatus(QString("Round %1: accepted! Credit %2")
            .arg(round).arg(formatAmount(credit)));
        } else if (r == minx::MINX_SOLUTION_UNTIMELY) {
          emit mineStatus(QString("Round %1: untimely (too old), mining new...")
            .arg(round));
        } else if (r == minx::MINX_SOLUTION_UNSPENT) {
          emit mineStatus(QString("Round %1: unspent (server hasn't processed yet?), mining new...")
            .arg(round));
        } else {
          emit mineStatus(QString("Round %1: response lost (likely spent), continuing...")
            .arg(round));
        }

        // Brief delay between rounds to avoid triggering server's per-IP
        // PoW rate limiter (filterPoW) when solutions come in fast
        sleepMs(cesqt_timing::kMineRoundDelayMs);
      }

      client.disconnect();
      client.stop();
    } catch (std::exception& e) {
      emit mineError(QString(e.what()));
    }
    emit mineFinished();
  }

private:
  QString server_;
  ces::KeyPair keyPair_;
  int extraDiff_;
  int numThreads_;
  int throttleUs_;
  std::atomic<bool> stop_{false};

  void sleepMs(int ms) {
    using cesqt_timing::kMineWorkerTickMs;
    for (int i = 0; i < ms && !stop_.load(); i += kMineWorkerTickMs)
      std::this_thread::sleep_for(std::chrono::milliseconds(kMineWorkerTickMs));
  }
};

// =============================================================================
// MiningWidget — mining controls and stats
// =============================================================================

class MiningWidget : public QWidget {
  Q_OBJECT
public:
  explicit MiningWidget(const KeyManagerWidget& keyManager,
                        AppConfig& config, ConsoleWidget* console,
                        QWidget* parent = nullptr)
    : QWidget(parent), keyManager_(keyManager), config_(config),
      console_(console) {
    auto* layout = new QVBoxLayout(this);

    // Account selector
    auto* acctRow = new QHBoxLayout;
    acctRow->addWidget(new QLabel("Mining account:"));
    keyCombo_ = new KeyComboBox;
    keyCombo_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    acctRow->addWidget(keyCombo_);
    layout->addLayout(acctRow);

    // Settings row
    auto* settingsRow = new QHBoxLayout;
    settingsRow->addWidget(new QLabel("Threads:"));
    threadSpin_ = new QSpinBox;
    threadSpin_->setRange(1, 64);
    threadSpin_->setValue(config_.mineThreads);
    connect(threadSpin_, QOverload<int>::of(&QSpinBox::valueChanged),
      this, [this](int val) {
        config_.mineThreads = val;
        config_.save();
      });
    settingsRow->addWidget(threadSpin_);
    settingsRow->addSpacing(16);
    settingsRow->addWidget(new QLabel("Throttle (\xc2\xb5s):"));
    throttleSpin_ = new QSpinBox;
    throttleSpin_->setRange(0, 1000000);
    throttleSpin_->setSingleStep(100);
    throttleSpin_->setValue(config_.mineThrottleUs);
    throttleSpin_->setToolTip("Microseconds to sleep between hash batches (0 = full speed)");
    connect(throttleSpin_, QOverload<int>::of(&QSpinBox::valueChanged),
      this, [this](int val) {
        config_.mineThrottleUs = val;
        config_.save();
      });
    settingsRow->addWidget(throttleSpin_);
    settingsRow->addStretch();
    layout->addLayout(settingsRow);

    // Difficulty info
    diffLabel_ = new QLabel("Target difficulty: —");
    diffLabel_->setStyleSheet("color: #ccc;");
    layout->addWidget(diffLabel_);

    // Start/Stop button
    startStopBtn_ = new QPushButton("Start Mining");
    startStopBtn_->setStyleSheet(
      "QPushButton { padding: 8px 24px; font-size: 12pt; font-weight: bold; }");
    connect(startStopBtn_, &QPushButton::clicked,
      this, &MiningWidget::toggleMining);
    layout->addWidget(startStopBtn_);

    // Status
    statusLabel_ = new QLabel("Idle");
    statusLabel_->setStyleSheet("color: #888; font-style: italic;");
    layout->addWidget(statusLabel_);

    // Stats
    auto* statsBox = new QGroupBox("Session Stats");
    auto* statsLayout = new QVBoxLayout(statsBox);
    solutionsLabel_ = new QLabel("Solutions found: 0");
    solutionsLabel_->setStyleSheet("color: #ccc;");
    statsLayout->addWidget(solutionsLabel_);
    creditsLabel_ = new QLabel("Total credits: 0");
    creditsLabel_->setStyleSheet("color: #4ec9b0; font-size: 14pt;");
    statsLayout->addWidget(creditsLabel_);
    layout->addWidget(statsBox);

    layout->addStretch();

    refreshKeyList();
  }

  ~MiningWidget() override {
    stopAllWorkers();
  }

public slots:
  void refreshKeyList() {
    keyCombo_->blockSignals(true);
    keyCombo_->clear();
    auto& w = keyManager_.wallet();
    for (int i = 0; i < w.size(); ++i) {
      auto kp = w.keyPair(i);
      keyCombo_->addItem(formatKeyLabel(i, kp, w.label(i)), i);
    }
    if (!w.empty()) {
      int sel = std::clamp(config_.defaultAccount, 0, w.size() - 1);
      keyCombo_->setCurrentIndex(sel);
    }
    keyCombo_->blockSignals(false);
    updateDifficultyLabel();
  }

  bool isMining() const { return wantMining_; }

  void autoMineOnce() {
    if (wantMining_) return;
    autoMineOnce_ = true;
    startMining();
    log("Auto-mining once for initial credits...");
  }

  int miningAccountIndex() const {
    if (!wantMining_ || keyCombo_->count() == 0) return -1;
    return keyCombo_->currentData().toInt();
  }

signals:
  void statusMessage(const QString& msg, int timeout);
  void creditEarned(int accountIndex, uint64_t credit);

private slots:
  void toggleMining() {
    if (wantMining_) {
      // Intent: stop. Button switches immediately.
      wantMining_ = false;
      startStopBtn_->setText("Start Mining");
      threadSpin_->setEnabled(true);
      throttleSpin_->setEnabled(true);
      keyCombo_->setEnabled(true);
      statusLabel_->setText("Stopping...");
      statusLabel_->setStyleSheet("color: #dcdcaa; font-style: italic;");
      log("Stopping mining...");
      if (worker_)
        worker_->requestStop();
    } else {
      startMining();
    }
  }

  void onMineStatus(const QString& status) {
    statusLabel_->setText(status);
    statusLabel_->setStyleSheet("color: #dcdcaa; font-style: italic;");
    log("Mine: " + status);
  }

  void onSolutionFound(uint64_t credit, int /*resultCode*/) {
    totalSolutions_++;
    totalCredits_ += credit;
    solutionsLabel_->setText(QString("Solutions found: %1").arg(totalSolutions_));
    creditsLabel_->setText(QString("Total credits: %1").arg(formatAmount(totalCredits_)));
    log(QString("Solution accepted! Credit: %1 (total: %2)")
      .arg(formatAmount(credit)).arg(formatAmount(totalCredits_)));
    emit creditEarned(miningAccountIndex(), credit);

    if (autoMineOnce_) {
      autoMineOnce_ = false;
      // Flip intent to stop — submission is already in flight
      wantMining_ = false;
      startStopBtn_->setText("Start Mining");
      threadSpin_->setEnabled(true);
      throttleSpin_->setEnabled(true);
      keyCombo_->setEnabled(true);
      if (worker_)
        worker_->requestStop();
      log("Auto-mine complete. Initial credits deposited.");
    }
  }

  void onMineError(const QString& error) {
    log("Mine error: " + error);
    statusLabel_->setText("Error: " + error);
    statusLabel_->setStyleSheet("color: #f44747; font-style: italic;");
  }

  void onWorkerFinished() {
    worker_ = nullptr;
    if (wantMining_) {
      // User toggled back to "start" while worker was winding down — restart.
      launchWorker();
    } else {
      statusLabel_->setText("Idle");
      statusLabel_->setStyleSheet("color: #888; font-style: italic;");
      log("Mining stopped.");
    }
  }

private:
  const KeyManagerWidget& keyManager_;
  AppConfig& config_;
  ConsoleWidget* console_ = nullptr;

  QComboBox* keyCombo_ = nullptr;
  QSpinBox* threadSpin_ = nullptr;
  QSpinBox* throttleSpin_ = nullptr;
  QLabel* diffLabel_ = nullptr;
  QPushButton* startStopBtn_ = nullptr;
  QLabel* statusLabel_ = nullptr;
  QLabel* solutionsLabel_ = nullptr;
  QLabel* creditsLabel_ = nullptr;

  bool wantMining_ = false;
  bool autoMineOnce_ = false;
  uint64_t totalSolutions_ = 0;
  uint64_t totalCredits_ = 0;
  MineWorker* worker_ = nullptr;

  void log(const QString& msg) {
    if (console_) console_->appendLog(msg);
  }

  int computeExtraDifficulty() {
    // We don't know the server's minDifficulty until we connect,
    // but we know the account existence from the Account tab.
    // For now, use extraDifficulty = 1 (server minDiff + 1).
    // Smart difficulty: if account doesn't exist, we need enough
    // credit to cover BASE_FEE_ACCOUNT (6,400,000).
    // credit = (1 << (diff-1)) * 1000
    // For diff 14: (1<<13)*1000 = 8,192,000 — first diff that covers it.
    // extraDifficulty is added on top of server's minDifficulty,
    // so we just pass 1 and let the server enforce the minimum.
    // The mineOnce function uses client.mine(extraDifficulty) which
    // targets serverMinDiff + extraDifficulty.
    return 1;
  }

  void updateDifficultyLabel() {
    diffLabel_->setText(
      QString("Target difficulty: server minimum + 1 "
              "(need >= %1 for new account)")
        .arg(formatAmount(static_cast<uint64_t>(ces::BASE_FEE_ACCOUNT))));
  }

  void startMining() {
    auto& w = keyManager_.wallet();
    if (w.empty()) {
      statusLabel_->setText("No keys in wallet.");
      statusLabel_->setStyleSheet("color: #f44747; font-style: italic;");
      return;
    }
    if (config_.currentServer.isEmpty()) {
      statusLabel_->setText("No current server set.");
      statusLabel_->setStyleSheet("color: #f44747; font-style: italic;");
      return;
    }

    int idx = keyCombo_->currentData().toInt();
    if (idx < 0 || idx >= w.size()) return;

    wantMining_ = true;
    startStopBtn_->setText("Stop Mining");
    threadSpin_->setEnabled(false);
    throttleSpin_->setEnabled(false);
    keyCombo_->setEnabled(false);

    int threads = threadSpin_->value();
    int throttle = throttleSpin_->value();
    statusLabel_->setText(QString("Starting with %1 thread(s), throttle %2\xc2\xb5s...")
      .arg(threads).arg(throttle));
    statusLabel_->setStyleSheet("color: #dcdcaa; font-style: italic;");

    log(QString("Starting mining: %1 thread(s), throttle %2us, account @%3, server %4")
      .arg(threads).arg(throttle).arg(idx).arg(config_.currentServer));

    launchWorker();
  }

  void launchWorker() {
    auto& w = keyManager_.wallet();
    int idx = keyCombo_->currentData().toInt();
    if (idx < 0 || idx >= w.size()) return;

    ces::KeyPair kp = w.keyPair(idx);
    int threads = threadSpin_->value();
    int throttle = throttleSpin_->value();
    int extraDiff = computeExtraDifficulty();

    worker_ = new MineWorker(config_.currentServer, kp, extraDiff, threads, throttle, this);
    connect(worker_, &MineWorker::mineStatus,
      this, &MiningWidget::onMineStatus);
    connect(worker_, &MineWorker::solutionFound,
      this, &MiningWidget::onSolutionFound);
    connect(worker_, &MineWorker::mineError,
      this, &MiningWidget::onMineError);
    connect(worker_, &MineWorker::mineFinished,
      this, &MiningWidget::onWorkerFinished);
    connect(worker_, &QThread::finished,
      worker_, &QObject::deleteLater);
    worker_->start();
  }

  void stopAllWorkers() {
    wantMining_ = false;
    if (worker_) {
      worker_->requestStop();
      worker_->wait(cesqt_timing::kWorkerJoinTimeoutMs);
      worker_ = nullptr;
    }
  }
};

// =============================================================================
// PingWorker — runs server ping on a background thread
// =============================================================================

class PingWorker : public QThread {
  Q_OBJECT
public:
  PingWorker(const QString& addr, int index, int generation,
             QObject* parent = nullptr)
    : QThread(parent), addr_(addr), index_(index), generation_(generation) {}

signals:
  void pingResult(int index, int generation, QString status);

protected:
  void run() override {
    try {
      auto probe = ces::Resolver::probe(addr_.toStdString(),
        [](const std::string& m) { ConsoleWidget::log(QString::fromStdString(m)); });
      auto clientPtr = probe.makeClient(false);
      auto& client = *clientPtr;
      client.start(0);

      if (!client.connect()) {
        emit pingResult(index_, generation_,
          QString("Offline (connect failed, %1)")
            .arg(probe.isTcp ? "TCP" : "UDP"));
        client.stop();
        return;
      }

      // Handshake info (free, from MINX layer)
      uint8_t diff = client.getMinDifficulty();
      uint8_t minSecs = client.getMinSecsPoW();
      uint16_t pending = client.getPendingPoWs();
      uint16_t tps = client.getTps();

      client.disconnect();
      client.stop();

      QString transport = probe.isTcp ? "TCP" : "UDP";
      QString status = QString("Online (%1) | diff %2, %3 tps, %4 pending, %5s min")
        .arg(transport).arg(diff).arg(tps).arg(pending).arg(minSecs);

      emit pingResult(index_, generation_, status);
    } catch (std::exception& e) {
      emit pingResult(index_, generation_,
        QString("Offline (%1)").arg(e.what()));
    }
  }

private:
  QString addr_;
  int index_;
  int generation_;
};

// =============================================================================
// ServerInfoWorker — queries server info (paid) on a background thread
// =============================================================================

class ServerInfoWorker : public QThread {
  Q_OBJECT
public:
  ServerInfoWorker(const QString& server, const ces::KeyPair& keyPair,
                   QObject* parent = nullptr)
    : QThread(parent), server_(server), keyPair_(keyPair) {}

signals:
  void infoResult(bool ok, QList<QPair<QString,QString>> entries, QString error);

protected:
  void run() override {
    try {
      auto probe = ces::Resolver::probe(server_.toStdString(),
        [](const std::string& m) { ConsoleWidget::log(QString::fromStdString(m)); });
      auto clientPtr = probe.makeClient(false);
      auto& client = *clientPtr;
      client.setKey(keyPair_);
      client.start(0);
      if (!client.connect()) {
        emit infoResult(false, {}, QString("Connect failed (%1)")
          .arg(probe.isTcp ? "TCP" : "UDP"));
        client.stop();
        return;
      }

      std::vector<ces::ServerInfoEntry> entries;
      uint8_t rc = client.queryServerInfo(entries);
      client.disconnect();
      client.stop();

      if (rc != ces::CES_OK) {
        emit infoResult(false, {},
          QString::fromUtf8(ces::errorString(rc)));
        return;
      }

      QList<QPair<QString,QString>> result;
      for (auto& e : entries)
        result.append({QString::fromStdString(e.key),
                       QString::fromStdString(e.value)});
      emit infoResult(true, result, "");
    } catch (std::exception& e) {
      emit infoResult(false, {}, QString::fromUtf8(e.what()));
    }
  }

private:
  QString server_;
  ces::KeyPair keyPair_;
};

// =============================================================================
// ServerManagerWidget — server address book with ping status
// =============================================================================

class ServerManagerWidget : public QWidget {
  Q_OBJECT
public:
  explicit ServerManagerWidget(const KeyManagerWidget& keyManager,
                               AppConfig& config, ConsoleWidget* console,
                               QWidget* parent = nullptr)
    : QWidget(parent), keyManager_(keyManager), config_(config),
      console_(console) {
    auto* layout = new QVBoxLayout(this);

    // Current server label
    currentLabel_ = new QLabel;
    updateDefaultLabel();
    layout->addWidget(currentLabel_);

    // Server table: Server | Status
    table_ = new QTableWidget(0, 2);
    table_->setHorizontalHeaderLabels({"Server", "Status"});
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->horizontalHeader()->setMinimumSectionSize(50);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    table_->verticalHeader()->setVisible(false);
    layout->addWidget(table_);

    // Buttons
    auto* btnRow = new QHBoxLayout;

    auto* btnAdd = new QPushButton("Add Server");
    connect(btnAdd, &QPushButton::clicked, this, &ServerManagerWidget::addServer);
    btnRow->addWidget(btnAdd);

    auto* btnEdit = new QPushButton("Edit Server");
    connect(btnEdit, &QPushButton::clicked, this, &ServerManagerWidget::editServer);
    btnRow->addWidget(btnEdit);

    auto* btnRemove = new QPushButton("Remove Server");
    connect(btnRemove, &QPushButton::clicked, this, &ServerManagerWidget::removeServer);
    btnRow->addWidget(btnRemove);

    auto* btnSetDefault = new QPushButton("Set as Default");
    connect(btnSetDefault, &QPushButton::clicked, this, &ServerManagerWidget::setAsDefault);
    btnRow->addWidget(btnSetDefault);

    auto* btnClearDefault = new QPushButton("Clear Default");
    connect(btnClearDefault, &QPushButton::clicked, this, &ServerManagerWidget::clearDefault);
    btnRow->addWidget(btnClearDefault);

    btnPingAll_ = new QPushButton("Ping All");
    connect(btnPingAll_, &QPushButton::clicked, this, &ServerManagerWidget::pingAll);
    btnRow->addWidget(btnPingAll_);

    btnQueryInfo_ = new QPushButton("Query Info");
    btnQueryInfo_->setToolTip("Query server info (paid, uses default account)");
    connect(btnQueryInfo_, &QPushButton::clicked, this, &ServerManagerWidget::queryInfo);
    btnRow->addWidget(btnQueryInfo_);

    layout->addLayout(btnRow);

    // --- Server info table ---
    infoTable_ = new QTableWidget(0, 2);
    infoTable_->setHorizontalHeaderLabels({"Property", "Value"});
    infoTable_->horizontalHeader()->setStretchLastSection(true);
    infoTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    infoTable_->verticalHeader()->setVisible(false);
    infoTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    infoTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    infoTable_->setFixedHeight(180);
    layout->addWidget(infoTable_);

    // Show cached info for initially selected server
    connect(table_, &QTableWidget::currentCellChanged,
      this, [this](int row, int, int, int) { showCachedInfo(row); });

    // Initialize status list and refresh
    statuses_.resize(config_.servers.size());
    for (auto& s : statuses_) s = "(not checked)";
    refreshTable();
  }

signals:
  void statusMessage(const QString& msg, int timeout);
  void allPingsDone();
  void serverListChanged();

public slots:
  void pingAll() {
    // Bump generation to discard results from any previous batch still in flight
    pingGeneration_++;
    pingsInFlight_ = config_.servers.size();

    log("Pinging all servers...");

    for (int i = 0; i < config_.servers.size(); ++i) {
      statuses_[i] = "Pinging...";
      auto* worker = new PingWorker(config_.servers[i], i, pingGeneration_, this);
      connect(worker, &PingWorker::pingResult,
        this, &ServerManagerWidget::onPingResult);
      connect(worker, &QThread::finished,
        worker, &QObject::deleteLater);
      worker->start();
    }
    refreshTable();
  }

private slots:
  void addServer() {
    bool ok;
    QString addr = QInputDialog::getText(this, "Add Server",
      "Server address (host:port):", QLineEdit::Normal, "", &ok);
    if (!ok || addr.trimmed().isEmpty()) return;

    addr = addr.trimmed();
    if (!addr.contains(':'))
      addr += ":" + QString::number(ces::DEFAULT_PORT);
    if (config_.servers.contains(addr)) {
      QMessageBox::information(this, "Add Server", "Server already in list.");
      return;
    }
    config_.servers.append(addr);
    statuses_.append("(not checked)");
    log("Added server: " + addr);
    saveAndRefresh();
  }

  void editServer() {
    int row = selectedRow();
    if (row < 0) return;

    QString old = config_.servers[row];
    bool ok;
    QString addr = QInputDialog::getText(this, "Edit Server",
      "Server address (host:port):", QLineEdit::Normal, old, &ok);
    if (!ok || addr.trimmed().isEmpty()) return;

    addr = addr.trimmed();
    if (!addr.contains(':'))
      addr += ":" + QString::number(ces::DEFAULT_PORT);
    bool wasCurrent = (config_.currentServer == old);
    config_.servers[row] = addr;
    statuses_[row] = "(not checked)";
    if (wasCurrent) config_.currentServer = addr;
    log("Edited server: " + old + " -> " + addr);
    saveAndRefresh();
  }

  void removeServer() {
    int row = selectedRow();
    if (row < 0) return;

    QString addr = config_.servers[row];
    auto reply = QMessageBox::question(this, "Remove Server",
      QString("Remove server '%1'?").arg(addr),
      QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (reply != QMessageBox::Yes) return;

    config_.servers.removeAt(row);
    statuses_.removeAt(row);
    if (config_.currentServer == addr)
      config_.currentServer.clear();
    log("Removed server: " + addr);
    saveAndRefresh();
  }

  void setAsDefault() {
    int row = selectedRow();
    if (row < 0) return;

    config_.currentServer = config_.servers[row];
    log("Current server set to: " + config_.currentServer);
    saveAndRefresh();
  }

  void clearDefault() {
    config_.currentServer.clear();
    log("Current server cleared.");
    saveAndRefresh();
  }

  void queryInfo() {
    int row = selectedRow();
    if (row < 0) return;
    auto& w = keyManager_.wallet();
    if (w.empty()) {
      log("Query Info: no keys in wallet.");
      return;
    }
    if (queryingInfo_) return;

    QString server = config_.servers[row];
    int kidx = std::clamp(config_.defaultAccount, 0, w.size() - 1);
    ces::KeyPair kp = w.keyPair(kidx);

    queryingInfo_ = true;
    btnQueryInfo_->setEnabled(false);
    log("Querying server info: " + server + " (account @" + QString::number(kidx) + ")");

    auto* worker = new ServerInfoWorker(server, kp, this);
    connect(worker, &ServerInfoWorker::infoResult,
      this, [this, server](bool ok, QList<QPair<QString,QString>> entries, QString error) {
        queryingInfo_ = false;
        btnQueryInfo_->setEnabled(true);
        if (!ok) {
          log("Server info failed: " + server + " — " + error);
          return;
        }
        // Store as JSON array of [key, value] pairs
        QJsonArray arr;
        for (auto& e : entries) {
          QJsonArray pair;
          pair.append(e.first);
          pair.append(e.second);
          arr.append(pair);
        }
        config_.serverInfo[server] = arr;
        config_.save();
        log(QString("Server info: %1 (%2 properties)").arg(server).arg(entries.size()));
        showCachedInfo(server);
      });
    connect(worker, &QThread::finished, worker, &QObject::deleteLater);
    worker->start();
  }

  void onPingResult(int index, int generation, QString status) {
    // Discard results from stale ping batches
    if (generation != pingGeneration_) return;

    if (index >= 0 && index < statuses_.size())
      statuses_[index] = status;

    log(QString("Ping %1: %2")
      .arg(config_.servers.value(index, "?"))
      .arg(status));

    pingsInFlight_--;
    if (pingsInFlight_ <= 0) {
      pingsInFlight_ = 0;
      emit allPingsDone();
    }
    refreshTable();
  }

private:
  const KeyManagerWidget& keyManager_;
  AppConfig& config_;
  ConsoleWidget* console_ = nullptr;
  QTableWidget* table_ = nullptr;
  QLabel* currentLabel_ = nullptr;
  QPushButton* btnPingAll_ = nullptr;
  QPushButton* btnQueryInfo_ = nullptr;
  QTableWidget* infoTable_ = nullptr;
  bool queryingInfo_ = false;
public:
  const QStringList& getStatuses() const { return statuses_; }
private:
  QStringList statuses_;
  int pingsInFlight_ = 0;
  int pingGeneration_ = 0;

  void showCachedInfo(int row) {
    if (row < 0 || row >= config_.servers.size()) {
      infoTable_->setRowCount(0);
      return;
    }
    showCachedInfo(config_.servers[row]);
  }

  void showCachedInfo(const QString& server) {
    infoTable_->setRowCount(0);
    auto it = config_.serverInfo.find(server);
    if (it == config_.serverInfo.end()) return;
    auto& arr = it.value();
    infoTable_->setRowCount(arr.size());
    for (int i = 0; i < arr.size(); ++i) {
      auto pair = arr[i].toArray();
      if (pair.size() >= 2) {
        infoTable_->setItem(i, 0, new QTableWidgetItem(pair[0].toString()));
        infoTable_->setItem(i, 1, new QTableWidgetItem(pair[1].toString()));
      }
    }
  }

  void log(const QString& msg) {
    if (console_) console_->appendLog(msg);
  }

  int selectedRow() {
    auto sel = table_->selectionModel()->selectedRows();
    if (sel.isEmpty()) {
      emit statusMessage("No server selected", 3000);
      return -1;
    }
    return sel.first().row();
  }

  void updateDefaultLabel() {
    if (config_.currentServer.isEmpty()) {
      currentLabel_->setText("Current server: (none)");
      currentLabel_->setStyleSheet("color: #888; font-style: italic;");
    } else {
      currentLabel_->setText("Current server: " + config_.currentServer);
      currentLabel_->setStyleSheet("color: #ccc;");
    }
  }

  void saveAndRefresh() {
    config_.save();
    refreshTable();
    emit serverListChanged();
  }

  void refreshTable() {
    updateDefaultLabel();
    table_->setRowCount(config_.servers.size());
    for (int i = 0; i < config_.servers.size(); ++i) {
      // Server column — mark default with a star
      bool isDefault = (config_.servers[i] == config_.currentServer);
      QString label = config_.servers[i];
      if (isDefault) label = label + "  *";

      auto* addrItem = new QTableWidgetItem(label);
      if (isDefault)
        addrItem->setForeground(QColor("#4ec9b0"));
      table_->setItem(i, 0, addrItem);

      // Status column
      QString st = (i < statuses_.size()) ? statuses_[i] : "(not checked)";
      auto* statusItem = new QTableWidgetItem(st);
      if (st.startsWith("Online"))
        statusItem->setForeground(QColor("#4ec9b0"));
      else if (st.startsWith("Offline"))
        statusItem->setForeground(QColor("#f44747"));
      else if (st.startsWith("Pinging"))
        statusItem->setForeground(QColor("#dcdcaa"));
      else
        statusItem->setForeground(QColor("#888888"));
      table_->setItem(i, 1, statusItem);
    }
  }
};

// =============================================================================
// TransferWorker — performs transfer on a background thread
// =============================================================================

class TransferWorker : public QThread {
  Q_OBJECT
public:
  TransferWorker(const QString& server, const ces::KeyPair& keyPair,
                 const std::string& destPubKey, uint64_t amount,
                 bool openTransfer = false,
                 const QString& crossServer = {},
                 QObject* parent = nullptr)
    : QThread(parent), server_(server), keyPair_(keyPair),
      destPubKey_(destPubKey), amount_(amount),
      openTransfer_(openTransfer), crossServer_(crossServer) {}

signals:
  void transferResult(bool ok, uint8_t rc, int64_t newBalance, QString error);

protected:
  void run() override {
    try {
      auto probe = ces::Resolver::probe(server_.toStdString(),
        [](const std::string& m) { ConsoleWidget::log(QString::fromStdString(m)); });
      auto clientPtr = probe.makeClient(false);
      auto& client = *clientPtr;
      client.setKey(keyPair_);
      client.start(0);

      if (!client.connect()) {
        emit transferResult(false, 0, 0,
          QString("Connect failed (%1)").arg(probe.isTcp ? "TCP" : "UDP"));
        client.stop();
        return;
      }

      minx::Hash dest;
      minx::stringToHash(dest, destPubKey_);
      int64_t newBal = 0;
      uint8_t rc;

      if (!crossServer_.isEmpty())
        rc = client.crossTransfer(dest, amount_,
               crossServer_.toStdString(), newBal);
      else if (openTransfer_)
        rc = client.openTransfer(dest, amount_, newBal);
      else
        rc = client.transfer(dest, amount_, newBal);

      client.disconnect();
      client.stop();

      if (rc == ces::CES_OK)
        emit transferResult(true, rc, newBal, "");
      else
        emit transferResult(false, rc, newBal,
          QString::fromUtf8(ces::errorString(rc)));
    } catch (std::exception& e) {
      emit transferResult(false, 0, 0, QString::fromUtf8(e.what()));
    }
  }

private:
  QString server_;
  ces::KeyPair keyPair_;
  std::string destPubKey_;
  uint64_t amount_;
  bool openTransfer_;
  QString crossServer_;
};

// =============================================================================
// TransferWidget — send funds from selected account
// =============================================================================

class TransferWidget : public QWidget {
  Q_OBJECT
public:
  void setWalletWidget(const WalletWidget* w) {
    walletWidget_ = w;
    updateInfoLabels();
  }

  explicit TransferWidget(const KeyManagerWidget& keyManager,
                          AppConfig& config, ConsoleWidget* console,
                          QWidget* parent = nullptr)
    : QWidget(parent), keyManager_(keyManager), config_(config),
      console_(console) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 16, 16, 16);
    layout->setSpacing(12);

    // From account
    auto* fromRow = new QHBoxLayout;
    fromRow->addWidget(new QLabel("From:"));
    keyCombo_ = new KeyComboBox;
    keyCombo_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    fromRow->addWidget(keyCombo_);
    layout->addLayout(fromRow);
    fromInfoLabel_ = new QLabel("");
    fromInfoLabel_->setStyleSheet("color: #6b7b8d; font-size: 9pt; margin-left: 40px;");
    layout->addWidget(fromInfoLabel_);

    // Destination
    auto* destRow = new QHBoxLayout;
    destRow->addWidget(new QLabel("To:"));
    destCombo_ = new QComboBox;
    destCombo_->setEditable(true);
    destCombo_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    destCombo_->setInsertPolicy(QComboBox::NoInsert);
    destCombo_->lineEdit()->setPlaceholderText(
      "Public key hex or @index (e.g. @0)");
    destRow->addWidget(destCombo_);
    layout->addLayout(destRow);
    toInfoLabel_ = new QLabel("");
    toInfoLabel_->setStyleSheet("color: #6b7b8d; font-size: 9pt; margin-left: 40px;");
    layout->addWidget(toInfoLabel_);

    // Amount
    auto* amountRow = new QHBoxLayout;
    amountRow->addWidget(new QLabel("Amount:"));
    amountEdit_ = new QLineEdit;
    amountEdit_->setPlaceholderText("0.00000000");
    amountRow->addWidget(amountEdit_);
    layout->addLayout(amountRow);

    // Open transfer
    openCheck_ = new QCheckBox("Open transfer (pays to create destination account if needed)");
    openCheck_->setChecked(false);
    layout->addWidget(openCheck_);

    // Cross-transfer
    auto* crossRow = new QHBoxLayout;
    crossCheck_ = new QCheckBox("Cross-transfer to:");
    crossRow->addWidget(crossCheck_);
    crossCombo_ = new CopyableComboBox;
    crossCombo_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    crossCombo_->setEnabled(false);
    crossRow->addWidget(crossCombo_);
    connect(crossCheck_, &QCheckBox::toggled, this, [this](bool on) {
      crossCombo_->setEnabled(on);
      if (on) refreshServerList();
    });
    layout->addLayout(crossRow);

    // Send button
    auto* btnRow = new QHBoxLayout;
    btnRow->addStretch();
    sendBtn_ = new QPushButton("Send");
    sendBtn_->setFixedWidth(120);
    connect(sendBtn_, &QPushButton::clicked, this, &TransferWidget::onSend);
    btnRow->addWidget(sendBtn_);
    btnRow->addStretch();
    layout->addLayout(btnRow);

    // Status
    statusLabel_ = new QLabel("");
    statusLabel_->setStyleSheet("font-style: italic; color: #6b7b8d;");
    statusLabel_->setWordWrap(true);
    layout->addWidget(statusLabel_);

    layout->addStretch();

    connect(keyCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged),
      this, [this](int) { updateInfoLabels(); });
    connect(destCombo_, &QComboBox::currentTextChanged,
      this, [this](const QString&) { updateInfoLabels(); });

    refreshKeyList();
  }

public slots:
  void refreshKeyList() {
    keyCombo_->clear();
    auto& w = keyManager_.wallet();
    for (int i = 0; i < w.size(); ++i) {
      auto kp = w.keyPair(i);
      keyCombo_->addItem(formatKeyLabel(i, kp, w.label(i)), i);
    }
    refreshDestCombo();
    refreshServerList();
    updateInfoLabels();
  }

  void updateInfoLabels() {
    // From: show cached balance if available
    int fromIdx = keyCombo_->currentData().toInt();
    fromInfoLabel_->setText(accountInfoForIndex(fromIdx));
    // To: show cached balance if it's a wallet key (@N)
    QString destText = destCombo_->currentText().trimmed();
    if (destText.startsWith('@')) {
      QString numPart = destText.mid(1).split(' ').first();
      bool ok;
      int toIdx = numPart.toInt(&ok);
      if (ok && toIdx >= 0 && toIdx < keyManager_.wallet().size()) {
        toInfoLabel_->setText(accountInfoForIndex(toIdx));
      } else {
        toInfoLabel_->setText("");
      }
    } else if (!destText.isEmpty()) {
      toInfoLabel_->setText("External address");
    } else {
      toInfoLabel_->setText("");
    }
  }

  void refreshServerList() {
    crossCombo_->clear();
    if (!config_.currentServer.isEmpty())
      crossCombo_->addItem(config_.currentServer);
    for (auto& s : config_.servers) {
      if (s != config_.currentServer)
        crossCombo_->addItem(s);
    }
  }

signals:
  void statusMessage(const QString& msg, int timeout);
  void transferCompleted(int accountIndex, int64_t newBalance);

private slots:
  void onSend() {
    auto& w = keyManager_.wallet();
    if (w.empty()) {
      statusLabel_->setText("No keys in wallet.");
      statusLabel_->setStyleSheet("font-style: italic; color: #f44747;");
      return;
    }
    if (config_.currentServer.isEmpty()) {
      statusLabel_->setText("No current server configured.");
      statusLabel_->setStyleSheet("font-style: italic; color: #f44747;");
      return;
    }
    if (sending_) return;

    QString destInput = destCombo_->currentText().trimmed();
    if (destInput.isEmpty()) {
      statusLabel_->setText("Enter a destination.");
      statusLabel_->setStyleSheet("font-style: italic; color: #f44747;");
      return;
    }

    // Parse amount: user types decimal like "1.5" meaning 1.50000000
    QString amountStr = amountEdit_->text().trimmed();
    if (amountStr.isEmpty()) {
      statusLabel_->setText("Enter an amount.");
      statusLabel_->setStyleSheet("font-style: italic; color: #f44747;");
      return;
    }

    uint64_t amount = 0;
    if (!parseAmount(amountStr, amount)) {
      statusLabel_->setText("Invalid amount format.");
      statusLabel_->setStyleSheet("font-style: italic; color: #f44747;");
      return;
    }
    if (amount == 0) {
      statusLabel_->setText("Amount must be > 0.");
      statusLabel_->setStyleSheet("font-style: italic; color: #f44747;");
      return;
    }

    // Resolve destination
    std::string resolvedDest;
    try {
      resolvedDest = w.resolveKey(destInput.toStdString());
    } catch (std::exception& e) {
      statusLabel_->setText(QString("Bad destination: %1").arg(e.what()));
      statusLabel_->setStyleSheet("font-style: italic; color: #f44747;");
      return;
    }

    int idx = keyCombo_->currentData().toInt();
    ces::KeyPair kp = w.keyPair(idx);
    resolvedDest_ = QString::fromStdString(resolvedDest);

    sending_ = true;
    sendBtn_->setEnabled(false);

    QString crossServer;
    if (crossCheck_->isChecked())
      crossServer = crossCombo_->currentText().trimmed();

    if (crossServer.isEmpty()) {
      statusLabel_->setText(QString("Sending %1 to %2...")
        .arg(formatAmount(amount))
        .arg(resolvedDest_.left(16) + "..."));
      log(QString("Transfer: %1 from @%2 to %3")
        .arg(formatAmount(amount)).arg(idx).arg(resolvedDest_));
    } else {
      statusLabel_->setText(QString("Cross-sending %1 to %2 via %3...")
        .arg(formatAmount(amount))
        .arg(resolvedDest_.left(16) + "...")
        .arg(crossServer));
      log(QString("Cross-transfer: %1 from @%2 to %3 on %4")
        .arg(formatAmount(amount)).arg(idx).arg(resolvedDest_).arg(crossServer));
    }
    statusLabel_->setStyleSheet("font-style: italic; color: #dcdcaa;");

    auto* worker = new TransferWorker(
      config_.currentServer, kp, resolvedDest.c_str(), amount,
      openCheck_->isChecked(), crossServer, this);
    connect(worker, &TransferWorker::transferResult,
      this, [this, idx](bool ok, uint8_t rc, int64_t newBal, QString error) {
        onTransferResult(ok, rc, newBal, error, idx);
      });
    connect(worker, &QThread::finished, worker, &QObject::deleteLater);
    worker->start();
  }

  void onTransferResult(bool ok, uint8_t rc, int64_t newBal,
                        QString error, int accountIndex) {
    sending_ = false;
    sendBtn_->setEnabled(true);
    (void)rc;

    if (ok) {
      statusLabel_->setText(QString("Sent! New balance: %1")
        .arg(formatAmount(newBal)));
      statusLabel_->setStyleSheet("font-style: italic; color: #4ec9b0;");
      log(QString("Transfer OK. New balance: %1").arg(formatAmount(newBal)));

      // Push resolved dest to history and refresh
      config_.pushTransferDest(resolvedDest_);
      refreshDestCombo();

      emit transferCompleted(accountIndex, newBal);
    } else {
      statusLabel_->setText("Transfer failed: " + error);
      statusLabel_->setStyleSheet("font-style: italic; color: #f44747;");
      log("Transfer failed: " + error);
    }
  }

private:
  void log(const QString& msg) {
    if (console_) console_->appendLog(msg);
  }

  void refreshDestCombo() {
    QString currentText = destCombo_->currentText();
    destCombo_->clear();
    // Wallet keys first (for easy self-transfers)
    auto& w = keyManager_.wallet();
    if (w.size() > 0) {
      for (int i = 0; i < w.size(); ++i) {
        auto kp = w.keyPair(i);
        destCombo_->addItem(formatKeyLabel(i, kp, w.label(i)));
      }
      // Separator before history
      if (!config_.transferDestHistory.isEmpty())
        destCombo_->insertSeparator(destCombo_->count());
    }
    // History (raw pubkeys from previous transfers)
    for (auto& h : config_.transferDestHistory)
      destCombo_->addItem(h);
    destCombo_->setCurrentText(currentText);
  }

  static bool parseAmount(const QString& str, uint64_t& out) {
    // Accept "1", "1.5", "0.001", etc. Convert to internal units (8 decimals)
    int dotPos = str.indexOf('.');
    if (dotPos < 0) {
      // No decimal point — whole units
      bool ok;
      uint64_t whole = str.toULongLong(&ok);
      if (!ok) return false;
      if (whole > UINT64_MAX / ces::PRICE_UNIT) return false; // overflow
      out = whole * ces::PRICE_UNIT;
      return true;
    }
    QString wholePart = str.left(dotPos);
    QString fracPart = str.mid(dotPos + 1);
    if (fracPart.size() > 8) return false;  // too many decimals
    // Pad to 8 digits
    while (fracPart.size() < 8) fracPart.append('0');

    bool ok1, ok2;
    uint64_t whole = wholePart.isEmpty() ? 0 : wholePart.toULongLong(&ok1);
    if (!wholePart.isEmpty() && !ok1) return false;
    uint64_t frac = fracPart.toULongLong(&ok2);
    if (!ok2) return false;
    out = whole * ces::PRICE_UNIT + frac;
    return true;
  }

  QString accountInfoForIndex(int idx) {
    if (!walletWidget_) return "";
    auto& accounts = walletWidget_->getAccounts();
    for (auto& a : accounts) {
      if (a.index == idx) {
        if (a.exists)
          return QString("Balance: %1").arg(formatAmount(a.balance));
        else
          return "Account not found on server";
      }
    }
    return "Not yet queried";
  }

  const KeyManagerWidget& keyManager_;
  AppConfig& config_;
  ConsoleWidget* console_ = nullptr;
  const WalletWidget* walletWidget_ = nullptr;
  QComboBox* keyCombo_ = nullptr;
  QComboBox* destCombo_ = nullptr;
  QLabel* fromInfoLabel_ = nullptr;
  QLabel* toInfoLabel_ = nullptr;
  QLineEdit* amountEdit_ = nullptr;
  QCheckBox* openCheck_ = nullptr;
  QCheckBox* crossCheck_ = nullptr;
  QComboBox* crossCombo_ = nullptr;
  QPushButton* sendBtn_ = nullptr;
  QLabel* statusLabel_ = nullptr;
  bool sending_ = false;
  QString resolvedDest_;
};

// =============================================================================
// AssetUnsignedQueryWorker — unsigned (free) asset query on background thread
// =============================================================================

class AssetUnsignedQueryWorker : public QThread {
  Q_OBJECT
public:
  AssetUnsignedQueryWorker(const QString& server, const QString& assetKeyHex,
                           QObject* parent = nullptr)
    : QThread(parent), server_(server), assetKeyHex_(assetKeyHex) {}

signals:
  void queryResult(bool ok, QString owner, QString contentHex,
                   uint16_t days, uint32_t storedPrice, QString error);

protected:
  void run() override {
    try {
      auto probe = ces::Resolver::probe(server_.toStdString(),
        [](const std::string& m) { ConsoleWidget::log(QString::fromStdString(m)); });
      auto clientPtr = probe.makeClient(false);
      auto& client = *clientPtr;
      client.start(0);
      if (!client.connect()) {
        emit queryResult(false, "", "", 0, 0,
          QString("Connect failed (%1)").arg(probe.isTcp ? "TCP" : "UDP"));
        client.stop();
        return;
      }

      minx::Hash assetId;
      minx::stringToHash(assetId, assetKeyHex_.toStdString());
      ces::HashPrefix owner{};
      ces::AssetData content{};
      uint16_t balance = 0;
      uint32_t price = 0;
      uint8_t rc = client.queryAsset(assetId, owner, content, balance, price);

      client.disconnect();
      client.stop();

      if (rc != ces::CES_OK) {
        emit queryResult(false, "", "", 0, 0,
          QString::fromUtf8(ces::errorString(rc)));
        return;
      }

      // Check if asset exists (zero owner = not found)
      ces::HashPrefix zero{};
      if (owner == zero) {
        emit queryResult(false, "", "", 0, 0, "Asset not found");
        return;
      }

      // Convert owner to hex
      QString ownerHex = QString::fromStdString(
        ces::hashPrefixToString(owner));
      // Convert content to hex
      QByteArray contentRaw(reinterpret_cast<const char*>(content.data()),
                            content.size());
      QString contentHexStr = contentRaw.toHex();

      // The signal still carries `days` semantics for the existing UI;
      // mask off the priv/aowned/immut flag bits (extending the UI to
      // display flags is left as a follow-up).
      emit queryResult(true, ownerHex, contentHexStr,
                       ces::assetDays(balance), price, "");
    } catch (std::exception& e) {
      emit queryResult(false, "", "", 0, 0, QString::fromUtf8(e.what()));
    }
  }

private:
  QString server_;
  QString assetKeyHex_;
};

// =============================================================================
// AssetActionWorker — signed asset operations on background thread
// =============================================================================

class AssetActionWorker : public QThread {
  Q_OBJECT
public:
  enum Action { Create, UpdateFull, UpdateFast, UpdateMeta, Fund, Give, Buy };

  AssetActionWorker(Action action, const QString& server,
                    const ces::KeyPair& keyPair,
                    const QString& assetKeyHex,
                    QObject* parent = nullptr)
    : QThread(parent), action_(action), server_(server),
      keyPair_(keyPair), assetKeyHex_(assetKeyHex) {}

  // Setters for action-specific parameters
  void setContent(const ces::AssetData& c) { content_ = c; }
  void setDays(uint16_t d) { days_ = d; }
  void setStoredPrice(uint32_t p) { storedPrice_ = p; }
  void setNewOwner(const ces::HashPrefix& o) { newOwner_ = o; }
  void setBuyAmount(uint64_t a) { buyAmount_ = a; }

signals:
  void actionResult(bool ok, uint8_t rc, QString error);

protected:
  void run() override {
    try {
      auto probe = ces::Resolver::probe(server_.toStdString(),
        [](const std::string& m) { ConsoleWidget::log(QString::fromStdString(m)); });
      auto clientPtr = probe.makeClient(false);
      auto& client = *clientPtr;
      client.setKey(keyPair_);
      client.start(0);
      if (!client.connect()) {
        emit actionResult(false, 0,
          QString("Connect failed (%1)").arg(probe.isTcp ? "TCP" : "UDP"));
        client.stop();
        return;
      }

      minx::Hash assetId;
      minx::stringToHash(assetId, assetKeyHex_.toStdString());
      uint8_t rc = 0;

      switch (action_) {
      case Create:
        rc = client.createAsset(assetId, content_, days_);
        break;
      case UpdateFull:
        rc = client.updateAsset(assetId, newOwner_, content_, storedPrice_);
        break;
      case UpdateFast:
        rc = client.updateAssetFast(assetId, content_);
        break;
      case UpdateMeta:
        rc = client.updateAssetMeta(assetId, newOwner_, storedPrice_);
        break;
      case Fund:
        rc = client.fundAsset(assetId, days_);
        break;
      case Give:
        rc = client.giveAsset(assetId, newOwner_);
        break;
      case Buy:
        rc = client.buyAsset(assetId, buyAmount_);
        break;
      }

      client.disconnect();
      client.stop();

      if (rc == ces::CES_OK)
        emit actionResult(true, rc, "");
      else
        emit actionResult(false, rc,
          QString::fromUtf8(ces::errorString(rc)));
    } catch (std::exception& e) {
      emit actionResult(false, 0, QString::fromUtf8(e.what()));
    }
  }

private:
  Action action_;
  QString server_;
  ces::KeyPair keyPair_;
  QString assetKeyHex_;
  ces::AssetData content_{};
  uint16_t days_ = 0;
  uint32_t storedPrice_ = 0;
  ces::HashPrefix newOwner_{};
  uint64_t buyAmount_ = 0;
};

// =============================================================================
// AssetsWidget — tracked assets management
// =============================================================================

class AssetsWidget : public QWidget {
  Q_OBJECT
public:
  explicit AssetsWidget(const KeyManagerWidget& keyManager,
                        AppConfig& config, ConsoleWidget* console,
                        QWidget* parent = nullptr)
    : QWidget(parent), keyManager_(keyManager), config_(config),
      console_(console) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(12, 12, 12, 12);
    layout->setSpacing(8);

    // --- Top: asset selector + add/remove ---
    auto* topRow = new QHBoxLayout;
    topRow->addWidget(new QLabel("Asset:"));
    assetCombo_ = new CopyableComboBox;
    assetCombo_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    connect(assetCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged),
      this, &AssetsWidget::onAssetSelected);
    topRow->addWidget(assetCombo_);

    auto* addBtn = new QPushButton("Track...");
    addBtn->setToolTip("Add an asset to track");
    connect(addBtn, &QPushButton::clicked, this, &AssetsWidget::onTrackAsset);
    topRow->addWidget(addBtn);

    removeBtn_ = new QPushButton("Remove");
    removeBtn_->setToolTip("Stop tracking this asset");
    connect(removeBtn_, &QPushButton::clicked,
      this, &AssetsWidget::onRemoveAsset);
    topRow->addWidget(removeBtn_);
    layout->addLayout(topRow);

    // --- Detail view ---
    auto* detailGroup = new QGroupBox("Asset Details");
    auto* detailLayout = new QVBoxLayout(detailGroup);
    detailLayout->setSpacing(4);

    keyLabel_ = new QLabel("Key: —");
    contentLabel_ = new QLabel("Content: —");
    contentLabel_->setWordWrap(true);
    ownerLabel_ = new QLabel("Owner: —");
    daysLabel_ = new QLabel("Days left: —");
    priceLabel_ = new QLabel("Price: —");
    queryTimeLabel_ = new QLabel("");
    queryTimeLabel_->setStyleSheet("color: #6b7b8d; font-size: 9pt;");

    detailLayout->addWidget(keyLabel_);
    detailLayout->addWidget(contentLabel_);
    detailLayout->addWidget(ownerLabel_);
    detailLayout->addWidget(daysLabel_);
    detailLayout->addWidget(priceLabel_);
    detailLayout->addWidget(queryTimeLabel_);
    layout->addWidget(detailGroup);

    // --- Query button ---
    auto* queryRow = new QHBoxLayout;
    queryBtn_ = new QPushButton("Query Asset");
    queryBtn_->setToolTip("Fetch fresh data from the asset's server");
    connect(queryBtn_, &QPushButton::clicked, this, &AssetsWidget::onQueryAsset);
    queryRow->addWidget(queryBtn_);
    queryRow->addStretch();
    layout->addLayout(queryRow);

    // --- Action buttons ---
    auto* actionGroup = new QGroupBox("Owner Actions");
    auto* actionLayout = new QVBoxLayout(actionGroup);

    // Fund
    auto* fundRow = new QHBoxLayout;
    fundRow->addWidget(new QLabel("Fund:"));
    fundDaysSpin_ = new QSpinBox;
    fundDaysSpin_->setRange(1, 65535);
    fundDaysSpin_->setValue(30);
    fundDaysSpin_->setSuffix(" days");
    fundRow->addWidget(fundDaysSpin_);
    auto* fundBtn = new QPushButton("Fund");
    connect(fundBtn, &QPushButton::clicked, this, &AssetsWidget::onFundAsset);
    fundRow->addWidget(fundBtn);
    fundRow->addStretch();
    actionLayout->addLayout(fundRow);

    // Update content
    auto* updateRow = new QHBoxLayout;
    updateRow->addWidget(new QLabel("Update:"));
    updateContentEdit_ = new QLineEdit;
    updateContentEdit_->setPlaceholderText("New content (text or hex)");
    updateRow->addWidget(updateContentEdit_);
    auto* updateBtn = new QPushButton("Update Content");
    connect(updateBtn, &QPushButton::clicked,
      this, &AssetsWidget::onUpdateContent);
    updateRow->addWidget(updateBtn);
    actionLayout->addLayout(updateRow);

    // Set price
    auto* priceRow = new QHBoxLayout;
    priceRow->addWidget(new QLabel("Price:"));
    priceEdit_ = new QLineEdit;
    priceEdit_->setPlaceholderText("Whole credits (0=not for sale)");
    priceEdit_->setMaximumWidth(200);
    priceRow->addWidget(priceEdit_);
    auto* priceBtn = new QPushButton("Set Price");
    connect(priceBtn, &QPushButton::clicked,
      this, &AssetsWidget::onSetPrice);
    priceRow->addWidget(priceBtn);
    priceRow->addStretch();
    actionLayout->addLayout(priceRow);

    // Give
    auto* giveRow = new QHBoxLayout;
    giveRow->addWidget(new QLabel("Give to:"));
    giveDestEdit_ = new QLineEdit;
    giveDestEdit_->setPlaceholderText("Public key hex or @index");
    giveRow->addWidget(giveDestEdit_);
    auto* giveBtn = new QPushButton("Give");
    connect(giveBtn, &QPushButton::clicked, this, &AssetsWidget::onGiveAsset);
    giveRow->addWidget(giveBtn);
    actionLayout->addLayout(giveRow);

    layout->addWidget(actionGroup);

    // --- Status ---
    statusLabel_ = new QLabel("");
    statusLabel_->setStyleSheet("font-style: italic; color: #6b7b8d;");
    statusLabel_->setWordWrap(true);
    layout->addWidget(statusLabel_);

    layout->addStretch();
    refreshAssetList();
  }

public slots:
  void refreshAssetList() {
    assetCombo_->blockSignals(true);
    int prevIdx = assetCombo_->currentIndex();
    assetCombo_->clear();
    for (auto& a : config_.trackedAssets)
      assetCombo_->addItem(a.fullId());
    if (prevIdx >= 0 && prevIdx < assetCombo_->count())
      assetCombo_->setCurrentIndex(prevIdx);
    assetCombo_->blockSignals(false);
    onAssetSelected(assetCombo_->currentIndex());
  }

signals:
  void statusMessage(const QString& msg, int timeout);

private slots:
  void onAssetSelected(int index) {
    if (index < 0 || index >= config_.trackedAssets.size()) {
      clearDetail();
      return;
    }
    auto& a = config_.trackedAssets[index];
    keyLabel_->setText("Key: " + a.keyDisplay());
    if (!a.known) {
      contentLabel_->setText("Content: —");
      ownerLabel_->setText("Owner: (not yet queried)");
      daysLabel_->setText("Days left: —");
      priceLabel_->setText("Price: —");
    } else {
      updateDetailFromAsset(a);
    }

    if (!a.lastQueryTime.isEmpty())
      queryTimeLabel_->setText("Last queried: " + a.lastQueryTime);
    else
      queryTimeLabel_->setText("");
    if (!a.lastQueryError.isEmpty())
      queryTimeLabel_->setText(queryTimeLabel_->text() +
        "  (error: " + a.lastQueryError + ")");
  }

  void onQueryAsset() {
    int idx = assetCombo_->currentIndex();
    if (idx < 0 || idx >= config_.trackedAssets.size()) return;
    if (busy_) return;

    auto& a = config_.trackedAssets[idx];
    busy_ = true;
    queryBtn_->setEnabled(false);
    setStatus("Querying " + a.fullId() + "...", "#dcdcaa");

    auto* worker = new AssetUnsignedQueryWorker(a.server, a.assetKey, this);
    connect(worker, &AssetUnsignedQueryWorker::queryResult,
      this, [this, idx](bool ok, QString owner, QString contentHex,
                         uint16_t days, uint32_t storedPrice, QString error) {
        onQueryResult(idx, ok, owner, contentHex, days, storedPrice, error);
      });
    connect(worker, &QThread::finished, worker, &QObject::deleteLater);
    worker->start();
  }

  void onQueryResult(int idx, bool ok, QString owner, QString contentHex,
                     uint16_t days, uint32_t storedPrice, QString error) {
    busy_ = false;
    queryBtn_->setEnabled(true);

    if (idx < 0 || idx >= config_.trackedAssets.size()) return;

    auto& a = config_.trackedAssets[idx];
    a.lastQueryTime = QDateTime::currentDateTime().toString(Qt::ISODate);

    if (ok) {
      a.known = true;
      a.owner = owner;
      a.contentHex = contentHex;
      a.days = days;
      a.storedPrice = storedPrice;
      a.lastQueryError = "";
      setStatus("Query OK.", "#4ec9b0");
      log("Asset query OK: " + a.fullId());
    } else {
      a.lastQueryError = error;
      setStatus("Query failed: " + error, "#f44747");
      log("Asset query failed: " + a.fullId() + " — " + error);
    }
    config_.updateTrackedAsset(idx, a);

    if (assetCombo_->currentIndex() == idx)
      onAssetSelected(idx);
  }

  void onTrackAsset() {
    bool ok;
    QString input = QInputDialog::getText(this, "Track Asset",
      "Asset ID (key@server or just key for current server):",
      QLineEdit::Normal, "", &ok);
    if (!ok || input.trimmed().isEmpty()) return;
    input = input.trimmed();

    QString assetKey, server;
    int atPos = input.lastIndexOf('@');
    if (atPos > 0) {
      assetKey = input.left(atPos);
      server = input.mid(atPos + 1);
    } else {
      assetKey = input;
      server = config_.currentServer;
    }

    if (server.isEmpty()) {
      setStatus("No server specified and no current server set.", "#f44747");
      return;
    }

    // Validate key: parse it through parseAssetKey to normalize
    try {
      auto parsed = ces::parseAssetKey(assetKey.toStdString());
      assetKey = QString::fromStdString(minx::hashToString(parsed));
    } catch (...) {
      setStatus("Invalid asset key.", "#f44747");
      return;
    }

    if (config_.findTrackedAsset(assetKey, server) >= 0) {
      setStatus("Already tracking this asset.", "#dcdcaa");
      return;
    }

    TrackedAsset ta;
    ta.assetKey = assetKey;
    ta.server = server;
    config_.addTrackedAsset(ta);
    refreshAssetList();
    assetCombo_->setCurrentIndex(config_.trackedAssets.size() - 1);
    setStatus("Now tracking: " + ta.fullId(), "#4ec9b0");
    log("Tracking asset: " + ta.fullId());
  }

  void onRemoveAsset() {
    int idx = assetCombo_->currentIndex();
    if (idx < 0 || idx >= config_.trackedAssets.size()) return;
    auto a = config_.trackedAssets[idx];

    auto reply = QMessageBox::question(this, "Remove Asset",
      "Stop tracking " + a.fullId() + "?",
      QMessageBox::Yes | QMessageBox::No);
    if (reply != QMessageBox::Yes) return;

    config_.removeTrackedAsset(a.assetKey, a.server);
    refreshAssetList();
    setStatus("Removed: " + a.fullId(), "#4ec9b0");
    log("Removed asset: " + a.fullId());
  }

  void onFundAsset() {
    int idx = assetCombo_->currentIndex();
    if (idx < 0 || idx >= config_.trackedAssets.size()) return;
    if (busy_) return;

    ces::KeyPair kp;
    if (!getSigningKey(kp)) return;

    auto& a = config_.trackedAssets[idx];
    busy_ = true;
    setStatus("Funding asset...", "#dcdcaa");

    auto* worker = new AssetActionWorker(
      AssetActionWorker::Fund, a.server, kp, a.assetKey, this);
    worker->setDays(static_cast<uint16_t>(fundDaysSpin_->value()));
    connectActionResult(worker, idx, "Funded");
    worker->start();
  }

  void onUpdateContent() {
    int idx = assetCombo_->currentIndex();
    if (idx < 0 || idx >= config_.trackedAssets.size()) return;
    if (busy_) return;

    QString contentStr = updateContentEdit_->text().trimmed();
    if (contentStr.isEmpty()) { setStatus("Enter content.", "#f44747"); return; }

    ces::KeyPair kp;
    if (!getSigningKey(kp)) return;

    ces::AssetData content;
    try {
      content = ces::parseAssetContent(contentStr.toStdString());
    } catch (std::exception& e) {
      setStatus(QString("Parse error: %1").arg(e.what()), "#f44747");
      return;
    }

    auto& a = config_.trackedAssets[idx];
    busy_ = true;
    setStatus("Updating content...", "#dcdcaa");

    auto* worker = new AssetActionWorker(
      AssetActionWorker::UpdateFast, a.server, kp, a.assetKey, this);
    worker->setContent(content);
    connectActionResult(worker, idx, "Content updated");
    worker->start();
  }

  void onSetPrice() {
    int idx = assetCombo_->currentIndex();
    if (idx < 0 || idx >= config_.trackedAssets.size()) return;
    if (busy_) return;

    bool ok;
    uint64_t wholeCredits = priceEdit_->text().trimmed().toULongLong(&ok);
    if (!ok) { setStatus("Invalid price number.", "#f44747"); return; }

    uint32_t stored;
    if (ces::validatePrice(wholeCredits, stored) != 0) {
      setStatus(QString("Invalid price. Max: %1").arg(UINT32_MAX), "#f44747");
      return;
    }

    ces::KeyPair kp;
    if (!getSigningKey(kp)) return;

    auto& a = config_.trackedAssets[idx];
    // Keep current owner for meta update
    ces::HashPrefix owner{};
    if (a.known && !a.owner.isEmpty()) {
      auto ownerBytes = QByteArray::fromHex(a.owner.toLatin1());
      if (ownerBytes.size() >= 8)
        std::memcpy(owner.data(), ownerBytes.data(), 8);
    } else {
      // Use our own key as owner
      owner = ces::Account::getMapKey(kp.getPublicKeyAsHash());
    }

    busy_ = true;
    setStatus("Setting price...", "#dcdcaa");

    auto* worker = new AssetActionWorker(
      AssetActionWorker::UpdateMeta, a.server, kp, a.assetKey, this);
    worker->setNewOwner(owner);
    worker->setStoredPrice(stored);
    connectActionResult(worker, idx, "Price updated");
    worker->start();
  }

  void onGiveAsset() {
    int idx = assetCombo_->currentIndex();
    if (idx < 0 || idx >= config_.trackedAssets.size()) return;
    if (busy_) return;

    QString destStr = giveDestEdit_->text().trimmed();
    if (destStr.isEmpty()) { setStatus("Enter destination.", "#f44747"); return; }

    ces::KeyPair kp;
    if (!getSigningKey(kp)) return;

    ces::HashPrefix newOwner;
    try {
      auto& w = keyManager_.wallet();
      std::string resolved = w.resolveKey(destStr.toStdString());
      minx::Hash h;
      minx::stringToHash(h, resolved);
      newOwner = ces::Account::getMapKey(h);
    } catch (std::exception& e) {
      setStatus(QString("Bad destination: %1").arg(e.what()), "#f44747");
      return;
    }

    auto& a = config_.trackedAssets[idx];
    busy_ = true;
    setStatus("Giving asset...", "#dcdcaa");

    auto* worker = new AssetActionWorker(
      AssetActionWorker::Give, a.server, kp, a.assetKey, this);
    worker->setNewOwner(newOwner);
    connectActionResult(worker, idx, "Asset given");
    worker->start();
  }

private:
  void connectActionResult(AssetActionWorker* worker, int idx,
                           const QString& successMsg) {
    connect(worker, &AssetActionWorker::actionResult,
      this, [this, idx, successMsg](bool ok, uint8_t, QString error) {
        busy_ = false;
        if (ok) {
          setStatus(successMsg + "!", "#4ec9b0");
          log(successMsg);
          // Auto-query to refresh cached data
          if (idx >= 0 && idx < config_.trackedAssets.size() &&
              assetCombo_->currentIndex() == idx) {
            QTimer::singleShot(200, this, &AssetsWidget::onQueryAsset);
          }
        } else {
          setStatus("Failed: " + error, "#f44747");
          log("Action failed: " + error);
        }
      });
    connect(worker, &QThread::finished, worker, &QObject::deleteLater);
  }

  bool getSigningKey(ces::KeyPair& kp) {
    auto& w = keyManager_.wallet();
    if (w.empty()) {
      setStatus("No keys in wallet.", "#f44747");
      return false;
    }

    int idx = assetCombo_->currentIndex();
    if (idx >= 0 && idx < config_.trackedAssets.size()) {
      auto& a = config_.trackedAssets[idx];
      if (a.known && !a.owner.isEmpty()) {
        // Try to find a local key matching the owner
        auto ownerBytes = QByteArray::fromHex(a.owner.toLatin1());
        for (int i = 0; i < w.size(); ++i) {
          auto localKp = w.keyPair(i);
          ces::HashPrefix localOwner =
            ces::Account::getMapKey(localKp.getPublicKeyAsHash());
          QByteArray localBytes(reinterpret_cast<const char*>(localOwner.data()),
                                localOwner.size());
          if (localBytes == ownerBytes) {
            kp = localKp;
            return true;
          }
        }
        setStatus("No local key matches the asset owner.", "#f44747");
        return false;
      }
    }
    // Fall back to first key
    kp = w.keyPair(0);
    return true;
  }

  void clearDetail() {
    keyLabel_->setText("Key: —");
    contentLabel_->setText("Content: —");
    ownerLabel_->setText("Owner: —");
    daysLabel_->setText("Days left: —");
    priceLabel_->setText("Price: —");
    queryTimeLabel_->setText("");
  }

  void updateDetailFromAsset(const TrackedAsset& a) {
    keyLabel_->setText("Key: " + a.keyDisplay());
    contentLabel_->setText("Content: " + a.contentDisplay());

    // Check if any local key matches the owner
    QString ownerStr = a.owner;
    auto& w = keyManager_.wallet();
    auto ownerBytes = QByteArray::fromHex(a.owner.toLatin1());
    for (int i = 0; i < w.size(); ++i) {
      ces::HashPrefix localOwner =
        ces::Account::getMapKey(w.keyPair(i).getPublicKeyAsHash());
      QByteArray localBytes(reinterpret_cast<const char*>(localOwner.data()),
                            localOwner.size());
      if (localBytes == ownerBytes) {
        ownerStr = QString("@%1 (%2)").arg(i).arg(a.owner);
        break;
      }
    }
    ownerLabel_->setText("Owner: " + ownerStr);
    daysLabel_->setText(QString("Days left: %1").arg(a.days));
    if (a.storedPrice == 0)
      priceLabel_->setText("Price: not for sale");
    else
      priceLabel_->setText(QString("Price: %1 credits")
        .arg(a.storedPrice));
  }

  void setStatus(const QString& msg, const char* color) {
    statusLabel_->setText(msg);
    statusLabel_->setStyleSheet(
      QString("font-style: italic; color: %1;").arg(color));
  }

  void log(const QString& msg) {
    if (console_) console_->appendLog(msg);
  }

  const KeyManagerWidget& keyManager_;
  AppConfig& config_;
  ConsoleWidget* console_ = nullptr;

  QComboBox* assetCombo_ = nullptr;
  QPushButton* removeBtn_ = nullptr;
  QPushButton* queryBtn_ = nullptr;
  QLabel* keyLabel_ = nullptr;
  QLabel* ownerLabel_ = nullptr;
  QLabel* daysLabel_ = nullptr;
  QLabel* priceLabel_ = nullptr;
  QLabel* contentLabel_ = nullptr;
  QLabel* queryTimeLabel_ = nullptr;
  QLabel* statusLabel_ = nullptr;

  // Action fields
  QSpinBox* fundDaysSpin_ = nullptr;
  QLineEdit* updateContentEdit_ = nullptr;
  QLineEdit* priceEdit_ = nullptr;
  QLineEdit* giveDestEdit_ = nullptr;

  bool busy_ = false;
};

// =============================================================================
// CreateAssetWidget — asset creation with live binary preview
// =============================================================================

class CreateAssetWidget : public QWidget {
  Q_OBJECT
public:
  explicit CreateAssetWidget(const KeyManagerWidget& keyManager,
                             AppConfig& config, ConsoleWidget* console,
                             QWidget* parent = nullptr)
    : QWidget(parent), keyManager_(keyManager), config_(config),
      console_(console) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(12, 12, 12, 12);
    layout->setSpacing(8);

    // --- Server selector ---
    auto* serverRow = new QHBoxLayout;
    serverRow->addWidget(new QLabel("Server:"));
    serverCombo_ = new CopyableComboBox;
    serverCombo_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    serverRow->addWidget(serverCombo_);
    layout->addLayout(serverRow);

    // --- Account selector ---
    auto* acctRow = new QHBoxLayout;
    acctRow->addWidget(new QLabel("Account:"));
    keyCombo_ = new KeyComboBox;
    keyCombo_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    acctRow->addWidget(keyCombo_);
    layout->addLayout(acctRow);

    // --- Asset key ---
    auto* keyLabelRow = new QHBoxLayout;
    keyLabelRow->addWidget(new QLabel("Asset key:"));
    keyHexCheck_ = new QCheckBox("Binary input (hex, e.g. FFA01032)");
    keyLabelRow->addWidget(keyHexCheck_);
    keyLabelRow->addStretch();
    layout->addLayout(keyLabelRow);
    keyEdit_ = new QLineEdit;
    keyEdit_->setPlaceholderText("Text name (max 32 bytes UTF-8)");
    layout->addWidget(keyEdit_);
    connect(keyHexCheck_, &QCheckBox::toggled, this, [this](bool hex) {
      keyEdit_->setPlaceholderText(hex
        ? "Hex bytes, e.g. 48656C6C6F (max 64 hex chars = 32 bytes)"
        : "Text name (max 32 bytes UTF-8)");
      updatePreview();
    });

    // --- Content ---
    auto* contentLabelRow = new QHBoxLayout;
    contentLabelRow->addWidget(new QLabel("Content:"));
    contentHexCheck_ = new QCheckBox("Binary input (hex, e.g. FFA01032)");
    contentLabelRow->addWidget(contentHexCheck_);
    contentLabelRow->addStretch();
    layout->addLayout(contentLabelRow);
    contentEdit_ = new QPlainTextEdit;
    contentEdit_->setPlaceholderText("Text content (max 210 bytes UTF-8)");
    contentEdit_->setFixedHeight(80);
    contentEdit_->setLineWrapMode(QPlainTextEdit::WidgetWidth);
    contentEdit_->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
    contentEdit_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    contentEdit_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
    layout->addWidget(contentEdit_);
    connect(contentHexCheck_, &QCheckBox::toggled, this, [this](bool hex) {
      contentEdit_->setPlaceholderText(hex
        ? "Hex bytes, e.g. 48656C6C6F (max 420 hex chars = 210 bytes)"
        : "Text content (max 210 bytes UTF-8)");
      contentEdit_->viewport()->repaint();
      updatePreview();
    });

    // --- Days + Create ---
    auto* actionRow = new QHBoxLayout;
    actionRow->addWidget(new QLabel("Prepaid days:"));
    daysSpin_ = new QSpinBox;
    daysSpin_->setRange(1, 65535);
    daysSpin_->setValue(30);
    actionRow->addWidget(daysSpin_);
    actionRow->addSpacing(16);
    createBtn_ = new QPushButton("Create Asset");
    createBtn_->setStyleSheet(
      "QPushButton { padding: 6px 20px; font-weight: bold; }");
    connect(createBtn_, &QPushButton::clicked,
      this, &CreateAssetWidget::onCreate);
    actionRow->addWidget(createBtn_);
    actionRow->addStretch();
    layout->addLayout(actionRow);

    // --- Status ---
    statusLabel_ = new QLabel("");
    statusLabel_->setStyleSheet("font-style: italic; color: #6b7b8d;");
    statusLabel_->setWordWrap(true);
    layout->addWidget(statusLabel_);

    // --- Live binary preview ---
    previewEdit_ = new QPlainTextEdit;
    previewEdit_->setReadOnly(true);
    previewEdit_->setFont(QFont("monospace", 9));
    previewEdit_->setMinimumHeight(160);
    previewEdit_->setLineWrapMode(QPlainTextEdit::WidgetWidth);
    previewEdit_->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
    previewEdit_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    previewEdit_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    previewEdit_->setPlainText("Live Preview");
    layout->addWidget(previewEdit_);

    // Connect live preview
    connect(keyEdit_, &QLineEdit::textChanged,
      this, &CreateAssetWidget::updatePreview);
    connect(contentEdit_, &QPlainTextEdit::textChanged,
      this, &CreateAssetWidget::updatePreview);

    refreshKeyList();
    refreshServerList();
  }

public slots:
  void refreshKeyList() {
    keyCombo_->blockSignals(true);
    keyCombo_->clear();
    auto& w = keyManager_.wallet();
    for (int i = 0; i < w.size(); ++i) {
      auto kp = w.keyPair(i);
      keyCombo_->addItem(formatKeyLabel(i, kp, w.label(i)), i);
    }
    if (!w.empty()) {
      int sel = std::clamp(config_.defaultAccount, 0, w.size() - 1);
      keyCombo_->setCurrentIndex(sel);
    }
    keyCombo_->blockSignals(false);
  }

  void refreshServerList() {
    serverCombo_->blockSignals(true);
    serverCombo_->clear();
    for (auto& s : config_.servers)
      serverCombo_->addItem(s);
    // Select current server if present
    if (!config_.currentServer.isEmpty()) {
      int idx = config_.servers.indexOf(config_.currentServer);
      if (idx >= 0) serverCombo_->setCurrentIndex(idx);
    }
    serverCombo_->blockSignals(false);
  }

signals:
  void statusMessage(const QString& msg, int timeout);
  void assetCreated(const QString& assetKey, const QString& server);

private slots:
  void updatePreview() {
    QString text;
    text += formatFieldPreview(keyEdit_->text(), 32, keyHexCheck_->isChecked(), "Asset Key");
    text += "\n";
    text += formatFieldPreview(contentEdit_->toPlainText(), 210, contentHexCheck_->isChecked(), "Content");
    previewEdit_->setPlainText(text);
  }

  void onCreate() {
    QString keyStr = keyEdit_->text().trimmed();
    QString contentStr = contentEdit_->toPlainText().trimmed();
    if (keyStr.isEmpty()) { setStatus("Enter asset key.", "#f44747"); return; }
    if (contentStr.isEmpty()) { setStatus("Enter content.", "#f44747"); return; }
    if (busy_) return;

    if (serverCombo_->count() == 0) {
      setStatus("No servers configured. Add servers in the Servers tab.", "#f44747");
      return;
    }
    QString server = serverCombo_->currentText();

    auto& w = keyManager_.wallet();
    if (w.empty()) {
      setStatus("No keys in wallet.", "#f44747");
      return;
    }
    int idx = keyCombo_->currentData().toInt();
    if (idx < 0 || idx >= w.size()) return;
    ces::KeyPair kp = w.keyPair(idx);

    ces::AssetData content{};
    minx::Hash keyBytes{};
    try {
      if (keyHexCheck_->isChecked()) {
        QString cleaned = keyStr;
        cleaned.remove(' ');
        QByteArray raw = QByteArray::fromHex(cleaned.toLatin1());
        if (raw.size() > 32) throw std::runtime_error("Key hex too long (max 32 bytes)");
        memcpy(keyBytes.data(), raw.data(), raw.size());
      } else {
        QByteArray utf8 = keyStr.toUtf8();
        if (utf8.size() > 32) throw std::runtime_error("Key text too long (max 32 bytes)");
        memcpy(keyBytes.data(), utf8.data(), utf8.size());
      }
      if (contentHexCheck_->isChecked()) {
        QString cleaned = contentStr;
        cleaned.remove(' ');
        QByteArray raw = QByteArray::fromHex(cleaned.toLatin1());
        if (raw.size() > 210) throw std::runtime_error("Content hex too long (max 210 bytes)");
        memcpy(content.data(), raw.data(), raw.size());
      } else {
        QByteArray utf8 = contentStr.toUtf8();
        if (utf8.size() > 210) throw std::runtime_error("Content text too long (max 210 bytes)");
        memcpy(content.data(), utf8.data(), utf8.size());
      }
    } catch (std::exception& e) {
      setStatus(QString("Parse error: %1").arg(e.what()), "#f44747");
      return;
    }
    QString assetKeyHex = QString::fromStdString(minx::hashToString(keyBytes));

    busy_ = true;
    setStatus("Creating asset...", "#dcdcaa");
    log(QString("Creating asset %1@%2 (%3 days)")
      .arg(assetKeyHex.left(16) + "...").arg(server)
      .arg(daysSpin_->value()));

    auto* worker = new AssetActionWorker(
      AssetActionWorker::Create, server, kp, assetKeyHex, this);
    worker->setContent(content);
    worker->setDays(static_cast<uint16_t>(daysSpin_->value()));
    connect(worker, &AssetActionWorker::actionResult,
      this, [this, assetKeyHex, server](bool ok, uint8_t, QString error) {
        busy_ = false;
        if (ok) {
          setStatus("Asset created!", "#4ec9b0");
          log("Created asset: " + assetKeyHex + "@" + server);
          TrackedAsset ta;
          ta.assetKey = assetKeyHex;
          ta.server = server;
          config_.addTrackedAsset(ta);
          emit assetCreated(assetKeyHex, server);
        } else {
          setStatus("Create failed: " + error, "#f44747");
          log("Create failed: " + error);
        }
      });
    connect(worker, &QThread::finished, worker, &QObject::deleteLater);
    worker->start();
  }

private:
  const KeyManagerWidget& keyManager_;
  AppConfig& config_;
  ConsoleWidget* console_ = nullptr;

  QComboBox* serverCombo_ = nullptr;
  QComboBox* keyCombo_ = nullptr;
  QCheckBox* keyHexCheck_ = nullptr;
  QLineEdit* keyEdit_ = nullptr;
  QCheckBox* contentHexCheck_ = nullptr;
  QPlainTextEdit* contentEdit_ = nullptr;
  QSpinBox* daysSpin_ = nullptr;
  QPushButton* createBtn_ = nullptr;
  QLabel* statusLabel_ = nullptr;

  QPlainTextEdit* previewEdit_ = nullptr;

  bool busy_ = false;

  void setStatus(const QString& msg, const char* color) {
    statusLabel_->setText(msg);
    statusLabel_->setStyleSheet(
      QString("font-style: italic; color: %1;").arg(color));
  }

  void log(const QString& msg) {
    if (console_) console_->appendLog(msg);
  }


  static QString bytesToHexSpaced(const QByteArray& bytes) {
    QString result;
    for (int i = 0; i < bytes.size(); ++i) {
      if (i > 0) result += ' ';
      result += QString("%1").arg(
        static_cast<uint8_t>(bytes[i]), 2, 16, QChar('0')).toUpper();
    }
    return result;
  }

  static QString tryUtf8Render(const QByteArray& bytes) {
    // Find length (up to first zero)
    int len = 0;
    for (int i = 0; i < bytes.size(); ++i) {
      if (bytes[i] == 0) break;
      len++;
    }
    if (len == 0) return "(empty)";
    QByteArray active = bytes.left(len);
    // Check valid UTF-8
    auto codec = QStringDecoder(QStringDecoder::Utf8);
    QString decoded = codec(active);
    if (codec.hasError())
      return "(invalid UTF-8)";
    // Escape control chars for display
    QString display;
    for (QChar c : decoded) {
      if (c == '\n') display += "\xe2\x90\x8a";       // ␊
      else if (c == '\r') display += "\xe2\x90\x8d";   // ␍
      else if (c == '\t') display += "\xe2\x90\x89";   // ␉
      else if (c == ' ') display += "\xe2\x90\xa3";    // ␣
      else if (c.unicode() < 32) display += "\xef\xbf\xbd"; // replacement
      else display += c;
    }
    return display;
  }

  QString formatFieldPreview(const QString& input, int fieldSize, bool hexMode,
                             const char* name) {
    if (input.isEmpty())
      return QString("%1 (0/%2 bytes):\n  UTF-8: (empty)\n  Binary: (empty)").arg(name).arg(fieldSize);

    QByteArray bytes(fieldSize, '\0');
    int activeLen = 0;

    if (hexMode) {
      QString cleaned = input;
      cleaned.remove(' ');
      if (cleaned.size() % 2 != 0)
        return QString("%1 (? /%2 bytes — odd hex length)").arg(name).arg(fieldSize);
      QByteArray raw = QByteArray::fromHex(cleaned.toLatin1());
      if (raw.size() > fieldSize)
        return QString("%1 (%2/%3 bytes — too long!)").arg(name).arg(raw.size()).arg(fieldSize);
      memcpy(bytes.data(), raw.data(), raw.size());
      activeLen = raw.size();
    } else {
      QByteArray utf8 = input.toUtf8();
      if (utf8.size() > fieldSize)
        return QString("%1 (%2/%3 bytes — too long!)").arg(name).arg(utf8.size()).arg(fieldSize);
      memcpy(bytes.data(), utf8.data(), utf8.size());
      activeLen = utf8.size();
    }

    return QString("%1 (%2/%3 bytes):\n  UTF-8: %4\n  Binary: %5")
      .arg(name).arg(activeLen).arg(fieldSize)
      .arg(tryUtf8Render(bytes))
      .arg(bytesToHexSpaced(bytes));
  }
};

// =============================================================================
// MarketplaceWidget — query and buy assets
// =============================================================================

class MarketplaceWidget : public QWidget {
  Q_OBJECT
public:
  explicit MarketplaceWidget(const KeyManagerWidget& keyManager,
                             AppConfig& config, ConsoleWidget* console,
                             QWidget* parent = nullptr)
    : QWidget(parent), keyManager_(keyManager), config_(config),
      console_(console) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(12, 12, 12, 12);
    layout->setSpacing(8);

    // --- Query section ---
    auto* queryRow = new QHBoxLayout;
    queryRow->addWidget(new QLabel("Asset ID:"));
    idEdit_ = new QLineEdit;
    idEdit_->setPlaceholderText("key@server or key (uses current server)");
    queryRow->addWidget(idEdit_);
    queryBtn_ = new QPushButton("Query");
    connect(queryBtn_, &QPushButton::clicked,
      this, &MarketplaceWidget::onQuery);
    queryRow->addWidget(queryBtn_);
    layout->addLayout(queryRow);

    // --- Result display ---
    auto* resultGroup = new QGroupBox("Result");
    auto* resultLayout = new QVBoxLayout(resultGroup);
    resultLayout->setSpacing(4);

    resultKey_ = new QLabel("Key: —");
    resultContent_ = new QLabel("Content: —");
    resultContent_->setWordWrap(true);
    resultOwner_ = new QLabel("Owner: —");
    resultDays_ = new QLabel("Days left: —");
    resultPrice_ = new QLabel("Price: —");

    resultLayout->addWidget(resultKey_);
    resultLayout->addWidget(resultContent_);
    resultLayout->addWidget(resultOwner_);
    resultLayout->addWidget(resultDays_);
    resultLayout->addWidget(resultPrice_);
    layout->addWidget(resultGroup);

    // --- Buy section ---
    auto* buyRow = new QHBoxLayout;
    buyRow->addWidget(new QLabel("Buy:"));
    buyRow->addWidget(new QLabel("Max price:"));
    buyAmountEdit_ = new QLineEdit;
    buyAmountEdit_->setPlaceholderText("Whole credits (integer, >= asking price)");
    buyAmountEdit_->setMaximumWidth(400);
    buyRow->addWidget(buyAmountEdit_);
    buyBtn_ = new QPushButton("Buy Asset");
    connect(buyBtn_, &QPushButton::clicked,
      this, &MarketplaceWidget::onBuy);
    buyRow->addWidget(buyBtn_);
    buyRow->addStretch();

    auto* trackBtn = new QPushButton("Track This");
    trackBtn->setToolTip("Add this asset to your tracked assets list");
    connect(trackBtn, &QPushButton::clicked,
      this, &MarketplaceWidget::onTrack);
    buyRow->addWidget(trackBtn);

    layout->addLayout(buyRow);

    // --- Account selector for buying ---
    auto* accountRow = new QHBoxLayout;
    accountRow->addWidget(new QLabel("Buy with account:"));
    keyCombo_ = new KeyComboBox;
    keyCombo_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    accountRow->addWidget(keyCombo_);
    layout->addLayout(accountRow);

    // Status
    statusLabel_ = new QLabel("");
    statusLabel_->setStyleSheet("font-style: italic; color: #6b7b8d;");
    statusLabel_->setWordWrap(true);
    layout->addWidget(statusLabel_);

    layout->addStretch();
    refreshKeyList();
  }

public slots:
  void refreshKeyList() {
    keyCombo_->clear();
    auto& w = keyManager_.wallet();
    for (int i = 0; i < w.size(); ++i) {
      auto kp = w.keyPair(i);
      keyCombo_->addItem(formatKeyLabel(i, kp, w.label(i)), i);
    }
  }

signals:
  void statusMessage(const QString& msg, int timeout);
  void assetBought(const QString& assetKey, const QString& server);

private slots:
  void onQuery() {
    if (busy_) return;
    QString input = idEdit_->text().trimmed();
    if (input.isEmpty()) { setStatus("Enter asset ID.", "#f44747"); return; }

    parseAssetId(input);
    if (lastServer_.isEmpty()) {
      setStatus("No server specified and no default set.", "#f44747");
      return;
    }

    busy_ = true;
    queryBtn_->setEnabled(false);
    setStatus("Querying...", "#dcdcaa");
    log("Market query: " + lastAssetKey_ + "@" + lastServer_);

    auto* worker = new AssetUnsignedQueryWorker(
      lastServer_, lastAssetKey_, this);
    connect(worker, &AssetUnsignedQueryWorker::queryResult,
      this, &MarketplaceWidget::onQueryResult);
    connect(worker, &QThread::finished, worker, &QObject::deleteLater);
    worker->start();
  }

  void onQueryResult(bool ok, QString owner, QString contentHex,
                     uint16_t days, uint32_t storedPrice, QString error) {
    busy_ = false;
    queryBtn_->setEnabled(true);

    if (!ok) {
      resultKey_->setText("Key: —");
      resultContent_->setText("Content: —");
      resultOwner_->setText("Owner: —");
      resultDays_->setText("Days left: —");
      resultPrice_->setText("Price: —");
      // Clear stale data so Track/Buy can't use previous query's results
      lastOwner_.clear();
      lastContentHex_.clear();
      lastDays_ = 0;
      lastStoredPrice_ = 0;
      setStatus("Query failed: " + error, "#f44747");
      log("Market query failed: " + lastAssetKey_ + " — " + error);
      return;
    }

    lastOwner_ = owner;
    lastDays_ = days;
    lastStoredPrice_ = storedPrice;
    lastContentHex_ = contentHex;

    // Key display (text if printable ASCII, else hex)
    TrackedAsset tmp;
    tmp.assetKey = lastAssetKey_;
    tmp.contentHex = contentHex;
    resultKey_->setText("Key: " + tmp.keyDisplay());
    resultContent_->setText("Content: " + tmp.contentDisplay());
    resultOwner_->setText("Owner: " + owner);
    resultDays_->setText(QString("Days left: %1").arg(days));
    QString priceStr;
    if (storedPrice == 0) {
      priceStr = "not for sale";
      resultPrice_->setText("Price: not for sale");
    } else {
      priceStr = QString("%1 credits").arg(storedPrice);
      resultPrice_->setText("Price: " + priceStr);
      buyAmountEdit_->setText(QString::number(storedPrice));
    }

    setStatus("Query OK.", "#4ec9b0");
    log(QString("Market query: %1 | owner %2 | %3 days | %4")
      .arg(tmp.keyDisplay()).arg(owner.left(16) + "...")
      .arg(days).arg(priceStr));
  }

  void onBuy() {
    if (busy_) return;
    if (lastAssetKey_.isEmpty()) {
      setStatus("Query an asset first.", "#f44747");
      return;
    }
    if (lastStoredPrice_ == 0) {
      setStatus("Asset is not for sale.", "#f44747");
      return;
    }

    bool ok;
    uint64_t wholeCredits = buyAmountEdit_->text().trimmed().toULongLong(&ok);
    if (!ok || wholeCredits == 0) {
      setStatus("Invalid buy amount.", "#f44747");
      return;
    }
    if (wholeCredits > UINT64_MAX / ces::PRICE_UNIT) {
      setStatus("Buy amount too large.", "#f44747");
      return;
    }
    uint64_t amount = wholeCredits * ces::PRICE_UNIT;

    auto& w = keyManager_.wallet();
    if (w.empty()) { setStatus("No keys in wallet.", "#f44747"); return; }
    int kidx = keyCombo_->currentData().toInt();
    ces::KeyPair kp = w.keyPair(kidx);

    busy_ = true;
    buyBtn_->setEnabled(false);
    setStatus("Buying asset...", "#dcdcaa");
    log(QString("Buying asset %1@%2 for %3 credits")
      .arg(lastAssetKey_.left(16) + "...").arg(lastServer_).arg(wholeCredits));

    auto* worker = new AssetActionWorker(
      AssetActionWorker::Buy, lastServer_, kp, lastAssetKey_, this);
    worker->setBuyAmount(amount);
    connect(worker, &AssetActionWorker::actionResult,
      this, [this](bool ok2, uint8_t, QString error) {
        busy_ = false;
        buyBtn_->setEnabled(true);
        if (ok2) {
          setStatus("Purchase successful!", "#4ec9b0");
          log("Bought asset: " + lastAssetKey_ + "@" + lastServer_);
          // Auto-track
          TrackedAsset ta;
          ta.assetKey = lastAssetKey_;
          ta.server = lastServer_;
          config_.addTrackedAsset(ta);
          emit assetBought(lastAssetKey_, lastServer_);
          // Re-query to see new ownership
          QTimer::singleShot(200, this, &MarketplaceWidget::onQuery);
        } else {
          setStatus("Buy failed: " + error, "#f44747");
          log("Buy failed: " + error);
        }
      });
    connect(worker, &QThread::finished, worker, &QObject::deleteLater);
    worker->start();
  }

  void onTrack() {
    if (lastAssetKey_.isEmpty() || lastServer_.isEmpty()) {
      setStatus("Query an asset first.", "#f44747");
      return;
    }
    if (config_.findTrackedAsset(lastAssetKey_, lastServer_) >= 0) {
      setStatus("Already tracking this asset.", "#dcdcaa");
      return;
    }
    TrackedAsset ta;
    ta.assetKey = lastAssetKey_;
    ta.server = lastServer_;
    // Store last query result if we have one
    if (!lastOwner_.isEmpty()) {
      ta.known = true;
      ta.owner = lastOwner_;
      ta.contentHex = lastContentHex_;
      ta.days = lastDays_;
      ta.storedPrice = lastStoredPrice_;
      ta.lastQueryTime = QDateTime::currentDateTime().toString(Qt::ISODate);
    }
    config_.addTrackedAsset(ta);
    setStatus("Now tracking: " + ta.fullId(), "#4ec9b0");
    log("Tracking asset from marketplace: " + ta.fullId());
    emit assetBought(lastAssetKey_, lastServer_); // reuse signal to refresh Assets tab
  }

private:
  void parseAssetId(const QString& input) {
    int atPos = input.lastIndexOf('@');
    if (atPos > 0) {
      QString keyPart = input.left(atPos);
      lastServer_ = input.mid(atPos + 1);
      try {
        auto parsed = ces::parseAssetKey(keyPart.toStdString());
        lastAssetKey_ = QString::fromStdString(minx::hashToString(parsed));
      } catch (...) {
        lastAssetKey_ = keyPart;
      }
    } else {
      lastServer_ = config_.currentServer;
      try {
        auto parsed = ces::parseAssetKey(input.toStdString());
        lastAssetKey_ = QString::fromStdString(minx::hashToString(parsed));
      } catch (...) {
        lastAssetKey_ = input;
      }
    }
  }

  void setStatus(const QString& msg, const char* color) {
    statusLabel_->setText(msg);
    statusLabel_->setStyleSheet(
      QString("font-style: italic; color: %1;").arg(color));
  }

  void log(const QString& msg) {
    if (console_) console_->appendLog(msg);
  }

  const KeyManagerWidget& keyManager_;
  AppConfig& config_;
  ConsoleWidget* console_ = nullptr;

  QLineEdit* idEdit_ = nullptr;
  QPushButton* queryBtn_ = nullptr;
  QPushButton* buyBtn_ = nullptr;
  QLabel* resultKey_ = nullptr;
  QLabel* resultContent_ = nullptr;
  QLabel* resultOwner_ = nullptr;
  QLabel* resultDays_ = nullptr;
  QLabel* resultPrice_ = nullptr;
  QLineEdit* buyAmountEdit_ = nullptr;
  QComboBox* keyCombo_ = nullptr;
  QLabel* statusLabel_ = nullptr;

  bool busy_ = false;
  QString lastAssetKey_;
  QString lastServer_;
  QString lastOwner_;
  QString lastContentHex_;
  uint16_t lastDays_ = 0;
  uint32_t lastStoredPrice_ = 0;
};

// =============================================================================
// MainWindow — tabbed container
// =============================================================================
// AboutWidget is in about.h

// =============================================================================

class MainWindow : public QMainWindow {
  Q_OBJECT
public:
  #include "mainwindow_api.inc"

  MainWindow(const QString& dataDirOverride = {},
             uint16_t rpcPortOverride = 0,
             bool autoApprove = false)
    : autoApprove_(autoApprove) {
    resize(900, 520);

    // Console tab (created first so others can log during init)
    console_ = new ConsoleWidget;
    console_->appendLog("CES Wallet starting...");

    // About tab
    aboutWidget_ = new AboutWidget;

    // Load config
    if (!dataDirOverride.isEmpty())
      config_.dataDirOverride = dataDirOverride;
    console_->appendLog("Config: " + config_.configPath());
    config_.load();
    if (config_.servers.isEmpty()) {
      console_->appendLog("No servers configured.");
    } else {
      console_->appendLog(QString("%1 server(s) in address book.").arg(config_.servers.size()));
    }
    if (!config_.currentServer.isEmpty()) {
      console_->appendLog("Current server: " + config_.currentServer);
    }

    // Key manager tab
    keyManager_ = new KeyManagerWidget(console_, config_);
    connect(keyManager_, &KeyManagerWidget::statusMessage,
      this, [this](const QString& msg, int timeout) {
        statusBar()->showMessage(msg, timeout);
      });

    // Account tab (main view)
    accountWidget_ = new AccountWidget(*keyManager_, config_, console_);
    connect(keyManager_, &KeyManagerWidget::walletChanged,
      accountWidget_, &AccountWidget::refreshKeyList);
    connect(accountWidget_, &AccountWidget::statusMessage,
      this, [this](const QString& msg, int timeout) {
        statusBar()->showMessage(msg, timeout);
      });
    connect(accountWidget_, &AccountWidget::balanceUpdated,
      this, [this](int /*accountIndex*/, int64_t /*balance*/) {
        // Account tab queried fresh data — refresh Wallet aggregate
        walletWidget_->queryAllFull();
      });

    // Wallet tab (aggregate balance view)
    walletWidget_ = new WalletWidget(*keyManager_, config_, console_);
    connect(keyManager_, &KeyManagerWidget::walletChanged,
      walletWidget_, &WalletWidget::refreshKeyList);

    // Mining tab
    miningWidget_ = new MiningWidget(*keyManager_, config_, console_);
    connect(keyManager_, &KeyManagerWidget::walletChanged,
      miningWidget_, &MiningWidget::refreshKeyList);
    connect(miningWidget_, &MiningWidget::statusMessage,
      this, [this](const QString& msg, int timeout) {
        statusBar()->showMessage(msg, timeout);
      });
    connect(miningWidget_, &MiningWidget::creditEarned,
      this, [this](int accountIndex, uint64_t credit) {
        if (accountIndex >= 0 &&
            accountIndex == accountWidget_->selectedAccountIndex())
          accountWidget_->addCredit(credit);
        // Also update the wallet aggregate view (total + per-key table)
        walletWidget_->addCredit(accountIndex, credit);
      });

    // Transfer tab
    transferWidget_ = new TransferWidget(*keyManager_, config_, console_);
    transferWidget_->setWalletWidget(walletWidget_);
    connect(keyManager_, &KeyManagerWidget::walletChanged,
      transferWidget_, &TransferWidget::refreshKeyList);
    connect(walletWidget_, &WalletWidget::walletQueryDone,
      this, [this](int64_t, int) { transferWidget_->updateInfoLabels(); });
    connect(transferWidget_, &TransferWidget::statusMessage,
      this, [this](const QString& msg, int timeout) {
        statusBar()->showMessage(msg, timeout);
      });
    connect(transferWidget_, &TransferWidget::transferCompleted,
      this, [this](int accountIndex, int64_t newBalance) {
        // Update account tab if viewing the same account
        if (accountIndex >= 0 &&
            accountIndex == accountWidget_->selectedAccountIndex()) {
          accountWidget_->setBalance(newBalance);
        }
        // Trigger wallet refresh to update aggregate
        walletWidget_->queryAllFull();
      });

    // Create Asset tab
    createAssetWidget_ = new CreateAssetWidget(*keyManager_, config_, console_);
    connect(keyManager_, &KeyManagerWidget::walletChanged,
      createAssetWidget_, &CreateAssetWidget::refreshKeyList);
    connect(createAssetWidget_, &CreateAssetWidget::statusMessage,
      this, [this](const QString& msg, int timeout) {
        statusBar()->showMessage(msg, timeout);
      });
    connect(createAssetWidget_, &CreateAssetWidget::assetCreated,
      this, [this](const QString&, const QString&) {
        assetsWidget_->refreshAssetList();
      });

    // Assets tab
    assetsWidget_ = new AssetsWidget(*keyManager_, config_, console_);
    connect(assetsWidget_, &AssetsWidget::statusMessage,
      this, [this](const QString& msg, int timeout) {
        statusBar()->showMessage(msg, timeout);
      });

    // Marketplace tab
    marketplaceWidget_ = new MarketplaceWidget(*keyManager_, config_, console_);
    connect(keyManager_, &KeyManagerWidget::walletChanged,
      marketplaceWidget_, &MarketplaceWidget::refreshKeyList);
    connect(marketplaceWidget_, &MarketplaceWidget::statusMessage,
      this, [this](const QString& msg, int timeout) {
        statusBar()->showMessage(msg, timeout);
      });
    // When marketplace tracks/buys an asset, refresh the Assets tab
    connect(marketplaceWidget_, &MarketplaceWidget::assetBought,
      this, [this](const QString&, const QString&) {
        assetsWidget_->refreshAssetList();
      });

    // Server manager tab
    serverManager_ = new ServerManagerWidget(*keyManager_, config_, console_);
    connect(serverManager_, &ServerManagerWidget::statusMessage,
      this, [this](const QString& msg, int timeout) {
        statusBar()->showMessage(msg, timeout);
      });
    connect(serverManager_, &ServerManagerWidget::serverListChanged,
      createAssetWidget_, &CreateAssetWidget::refreshServerList);

    // Tree-on-left navigation + stacked-pages on the right. Replaces
    // the flat tab strip — categories group naturally and there's room
    // to grow without a multi-row hack. Top-level items that have
    // children get a placeholder summary page for now; we'll fill them
    // in as features land.
    auto* nav = new QTreeWidget;
    nav->setHeaderHidden(true);
    nav->setIndentation(18);
    nav->setUniformRowHeights(true);
    nav->setFrameShape(QFrame::NoFrame);
    {
      // Slightly larger font than the page body — sidebar labels
      // are scan-targets, not body text.
      QFont f = nav->font();
      f.setPointSize(f.pointSize() + 2);
      nav->setFont(f);
    }
    // Tabbed-sidebar look: the tree sits on a dark bg (terminal-ish);
    // the selected row paints in the chrome color so it visually
    // bleeds into the page area to its right — like a tab connecting
    // to its content panel. Bold-on-selection adds a second cue;
    // ::item padding gives the vertical breathing room well-designed
    // sidebars (VS Code, IDEs, settings dialogs) all share.
    nav->setStyleSheet(
      "QTreeWidget { "
      "  background: #1e1e1e; "
      "  color: #d0d0d0; "
      "  outline: none; "
      "}"
      "QTreeWidget::item { padding: 6px 4px; }"
      "QTreeWidget::item:selected { "
      "  background: palette(window); "
      "  color: palette(window-text); "
      "}");
    auto* pages = new QStackedWidget;

    auto bindPage = [pages](QTreeWidgetItem* item, QWidget* w) {
      int idx = pages->addWidget(w);
      item->setData(0, Qt::UserRole, idx);
    };
    auto helpPage = [](const QString& title, const QString& body) {
      auto* w = new QWidget;
      auto* lay = new QVBoxLayout(w);
      lay->addStretch();
      auto* lbl = new QLabel(QStringLiteral(
        "<h2>%1</h2><p>%2</p>").arg(title, body));
      lbl->setAlignment(Qt::AlignCenter);
      lbl->setWordWrap(true);
      lay->addWidget(lbl);
      lay->addStretch();
      return w;
    };

    auto* walletTop = new QTreeWidgetItem(nav, QStringList{"Wallet"});
    bindPage(walletTop, helpPage("Wallet",
      "Accounts, transfers, and keys."));
    {
      auto* it = new QTreeWidgetItem(walletTop, QStringList{"Overview"});
      bindPage(it, walletWidget_);
      it = new QTreeWidgetItem(walletTop, QStringList{"Account"});
      bindPage(it, accountWidget_);
      it = new QTreeWidgetItem(walletTop, QStringList{"Transfer"});
      bindPage(it, transferWidget_);
      it = new QTreeWidgetItem(walletTop, QStringList{"Keys"});
      bindPage(it, keyManager_);
    }

    auto* mining = new QTreeWidgetItem(nav, QStringList{"Mining"});
    bindPage(mining, miningWidget_);

    auto* assetsTop = new QTreeWidgetItem(nav, QStringList{"Assets"});
    bindPage(assetsTop, helpPage("Assets",
      "Create, fund, browse, and trade assets on the current server."));
    {
      auto* it = new QTreeWidgetItem(assetsTop, QStringList{"Create"});
      bindPage(it, createAssetWidget_);
      it = new QTreeWidgetItem(assetsTop, QStringList{"Browse"});
      bindPage(it, assetsWidget_);
      it = new QTreeWidgetItem(assetsTop, QStringList{"Market"});
      bindPage(it, marketplaceWidget_);
    }

    auto* servers = new QTreeWidgetItem(nav, QStringList{"Servers"});
    bindPage(servers, serverManager_);

    auto* consoleItem = new QTreeWidgetItem(nav, QStringList{"Console"});
    bindPage(consoleItem, console_);

    auto* about = new QTreeWidgetItem(nav, QStringList{"About"});
    bindPage(about, aboutWidget_);

    nav->expandAll();

    connect(nav, &QTreeWidget::currentItemChanged, pages,
      [pages](QTreeWidgetItem* cur, QTreeWidgetItem* prev) {
        // Page switch.
        if (cur) {
          bool ok = false;
          int idx = cur->data(0, Qt::UserRole).toInt(&ok);
          if (ok) pages->setCurrentIndex(idx);
        }
        // Bold-on-selection — the only visual indicator since the
        // selection bg matches the chrome.
        auto setBold = [](QTreeWidgetItem* it, bool b) {
          if (!it) return;
          QFont f = it->font(0);
          f.setBold(b);
          it->setFont(0, f);
        };
        setBold(prev, false);
        setBold(cur, true);
      });

    // If the user collapses a parent whose descendant is currently
    // selected, the selection rectangle would disappear into the
    // collapsed branch. Promote the current selection to the collapsed
    // parent so the visual cue stays visible (and the page swaps to
    // the parent's summary page).
    connect(nav, &QTreeWidget::itemCollapsed, nav,
      [nav](QTreeWidgetItem* collapsed) {
        QTreeWidgetItem* cur = nav->currentItem();
        if (!cur) return;
        for (auto* p = cur->parent(); p; p = p->parent()) {
          if (p == collapsed) {
            nav->setCurrentItem(collapsed);
            return;
          }
        }
      });

    // Pin the nav to the widest label + indentation chrome + 20 px
    // breathing room. No splitter — categories don't need to be
    // resizable, and pages get all the leftover space. Measure with
    // bold metrics so the selected (bolded) item still fits.
    {
      QFont boldFont = nav->font();
      boldFont.setBold(true);
      QFontMetrics fm(boldFont);
      int widest = 0;
      std::function<void(QTreeWidgetItem*, int)> walk =
        [&](QTreeWidgetItem* it, int depth) {
          int w = fm.horizontalAdvance(it->text(0))
                  + depth * nav->indentation();
          widest = std::max(widest, w);
          for (int i = 0; i < it->childCount(); ++i)
            walk(it->child(i), depth + 1);
        };
      for (int i = 0; i < nav->topLevelItemCount(); ++i)
        walk(nav->topLevelItem(i), 0);
      nav->setFixedWidth(widest + nav->indentation() + 30);
    }

    // Set the initial selection AFTER the signal is wired so the
    // bold-on-selection handler fires for the first item too.
    nav->setCurrentItem(walletTop);

    // Wrap the tree in a dark-bg column with 6 px top/bottom padding
    // so the topmost selected item doesn't butt directly against the
    // (whiteish) window title bar — without that gap, selecting
    // "Wallet" reads as if it's activating the title chrome itself.
    auto* navColumn = new QWidget;
    navColumn->setFixedWidth(nav->width());
    navColumn->setStyleSheet("background: #1e1e1e;");
    navColumn->setAutoFillBackground(true);
    auto* navLayout = new QVBoxLayout(navColumn);
    navLayout->setContentsMargins(0, 6, 0, 6);
    navLayout->setSpacing(0);
    navLayout->addWidget(nav);

    auto* central = new QWidget;
    auto* row = new QHBoxLayout(central);
    row->setContentsMargins(0, 0, 0, 0);
    row->setSpacing(0);
    row->addWidget(navColumn);
    row->addWidget(pages, 1);
    setCentralWidget(central);

    // Ctrl+Q bypasses the close-to-tray behavior and quits outright —
    // standard Linux GUI quit chord, no conflict with copy/paste.
    auto* quitShortcut = new QShortcut(QKeySequence("Ctrl+Q"), this);
    quitShortcut->setContext(Qt::ApplicationShortcut);
    connect(quitShortcut, &QShortcut::activated,
            qApp, &QApplication::quit);

    // Wire console to app API
    console_->setApp(this);

    // Dynamic tab completion: complete the last word if it starts with @
    console_->input()->setDynamicCompleter([this](const QString& input) -> QStringList {
      // Find the last word being typed
      int lastSpace = input.lastIndexOf(' ');
      QString lastWord = (lastSpace >= 0) ? input.mid(lastSpace + 1) : input;
      QString beforeLast = (lastSpace >= 0) ? input.left(lastSpace + 1) : "";

      if (!lastWord.startsWith("@")) return {};

      QStringList results;
      auto& w = keyManager_->wallet();
      for (int i = 0; i < w.size(); ++i) {
        QString candidate = QString("@%1").arg(i);
        if (candidate.startsWith(lastWord))
          results << (beforeLast + candidate);
      }
      return results;
    });

    updateWindowTitle();
    connect(serverManager_, &ServerManagerWidget::serverListChanged,
      this, &MainWindow::updateWindowTitle);

    // Auto-ping all servers once the event loop starts
    QTimer::singleShot(0, serverManager_, &ServerManagerWidget::pingAll);

    // Auto-mine once for fresh wallets
    if (keyManager_->didGenerateDefaultKey() && !config_.currentServer.isEmpty()) {
      QTimer::singleShot(cesqt_timing::kAutoMineStartDelayMs, this, [this]() {
        miningWidget_->autoMineOnce();
      });
    }

    // Start RPC server for browser wallet integration
    RpcWalletBridge bridge;
    bridge.findByLabel = [this](const std::string& l) {
      return keyManager_->wallet().findByLabel(l);
    };
    bridge.generateKey = [this](const std::string& l) {
      return keyManager_->wallet().generate(1, ces::KeyAlgo::ED25519, l);
    };
    bridge.keyPair = [this](int i) { return keyManager_->wallet().keyPair(i); };
    bridge.pubKeyHex = [this](int i) {
      return keyManager_->wallet().keyPair(i).getPublicKeyHexStr();
    };
    bridge.label = [this](int i) { return keyManager_->wallet().label(i); };
    bridge.saveAndRefresh = [this]() { keyManager_->saveAndRefresh(); };
    bridge.getAccounts = [this]() -> QList<CachedAccount> {
      QList<CachedAccount> result;
      for (auto& a : walletWidget_->getAccounts())
        result.append({a.index, a.balance, a.exists});
      return result;
    };
    bridge.currentServer = [this]() { return config_.currentServer; };
    rpcServer_ = new RpcServer(std::move(bridge), console_, autoApprove_, this);
    rpcServer_->start(rpcPortOverride ? rpcPortOverride
                                      : RpcServer::DEFAULT_PORT);
  }

  void updateWindowTitle() {
    QString server = config_.currentServer;
    if (server.isEmpty()) {
      setWindowTitle("CES Wallet");
    } else {
      const QString defaultSuffix = ":" + QString::number(ces::DEFAULT_PORT);
      if (server.endsWith(defaultSuffix))
        server.chop(defaultSuffix.size());
      setWindowTitle(server + " - CES Wallet");
    }
  }

  void showFromTray() {
    show();
    raise();
    activateWindow();
  }

  void setTrayIcon(QSystemTrayIcon* icon) { trayIcon_ = icon; }

protected:
  void closeEvent(QCloseEvent* e) override {
    if (trayIcon_ && trayIcon_->isVisible()) {
      hide();
      e->ignore();
    } else {
      e->accept();
    }
  }

private:
  AppConfig config_;
  ConsoleWidget* console_ = nullptr;
  WalletWidget* walletWidget_ = nullptr;
  AccountWidget* accountWidget_ = nullptr;
  MiningWidget* miningWidget_ = nullptr;
  TransferWidget* transferWidget_ = nullptr;
  CreateAssetWidget* createAssetWidget_ = nullptr;
  AssetsWidget* assetsWidget_ = nullptr;
  MarketplaceWidget* marketplaceWidget_ = nullptr;
  KeyManagerWidget* keyManager_ = nullptr;
  ServerManagerWidget* serverManager_ = nullptr;
  AboutWidget* aboutWidget_ = nullptr;
  RpcServer* rpcServer_ = nullptr;
  bool autoApprove_ = false;
  QSystemTrayIcon* trayIcon_ = nullptr;
};

// =============================================================================
// Console command execution (defined here where MainWindow is complete)
// =============================================================================

void ConsoleWidget::execCommand(const QString& cmd) {
  QString lower = cmd.toLower().trimmed();
  bool ok = false;

  if (lower == "help" || lower == "?") {
    appendCmd("Available commands:");
    appendCmd("  help      - Show this message");
    appendCmd("  clear     - Clear the console");
    appendCmd("  history   - Show command history");
    appendCmd("  !N        - Recall command N from history");
    appendCmd("  bal       - Show selected account balance");
    appendCmd("  bal all   - Show all account balances");
    appendCmd("  keys      - List wallet keys");
    appendCmd("  ping      - Ping all servers");
    appendCmd("  @         - Show current account");
    appendCmd("  @N        - Switch to account N");
    appendCmd("  send <amount> <dest> - Transfer funds");
    appendCmd("  status    - Show app status");
    appendCmd("  tron      - Enable trace logging (default)");
    appendCmd("  troff     - Suppress trace logging");
    appendCmd("  quit      - Close the application");
  } else if (lower == "clear" || lower == "cls") {
    log_->clear();
  } else if (lower == "history" || lower == "hist") {
    auto& h = input_->history();
    if (h.isEmpty()) {
      appendCmd("  (empty)");
    } else {
      for (int i = 0; i < h.size(); ++i)
        appendCmd(QString("  %1: %2").arg(i + 1).arg(h[i]));
    }
  } else if (lower.startsWith("!")) {
    bool ok;
    int idx = lower.mid(1).toInt(&ok);
    auto& h = input_->history();
    if (ok && idx >= 1 && idx <= h.size()) {
      QString recalled = h[idx - 1];
      input_->pushHistory(recalled);
      appendCmd("] " + recalled);
      execCommand(recalled);
    } else {
      appendError("Invalid history reference: " + cmd);
    }
  } else if (lower == "quit" || lower == "exit") {
    QApplication::quit();
  } else if (lower == "keys" || lower == "k") {
    if (!app_) { appendError("Not connected to app."); return; }
    int n = app_->keyCount();
    if (n == 0) {
      appendCmd("  No keys in wallet.");
    } else {
      for (int i = 0; i < n; ++i)
        appendCmd(QString("  @%1  %2").arg(i).arg(app_->publicKeyHex(i)));
    }
  } else if (lower == "ping" || lower == "p") {
    if (!app_) { appendError("Not connected to app."); return; }
    auto r = app_->pingAllSync();
    if (r) {
      for (int i = 0; i < r->servers.size(); ++i) {
        QString st = (i < r->statuses.size()) ? r->statuses[i] : "?";
        appendCmd(QString("  %1: %2").arg(r->servers[i]).arg(st));
      }
    } else {
      appendError("Ping timed out.");
    }
  } else if (lower == "bal" || lower == "b") {
    if (!app_) { appendError("Not connected to app."); return; }
    auto r = app_->queryBalanceSync();
    if (r)
      appendCmd(QString("@%1 balance: %2")
        .arg(app_->selectedAccount()).arg(formatAmount(r->balance)));
    else
      appendError("Query timed out.");
  } else if (lower.startsWith("bal @") || lower.startsWith("b @")) {
    if (!app_) { appendError("Not connected to app."); return; }
    QString idxStr = lower.mid(lower.indexOf('@') + 1).trimmed();
    int idx;
    if (idxStr.isEmpty()) {
      idx = app_->selectedAccount();
      ok = true;
    } else {
      idx = idxStr.toInt(&ok);
    }
    if (!ok || idx < 0 || idx >= app_->keyCount()) {
      appendError(QString("Invalid account. Range: @0..@%1")
        .arg(app_->keyCount() - 1));
    } else {
      auto r = app_->queryAccountSync(idx);
      if (r)
        appendCmd(QString("@%1 balance: %2")
          .arg(idx).arg(formatAmount(r->balance)));
      else
        appendError("Query failed.");
    }
  } else if (lower == "bal all" || lower == "b all") {
    if (!app_) { appendError("Not connected to app."); return; }
    auto r = app_->queryWalletSync();
    if (r) {
      for (auto& a : r->accounts)
        appendCmd(QString("  @%1  %2  %3")
          .arg(a.index).arg(formatAmount(a.balance)).arg(a.fullPubKey));
      appendCmd(QString("Total: %1 (%2 accounts)")
        .arg(formatAmount(r->total)).arg(r->count));
    } else {
      appendError("Wallet query timed out.");
    }
  } else if (lower == "status") {
    if (!app_) { appendError("Not connected to app."); return; }
    appendCmd(QString("Keys: %1").arg(app_->keyCount()));
    appendCmd(QString("Current server: %1")
      .arg(app_->currentServer().isEmpty() ? "(none)" : app_->currentServer()));
    appendCmd(QString("Selected account: @%1").arg(app_->selectedAccount()));
    appendCmd(QString("Mining: %1").arg(app_->isMining() ? "active" : "idle"));
    appendCmd(QString("Servers: %1").arg(app_->config().servers.size()));
    appendCmd(QString("Tracked assets: %1").arg(app_->config().trackedAssets.size()));
  } else if (lower == "@") {
    if (!app_) { appendError("Not connected to app."); return; }
    int idx = app_->selectedAccount();
    appendCmd(QString("Selected account: @%1  %2")
      .arg(idx).arg(app_->publicKeyHex(idx)));
  } else if (lower.startsWith("@") && lower.size() > 1) {
    if (!app_) { appendError("Not connected to app."); return; }
    bool ok;
    int idx = lower.mid(1).toInt(&ok);
    if (!ok || idx < 0 || idx >= app_->keyCount()) {
      appendError(QString("Invalid account index. Range: @0..@%1")
        .arg(app_->keyCount() - 1));
    } else {
      app_->config().defaultAccount = idx;
      app_->config().save();
      app_->accountWidget()->refreshKeyListNoQuery();
      appendCmd(QString("@%1  %2")
        .arg(idx).arg(app_->publicKeyHex(idx)));
    }
  } else if (lower.startsWith("send ") || lower.startsWith("s ")) {
    if (!app_) { appendError("Not connected to app."); return; }
    // Parse: send <amount> <dest>
    auto parts = cmd.trimmed().split(' ', Qt::SkipEmptyParts);
    if (parts.size() < 3) {
      appendError("Usage: send <amount> <dest>");
      appendCmd("  amount: decimal (e.g. 1.5)");
      appendCmd("  dest: public key hex or @N");
      return;
    }
    // Parse amount (decimal → internal units)
    QString amtStr = parts[1];
    double amtDbl = amtStr.toDouble(&ok);
    if (!ok || amtDbl <= 0) {
      appendError("Invalid amount: " + amtStr);
      return;
    }
    uint64_t amount = static_cast<uint64_t>(
      amtDbl * static_cast<double>(ces::PRICE_UNIT) + 0.5);

    // Resolve destination
    QString destStr = parts[2];
    QString destHex;
    if (destStr == "@") {
      destHex = app_->publicKeyHex(app_->selectedAccount());
    } else if (destStr.startsWith("@")) {
      int di = destStr.mid(1).toInt(&ok);
      if (!ok || di < 0 || di >= app_->keyCount()) {
        appendError("Invalid destination index: " + destStr);
        return;
      }
      destHex = app_->publicKeyHex(di);
    } else {
      destHex = destStr;
    }

    int fromIdx = app_->selectedAccount();
    QString destDisplay = destStr;
    if (destStr == "@")
      destDisplay = QString("@%1").arg(app_->selectedAccount());
    else if (!destStr.startsWith("@"))
      destDisplay = destHex;
    appendCmd(QString("Sending %1 from @%2 to %3...")
      .arg(formatAmount(amount)).arg(fromIdx).arg(destDisplay));

    auto r = app_->transferSync(fromIdx, destHex, amount);
    if (!r) {
      appendError("Transfer failed (connection error).");
    } else if (r->rc == 0) {
      appendCmd(QString("Sent! New balance: %1").arg(formatAmount(r->newBalance)));
      // Update transfer history
      app_->config().pushTransferDest(destHex);
    } else {
      appendError(QString("Transfer error: %1").arg(
        QString::fromStdString(ces::errorString(r->rc))));
    }
  } else if (lower == "tron") {
    trace_ = true;
    appendCmd("Trace on.");
  } else if (lower == "troff") {
    trace_ = false;
    appendCmd("Trace off.");
  } else {
    appendError("Unknown command: " + cmd + "  (type 'help' for commands)");
  }
}

// =============================================================================
// Main — system tray + window
// =============================================================================

int main(int argc, char* argv[]) {
  // Parse CLI args before Qt init
  bool noDaemon = false;
  bool autoApprove = false;
  std::string dataDirOverride;
  uint16_t rpcPortOverride = 0;
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--no-daemon") {
      noDaemon = true;
    } else if (arg == "--autoapprove") {
      autoApprove = true;
    } else if (arg == "--datadir" && i + 1 < argc) {
      dataDirOverride = argv[++i];
    } else if (arg == "--rpcport" && i + 1 < argc) {
      rpcPortOverride = static_cast<uint16_t>(std::stoi(argv[++i]));
    } else if (arg == "--help" || arg == "-h") {
      std::cout << "cesqt - CES Wallet (Qt GUI)\n\n"
                << "Usage: cesqt [options]\n\n"
                << "Options:\n"
                << "  --datadir <path>  Override config/wallet directory\n"
                << "  --rpcport <port>  Override RPC port (default 21008)\n"
                << "  --autoapprove     Auto-approve all RPC origin requests\n"
                << "  --no-daemon       Stay attached to the terminal\n"
                << "  --help, -h        Show this help and exit\n";
      return 0;
    } else {
      std::cerr << "Unknown option: " << arg << "\n"
                << "Run 'cesqt --help' for usage.\n";
      return 1;
    }
  }

  // Single-instance guard is set up after QApplication (needs config dir)

  // Detach from terminal (Unix only)
#ifndef _WIN32
  if (!noDaemon) {
    pid_t pid = fork();
    if (pid < 0) _exit(1);
    if (pid > 0) _exit(0);
    setsid();
  }
#endif

  QApplication app(argc, argv);
  app.setApplicationName("cesqt");
  app.setOrganizationName("ces");
  QApplication::setQuitOnLastWindowClosed(false);

  // Route SIGTERM/SIGINT into Qt's event loop. ceslib's static signal
  // installer (src/ceslib/ctrlc.cpp) installs a poll-flag handler at
  // static-init time, which is correct for the server but leaves cesqt
  // ignoring SIGTERM since its Qt loop never polls that flag. Override
  // here with a self-pipe → QSocketNotifier → app.quit() so stopqt
  // can shut it down gracefully without escalating to SIGKILL.
  static int sigPipe[2] = {-1, -1};
  if (::pipe(sigPipe) == 0) {
    auto* notifier = new QSocketNotifier(sigPipe[0],
                                         QSocketNotifier::Read, &app);
    QObject::connect(notifier, &QSocketNotifier::activated, &app,
      [&app](int) {
        char b = 0;
        ssize_t r = ::read(sigPipe[0], &b, 1);
        (void)r;
        app.quit();
      });
    auto handler = +[](int) {
      const char b = 1;
      ssize_t n = ::write(sigPipe[1], &b, 1);
      (void)n;
    };
    ::signal(SIGTERM, handler);
    ::signal(SIGINT,  handler);
  }

  // Single-instance guard (per datadir, so sandboxed instances don't conflict)
  QString lockDir = dataDirOverride.empty()
    ? QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation)
    : QString::fromStdString(dataDirOverride);
  QDir().mkpath(lockDir);
  QLockFile lockFile(lockDir + "/cesqt.lock");
  lockFile.setStaleLockTime(0);
  if (!lockFile.tryLock(0)) {
    qint64 pid = 0;
    QString hostname, appname;
    lockFile.getLockInfo(&pid, &hostname, &appname);
    std::cerr << "cesqt is already running (pid " << pid << ").\n";
    return 1;
  }

  MainWindow window(QString::fromStdString(dataDirOverride), rpcPortOverride,
                    autoApprove);

  // System tray icon
  QSystemTrayIcon trayIcon;
  trayIcon.setIcon(app.style()->standardIcon(QStyle::SP_ComputerIcon));
  trayIcon.setToolTip("CES Wallet");

  QMenu trayMenu;
  auto* showAction = trayMenu.addAction("Show Wallet");
  QObject::connect(showAction, &QAction::triggered, &window,
    &MainWindow::showFromTray);
  trayMenu.addSeparator();
  auto* quitAction = trayMenu.addAction("Quit");
  QObject::connect(quitAction, &QAction::triggered, &app, &QApplication::quit);

  trayIcon.setContextMenu(&trayMenu);
  trayIcon.show();

  window.setTrayIcon(&trayIcon);

  QObject::connect(&trayIcon, &QSystemTrayIcon::activated,
    [&window](QSystemTrayIcon::ActivationReason reason) {
      if (reason == QSystemTrayIcon::DoubleClick)
        window.showFromTray();
    });

  window.show();

  return app.exec();
}

#include "main.moc"
