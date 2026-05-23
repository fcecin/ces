#pragma once

#include <QEventLoop>
#include <QWidget>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QTextCursor>
#include <QVBoxLayout>
#include <QDateTime>
#include <QKeyEvent>
#include <functional>
#include <QMap>
#include <QStringList>

// =============================================================================
// ConsoleInput — input line with history, tab completion, esc to clear
// =============================================================================

// Display/retention caps for the console widgets.
namespace cesqt_console_limits {
constexpr int kConsoleMaxBlocks = 10000;   // max visible log lines
constexpr int kConsoleMaxHistory = 100;    // recalled command history depth
}

class ConsoleInput : public QLineEdit {
  Q_OBJECT
public:
  explicit ConsoleInput(QWidget* parent = nullptr) : QLineEdit(parent) {}

  void setCommands(const QStringList& cmds) {
    commands_.clear();
    subcommands_.clear();
    for (auto& c : cmds) {
      int sp = c.indexOf(' ');
      if (sp < 0) {
        commands_ << c;
      } else {
        QString parent = c.left(sp);
        QString sub = c.mid(sp + 1);
        if (!commands_.contains(parent))
          commands_ << parent;
        subcommands_[parent] << sub;
      }
    }
  }

  // Dynamic completions provider (called at tab-time)
  using DynCompleter = std::function<QStringList(const QString& prefix)>;
  void setDynamicCompleter(DynCompleter fn) { dynComplete_ = fn; }

  void pushHistory(const QString& cmd) {
    if (!cmd.isEmpty() &&
        (history_.isEmpty() || history_.last() != cmd))
      history_.append(cmd);
    while (history_.size() > cesqt_console_limits::kConsoleMaxHistory)
      history_.removeFirst();
    historyPos_ = history_.size();
    draft_.clear();
  }

  const QStringList& history() const { return history_; }

signals:
  void tabComplete(const QString& options);

protected:
  bool event(QEvent* e) override {
    if (e->type() == QEvent::KeyPress) {
      auto* ke = static_cast<QKeyEvent*>(e);
      if (ke->key() == Qt::Key_Tab) {
        QString input = text().toLower();
        QString trimmed = input.trimmed();
        bool hasTrailingSpace = input.endsWith(' ') && !trimmed.isEmpty();

        if (!trimmed.isEmpty()) {
          // Try dynamic completer first (handles @N, etc.)
          if (dynComplete_) {
            QStringList dyn = dynComplete_(trimmed);
            if (!dyn.isEmpty()) {
              if (dyn.size() == 1)
                setText(dyn[0] + " ");
              else
                emit tabComplete(dyn.join("  "));
              return true;
            }
          }

          int sp = trimmed.indexOf(' ');
          if (sp >= 0) {
            // Multi-word: complete subcommand
            QString parent = trimmed.left(sp);
            QString subPrefix = trimmed.mid(sp + 1);

            // Try dynamic for second word too
            if (dynComplete_) {
              QStringList dyn = dynComplete_(trimmed);
              if (!dyn.isEmpty()) {
                if (dyn.size() == 1)
                  setText(dyn[0] + " ");
                else
                  emit tabComplete(dyn.join("  "));
                return true;
              }
            }

            auto it = subcommands_.find(parent);
            if (it != subcommands_.end()) {
              QStringList matches;
              for (auto& s : it.value())
                if (s.startsWith(subPrefix)) matches << s;
              if (matches.size() == 1)
                setText(parent + " " + matches[0] + " ");
              else if (matches.size() > 1)
                emit tabComplete(matches.join("  "));
            }
          } else if (hasTrailingSpace) {
            // Exact command with trailing space: show subcommands
            auto it = subcommands_.find(trimmed);
            if (it != subcommands_.end()) {
              QStringList& subs = it.value();
              if (subs.size() == 1)
                setText(trimmed + " " + subs[0] + " ");
              else if (subs.size() > 1)
                emit tabComplete(subs.join("  "));
            }
          } else {
            // Partial first word: complete command names
            QStringList matches;
            for (auto& c : commands_)
              if (c.startsWith(trimmed)) matches << c;
            if (matches.size() == 1)
              setText(matches[0] + " ");
            else if (matches.size() > 1)
              emit tabComplete(matches.join("  "));
          }
        }
        return true;
      }
    }
    return QLineEdit::event(e);
  }

  void keyPressEvent(QKeyEvent* e) override {
    if (e->key() == Qt::Key_Up) {
      if (!history_.isEmpty() && historyPos_ > 0) {
        if (historyPos_ == history_.size())
          draft_ = text();
        --historyPos_;
        setText(history_[historyPos_]);
      }
      return;
    }
    if (e->key() == Qt::Key_Down) {
      if (historyPos_ < history_.size()) {
        ++historyPos_;
        setText(historyPos_ < history_.size()
                  ? history_[historyPos_] : draft_);
      }
      return;
    }
    if (e->key() == Qt::Key_Escape) {
      clear();
      return;
    }
    QLineEdit::keyPressEvent(e);
  }

private:
  QStringList history_;
  QStringList commands_;
  QMap<QString, QStringList> subcommands_;
  DynCompleter dynComplete_;
  int historyPos_ = 0;
  QString draft_;
};

// =============================================================================
// ConsoleWidget — scrolling log output + interactive command input
// =============================================================================

class MainWindow; // forward declaration

class ConsoleWidget : public QWidget {
  Q_OBJECT
public:
  void setApp(MainWindow* app) { app_ = app; }
  ConsoleInput* input() { return input_; }

  explicit ConsoleWidget(QWidget* parent = nullptr) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    // Uniform chrome border on all four sides equal to the gap
    // between the log pane and the input box, so the console reads
    // as a framed pane on its tab rather than edge-to-edge content.
    const int gap = 6;
    layout->setSpacing(gap);
    layout->setContentsMargins(gap, gap, gap, gap);

    log_ = new QPlainTextEdit;
    log_->setReadOnly(true);
    log_->setMaximumBlockCount(cesqt_console_limits::kConsoleMaxBlocks);
    log_->setStyleSheet(
      "QPlainTextEdit { background: #1e1e1e; color: #d4d4d4;"
      " font-family: monospace; font-size: 10pt; }");
    layout->addWidget(log_);

    input_ = new ConsoleInput;
    input_->setPlaceholderText(
      "Type a command (Tab to complete, Up/Down for history)");
    input_->setStyleSheet(
      "QLineEdit { background: #252526; color: #d4d4d4;"
      " font-family: monospace; font-size: 10pt;"
      " border: 1px solid #3c3c3c; padding: 4px; }");
    input_->setCommands({"help", "clear", "history", "bal", "bal all",
                         "keys", "send", "ping", "status", "tron",
                         "troff", "quit", "exit"});
    layout->addWidget(input_);

    connect(input_, &QLineEdit::returnPressed,
            this, &ConsoleWidget::onCommand);
    connect(input_, &ConsoleInput::tabComplete, [this](const QString& opts) {
      appendCmd("  " + opts);
    });

    instance_ = this;
  }

  ~ConsoleWidget() { if (instance_ == this) instance_ = nullptr; }

  // -- Output categories --
  // Log: background system events (gray, suppressible with troff)
  void appendLog(const QString& msg) {
    if (!trace_) return;
    append(msg, QColor("#888888"));
  }
  // Command echo: user input (teal)
  void appendEcho(const QString& msg) { append(msg, QColor("#4ec9b0")); }
  // Command output: results from commands (white)
  void appendCmd(const QString& msg) { append(msg, QColor("#ffffff")); }
  // Error output (red)
  void appendError(const QString& msg) { append(msg, QColor("#f44747")); }

  // Thread-safe global log. Can be called from any thread.
  static void log(const QString& msg) {
    if (!instance_) return;
    QMetaObject::invokeMethod(instance_, [msg]() {
      instance_->appendLog(msg);
    }, Qt::QueuedConnection);
  }

private:
  void append(const QString& msg, const QColor& color) {
    QString ts = QDateTime::currentDateTime().toString("hh:mm:ss");
    QTextCharFormat fmt;
    fmt.setForeground(color);
    QTextCursor cursor = log_->textCursor();
    cursor.movePosition(QTextCursor::End);
    cursor.insertText("[" + ts + "] " + msg + "\n", fmt);
    log_->setTextCursor(cursor);
    log_->ensureCursorVisible();
  }

public:

private slots:
  void onCommand() {
    QString cmd = input_->text().trimmed();
    input_->clear();
    if (cmd.isEmpty()) {
      execCommand("help");
      return;
    }
    if (!cmd.startsWith("!"))
      input_->pushHistory(cmd);
    appendEcho("] " + cmd);
    execCommand(cmd);
  }

private:
  void execCommand(const QString& cmd);

  MainWindow* app_ = nullptr;
  QPlainTextEdit* log_ = nullptr;
  ConsoleInput* input_ = nullptr;
  bool trace_ = true;
  static inline ConsoleWidget* instance_ = nullptr;
};
