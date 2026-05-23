#pragma once

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QApplication>

// =============================================================================
// AboutWidget — version info and close button
// =============================================================================

class AboutWidget : public QWidget {
  Q_OBJECT
public:
  explicit AboutWidget(QWidget* parent = nullptr) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(20, 20, 20, 20);

    auto* title = new QLabel("CES Wallet");
    title->setStyleSheet(
      "font-size: 20pt; font-weight: bold; color: #4ec9b0;");
    layout->addWidget(title);

    layout->addSpacing(10);

    auto addField = [&](const QString& label, const QString& value) {
      auto* row = new QHBoxLayout;
      auto* lbl = new QLabel(label);
      lbl->setStyleSheet(
        "font-weight: bold; color: #888; min-width: 120px;");
      auto* val = new QLabel(value);
      val->setTextInteractionFlags(Qt::TextSelectableByMouse);
      val->setStyleSheet("color: #ccc;");
      row->addWidget(lbl);
      row->addWidget(val, 1);
      layout->addLayout(row);
    };

#ifndef CES_GIT_HASH
#define CES_GIT_HASH "unknown"
#endif
#ifndef CES_GIT_DATE
#define CES_GIT_DATE "unknown"
#endif
#ifndef CES_BUILD_TYPE
#define CES_BUILD_TYPE "unknown"
#endif
#ifndef CES_COMPILER
#define CES_COMPILER "unknown"
#endif

    addField("Version:", CES_GIT_HASH);
    addField("Date:", CES_GIT_DATE);
    addField("Build:", CES_BUILD_TYPE);
    addField("Compiler:", CES_COMPILER);
    addField("Qt:", QT_VERSION_STR);

    layout->addSpacing(20);

    auto* btnClose = new QPushButton("Close");
    btnClose->setMaximumWidth(100);
    connect(btnClose, &QPushButton::clicked, []() {
      QApplication::quit();
    });
    layout->addWidget(btnClose);

    layout->addStretch();
  }
};
