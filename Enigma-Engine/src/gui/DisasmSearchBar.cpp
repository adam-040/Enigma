#include "DisasmSearchBar.h"
#include "DisassemblyFieldView.h"
#include <QHBoxLayout>
#include <QKeyEvent>

DisasmSearchBar::DisasmSearchBar(DisassemblyFieldView* disasmView, QWidget* parent)
    : QWidget(parent), disasmView_(disasmView)
{
    auto* layout = new QHBoxLayout(this);
    layout->setContentsMargins(6, 3, 6, 3);
    layout->setSpacing(6);

    closeBtn_ = new QToolButton(this);
    closeBtn_->setText(QStringLiteral("✕"));
    closeBtn_->setToolTip(tr("Close Find Bar (Esc)"));
    closeBtn_->setAutoRaise(true);
    closeBtn_->setFixedSize(20, 20);
    connect(closeBtn_, &QToolButton::clicked, this, &DisasmSearchBar::closeSearch);
    layout->addWidget(closeBtn_);

    searchInput_ = new QLineEdit(this);
    searchInput_->setPlaceholderText(tr("Find in disassembly (mnemonic, operand, address, string)..."));
    searchInput_->setToolTip(tr("Search disassembly by mnemonic, operand value, address, or string"));
    searchInput_->setMinimumWidth(220);
    connect(searchInput_, &QLineEdit::textChanged, this, &DisasmSearchBar::onTextChanged);
    connect(searchInput_, &QLineEdit::returnPressed, this, &DisasmSearchBar::findNext);
    layout->addWidget(searchInput_);

    matchCaseCheck_ = new QCheckBox(tr("Match Case"), this);
    matchCaseCheck_->setToolTip(tr("When enabled, search is case-sensitive"));
    connect(matchCaseCheck_, &QCheckBox::toggled, this, &DisasmSearchBar::onMatchCaseToggled);
    layout->addWidget(matchCaseCheck_);

    prevBtn_ = new QToolButton(this);
    prevBtn_->setText(QStringLiteral("▲"));
    prevBtn_->setToolTip(tr("Previous Match (Shift+F3)"));
    prevBtn_->setAutoRaise(true);
    prevBtn_->setFixedSize(22, 20);
    connect(prevBtn_, &QToolButton::clicked, this, &DisasmSearchBar::findPrev);
    layout->addWidget(prevBtn_);

    nextBtn_ = new QToolButton(this);
    nextBtn_->setText(QStringLiteral("▼"));
    nextBtn_->setToolTip(tr("Next Match (F3 / Enter)"));
    nextBtn_->setAutoRaise(true);
    nextBtn_->setFixedSize(22, 20);
    connect(nextBtn_, &QToolButton::clicked, this, &DisasmSearchBar::findNext);
    layout->addWidget(nextBtn_);

    countLabel_ = new QLabel(this);
    countLabel_->setMinimumWidth(100);
    countLabel_->setStyleSheet(QStringLiteral("color: #555555; font-size: 11px;"));
    layout->addWidget(countLabel_);

    layout->addStretch();

    setStyleSheet(
        QStringLiteral("DisasmSearchBar { background: #f8f9fa; border-top: 1px solid #dcdcdc; padding: 2px; }"
                       "QLineEdit { background: #ffffff; color: #111111; border: 1px solid #c8c8c8; padding: 2px 6px; border-radius: 3px; font-size: 12px; }"
                       "QLineEdit:focus { border: 1px solid #0078d4; }"
                       "QToolButton { color: #333333; background: transparent; border: 1px solid transparent; border-radius: 3px; padding: 2px; }"
                       "QToolButton:hover { background: #e9ecef; border-color: #ced4da; color: #000000; }"
                       "QToolButton:pressed { background: #dee2e6; }"
                       "QCheckBox { color: #333333; font-size: 11px; }"));

    hide();
}

void DisasmSearchBar::openSearch(const QString& initialText) {
    show();
    raise();
    if (!initialText.isEmpty()) {
        searchInput_->setText(initialText);
        searchInput_->selectAll();
    }
    searchInput_->setFocus();
    performSearch();
}

void DisasmSearchBar::closeSearch() {
    hide();
    matchingRows_.clear();
    currentMatchIdx_ = -1;
    if (disasmView_) {
        disasmView_->clearSearchHighlight();
        disasmView_->setFocus();
    }
    emit searchClosed();
}

void DisasmSearchBar::onTextChanged(const QString& /*text*/) {
    performSearch();
}

void DisasmSearchBar::onMatchCaseToggled(bool /*checked*/) {
    performSearch();
}

void DisasmSearchBar::performSearch() {
    matchingRows_.clear();
    currentMatchIdx_ = -1;
    QString query = searchInput_->text();

    if (!disasmView_ || query.isEmpty()) {
        updateMatchLabel();
        if (disasmView_) disasmView_->clearSearchHighlight();
        return;
    }

    Qt::CaseSensitivity cs = matchCaseCheck_->isChecked() ? Qt::CaseSensitive : Qt::CaseInsensitive;
    int total = disasmView_->lineCount();

    int startRow = disasmView_->currentRow();
    int bestIdx = -1;

    for (int r = 0; r < total; ++r) {
        QString text = disasmView_->lineText(r);
        if (text.contains(query, cs)) {
            matchingRows_.append(r);
            if (bestIdx == -1 && r >= startRow) {
                bestIdx = matchingRows_.size() - 1;
            }
        }
    }

    if (!matchingRows_.isEmpty()) {
        currentMatchIdx_ = (bestIdx >= 0) ? bestIdx : 0;
        goToCurrentMatch();
    } else {
        if (disasmView_) disasmView_->setSearchHighlight(query, matchCaseCheck_->isChecked(), -1);
    }

    updateMatchLabel();
}

void DisasmSearchBar::findNext() {
    if (matchingRows_.isEmpty()) return;
    currentMatchIdx_ = (currentMatchIdx_ + 1) % matchingRows_.size();
    goToCurrentMatch();
    updateMatchLabel();
}

void DisasmSearchBar::findPrev() {
    if (matchingRows_.isEmpty()) return;
    currentMatchIdx_ = (currentMatchIdx_ - 1 + matchingRows_.size()) % matchingRows_.size();
    goToCurrentMatch();
    updateMatchLabel();
}

void DisasmSearchBar::goToCurrentMatch() {
    if (currentMatchIdx_ < 0 || currentMatchIdx_ >= matchingRows_.size() || !disasmView_) return;
    int row = matchingRows_[currentMatchIdx_];
    disasmView_->seekToRow(row);
    disasmView_->setSearchHighlight(searchInput_->text(), matchCaseCheck_->isChecked(), row);
}

void DisasmSearchBar::updateMatchLabel() {
    QString query = searchInput_->text();
    if (query.isEmpty()) {
        countLabel_->setText(QString());
    } else if (matchingRows_.isEmpty()) {
        countLabel_->setText(tr("No matches"));
        countLabel_->setStyleSheet(QStringLiteral("color: #d9534f; font-weight: 500; font-size: 11px;"));
    } else {
        countLabel_->setText(tr("%1 of %2 matches").arg(currentMatchIdx_ + 1).arg(matchingRows_.size()));
        countLabel_->setStyleSheet(QStringLiteral("color: #555555; font-size: 11px;"));
    }
}

void DisasmSearchBar::keyPressEvent(QKeyEvent* event) {
    if (event->key() == Qt::Key_Escape) {
        closeSearch();
        event->accept();
        return;
    }
    if (event->key() == Qt::Key_F3) {
        if (event->modifiers() & Qt::ShiftModifier) {
            findPrev();
        } else {
            findNext();
        }
        event->accept();
        return;
    }
    QWidget::keyPressEvent(event);
}
