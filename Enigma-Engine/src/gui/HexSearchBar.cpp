#include "HexSearchBar.h"
#include "HexView.h"
#include "FieldView.h"
#include "EditorTheme.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QKeyEvent>
#include <QMessageBox>

HexSearchBar::HexSearchBar(HexView* hexView, QWidget* parent)
    : QWidget(parent), hexView_(hexView)
{
    auto* mainLay = new QVBoxLayout(this);
    mainLay->setContentsMargins(4, 2, 4, 2);
    mainLay->setSpacing(2);

    // Search row
    auto* searchRow = new QHBoxLayout();
    searchRow->setSpacing(4);

    closeBtn_ = new QPushButton("X", this);
    closeBtn_->setFixedSize(20, 20);
    closeBtn_->setToolTip(tr("Close hex search bar"));
    connect(closeBtn_, &QPushButton::clicked, this, &HexSearchBar::deactivate);

    patternEdit_ = new QLineEdit(this);
    patternEdit_->setPlaceholderText(tr("Search hex or text..."));
    patternEdit_->setToolTip(tr("Enter hex bytes (e.g. 90 90) or ASCII text to search for"));
    patternEdit_->setFixedWidth(200);
    connect(patternEdit_, &QLineEdit::textChanged, this, &HexSearchBar::onPatternChanged);
    connect(patternEdit_, &QLineEdit::returnPressed, this, &HexSearchBar::searchNext);

    modeCombo_ = new QComboBox(this);
    modeCombo_->addItems({ "Hex", "ASCII" });
    modeCombo_->setToolTip(tr("Switch between hex and ASCII search mode"));
    modeCombo_->setFixedWidth(60);

    prevBtn_ = new QPushButton("<", this);
    prevBtn_->setFixedSize(24, 20);
    prevBtn_->setToolTip(tr("Previous match"));
    connect(prevBtn_, &QPushButton::clicked, this, &HexSearchBar::searchPrev);

    nextBtn_ = new QPushButton(">", this);
    nextBtn_->setFixedSize(24, 20);
    nextBtn_->setToolTip(tr("Next match"));
    connect(nextBtn_, &QPushButton::clicked, this, &HexSearchBar::searchNext);

    matchLabel_ = new QLabel(this);
    matchLabel_->setFixedWidth(80);

    searchRow->addWidget(closeBtn_);
    searchRow->addWidget(patternEdit_);
    searchRow->addWidget(modeCombo_);
    searchRow->addWidget(prevBtn_);
    searchRow->addWidget(nextBtn_);
    searchRow->addWidget(matchLabel_);
    searchRow->addStretch();

    mainLay->addLayout(searchRow);

    // Replace row (hidden by default)
    replaceRow_ = new QWidget(this);
    auto* replaceRowLay = new QHBoxLayout(replaceRow_);
    replaceRowLay->setContentsMargins(0, 0, 0, 0);
    replaceRowLay->setSpacing(4);

    auto* replaceLabel = new QLabel(tr("Replace:"), replaceRow_);
    replaceEdit_ = new QLineEdit(replaceRow_);
    replaceEdit_->setPlaceholderText(tr("Replacement hex or text..."));
    replaceEdit_->setFixedWidth(200);

    replaceBtn_ = new QPushButton(tr("Replace"), replaceRow_);
    replaceBtn_->setFixedWidth(60);
    connect(replaceBtn_, &QPushButton::clicked, this, &HexSearchBar::replaceCurrent);

    replaceAllBtn_ = new QPushButton(tr("All"), replaceRow_);
    replaceAllBtn_->setFixedWidth(40);
    connect(replaceAllBtn_, &QPushButton::clicked, this, &HexSearchBar::replaceAll);

    replaceRowLay->addWidget(replaceLabel);
    replaceRowLay->addWidget(replaceEdit_);
    replaceRowLay->addWidget(replaceBtn_);
    replaceRowLay->addWidget(replaceAllBtn_);
    replaceRowLay->addStretch();

    mainLay->addWidget(replaceRow_);
    replaceRow_->setVisible(false);

    setVisible(false);
}

void HexSearchBar::activate() {
    visible_ = true;
    setVisible(true);
    patternEdit_->setFocus();
    patternEdit_->selectAll();
}

void HexSearchBar::activateReplace() {
    activate();
    replaceVisible_ = true;
    replaceRow_->setVisible(true);
    replaceEdit_->setFocus();
}

void HexSearchBar::deactivate() {
    visible_ = false;
    replaceVisible_ = false;
    matches_.clear();
    currentMatchIndex_ = -1;
    setVisible(false);
    replaceRow_->setVisible(false);
    hexView_->setFocus();
    hexView_->clearSearchHighlights();
}

void HexSearchBar::keyPressEvent(QKeyEvent* event) {
    if (event->key() == Qt::Key_Escape) {
        deactivate();
        return;
    }
    if (event->key() == Qt::Key_F3) {
        if (event->modifiers() & Qt::ShiftModifier)
            searchPrev();
        else
            searchNext();
        return;
    }
    if (event->key() == Qt::Key_Return) {
        if (event->modifiers() & Qt::ShiftModifier)
            searchPrev();
        else
            searchNext();
        return;
    }
    QWidget::keyPressEvent(event);
}

void HexSearchBar::onPatternChanged(const QString& text) {
    Q_UNUSED(text);
    performSearch();
}

void HexSearchBar::performSearch() {
    matches_.clear();
    currentMatchIndex_ = -1;

    QString pattern = patternEdit_->text().trimmed();
    if (pattern.isEmpty()) {
        updateMatchLabel();
        hexView_->clearSearchHighlights();
        return;
    }

    bool hexMode = (modeCombo_->currentIndex() == 0);
    auto* doc = hexView_->document();
    if (!doc) {
        updateMatchLabel();
        return;
    }

    QByteArray searchBytes;
    if (hexMode) {
        QString cleaned = pattern;
        cleaned.remove(QRegularExpression("[\\s0x]"));
        if (cleaned.size() % 2 != 0)
            cleaned.prepend('0');
        for (int i = 0; i < cleaned.size(); i += 2) {
            bool ok;
            uint8_t b = static_cast<uint8_t>(cleaned.mid(i, 2).toUInt(&ok, 16));
            if (ok) searchBytes.append(static_cast<char>(b));
        }
    } else {
        searchBytes = pattern.toUtf8();
    }

    if (searchBytes.isEmpty()) {
        updateMatchLabel();
        hexView_->clearSearchHighlights();
        return;
    }

    for (int li = 0; li < doc->lineCount(); ++li) {
        const Line& line = doc->line(li);

        if (hexMode) {
            QByteArray lineBytes;
            QVector<int> byteIndices;
            for (const Token& tok : line.tokens) {
                if (tok.byteIndex >= 0 && tok.len == 2) {
                    bool ok;
                    uint8_t b = static_cast<uint8_t>(tok.text.toUInt(&ok, 16));
                    if (ok) {
                        lineBytes.append(static_cast<char>(b));
                        byteIndices.append(tok.byteIndex);
                    }
                }
            }
            int pos = 0;
            while ((pos = lineBytes.indexOf(searchBytes, pos)) != -1) {
                HexSearchMatch m;
                m.line = li;
                m.byteStart = byteIndices[pos];
                m.byteEnd = byteIndices[pos + searchBytes.size() - 1];
                matches_.append(m);
                pos++;
            }
        } else {
            QString lineAscii;
            QVector<int> byteIndices;
            for (const Token& tok : line.tokens) {
                if (tok.byteIndex >= 0 && tok.len == 1) {
                    lineAscii += tok.text;
                    byteIndices.append(tok.byteIndex);
                }
            }
            int pos = 0;
            while ((pos = lineAscii.indexOf(pattern, pos, Qt::CaseInsensitive)) != -1) {
                HexSearchMatch m;
                m.line = li;
                m.byteStart = byteIndices[pos];
                m.byteEnd = byteIndices[pos + pattern.size() - 1];
                matches_.append(m);
                pos++;
            }
        }
    }

    currentMatchIndex_ = matches_.isEmpty() ? -1 : 0;
    updateMatchLabel();
    highlightMatches();

    if (!matches_.isEmpty())
        navigateToMatch(currentMatchIndex_);
}

void HexSearchBar::searchNext() {
    if (matches_.isEmpty()) return;
    currentMatchIndex_ = (currentMatchIndex_ + 1) % matches_.size();
    updateMatchLabel();
    navigateToMatch(currentMatchIndex_);
}

void HexSearchBar::searchPrev() {
    if (matches_.isEmpty()) return;
    currentMatchIndex_ = (currentMatchIndex_ - 1 + matches_.size()) % matches_.size();
    updateMatchLabel();
    navigateToMatch(currentMatchIndex_);
}

void HexSearchBar::navigateToMatch(int index) {
    if (index < 0 || index >= matches_.size()) return;
    const HexSearchMatch& m = matches_[index];
    auto* doc = hexView_->document();
    if (!doc || m.line < 0 || m.line >= doc->lineCount()) return;
    uint64_t addr = doc->line(m.line).addr + static_cast<uint64_t>(m.byteStart);
    hexView_->seek(addr);
}

void HexSearchBar::highlightMatches() {
    hexView_->setSearchHighlights(matches_);
}

void HexSearchBar::replaceCurrent() {
    if (currentMatchIndex_ < 0 || currentMatchIndex_ >= matches_.size()) return;

    bool hexMode = (modeCombo_->currentIndex() == 0);
    QString replaceText = replaceEdit_->text().trimmed();
    if (replaceText.isEmpty()) return;

    QByteArray replaceBytes;
    if (hexMode) {
        QString cleaned = replaceText;
        cleaned.remove(QRegularExpression("[\\s0x]"));
        if (cleaned.size() % 2 != 0)
            cleaned.prepend('0');
        for (int i = 0; i < cleaned.size(); i += 2) {
            bool ok;
            uint8_t b = static_cast<uint8_t>(cleaned.mid(i, 2).toUInt(&ok, 16));
            if (ok) replaceBytes.append(static_cast<char>(b));
        }
    } else {
        replaceBytes = replaceText.toUtf8();
    }

    if (replaceBytes.isEmpty()) return;

    const HexSearchMatch& m = matches_[currentMatchIndex_];
    auto* doc = hexView_->document();
    if (!doc || m.line < 0 || m.line >= doc->lineCount()) return;

    int matchSize = m.byteEnd - m.byteStart + 1;
    int replaceSize = replaceBytes.size();

    // Get the address and emit individual byte edits
    uint64_t lineAddr = doc->line(m.line).addr;
    for (int i = 0; i < matchSize && i < replaceSize; ++i) {
        uint64_t addr = lineAddr + static_cast<uint64_t>(m.byteStart + i);
        uint8_t newByte = static_cast<uint8_t>(replaceBytes[i]);
        emit hexView_->byteEditRequested(addr, 0, newByte);
    }

    // Rebuild search after replace
    performSearch();
}

void HexSearchBar::replaceAll() {
    if (matches_.isEmpty()) return;

    bool hexMode = (modeCombo_->currentIndex() == 0);
    QString replaceText = replaceEdit_->text().trimmed();
    if (replaceText.isEmpty()) return;

    QByteArray replaceBytes;
    if (hexMode) {
        QString cleaned = replaceText;
        cleaned.remove(QRegularExpression("[\\s0x]"));
        if (cleaned.size() % 2 != 0)
            cleaned.prepend('0');
        for (int i = 0; i < cleaned.size(); i += 2) {
            bool ok;
            uint8_t b = static_cast<uint8_t>(cleaned.mid(i, 2).toUInt(&ok, 16));
            if (ok) replaceBytes.append(static_cast<char>(b));
        }
    } else {
        replaceBytes = replaceText.toUtf8();
    }

    if (replaceBytes.isEmpty()) return;

    auto* doc = hexView_->document();
    if (!doc) return;

    // Replace in reverse order to preserve indices
    for (int i = matches_.size() - 1; i >= 0; --i) {
        const HexSearchMatch& m = matches_[i];
        if (m.line < 0 || m.line >= doc->lineCount()) continue;

        int matchSize = m.byteEnd - m.byteStart + 1;
        int replaceSize = replaceBytes.size();

        uint64_t lineAddr = doc->line(m.line).addr;
        for (int j = 0; j < matchSize && j < replaceSize; ++j) {
            uint64_t addr = lineAddr + static_cast<uint64_t>(m.byteStart + j);
            uint8_t newByte = static_cast<uint8_t>(replaceBytes[j]);
            emit hexView_->byteEditRequested(addr, 0, newByte);
        }
    }

    performSearch();
}

void HexSearchBar::updateMatchLabel() {
    if (matches_.isEmpty()) {
        matchLabel_->setText(patternEdit_->text().isEmpty() ? QString() : tr("No match"));
    } else {
        matchLabel_->setText(tr("%1 of %2")
            .arg(currentMatchIndex_ + 1)
            .arg(matches_.size()));
    }
}
