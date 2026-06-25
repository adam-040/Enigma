#include "FieldView.h"
#include "EditorTheme.h"
#include "SelectionManager.h"
#include <QPainter>
#include <QPaintEvent>
#include <QResizeEvent>
#include <QMouseEvent>
#include <QContextMenuEvent>
#include <QKeyEvent>
#include <QScrollBar>
#include <QApplication>
#include <QClipboard>
#include <QMenu>

void Document::clear() {
    lines_.clear();
    addrIndex_.clear();
    maxColumns_ = 0;
}

void Document::addLine(Line line) {
    lines_.push_back(std::move(line));
}

void Document::finalize() {
    maxColumns_ = 0;
    addrIndex_.clear();
    for (int i = 0; i < lines_.size(); ++i) {
        Line& l = lines_[i];
        l.text.clear();
        int col = 0;
        for (Token& tok : l.tokens) {
            tok.startCol = col;
            tok.len = static_cast<int>(tok.text.size());
            col += tok.len + tok.spaceAfter;
            l.text += tok.text;
            l.text += QString(tok.spaceAfter, QLatin1Char(' '));
        }
        maxColumns_ = std::max(maxColumns_, col);
        if (l.addr != 0 && (addrIndex_.isEmpty() || addrIndex_.back().first != l.addr))
            addrIndex_.append({l.addr, i});
    }
}

int Document::lineForAddress(uint64_t addr) const {
    if (addrIndex_.isEmpty()) return -1;
    auto it = std::upper_bound(addrIndex_.begin(), addrIndex_.end(),
        QPair<uint64_t, int>(addr, INT_MAX));
    if (it == addrIndex_.begin())
        return addrIndex_.front().second;
    --it;
    return it->second;
}

uint64_t Document::addressForLine(int idx) const {
    if (idx >= 0 && idx < lines_.size())
        return lines_[idx].addr;
    return 0;
}

std::pair<uint64_t, uint64_t> Document::instructionRangeForAddress(uint64_t addr) const {
    if (addrIndex_.isEmpty())
        return {0, 0};
    auto it = std::upper_bound(addrIndex_.begin(), addrIndex_.end(),
                               QPair<uint64_t, int>(addr, INT_MAX));
    if (it == addrIndex_.begin()) {
        const Line& l = lines_[addrIndex_.front().second];
        return {l.addr, addrIndex_.size() > 1 ? lines_[(addrIndex_.begin() + 1)->second].addr : l.addr};
    }
    --it;
    int idx = it->second;
    uint64_t start = lines_[idx].addr;
    uint64_t end = 0;
    if (it + 1 != addrIndex_.end())
        end = lines_[(it + 1)->second].addr;
    return {start, end};
}

FieldView::FieldView(QWidget* parent)
    : QAbstractScrollArea(parent)
{
    setFont(EditorTheme::baseFont());
    setFocusPolicy(Qt::StrongFocus);
    setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);

    caretBlinkTimer_ = new QTimer(this);
    caretBlinkTimer_->setInterval(qMax(100, QApplication::cursorFlashTime() / 2));
    connect(caretBlinkTimer_, &QTimer::timeout, this, [this]() {
        if (hasFocus()) {
            caretVisible_ = !caretVisible_;
            viewport()->update();
        }
    });
    caretBlinkTimer_->start();
    viewport()->setMouseTracking(true);
}

void FieldView::setDocument(std::unique_ptr<Document> doc) {
    doc_ = std::move(doc);
    currentLine_ = 0;
    currentAddr_ = 0;
    anchor_ = {0, 0};
    caret_ = {0, 0};
    selecting_ = false;
    dragging_ = false;
    highlightWord_.clear();
    highlightKind_ = TokenKind::Plain;
    selectedToken_ = {};
    currentSelection_ = {};
    horizontalScrollBar()->setValue(0);
    verticalScrollBar()->setValue(0);
    updateScrollBars();
    viewport()->update();
}

void FieldView::clearDocument() {
    doc_.reset();
    currentLine_ = 0;
    currentAddr_ = 0;
    anchor_ = {0, 0};
    caret_ = {0, 0};
    selecting_ = false;
    dragging_ = false;
    highlightWord_.clear();
    highlightKind_ = TokenKind::Plain;
    selectedToken_ = {};
    currentSelection_ = {};
    horizontalScrollBar()->setValue(0);
    verticalScrollBar()->setValue(0);
    updateScrollBars();
    viewport()->update();
}

uint64_t FieldView::addressAtCurrentLine() const {
    if (doc_ && currentLine_ >= 0 && currentLine_ < doc_->lineCount())
        return doc_->line(currentLine_).addr;
    return 0;
}

static bool isRegisterOrVariableLike(TokenKind k) {
    return k == TokenKind::Register || k == TokenKind::Variable
        || k == TokenKind::Function || k == TokenKind::Label
        || k == TokenKind::Immediate;
}

void FieldView::seek(uint64_t addr) {
    if (!doc_) return;
    int line = doc_->lineForAddress(addr);
    if (line < 0) return;
    currentLine_ = line;
    currentAddr_ = addr;
    anchor_ = caret_ = {line, 0};
    ensureVisible(line);
    highlightWord_.clear();
    highlightKind_ = TokenKind::Plain;
    selectedToken_ = {};
    viewport()->update();
}

void FieldView::setSelectionManager(SelectionManager* mgr) {
    if (selectionMgr_ == mgr) return;
    if (selectionMgr_)
        disconnect(selectionMgr_, &SelectionManager::selectionChanged,
                   this, &FieldView::applySelection);
    selectionMgr_ = mgr;
    if (selectionMgr_)
        connect(selectionMgr_, &SelectionManager::selectionChanged,
                this, &FieldView::applySelection);
}

void FieldView::applySelection(const SelectionState& sel) {
    if (sel.originView == this) return;
    currentSelection_ = sel;
    if (!sel.valid || !doc_) {
        selectedToken_ = {};
        highlightWord_.clear();
        highlightKind_ = TokenKind::Plain;
        viewport()->update();
        return;
    }

    bool moved = false;
    int line = -1;
    if (sel.address != 0) {
        line = doc_->lineForAddress(sel.address);
        if (line >= 0) {
            currentLine_ = line;
            currentAddr_ = sel.address;
            moved = true;
        }
    }

    if (!sel.tokenText.isEmpty()) {
        const Token* tok = (line >= 0)
            ? findTokenByAddressAndText(sel.address, sel.tokenText, sel.tokenKind)
            : nullptr;
        if (tok) {
            selectedToken_ = {line, tok->startCol, tok->len};
            anchor_ = {line, tok->startCol};
            caret_ = {line, tok->startCol + tok->len};
            highlightWord_ = tok->text;
            highlightKind_ = tok->kind;
        } else {
            // Occurrence highlight only (token not on this line or no address given)
            selectedToken_ = {};
            highlightWord_ = sel.tokenText;
            highlightKind_ = sel.tokenKind;
            anchor_ = caret_ = {currentLine_, 0};
        }
    } else {
        selectedToken_ = {};
        highlightWord_.clear();
        highlightKind_ = TokenKind::Plain;
        anchor_ = caret_ = {currentLine_, 0};
    }
    if (moved)
        ensureVisible(currentLine_);
    viewport()->update();
}

const Token* FieldView::findTokenByAddressAndText(uint64_t addr, const QString& text, TokenKind kind) const {
    if (!doc_) return nullptr;
    int line = doc_->lineForAddress(addr);
    if (line < 0) return nullptr;
    const Line& l = doc_->line(line);
    for (const Token& t : l.tokens) {
        if (t.text == text && (kind == TokenKind::Plain || t.kind == kind))
            return &t;
    }
    return nullptr;
}

void FieldView::resetCaretBlink() {
    caretVisible_ = true;
    if (caretBlinkTimer_) {
        caretBlinkTimer_->setInterval(qMax(100, QApplication::cursorFlashTime() / 2));
        caretBlinkTimer_->start();
    }
    viewport()->update();
}

void FieldView::focusInEvent(QFocusEvent* event) {
    QAbstractScrollArea::focusInEvent(event);
    resetCaretBlink();
}

void FieldView::focusOutEvent(QFocusEvent* event) {
    QAbstractScrollArea::focusOutEvent(event);
    caretVisible_ = false;
    viewport()->update();
}

QColor FieldView::colorForKind(TokenKind kind) const {
    return EditorTheme::colorFor(kind);
}

bool FieldView::isBoldKind(TokenKind kind) const {
    return EditorTheme::isEmphasis(kind);
}

int FieldView::visibleLineCount() const {
    int cellH = EditorTheme::cellHeight();
    return std::max(1, viewport()->height() / cellH);
}

FieldView::HitResult FieldView::caretAtPos(const QPoint& pos) const {
    if (!doc_ || doc_->lineCount() == 0) return {0, 0};
    int cellW = EditorTheme::cellWidth();
    int cellH = EditorTheme::cellHeight();
    int scrollY = verticalScrollBar()->value();
    int scrollX = horizontalScrollBar()->value();
    int line = (pos.y() + scrollY) / cellH;
    line = std::clamp(line, 0, doc_->lineCount() - 1);
    int col = qRound(static_cast<qreal>(pos.x() + scrollX - EditorTheme::leftPadding()) / cellW);
    col = std::clamp(col, 0, static_cast<int>(doc_->line(line).text.size()));
    return {line, col};
}

const Token* FieldView::tokenAt(int line, int col) const {
    if (!doc_ || line < 0 || line >= doc_->lineCount())
        return nullptr;
    const Line& l = doc_->line(line);
    for (const Token& t : l.tokens) {
        if (col >= t.startCol && col < t.startCol + t.len)
            return &t;
    }
    return nullptr;
}

int FieldView::tokenIndexAt(int line, int col) const {
    if (!doc_ || line < 0 || line >= doc_->lineCount())
        return -1;
    const Line& l = doc_->line(line);
    for (int i = 0; i < l.tokens.size(); ++i) {
        const Token& t = l.tokens[i];
        if (col >= t.startCol && col < t.startCol + t.len)
            return i;
    }
    return -1;
}

void FieldView::selectTokenAt(int line, int col) {
    if (!doc_ || line < 0 || line >= doc_->lineCount())
        return;
    const Line& l = doc_->line(line);
    const Token* tok = tokenAt(line, col);
    if (!tok) {
        // A click on whitespace still selects the containing instruction line.
        anchor_ = caret_ = {line, col};
        selectedToken_ = {};
        highlightWord_.clear();
        highlightKind_ = TokenKind::Plain;
        currentLine_ = line;
        currentAddr_ = l.addr;
        if (l.addr != 0) {
            auto range = doc_->instructionRangeForAddress(l.addr);
            SelectionState sel;
            sel.valid = true;
            sel.address = range.first;
            sel.endAddress = range.second;
            sel.originView = this;
            if (selectionMgr_)
                selectionMgr_->select(sel, this);
            emit cursorAddressChanged(l.addr);
        }
        return;
    }
    selectedToken_ = {line, tok->startCol, tok->len};
    anchor_ = {line, tok->startCol};
    caret_ = {line, tok->startCol + tok->len};
    highlightWord_ = tok->text;
    highlightKind_ = tok->kind;
    currentLine_ = line;
    currentAddr_ = l.addr;

    auto range = doc_->instructionRangeForAddress(l.addr);
    SelectionState sel;
    sel.valid = true;
    sel.address = range.first;
    sel.endAddress = range.second;
    sel.tokenText = tok->text;
    sel.tokenKind = tok->kind;
    sel.originView = this;
    if (selectionMgr_)
        selectionMgr_->select(sel, this);

    uint64_t lineAddr = l.addr;
    if (lineAddr != 0)
        emit cursorAddressChanged(lineAddr);
}

void FieldView::updateScrollBars() {
    int cellW = EditorTheme::cellWidth();
    int cellH = EditorTheme::cellHeight();
    int leftPad = EditorTheme::leftPadding();
    if (!doc_ || doc_->lineCount() == 0) {
        verticalScrollBar()->setRange(0, 0);
        horizontalScrollBar()->setRange(0, 0);
        return;
    }
    int vpH = viewport()->height();
    int vpW = viewport()->width();
    int vMax = std::max(0, doc_->lineCount() * cellH - vpH);
    verticalScrollBar()->setRange(0, vMax);
    verticalScrollBar()->setPageStep(vpH);
    verticalScrollBar()->setSingleStep(cellH);

    int hMax = std::max(0, doc_->maxColumns() * cellW + 2 * leftPad - vpW);
    horizontalScrollBar()->setRange(0, hMax);
    horizontalScrollBar()->setPageStep(vpW);
    horizontalScrollBar()->setSingleStep(cellW * 4);
}

void FieldView::ensureVisible(int line) {
    int cellH = EditorTheme::cellHeight();
    int y = line * cellH;
    int scrollY = verticalScrollBar()->value();
    int vpH = viewport()->height();
    if (y < scrollY)
        verticalScrollBar()->setValue(std::max(0, y));
    else if (y + cellH > scrollY + vpH)
        verticalScrollBar()->setValue(std::max(0, y + cellH - vpH));
}

void FieldView::paintEvent(QPaintEvent* event) {
    QPainter painter(viewport());
    painter.fillRect(event->rect(), EditorTheme::backgroundColor());
    if (!doc_ || doc_->lineCount() == 0) return;

    int cellW = EditorTheme::cellWidth();
    int cellH = EditorTheme::cellHeight();
    int ascent = EditorTheme::ascent();
    int glyphH = EditorTheme::glyphHeight();
    int leftPad = EditorTheme::leftPadding();
    int scrollY = verticalScrollBar()->value();
    int scrollX = horizontalScrollBar()->value();
    int vpH = viewport()->height();
    int vpW = viewport()->width();

    int first = scrollY / cellH;
    int last = std::min((scrollY + vpH) / cellH + 1, doc_->lineCount() - 1);

    QFont baseFont = EditorTheme::baseFont();
    QFont emphasisFont = EditorTheme::emphasisFont();

    auto lineSelection = [&](int li, int& sCol, int& eCol) -> bool {
        if (anchor_ == caret_) return false;
        int l1 = anchor_.line, l2 = caret_.line;
        int c1 = anchor_.col, c2 = caret_.col;
        if (l1 > l2 || (l1 == l2 && c1 > c2)) { std::swap(l1, l2); std::swap(c1, c2); }
        if (li < l1 || li > l2) return false;
        if (l1 == l2) { sCol = c1; eCol = c2; }
        else if (li == l1) { sCol = c1; eCol = static_cast<int>(doc_->line(l1).text.size()); }
        else if (li == l2) { sCol = 0;  eCol = c2; }
        else { sCol = 0; eCol = static_cast<int>(doc_->line(li).text.size()); }
        return true;
    };

    for (int li = first; li <= last; ++li) {
        int y = li * cellH - scrollY;
        int baseX = leftPad - scrollX;
        const Line& l = doc_->line(li);

        if (li == currentLine_)
            painter.fillRect(0, y, vpW, cellH, EditorTheme::caretLineColor());

        bool selectedTokenOnLine = (selectedToken_.line == li && selectedToken_.len > 0);

        int selS = 0, selE = 0;
        bool hasSel = lineSelection(li, selS, selE);
        if (hasSel && !selectedTokenOnLine) {
            int sx = baseX + selS * cellW;
            int sw = (selE - selS) * cellW;
            painter.fillRect(sx, y, sw, cellH, EditorTheme::selectionColor());
        }

        if (selectedTokenOnLine) {
            int sx = baseX + selectedToken_.startCol * cellW;
            int sw = selectedToken_.len * cellW;
            painter.fillRect(sx, y, sw, cellH, EditorTheme::primarySelectionColor());
        }

        for (const Token& tok : l.tokens) {
            painter.setPen(colorForKind(tok.kind));
            painter.setFont(isBoldKind(tok.kind) ? emphasisFont : baseFont);

            bool isSelectedToken = selectedTokenOnLine &&
                tok.startCol == selectedToken_.startCol &&
                tok.len == selectedToken_.len;

            for (int i = 0; i < tok.text.size(); ++i) {
                int col = tok.startCol + i;
                int tx = baseX + col * cellW;
                int ty = y + ascent;

                if (!highlightWord_.isEmpty() && !isSelectedToken &&
                    tok.kind == highlightKind_ && tok.text == highlightWord_) {
                    painter.fillRect(tx, y, cellW, cellH, EditorTheme::occurrenceColor());
                }

                if (isSelectedToken)
                    painter.setPen(Qt::white);
                painter.drawText(tx, ty, tok.text[i]);
                if (isSelectedToken)
                    painter.setPen(colorForKind(tok.kind));
            }
        }
    }

    if (hasFocus() && caretVisible_) {
        int cx = leftPad - scrollX + caret_.col * cellW;
        int cy = caret_.line * cellH - scrollY;
        painter.fillRect(cx, cy, 2, glyphH, EditorTheme::textColor());
    }
}

void FieldView::resizeEvent(QResizeEvent* event) {
    QAbstractScrollArea::resizeEvent(event);
    updateScrollBars();
}

void FieldView::mousePressEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton) {
        viewport()->setFocus();
        resetCaretBlink();
        auto hit = caretAtPos(event->pos());
        anchor_ = caret_ = {hit.line, hit.col};
        selecting_ = true;
        dragging_ = false;
        if (doc_) {
            currentLine_ = hit.line;
            currentAddr_ = doc_->line(hit.line).addr;
        }
        return;
    }
    QAbstractScrollArea::mousePressEvent(event);
}

void FieldView::mouseMoveEvent(QMouseEvent* event) {
    if (selecting_) {
        auto hit = caretAtPos(event->pos());
        if (hit.line != caret_.line || hit.col != caret_.col) {
            dragging_ = true;
            selectedToken_ = {};
            highlightWord_.clear();
            highlightKind_ = TokenKind::Plain;
        }
        caret_ = {hit.line, hit.col};
        viewport()->update();
        return;
    }
    if (doc_) {
        auto hit = caretAtPos(event->pos());
        const Token* tok = tokenAt(hit.line, hit.col);
        bool clickable = tok && (tok->refTarget != 0 ||
            tok->kind == TokenKind::Function ||
            tok->kind == TokenKind::Label ||
            tok->kind == TokenKind::Address);
        viewport()->setCursor(clickable ? Qt::PointingHandCursor : Qt::ArrowCursor);
    }
    QAbstractScrollArea::mouseMoveEvent(event);
}

void FieldView::mouseReleaseEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton && selecting_) {
        selecting_ = false;
        if (!dragging_) {
            auto hit = caretAtPos(event->pos());
            caret_ = {hit.line, hit.col};
            const Token* tok = tokenAt(hit.line, hit.col);
            if (tok) {
                if (event->modifiers() & Qt::ControlModifier) {
                    uint64_t target = tok->refTarget
                        ? tok->refTarget
                        : (tok->kind == TokenKind::Address ? tok->addr : 0);
                    if (target != 0) {
                        seek(target);
                        emit seekRequested(target);
                        dragging_ = false;
                        return;
                    }
                }

                selectTokenAt(hit.line, hit.col);
            } else {
                selectTokenAt(hit.line, hit.col);
            }
        } else {
            // Drag selection finished: keep range, no token/occurrence highlight
            selectedToken_ = {};
            highlightWord_.clear();
            highlightKind_ = TokenKind::Plain;
        }
        dragging_ = false;
        viewport()->update();
        return;
    }
    QAbstractScrollArea::mouseReleaseEvent(event);
}

void FieldView::contextMenuEvent(QContextMenuEvent* event) {
    auto hit = caretAtPos(event->pos());
    if (hit.line >= 0 && hit.col >= 0 && doc_.get()) {
        const Token* tok = tokenAt(hit.line, hit.col);
        if (tok && (tok->refTarget != 0 || tok->addr != 0)) {
            uint64_t target = tok->refTarget != 0 ? tok->refTarget : tok->addr;
            QMenu menu(this);
            QAction* actTo = menu.addAction(tr("Show References to 0x%1").arg(target, 0, 16));
            QAction* actFrom = menu.addAction(tr("Show References from 0x%1").arg(target, 0, 16));
            QAction* chosen = menu.exec(event->globalPos());
            if (chosen == actTo) {
                emit showReferencesRequested(target, true);
            } else if (chosen == actFrom) {
                emit showReferencesRequested(target, false);
            }
            return;
        }
    }
    QAbstractScrollArea::contextMenuEvent(event);
}

void FieldView::mouseDoubleClickEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton) {
        selecting_ = false;
        dragging_ = false;
        auto hit = caretAtPos(event->pos());
        const Token* tok = tokenAt(hit.line, hit.col);
        if (tok) {
            uint64_t target = tok->refTarget
                ? tok->refTarget
                : (tok->kind == TokenKind::Address ? tok->addr : 0);
            if (target != 0) {
                seek(target);
                emit seekRequested(target);
                SelectionState sel;
                sel.valid = true;
                sel.address = target;
                sel.endAddress = target + 1;
                sel.tokenText = QString("0x%1").arg(target, 0, 16);
                sel.tokenKind = TokenKind::Address;
                sel.originView = this;
                if (selectionMgr_)
                    selectionMgr_->select(sel, this);
                return;
            }
            selectedToken_ = {hit.line, tok->startCol, tok->len};
            anchor_ = {hit.line, tok->startCol};
            caret_ = {hit.line, tok->startCol + tok->len};
            highlightWord_ = tok->text;
            highlightKind_ = tok->kind;
            currentLine_ = hit.line;
            currentAddr_ = doc_ ? doc_->line(hit.line).addr : 0;
            if (doc_) {
                auto range = doc_->instructionRangeForAddress(currentAddr_);
                SelectionState sel;
                sel.valid = true;
                sel.address = range.first;
                sel.endAddress = range.second;
                sel.tokenText = tok->text;
                sel.tokenKind = tok->kind;
                sel.originView = this;
                if (selectionMgr_)
                    selectionMgr_->select(sel, this);
            }
            viewport()->update();
            return;
        }
    }
    QAbstractScrollArea::mouseDoubleClickEvent(event);
}

void FieldView::keyPressEvent(QKeyEvent* event) {
    resetCaretBlink();
    if (event->matches(QKeySequence::Copy)) {
        copySelection();
        return;
    }
    if (event->matches(QKeySequence::SelectAll)) {
        selectAll();
        return;
    }
    if (!doc_ || doc_->lineCount() == 0) {
        QAbstractScrollArea::keyPressEvent(event);
        return;
    }
    int oldLine = caret_.line;
    bool shifted = event->modifiers() & Qt::ShiftModifier;
    int linesPerPage = visibleLineCount();

    auto clampCol = [&](int line, int col) {
        int maxCol = static_cast<int>(doc_->line(line).text.size());
        return std::clamp(col, 0, maxCol);
    };

    auto moveTo = [&](int newLine, int newCol) {
        newLine = std::clamp(newLine, 0, doc_->lineCount() - 1);
        newCol = clampCol(newLine, newCol);
        if (shifted) {
            caret_ = {newLine, newCol};
        } else {
            anchor_ = caret_ = {newLine, newCol};
        }
        currentLine_ = newLine;
        currentAddr_ = doc_->line(newLine).addr;
        ensureVisible(newLine);
        viewport()->update();
    };

    switch (event->key()) {
    case Qt::Key_Up:       moveTo(caret_.line - 1, caret_.col); break;
    case Qt::Key_Down:     moveTo(caret_.line + 1, caret_.col); break;
    case Qt::Key_PageUp:   moveTo(caret_.line - linesPerPage, caret_.col); break;
    case Qt::Key_PageDown: moveTo(caret_.line + linesPerPage, caret_.col); break;
    case Qt::Key_Home:
        if (event->modifiers() & Qt::ControlModifier)
            moveTo(0, 0);
        else
            moveTo(caret_.line, 0);
        break;
    case Qt::Key_End:
        if (event->modifiers() & Qt::ControlModifier)
            moveTo(doc_->lineCount() - 1, static_cast<int>(doc_->line(doc_->lineCount() - 1).text.size()));
        else
            moveTo(caret_.line, static_cast<int>(doc_->line(caret_.line).text.size()));
        break;
    case Qt::Key_Left: {
        int line = caret_.line;
        int col = caret_.col;
        const Line& l = doc_->line(line);
        int idx = tokenIndexAt(line, col);
        if (idx > 0) {
            moveTo(line, l.tokens[idx - 1].startCol);
        } else if (idx == 0 || (idx < 0 && !l.tokens.isEmpty() && col > l.tokens.front().startCol)) {
            moveTo(line, l.tokens.front().startCol);
        } else if (line > 0) {
            const Line& prev = doc_->line(line - 1);
            if (!prev.tokens.isEmpty())
                moveTo(line - 1, prev.tokens.back().startCol);
            else
                moveTo(line - 1, 0);
        }
        break;
    }
    case Qt::Key_Right: {
        int line = caret_.line;
        int col = caret_.col;
        const Line& l = doc_->line(line);
        int idx = tokenIndexAt(line, col);
        if (idx >= 0 && idx + 1 < l.tokens.size()) {
            moveTo(line, l.tokens[idx + 1].startCol);
        } else if (line + 1 < doc_->lineCount()) {
            const Line& next = doc_->line(line + 1);
            if (!next.tokens.isEmpty())
                moveTo(line + 1, next.tokens.front().startCol);
            else
                moveTo(line + 1, 0);
        }
        break;
    }
    default:
        QAbstractScrollArea::keyPressEvent(event);
        return;
    }

    if (!shifted) {
        selectedToken_ = {};
        highlightWord_.clear();
        highlightKind_ = TokenKind::Plain;
        selectTokenAt(caret_.line, caret_.col);
    }

    if (oldLine != caret_.line) {
        uint64_t newAddr = doc_->line(caret_.line).addr;
        if (newAddr != 0)
            emit cursorAddressChanged(newAddr);
    }
}

void FieldView::selectAll() {
    if (!doc_ || doc_->lineCount() == 0) return;
    int lastLine = doc_->lineCount() - 1;
    anchor_ = {0, 0};
    caret_ = {lastLine, static_cast<int>(doc_->line(lastLine).text.size())};
    viewport()->update();
}

void FieldView::copySelection() {
    if (!doc_ || anchor_ == caret_) return;
    int l1 = anchor_.line, l2 = caret_.line;
    int c1 = anchor_.col, c2 = caret_.col;
    if (l1 > l2 || (l1 == l2 && c1 > c2)) { std::swap(l1, l2); std::swap(c1, c2); }
    QString result;
    for (int i = l1; i <= l2; ++i) {
        const QString& lineText = doc_->line(i).text;
        if (i == l1 && i == l2)
            result += lineText.mid(c1, c2 - c1);
        else if (i == l1)
            result += lineText.mid(c1);
        else if (i == l2)
            result += lineText.left(c2);
        else
            result += lineText;
        if (i < l2) result += QLatin1Char('\n');
    }
    QApplication::clipboard()->setText(result);
}
