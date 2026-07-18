#include "HexView.h"
#include "HexSearchBar.h"
#include <ghidra/ProgramDB.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/patch/PatchMemory.h>
#include <QScrollBar>
#include <QFile>
#include <QPainter>
#include <QMenu>
#include <QInputDialog>
#include <QKeyEvent>
#include <QApplication>
#include <QClipboard>
#include <QToolTip>
#include <QRegularExpression>
#include <cstring>
#include "EditorTheme.h"

HexView::HexView(QWidget* parent)
    : FieldView(parent)
{
    setHeaderHeight(EditorTheme::cellHeight());

    connect(verticalScrollBar(), &QScrollBar::rangeChanged, this, [this](int, int) {
        int hdr = EditorTheme::cellHeight();
        QScrollBar* sb = verticalScrollBar();
        sb->blockSignals(true);
        sb->setMaximum(sb->maximum() + hdr);
        sb->blockSignals(false);
    });
}

void HexView::setData(uint64_t baseAddr, const std::vector<uint8_t>& data) {
    clearEditState();
    undoStack_.clear();
    redoStack_.clear();
    baseAddr_ = baseAddr;
    endAddr_ = baseAddr + data.size();
    auto doc = std::make_unique<Document>();

    for (size_t offset = 0; offset < data.size(); offset += 16) {
        Line line;
        line.addr = baseAddr + offset;

        QString addrStr = QString("%1").arg(baseAddr + offset, 8, 16, QChar('0'));

        Token addrTok;
        addrTok.text = addrStr;
        addrTok.kind = TokenKind::Address;
        addrTok.spaceAfter = 3;
        addrTok.addr = line.addr;
        line.tokens.push_back(addrTok);

        for (int i = 0; i < 16; ++i) {
            Token hexTok;
            if (offset + i < data.size()) {
                hexTok.text = QString("%1").arg(data[offset + i], 2, 16, QChar('0'));
                hexTok.kind = TokenKind::Plain;
            } else {
                hexTok.text = QStringLiteral("  ");
                hexTok.kind = TokenKind::Bytes;
            }
            hexTok.spaceAfter = (i == 7) ? 2 : ((i == 15) ? 2 : 1);
            hexTok.addr = line.addr;
            hexTok.byteIndex = i;
            line.tokens.push_back(hexTok);
        }

        Token sepTok;
        sepTok.text = QStringLiteral("|");
        sepTok.kind = TokenKind::Punctuation;
        sepTok.spaceAfter = 1;
        sepTok.addr = line.addr;
        line.tokens.push_back(sepTok);

        for (int i = 0; i < 16; ++i) {
            Token asciiTok;
            if (offset + i < data.size()) {
                uint8_t b = data[offset + i];
                asciiTok.text = (b >= 0x20 && b <= 0x7e) ? QChar(b) : QChar('.');
                asciiTok.kind = TokenKind::Plain;
            } else {
                asciiTok.text = QChar(' ');
                asciiTok.kind = TokenKind::Plain;
            }
            asciiTok.spaceAfter = 0;
            asciiTok.addr = line.addr;
            asciiTok.byteIndex = i;
            line.tokens.push_back(asciiTok);
        }

        doc->addLine(std::move(line));
    }

    doc->finalize();
    setDocument(std::move(doc));
}

void HexView::buildFullHex(ghidra::ProgramDB* program, const QString& binaryPath) {
    if (!program) { clear(); return; }
    auto* mem = program->getMemory();
    auto* af = program->getAddressFactory();
    if (!mem || !af) { clear(); return; }

    auto blocks = mem->getBlocks();
    if (blocks.empty()) { clear(); return; }

    clearEditState();
    undoStack_.clear();
    redoStack_.clear();

    uint64_t imageBase = static_cast<uint64_t>(program->getImageBase().getOffset());

    auto doc = std::make_unique<Document>();

    auto addLines = [&](uint64_t baseAddr, const uint8_t* data, int dataLen) {
        for (int offset = 0; offset < dataLen; offset += 16) {
            uint64_t lineAddr = baseAddr + offset;
            Line line;
            line.addr = lineAddr;

            Token addrTok;
            addrTok.text = QString("%1").arg(lineAddr, 8, 16, QChar('0'));
            addrTok.kind = TokenKind::Address;
            addrTok.spaceAfter = 3;
            addrTok.addr = lineAddr;
            line.tokens.push_back(addrTok);

            for (int i = 0; i < 16; ++i) {
                Token hexTok;
                int idx = offset + i;
                if (data && idx < dataLen) {
                    uint8_t b = data[idx];
                    hexTok.text = QString("%1").arg(b, 2, 16, QChar('0'));
                    hexTok.kind = TokenKind::Plain;
                } else {
                    hexTok.text = QStringLiteral("00");
                    hexTok.kind = TokenKind::Bytes;
                }
                hexTok.spaceAfter = (i == 7) ? 2 : ((i == 15) ? 2 : 1);
                hexTok.addr = lineAddr;
                hexTok.byteIndex = i;
                line.tokens.push_back(hexTok);
            }

            Token sepTok;
            sepTok.text = QStringLiteral("|");
            sepTok.kind = TokenKind::Punctuation;
            sepTok.spaceAfter = 1;
            sepTok.addr = lineAddr;
            line.tokens.push_back(sepTok);

            for (int i = 0; i < 16; ++i) {
                Token asciiTok;
                int idx = offset + i;
                if (data && idx < dataLen) {
                    uint8_t b = data[idx];
                    asciiTok.text = (b >= 0x20 && b <= 0x7e) ? QChar(b) : QChar('.');
                    asciiTok.kind = TokenKind::Plain;
                } else {
                    asciiTok.text = QChar('.');
                    asciiTok.kind = TokenKind::Plain;
                }
                asciiTok.spaceAfter = 0;
                asciiTok.addr = lineAddr;
                asciiTok.byteIndex = i;
                line.tokens.push_back(asciiTok);
            }

            doc->addLine(std::move(line));
        }
    };

    if (imageBase > 0) {
        uint64_t firstStart = UINT64_MAX;
        for (auto* b : blocks) {
            if (b && b->isInitialized()) {
                uint64_t s = b->getStart().getOffset();
                if (s < firstStart) firstStart = s;
            }
        }
        if (firstStart != UINT64_MAX && firstStart > imageBase) {
            uint64_t gapSize = std::min<uint64_t>(firstStart - imageBase, 0x10000);
            std::vector<uint8_t> hdrBytes;
            if (!binaryPath.isEmpty()) {
                QFile f(binaryPath);
                if (f.open(QIODevice::ReadOnly)) {
                    hdrBytes.resize(static_cast<size_t>(gapSize));
                    qint64 n = f.read(reinterpret_cast<char*>(hdrBytes.data()),
                                      static_cast<qint64>(gapSize));
                    if (n > 0) {
                        hdrBytes.resize(static_cast<size_t>(n));
                    } else {
                        hdrBytes.clear();
                    }
                }
            }
            if (!hdrBytes.empty()) {
                addLines(imageBase, hdrBytes.data(), static_cast<int>(hdrBytes.size()));
            }
        }
    }

    for (auto* block : blocks) {
        if (!block || !block->isInitialized()) continue;

        ghidra::Address start = block->getStart();
        uint64_t blockStart = start.getOffset();
        long long blockSize = block->getSize();
        if (blockSize <= 0) continue;

        std::vector<uint8_t> blockData(static_cast<size_t>(blockSize));
        int got = mem->getBytes(start, blockData.data(), static_cast<int>(blockSize));
        if (got <= 0) continue;

        addLines(blockStart, blockData.data(), got);
    }

    if (doc->lineCount() == 0) { clear(); return; }

    baseAddr_ = doc->line(0).addr;
    endAddr_ = doc->line(doc->lineCount() - 1).addr + 16;
    doc->finalize();
    setDocument(std::move(doc));
}

void HexView::clear() {
    clearEditState();
    undoStack_.clear();
    redoStack_.clear();
    baseAddr_ = 0;
    endAddr_ = 0;
    clearDocument();
}

bool HexView::containsAddress(uint64_t addr) const {
    return baseAddr_ != endAddr_ && addr >= baseAddr_ && addr < endAddr_;
}

int HexView::byteIndexAt(int line, int col) const {
    auto* doc = document();
    if (!doc || line < 0 || line >= doc->lineCount())
        return -1;
    const Line& l = doc->line(line);
    for (const Token& t : l.tokens) {
        if (col >= t.startCol && col < t.startCol + t.len)
            return t.byteIndex;
    }
    return -1;
}

uint64_t HexView::addressForByteToken(int line, int col) const {
    auto* doc = document();
    if (!doc || line < 0 || line >= doc->lineCount())
        return 0;
    const Line& l = doc->line(line);
    for (const Token& t : l.tokens) {
        if (t.byteIndex >= 0 && col >= t.startCol && col < t.startCol + t.len)
            return l.addr + static_cast<uint64_t>(t.byteIndex);
    }
    return 0;
}

int HexView::byteColumnAt(int line, int byteIdx) const {
    auto* doc = document();
    if (!doc || line < 0 || line >= doc->lineCount())
        return -1;
    const Line& l = doc->line(line);
    for (const Token& t : l.tokens) {
        if (t.byteIndex == byteIdx && t.len == 2)
            return t.startCol;
    }
    return -1;
}

bool HexView::isHexDigit(int key) const {
    return (key >= Qt::Key_0 && key <= Qt::Key_9) ||
           (key >= Qt::Key_A && key <= Qt::Key_F);
}

int HexView::hexDigitValue(int key) const {
    if (key >= Qt::Key_0 && key <= Qt::Key_9)
        return key - Qt::Key_0;
    if (key >= Qt::Key_A && key <= Qt::Key_F)
        return 10 + (key - Qt::Key_A);
    return -1;
}

void HexView::clearEditState() {
    editing_ = false;
    editAddr_ = 0;
    editLine_ = -1;
    editByteIdx_ = -1;
    editCol_ = -1;
    editNibble_ = 0;
    editAccumulator_ = 0;
}

void HexView::pushUndo(uint64_t addr, uint8_t oldVal, uint8_t newVal) {
    redoStack_.clear();
    if (undoStack_.size() >= kMaxUndoEntries)
        undoStack_.removeFirst();
    undoStack_.append({addr, oldVal, newVal});
}

void HexView::commitByte(uint64_t addr, uint8_t newByte) {
    if (!containsAddress(addr)) return;

    // Get old value from document token text
    uint8_t oldByte = 0;
    auto* doc = document();
    if (doc && editLine_ >= 0 && editLine_ < doc->lineCount()) {
        const Line& line = doc->line(editLine_);
        for (const Token& tok : line.tokens) {
            if (tok.byteIndex == editByteIdx_ && tok.len == 2) {
                oldByte = static_cast<uint8_t>(tok.text.toUInt(nullptr, 16));
                break;
            }
        }
    }

    if (oldByte == newByte) {
        clearEditState();
        viewport()->update();
        return;
    }

    pushUndo(addr, oldByte, newByte);
    emit byteEditRequested(addr, oldByte, newByte);

    // Update the token text in the document immediately for visual feedback
    if (doc && editLine_ >= 0 && editLine_ < doc->lineCount()) {
        Line& line = const_cast<Line&>(doc->line(editLine_));
        for (Token& tok : line.tokens) {
            if (tok.byteIndex == editByteIdx_ && tok.len == 2) {
                tok.text = QString("%1").arg(newByte, 2, 16, QChar('0'));
                break;
            }
        }
        // Update ASCII token too
        for (Token& tok : line.tokens) {
            if (tok.byteIndex == editByteIdx_ && tok.len == 1) {
                tok.text = (newByte >= 0x20 && newByte <= 0x7e)
                    ? QChar(newByte) : QChar('.');
                break;
            }
        }
    }

    clearEditState();
    viewport()->update();
}

void HexView::advanceCaretAfterEdit() {
    auto* doc = document();
    if (!doc || editLine_ < 0) return;

    // Move to next byte on same line
    int nextByteIdx = editByteIdx_ + 1;
    if (nextByteIdx < 16) {
        int nextCol = byteColumnAt(editLine_, nextByteIdx);
        if (nextCol >= 0) {
            anchor_ = caret_ = {editLine_, nextCol};
            ensureVisible(editLine_);
            return;
        }
    }

    // Move to first byte on next line
    if (editLine_ + 1 < doc->lineCount()) {
        const Line& nextLine = doc->line(editLine_ + 1);
        int nextCol = byteColumnAt(editLine_ + 1, 0);
        if (nextCol >= 0) {
            anchor_ = caret_ = {editLine_ + 1, nextCol};
            currentLine_ = editLine_ + 1;
            currentAddr_ = nextLine.addr;
            ensureVisible(editLine_ + 1);
        }
    }
}

bool HexView::undoLastEdit() {
    if (undoStack_.isEmpty()) return false;
    HexEditUndoEntry entry = undoStack_.takeLast();
    redoStack_.append(entry);
    emit undoRequested(entry.addr, entry.oldValue);
    viewport()->update();
    return true;
}

bool HexView::redoLastEdit() {
    if (redoStack_.isEmpty()) return false;
    HexEditUndoEntry entry = redoStack_.takeLast();
    undoStack_.append(entry);
    emit redoRequested(entry.addr, entry.newValue);
    viewport()->update();
    return true;
}

void HexView::pasteFromClipboard() {
    QString clipText = QApplication::clipboard()->text();
    if (clipText.isEmpty()) return;

    // Strip common prefixes and whitespace
    clipText.remove(QRegularExpression("\\s+"));
    clipText.remove("0x", Qt::CaseInsensitive);

    // Validate hex characters
    if (clipText.isEmpty()) return;
    static QRegularExpression hexRe("^[0-9a-fA-F]+$");
    if (!hexRe.match(clipText).hasMatch()) return;

    // Odd-length: pad leading nibble with 0
    if (clipText.size() % 2 != 0)
        clipText.prepend('0');

    // Convert to bytes
    std::vector<uint8_t> bytes;
    bytes.reserve(clipText.size() / 2);
    for (int i = 0; i < clipText.size(); i += 2) {
        bool ok;
        uint8_t b = static_cast<uint8_t>(clipText.mid(i, 2).toUInt(&ok, 16));
        if (ok) bytes.push_back(b);
    }
    if (bytes.empty()) return;

    // Write starting at caret address
    auto* doc = document();
    if (!doc) return;

    int line = caret_.line;
    int bi = byteIndexAt(line, caret_.col);
    if (bi < 0) return;

    uint64_t startAddr = doc->line(line).addr + static_cast<uint64_t>(bi);

    for (size_t i = 0; i < bytes.size(); ++i) {
        uint64_t addr = startAddr + i;
        if (!containsAddress(addr)) break;

        int line = doc->lineForAddress(addr);
        if (line < 0) break;
        int byteIdx = static_cast<int>(addr - doc->line(line).addr);

        // Get old value from document token
        uint8_t oldByte = 0;
        const Line& ln = doc->line(line);
        for (const Token& tok : ln.tokens) {
            if (tok.byteIndex == byteIdx && tok.len == 2) {
                oldByte = static_cast<uint8_t>(tok.text.toUInt(nullptr, 16));
                break;
            }
        }

        if (oldByte != bytes[i]) {
            pushUndo(addr, oldByte, bytes[i]);
            emit byteEditRequested(addr, oldByte, bytes[i]);

            // Update token text
            Line& lnMut = const_cast<Line&>(doc->line(line));
            for (Token& tok : lnMut.tokens) {
                if (tok.byteIndex == byteIdx && tok.len == 2) {
                    tok.text = QString("%1").arg(bytes[i], 2, 16, QChar('0'));
                }
                if (tok.byteIndex == byteIdx && tok.len == 1) {
                    tok.text = (bytes[i] >= 0x20 && bytes[i] <= 0x7e)
                        ? QChar(bytes[i]) : QChar('.');
                }
            }
        }
    }

    emit bytesPasted(startAddr, static_cast<int>(bytes.size()));
    viewport()->update();
}

void HexView::setSearchHighlights(const QVector<HexSearchMatch>& matches) {
    searchMatches_ = matches;
    viewport()->update();
}

void HexView::clearSearchHighlights() {
    searchMatches_.clear();
    viewport()->update();
}

void HexView::toggleBookmark(uint64_t addr) {
    for (int i = 0; i < bookmarks_.size(); ++i) {
        if (bookmarks_[i] == addr) {
            bookmarks_.removeAt(i);
            viewport()->update();
            return;
        }
    }
    // Insert in sorted order
    int pos = 0;
    while (pos < bookmarks_.size() && bookmarks_[pos] < addr) ++pos;
    bookmarks_.insert(pos, addr);
    viewport()->update();
}

bool HexView::isBookmarked(uint64_t addr) const {
    return bookmarks_.contains(addr);
}

void HexView::navigateBookmark(bool forward) {
    if (bookmarks_.isEmpty()) return;
    uint64_t cur = currentAddr_;
    if (forward) {
        for (uint64_t b : bookmarks_) {
            if (b > cur) { seek(b); emit seekRequested(b); return; }
        }
        seek(bookmarks_.first());
        emit seekRequested(bookmarks_.first());
    } else {
        for (int i = bookmarks_.size() - 1; i >= 0; --i) {
            if (bookmarks_[i] < cur) { seek(bookmarks_[i]); emit seekRequested(bookmarks_[i]); return; }
        }
        seek(bookmarks_.last());
        emit seekRequested(bookmarks_.last());
    }
}

void HexView::keyPressEvent(QKeyEvent* event) {
    // Ctrl shortcuts
    if (event->modifiers() & Qt::ControlModifier) {
        if (event->key() == Qt::Key_Z) {
            undoLastEdit();
            return;
        }
        if (event->key() == Qt::Key_Y) {
            redoLastEdit();
            return;
        }
        if (event->key() == Qt::Key_V) {
            pasteFromClipboard();
            return;
        }
        if (event->key() == Qt::Key_G) {
            bool ok = false;
            QString input = QInputDialog::getText(this,
                tr("Go to Address"),
                tr("Address (hex):"),
                QLineEdit::Normal,
                QString("0x"), &ok);
            if (!ok) return;
            uint64_t target = input.toULongLong(&ok, 16);
            if (!ok || !containsAddress(target)) return;
            seek(target);
            emit seekRequested(target);
            return;
        }
        if (event->key() == Qt::Key_F) {
            if (auto* sb = findChild<HexSearchBar*>()) {
                sb->activate();
            }
            return;
        }
        if (event->key() == Qt::Key_H) {
            if (auto* sb = findChild<HexSearchBar*>()) {
                sb->activateReplace();
            }
            return;
        }
        if (event->key() == Qt::Key_D) {
            auto* doc = document();
            if (doc && caret_.line >= 0 && caret_.line < doc->lineCount()) {
                int bi = byteIndexAt(caret_.line, caret_.col);
                uint64_t addr = doc->line(caret_.line).addr;
                if (bi >= 0) addr += static_cast<uint64_t>(bi);
                toggleBookmark(addr);
            }
            return;
        }
        if (event->key() == Qt::Key_Up) {
            navigateBookmark(false);
            return;
        }
        if (event->key() == Qt::Key_Down) {
            navigateBookmark(true);
            return;
        }
        // Let FieldView handle Ctrl+A, Ctrl+C, etc.
        FieldView::keyPressEvent(event);
        return;
    }

    // F3 = Find Next, Shift+F3 = Find Previous (when search bar was used)
    if (event->key() == Qt::Key_F3) {
        if (auto* sb = findChild<HexSearchBar*>()) {
            if (event->modifiers() & Qt::ShiftModifier)
                QMetaObject::invokeMethod(sb, "searchPrev");
            else
                QMetaObject::invokeMethod(sb, "searchNext");
        }
        return;
    }

    // Escape: cancel edit
    if (event->key() == Qt::Key_Escape && editing_) {
        clearEditState();
        viewport()->update();
        return;
    }

    // Hex digit input
    if (isHexDigit(event->key())) {
        auto* doc = document();
        if (!doc || doc->lineCount() == 0) return;

        int line = caret_.line;
        int col = caret_.col;
        int bi = byteIndexAt(line, col);
        if (bi < 0) return;

        uint64_t addr = doc->line(line).addr + static_cast<uint64_t>(bi);

        if (!editing_) {
            // Start new edit
            editing_ = true;
            editAddr_ = addr;
            editLine_ = line;
            editByteIdx_ = bi;
            editCol_ = col;
            editNibble_ = 0;
            editAccumulator_ = 0;
        } else if (editAddr_ != addr) {
            // Different byte — commit previous and start new
            if (editNibble_ == 1) {
                commitByte(editAddr_, editAccumulator_);
            }
            editing_ = true;
            editAddr_ = addr;
            editLine_ = line;
            editByteIdx_ = bi;
            editCol_ = col;
            editNibble_ = 0;
            editAccumulator_ = 0;
        }

        int val = hexDigitValue(event->key());

        if (editNibble_ == 0) {
            // First nibble: store high nibble
            editAccumulator_ = static_cast<uint8_t>(val << 4);
            editNibble_ = 1;
            viewport()->update();
        } else {
            // Second nibble: commit byte
            editAccumulator_ |= static_cast<uint8_t>(val);
            commitByte(editAddr_, editAccumulator_);
            advanceCaretAfterEdit();
        }
        return;
    }

    // For all other keys, delegate to FieldView (navigation, etc.)
    // But first commit any pending edit
    if (editing_ && editNibble_ == 1) {
        commitByte(editAddr_, editAccumulator_);
    }
    FieldView::keyPressEvent(event);
}

void HexView::paintEvent(QPaintEvent* event) {
    auto* doc = document();
    int cellW = EditorTheme::cellWidth();
    int cellH = EditorTheme::cellHeight();
    int ascent = EditorTheme::ascent();
    int glyphH = EditorTheme::glyphHeight();
    int leftPad = EditorTheme::leftPadding();
    int scrollY = verticalScrollBar()->value();
    int scrollX = horizontalScrollBar()->value();
    int vpH = viewport()->height();
    int vpW = viewport()->width();

    QPainter painter(viewport());
    painter.fillRect(event->rect(), EditorTheme::backgroundColor());

    if (!doc || doc->lineCount() == 0) return;

    int first = scrollY / cellH;
    int last = std::min((scrollY + vpH) / cellH + 1, doc->lineCount() - 1);
    QFont baseFont = EditorTheme::baseFont();
    QFont emphFont = EditorTheme::emphasisFont();
    const QColor* colorTbl = EditorTheme::colorTable();
    const QFont* fontTbl = EditorTheme::fontTable();
    int headerH = cellH;

    // Byte-index range selection
    int selByteIdx = -1;
    if (selectedToken_.len > 0)
        selByteIdx = byteIndexAt(selectedToken_.line, selectedToken_.startCol);

    int aLine = anchorLine(), aCol = anchorCol();
    int cLine = caretLine(), cCol = caretCol();
    bool hasByteRange = false;
    int byteL1 = 0, byteL2 = 0, byteB1 = 0, byteB2 = 0;

    if (selByteIdx >= 0) {
        hasByteRange = true;
        byteL1 = byteL2 = selectedToken_.line;
        byteB1 = byteB2 = selByteIdx;
    } else {
        int ab = byteIndexAt(aLine, aCol);
        int cb = byteIndexAt(cLine, cCol);
        if (ab >= 0 && cb >= 0) {
            hasByteRange = true;
            byteL1 = aLine; byteL2 = cLine;
            byteB1 = ab;    byteB2 = cb;
        } else if (ab >= 0) {
            hasByteRange = true;
            byteL1 = byteL2 = aLine;
            byteB1 = byteB2 = ab;
        }
    }
    if (hasByteRange) {
        if (byteL1 > byteL2 || (byteL1 == byteL2 && byteB1 > byteB2)) {
            std::swap(byteL1, byteL2);
            std::swap(byteB1, byteB2);
        }
    }

    for (int li = first; li <= last; ++li) {
        int y = headerH + li * cellH - scrollY;
        int baseX = leftPad - scrollX;
        const Line& l = doc->line(li);

        int byteStart = -1, byteEnd = -1;
        if (hasByteRange && li >= byteL1 && li <= byteL2) {
            byteStart = (li == byteL1) ? byteB1 : 0;
            byteEnd   = (li == byteL2) ? byteB2 : 15;
        }
        int hexSelStart = INT_MAX, hexSelEnd = 0;
        int ascSelStart = INT_MAX, ascSelEnd = 0;
        bool primOnLine = false;
        int primByteIdx = -1;
        int primCol = -1, primLen = 0;
        bool primIsHex = false;
        int crossCol = -1, crossLen = 0;

        for (const Token& t : l.tokens) {
            if (t.byteIndex >= 0) {
                if (byteStart >= 0 && t.byteIndex >= byteStart && t.byteIndex <= byteEnd) {
                    if (t.len == 2) {
                        hexSelStart = std::min(hexSelStart, t.startCol);
                        hexSelEnd   = std::max(hexSelEnd,   t.startCol + t.len);
                    } else {
                        ascSelStart = std::min(ascSelStart, t.startCol);
                        ascSelEnd   = std::max(ascSelEnd,   t.startCol + t.len);
                    }
                }
            }
            if (selectedToken_.line == li && selectedToken_.len > 0 &&
                t.startCol == selectedToken_.startCol && t.len == selectedToken_.len &&
                t.byteIndex >= 0) {
                primOnLine = true;
                primByteIdx = t.byteIndex;
                primCol = t.startCol;
                primLen = t.len;
                primIsHex = (t.len == 2);
            }
        }

        if (primByteIdx >= 0) {
            for (const Token& t : l.tokens) {
                if (t.byteIndex == primByteIdx) {
                    bool tIsHex = (t.len == 2);
                    if (tIsHex != primIsHex) {
                        crossCol = t.startCol;
                        crossLen = t.len;
                        break;
                    }
                }
            }
        }

        // --- Fill pass ---
        if (hexSelStart < hexSelEnd) {
            int hx = baseX + hexSelStart * cellW;
            int hw = (hexSelEnd - hexSelStart) * cellW;
            painter.fillRect(hx, y, hw, cellH, EditorTheme::selectionColor());
        }
        if (ascSelStart < ascSelEnd) {
            int ax = baseX + ascSelStart * cellW;
            int aw = (ascSelEnd - ascSelStart) * cellW;
            painter.fillRect(ax, y, aw, cellH, EditorTheme::selectionColor());
        }
        if (primOnLine && byteStart < 0) {
            int px = baseX + primCol * cellW;
            int pw = primLen * cellW;
            painter.fillRect(px, y, pw, cellH, EditorTheme::primarySelectionColor());
        }
        if (crossCol >= 0 && byteStart < 0) {
            int cx = baseX + crossCol * cellW;
            int cw = crossLen * cellW;
            painter.fillRect(cx, y, cw, cellH, EditorTheme::primarySelectionColor());
        }

        // Patch overlay
        if (patchMemory_) {
            for (const Token& t : l.tokens) {
                if (t.byteIndex < 0) continue;
                uint64_t byteAddr = l.addr + t.byteIndex;
                if (patchMemory_->hasOverride(byteAddr)) {
                    int px = baseX + t.startCol * cellW;
                    int pw = t.len * cellW;
                    QColor patchColor(0xff, 0x99, 0x33, 160);
                    painter.fillRect(px, y, pw, cellH, patchColor);
                }
            }
        }

        // Editing highlight — yellow background on the byte being edited
        if (editing_ && li == editLine_) {
            for (const Token& t : l.tokens) {
                if (t.byteIndex == editByteIdx_ && t.len == 2) {
                    int px = baseX + t.startCol * cellW;
                    int pw = t.len * cellW;
                    QColor editColor(0xff, 0xff, 0x00, 180);
                    painter.fillRect(px, y, pw, cellH, editColor);
                    break;
                }
            }
        }

        // Search match highlights — green background
        for (const HexSearchMatch& m : searchMatches_) {
            if (m.line != li) continue;
            for (const Token& t : l.tokens) {
                if (t.byteIndex >= 0 && t.byteIndex >= m.byteStart && t.byteIndex <= m.byteEnd) {
                    int px = baseX + t.startCol * cellW;
                    int pw = t.len * cellW;
                    QColor matchColor(0x00, 0xcc, 0x00, 120);
                    painter.fillRect(px, y, pw, cellH, matchColor);
                }
            }
        }

        // Bookmark glyph — small blue diamond in left margin
        if (bookmarks_.contains(l.addr)) {
            int bx = baseX - 10;
            int by = y + cellH / 2;
            painter.setPen(Qt::NoPen);
            painter.setBrush(QColor(0x33, 0x66, 0xcc));
            QPolygon diamond;
            diamond << QPoint(bx, by - 4) << QPoint(bx + 4, by)
                    << QPoint(bx, by + 4) << QPoint(bx - 4, by);
            painter.drawPolygon(diamond);
        }

        // --- Text pass ---
        for (const Token& tok : l.tokens) {
            int tx = baseX + tok.startCol * cellW;
            int ty = y + ascent;

            bool isPrimary = primOnLine &&
                tok.startCol == primCol && tok.len == primLen;
            bool isCross = (crossCol >= 0 &&
                tok.startCol == crossCol && tok.len == crossLen);

            // Editing nibble indicator — show only typed nibble dimmed
            bool isEditingByte = editing_ && li == editLine_ && tok.byteIndex == editByteIdx_ && tok.len == 2;

            if ((isPrimary || isCross) && byteStart < 0)
                painter.setPen(Qt::white);
            else if (isEditingByte)
                painter.setPen(QColor(0x80, 0x80, 0x00));
            else
                painter.setPen(colorTbl[static_cast<int>(tok.kind)]);

            painter.setFont(fontTbl[static_cast<int>(tok.kind)]);

            if (isEditingByte && editNibble_ == 1) {
                // Show first nibble, blank second nibble
                QString partial = tok.text.left(1) + QChar('_');
                painter.drawText(tx, ty, partial);
            } else {
                painter.drawText(tx, ty, tok.text);
            }
        }
    }

    // Caret
    if (hasFocus() && isCaretVisible()) {
        int cx = leftPad - scrollX + caretCol() * cellW;
        int cy = headerH + caretLine() * cellH - scrollY;
        painter.fillRect(cx, cy, 2, glyphH, EditorTheme::textColor());
    }

    // --- Column header row ---
    {
        int hx = leftPad - scrollX + 2;
        painter.fillRect(0, 0, vpW, headerH, EditorTheme::backgroundColor());
        painter.setFont(baseFont);
        QColor headerColor(0x00, 0x70, 0xc0);
        painter.setPen(headerColor);

        painter.drawText(hx + 0 * cellW, ascent, QStringLiteral("Offset(h)"));

        static const char* hexIdx[] = {
            "00","01","02","03","04","05","06","07",
            "08","09","0A","0B","0C","0D","0E","0F"
        };
        int hexCol[] = {
            11, 14, 17, 20, 23, 26, 29, 32,
            36, 39, 42, 45, 48, 51, 54, 57
        };
        for (int i = 0; i < 16; ++i)
            painter.drawText(hx + hexCol[i] * cellW, ascent, QLatin1String(hexIdx[i]));

        painter.drawText(hx + 61 * cellW, ascent, QStringLiteral("|"));
        painter.drawText(hx + 63 * cellW, ascent, QStringLiteral("Decoded text"));
    }
}

void HexView::contextMenuEvent(QContextMenuEvent* event) {
    auto hit = caretAtPos(event->pos());
    auto* doc = document();
    if (!doc || hit.line < 0 || hit.line >= doc->lineCount()) {
        QAbstractScrollArea::contextMenuEvent(event);
        return;
    }
    uint64_t addr = doc->line(hit.line).addr;
    int bi = byteIndexAt(hit.line, hit.col);
    if (bi >= 0) addr += static_cast<uint64_t>(bi);

    // Compute byte selection range from anchor/caret (same logic as paintEvent)
    int aLine = anchor_.line, aCol = anchor_.col;
    int cLine = caret_.line, cCol = caret_.col;
    int selByteIdx = -1;
    if (selectedToken_.len > 0)
        selByteIdx = byteIndexAt(selectedToken_.line, selectedToken_.startCol);

    int selL1 = -1, selL2 = -1, selB1 = -1, selB2 = -1;
    if (selByteIdx >= 0) {
        selL1 = selL2 = selectedToken_.line;
        selB1 = selB2 = selByteIdx;
    } else {
        int ab = byteIndexAt(aLine, aCol);
        int cb = byteIndexAt(cLine, cCol);
        if (ab >= 0 && cb >= 0) {
            selL1 = aLine; selL2 = cLine;
            selB1 = ab;    selB2 = cb;
        } else if (ab >= 0) {
            selL1 = selL2 = aLine;
            selB1 = selB2 = ab;
        }
    }
    if (selL1 >= 0 && (selL1 > selL2 || (selL1 == selL2 && selB1 > selB2))) {
        std::swap(selL1, selL2);
        std::swap(selB1, selB2);
    }

    QMenu menu(this);
    QAction* patchByte = menu.addAction(tr("Patch &Byte... @ 0x%1").arg(addr, 0, 16));
    QAction* nopFill = menu.addAction(tr("&NOP Fill... @ 0x%1").arg(addr, 0, 16));
    QAction* patchStr = menu.addAction(tr("Patch &String... @ 0x%1").arg(addr, 0, 16));
    menu.addSeparator();

    // Interpret As submenu
    QMenu* interpMenu = menu.addMenu(tr("&Interpret Selection As"));
    QAction* interpI8 = interpMenu->addAction(tr("Int8"));
    QAction* interpI16 = interpMenu->addAction(tr("Int16 (LE)"));
    QAction* interpI32 = interpMenu->addAction(tr("Int32 (LE)"));
    QAction* interpI64 = interpMenu->addAction(tr("Int64 (LE)"));
    QAction* interpU8 = interpMenu->addAction(tr("UInt8"));
    QAction* interpU16 = interpMenu->addAction(tr("UInt16 (LE)"));
    QAction* interpU32 = interpMenu->addAction(tr("UInt32 (LE)"));
    QAction* interpU64 = interpMenu->addAction(tr("UInt64 (LE)"));
    QAction* interpF32 = interpMenu->addAction(tr("Float (32-bit)"));
    QAction* interpF64 = interpMenu->addAction(tr("Double (64-bit)"));
    QAction* interpStr = interpMenu->addAction(tr("ASCII String"));
    Q_UNUSED(interpI8); Q_UNUSED(interpI16); Q_UNUSED(interpI32); Q_UNUSED(interpI64);
    Q_UNUSED(interpU8); Q_UNUSED(interpU16); Q_UNUSED(interpU32); Q_UNUSED(interpU64);
    Q_UNUSED(interpF32); Q_UNUSED(interpF64); Q_UNUSED(interpStr);
    interpMenu->setEnabled(selL1 >= 0);

    menu.addSeparator();
    QAction* actCopyHex = menu.addAction(tr("Copy &Hex String"));
    QAction* actCopyC = menu.addAction(tr("Copy as C &Array"));
    QAction* actCopyPy = menu.addAction(tr("Copy as &Python Bytes"));
    menu.addSeparator();
    QAction* actBookmark = menu.addAction(tr("Toggle &Bookmark (Ctrl+D)"));
    Q_UNUSED(actBookmark);
    menu.addSeparator();
    QAction* actUndo = menu.addAction(tr("&Undo (Ctrl+Z)"));
    QAction* actRedo = menu.addAction(tr("&Redo (Ctrl+Y)"));
    actUndo->setEnabled(canUndo());
    actRedo->setEnabled(canRedo());
    menu.addSeparator();
    QAction* actPaste = menu.addAction(tr("&Paste from Clipboard (Ctrl+V)"));

    QAction* chosen = menu.exec(event->globalPos());

    if (chosen == patchByte) {
        emit patchByteRequested(addr);
    } else if (chosen == nopFill) {
        bool ok = false;
        QString input = QInputDialog::getText(this,
            tr("NOP Fill Range"),
            tr("End address (inclusive):\n(e.g. 0x1A2F)"),
            QLineEdit::Normal,
            QString("0x%1").arg(addr + 0x10, 0, 16), &ok);
        if (!ok) return;
        uint64_t endAddr = input.toULongLong(&ok, 16);
        if (!ok || endAddr <= addr) return;
        emit patchNopFillRequested(addr, endAddr);
    } else if (chosen == patchStr) {
        emit patchStringRequested(addr);
    } else if (chosen == actCopyHex || chosen == actCopyC || chosen == actCopyPy) {
        if (selL1 < 0) return;

        QVector<uint8_t> selectedBytes;
        for (int li = selL1; li <= selL2; ++li) {
            const Line& ln = doc->line(li);
            int bStart = (li == selL1) ? selB1 : 0;
            int bEnd = (li == selL2) ? selB2 : 15;
            for (int bi = bStart; bi <= bEnd; ++bi) {
                for (const Token& tok : ln.tokens) {
                    if (tok.byteIndex == bi && tok.len == 2) {
                        bool ok;
                        selectedBytes.append(
                            static_cast<uint8_t>(tok.text.toUInt(&ok, 16)));
                        break;
                    }
                }
            }
        }
        if (selectedBytes.isEmpty()) return;

        QString result;
        if (chosen == actCopyHex) {
            for (int i = 0; i < selectedBytes.size(); ++i) {
                if (i > 0) result += ' ';
                result += QString("%1").arg(selectedBytes[i], 2, 16, QChar('0')).toUpper();
            }
        } else if (chosen == actCopyC) {
            result = "uint8_t data[] = { ";
            for (int i = 0; i < selectedBytes.size(); ++i) {
                if (i > 0) result += ", ";
                result += QString("0x%1").arg(selectedBytes[i], 2, 16, QChar('0'));
            }
            result += " };";
        } else {
            result = "b'";
            for (uint8_t b : selectedBytes) {
                if (b >= 0x20 && b <= 0x7e && b != '\'' && b != '\\')
                    result += QChar(b);
                else
                    result += QString("\\x%1").arg(b, 2, 16, QChar('0'));
            }
            result += "'";
        }
        QApplication::clipboard()->setText(result);
    } else if (chosen == actBookmark) {
        toggleBookmark(addr);
    } else if (selL1 >= 0) {
        // Interpret As actions — collect bytes and show interpretation
        QVector<uint8_t> interpBytes;
        for (int li = selL1; li <= selL2; ++li) {
            const Line& ln = doc->line(li);
            int bStart = (li == selL1) ? selB1 : 0;
            int bEnd = (li == selL2) ? selB2 : 15;
            for (int bi = bStart; bi <= bEnd; ++bi) {
                for (const Token& tok : ln.tokens) {
                    if (tok.byteIndex == bi && tok.len == 2) {
                        bool ok;
                        interpBytes.append(
                            static_cast<uint8_t>(tok.text.toUInt(&ok, 16)));
                        break;
                    }
                }
            }
        }
        if (interpBytes.isEmpty()) return;

        auto peekU = [&](int n) -> uint64_t {
            uint64_t v = 0;
            for (int i = 0; i < n && i < interpBytes.size(); ++i)
                v |= static_cast<uint64_t>(interpBytes[i]) << (i * 8);
            return v;
        };
        auto peekI = [&](int n) -> int64_t {
            uint64_t u = peekU(n);
            if (n < 8 && (u & (1ULL << (n * 8 - 1))))
                u |= ~((1ULL << (n * 8)) - 1);
            return static_cast<int64_t>(u);
        };

        QString interpResult;
        if (chosen == interpI8 && interpBytes.size() >= 1)
            interpResult = QString::number(static_cast<int8_t>(interpBytes[0]));
        else if (chosen == interpI16 && interpBytes.size() >= 2)
            interpResult = QString::number(static_cast<int16_t>(peekU(2)));
        else if (chosen == interpI32 && interpBytes.size() >= 4)
            interpResult = QString::number(static_cast<int32_t>(peekU(4)));
        else if (chosen == interpI64 && interpBytes.size() >= 8)
            interpResult = QString::number(peekI(8));
        else if (chosen == interpU8 && interpBytes.size() >= 1)
            interpResult = QString::number(interpBytes[0]);
        else if (chosen == interpU16 && interpBytes.size() >= 2)
            interpResult = QString::number(peekU(2));
        else if (chosen == interpU32 && interpBytes.size() >= 4)
            interpResult = QString::number(peekU(4));
        else if (chosen == interpU64 && interpBytes.size() >= 8)
            interpResult = QString::number(peekU(8));
        else if (chosen == interpF32 && interpBytes.size() >= 4) {
            float f;
            uint32_t u32 = static_cast<uint32_t>(peekU(4));
            memcpy(&f, &u32, sizeof(float));
            interpResult = QString::number(f, 'g', 8);
        } else if (chosen == interpF64 && interpBytes.size() >= 8) {
            double d;
            uint64_t u64 = peekU(8);
            memcpy(&d, &u64, sizeof(double));
            interpResult = QString::number(d, 'g', 16);
        } else if (chosen == interpStr) {
            for (uint8_t b : interpBytes) {
                if (b == 0) break;
                interpResult += (b >= 0x20 && b <= 0x7e) ? QChar(b) : QChar('.');
            }
        }

        if (!interpResult.isEmpty()) {
            QToolTip::showText(event->globalPos(),
                tr("<b>0x%1</b>: %2").arg(addr, 0, 16).arg(interpResult),
                this);
        }
    } else if (chosen == actUndo) {
        undoLastEdit();
    } else if (chosen == actRedo) {
        redoLastEdit();
    } else if (chosen == actPaste) {
        pasteFromClipboard();
    }
}
