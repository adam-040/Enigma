#include "HexView.h"
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
#include "EditorTheme.h"

HexView::HexView(QWidget* parent)
    : FieldView(parent)
{
    setHeaderHeight(EditorTheme::cellHeight());

    // Adjust vertical scroll range to account for fixed column header row
    connect(verticalScrollBar(), &QScrollBar::rangeChanged, this, [this](int, int) {
        int hdr = EditorTheme::cellHeight();
        QScrollBar* sb = verticalScrollBar();
        sb->blockSignals(true);
        sb->setMaximum(sb->maximum() + hdr);
        sb->blockSignals(false);
    });
}

void HexView::setData(uint64_t baseAddr, const std::vector<uint8_t>& data) {
    baseAddr_ = baseAddr;
    endAddr_ = baseAddr + data.size();
    auto doc = std::make_unique<Document>();

    for (size_t offset = 0; offset < data.size(); offset += 16) {
        Line line;
        line.addr = baseAddr + offset;

        QString addrStr = QString("%1").arg(baseAddr + offset, 8, 16, QChar('0'));

        // 1. Address token
        Token addrTok;
        addrTok.text = addrStr;
        addrTok.kind = TokenKind::Address;
        addrTok.spaceAfter = 3;
        addrTok.addr = line.addr;
        line.tokens.push_back(addrTok);

        // 2. Hex tokens
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

        // 3. Separator between hex and ASCII
        Token sepTok;
        sepTok.text = QStringLiteral("|");
        sepTok.kind = TokenKind::Punctuation;
        sepTok.spaceAfter = 1;
        sepTok.addr = line.addr;
        line.tokens.push_back(sepTok);

        // 4. ASCII tokens (individual per byte)
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

    uint64_t imageBase = static_cast<uint64_t>(program->getImageBase().getOffset());

    auto doc = std::make_unique<Document>();

    // Helper to add 16-byte hex lines from a data buffer
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

    // Gap from imageBase to the first initialized block.
    // For old snapshots that lack IMAGE_HEADER, try to read real PE header bytes
    // from the original binary on disk.
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
            // Try to read real PE header bytes from the original binary file
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
            } else {
                // No binary available — don't show gap lines at all
            }
        }
    }

    // Real block data
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
    // selectedToken_ is set after a single click and cleared after a drag,
    // so its presence reliably distinguishes single-click from drag.
    int selByteIdx = -1;
    if (selectedToken_.len > 0)
        selByteIdx = byteIndexAt(selectedToken_.line, selectedToken_.startCol);

    int aLine = anchorLine(), aCol = anchorCol();
    int cLine = caretLine(), cCol = caretCol();
    bool hasByteRange = false;
    int byteL1 = 0, byteL2 = 0, byteB1 = 0, byteB2 = 0;

    if (selByteIdx >= 0) {
        // Single click on a byte token → 1-byte range at that index
        hasByteRange = true;
        byteL1 = byteL2 = selectedToken_.line;
        byteB1 = byteB2 = selByteIdx;
    } else {
        // Drag or no selection — use anchor/caret byte indices directly
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

        // Per-line byte range
        int byteStart = -1, byteEnd = -1;
        if (hasByteRange && li >= byteL1 && li <= byteL2) {
            byteStart = (li == byteL1) ? byteB1 : 0;
            byteEnd   = (li == byteL2) ? byteB2 : 15;
        }
        // Contiguous selection bounds per column
        int hexSelStart = INT_MAX, hexSelEnd = 0;
        int ascSelStart = INT_MAX, ascSelEnd = 0;
        // Primary selection info
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

            // Primary token detection
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

        // Find cross-column counterpart for primary selection
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

        // --- Fill pass (all backgrounds before text) ---

        // Hex byte-range selection — one solid contiguous block
        if (hexSelStart < hexSelEnd) {
            int hx = baseX + hexSelStart * cellW;
            int hw = (hexSelEnd - hexSelStart) * cellW;
            painter.fillRect(hx, y, hw, cellH, EditorTheme::selectionColor());
        }

        // ASCII byte-range selection — one solid contiguous block
        if (ascSelStart < ascSelEnd) {
            int ax = baseX + ascSelStart * cellW;
            int aw = (ascSelEnd - ascSelStart) * cellW;
            painter.fillRect(ax, y, aw, cellH, EditorTheme::selectionColor());
        }

        // Primary selection (only paint when byte-range does not already cover this token)
        if (primOnLine && byteStart < 0) {
            int px = baseX + primCol * cellW;
            int pw = primLen * cellW;
            painter.fillRect(px, y, pw, cellH, EditorTheme::primarySelectionColor());
        }

        // Cross-column sync for primary selection
        if (crossCol >= 0 && byteStart < 0) {
            int cx = baseX + crossCol * cellW;
            int cw = crossLen * cellW;
            painter.fillRect(cx, y, cw, cellH, EditorTheme::primarySelectionColor());
        }

        // Patch overlay — orange background for modified bytes
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

        // --- Text pass ---
        for (const Token& tok : l.tokens) {
            int tx = baseX + tok.startCol * cellW;
            int ty = y + ascent;

            bool isPrimary = primOnLine &&
                tok.startCol == primCol && tok.len == primLen;
            bool isCross = (crossCol >= 0 &&
                tok.startCol == crossCol && tok.len == crossLen);

            if ((isPrimary || isCross) && byteStart < 0)
                painter.setPen(Qt::white);
            else
                painter.setPen(colorTbl[static_cast<int>(tok.kind)]);

            painter.setFont(fontTbl[static_cast<int>(tok.kind)]);
            painter.drawText(tx, ty, tok.text);
        }
    }

    // Caret
    if (hasFocus() && isCaretVisible()) {
        int cx = leftPad - scrollX + caretCol() * cellW;
        int cy = headerH + caretLine() * cellH - scrollY;
        painter.fillRect(cx, cy, 2, glyphH, EditorTheme::textColor());
    }

    // --- Column header row (painted last so it stays on top and does not scroll vertically) ---
    {
        int hx = leftPad - scrollX + 2;
        painter.fillRect(0, 0, vpW, headerH, EditorTheme::backgroundColor());
        painter.setFont(baseFont);
        QColor headerColor(0x00, 0x70, 0xc0);
        painter.setPen(headerColor);

        // "Offset(h)" at address column (col 0)
        painter.drawText(hx + 0 * cellW, ascent, QStringLiteral("Offset(h)"));

        // Hex indices "00" - "0F" above each hex byte column
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

        // Separator before decoded text column
        painter.drawText(hx + 61 * cellW, ascent, QStringLiteral("|"));

        // "Decoded text" aligned with the ASCII column content (col 63)
        painter.drawText(hx + 63 * cellW, ascent, QStringLiteral("Decoded text"));
    }
}

void HexView::contextMenuEvent(QContextMenuEvent* event) {
    uint64_t addr = addressAtCurrentLine();
    if (addr == 0) {
        QAbstractScrollArea::contextMenuEvent(event);
        return;
    }

    // Adjust addr to the byte under cursor
    auto hit = caretAtPos(event->pos());
    int bi = byteIndexAt(hit.line, hit.col);
    if (bi >= 0) addr += static_cast<uint64_t>(bi);

    QMenu menu(this);
    QAction* patchByte = menu.addAction(tr("Patch &Byte... @ 0x%1").arg(addr, 0, 16));
    QAction* nopFill = menu.addAction(tr("&NOP Fill... @ 0x%1").arg(addr, 0, 16));
    QAction* patchStr = menu.addAction(tr("Patch &String... @ 0x%1").arg(addr, 0, 16));
    menu.addSeparator();
    QAction* chosen = menu.exec(event->globalPos());

    if (chosen == patchByte) {
        emit patchByteRequested(addr);
    } else if (chosen == nopFill) {
        bool ok = false;
        QString input = QInputDialog::getText(const_cast<HexView*>(this),
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
    }
}
