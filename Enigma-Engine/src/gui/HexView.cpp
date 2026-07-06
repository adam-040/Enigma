#include "HexView.h"
#include <ghidra/ProgramDB.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <QScrollBar>
#include <QFile>

HexView::HexView(QWidget* parent)
    : FieldView(parent)
{
}

void HexView::setData(uint64_t baseAddr, const std::vector<uint8_t>& data) {
    baseAddr_ = baseAddr;
    endAddr_ = baseAddr + data.size();
    auto doc = std::make_unique<Document>();

    for (size_t offset = 0; offset < data.size(); offset += 16) {
        Line line;
        line.addr = baseAddr + offset;

        QString addrStr = QString("%1").arg(baseAddr + offset, 8, 16, QChar('0'));
        QString asciiStr;
        for (int i = 0; i < 16; ++i) {
            if (offset + i < data.size()) {
                uint8_t b = data[offset + i];
                asciiStr += (b >= 0x20 && b <= 0x7e) ? QChar(b) : QChar('.');
            } else {
                asciiStr += QChar(' ');
            }
        }

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
                hexTok.kind = TokenKind::Bytes; // Draw dummy/empty bytes in a light-grey style
            }
            hexTok.spaceAfter = (i == 7) ? 2 : ((i == 15) ? 2 : 1);
            hexTok.addr = line.addr;
            line.tokens.push_back(hexTok);
        }

        // 3. ASCII token
        Token asciiTok;
        asciiTok.text = asciiStr;
        asciiTok.kind = TokenKind::Plain;
        asciiTok.spaceAfter = 0;
        asciiTok.addr = line.addr;
        line.tokens.push_back(asciiTok);

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

            QString asciiStr;
            for (int i = 0; i < 16; ++i) {
                Token hexTok;
                int idx = offset + i;
                if (data && idx < dataLen) {
                    uint8_t b = data[idx];
                    hexTok.text = QString("%1").arg(b, 2, 16, QChar('0'));
                    hexTok.kind = TokenKind::Plain;
                    asciiStr += (b >= 0x20 && b <= 0x7e) ? QChar(b) : QChar('.');
                } else {
                    hexTok.text = QStringLiteral("00");
                    hexTok.kind = TokenKind::Bytes;
                    asciiStr += QChar('.');
                }
                hexTok.spaceAfter = (i == 7) ? 2 : ((i == 15) ? 2 : 1);
                hexTok.addr = lineAddr;
                line.tokens.push_back(hexTok);
            }

            Token asciiTok;
            asciiTok.text = asciiStr;
            asciiTok.kind = TokenKind::Plain;
            asciiTok.spaceAfter = 0;
            asciiTok.addr = lineAddr;
            line.tokens.push_back(asciiTok);

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
