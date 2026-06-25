#include "HexView.h"
#include <QScrollBar>

HexView::HexView(QWidget* parent)
    : FieldView(parent)
{
}

void HexView::setData(uint64_t baseAddr, const std::vector<uint8_t>& data) {
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

void HexView::clear() {
    clearDocument();
}
