#include "HexView.h"
#include <QPainter>
#include <QPaintEvent>
#include <QScrollBar>

HexView::HexView(QWidget* parent)
    : QAbstractScrollArea(parent)
{
    font_ = QFont("Consolas", 10);
    setFont(font_);
}

void HexView::setData(uint64_t baseAddr, const std::vector<uint8_t>& data) {
    baseAddr_ = baseAddr;
    data_ = data;
    int lines = (data.size() + bytesPerLine_ - 1) / bytesPerLine_;
    QFontMetrics fm(font_);
    int lineHeight = fm.height() + 2;
    verticalScrollBar()->setRange(0, (lines * lineHeight) - viewport()->height());
    verticalScrollBar()->setValue(0);
    viewport()->update();
}

void HexView::clear() {
    data_.clear();
    viewport()->update();
}

void HexView::paintEvent(QPaintEvent* event) {
    QPainter painter(viewport());
    painter.setFont(font_);
    QFontMetrics fm(font_);
    int lineHeight = fm.height() + 2;
    int charWidth = fm.horizontalAdvance('0');

    int firstLine = event->rect().top() / lineHeight;
    int lastLine = (event->rect().bottom() + lineHeight - 1) / lineHeight;

    int addrWidth = 10 * charWidth;
    int hexStart = addrWidth + charWidth;
    int asciiStart = hexStart + (bytesPerLine_ * 3 + 1) * charWidth;

    for (int line = firstLine; line <= lastLine; ++line) {
        int offset = line * bytesPerLine_;
        if (offset >= (int)data_.size()) break;

        int y = line * lineHeight + fm.ascent();

        // Address column
        QString addrStr = QString("%1").arg(baseAddr_ + offset, 8, 16, QChar('0'));
        painter.setPen(QColor(0x88, 0x88, 0x88));
        painter.drawText(2, y, addrStr);

        // Hex column
        painter.setPen(QColor(0xd0, 0xd0, 0xd0));
        QString hexStr;
        for (int i = 0; i < bytesPerLine_; ++i) {
            if (offset + i < (int)data_.size())
                hexStr += QString("%1 ").arg(data_[offset + i], 2, 16, QChar('0'));
            else
                hexStr += "   ";
        }
        painter.drawText(hexStart, y, hexStr);

        // ASCII column
        painter.setPen(QColor(0xaa, 0xaa, 0xaa));
        QString asciiStr;
        for (int i = 0; i < bytesPerLine_; ++i) {
            if (offset + i >= (int)data_.size()) break;
            uint8_t b = data_[offset + i];
            asciiStr += (b >= 0x20 && b <= 0x7e) ? QChar(b) : QChar('.');
        }
        painter.drawText(asciiStart, y, asciiStr);
    }
}
