#include "EditorTheme.h"
#include <QFontMetrics>

QFont EditorTheme::baseFont() {
    static QFont font = [] {
        QFont f({"JetBrains Mono", "Cascadia Code", "Consolas", "Courier New"}, 10);
        f.setStyleHint(QFont::Monospace);
        f.setFixedPitch(true);
        f.setWeight(QFont::Normal);
        f.setKerning(false);
        return f;
    }();
    return font;
}

QFont EditorTheme::emphasisFont() {
    QFont font = baseFont();
    font.setWeight(QFont::Medium);
    return font;
}

int EditorTheme::cellWidth() {
    static int w = -1;
    if (w < 0) {
        QFontMetrics fm(baseFont());
        w = std::max(1, fm.horizontalAdvance(QLatin1Char('0')));
    }
    return w;
}

int EditorTheme::cellHeight() {
    static int h = -1;
    if (h < 0) {
        QFontMetrics fm(baseFont());
        h = static_cast<int>(fm.height() * lineSpacing());
        if (h < fm.height()) h = fm.height();
    }
    return h;
}

int EditorTheme::ascent() {
    static int a = -1;
    if (a < 0) {
        QFontMetrics fm(baseFont());
        a = fm.ascent();
    }
    return a;
}

int EditorTheme::descent() {
    static int d = -1;
    if (d < 0) {
        QFontMetrics fm(baseFont());
        d = fm.descent();
    }
    return d;
}

int EditorTheme::glyphHeight() {
    static int h = -1;
    if (h < 0) {
        h = ascent() + descent();
    }
    return h;
}

int EditorTheme::leftPadding() {
    return 8;
}

double EditorTheme::lineSpacing() {
    return 1.35;
}

QColor EditorTheme::backgroundColor() { return QColor(0xff, 0xff, 0xff); }
QColor EditorTheme::textColor()       { return QColor(0x1e, 0x1e, 0x1e); }
QColor EditorTheme::caretLineColor()  { return QColor(0xcc, 0xe5, 0xff); }
QColor EditorTheme::selectionColor()         { return QColor(33, 99, 255, 0x55); }
QColor EditorTheme::primarySelectionColor()  { return QColor(0x00, 0x78, 0xd4, 0xcc); }
QColor EditorTheme::occurrenceColor()        { return QColor(255, 226, 138, 0x88); }

QColor EditorTheme::colorFor(TokenKind kind) {
    switch (kind) {
    case TokenKind::Address:     return QColor(0x6a, 0x73, 0x7d);
    case TokenKind::Bytes:       return QColor(0x99, 0x99, 0x99);
    case TokenKind::Mnemonic:    return QColor(0x00, 0x00, 0xc0);
    case TokenKind::Branch:      return QColor(0xd7, 0x3a, 0x49);
    case TokenKind::Register:    return QColor(0x00, 0x70, 0xc0);
    case TokenKind::Immediate:
    case TokenKind::Number:      return QColor(0xb8, 0x4e, 0x4e);
    case TokenKind::MemRef:      return QColor(0x8b, 0x45, 0x13);
    case TokenKind::Punctuation: return QColor(0x60, 0x60, 0x60);
    case TokenKind::Label:
    case TokenKind::Function:
    case TokenKind::Variable:    return QColor(0x6f, 0x42, 0xc1);
    case TokenKind::Type:        return QColor(0x0e, 0x8a, 0x8a);
    case TokenKind::Keyword:     return QColor(0x00, 0x00, 0xff);
    case TokenKind::String:      return QColor(0xa3, 0x15, 0x15);
    case TokenKind::Comment:     return QColor(0x6a, 0x99, 0x55);
    default:                     return textColor();
    }
}

bool EditorTheme::isEmphasis(TokenKind kind) {
    return kind == TokenKind::Mnemonic
        || kind == TokenKind::Branch
        || kind == TokenKind::Type
        || kind == TokenKind::Keyword;
}
