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
    static QFont font = [] {
        QFont f = baseFont();
        f.setWeight(QFont::Medium);
        return f;
    }();
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
    case TokenKind::Bytes:       return QColor(0x55, 0x55, 0x55);
    case TokenKind::Mnemonic:    return QColor(0x00, 0x00, 0xc0);
    case TokenKind::Branch:      return QColor(0xd7, 0x3a, 0x49);
    case TokenKind::Register:    return QColor(0x00, 0x70, 0xc0);
    case TokenKind::Immediate:
    case TokenKind::Number:      return QColor(0xb8, 0x4e, 0x4e);
    case TokenKind::MemRef:      return QColor(0x8b, 0x45, 0x13);
    case TokenKind::Punctuation: return QColor(0x80, 0x80, 0x80);
    case TokenKind::Label:
    case TokenKind::Variable:    return QColor(0x6f, 0x42, 0xc1);
    case TokenKind::Function:    return QColor(0x6f, 0x42, 0xc1);
    case TokenKind::Type:        return QColor(0x0e, 0x8a, 0x8a);
    case TokenKind::Keyword:     return QColor(0x00, 0x00, 0xff);
    case TokenKind::String:      return QColor(0xa3, 0x15, 0x15);
    case TokenKind::Comment:     return QColor(0x6a, 0x99, 0x55);
    case TokenKind::BracesOuter: return QColor(0xb5, 0x89, 0x00);
    case TokenKind::BracesInner: return QColor(0xc0, 0x39, 0x2b);
    case TokenKind::Operator:    return textColor();
    case TokenKind::Semicolon:   return QColor(0xc0, 0x39, 0x2b);
    default:                     return textColor();
    }
}

bool EditorTheme::isEmphasis(TokenKind kind) {
    return kind == TokenKind::Mnemonic
        || kind == TokenKind::Branch
        || kind == TokenKind::Type
        || kind == TokenKind::Keyword
        || kind == TokenKind::BracesOuter
        || kind == TokenKind::BracesInner
        || kind == TokenKind::Semicolon
        || kind == TokenKind::Punctuation;
}

// Pre-computed lookup tables indexed by TokenKind for O(1) per-token access.
// Avoids per-token switch statements and virtual function calls in paint hot path.

static const int TOKEN_KIND_COUNT = 21; // Plain..Semicolon

const QColor* EditorTheme::colorTable() {
    static QColor table[TOKEN_KIND_COUNT] = {
        /* Plain     */ QColor(0x1e, 0x1e, 0x1e),
        /* Address   */ QColor(0x6a, 0x73, 0x7d),
        /* Bytes     */ QColor(0x55, 0x55, 0x55),
        /* Mnemonic  */ QColor(0x00, 0x00, 0xc0),
        /* Branch    */ QColor(0xd7, 0x3a, 0x49),
        /* Register  */ QColor(0x00, 0x70, 0xc0),
        /* Immediate */ QColor(0xb8, 0x4e, 0x4e),
        /* Number    */ QColor(0xb8, 0x4e, 0x4e),
        /* MemRef    */ QColor(0x8b, 0x45, 0x13),
        /* Punctuation */ QColor(0x80, 0x80, 0x80),
        /* Label     */ QColor(0x6f, 0x42, 0xc1),
        /* Function  */ QColor(0x6f, 0x42, 0xc1),
        /* Variable  */ QColor(0x6f, 0x42, 0xc1),
        /* Type      */ QColor(0x0e, 0x8a, 0x8a),
        /* Keyword   */ QColor(0x00, 0x00, 0xff),
        /* String    */ QColor(0xa3, 0x15, 0x15),
        /* Comment   */ QColor(0x6a, 0x99, 0x55),
        /* BracesOuter */ QColor(0xb5, 0x89, 0x00), // yellow
        /* BracesInner */ QColor(0xc0, 0x39, 0x2b), // red
        /* Operator  */ QColor(0x1e, 0x1e, 0x1e),    // dark/black
        /* Semicolon */ QColor(0xc0, 0x39, 0x2b),    // red
    };
    return table;
}

const QFont* EditorTheme::fontTable() {
    static QFont table[TOKEN_KIND_COUNT];
    static bool init = false;
    if (!init) {
        QFont base = baseFont();
        QFont emph = emphasisFont();
        for (int i = 0; i < TOKEN_KIND_COUNT; ++i) {
            TokenKind k = static_cast<TokenKind>(i);
            table[i] = isEmphasis(k) ? emph : base;
        }
        init = true;
    }
    return table;
}
