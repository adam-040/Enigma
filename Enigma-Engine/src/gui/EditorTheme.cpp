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
    static const int w = [] {
        QFontMetrics fm(baseFont());
        return std::max(1, fm.horizontalAdvance(QLatin1Char('0')));
    }();
    return w;
}

int EditorTheme::cellHeight() {
    static const int h = [] {
        QFontMetrics fm(baseFont());
        const int rh = static_cast<int>(fm.height() * lineSpacing());
        return std::max(rh, fm.height());
    }();
    return h;
}

int EditorTheme::ascent() {
    static const int a = [] {
        QFontMetrics fm(baseFont());
        return fm.ascent();
    }();
    return a;
}

int EditorTheme::descent() {
    static const int d = [] {
        QFontMetrics fm(baseFont());
        return fm.descent();
    }();
    return d;
}

int EditorTheme::glyphHeight() {
    static const int h = ascent() + descent();
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

QColor EditorTheme::cfaColor(cfg::EdgeKind kind) {
    switch (kind) {
    case cfg::EdgeKind::Unconditional: return QColor(0x4f, 0x7f, 0xc0); // muted steel blue
    case cfg::EdgeKind::Conditional:   return QColor(0x7a, 0x9c, 0xb8); // muted gray-blue
    case cfg::EdgeKind::Call:          return QColor(0x7f, 0x6f, 0xc8); // muted violet
    case cfg::EdgeKind::Computed:      return QColor(0x4f, 0x7f, 0xc0); // blue, dashed
    case cfg::EdgeKind::ComputedCall:  return QColor(0x7f, 0x6f, 0xc8); // violet, dashed
    case cfg::EdgeKind::Return:        return QColor(0xc0, 0x6f, 0x63); // muted red stop
    }
    return QColor(0x4f, 0x7f, 0xc0);
}

QColor EditorTheme::blockTint(int parity) {
    // Subtle alternating wash behind basic blocks on the light theme.
    return (parity & 1) ? QColor(0xe9, 0xf0, 0xf8) : QColor(0xf7, 0xf9, 0xfc);
}

QColor EditorTheme::blockSeparatorColor() { return QColor(0xb8, 0xc2, 0xd0); }

QColor EditorTheme::colorFor(TokenKind kind) {
    switch (kind) {
    case TokenKind::Address:     return QColor(0x6a, 0x73, 0x7d);
    case TokenKind::Bytes:       return QColor(0x55, 0x55, 0x55);
    case TokenKind::Mnemonic:    return QColor(0x00, 0x00, 0xc0);
    case TokenKind::Branch:      return QColor(0xd7, 0x3a, 0x49);
    case TokenKind::Call:        return QColor(0x00, 0x85, 0x00);
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
        || kind == TokenKind::Call
        || kind == TokenKind::Type
        || kind == TokenKind::Keyword
        || kind == TokenKind::BracesOuter
        || kind == TokenKind::BracesInner
        || kind == TokenKind::Semicolon
        || kind == TokenKind::Punctuation;
}

// Pre-computed lookup tables indexed by TokenKind for O(1) per-token access.
// Avoids per-token switch statements and virtual function calls in paint hot path.

// Derived from the enum so adding new TokenKind values keeps the tables in sync,
// avoiding out-of-bounds access in the paint hot path.
static const int TOKEN_KIND_COUNT = static_cast<int>(TokenKind::Semicolon) + 1;

const QColor* EditorTheme::colorTable() {
    static QColor table[TOKEN_KIND_COUNT] = {
        /* Plain     */ QColor(0x1e, 0x1e, 0x1e),
        /* Address   */ QColor(0x6a, 0x73, 0x7d),
        /* Bytes     */ QColor(0x55, 0x55, 0x55),
        /* Mnemonic  */ QColor(0x00, 0x00, 0xc0),
        /* Branch    */ QColor(0xd7, 0x3a, 0x49),
        /* Call      */ QColor(0x00, 0x85, 0x00),
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
