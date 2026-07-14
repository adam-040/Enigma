#pragma once

#include <QFont>
#include <QColor>
#include "FieldView.h"

class EditorTheme {
public:
    static QFont baseFont();
    static QFont emphasisFont();

    static int cellWidth();
    static int cellHeight();
    static int ascent();
    static int descent();
    static int glyphHeight();
    static int leftPadding();
    static double lineSpacing();

    static QColor backgroundColor();
    static QColor textColor();
    static QColor caretLineColor();
    static QColor selectionColor();
    static QColor primarySelectionColor();
    static QColor occurrenceColor();
    static QColor colorFor(TokenKind kind);
    static bool isEmphasis(TokenKind kind);

    // Fast lookup arrays indexed by TokenKind (avoids per-token switch/virtual calls)
    static const QColor* colorTable();
    static const QFont* fontTable();
};
