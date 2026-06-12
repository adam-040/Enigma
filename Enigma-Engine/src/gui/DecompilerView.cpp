#include "DecompilerView.h"
#include "CppHighlighter.h"
#include <QMouseEvent>
#include <QTextCursor>
#include <QRegularExpression>

DecompilerView::DecompilerView(QWidget* parent)
    : QPlainTextEdit(parent)
{
    setReadOnly(true);
    setFont(QFont("Consolas", 10));
    setLineWrapMode(QPlainTextEdit::NoWrap);
    highlighter_ = new CppHighlighter(document());
}

void DecompilerView::showDecompiled(const QString& text) {
    clear();
    setPlainText(text);
}

void DecompilerView::clear() {
    QPlainTextEdit::clear();
}

void DecompilerView::mouseDoubleClickEvent(QMouseEvent* event) {
    QTextCursor cursor = cursorForPosition(event->pos());
    cursor.select(QTextCursor::WordUnderCursor);
    QString word = cursor.selectedText();

    static QRegularExpression hexRe("0x[0-9a-fA-F]+");
    auto match = hexRe.match(word);
    if (match.hasMatch()) {
        bool ok;
        uint64_t addr = match.captured().toULongLong(&ok, 16);
        if (ok && addr > 0) {
            emit addressDoubleClicked(addr);
            return;
        }
    }

    QPlainTextEdit::mouseDoubleClickEvent(event);
}
