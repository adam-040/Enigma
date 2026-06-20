#include "CodePlainTextEdit.h"
#include "EditorTheme.h"
#include <QPainter>
#include <QTextBlock>
#include <QTextBlockFormat>
#include <QMenu>
#include <QClipboard>
#include <QApplication>
#include <QContextMenuEvent>
#include <QMouseEvent>
#include <QScrollBar>

CodePlainTextEdit::LineNumberArea::LineNumberArea(CodePlainTextEdit* editor)
    : QWidget(editor), editor_(editor)
{
}

QSize CodePlainTextEdit::LineNumberArea::sizeHint() const {
    return QSize(editor_->lineNumberAreaWidth(), 0);
}

void CodePlainTextEdit::LineNumberArea::paintEvent(QPaintEvent* event) {
    editor_->lineNumberAreaPaintEvent(event);
}

CodePlainTextEdit::CodePlainTextEdit(QWidget* parent)
    : QPlainTextEdit(parent)
{
    setFont(EditorTheme::baseFont());
    setReadOnly(true);
    setTextInteractionFlags(Qt::TextSelectableByKeyboard | Qt::TextSelectableByMouse);

    setStyleSheet(
        "QPlainTextEdit { background: #ffffff; color: #1e1e1e; border: none; }"
        "QPlainTextEdit:focus { border: none; }"
    );

    lineNumberArea_ = new LineNumberArea(this);
    connect(this, &QPlainTextEdit::blockCountChanged,
            this, &CodePlainTextEdit::updateLineNumberAreaWidth);
    connect(this, &QPlainTextEdit::updateRequest,
            this, &CodePlainTextEdit::updateLineNumberArea);
    connect(this, &QPlainTextEdit::cursorPositionChanged,
            this, &CodePlainTextEdit::highlightCurrentLine);
    updateLineNumberAreaWidth(0);
    highlightCurrentLine();
}

int CodePlainTextEdit::saveScrollPosition() const {
    return verticalScrollBar()->value();
}

void CodePlainTextEdit::restoreScrollPosition(int pos) {
    verticalScrollBar()->setValue(pos);
}

void CodePlainTextEdit::applyLineSpacing(double spacing) {
    QTextBlockFormat fmt;
    fmt.setLineHeight(
        static_cast<int>(fontMetrics().height() * spacing),
        QTextBlockFormat::FixedHeight);
    QTextCursor cursor(document());
    cursor.select(QTextCursor::Document);
    cursor.mergeBlockFormat(fmt);
}

int CodePlainTextEdit::lineNumberAreaWidth() const {
    int digits = 1;
    int max = qMax(1, document()->blockCount());
    while (max >= 10) { max /= 10; ++digits; }
    int space = 12 + fontMetrics().horizontalAdvance(QLatin1Char('9')) * digits;
    return space;
}

void CodePlainTextEdit::updateLineNumberAreaWidth(int) {
    setViewportMargins(lineNumberAreaWidth(), 0, 0, 0);
}

void CodePlainTextEdit::updateLineNumberArea(const QRect& rect, int dy) {
    if (dy)
        lineNumberArea_->scroll(0, dy);
    else
        lineNumberArea_->update(0, rect.y(), lineNumberArea_->width(), rect.height());
    if (rect.contains(viewport()->rect()))
        updateLineNumberAreaWidth(0);
}

void CodePlainTextEdit::highlightCurrentLine() {
    QTextEdit::ExtraSelection sel;
    sel.format.setBackground(QColor(0xf0, 0xf0, 0xf8));
    sel.format.setProperty(QTextFormat::FullWidthSelection, true);
    sel.cursor = textCursor();
    sel.cursor.clearSelection();
    setExtraSelections({sel});
}

void CodePlainTextEdit::mousePressEvent(QMouseEvent* event) {
    QPlainTextEdit::mousePressEvent(event);
}

void CodePlainTextEdit::resizeEvent(QResizeEvent* event) {
    QPlainTextEdit::resizeEvent(event);
    QRect cr = contentsRect();
    lineNumberArea_->setGeometry(
        QRect(cr.left(), cr.top(), lineNumberAreaWidth(), cr.height()));
}

void CodePlainTextEdit::contextMenuEvent(QContextMenuEvent* event) {
    QMenu menu(this);
    QAction* copy = menu.addAction(tr("Copy"));
    copy->setShortcut(QKeySequence::Copy);
    copy->setEnabled(textCursor().hasSelection());
    connect(copy, &QAction::triggered, this, [this]() {
        QApplication::clipboard()->setText(textCursor().selectedText());
    });
    QAction* selectAll = menu.addAction(tr("Select All"));
    selectAll->setShortcut(QKeySequence::SelectAll);
    connect(selectAll, &QAction::triggered, this, &QPlainTextEdit::selectAll);
    menu.exec(event->globalPos());
}

void CodePlainTextEdit::lineNumberAreaPaintEvent(QPaintEvent* event) {
    QPainter painter(lineNumberArea_);
    painter.fillRect(event->rect(), QColor(0xf5, 0xf5, 0xf5));

    QTextBlock block = firstVisibleBlock();
    int blockNumber = block.blockNumber();
    int top = qRound(blockBoundingGeometry(block).translated(contentOffset()).top());
    int bottom = top + qRound(blockBoundingRect(block).height());

    painter.setPen(QColor(0x88, 0x88, 0x88));
    QFont numFont = font();
    numFont.setPointSize(numFont.pointSize() - 1);
    painter.setFont(numFont);

    while (block.isValid() && top <= event->rect().bottom()) {
        if (block.isVisible() && bottom >= event->rect().top()) {
            QString number = QString::number(blockNumber + 1);
            painter.drawText(0, top, lineNumberArea_->width() - 6, fontMetrics().height(),
                             Qt::AlignRight, number);
        }
        block = block.next();
        top = bottom;
        bottom = top + qRound(blockBoundingRect(block).height());
        ++blockNumber;
    }
}
