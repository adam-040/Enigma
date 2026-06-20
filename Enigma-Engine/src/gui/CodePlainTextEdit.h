#pragma once

#include <QPlainTextEdit>
#include <QWidget>

class CodePlainTextEdit : public QPlainTextEdit {
    Q_OBJECT
public:
    explicit CodePlainTextEdit(QWidget* parent = nullptr);

    int saveScrollPosition() const;
    void restoreScrollPosition(int pos);

    void applyLineSpacing(double spacing);

protected:
    void resizeEvent(QResizeEvent* event) override;
    void contextMenuEvent(QContextMenuEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;

private slots:
    void updateLineNumberAreaWidth(int newBlockCount);
    void updateLineNumberArea(const QRect& rect, int dy);
    void highlightCurrentLine();

private:
    void lineNumberAreaPaintEvent(QPaintEvent* event);
    int lineNumberAreaWidth() const;

    class LineNumberArea : public QWidget {
    public:
        LineNumberArea(CodePlainTextEdit* editor);
        QSize sizeHint() const override;
    protected:
        void paintEvent(QPaintEvent* event) override;
    private:
        CodePlainTextEdit* editor_;
    };

    friend class LineNumberArea;
    LineNumberArea* lineNumberArea_;
};
