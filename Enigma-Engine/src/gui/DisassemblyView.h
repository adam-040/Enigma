#pragma once

#include <QPlainTextEdit>
#include <QElapsedTimer>
#include <cstdint>

class AsmHighlighter;

class DisassemblyView : public QPlainTextEdit {
    Q_OBJECT
public:
    explicit DisassemblyView(QWidget* parent = nullptr);
    void showDisassembly(const QString& text);
    void clear();

    int scrollLine() const { return scrollLine_; }
    void setScrollLine(int line) { scrollLine_ = line; }

signals:
    void addressDoubleClicked(uint64_t addr);

protected:
    void mouseDoubleClickEvent(QMouseEvent* event) override;

private:
    AsmHighlighter* highlighter_;
    QElapsedTimer navTimer_;
    int scrollLine_ = 0;
};
