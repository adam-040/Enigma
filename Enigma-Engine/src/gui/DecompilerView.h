#pragma once

#include <QPlainTextEdit>
#include <cstdint>

class CppHighlighter;

class DecompilerView : public QPlainTextEdit {
    Q_OBJECT
public:
    explicit DecompilerView(QWidget* parent = nullptr);
    void showDecompiled(const QString& text);
    void clear();

signals:
    void addressDoubleClicked(uint64_t addr);

protected:
    void mouseDoubleClickEvent(QMouseEvent* event) override;

private:
    CppHighlighter* highlighter_;
};
