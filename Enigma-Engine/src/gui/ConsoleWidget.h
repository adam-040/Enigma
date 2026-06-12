#pragma once

#include <QWidget>
#include <QTabWidget>
#include <QPlainTextEdit>

class ConsoleWidget : public QWidget {
    Q_OBJECT
public:
    explicit ConsoleWidget(QWidget* parent = nullptr);
    void log(const QString& text);
    void clear();

private:
    QTabWidget* tabs_;
    QPlainTextEdit* console_;
    QPlainTextEdit* output_;
    QPlainTextEdit* problems_;
    QPlainTextEdit* search_;
};
