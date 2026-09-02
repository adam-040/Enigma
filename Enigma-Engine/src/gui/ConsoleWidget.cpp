#include "ConsoleWidget.h"
#include <QVBoxLayout>
#include <QScrollBar>

ConsoleWidget::ConsoleWidget(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    tabs_ = new QTabWidget(this);
    tabs_->setToolTip(tr("Console output and diagnostic messages"));

    console_ = new QPlainTextEdit(this);
    console_->setReadOnly(true);
    console_->setFont(QFont("Consolas", 9));
    console_->setToolTip(tr("Application console log"));
    tabs_->addTab(console_, tr("Console"));

    output_ = new QPlainTextEdit(this);
    output_->setReadOnly(true);
    output_->setFont(QFont("Consolas", 9));
    output_->setToolTip(tr("Analysis and decompiler output"));
    tabs_->addTab(output_, tr("Output"));

    problems_ = new QPlainTextEdit(this);
    problems_->setReadOnly(true);
    problems_->setFont(QFont("Consolas", 9));
    problems_->setToolTip(tr("Errors and warnings encountered during analysis"));
    tabs_->addTab(problems_, tr("Problems"));

    search_ = new QPlainTextEdit(this);
    search_->setReadOnly(true);
    search_->setFont(QFont("Consolas", 9));
    search_->setToolTip(tr("Search results from function and string lookups"));
    tabs_->addTab(search_, tr("Search"));

    layout->addWidget(tabs_);
}

void ConsoleWidget::log(const QString& text) {
    console_->appendPlainText(text);
    console_->verticalScrollBar()->setValue(
        console_->verticalScrollBar()->maximum());
}

void ConsoleWidget::clear() {
    console_->clear();
    output_->clear();
    problems_->clear();
    search_->clear();
}
