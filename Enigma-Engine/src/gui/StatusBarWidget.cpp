#include "StatusBarWidget.h"

StatusBarWidget::StatusBarWidget(QWidget* parent)
    : QStatusBar(parent)
{
    funcLabel_ = new QLabel(tr("No binary loaded"));
    addrLabel_ = new QLabel(QString());
    countLabel_ = new QLabel(QString());
    hexInfoLabel_ = new QLabel(QString());

    addWidget(funcLabel_, 1);
    addWidget(addrLabel_);
    addWidget(hexInfoLabel_);
    addPermanentWidget(countLabel_);
}

void StatusBarWidget::setFunction(const QString& name) {
    funcLabel_->setText(name);
}

void StatusBarWidget::setAddress(uint64_t addr) {
    addrLabel_->setText(QString("0x%1").arg(addr, 0, 16));
}

void StatusBarWidget::setFunctionCount(int count) {
    countLabel_->setText(tr("%1 functions").arg(count));
}

void StatusBarWidget::setHexInfo(uint64_t offset, int selectionSize, int bookmarkCount) {
    QString info = QString("Offset: 0x%1").arg(offset, 0, 16);
    if (selectionSize > 0)
        info += QString(" | Selection: %1 byte%2").arg(selectionSize).arg(selectionSize > 1 ? "s" : "");
    if (bookmarkCount > 0)
        info += QString(" | %1 bookmark%2").arg(bookmarkCount).arg(bookmarkCount > 1 ? "s" : "");
    hexInfoLabel_->setText(info);
}

void StatusBarWidget::clear() {
    funcLabel_->setText(tr("No binary loaded"));
    addrLabel_->setText(QString());
    countLabel_->setText(QString());
    hexInfoLabel_->setText(QString());
}
