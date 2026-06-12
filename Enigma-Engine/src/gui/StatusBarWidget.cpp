#include "StatusBarWidget.h"

StatusBarWidget::StatusBarWidget(QWidget* parent)
    : QStatusBar(parent)
{
    funcLabel_ = new QLabel(tr("No binary loaded"));
    addrLabel_ = new QLabel(QString());
    countLabel_ = new QLabel(QString());

    addWidget(funcLabel_, 1);
    addWidget(addrLabel_);
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

void StatusBarWidget::clear() {
    funcLabel_->setText(tr("No binary loaded"));
    addrLabel_->setText(QString());
    countLabel_->setText(QString());
}
