#include "FunctionExplorer.h"
#include <QHeaderView>

FunctionExplorer::FunctionExplorer(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    tree_ = new QTreeWidget(this);
    tree_->setHeaderLabels({tr("Name"), tr("Address")});
    tree_->setAlternatingRowColors(true);
    tree_->header()->setStretchLastSection(false);
    tree_->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    tree_->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    layout->addWidget(tree_);

    filter_ = new QLineEdit(this);
    filter_->setPlaceholderText(tr("Filter..."));
    layout->addWidget(filter_);

    connect(tree_, &QTreeWidget::itemDoubleClicked,
            this, &FunctionExplorer::onItemDoubleClicked);
    connect(filter_, &QLineEdit::textChanged,
            this, &FunctionExplorer::onFilterChanged);
}

void FunctionExplorer::clear() {
    tree_->clear();
}

QTreeWidgetItem* FunctionExplorer::addCategory(const QString& name) {
    auto* item = new QTreeWidgetItem(tree_);
    item->setText(0, name);
    item->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);
    item->setExpanded(true);
    return item;
}

void FunctionExplorer::addEntry(QTreeWidgetItem* parent, uint64_t addr, const QString& name) {
    auto* item = new QTreeWidgetItem(parent);
    item->setText(0, name);
    item->setText(1, QString("0x%1").arg(addr, 0, 16));
    item->setData(0, Qt::UserRole, static_cast<qlonglong>(addr));
}

void FunctionExplorer::setFilter(const QString& text) {
    filter_->setText(text);
}

void FunctionExplorer::onItemDoubleClicked(QTreeWidgetItem* item, int) {
    if (!item || item->childCount() > 0) return;
    uint64_t addr = static_cast<uint64_t>(item->data(0, Qt::UserRole).toLongLong());
    emit functionSelected(addr, item->text(0));
}

void FunctionExplorer::onFilterChanged(const QString& text) {
    for (int i = 0; i < tree_->topLevelItemCount(); ++i) {
        QTreeWidgetItem* top = tree_->topLevelItem(i);
        bool topMatch = text.isEmpty() ||
            top->text(0).contains(text, Qt::CaseInsensitive);
        bool childVisible = false;
        for (int j = 0; j < top->childCount(); ++j) {
            QTreeWidgetItem* child = top->child(j);
            bool match = text.isEmpty() ||
                child->text(0).contains(text, Qt::CaseInsensitive) ||
                child->text(1).contains(text, Qt::CaseInsensitive);
            child->setHidden(!match);
            if (match) childVisible = true;
        }
        top->setHidden(!topMatch && !childVisible);
    }
}
