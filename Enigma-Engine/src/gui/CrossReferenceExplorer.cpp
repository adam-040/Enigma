#include "CrossReferenceExplorer.h"
#include <QVBoxLayout>
#include <QHeaderView>
#include <ghidra/Reference.h>
#include <ghidra/RefType.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Symbol.h>

CrossReferenceExplorer::CrossReferenceExplorer(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    tree_ = new QTreeWidget(this);
    tree_->setHeaderLabels({tr("Type"), tr("From"), tr("To")});
    tree_->setRootIsDecorated(false);
    tree_->setAlternatingRowColors(true);
    tree_->setSelectionMode(QAbstractItemView::SingleSelection);
    tree_->header()->setStretchLastSection(true);
    layout->addWidget(tree_);

    connect(tree_, &QTreeWidget::itemDoubleClicked,
            this, &CrossReferenceExplorer::onItemDoubleClicked);
}

void CrossReferenceExplorer::clear() {
    tree_->clear();
    tree_->setHeaderLabels({tr("Type"), tr("From"), tr("To")});
}

void CrossReferenceExplorer::showReferencesTo(const ghidra::Address& addr,
                                               const std::string& name,
                                               ghidra::ReferenceManager* refMgr) {
    tree_->clear();
    tree_->setHeaderLabels({
        QString::fromStdString("XRefs to " + name + " @" + addr.toString())
    });

    if (!refMgr) return;

    auto refs = refMgr->getReferencesTo(addr);
    for (auto* ref : refs) {
        if (!ref) continue;
        auto* item = new QTreeWidgetItem(tree_);
        item->setText(0, QString::fromStdString(ref->getReferenceType()->getName()));
        item->setText(1, QString::fromStdString(ref->getFromAddress().toString()));
        item->setText(2, QString::fromStdString(addr.toString()));
        item->setData(1, Qt::UserRole,
                      static_cast<qulonglong>(ref->getFromAddress().getOffset()));
        item->setData(2, Qt::UserRole,
                      static_cast<qulonglong>(addr.getOffset()));
    }

    for (int i = 0; i < tree_->columnCount(); ++i)
        tree_->resizeColumnToContents(i);
}

void CrossReferenceExplorer::showReferencesFrom(const ghidra::Address& addr,
                                                 const std::string& name,
                                                 ghidra::ReferenceManager* refMgr) {
    tree_->clear();
    tree_->setHeaderLabels({
        QString::fromStdString("Refs from " + name + " @" + addr.toString())
    });

    if (!refMgr) return;

    auto refs = refMgr->getReferencesFrom(addr);
    for (auto* ref : refs) {
        if (!ref) continue;
        auto* item = new QTreeWidgetItem(tree_);
        item->setText(0, QString::fromStdString(ref->getReferenceType()->getName()));
        item->setText(1, QString::fromStdString(addr.toString()));
        item->setText(2, QString::fromStdString(ref->getToAddress().toString()));
        item->setData(1, Qt::UserRole,
                      static_cast<qulonglong>(addr.getOffset()));
        item->setData(2, Qt::UserRole,
                      static_cast<qulonglong>(ref->getToAddress().getOffset()));
    }

    for (int i = 0; i < tree_->columnCount(); ++i)
        tree_->resizeColumnToContents(i);
}

void CrossReferenceExplorer::onItemDoubleClicked(QTreeWidgetItem* item, int) {
    if (!item) return;
    uint64_t fromAddr = item->data(1, Qt::UserRole).toULongLong();
    uint64_t toAddr = item->data(2, Qt::UserRole).toULongLong();
    emit referenceSelected(fromAddr, toAddr);
}
