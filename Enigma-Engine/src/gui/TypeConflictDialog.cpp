#include "TypeConflictDialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QDialogButtonBox>
#include <QHeaderView>
#include <QLineEdit>
#include <QGroupBox>
#include <QLabel>
#include <QPushButton>
#include <QSplitter>
#include <QFont>
#include <sstream>
#include <ghidra/Composite.h>

namespace ghidra {

TypeConflictDialog::TypeConflictDialog(DataType* existing, DataType* incoming, QWidget* parent)
    : QDialog(parent), existing_(existing), incoming_(incoming)
{
    setWindowTitle(tr("Type Conflict"));
    setMinimumSize(700, 450);

    auto* mainLayout = new QVBoxLayout(this);

    auto* infoLabel = new QLabel(tr(
        "A type conflict was detected. The existing type and the incoming type "
        "have the same name but different definitions."), this);
    infoLabel->setWordWrap(true);
    mainLayout->addWidget(infoLabel);

    auto* splitter = new QSplitter(Qt::Horizontal, this);

    auto* existingGroup = new QGroupBox(tr("Existing Type"), this);
    auto* existingLayout = new QVBoxLayout(existingGroup);
    existingTree_ = new QTreeWidget(existingGroup);
    existingTree_->setHeaderLabels({tr("Offset"), tr("Size"), tr("Type"), tr("Name")});
    existingTree_->header()->setStretchLastSection(true);
    existingTree_->setAlternatingRowColors(true);
    existingLayout->addWidget(existingTree_);
    populateTree(existingTree_, existing_);
    splitter->addWidget(existingGroup);

    auto* incomingGroup = new QGroupBox(tr("Incoming Type"), this);
    auto* incomingLayout = new QVBoxLayout(incomingGroup);
    incomingTree_ = new QTreeWidget(incomingGroup);
    incomingTree_->setHeaderLabels({tr("Offset"), tr("Size"), tr("Type"), tr("Name")});
    incomingTree_->header()->setStretchLastSection(true);
    incomingTree_->setAlternatingRowColors(true);
    incomingLayout->addWidget(incomingTree_);
    populateTree(incomingTree_, incoming_);
    splitter->addWidget(incomingGroup);

    splitter->setStretchFactor(0, 1);
    splitter->setStretchFactor(1, 1);
    mainLayout->addWidget(splitter);

    auto* renameRow = new QHBoxLayout;
    renameRow->addWidget(new QLabel(tr("New name if renamed:"), this));
    newNameEdit_ = new QLineEdit(this);
    newNameEdit_->setText(QString::fromStdString(incoming_->getName()) + "_renamed");
    newNameEdit_->setEnabled(false);
    renameRow->addWidget(newNameEdit_);
    mainLayout->addLayout(renameRow);

    auto* btnBox = new QDialogButtonBox(this);
    auto* keepBtn = btnBox->addButton(tr("Keep Existing"), QDialogButtonBox::AcceptRole);
    keepBtn->setToolTip(tr("Discard the incoming type and keep the existing definition"));
    auto* replaceBtn = btnBox->addButton(tr("Replace with New"), QDialogButtonBox::AcceptRole);
    replaceBtn->setToolTip(tr("Overwrite the existing type with the incoming definition"));
    auto* renameBtn = btnBox->addButton(tr("Rename New"), QDialogButtonBox::AcceptRole);
    renameBtn->setToolTip(tr("Add the incoming type under a new name"));
    auto* cancelBtn = btnBox->addButton(QDialogButtonBox::Cancel);
    mainLayout->addWidget(btnBox);

    connect(keepBtn, &QPushButton::clicked, this, &TypeConflictDialog::onKeepExisting);
    connect(replaceBtn, &QPushButton::clicked, this, &TypeConflictDialog::onReplaceWithNew);
    connect(renameBtn, &QPushButton::clicked, this, &TypeConflictDialog::onRenameNew);
    connect(cancelBtn, &QPushButton::clicked, this, &TypeConflictDialog::reject);
}

void TypeConflictDialog::populateTree(QTreeWidget* tree, DataType* dt) {
    tree->clear();
    if (!dt) {
        auto* item = new QTreeWidgetItem(tree);
        item->setText(0, tr("(null)"));
        return;
    }

    auto* nameItem = new QTreeWidgetItem(tree);
    nameItem->setText(0, tr("Name"));
    nameItem->setText(1, QString::fromStdString(dt->getName()));
    nameItem->setForeground(1, QColor(0x1a, 0x7f, 0x37));
    QFont boldFont;
    boldFont.setBold(true);
    nameItem->setFont(1, boldFont);

    auto* sizeItem = new QTreeWidgetItem(tree);
    sizeItem->setText(0, tr("Size"));
    sizeItem->setText(1, QStringLiteral("%1 bytes").arg(dt->getLength()));

    auto* catItem = new QTreeWidgetItem(tree);
    catItem->setText(0, tr("Category"));
    catItem->setText(1, QString::fromStdString(dt->getPathName()));

    Composite* comp = dynamic_cast<Composite*>(dt);
    if (comp && comp->getNumComponents() > 0) {
        auto* fieldsHeader = new QTreeWidgetItem(tree);
        fieldsHeader->setText(0, tr("Fields"));
        fieldsHeader->setForeground(0, QColor(0x33, 0x33, 0x99));
        fieldsHeader->setFont(0, boldFont);

        for (int i = 0; i < comp->getNumComponents(); ++i) {
            DataTypeComponent* c = comp->getComponent(i);
            if (!c) continue;

            auto* row = new QTreeWidgetItem(fieldsHeader);
            row->setText(0, QStringLiteral("0x%1").arg(c->getOffset(), 0, 16));
            row->setText(1, QStringLiteral("%1").arg(c->getLength()));
            row->setText(2, c->getDataType() ? QString::fromStdString(c->getDataType()->getName()) : QStringLiteral("?"));
            row->setText(3, QString::fromStdString(c->getFieldName()));
        }
        fieldsHeader->setExpanded(true);
    }
}

void TypeConflictDialog::onKeepExisting() {
    resolution_ = Resolution::KeepExisting;
    accept();
}

void TypeConflictDialog::onReplaceWithNew() {
    resolution_ = Resolution::ReplaceWithNew;
    accept();
}

void TypeConflictDialog::onRenameNew() {
    resolution_ = Resolution::RenameNew;
    accept();
}

} // namespace ghidra
