#include "StructureEditorWidget.h"
#include <ghidra/Program.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/Category.h>
#include <ghidra/CategoryPath.h>
#include <ghidra/Structure.h>
#include <ghidra/Union.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/UnionDataType.h>
#include <ghidra/DataTypeComponent.h>
#include <ghidra/Msg.h>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QMessageBox>
#include <QInputDialog>

namespace ghidra {

StructureEditorWidget::StructureEditorWidget(QWidget* parent)
    : QWidget(parent) {
    setupUI();
}

void StructureEditorWidget::setupUI() {
    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(2, 2, 2, 2);
    mainLayout->setSpacing(2);

    // Toolbar row: filter + buttons in a single line
    auto* toolbar = new QHBoxLayout();
    toolbar->setSpacing(2);
    filterEdit_ = new QLineEdit(this);
    filterEdit_->setPlaceholderText("Filter...");
    filterEdit_->setClearButtonEnabled(true);
    connect(filterEdit_, &QLineEdit::textChanged, this, &StructureEditorWidget::onFilterChanged);
    toolbar->addWidget(filterEdit_, 1);

    auto* addStructBtn = new QPushButton("+S", this);
    addStructBtn->setToolTip("Add Structure");
    addStructBtn->setFixedWidth(32);
    connect(addStructBtn, &QPushButton::clicked, this, &StructureEditorWidget::onAddStructure);
    toolbar->addWidget(addStructBtn);

    auto* addUnionBtn = new QPushButton("+U", this);
    addUnionBtn->setToolTip("Add Union");
    addUnionBtn->setFixedWidth(32);
    connect(addUnionBtn, &QPushButton::clicked, this, &StructureEditorWidget::onAddUnion);
    toolbar->addWidget(addUnionBtn);

    mainLayout->addLayout(toolbar);

    // Tree view
    treeView_ = new QTreeView(this);
    treeView_->setHeaderHidden(true);
    treeView_->setContextMenuPolicy(Qt::CustomContextMenu);
    treeView_->setAlternatingRowColors(true);
    treeView_->setSelectionMode(QAbstractItemView::SingleSelection);

    treeModel_ = new QStandardItemModel(this);
    treeView_->setModel(treeModel_);

    connect(treeView_, &QTreeView::customContextMenuRequested, this, &StructureEditorWidget::onTreeContextMenu);
    connect(treeView_, &QTreeView::doubleClicked, this, &StructureEditorWidget::onTreeDoubleClicked);

    mainLayout->addWidget(treeView_);

    // Status bar
    statusLabel_ = new QLabel("No program loaded", this);
    mainLayout->addWidget(statusLabel_);
}

void StructureEditorWidget::setProgram(Program* program) {
    program_ = program;
    dtm_ = program ? program->getDataTypeManager() : nullptr;
    refreshTree();
}

void StructureEditorWidget::refreshTree() {
    treeModel_->clear();

    if (!program_ || !dtm_) {
        statusLabel_->setText("No program loaded");
        return;
    }

    int structCount = 0;
    int unionCount = 0;
    int totalTypes = 0;

    // Add root categories
    Category* rootCat = dtm_->getRootCategory();
    if (rootCat) {
        populateCategories(treeModel_->invisibleRootItem(), rootCat);
    }

    // Count types
    auto allTypes = dtm_->getDataTypes();
    for (auto* dt : allTypes) {
        if (!dt) continue;
        totalTypes++;
        std::string name = dt->getName();
        if (name.find("struct ") != std::string::npos) structCount++;
        else if (name.find("union ") != std::string::npos) unionCount++;
    }

    statusLabel_->setText(QString("%1 types (%2 structs, %3 unions)")
        .arg(totalTypes).arg(structCount).arg(unionCount));

    treeView_->expandAll();
}

void StructureEditorWidget::populateCategories(QStandardItem* parent, void* category) {
    Category* cat = static_cast<Category*>(category);
    if (!cat) return;

    QString catName = QString::fromStdString(cat->getName());
    if (catName.isEmpty()) catName = "Root";

    auto* catItem = new QStandardItem(catName);
    catItem->setIcon(QIcon(":/resources/folder-free.svg"));
    catItem->setData(QVariant::fromValue(reinterpret_cast<quintptr>(category)), Qt::UserRole);
    parent->appendRow(catItem);

    // Populate sub-categories
    auto subCats = cat->getCategories();
    for (auto* subCat : subCats) {
        populateCategories(catItem, subCat);
    }

    // Populate data types in this category
    auto dataTypes = cat->getDataTypes();
    for (auto* dt : dataTypes) {
        if (!dt) continue;
        QString typeName = QString::fromStdString(dt->getName());
        auto* typeItem = new QStandardItem(typeName);
        typeItem->setData(QVariant::fromValue(reinterpret_cast<quintptr>(dt)), Qt::UserRole);

        // Different icons for different types
        Structure* asStruct = dynamic_cast<Structure*>(dt);
        Union* asUnion = dynamic_cast<Union*>(dt);
        if (asStruct) {
            typeItem->setIcon(QIcon(":/resources/type.svg"));
        } else if (asUnion) {
            typeItem->setIcon(QIcon(":/resources/type.svg"));
        } else {
            typeItem->setIcon(QIcon(":/resources/type.svg"));
        }

        catItem->appendRow(typeItem);
    }
}

void StructureEditorWidget::populateTypeChildren(QStandardItem* parent, void* dataType) {
    DataType* dt = static_cast<DataType*>(dataType);
    Structure* asStruct = dynamic_cast<Structure*>(dt);
    Union* asUnion = dynamic_cast<Union*>(dt);

    if (asStruct) {
        for (int i = 0; i < asStruct->getNumComponents(); ++i) {
            auto* comp = asStruct->getComponent(i);
            if (!comp) continue;
            QString fieldName = QString::fromStdString(comp->getFieldName());
            if (fieldName.isEmpty()) fieldName = QString::fromStdString(comp->getDataType()->getName());
            auto* fieldItem = new QStandardItem(fieldName);
            fieldItem->setData(QVariant::fromValue(reinterpret_cast<quintptr>(comp)), Qt::UserRole);
            parent->appendRow(fieldItem);
        }
    } else if (asUnion) {
        for (int i = 0; i < asUnion->getNumComponents(); ++i) {
            auto* comp = asUnion->getComponent(i);
            if (!comp) continue;
            QString fieldName = QString::fromStdString(comp->getFieldName());
            if (fieldName.isEmpty()) fieldName = QString::fromStdString(comp->getDataType()->getName());
            auto* fieldItem = new QStandardItem(fieldName);
            fieldItem->setData(QVariant::fromValue(reinterpret_cast<quintptr>(comp)), Qt::UserRole);
            parent->appendRow(fieldItem);
        }
    }
}

void StructureEditorWidget::onTreeContextMenu(const QPoint& pos) {
    QModelIndex index = treeView_->indexAt(pos);
    if (!index.isValid()) return;

    QMenu menu(this);
    QAction* addFieldAction = menu.addAction("Add Field");
    QAction* deleteAction = menu.addAction("Delete");

    QAction* selectedAction = menu.exec(treeView_->viewport()->mapToGlobal(pos));
    if (selectedAction == addFieldAction) {
        onAddField();
    } else if (selectedAction == deleteAction) {
        onDeleteType();
    }
}

void StructureEditorWidget::onAddStructure() {
    if (!dtm_ || !program_) return;

    bool ok;
    QString name = QInputDialog::getText(this, "New Structure", "Structure name:", QLineEdit::Normal, "", &ok);
    if (!ok || name.isEmpty()) return;

    std::string structName = name.toStdString();

    // Check if name already exists
    std::vector<DataType*> existingTypes;
    dtm_->findDataTypes(structName, existingTypes);
    if (!existingTypes.empty()) {
        QMessageBox::warning(this, "Error", "A type with this name already exists.");
        return;
    }

    auto* newStruct = new StructureDataType(structName, 0, dtm_);
    dtm_->addDataType(newStruct, nullptr);

    refreshTree();
    emit typeModified(name);
}

void StructureEditorWidget::onAddUnion() {
    if (!dtm_ || !program_) return;

    bool ok;
    QString name = QInputDialog::getText(this, "New Union", "Union name:", QLineEdit::Normal, "", &ok);
    if (!ok || name.isEmpty()) return;

    std::string unionName = name.toStdString();

    std::vector<DataType*> existingTypes;
    dtm_->findDataTypes(unionName, existingTypes);
    if (!existingTypes.empty()) {
        QMessageBox::warning(this, "Error", "A type with this name already exists.");
        return;
    }

    auto* newUnion = new UnionDataType(unionName, dtm_);
    dtm_->addDataType(newUnion, nullptr);

    refreshTree();
    emit typeModified(name);
}

void StructureEditorWidget::onAddField() {
    QModelIndex index = treeView_->currentIndex();
    if (!index.isValid() || !dtm_) return;

    // Get the selected item's data
    QVariant data = index.data(Qt::UserRole);
    if (!data.isValid()) return;

    void* ptr = reinterpret_cast<void*>(data.value<quintptr>());
    Structure* asStruct = dynamic_cast<Structure*>(static_cast<DataType*>(ptr));
    Union* asUnion = dynamic_cast<Union*>(static_cast<DataType*>(ptr));

    if (!asStruct && !asUnion) return;

    bool ok;
    QString fieldName = QInputDialog::getText(this, "Add Field", "Field name:", QLineEdit::Normal, "", &ok);
    if (!ok || fieldName.isEmpty()) return;

    // Create a default int field
    auto* fieldDt = dtm_->getDataType("int32");
    if (!fieldDt) return;

    if (asStruct) {
        asStruct->add(fieldDt, fieldName.toStdString(), "");
    } else if (asUnion) {
        asUnion->add(fieldDt, fieldName.toStdString(), "");
    }

    refreshTree();
    emit typeModified(fieldName);
}

void StructureEditorWidget::onDeleteType() {
    QModelIndex index = treeView_->currentIndex();
    if (!index.isValid() || !dtm_) return;

    QVariant data = index.data(Qt::UserRole);
    if (!data.isValid()) return;

    void* ptr = reinterpret_cast<void*>(data.value<quintptr>());
    DataType* dt = static_cast<DataType*>(ptr);
    if (!dt) return;

    QMessageBox::StandardButton reply = QMessageBox::question(this, "Delete Type",
        "Delete type \"" + QString::fromStdString(dt->getName()) + "\"?",
        QMessageBox::Yes | QMessageBox::No);

    if (reply == QMessageBox::Yes) {
        dtm_->remove(dt);
        refreshTree();
    }
}

void StructureEditorWidget::onFilterChanged(const QString& text) {
    if (!treeModel_) return;

    QString filter = text.toLower();
    for (int i = 0; i < treeModel_->rowCount(); ++i) {
        QModelIndex index = treeModel_->index(i, 0);
        QString name = index.data(Qt::DisplayRole).toString().toLower();
        treeView_->setRowHidden(i, QModelIndex(), !filter.isEmpty() && !name.contains(filter));
    }
}

void StructureEditorWidget::onTreeDoubleClicked(const QModelIndex& index) {
    if (!index.isValid()) return;

    QVariant data = index.data(Qt::UserRole);
    if (!data.isValid()) return;

    void* ptr = reinterpret_cast<void*>(data.value<quintptr>());
    DataType* dt = static_cast<DataType*>(ptr);
    if (dt) {
        emit typeSelected(QString::fromStdString(dt->getName()));
    }
}

} // namespace ghidra
