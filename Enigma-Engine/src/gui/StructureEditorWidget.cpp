#include "StructureEditorWidget.h"
#include "GuiConflictHandler.h"
#include <ghidra/Program.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/Category.h>
#include <ghidra/Structure.h>
#include <ghidra/Union.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/UnionDataType.h>
#include <ghidra/DataTypeComponent.h>
#include <ghidra/DataType.h>
#include <QHeaderView>
#include <QMessageBox>
#include <QInputDialog>
#include <QMenu>
#include <QAction>

namespace ghidra {

StructureEditorWidget::StructureEditorWidget(QWidget* parent) : QWidget(parent) {
    auto* lay = new QVBoxLayout(this);
    lay->setContentsMargins(4, 4, 4, 4);
    lay->setSpacing(4);

    // row 1: filter + buttons
    auto* row = new QHBoxLayout;
    row->setSpacing(4);
    filter_ = new QLineEdit;
    filter_->setPlaceholderText("Filter types...");
    filter_->setClearButtonEnabled(true);
    connect(filter_, &QLineEdit::textChanged, this, &StructureEditorWidget::onFilter);
    row->addWidget(filter_, 1);

    auto* btnS = new QPushButton("+S");
    btnS->setToolTip("New structure");
    btnS->setFixedWidth(30);
    connect(btnS, &QPushButton::clicked, this, &StructureEditorWidget::onAddStruct);
    row->addWidget(btnS);

    auto* btnU = new QPushButton("+U");
    btnU->setToolTip("New union");
    btnU->setFixedWidth(30);
    connect(btnU, &QPushButton::clicked, this, &StructureEditorWidget::onAddUnion);
    row->addWidget(btnU);

    lay->addLayout(row);

    // row 2: horizontal splitter — tree left, table right
    auto* split = new QSplitter(Qt::Horizontal);
    split->setHandleWidth(3);

    tree_ = new QTreeView;
    tree_->setHeaderHidden(true);
    tree_->setContextMenuPolicy(Qt::CustomContextMenu);
    tree_->setAlternatingRowColors(true);
    model_ = new QStandardItemModel;
    tree_->setModel(model_);
    connect(tree_, &QTreeView::customContextMenuRequested, this, &StructureEditorWidget::onTreeMenu);
    connect(tree_->selectionModel(), &QItemSelectionModel::currentChanged, this, [this]() { onTreeSelect(); });
    split->addWidget(tree_);

    auto* right = new QWidget;
    auto* rlay = new QVBoxLayout(right);
    rlay->setContentsMargins(0, 0, 0, 0);
    rlay->setSpacing(0);

    info_ = new QLabel("Select a type");
    info_->setContentsMargins(4, 2, 4, 2);
    rlay->addWidget(info_);

    table_ = new QTableWidget;
    table_->setColumnCount(4);
    table_->setHorizontalHeaderLabels({"Offset", "Size", "Type", "Name"});
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    table_->verticalHeader()->setVisible(false);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    rlay->addWidget(table_);

    split->addWidget(right);
    split->setStretchFactor(0, 1);
    split->setStretchFactor(1, 2);
    lay->addWidget(split, 1);

    // row 3: status
    status_ = new QLabel;
    lay->addWidget(status_);
}

void StructureEditorWidget::setProgram(Program* p) {
    program_ = p;
    dtm_ = p ? p->getDataTypeManager() : nullptr;
    rebuild();
}

void StructureEditorWidget::rebuild() {
    model_->clear();
    table_->setRowCount(0);
    info_->setText("Select a type");

    if (!dtm_) {
        status_->setText("No program loaded");
        return;
    }

    Category* root = dtm_->getRootCategory();
    if (root) {
        std::function<void(QStandardItem*, Category*)> addCat = [&](QStandardItem* par, Category* cat) {
            QString name = QString::fromStdString(cat->getName());
            if (name.isEmpty()) name = "Root";
            auto* item = new QStandardItem(name);
            item->setIcon(QIcon(":/icons/folder-free.svg"));
            par->appendRow(item);
            for (auto* sub : cat->getCategories())
                addCat(item, sub);
            for (auto* dt : cat->getDataTypes()) {
                if (!dt) continue;
                auto* ti = new QStandardItem(QString::fromStdString(dt->getName()));
                ti->setIcon(QIcon(":/icons/type.svg"));
                ti->setData(QVariant::fromValue(reinterpret_cast<quintptr>(dt)), Qt::UserRole);
                item->appendRow(ti);
            }
        };
        addCat(model_->invisibleRootItem(), root);
    }

    int n = dtm_->getDataTypes().size();
    status_->setText(QString("%1 types").arg(n));
    tree_->expandAll();
}

void StructureEditorWidget::onTreeSelect() {
    QModelIndex idx = tree_->currentIndex();
    if (!idx.isValid()) { table_->setRowCount(0); info_->setText("Select a type"); return; }
    QVariant v = idx.data(Qt::UserRole);
    if (!v.isValid()) { table_->setRowCount(0); info_->setText("Select a type"); return; }
    showFields(reinterpret_cast<DataType*>(v.value<quintptr>()));
}

void StructureEditorWidget::showFields(DataType* dt) {
    if (!dt) { table_->setRowCount(0); info_->setText("Select a type"); return; }

    QString name = QString::fromStdString(dt->getName());
    Structure* s = dynamic_cast<Structure*>(dt);
    Union* u = dynamic_cast<Union*>(dt);

    if (s) {
        int n = s->getNumComponents();
        info_->setText(QString("%1 — %2 fields, %3 bytes").arg(name).arg(n).arg(dt->getLength()));
        table_->setRowCount(n);
        for (int i = 0; i < n; ++i) {
            auto* c = s->getComponent(i);
            if (!c) continue;
            auto* a = new QTableWidgetItem(QString::number(c->getOffset()));
            a->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            auto* b = new QTableWidgetItem(QString::number(c->getLength()));
            b->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            QString typ = c->getDataType() ? QString::fromStdString(c->getDataType()->getName()) : "?";
            QString fn = QString::fromStdString(c->getFieldName());
            if (fn.isEmpty()) fn = typ;
            table_->setItem(i, 0, a);
            table_->setItem(i, 1, b);
            table_->setItem(i, 2, new QTableWidgetItem(typ));
            table_->setItem(i, 3, new QTableWidgetItem(fn));
        }
    } else if (u) {
        int n = u->getNumComponents();
        info_->setText(QString("%1 (union) — %2 fields, %3 bytes").arg(name).arg(n).arg(dt->getLength()));
        table_->setRowCount(n);
        for (int i = 0; i < n; ++i) {
            auto* c = u->getComponent(i);
            if (!c) continue;
            auto* a = new QTableWidgetItem("0");
            a->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            auto* b = new QTableWidgetItem(QString::number(c->getLength()));
            b->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            QString typ = c->getDataType() ? QString::fromStdString(c->getDataType()->getName()) : "?";
            QString fn = QString::fromStdString(c->getFieldName());
            if (fn.isEmpty()) fn = typ;
            table_->setItem(i, 0, a);
            table_->setItem(i, 1, b);
            table_->setItem(i, 2, new QTableWidgetItem(typ));
            table_->setItem(i, 3, new QTableWidgetItem(fn));
        }
    } else {
        info_->setText(name + " — " + QString::number(dt->getLength()) + " bytes");
        table_->setRowCount(0);
    }
}

void StructureEditorWidget::onTreeMenu(const QPoint& pos) {
    QModelIndex idx = tree_->indexAt(pos);
    if (!idx.isValid()) return;
    QVariant v = idx.data(Qt::UserRole);
    if (!v.isValid()) return;
    DataType* dt = reinterpret_cast<DataType*>(v.value<quintptr>());

    QMenu m(this);
    if (dynamic_cast<Structure*>(dt) || dynamic_cast<Union*>(dt)) {
        auto* a = m.addAction("Add Field...");
        connect(a, &QAction::triggered, this, &StructureEditorWidget::onAddField);
        m.addSeparator();
    }
    auto* d = m.addAction("Delete");
    connect(d, &QAction::triggered, this, &StructureEditorWidget::onDelete);
    m.exec(tree_->viewport()->mapToGlobal(pos));
}

void StructureEditorWidget::onAddStruct() {
    if (!dtm_) return;
    bool ok;
    QString n = QInputDialog::getText(this, "New Structure", "Name:", QLineEdit::Normal, "", &ok);
    if (!ok || n.isEmpty()) return;
    GuiConflictHandler h;
    dtm_->addDataType(new StructureDataType(n.toStdString(), 0, dtm_), &h);
    rebuild();
    emit typeModified(n);
}

void StructureEditorWidget::onAddUnion() {
    if (!dtm_) return;
    bool ok;
    QString n = QInputDialog::getText(this, "New Union", "Name:", QLineEdit::Normal, "", &ok);
    if (!ok || n.isEmpty()) return;
    GuiConflictHandler h;
    dtm_->addDataType(new UnionDataType(n.toStdString(), dtm_), &h);
    rebuild();
    emit typeModified(n);
}

void StructureEditorWidget::onAddField() {
    QModelIndex idx = tree_->currentIndex();
    if (!idx.isValid() || !dtm_) return;
    QVariant v = idx.data(Qt::UserRole);
    if (!v.isValid()) return;
    DataType* dt = reinterpret_cast<DataType*>(v.value<quintptr>());
    Structure* s = dynamic_cast<Structure*>(dt);
    Union* u = dynamic_cast<Union*>(dt);
    if (!s && !u) return;

    bool ok;
    QString fn = QInputDialog::getText(this, "Add Field", "Field name:", QLineEdit::Normal, "", &ok);
    if (!ok || fn.isEmpty()) return;

    QStringList types = {"int8","int16","int32","int64","uint8","uint16","uint32","uint64","float","double","bool","char"};
    for (auto* t : dtm_->getDataTypes())
        if (t) types.append(QString::fromStdString(t->getName()));
    types.removeDuplicates();

    QString tn = QInputDialog::getItem(this, "Type", "Field type:", types, 2, false, &ok);
    if (!ok || tn.isEmpty()) tn = "int32";

    DataType* fdt = dtm_->getDataType(tn.toStdString());
    if (!fdt) fdt = dtm_->getDataType("int32");
    if (!fdt) return;

    if (s) s->add(fdt, fn.toStdString(), "");
    else u->add(fdt, fn.toStdString(), "");
    rebuild();
    emit typeModified(fn);
}

void StructureEditorWidget::onDelete() {
    QModelIndex idx = tree_->currentIndex();
    if (!idx.isValid() || !dtm_) return;
    QVariant v = idx.data(Qt::UserRole);
    if (!v.isValid()) return;
    DataType* dt = reinterpret_cast<DataType*>(v.value<quintptr>());
    if (!dt) return;
    if (QMessageBox::question(this, "Delete", "Delete \"" + QString::fromStdString(dt->getName()) + "\"?") == QMessageBox::Yes) {
        dtm_->remove(dt);
        rebuild();
    }
}

void StructureEditorWidget::onFilter(const QString& text) {
    QString f = text.toLower();
    std::function<bool(QStandardItem*)> filter = [&](QStandardItem* item) -> bool {
        bool vis = false;
        for (int i = 0; i < item->rowCount(); ++i)
            if (filter(item->child(i))) vis = true;
        bool match = f.isEmpty() || item->text().toLower().contains(f) || vis;
        QModelIndex idx = model_->indexFromItem(item);
        if (idx.parent().isValid())
            tree_->setRowHidden(idx.row(), idx.parent(), !match);
        return match;
    };
    for (int i = 0; i < model_->rowCount(); ++i)
        filter(model_->item(i));
}

} // namespace ghidra
