#pragma once

#include <QWidget>
#include <QTreeView>
#include <QStandardItemModel>
#include <QSplitter>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QLineEdit>
#include <QHeaderView>
#include <QMenu>
#include <QAction>
#include <QModelIndex>
#include <memory>

namespace ghidra {

class Program;
class DataTypeManager;
class Structure;
class Union;

class StructureEditorWidget : public QWidget {
    Q_OBJECT

public:
    explicit StructureEditorWidget(QWidget* parent = nullptr);
    virtual ~StructureEditorWidget() = default;

    void setProgram(Program* program);

signals:
    void typeSelected(const QString& typeName);
    void typeModified(const QString& typeName);

private slots:
    void onTreeContextMenu(const QPoint& pos);
    void onAddStructure();
    void onAddUnion();
    void onAddField();
    void onDeleteType();
    void onFilterChanged(const QString& text);
    void onTreeDoubleClicked(const QModelIndex& index);

private:
    void setupUI();
    void refreshTree();
    void populateCategories(QStandardItem* parent, void* category);
    void populateTypeChildren(QStandardItem* parent, void* dataType);

    Program* program_ = nullptr;
    DataTypeManager* dtm_ = nullptr;

    QTreeView* treeView_ = nullptr;
    QStandardItemModel* treeModel_ = nullptr;
    QLineEdit* filterEdit_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QMenu* contextMenu_ = nullptr;
};

} // namespace ghidra
