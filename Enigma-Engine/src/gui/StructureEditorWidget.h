#pragma once

#include <QWidget>
#include <QSplitter>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTreeView>
#include <QStandardItemModel>
#include <QTableWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>

namespace ghidra {

class Program;
class DataTypeManager;
class DataType;

class StructureEditorWidget : public QWidget {
    Q_OBJECT
public:
    explicit StructureEditorWidget(QWidget* parent = nullptr);

    void setProgram(Program* program);

signals:
    void typeSelected(const QString& typeName);
    void typeModified(const QString& typeName);

private slots:
    void onAddStruct();
    void onAddUnion();
    void onAddField();
    void onDelete();
    void onFilter(const QString& text);
    void onTreeSelect();
    void onTreeMenu(const QPoint& pos);

private:
    Program* program_ = nullptr;
    DataTypeManager* dtm_ = nullptr;

    QLineEdit* filter_ = nullptr;
    QTreeView* tree_ = nullptr;
    QStandardItemModel* model_ = nullptr;
    QLabel* info_ = nullptr;
    QTableWidget* table_ = nullptr;
    QLabel* status_ = nullptr;

    void rebuild();
    void showFields(DataType* dt);
};

} // namespace ghidra
