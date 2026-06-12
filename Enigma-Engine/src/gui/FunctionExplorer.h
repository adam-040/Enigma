#pragma once

#include <QWidget>
#include <QTreeWidget>
#include <QLineEdit>
#include <QVBoxLayout>
#include <vector>
#include <cstdint>

class FunctionExplorer : public QWidget {
    Q_OBJECT
public:
    explicit FunctionExplorer(QWidget* parent = nullptr);

    void clear();
    QTreeWidgetItem* addCategory(const QString& name);
    void addEntry(QTreeWidgetItem* parent, uint64_t addr, const QString& name);
    void setFilter(const QString& text);

    QTreeWidget* treeWidget() const { return tree_; }

signals:
    void functionSelected(uint64_t addr, const QString& name);

private slots:
    void onItemDoubleClicked(QTreeWidgetItem* item, int col);
    void onFilterChanged(const QString& text);

private:
    QTreeWidget* tree_;
    QLineEdit* filter_;
};
