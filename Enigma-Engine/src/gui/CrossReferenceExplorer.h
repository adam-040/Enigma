#pragma once

#include <QWidget>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <cstdint>
#include <string>
#include <ghidra/Address.h>
#include <ghidra/ReferenceManager.h>

class CrossReferenceExplorer : public QWidget {
    Q_OBJECT
public:
    explicit CrossReferenceExplorer(QWidget* parent = nullptr);

    void showReferencesTo(const ghidra::Address& addr, const std::string& name,
                          ghidra::ReferenceManager* refMgr);
    void showReferencesFrom(const ghidra::Address& addr, const std::string& name,
                            ghidra::ReferenceManager* refMgr);
    void clear();

    // QTreeWidget helpers
    void setRootIsDecorated(bool v) { tree_->setRootIsDecorated(v); }
    void setHeaderHidden(bool v) { tree_->setHeaderHidden(v); }
    void setHeaderLabels(const QStringList& labels) { tree_->setHeaderLabels(labels); }

signals:
    void referenceSelected(uint64_t fromAddr, uint64_t toAddr);

private:
    QTreeWidget* tree_;
    void populateFrom(ghidra::ReferenceManager* refMgr);
    void populateTo(ghidra::ReferenceManager* refMgr);
    void onItemDoubleClicked(QTreeWidgetItem* item, int col);
};
