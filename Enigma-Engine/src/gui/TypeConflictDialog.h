#pragma once

#include <QDialog>
#include <QTreeWidget>
#include <QLineEdit>
#include <ghidra/DataType.h>

namespace ghidra {

class TypeConflictDialog : public QDialog {
    Q_OBJECT
public:
    enum class Resolution { KeepExisting, ReplaceWithNew, RenameNew, Cancel };

    TypeConflictDialog(DataType* existing, DataType* incoming, QWidget* parent = nullptr);

    Resolution resolution() const { return resolution_; }
    QString newName() const { return newNameEdit_->text(); }

private slots:
    void onKeepExisting();
    void onReplaceWithNew();
    void onRenameNew();

private:
    void populateTree(QTreeWidget* tree, DataType* dt);

    DataType* existing_;
    DataType* incoming_;
    Resolution resolution_ = Resolution::Cancel;

    QTreeWidget* existingTree_ = nullptr;
    QTreeWidget* incomingTree_ = nullptr;
    QLineEdit* newNameEdit_ = nullptr;
};

} // namespace ghidra
