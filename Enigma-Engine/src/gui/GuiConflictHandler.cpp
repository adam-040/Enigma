#include "GuiConflictHandler.h"
#include "TypeConflictDialog.h"
#include <QApplication>

namespace ghidra {

DataTypeConflictHandler::ConflictResult
GuiConflictHandler::resolveConflict(DataType* addedDataType, DataType* existingDataType) {
    if (!addedDataType || !existingDataType) return ConflictResult::USE_EXISTING;

    QWidget* parent = nullptr;
    for (QWidget* w : QApplication::topLevelWidgets()) {
        if (w->isVisible()) { parent = w; break; }
    }

    TypeConflictDialog dlg(existingDataType, addedDataType, parent);
    if (dlg.exec() != QDialog::Accepted) return ConflictResult::USE_EXISTING;

    switch (dlg.resolution()) {
        case TypeConflictDialog::Resolution::KeepExisting:
            return ConflictResult::USE_EXISTING;
        case TypeConflictDialog::Resolution::ReplaceWithNew:
            return ConflictResult::REPLACE_EXISTING;
        case TypeConflictDialog::Resolution::RenameNew:
            return ConflictResult::RENAME_AND_ADD;
        default:
            return ConflictResult::USE_EXISTING;
    }
}

bool GuiConflictHandler::shouldUpdate(DataType* sourceDataType, DataType* localDataType) {
    return false;
}

DataTypeConflictHandler* GuiConflictHandler::getSubsequentHandler() {
    if (!subsequent_) subsequent_ = DataTypeConflictHandler::getHandler(
        ConflictResolutionPolicy::REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD);
    return subsequent_;
}

} // namespace ghidra
