#pragma once

#include <ghidra/DataTypeConflictHandler.h>

namespace ghidra {

class GuiConflictHandler : public DataTypeConflictHandler {
public:
    GuiConflictHandler() = default;

    ConflictResult resolveConflict(DataType* addedDataType, DataType* existingDataType) override;
    bool shouldUpdate(DataType* sourceDataType, DataType* localDataType) override;
    DataTypeConflictHandler* getSubsequentHandler() override;

private:
    DataTypeConflictHandler* subsequent_ = nullptr;
};

} // namespace ghidra
