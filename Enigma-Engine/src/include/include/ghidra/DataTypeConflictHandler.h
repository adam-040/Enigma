#pragma once

#include <ghidra/DataType.h>

namespace ghidra {

class DataTypeConflictHandler {
public:
    enum class ConflictResolutionPolicy {
        RENAME_AND_ADD,
        USE_EXISTING,
        REPLACE_EXISTING,
        REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD
    };

    enum class ConflictResult {
        RENAME_AND_ADD,
        USE_EXISTING,
        REPLACE_EXISTING
    };

    static DataTypeConflictHandler* getHandler(ConflictResolutionPolicy policy);

    virtual ConflictResult resolveConflict(DataType* addedDataType, DataType* existingDataType) = 0;
    virtual bool shouldUpdate(DataType* sourceDataType, DataType* localDataType) = 0;
    virtual DataTypeConflictHandler* getSubsequentHandler() = 0;

    static DataTypeConflictHandler& DEFAULT_HANDLER();
    static DataTypeConflictHandler& KEEP_HANDLER();
    static DataTypeConflictHandler& REPLACE_HANDLER();
    static DataTypeConflictHandler& REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER();
    static DataTypeConflictHandler& BUILT_IN_MANAGER_HANDLER();

    virtual ~DataTypeConflictHandler() = default;
};

} // namespace ghidra
