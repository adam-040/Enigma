#include <ghidra/DataTypeConflictHandler.h>
#include <ghidra/Composite.h>
#include <ghidra/Structure.h>
#include <ghidra/Union.h>
#include <stdexcept>

namespace ghidra {

namespace {

// Forward declarations for subsequent handlers
class DefaultSubsequentHandler final : public DataTypeConflictHandler {
public:
    ConflictResult resolveConflict(DataType* addedDataType, DataType* existingDataType) override {
        return ConflictResult::RENAME_AND_ADD;
    }
    bool shouldUpdate(DataType* sourceDataType, DataType* localDataType) override {
        return false;
    }
    DataTypeConflictHandler* getSubsequentHandler() override {
        return this;
    }
};

class SubsequentReplaceHandler final : public DataTypeConflictHandler {
public:
    ConflictResult resolveConflict(DataType* addedDataType, DataType* existingDataType) override {
        return ConflictResult::REPLACE_EXISTING;
    }
    bool shouldUpdate(DataType* sourceDataType, DataType* localDataType) override {
        return false;
    }
    DataTypeConflictHandler* getSubsequentHandler() override {
        return this;
    }
};

// --- DEFAULT_HANDLER ---
class DefaultHandler final : public DataTypeConflictHandler {
public:
    ConflictResult resolveConflict(DataType* addedDataType, DataType* existingDataType) override {
        return ConflictResult::RENAME_AND_ADD;
    }
    bool shouldUpdate(DataType* sourceDataType, DataType* localDataType) override {
        return true;
    }
    DataTypeConflictHandler* getSubsequentHandler() override {
        static DefaultSubsequentHandler handler;
        return &handler;
    }
};

// --- REPLACE_HANDLER ---
class ReplaceHandler final : public DataTypeConflictHandler {
public:
    ConflictResult resolveConflict(DataType* addedDataType, DataType* existingDataType) override {
        return ConflictResult::REPLACE_EXISTING;
    }
    bool shouldUpdate(DataType* sourceDataType, DataType* localDataType) override {
        return true;
    }
    DataTypeConflictHandler* getSubsequentHandler() override {
        static SubsequentReplaceHandler handler;
        return &handler;
    }
};

// --- KEEP_HANDLER ---
class KeepHandler final : public DataTypeConflictHandler {
public:
    ConflictResult resolveConflict(DataType* addedDataType, DataType* existingDataType) override {
        return ConflictResult::USE_EXISTING;
    }
    bool shouldUpdate(DataType* sourceDataType, DataType* localDataType) override {
        return false;
    }
    DataTypeConflictHandler* getSubsequentHandler() override {
        return this;
    }
};

// --- REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER ---
class ReplaceEmptyOrRenameHandler final : public DataTypeConflictHandler {
    ConflictResult resolveConflictReplaceEmpty(DataType* addedDataType, DataType* existingDataType) {
        if (addedDataType->isNotYetDefined()) return ConflictResult::USE_EXISTING;
        if (existingDataType->isNotYetDefined()) return ConflictResult::REPLACE_EXISTING;
        return ConflictResult::RENAME_AND_ADD;
    }

public:
    ConflictResult resolveConflict(DataType* addedDataType, DataType* existingDataType) override {
        if (dynamic_cast<Structure*>(addedDataType) && dynamic_cast<Structure*>(existingDataType)) {
            return resolveConflictReplaceEmpty(addedDataType, existingDataType);
        }
        if (dynamic_cast<Union*>(addedDataType) && dynamic_cast<Union*>(existingDataType)) {
            return resolveConflictReplaceEmpty(addedDataType, existingDataType);
        }
        return ConflictResult::RENAME_AND_ADD;
    }
    bool shouldUpdate(DataType* sourceDataType, DataType* localDataType) override {
        return false;
    }
    DataTypeConflictHandler* getSubsequentHandler() override {
        return this;
    }
};

// --- BUILT_IN_MANAGER_HANDLER ---
class BuiltInManagerHandler final : public DataTypeConflictHandler {
public:
    ConflictResult resolveConflict(DataType* addedDataType, DataType* existingDataType) override {
        throw std::runtime_error("Built-in data-types may not be changed while running");
    }
    bool shouldUpdate(DataType* sourceDataType, DataType* localDataType) override {
        return false;
    }
    DataTypeConflictHandler* getSubsequentHandler() override {
        return this;
    }
};

} // anonymous namespace

DataTypeConflictHandler& DataTypeConflictHandler::DEFAULT_HANDLER() {
    static DefaultHandler handler;
    return handler;
}

DataTypeConflictHandler& DataTypeConflictHandler::KEEP_HANDLER() {
    static KeepHandler handler;
    return handler;
}

DataTypeConflictHandler& DataTypeConflictHandler::REPLACE_HANDLER() {
    static ReplaceHandler handler;
    return handler;
}

DataTypeConflictHandler& DataTypeConflictHandler::REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER() {
    static ReplaceEmptyOrRenameHandler handler;
    return handler;
}

DataTypeConflictHandler& DataTypeConflictHandler::BUILT_IN_MANAGER_HANDLER() {
    static BuiltInManagerHandler handler;
    return handler;
}

DataTypeConflictHandler* DataTypeConflictHandler::getHandler(ConflictResolutionPolicy policy) {
    switch (policy) {
        case ConflictResolutionPolicy::RENAME_AND_ADD:
            return &DEFAULT_HANDLER();
        case ConflictResolutionPolicy::USE_EXISTING:
            return &KEEP_HANDLER();
        case ConflictResolutionPolicy::REPLACE_EXISTING:
            return &REPLACE_HANDLER();
        case ConflictResolutionPolicy::REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD:
            return &REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER();
    }
    return &DEFAULT_HANDLER();
}

} // namespace ghidra
