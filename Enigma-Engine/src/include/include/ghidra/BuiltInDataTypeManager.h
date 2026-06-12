/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <ghidra/StandAloneDataTypeManager.h>

namespace ghidra {

class BuiltInDataTypeManager : public StandAloneDataTypeManager {
public:
    static constexpr const char* BUILT_IN_DATA_TYPES_NAME = "BuiltInTypes";

    static BuiltInDataTypeManager& getDataTypeManager();

    ~BuiltInDataTypeManager() override;

    int startTransaction(const std::string& description);
    bool endTransaction(int transactionID, bool commit);
    bool canUndo() const;
    bool canRedo() const;

    Category* createCategory(const CategoryPath& path) override;

    ArchiveType getType() const override;
    DataType* resolve(DataType* dataType, DataTypeConflictHandler* handler) override;
    DataType* addDataType(DataType* originalDataType, DataTypeConflictHandler* handler) override;
    void setName(const std::string& name) override;
    void associateDataTypeWithArchive(DataType* datatype, SourceArchive* archive) override;
    bool remove(DataType* dataType) override;
    DataType* replaceDataType(DataType* existingDt, DataType* replacementDt,
                              bool updateCategoryPath) override;
    void close() override;

private:
    BuiltInDataTypeManager();
    BuiltInDataTypeManager(const BuiltInDataTypeManager&) = delete;
    BuiltInDataTypeManager& operator=(const BuiltInDataTypeManager&) = delete;

    void populateBuiltInTypes();

    static BuiltInDataTypeManager* manager_;
    bool populated_;
};

} // namespace ghidra
