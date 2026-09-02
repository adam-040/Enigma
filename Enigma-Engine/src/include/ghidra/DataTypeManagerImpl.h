/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeManagerImpl.h
/// \brief Concrete standard data type manager implementation
#pragma once

#include <ghidra/DataTypeManager.h>
#include <ghidra/DataOrganizationImpl.h>
#include <vector>
#include <unordered_map>
#include <memory>
#include <string>

namespace ghidra {

class DataTypeManagerImpl : public DataTypeManager {
public:
    DataTypeManagerImpl();
    explicit DataTypeManagerImpl(const std::string& name);
    ~DataTypeManagerImpl() override;

    const std::string& getName() const override;
    void setName(const std::string& name) { name_ = name; }

    DataType* getDataType(const CategoryPath& categoryPath, const std::string& name) override;
    DataType* getDataType(int64_t id) override;
    std::vector<DataType*> getDataTypes() override;
    DataType* resolve(DataType* dataType, DataTypeConflictHandler* handler) override;
    int getDataTypeCount(bool includePointersAndArrays) const override;

    std::vector<std::string> getDefinedCallingConventionNames() const override { return {}; }
    std::vector<std::string> getKnownCallingConventionNames() const override { return {}; }
    DataOrganization* getDataOrganization() const override;

    // Methods for adding/registering custom and composite types.
    // Datatype ids are 64-bit: composite/typedef/pointer/array/enum/function
    // ids carry a 2^56 type tag plus an ordinal (Ghidra DataTypeDB ids), which
    // does not fit in a 32-bit long.
    DataType* addDataType(DataType* dt);
    DataType* addDataType(DataType* dt, DataTypeConflictHandler* handler) override;
    DataType* addDataTypeWithId(DataType* dt, int64_t id);
    void removeDataType(DataType* dt);
    void clearAllDataTypes();
    int64_t getNextId();
    int64_t getDataTypeId(DataType* dt) const;

    Category* getRootCategory() override;
    Category* getCategory(const CategoryPath& path) override;
    Category* getCategory(long categoryID) override;
    Category* createCategory(const CategoryPath& path) override;
    int getCategoryCount() const override;

    /// Takes ownership of a helper type that must stay alive for the
    /// program's lifetime but is not a listed program type (e.g. a
    /// materialized inline pointer base restored from a snapshot).
    DataType* adoptOrphanDataType(DataType* dt) {
        orphans_.emplace_back(dt);
        return dt;
    }

private:
    void populateBuiltInTypes();

    std::string name_ = "ProgramDB";
    std::unique_ptr<DataOrganizationImpl> dataOrganization_;
    std::vector<std::unique_ptr<DataType>> types_;
    std::vector<std::unique_ptr<DataType>> orphans_;
    std::unordered_map<std::string, DataType*> typesByPath_;
    std::unordered_map<int64_t, DataType*> typesById_;
    int64_t nextId_ = 1000; // Built-ins use < 1000, custom starts at 1000

    // Category tree (mirrors Ghidra CategoryDB): categories carry the small
    // per-database ids from the "Categories" table; datatypes are registered
    // into the categories that their CategoryPath names.
    class CategoryImpl;
    std::map<long, CategoryImpl*> categoriesById_;
    std::unordered_map<std::string, CategoryImpl*> categoriesByPath_;
    CategoryImpl* rootCategory_ = nullptr;
    long nextCategoryId_ = 1;

    CategoryImpl* getOrCreateCategory(const CategoryPath& path);
};

} // namespace ghidra
