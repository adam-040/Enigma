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

#include <ghidra/DataTypeManager.h>
#include <ghidra/Category.h>
#include <ghidra/CategoryPath.h>
#include <ghidra/DataTypeConflictHandler.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include <list>

namespace ghidra {

class DataOrganization;
class Pointer;

class StandAloneDataTypeManager : public DataTypeManager {
public:
    StandAloneDataTypeManager(const std::string& rootName);
    StandAloneDataTypeManager(const std::string& rootName, DataOrganization* dataOrganization);
    ~StandAloneDataTypeManager() override;

    const std::string& getName() const override;
    void setName(const std::string& name) override;

    DataType* getDataType(const CategoryPath& categoryPath, const std::string& name) override;
    DataType* getDataType(int64_t id) override;
    DataType* getDataType(const std::string& dataTypePath) override;

    std::vector<DataType*> getDataTypes() override;
    std::vector<std::string> getDefinedCallingConventionNames() const override;
    std::vector<std::string> getKnownCallingConventionNames() const override;

    DataOrganization* getDataOrganization() const override;

    long getID(DataType* dt) override;

    DataType* resolve(DataType* dataType, DataTypeConflictHandler* handler) override;
    DataType* addDataType(DataType* dataType, DataTypeConflictHandler* handler) override;
    DataType* replaceDataType(DataType* existingDt, DataType* replacementDt, bool updateCategoryPath) override;

    void findDataTypes(const std::string& name, std::vector<DataType*>& list) override;
    void findDataTypes(const std::string& name, std::vector<DataType*>& list, bool caseSensitive) override;

    Category* getRootCategory() override;
    Category* getCategory(const CategoryPath& path) override;
    Category* getCategory(long categoryID) override;
    Category* createCategory(const CategoryPath& path) override;
    int getCategoryCount() const override;

    bool remove(DataType* dataType) override;
    bool contains(DataType* dataType) const override;
    bool isUpdatable() const override;

    int getDataTypeCount(bool includePointersAndArrays) const override;

    void close() override;

    int startTransaction(const std::string& description);
    bool endTransaction(int transactionID, bool commit);

    UniversalID getUniversalID() const override;
    ArchiveType getType() const override;

    Pointer* getPointer(DataType* datatype) override;
    Pointer* getPointer(DataType* datatype, int size) override;

    void findEnumValueNames(long value, std::set<std::string>& enumValueNames) override;

    bool isFavorite(DataType* datatype) override;
    void setFavorite(DataType* datatype, bool isFavorite) override;
    std::vector<DataType*> getFavorites() override;

    void flushEvents() override;

    bool allowsDefaultBuiltInSettings() const override { return true; }
    bool allowsDefaultComponentSettings() const override { return true; }

protected:
    long allocateDataTypeId();

private:
    class CategoryImpl;

    std::string name_;
    DataOrganization* dataOrganization_;
    bool ownsDataOrganization_;
    bool closed_;

    mutable long nextDataTypeId_;
    std::unordered_map<long, DataType*> dataTypeById_;
    std::unordered_map<std::string, DataType*> dataTypeByPath_;
    std::unordered_map<std::string, std::vector<DataType*>> dataTypeByName_;
    std::map<long, CategoryImpl*> categoryById_;
    std::unordered_map<std::string, CategoryImpl*> categoryByPath_;

    CategoryImpl* rootCategory_;

    std::unordered_map<DataType*, long> dataTypeToId_;
    int transactionCount_;
    long transaction_;
    bool commitTransaction_;
    std::string transactionName_;

    std::list<std::string> undoList_;
    std::list<std::string> redoList_;
    static constexpr int NUM_UNDOS = 50;

    void clear();

    std::string makePath(const CategoryPath& categoryPath, const std::string& name) const;
    DataType* findDataType(const CategoryPath& categoryPath, const std::string& name) const;
};

} // namespace ghidra
