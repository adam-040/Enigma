/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file DataTypeManager.h
/// \brief Interface for managing data types
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ghidra {

class Category;
class DataType;
class DataTypeConflictHandler;
class DataOrganization;
class SourceArchive;
class CategoryPath;
class DataTypePath;
class UniversalID;

class DataTypeManager {
public:
    virtual ~DataTypeManager() = default;

    virtual std::shared_ptr<DataType> getDataType(const DataTypePath& path) const = 0;
    virtual std::shared_ptr<DataType> getDataType(const std::string& dataTypeName) const = 0;
    virtual std::shared_ptr<DataType> getDataType(uint64_t universalID) const = 0;
    virtual std::shared_ptr<DataType> findDataType(const std::string& dataTypePath) const = 0;
    virtual std::shared_ptr<Category> getCategory(const CategoryPath& path) const = 0;
    virtual std::shared_ptr<Category> createCategory(const CategoryPath& path) = 0;
    virtual std::shared_ptr<DataType> addDataType(const std::shared_ptr<DataType>& dataType, const std::shared_ptr<DataTypeConflictHandler>& handler) = 0;
    virtual std::shared_ptr<DataType> resolve(const std::shared_ptr<DataType>& dataType, const std::shared_ptr<DataTypeConflictHandler>& handler) = 0;
    virtual void remove(const std::shared_ptr<DataType>& dataType, bool force) = 0;
    virtual void removeCategory(const CategoryPath& path) = 0;
    virtual void renameCategory(const CategoryPath& oldPath, const CategoryPath& newPath) = 0;
    virtual std::vector<std::shared_ptr<DataType>> getAllDataTypes() const = 0;
    virtual int getDataTypeCount(bool includeCategories) const = 0;
    virtual std::shared_ptr<DataOrganization> getDataOrganization() const = 0;
    virtual std::shared_ptr<SourceArchive> getSourceArchive(const std::string& name) const = 0;
    virtual std::vector<std::shared_ptr<SourceArchive>> getSourceArchives() const = 0;
    virtual bool isChanged() const = 0;
    virtual void flush() = 0;
    virtual void close() = 0;
    virtual std::string getName() const = 0;
};

} // namespace ghidra
