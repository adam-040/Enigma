#pragma once

#include <ghidra/CategoryPath.h>
#include <vector>
#include <string>

namespace ghidra {

class DataType;
class DataTypeConflictHandler;
class DataTypeManager;

class Category {
public:
    virtual ~Category() = default;

    virtual std::string getName() = 0;
    virtual void setName(const std::string& name) = 0;

    virtual std::vector<Category*> getCategories() = 0;
    virtual std::vector<DataType*> getDataTypes() = 0;
    virtual std::vector<DataType*> getDataTypesByBaseName(const std::string& name) = 0;
    virtual DataType* addDataType(DataType* dt, DataTypeConflictHandler* handler) = 0;

    virtual Category* getCategory(const std::string& name) = 0;
    virtual CategoryPath getCategoryPath() = 0;
    virtual DataType* getDataType(const std::string& name) = 0;

    virtual Category* createCategory(const std::string& name) = 0;
    virtual bool removeCategory(const std::string& name) = 0;
    virtual bool removeEmptyCategory(const std::string& name) = 0;

    virtual void moveCategory(Category* category) = 0;
    virtual Category* copyCategory(Category* category, DataTypeConflictHandler* handler) = 0;

    virtual Category* getParent() = 0;
    virtual bool isRoot() = 0;
    virtual std::string getCategoryPathName() = 0;
    virtual Category* getRoot() = 0;
    virtual DataTypeManager* getDataTypeManager() = 0;

    virtual void moveDataType(DataType* type, DataTypeConflictHandler* handler) = 0;
    virtual bool removeDataType(DataType* type) = 0;

    virtual long getID() = 0;
};

} // namespace ghidra
