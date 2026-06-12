#pragma once

#include <ghidra/CategoryPath.h>
#include <vector>
#include <string>

namespace ghidra {

class DataType;
class DataTypeConflictHandler;
class DataTypeManager;

class ICategory {
public:
    virtual ~ICategory() = default;

    static constexpr char DELIMITER_CHAR = '/';
    inline static const std::string NAME_DELIMITER = "/";
    inline static const std::string DELIMITER_STRING = "/";

    virtual std::string getName() = 0;
    virtual void setName(const std::string& name) = 0;

    virtual std::vector<class Category*> getCategories() = 0;
    virtual std::vector<DataType*> getDataTypes() = 0;
    virtual DataType* addDataType(DataType* dt, DataTypeConflictHandler* handler) = 0;

    virtual class Category* getCategory(const std::string& name) = 0;
    virtual CategoryPath getCategoryPath() = 0;
    virtual DataType* getDataType(const std::string& name) = 0;

    virtual class Category* createCategory(const std::string& name) = 0;
    virtual bool removeCategory(const std::string& name) = 0;

    virtual void moveCategory(class Category* category) = 0;
    virtual class Category* copyCategory(class Category* category, DataTypeConflictHandler* handler) = 0;

    virtual class Category* getParent() = 0;
    virtual bool isRoot() = 0;
    virtual std::string getCategoryPathName() = 0;
    virtual class Category* getRoot() = 0;
    virtual DataTypeManager* getDataTypeManager() = 0;

    virtual void moveDataType(DataType* type, DataTypeConflictHandler* handler) = 0;
    virtual bool remove(DataType* type) = 0;
};

} // namespace ghidra
