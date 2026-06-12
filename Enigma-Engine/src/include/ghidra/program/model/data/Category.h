/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file Category.h
/// \brief Interface for a category in the data type tree
#pragma once

#include <memory>
#include <string>
#include <vector>
#include <ghidra/program/model/data/CategoryPath.h>

namespace ghidra {

class DataType;

class Category {
public:
    virtual ~Category() = default;

    virtual std::string getName() const = 0;
    virtual CategoryPath getCategoryPath() const = 0;
    virtual std::shared_ptr<Category> getParent() const = 0;
    virtual std::vector<std::shared_ptr<Category>> getCategories() const = 0;
    virtual std::shared_ptr<Category> getCategory(const std::string& name) const = 0;
    virtual std::shared_ptr<Category> createCategory(const std::string& name) = 0;
    virtual void removeCategory(const std::string& name) = 0;
    virtual void moveCategory(const std::shared_ptr<Category>& newParent) = 0;
    virtual void rename(const std::string& newName) = 0;

    virtual std::vector<std::shared_ptr<DataType>> getDataTypes() const = 0;
    virtual std::shared_ptr<DataType> getDataType(const std::string& name) const = 0;
    virtual std::shared_ptr<DataType> addDataType(const std::shared_ptr<DataType>& dataType) = 0;
    virtual void removeDataType(const std::string& name) = 0;
    virtual int getNumDataTypes() const = 0;
    virtual int getNumCategories() const = 0;
    virtual bool isEmpty() const = 0;
    virtual bool isRoot() const = 0;
};

} // namespace ghidra
