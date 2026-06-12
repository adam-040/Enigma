/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeManagerImpl.cpp
/// \brief Concrete standard data type manager implementation
#include <ghidra/DataTypeManagerImpl.h>
#include <ghidra/VoidDataType.h>
#include <ghidra/BooleanDataType.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/SignedByteDataType.h>
#include <ghidra/ShortDataType.h>
#include <ghidra/IntegerDataType.h>
#include <ghidra/LongDataType.h>
#include <ghidra/LongLongDataType.h>
#include <ghidra/UnsignedShortDataType.h>
#include <ghidra/UnsignedIntegerDataType.h>
#include <ghidra/UnsignedLongDataType.h>
#include <ghidra/UnsignedLongLongDataType.h>
#include <ghidra/FloatDataType.h>
#include <ghidra/DoubleDataType.h>
#include <ghidra/LongDoubleDataType.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/StringDataType.h>

namespace ghidra {

DataTypeManagerImpl::DataTypeManagerImpl() : DataTypeManagerImpl("ProgramDB") {}

DataTypeManagerImpl::DataTypeManagerImpl(const std::string& name) : name_(name) {
    dataOrganization_ = std::make_unique<DataOrganizationImpl>();
    populateBuiltInTypes();
}

DataTypeManagerImpl::~DataTypeManagerImpl() = default;

const std::string& DataTypeManagerImpl::getName() const {
    return name_;
}

DataType* DataTypeManagerImpl::getDataType(const CategoryPath& categoryPath, const std::string& name) {
    std::string key = categoryPath.getPath(name);
    auto it = typesByPath_.find(key);
    if (it != typesByPath_.end()) {
        return it->second;
    }
    return nullptr;
}

DataType* DataTypeManagerImpl::getDataType(long id) {
    auto it = typesById_.find(id);
    if (it != typesById_.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<DataType*> DataTypeManagerImpl::getDataTypes() {
    std::vector<DataType*> result;
    result.reserve(types_.size());
    for (const auto& ptr : types_) {
        result.push_back(ptr.get());
    }
    return result;
}

DataOrganization* DataTypeManagerImpl::getDataOrganization() const {
    return dataOrganization_.get();
}

DataType* DataTypeManagerImpl::resolve(DataType* dataType, DataTypeConflictHandler* handler) {
    if (!dataType) return nullptr;
    // Check if type already exists by path
    std::string path = dataType->getCategoryPath().getPath(dataType->getName());
    auto it = typesByPath_.find(path);
    if (it != typesByPath_.end())
        return it->second;
    // Not found — add it
    return addDataType(dataType);
}

DataType* DataTypeManagerImpl::addDataType(DataType* dt) {
    if (!dt) return nullptr;

    // Check if already registered (exact same pointer)
    for (const auto& ptr : types_) {
        if (ptr.get() == dt) {
            return dt;
        }
    }

    // Check if equivalent exists by path
    std::string key = dt->getCategoryPath().getPath(dt->getName());
    auto it = typesByPath_.find(key);
    if (it != typesByPath_.end()) {
        return it->second;
    }

    // Register
    types_.push_back(std::unique_ptr<DataType>(dt));
    long id = getNextId();
    typesById_[id] = dt;
    typesByPath_[key] = dt;
    return dt;
}

DataType* DataTypeManagerImpl::addDataTypeWithId(DataType* dt, long id) {
    if (!dt) return nullptr;

    // Check if already registered (exact same pointer)
    for (const auto& ptr : types_) {
        if (ptr.get() == dt) {
            return dt;
        }
    }

    // Check if equivalent exists by path
    std::string key = dt->getCategoryPath().getPath(dt->getName());
    auto it = typesByPath_.find(key);
    if (it != typesByPath_.end()) {
        return it->second;
    }

    // Register with exact ID
    types_.push_back(std::unique_ptr<DataType>(dt));
    typesById_[id] = dt;
    typesByPath_[key] = dt;

    if (id >= nextId_) {
        nextId_ = id + 1;
    }
    return dt;
}

void DataTypeManagerImpl::clearAllDataTypes() {
    types_.clear();
    typesById_.clear();
    typesByPath_.clear();
    nextId_ = 1000;
    populateBuiltInTypes();
}

void DataTypeManagerImpl::removeDataType(DataType* dt) {
    if (!dt) return;
    
    // Find ID and path keys
    long idToDelete = -1;
    for (const auto& pair : typesById_) {
        if (pair.second == dt) {
            idToDelete = pair.first;
            break;
        }
    }
    
    std::string pathToDelete;
    for (const auto& pair : typesByPath_) {
        if (pair.second == dt) {
            pathToDelete = pair.first;
            break;
        }
    }

    if (idToDelete != -1) typesById_.erase(idToDelete);
    if (!pathToDelete.empty()) typesByPath_.erase(pathToDelete);

    auto it = std::find_if(types_.begin(), types_.end(),
                           [dt](const std::unique_ptr<DataType>& p) { return p.get() == dt; });
    if (it != types_.end()) {
        types_.erase(it);
    }
}

long DataTypeManagerImpl::getNextId() {
    return nextId_++;
}

void DataTypeManagerImpl::populateBuiltInTypes() {
    // Standard primitive types prepopulation
    auto addBuiltIn = [this](DataType* dt, long id) {
        types_.push_back(std::unique_ptr<DataType>(dt));
        typesById_[id] = dt;
        std::string key = dt->getCategoryPath().getPath(dt->getName());
        typesByPath_[key] = dt;
    };

    addBuiltIn(new VoidDataType(this), 1);
    addBuiltIn(new BooleanDataType(this), 2);
    addBuiltIn(new ByteDataType(this), 3);
    addBuiltIn(new SignedByteDataType(this), 4);
    addBuiltIn(new ShortDataType(this), 5);
    addBuiltIn(new IntegerDataType(this), 6);
    addBuiltIn(new LongDataType(this), 7);
    addBuiltIn(new LongLongDataType(this), 8);
    addBuiltIn(new UnsignedShortDataType(this), 9);
    addBuiltIn(new UnsignedIntegerDataType(this), 10);
    addBuiltIn(new UnsignedLongDataType(this), 11);
    addBuiltIn(new UnsignedLongLongDataType(this), 12);
    addBuiltIn(new FloatDataType(this), 13);
    addBuiltIn(new DoubleDataType(this), 14);
    addBuiltIn(new LongDoubleDataType(this), 15);
    addBuiltIn(new StringDataType(this), 16);
}

long DataTypeManagerImpl::getDataTypeId(DataType* dt) const {
    if (!dt) return -1;
    for (const auto& pair : typesById_) {
        if (pair.second == dt) {
            return pair.first;
        }
    }
    return -1;
}

} // namespace ghidra
