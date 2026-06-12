/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file GenericDataType.cpp
/// \brief Base implementation for generic data types
#include "ghidra/GenericDataType.h"

namespace ghidra {

GenericDataType::GenericDataType(const CategoryPath& path, const std::string& name, DataTypeManager* dataMgr)
    : DataTypeImpl(path, name, dataMgr) {}

GenericDataType::~GenericDataType() = default;

void GenericDataType::setName(const std::string& name) {
    if (name.empty()) throw std::invalid_argument("Invalid DataType name");
    if (name_ == name) return;
    name_ = name;
}

void GenericDataType::setNameAndCategory(const CategoryPath& path, const std::string& name) {
    setName(name);
    setCategoryPath(path);
}

void GenericDataType::setCategoryPath(const CategoryPath& path) {
    categoryPath_ = path;
}

void GenericDataType::setDescription(const std::string& description) {
    description_ = description;
}

std::string GenericDataType::getDescription() const {
    return description_;
}

} // namespace ghidra
