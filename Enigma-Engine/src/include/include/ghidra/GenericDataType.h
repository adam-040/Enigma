/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file GenericDataType.h
/// \brief Base implementation for generic data types that support mutable name/category/description.
#pragma once

#include "DataTypeImpl.h"

namespace ghidra {

/**
 * Base implementation for a generic data type.
 * Unlike BuiltIn types, GenericDataTypes support mutable name, category, and description.
 * Translated from: ghidra.program.model.data.GenericDataType
 *
 * Ghidra hierarchy:
 *   DataType → AbstractDataType → DataTypeImpl → GenericDataType
 *   Used by: EnumDataType, TypedefDataType, FunctionDefinitionDataType, CompositeDataTypeImpl
 */
class GenericDataType : public DataTypeImpl {
protected:
    std::string description_;

    GenericDataType(const CategoryPath& path, const std::string& name, DataTypeManager* dataMgr);

public:
    virtual ~GenericDataType();

    void setName(const std::string& name) override;

    void setNameAndCategory(const CategoryPath& path, const std::string& name) override;

    void setCategoryPath(const CategoryPath& path) override;

    void setDescription(const std::string& description) override;

    std::string getDescription() const override;
};

} // namespace ghidra
