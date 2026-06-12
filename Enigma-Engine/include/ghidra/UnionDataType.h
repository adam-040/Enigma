/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file UnionDataType.h
/// \brief Basic implementation of the union data type.
#pragma once

#include "CompositeDataTypeImpl.h"
#include "Union.h"
#include <vector>
#include <algorithm>

namespace ghidra {

class UnionDataType : public CompositeDataTypeImpl, public virtual Union {
protected:
    int unionLength_;
    std::vector<DataTypeComponentImpl*> components_;

public:
    UnionDataType(const std::string& name, DataTypeManager* dtm = nullptr);

    UnionDataType(const CategoryPath& path, const std::string& name, DataTypeManager* dtm = nullptr);

    virtual ~UnionDataType();

    int getNumComponents() const override;
    int getNumDefinedComponents() const override;

    DataTypeComponent* getComponent(int ordinal) const override;

    std::vector<DataTypeComponent*> getComponents() const override;

    std::vector<DataTypeComponent*> getDefinedComponents() const override;

    DataTypeComponent* add(DataType* dataType) override;

    DataTypeComponent* add(DataType* dataType, int length) override;

    DataTypeComponent* add(DataType* dataType, const std::string& componentName, const std::string& comment) override;

    DataTypeComponent* add(DataType* dataType, int length, const std::string& componentName, const std::string& comment) override;

    DataTypeComponent* insert(int ordinal, DataType* dataType) override;

    DataTypeComponent* insert(int ordinal, DataType* dataType, int length) override;

    DataTypeComponent* insert(int ordinal, DataType* dataType, int length, const std::string& name, const std::string& comment) override;

    void deleteComponent(int ordinal) override;

    void deleteComponents(const std::set<int>& ordinals) override;

    bool isZeroLength() const override;

    int getLength() const override;

    void repack() override;

    bool hasLanguageDependantLength() const override;

    std::string getRepresentation(MemBuffer*, Settings*, int) const override;

    std::string getDefaultLabelPrefix() const override;

    DataType* clone(DataTypeManager* dtm) const override;

    DataType* copy(DataTypeManager* dtm) const override;

    bool isEquivalent(const DataType* dt) const override;
};

} // namespace ghidra
