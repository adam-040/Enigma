/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file StructureDataType.h
/// \brief Basic implementation of the structure data type.
#pragma once

#include "CompositeDataTypeImpl.h"
#include "Structure.h"
#include "BitFieldPacking.h"
#include <vector>

namespace ghidra {

class StructureDataType : public CompositeDataTypeImpl, public virtual Structure {
protected:
    int structLength_;
    int numComponents_;
    std::vector<DataTypeComponentImpl*> components_;

public:
    StructureDataType(const std::string& name, int length, DataTypeManager* dtm = nullptr);

    StructureDataType(const CategoryPath& path, const std::string& name, int length, DataTypeManager* dtm = nullptr);

    virtual ~StructureDataType();

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

    bool hasLanguageDependantLength() const override;

    std::string getRepresentation(MemBuffer*, Settings*, int) const override;

    std::string getDefaultLabelPrefix() const override;

    Structure* clone(DataTypeManager* dtm) const override;

    DataType* copy(DataTypeManager* dtm) const override;

    DataTypeComponent* getDefinedComponentAtOrAfterOffset(int offset) const override;

    DataTypeComponent* getComponentContaining(int offset) const override;

    std::vector<DataTypeComponent*> getComponentsContaining(int offset) const override;

    DataTypeComponent* getDataTypeAt(int offset) const override;

    DataTypeComponent* insertBitField(int ordinal, int byteWidth, int bitOffset, DataType* baseDataType, int bitSize, const std::string& componentName, const std::string& comment) override;

    DataTypeComponent* insertBitFieldAt(int byteOffset, int byteWidth, int bitOffset, DataType* baseDataType, int bitSize, const std::string& componentName, const std::string& comment) override;

    DataTypeComponent* insertAtOffset(int offset, DataType* dataType, int length) override;

    DataTypeComponent* insertAtOffset(int offset, DataType* dataType, int length, const std::string& componentName, const std::string& comment) override;

    void deleteAtOffset(int offset) override;

    void deleteAll() override;

    void clearAtOffset(int offset) override;
    void clearComponent(int ordinal) override;

    DataTypeComponent* replace(int ordinal, DataType* dataType, int length) override;

    DataTypeComponent* replace(int ordinal, DataType* dataType, int length, const std::string& name, const std::string& comment) override;

    DataTypeComponent* replaceAtOffset(int offset, DataType* dataType, int length, const std::string& name, const std::string& comment) override;

    void growStructure(int amount) override;

    void setLength(int length) override;

    void repack() override;

    bool isEquivalent(const DataType* dt) const override;
};

} // namespace ghidra
