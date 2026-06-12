/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Composite.h
/// \brief Interface for common methods in Structure and Union
#pragma once

#include "DataType.h"
#include "DataTypeComponent.h"
#include "UsrException.h"
#include <vector>
#include <set>

namespace ghidra {

class InvalidDataTypeException : public UsrException {
public:
    explicit InvalidDataTypeException(const std::string& msg) : UsrException(msg) {}
};

enum class PackingType {
    DEFAULT,
    EXPLICIT,
    DISABLED
};

enum class AlignmentType {
    DEFAULT,
    MACHINE,
    EXPLICIT
};

/**
 * Interface for common methods in Structure and Union.
 * Translated from: ghidra.program.model.data.Composite
 */
class Composite : public virtual DataType {
public:
    virtual ~Composite() = default;

    virtual int getNumComponents() const = 0;

    virtual int getNumDefinedComponents() const = 0;

    virtual DataTypeComponent* getComponent(int ordinal) const = 0;

    virtual DataTypeComponent* findComponent(const std::string& fieldName) const;

    virtual std::vector<DataTypeComponent*> findComponents(const std::string& name) const;

    virtual std::vector<DataTypeComponent*> getComponents() const = 0;

    virtual std::vector<DataTypeComponent*> getDefinedComponents() const = 0;

    virtual DataTypeComponent* add(DataType* dataType) = 0;

    virtual DataTypeComponent* add(DataType* dataType, int length) = 0;

    virtual DataTypeComponent* add(DataType* dataType, const std::string& componentName, const std::string& comment) = 0;

    virtual DataTypeComponent* addBitField(DataType* baseDataType, int bitSize, const std::string& componentName, const std::string& comment) = 0;

    virtual DataTypeComponent* add(DataType* dataType, int length, const std::string& componentName, const std::string& comment) = 0;

    virtual DataTypeComponent* insert(int ordinal, DataType* dataType) = 0;

    virtual DataTypeComponent* insert(int ordinal, DataType* dataType, int length) = 0;

    virtual DataTypeComponent* insert(int ordinal, DataType* dataType, int length, const std::string& componentName, const std::string& comment) = 0;

    virtual void deleteComponent(int ordinal) = 0; // Renamed from delete to avoid C++ keyword

    virtual void deleteComponents(const std::set<int>& ordinals) = 0; // Renamed

    virtual bool isPartOf(const DataType* dataType) const = 0;

    virtual void repack() = 0;

    virtual PackingType getPackingType() const = 0;

    virtual bool isPackingEnabled() const;

    virtual void setPackingEnabled(bool enabled) = 0;

    virtual bool hasExplicitPackingValue() const;

    virtual bool hasDefaultPacking() const;

    virtual int getExplicitPackingValue() const = 0;

    virtual void setExplicitPackingValue(int packingValue) = 0;

    virtual void pack(int packingValue);

    virtual void setToDefaultPacking() = 0;

    virtual AlignmentType getAlignmentType() const = 0;

    virtual bool isDefaultAligned() const;

    virtual bool isMachineAligned() const;

    virtual bool hasExplicitMinimumAlignment() const;

    virtual int getExplicitMinimumAlignment() const = 0;

    virtual void setExplicitMinimumAlignment(int minAlignment) = 0;

    virtual void align(int minAlignment);

    virtual void setToDefaultAligned() = 0;

    virtual void setToMachineAligned() = 0;
};

} // namespace ghidra
