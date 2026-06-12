/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CompositeDataTypeImpl.h
/// \brief Common implementation methods for structure and union.
#pragma once

#include "GenericDataType.h"
#include "Composite.h"
#include "DataTypeComponentImpl.h"
#include "BitFieldDataType.h"

namespace ghidra {

static constexpr int NO_PACKING = -1;
static constexpr int DEFAULT_PACKING = 0;
static constexpr int DEFAULT_ALIGNMENT = 0;
static constexpr int MACHINE_ALIGNMENT = -1;

class CompositeDataTypeImpl : public GenericDataType, public virtual Composite {
protected:
    int minimumAlignment_;
    int packing_;

    CompositeDataTypeImpl(const CategoryPath& path, const std::string& name, DataTypeManager* dtm);

    int getPreferredComponentLength(DataType* dataType, int length) const;

public:
    virtual ~CompositeDataTypeImpl();

    DataTypeComponent* addBitField(DataType* baseDataType, int bitSize, const std::string& componentName, const std::string& comment) override;

    bool isNotYetDefined() const override;

    bool isPartOf(const DataType* dataType) const override;

    int getAlignedLength() const override;

    std::string getMnemonic(Settings*) const override;

    const std::type_info& getValueClass(Settings*) const override;

    PackingType getPackingType() const override;

    void setPackingEnabled(bool enabled) override;

    void setToDefaultPacking() override;

    int getExplicitPackingValue() const override;

    void setExplicitPackingValue(int packingValue) override;

    AlignmentType getAlignmentType() const override;

    void setToDefaultAligned() override;

    void setToMachineAligned() override;

    int getExplicitMinimumAlignment() const override;

    void setExplicitMinimumAlignment(int minAlignment) override;

    int alignTo(int offset, int alignment) const;

    int getBitFieldAlignment(BitFieldDataType* bitField, BitFieldPacking* packing) const;

    void repack() override;

    std::string getRepresentation(MemBuffer*, Settings*, int) const override;
};

} // namespace ghidra
