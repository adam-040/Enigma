/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AlignedComponentPacker.h
/// \brief Provides component packing support for aligned structures.
/// Package-private; internal to the data model.
#pragma once

#include <ghidra/DataOrganization.h>
#include <ghidra/BitFieldPacking.h>
#include <ghidra/CompositeInternal.h>
#include <ghidra/DataOrganizationImpl.h>

namespace ghidra {

class InternalDataTypeComponent;
class BitFieldDataType;

class AlignedComponentPacker {
public:
    AlignedComponentPacker(int packValue, DataOrganization* dataOrganization);

    void addComponent(InternalDataTypeComponent* dtc, bool isLastComponent);
    bool componentsChanged() const;
    int getDefaultAlignment() const;
    int getLength() const;

private:
    bool packComponent(InternalDataTypeComponent* dataTypeComponent);
    void initGroup(InternalDataTypeComponent* dataTypeComponent, bool isLastComponent);
    void alignAndPackNonBitfieldComponent(InternalDataTypeComponent* dataTypeComponent, int minOffset);
    void alignAndPackBitField(InternalDataTypeComponent* dataTypeComponent);
    int setBitFieldDataType(InternalDataTypeComponent* dataTypeComponent,
                            BitFieldDataType* currentBitFieldDt, int bitsConsumed);
    void updateComponent(InternalDataTypeComponent* dataTypeComponent, int ordinal,
                         int offset, int length, int alignment);
    int getComponentAlignmentLCM(int allComponentsLCM);

    int getBitFieldTypeSize(InternalDataTypeComponent* dataTypeComponent);
    int getBitFieldAlignment(BitFieldDataType* bitfieldDt) const;
    bool isIgnoredZeroBitField(BitFieldDataType* zeroBitFieldDt);
    int getZeroBitFieldAlignment(BitFieldDataType* zeroBitFieldDt, bool isLastComponent);
    void adjustZeroLengthBitField(int ordinal, int minimumAlignment);

    DataOrganization* dataOrganization_;
    BitFieldPacking* bitFieldPacking_;
    int packValue_;
    int nextOrdinal_ = 0;
    int zeroAlignment_ = 0;
    int lastAlignment_ = 0;
    int groupOffset_ = -1;
    InternalDataTypeComponent* lastComponent_ = nullptr;
    int defaultAlignment_ = 1;
    bool componentsChanged_ = false;
};

} // namespace ghidra
