/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file BitFieldDataType.h
/// \brief Minimal bitfield datatype for use in structures and unions.
#pragma once

#include <algorithm>
#include <stdexcept>
#include <string>
#include <typeinfo>

#include "DataTypeImpl.h"
#include "TypeDef.h"
#include "Enum.h"
#include "AbstractIntegerDataType.h"

namespace ghidra {

class BitFieldDataType : public DataTypeImpl {
private:
    static constexpr int MAX_BIT_LENGTH = 255;

    DataType* baseDataType_;
    bool ownsBaseDataType_;
    int declaredBitSize_;
    int effectiveBitSize_;
    int bitOffset_;
    int storageSize_;

public:
    static int getEffectiveBitSize(int declaredBitSize, int baseTypeByteSize);

    static int getMinimumStorageSize(int bitSize, int bitOffset = 0);

    static bool isValidBaseDataType(DataType* baseDataType);

    static void checkBaseDataType(DataType* baseDataType);

    BitFieldDataType(DataType* baseDataType, int bitSize, int bitOffset = 0, bool ownsBaseDataType = false);

    ~BitFieldDataType() override;

    bool isZeroLength() const override;

    bool hasLanguageDependantLength() const override;

    DataType* clone(DataTypeManager* dtm) const override;

    DataType* copy(DataTypeManager* dtm) const override;

    int getLength() const override;

    int getAlignedLength() const override;

    std::string getDescription() const override;

    std::string getRepresentation(MemBuffer*, Settings*, int) const override;

    const std::type_info& getValueClass(Settings*) const override;

    bool isEquivalent(const DataType* dt) const override;

    int getAlignment() const override;

    int getBitSize() const;

    int getDeclaredBitSize() const;

    int getBitOffset() const;

    int getStorageSize() const;

    int getBaseTypeSize() const;

    DataType* getBaseDataType() const;

    std::string getDefaultLabelPrefix() const override;
};

} // namespace ghidra
