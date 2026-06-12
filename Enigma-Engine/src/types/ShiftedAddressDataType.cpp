/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ShiftedAddressDataType.cpp
/// \brief Shifted address data type implementation
#include "ghidra/ShiftedAddressDataType.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/AddressSpace.h"
#include "ghidra/Address.h"
#include "ghidra/DataOrganization.h"
#include <vector>
#include <cstdint>

namespace ghidra {

ShiftedAddressDataType& ShiftedAddressDataType::dataType() {
    static ShiftedAddressDataType instance;
    return instance;
}

ShiftedAddressDataType::ShiftedAddressDataType(DataTypeManager* dtm)
    : BuiltIn(CategoryPath::ROOT(), "ShiftedAddress", dtm) {}

std::string ShiftedAddressDataType::getDescription() const {
    return "shifted address (as specified by compiler spec)";
}

int ShiftedAddressDataType::getLength() const {
    DataOrganization* org = getDataOrganization();
    return org ? org->getPointerSize() : 4;
}

bool ShiftedAddressDataType::hasLanguageDependantLength() const {
    return true;
}

std::string ShiftedAddressDataType::getMnemonic(Settings* settings) const {
    return "addr";
}

Address ShiftedAddressDataType::getAddressValue(MemBuffer* buf, int size, int shift, AddressSpace* targetSpace) {
    if (size <= 0 || size > 8 || !targetSpace) {
        return Address();
    }

    std::vector<uint8_t> bytes(size);
    if (buf->getBytes(bytes.data(), size, 0) != size) {
        return Address();
    }

    uint64_t val = 0;
    if (buf->isBigEndian()) {
        for (int i = 0; i < size; i++) {
            val = (val << 8) | bytes[i];
        }
    } else {
        for (int i = size - 1; i >= 0; i--) {
            val = (val << 8) | bytes[i];
        }
    }

    val <<= shift;

    return targetSpace->getAddress(static_cast<int64_t>(val));
}

std::string ShiftedAddressDataType::getString(MemBuffer* buf, Settings* settings) const {
    DataOrganization* org = getDataOrganization();
    if (!org) return "??";

    int ptrSize = org->getPointerSize();
    int ptrShift = org->getPointerShift();

    AddressSpace* space = buf->getAddress().getAddressSpace();
    if (!space) return "??";

    Address addr = getAddressValue(buf, ptrSize, ptrShift, space);
    if (addr.isValid()) {
        return addr.toString();
    }
    return "??";
}

std::string ShiftedAddressDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return getString(buf, settings);
}

const std::type_info& ShiftedAddressDataType::getValueClass(Settings* settings) const {
    return typeid(Address);
}

DataType* ShiftedAddressDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<ShiftedAddressDataType*>(this);
    }
    return new ShiftedAddressDataType(dtm);
}

} // namespace ghidra
