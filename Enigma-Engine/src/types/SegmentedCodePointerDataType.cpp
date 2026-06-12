/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SegmentedCodePointerDataType.cpp
/// \brief Segmented code pointer data type implementation
#include "ghidra/SegmentedCodePointerDataType.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/AddressSpace.h"
#include "ghidra/Address.h"
#include <sstream>
#include <cstdint>

namespace ghidra {

SegmentedCodePointerDataType::SegmentedCodePointerDataType(DataTypeManager* dtm)
    : BuiltIn(CategoryPath::ROOT(), "SegmentedCodeAddress", dtm) {}

std::string SegmentedCodePointerDataType::getDescription() const {
    return "Code address from 16 bit segment and 16 bit offset";
}

int SegmentedCodePointerDataType::getLength() const {
    return 4;
}

std::string SegmentedCodePointerDataType::getMnemonic(Settings* settings) const {
    return "segAddr";
}

std::string SegmentedCodePointerDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    Address currentAddr = buf->getAddress();
    AddressSpace* space = currentAddr.getAddressSpace();
    if (!space) return "??";

    uint16_t segment, offset;
    try {
        segment = static_cast<uint16_t>(buf->getShort(0));
        offset = static_cast<uint16_t>(buf->getShort(2));
    } catch (...) {
        return "??";
    }

    uint64_t addrValue = (static_cast<uint64_t>(segment) << 16) | offset;
    Address addr = space->getAddress(static_cast<int64_t>(addrValue));
    return addr.toString();
}

const std::type_info& SegmentedCodePointerDataType::getValueClass(Settings* settings) const {
    return typeid(Address);
}

DataType* SegmentedCodePointerDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<SegmentedCodePointerDataType*>(this);
    }
    return new SegmentedCodePointerDataType(dtm);
}

} // namespace ghidra
