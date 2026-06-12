/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AlignmentDataType.cpp
/// \brief Alignment data type implementation
#include "ghidra/AlignmentDataType.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/ByteDataType.h"
#include <typeinfo>

namespace ghidra {

AlignmentDataType& AlignmentDataType::dataType() {
    static AlignmentDataType instance;
    return instance;
}

AlignmentDataType::AlignmentDataType(DataTypeManager* dtm)
    : BuiltIn(CategoryPath::ROOT(), "Alignment", dtm), Dynamic() {}

DataType* AlignmentDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<AlignmentDataType*>(this);
    }
    return new AlignmentDataType(dtm);
}

std::string AlignmentDataType::getDescription() const {
    return "Consumes alignment/repeating bytes.";
}

std::string AlignmentDataType::getMnemonic(Settings* settings) const {
    return "align";
}

bool AlignmentDataType::canSpecifyLength() {
    return true;
}

int AlignmentDataType::getLength(MemBuffer* buf, int maxLength) {
    if (maxLength < 0) {
        return computeLength(buf);
    }
    return maxLength;
}

std::string AlignmentDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return "align(" + std::to_string(length) + ")";
}

const std::type_info& AlignmentDataType::getValueClass(Settings* settings) const {
    return typeid(std::string);
}

int AlignmentDataType::getLength() const {
    return -1;
}

DataType* AlignmentDataType::getReplacementBaseType() {
    return &ByteDataType::dataType();
}

std::string AlignmentDataType::getCTypeDeclaration(DataOrganization* dataOrganization) {
    return getDecompilerDisplayName();
}

void AlignmentDataType::setDefaultSettings(Settings* settings) {
    BuiltIn::setDefaultSettings(settings);
}

int AlignmentDataType::computeLength(MemBuffer* buf) const {
    int length = 0;
    try {
        uint8_t startByte = buf->getUnsignedByte(0);
        while (length < MAX_LENGTH) {
            uint8_t b = buf->getUnsignedByte(length);
            if (b != startByte) break;
            ++length;
        }
    } catch (const MemoryAccessException&) {
        // stop counting
    }
    return length > 0 ? length : -1;
}

} // namespace ghidra
