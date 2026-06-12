/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file UnsignedShortDataType.cpp
/// \brief Unsigned Short Integer data type implementation
#include "ghidra/UnsignedShortDataType.h"
#include "ghidra/ShortDataType.h"

namespace ghidra {

UnsignedShortDataType& UnsignedShortDataType::dataType() {
    static UnsignedShortDataType instance;
    return instance;
}

UnsignedShortDataType::UnsignedShortDataType(DataTypeManager* dtm)
    : AbstractUnsignedIntegerDataType("ushort", dtm) {}

bool UnsignedShortDataType::hasLanguageDependantLength() const {
    return true;
}

int UnsignedShortDataType::getLength() const {
    DataOrganization* org = getDataOrganization();
    return org ? org->getShortSize() : 2;
}

std::string UnsignedShortDataType::getDescription() const {
    return "Unsigned Short Integer (compiler-specific size)";
}

std::string UnsignedShortDataType::getCDeclaration() const {
    return C_UNSIGNED_SHORT;
}

AbstractIntegerDataType* UnsignedShortDataType::getOppositeSignednessDataType() const {
    return new ShortDataType(getDataTypeManager());
}

DataType* UnsignedShortDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<UnsignedShortDataType*>(this);
    }
    return new UnsignedShortDataType(dtm);
}

std::string UnsignedShortDataType::getCTypeDeclaration(DataOrganization* dataOrganization) const {
    return "";
}

} // namespace ghidra
