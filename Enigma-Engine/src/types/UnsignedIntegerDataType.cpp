/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file UnsignedIntegerDataType.cpp
/// \brief Unsigned Integer data type implementation
#include "ghidra/UnsignedIntegerDataType.h"
#include "ghidra/IntegerDataType.h"

namespace ghidra {

UnsignedIntegerDataType& UnsignedIntegerDataType::dataType() {
    static UnsignedIntegerDataType instance;
    return instance;
}

UnsignedIntegerDataType::UnsignedIntegerDataType(DataTypeManager* dtm)
    : AbstractUnsignedIntegerDataType("uint", dtm) {}

bool UnsignedIntegerDataType::hasLanguageDependantLength() const {
    return true;
}

int UnsignedIntegerDataType::getLength() const {
    DataOrganization* org = getDataOrganization();
    return org ? org->getIntegerSize() : 4;
}

std::string UnsignedIntegerDataType::getDescription() const {
    return "Unsigned Integer (compiler-specific size)";
}

std::string UnsignedIntegerDataType::getCDeclaration() const {
    return C_UNSIGNED_INT;
}

AbstractIntegerDataType* UnsignedIntegerDataType::getOppositeSignednessDataType() const {
    return new IntegerDataType(getDataTypeManager());
}

DataType* UnsignedIntegerDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<UnsignedIntegerDataType*>(this);
    }
    return new UnsignedIntegerDataType(dtm);
}

std::string UnsignedIntegerDataType::getCTypeDeclaration(DataOrganization* dataOrganization) const {
    return "";
}

} // namespace ghidra
