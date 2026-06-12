/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file UnsignedLongDataType.cpp
/// \brief Unsigned Long Integer data type implementation
#include "ghidra/UnsignedLongDataType.h"
#include "ghidra/LongDataType.h"

namespace ghidra {

UnsignedLongDataType& UnsignedLongDataType::dataType() {
    static UnsignedLongDataType instance;
    return instance;
}

UnsignedLongDataType::UnsignedLongDataType(DataTypeManager* dtm)
    : AbstractUnsignedIntegerDataType("ulong", dtm) {}

bool UnsignedLongDataType::hasLanguageDependantLength() const {
    return true;
}

int UnsignedLongDataType::getLength() const {
    DataOrganization* org = getDataOrganization();
    return org ? org->getLongSize() : 4;
}

std::string UnsignedLongDataType::getDescription() const {
    return "Unsigned Long Integer (compiler-specific size)";
}

std::string UnsignedLongDataType::getCDeclaration() const {
    return C_UNSIGNED_LONG;
}

AbstractIntegerDataType* UnsignedLongDataType::getOppositeSignednessDataType() const {
    return new LongDataType(getDataTypeManager());
}

DataType* UnsignedLongDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<UnsignedLongDataType*>(this);
    }
    return new UnsignedLongDataType(dtm);
}

std::string UnsignedLongDataType::getCTypeDeclaration(DataOrganization* dataOrganization) const {
    return "";
}

} // namespace ghidra
