/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file UnsignedLongLongDataType.cpp
/// \brief Unsigned Long Long Integer data type implementation
#include "ghidra/UnsignedLongLongDataType.h"
#include "ghidra/LongLongDataType.h"

namespace ghidra {

UnsignedLongLongDataType& UnsignedLongLongDataType::dataType() {
    static UnsignedLongLongDataType instance;
    return instance;
}

UnsignedLongLongDataType::UnsignedLongLongDataType(DataTypeManager* dtm)
    : AbstractUnsignedIntegerDataType("ulonglong", dtm) {}

bool UnsignedLongLongDataType::hasLanguageDependantLength() const {
    return true;
}

int UnsignedLongLongDataType::getLength() const {
    DataOrganization* org = getDataOrganization();
    return org ? org->getLongLongSize() : 8;
}

std::string UnsignedLongLongDataType::getDescription() const {
    return "Unsigned Long Long Integer (compiler-specific size)";
}

std::string UnsignedLongLongDataType::getCDeclaration() const {
    return C_UNSIGNED_LONGLONG;
}

AbstractIntegerDataType* UnsignedLongLongDataType::getOppositeSignednessDataType() const {
    return new LongLongDataType(getDataTypeManager());
}

DataType* UnsignedLongLongDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<UnsignedLongLongDataType*>(this);
    }
    return new UnsignedLongLongDataType(dtm);
}

std::string UnsignedLongLongDataType::getCTypeDeclaration(DataOrganization* dataOrganization) const {
    return "";
}

} // namespace ghidra
