/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file LongLongDataType.cpp
/// \brief Signed Long Long Integer data type implementation
#include "ghidra/LongLongDataType.h"
#include "ghidra/UnsignedLongLongDataType.h"

namespace ghidra {

LongLongDataType& LongLongDataType::dataType() {
    static LongLongDataType instance;
    return instance;
}

LongLongDataType::LongLongDataType(DataTypeManager* dtm)
    : AbstractSignedIntegerDataType("longlong", dtm) {}

bool LongLongDataType::hasLanguageDependantLength() const {
    return true;
}

int LongLongDataType::getLength() const {
    DataOrganization* org = getDataOrganization();
    return org ? org->getLongLongSize() : 8;
}

std::string LongLongDataType::getDescription() const {
    return "Signed Long Long Integer (compiler-specific size)";
}

std::string LongLongDataType::getCDeclaration() const {
    return C_SIGNED_LONGLONG;
}

AbstractIntegerDataType* LongLongDataType::getOppositeSignednessDataType() const {
    return new UnsignedLongLongDataType(getDataTypeManager());
}

DataType* LongLongDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<LongLongDataType*>(this);
    }
    return new LongLongDataType(dtm);
}

std::string LongLongDataType::getCTypeDeclaration(DataOrganization* dataOrganization) const {
    return "";
}

} // namespace ghidra
