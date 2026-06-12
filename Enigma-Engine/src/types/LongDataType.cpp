/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file LongDataType.cpp
/// \file LongDataType.cpp
/// \brief Signed Long Integer data type implementation
#include "ghidra/LongDataType.h"
#include "ghidra/UnsignedLongDataType.h"

namespace ghidra {

LongDataType& LongDataType::dataType() {
    static LongDataType instance;
    return instance;
}

LongDataType::LongDataType(DataTypeManager* dtm)
    : AbstractSignedIntegerDataType("long", dtm) {}

bool LongDataType::hasLanguageDependantLength() const {
    return true;
}

int LongDataType::getLength() const {
    DataOrganization* org = getDataOrganization();
    return org ? org->getLongSize() : 4;
}

std::string LongDataType::getDescription() const {
    return "Signed Long Integer (compiler-specific size)";
}

std::string LongDataType::getCDeclaration() const {
    return C_SIGNED_LONG;
}

AbstractIntegerDataType* LongDataType::getOppositeSignednessDataType() const {
    return new UnsignedLongDataType(getDataTypeManager());
}

DataType* LongDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<LongDataType*>(this);
    }
    return new LongDataType(dtm);
}

std::string LongDataType::getCTypeDeclaration(DataOrganization* dataOrganization) const {
    return "";
}

} // namespace ghidra
