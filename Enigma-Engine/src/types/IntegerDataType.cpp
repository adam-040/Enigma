/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file IntegerDataType.cpp
/// \brief Signed Integer data type implementation
#include "ghidra/IntegerDataType.h"
#include "ghidra/UnsignedIntegerDataType.h"

namespace ghidra {

IntegerDataType& IntegerDataType::dataType() {
    static IntegerDataType instance;
    return instance;
}

IntegerDataType::IntegerDataType(DataTypeManager* dtm)
    : AbstractSignedIntegerDataType("int", dtm) {}

bool IntegerDataType::hasLanguageDependantLength() const {
    return true;
}

int IntegerDataType::getLength() const {
    DataOrganization* org = getDataOrganization();
    return org ? org->getIntegerSize() : 4;
}

std::string IntegerDataType::getDescription() const {
    return "Signed Integer (compiler-specific size)";
}

std::string IntegerDataType::getCDeclaration() const {
    return C_SIGNED_INT;
}

AbstractIntegerDataType* IntegerDataType::getOppositeSignednessDataType() const {
    return new UnsignedIntegerDataType(getDataTypeManager());
}

DataType* IntegerDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<IntegerDataType*>(this);
    }
    return new IntegerDataType(dtm);
}

std::string IntegerDataType::getCTypeDeclaration(DataOrganization* dataOrganization) const {
    return "";
}

} // namespace ghidra
