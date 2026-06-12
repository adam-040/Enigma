/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ShortDataType.cpp
/// \brief Signed Short Integer data type implementation
#include "ghidra/ShortDataType.h"
#include "ghidra/UnsignedShortDataType.h"

namespace ghidra {

ShortDataType& ShortDataType::dataType() {
    static ShortDataType instance;
    return instance;
}

ShortDataType::ShortDataType(DataTypeManager* dtm)
    : AbstractSignedIntegerDataType("short", dtm) {}

bool ShortDataType::hasLanguageDependantLength() const {
    return true;
}

int ShortDataType::getLength() const {
    DataOrganization* org = getDataOrganization();
    return org ? org->getShortSize() : 2;
}

std::string ShortDataType::getDescription() const {
    return "Signed Short Integer (compiler-specific size)";
}

std::string ShortDataType::getCDeclaration() const {
    return C_SIGNED_SHORT;
}

AbstractIntegerDataType* ShortDataType::getOppositeSignednessDataType() const {
    return new UnsignedShortDataType(getDataTypeManager());
}

DataType* ShortDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<ShortDataType*>(this);
    }
    return new ShortDataType(dtm);
}

std::string ShortDataType::getCTypeDeclaration(DataOrganization* dataOrganization) const {
    return "";
}

} // namespace ghidra
