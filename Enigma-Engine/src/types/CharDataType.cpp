/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/CharDataType.h"
#include "ghidra/DataTypeManager.h"
#include "ghidra/DataOrganization.h"
#include "ghidra/UnsignedCharDataType.h"
#include "ghidra/SignedByteDataType.h"

namespace ghidra {

CharDataType& CharDataType::dataType() {
    static CharDataType instance;
    return instance;
}

CharDataType::CharDataType(DataTypeManager* dtm)
    : AbstractIntegerDataType("char", dtm) {}

bool CharDataType::isSigned() const {
    DataTypeManager* dtm = getDataTypeManager();
    if (dtm) {
        DataOrganization* org = dtm->getDataOrganization();
        if (org) return org->isSignedChar();
    }
    return false;
}

std::string CharDataType::getDescription() const {
    return "Character";
}

int CharDataType::getLength() const {
    DataTypeManager* dtm = getDataTypeManager();
    if (dtm) {
        DataOrganization* org = dtm->getDataOrganization();
        if (org) return org->getCharSize();
    }
    return 1;
}

AbstractIntegerDataType* CharDataType::getOppositeSignednessDataType() const {
    if (isSigned()) {
        return new UnsignedCharDataType(getDataTypeManager());
    }
    return new SignedByteDataType(getDataTypeManager());
}

DataType* CharDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<CharDataType*>(this);
    }
    return new CharDataType(dtm);
}

} // namespace ghidra
