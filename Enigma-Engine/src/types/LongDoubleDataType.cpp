/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file LongDoubleDataType.cpp
/// \brief Long Double data type implementation
#include "ghidra/LongDoubleDataType.h"

namespace ghidra {

int LongDoubleDataType::getLongDoubleSize(DataTypeManager* dtm) {
    if (dtm) {
        DataOrganization* org = dtm->getDataOrganization();
        if (org) return org->getLongDoubleSize();
    }
    return 10;
}

LongDoubleDataType& LongDoubleDataType::dataType() {
    static LongDoubleDataType instance;
    return instance;
}

LongDoubleDataType::LongDoubleDataType(DataTypeManager* dtm)
    : AbstractFloatDataType("longdouble", getLongDoubleSize(dtm), dtm) {}

std::string LongDoubleDataType::buildDescription() const {
    return "Compiler-defined 'long double' " + AbstractFloatDataType::buildDescription();
}

DataType* LongDoubleDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<LongDoubleDataType*>(this);
    }
    return new LongDoubleDataType(dtm);
}

std::string LongDoubleDataType::getCTypeDeclaration(DataOrganization* dataOrganization) const {
    return "long double";
}

bool LongDoubleDataType::hasLanguageDependantLength() const {
    return true;
}

} // namespace ghidra
