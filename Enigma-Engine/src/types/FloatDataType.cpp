/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file FloatDataType.cpp
/// \brief Float data type implementation
#include "ghidra/FloatDataType.h"

namespace ghidra {

int FloatDataType::getFloatSize(DataTypeManager* dtm) {
    if (dtm) {
        DataOrganization* org = dtm->getDataOrganization();
        if (org) return org->getFloatSize();
    }
    return 4;
}

FloatDataType& FloatDataType::dataType() {
    static FloatDataType instance;
    return instance;
}

FloatDataType::FloatDataType(DataTypeManager* dtm)
    : AbstractFloatDataType("float", getFloatSize(dtm), dtm) {}

std::string FloatDataType::buildDescription() const {
    return "Compiler-defined 'float' " + AbstractFloatDataType::buildDescription();
}

DataType* FloatDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<FloatDataType*>(this);
    }
    return new FloatDataType(dtm);
}

bool FloatDataType::hasLanguageDependantLength() const {
    return true;
}

} // namespace ghidra
