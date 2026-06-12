/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DoubleDataType.cpp
/// \brief Double data type implementation
#include "ghidra/DoubleDataType.h"

namespace ghidra {

int DoubleDataType::getDoubleSize(DataTypeManager* dtm) {
    if (dtm) {
        DataOrganization* org = dtm->getDataOrganization();
        if (org) return org->getDoubleSize();
    }
    return 8;
}

DoubleDataType& DoubleDataType::dataType() {
    static DoubleDataType instance;
    return instance;
}

DoubleDataType::DoubleDataType(DataTypeManager* dtm)
    : AbstractFloatDataType("double", getDoubleSize(dtm), dtm) {}

std::string DoubleDataType::buildDescription() const {
    return "Compiler-defined 'double' " + AbstractFloatDataType::buildDescription();
}

DataType* DoubleDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<DoubleDataType*>(this);
    }
    return new DoubleDataType(dtm);
}

bool DoubleDataType::hasLanguageDependantLength() const {
    return true;
}

} // namespace ghidra
