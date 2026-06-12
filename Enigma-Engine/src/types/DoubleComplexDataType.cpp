/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DoubleComplexDataType.cpp
/// \brief doublecomplex data type
#include "ghidra/DoubleComplexDataType.h"

namespace ghidra {

DoubleComplexDataType& DoubleComplexDataType::dataType() {
    static DoubleComplexDataType instance;
    return instance;
}

DoubleComplexDataType::DoubleComplexDataType(DataTypeManager* dtm)
    : AbstractComplexDataType("doublecomplex", &DoubleDataType::dataType(), dtm) {}

DataType* DoubleComplexDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<DoubleComplexDataType*>(this);
    }
    return new DoubleComplexDataType(dtm);
}

} // namespace ghidra
