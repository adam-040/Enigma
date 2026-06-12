/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file LongDoubleComplexDataType.cpp
/// \brief longdoublecomplex data type
#include "ghidra/LongDoubleComplexDataType.h"

namespace ghidra {

LongDoubleComplexDataType& LongDoubleComplexDataType::dataType() {
    static LongDoubleComplexDataType instance;
    return instance;
}

LongDoubleComplexDataType::LongDoubleComplexDataType(DataTypeManager* dtm)
    : AbstractComplexDataType("longdoublecomplex", &LongDoubleDataType::dataType(), dtm) {}

DataType* LongDoubleComplexDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<LongDoubleComplexDataType*>(this);
    }
    return new LongDoubleComplexDataType(dtm);
}

} // namespace ghidra
