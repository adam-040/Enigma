/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file FloatComplexDataType.cpp
/// \brief floatcomplex data type
#include "ghidra/FloatComplexDataType.h"

namespace ghidra {

FloatComplexDataType& FloatComplexDataType::dataType() {
    static FloatComplexDataType instance;
    return instance;
}

FloatComplexDataType::FloatComplexDataType(DataTypeManager* dtm)
    : AbstractComplexDataType("floatcomplex", &FloatDataType::dataType(), dtm) {}

DataType* FloatComplexDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<FloatComplexDataType*>(this);
    }
    return new FloatComplexDataType(dtm);
}

} // namespace ghidra
