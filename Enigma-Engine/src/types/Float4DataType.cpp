/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Float4DataType.cpp
/// \brief Float4DataType - IEEE 754 4-byte float
#include "ghidra/Float4DataType.h"

namespace ghidra {

Float4DataType& Float4DataType::dataType() {
    static Float4DataType instance;
    return instance;
}

Float4DataType::Float4DataType(DataTypeManager* dtm)
    : AbstractFloatDataType("float4", 4, dtm) {}

DataType* Float4DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Float4DataType*>(this);
    }
    return new Float4DataType(dtm);
}
} // namespace ghidra
