/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Float2DataType.cpp
/// \brief Float2DataType - IEEE 754 2-byte float
#include "ghidra/Float2DataType.h"

namespace ghidra {

Float2DataType& Float2DataType::dataType() {
    static Float2DataType instance;
    return instance;
}

Float2DataType::Float2DataType(DataTypeManager* dtm)
    : AbstractFloatDataType("float2", 2, dtm) {}

DataType* Float2DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Float2DataType*>(this);
    }
    return new Float2DataType(dtm);
}
} // namespace ghidra
