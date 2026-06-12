/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Float8DataType.cpp
/// \brief Float8DataType - IEEE 754 8-byte float
#include "ghidra/Float8DataType.h"

namespace ghidra {

Float8DataType& Float8DataType::dataType() {
    static Float8DataType instance;
    return instance;
}

Float8DataType::Float8DataType(DataTypeManager* dtm)
    : AbstractFloatDataType("float8", 8, dtm) {}

DataType* Float8DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Float8DataType*>(this);
    }
    return new Float8DataType(dtm);
}
} // namespace ghidra
