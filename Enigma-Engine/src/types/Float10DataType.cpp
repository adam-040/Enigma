/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Float10DataType.cpp
/// \brief Float10DataType - IEEE 754 10-byte float
#include "ghidra/Float10DataType.h"

namespace ghidra {

Float10DataType& Float10DataType::dataType() {
    static Float10DataType instance;
    return instance;
}

Float10DataType::Float10DataType(DataTypeManager* dtm)
    : AbstractFloatDataType("float10", 10, dtm) {}

DataType* Float10DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Float10DataType*>(this);
    }
    return new Float10DataType(dtm);
}
} // namespace ghidra
