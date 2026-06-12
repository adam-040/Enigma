/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Float16DataType.cpp
/// \brief Float16DataType - IEEE 754 16-byte float
#include "ghidra/Float16DataType.h"

namespace ghidra {

Float16DataType& Float16DataType::dataType() {
    static Float16DataType instance;
    return instance;
}

Float16DataType::Float16DataType(DataTypeManager* dtm)
    : AbstractFloatDataType("float16", 16, dtm) {}

DataType* Float16DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Float16DataType*>(this);
    }
    return new Float16DataType(dtm);
}
} // namespace ghidra
