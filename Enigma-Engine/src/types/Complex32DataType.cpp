/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Complex32DataType.cpp
/// \brief complex32 data type
#include "ghidra/Complex32DataType.h"

namespace ghidra {

Complex32DataType& Complex32DataType::dataType() {
    static Complex32DataType instance;
    return instance;
}

Complex32DataType::Complex32DataType(DataTypeManager* dtm)
    : AbstractComplexDataType("complex32", &Float16DataType::dataType(), dtm) {}

DataType* Complex32DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Complex32DataType*>(this);
    }
    return new Complex32DataType(dtm);
}

} // namespace ghidra
