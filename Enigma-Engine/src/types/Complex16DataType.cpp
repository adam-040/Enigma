/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Complex16DataType.cpp
/// \brief complex16 data type
#include "ghidra/Complex16DataType.h"

namespace ghidra {

Complex16DataType& Complex16DataType::dataType() {
    static Complex16DataType instance;
    return instance;
}

Complex16DataType::Complex16DataType(DataTypeManager* dtm)
    : AbstractComplexDataType("complex16", &Float8DataType::dataType(), dtm) {}

DataType* Complex16DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Complex16DataType*>(this);
    }
    return new Complex16DataType(dtm);
}

} // namespace ghidra
