/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Pointer48DataType.cpp
/// \brief 48-bit pointer factory
#include "ghidra/Pointer48DataType.h"

namespace ghidra {

Pointer48DataType& Pointer48DataType::dataType() {
    static Pointer48DataType instance;
    return instance;
}

Pointer48DataType::Pointer48DataType(DataType* dt, DataTypeManager* dtm)
    : PointerDataType(dt, 6, dtm) {}

DataType* Pointer48DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Pointer48DataType*>(this);
    }
    DataType* ref = getDataType();
    DataType* clonedRef = ref ? ref->clone(dtm) : nullptr;
    auto* p = new Pointer48DataType(clonedRef, dtm);
    return p;
}

} // namespace ghidra
