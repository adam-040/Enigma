/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Pointer8DataType.cpp
/// \brief 8-bit pointer factory
#include "ghidra/Pointer8DataType.h"

namespace ghidra {

Pointer8DataType& Pointer8DataType::dataType() {
    static Pointer8DataType instance;
    return instance;
}

Pointer8DataType::Pointer8DataType(DataType* dt, DataTypeManager* dtm)
    : PointerDataType(dt, 1, dtm) {}

DataType* Pointer8DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Pointer8DataType*>(this);
    }
    DataType* ref = getDataType();
    DataType* clonedRef = ref ? ref->clone(dtm) : nullptr;
    auto* p = new Pointer8DataType(clonedRef, dtm);
    return p;
}

} // namespace ghidra
