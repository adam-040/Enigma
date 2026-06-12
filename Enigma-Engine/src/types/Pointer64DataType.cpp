/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Pointer64DataType.cpp
/// \brief 64-bit pointer factory
#include "ghidra/Pointer64DataType.h"

namespace ghidra {

Pointer64DataType& Pointer64DataType::dataType() {
    static Pointer64DataType instance;
    return instance;
}

Pointer64DataType::Pointer64DataType(DataType* dt, DataTypeManager* dtm)
    : PointerDataType(dt, 8, dtm) {}

DataType* Pointer64DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Pointer64DataType*>(this);
    }
    DataType* ref = getDataType();
    DataType* clonedRef = ref ? ref->clone(dtm) : nullptr;
    auto* p = new Pointer64DataType(clonedRef, dtm);
    return p;
}

} // namespace ghidra
