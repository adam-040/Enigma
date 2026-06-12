/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Pointer40DataType.cpp
/// \brief 40-bit pointer factory
#include "ghidra/Pointer40DataType.h"

namespace ghidra {

Pointer40DataType& Pointer40DataType::dataType() {
    static Pointer40DataType instance;
    return instance;
}

Pointer40DataType::Pointer40DataType(DataType* dt, DataTypeManager* dtm)
    : PointerDataType(dt, 5, dtm) {}

DataType* Pointer40DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Pointer40DataType*>(this);
    }
    DataType* ref = getDataType();
    DataType* clonedRef = ref ? ref->clone(dtm) : nullptr;
    auto* p = new Pointer40DataType(clonedRef, dtm);
    return p;
}

} // namespace ghidra
