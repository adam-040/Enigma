/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Pointer16DataType.cpp
/// \brief 16-bit pointer factory
#include "ghidra/Pointer16DataType.h"

namespace ghidra {

Pointer16DataType& Pointer16DataType::dataType() {
    static Pointer16DataType instance;
    return instance;
}

Pointer16DataType::Pointer16DataType(DataType* dt, DataTypeManager* dtm)
    : PointerDataType(dt, 2, dtm) {}

DataType* Pointer16DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Pointer16DataType*>(this);
    }
    DataType* ref = getDataType();
    DataType* clonedRef = ref ? ref->clone(dtm) : nullptr;
    auto* p = new Pointer16DataType(clonedRef, dtm);
    return p;
}

} // namespace ghidra
