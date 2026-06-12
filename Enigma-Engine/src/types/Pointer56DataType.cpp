/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Pointer56DataType.cpp
/// \brief 56-bit pointer factory
#include "ghidra/Pointer56DataType.h"

namespace ghidra {

Pointer56DataType& Pointer56DataType::dataType() {
    static Pointer56DataType instance;
    return instance;
}

Pointer56DataType::Pointer56DataType(DataType* dt, DataTypeManager* dtm)
    : PointerDataType(dt, 7, dtm) {}

DataType* Pointer56DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Pointer56DataType*>(this);
    }
    DataType* ref = getDataType();
    DataType* clonedRef = ref ? ref->clone(dtm) : nullptr;
    auto* p = new Pointer56DataType(clonedRef, dtm);
    return p;
}

} // namespace ghidra
