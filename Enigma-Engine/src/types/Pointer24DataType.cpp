/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Pointer24DataType.cpp
/// \brief 24-bit pointer factory
#include "ghidra/Pointer24DataType.h"

namespace ghidra {

Pointer24DataType& Pointer24DataType::dataType() {
    static Pointer24DataType instance;
    return instance;
}

Pointer24DataType::Pointer24DataType(DataType* dt, DataTypeManager* dtm)
    : PointerDataType(dt, 3, dtm) {}

DataType* Pointer24DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Pointer24DataType*>(this);
    }
    DataType* ref = getDataType();
    DataType* clonedRef = ref ? ref->clone(dtm) : nullptr;
    auto* p = new Pointer24DataType(clonedRef, dtm);
    return p;
}

} // namespace ghidra
