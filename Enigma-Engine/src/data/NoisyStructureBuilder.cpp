/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file NoisyStructureBuilder.cpp
/// \brief Build a structure from a "noisy" source of field information.
#include "ghidra/NoisyStructureBuilder.h"
#include "ghidra/StructureDataType.h"
#include "ghidra/Pointer.h"

namespace ghidra {

NoisyStructureBuilder::NoisyStructureBuilder() {}

void NoisyStructureBuilder::addDataType(int64_t offset, DataType* dt) {
    if (dt == nullptr) return;
    auto it = offsetToDataTypeMap_.find(offset);
    if (it == offsetToDataTypeMap_.end()) {
        offsetToDataTypeMap_[offset] = dt;
    } else if (dynamic_cast<Pointer*>(dt)) {
        // Pointer is less specific than a concrete type; don't replace
    } else {
        offsetToDataTypeMap_[offset] = dt;
    }
}

void NoisyStructureBuilder::addReference(int64_t offset, DataType* dt) {
    if (dt == nullptr) return;
    if (offsetToDataTypeMap_.find(offset) == offsetToDataTypeMap_.end()) {
        offsetToDataTypeMap_[offset] = dt;
    }
}

void NoisyStructureBuilder::openStruct(int64_t offset, DataType* dt) {
    auto* s = new StructureDataType("struct", 0);
    if (dt) s->add(dt);
    structs_[offset] = s;
}

void NoisyStructureBuilder::openComponent(int64_t /*offset*/, int64_t /*size*/) {}

void NoisyStructureBuilder::closeStruct(int64_t offset) {
    auto it = structs_.find(offset);
    if (it != structs_.end()) {
        delete it->second;
        structs_.erase(it);
    }
}

Structure* NoisyStructureBuilder::getStruct(int64_t offset) {
    auto it = structs_.find(offset);
    return (it != structs_.end()) ? it->second : nullptr;
}

} // namespace ghidra
