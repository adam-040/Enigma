/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <ghidra/PointerTypedef.h>

namespace ghidra {

class PointerTypedefBuilder {
    PointerTypedef* typedef_;
public:
    PointerTypedefBuilder(DataType* baseDataType, int pointerSize, DataTypeManager* dtm);
    explicit PointerTypedefBuilder(Pointer* pointerDataType, DataTypeManager* dtm);

    PointerTypedefBuilder& name(const std::string& name);
    PointerTypedefBuilder& type(PointerType type);
    PointerTypedefBuilder& bitShift(int shift);
    PointerTypedefBuilder& bitMask(uint64_t unsignedMask);
    PointerTypedefBuilder& componentOffset(int64_t offset);
    PointerTypedefBuilder& addressSpace(AddressSpace* space);
    PointerTypedefBuilder& addressSpace(const std::string& spaceName);

    TypeDef* build();
};

} // namespace ghidra
