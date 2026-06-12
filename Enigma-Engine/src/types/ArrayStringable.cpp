/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ArrayStringable.cpp
#include "ghidra/ArrayStringable.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/Settings.h"
#include "ghidra/TypeDef.h"

namespace ghidra {

std::string ArrayStringable::getArrayString(MemBuffer* buf, Settings* settings, int length) const {
    if (hasStringValue(settings) && buf != nullptr && buf->isInitializedMemory()) {
        return "";
    }
    return std::string();
}

ArrayStringable* ArrayStringable::getArrayStringable(const DataType* dt) {
    if (dt == nullptr) {
        return nullptr;
    }
    const TypeDef* td = dynamic_cast<const TypeDef*>(dt);
    if (td != nullptr) {
        dt = td->getBaseDataType();
    }
    return const_cast<ArrayStringable*>(dynamic_cast<const ArrayStringable*>(dt));
}

} // namespace ghidra
