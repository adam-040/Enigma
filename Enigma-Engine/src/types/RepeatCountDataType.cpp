/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RepeatCountDataType.cpp
/// \brief Dynamic data type with a leading 2-byte count followed by N repeats of a DataType.
#include "ghidra/RepeatCountDataType.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/WordDataType.h"
#include "ghidra/DataTypeComponentImpl.h"

namespace ghidra {

RepeatCountDataType::RepeatCountDataType(DataType* repeatDataType, const CategoryPath& path,
                                         const std::string& name, DataTypeManager* dtm)
    : DynamicDataType(path, name, dtm), repeatDataType_(repeatDataType) {}

std::vector<DataTypeComponent*> RepeatCountDataType::getAllComponents(MemBuffer* buf) {
    std::vector<DataTypeComponent*> comps;
    if (buf == nullptr) return comps;
    int n;
    try {
        int b0 = static_cast<int>(buf->getByte(0)) & 0xff;
        int b1 = static_cast<int>(buf->getByte(1)) & 0xff;
        n = b0 * 16 + b1 + 1;
    } catch (...) {
        return comps;
    }
    auto* wordDt = new WordDataType();
    auto* countComp = new DataTypeComponentImpl(wordDt, wordDt->getLength(), 0, 0, "Size", "", this, true);
    comps.push_back(countComp);
    int offset = countComp->getLength();
    for (int i = 1; i < n; i++) {
        if (repeatDataType_ == nullptr) break;
        int len = repeatDataType_->getLength();
        auto* c = new DataTypeComponentImpl(repeatDataType_, len, i, offset, "elem_" + std::to_string(i), "", this);
        comps.push_back(c);
        offset += len;
    }
    return comps;
}

std::string RepeatCountDataType::getMnemonic(Settings* /*settings*/) const {
    return getName();
}

std::string RepeatCountDataType::getRepresentation(MemBuffer* /*buf*/, Settings* /*settings*/, int /*length*/) const {
    return "";
}

void* RepeatCountDataType::getValue(MemBuffer* /*buf*/, Settings* /*settings*/, int /*length*/) const {
    return nullptr;
}

int RepeatCountDataType::getLength(MemBuffer* buf, int /*maxLength*/) {
    if (buf == nullptr) return 0;
    try {
        int b0 = static_cast<int>(buf->getByte(0)) & 0xff;
        int b1 = static_cast<int>(buf->getByte(1)) & 0xff;
        int n = b0 * 16 + b1 + 1;
        int total = 2;
        if (repeatDataType_ != nullptr) {
            total += (n - 1) * repeatDataType_->getLength();
        }
        return total;
    } catch (...) {
        return 0;
    }
}

} // namespace ghidra
