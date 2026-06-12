/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CountedDynamicDataType.cpp
/// \brief A dynamic data type that changes the number of elements it contains based on a count.
#include "ghidra/CountedDynamicDataType.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/IntegerDataType.h"
#include "ghidra/DataTypeComponentImpl.h"

namespace ghidra {

CountedDynamicDataType::CountedDynamicDataType(const std::string& name,
                                               const std::string& description,
                                               DataType* header, DataType* baseStruct,
                                               int64_t counterOffset, int counterSize,
                                               int64_t mask)
    : DynamicDataType(name, header ? header->getDataTypeManager() : nullptr),
      description_(description), header_(header), baseStruct_(baseStruct),
      counterOffset_(counterOffset), counterSize_(counterSize), mask_(mask) {}

int CountedDynamicDataType::getLength(MemBuffer* buf, int /*maxLength*/) {
    if (buf == nullptr) return 0;
    int count = getCount(buf);
    int total = 0;
    if (header_ != nullptr) total += header_->getLength();
    if (baseStruct_ != nullptr) total += count * baseStruct_->getLength();
    return total;
}

int CountedDynamicDataType::getCount(MemBuffer* buf) {
    if (buf == nullptr) return 0;
    int64_t val = 0;
    try {
        if (counterSize_ == 1) val = static_cast<int64_t>(buf->getByte(static_cast<int>(counterOffset_)));
        else if (counterSize_ == 2) val = static_cast<int64_t>(buf->getShort(static_cast<int>(counterOffset_)));
        else if (counterSize_ == 4) val = static_cast<int64_t>(buf->getInt(static_cast<int>(counterOffset_)));
        else if (counterSize_ == 8) val = buf->getLong(static_cast<int>(counterOffset_));
    } catch (...) {
        return 0;
    }
    return static_cast<int>(val & mask_);
}

std::vector<DataTypeComponent*> CountedDynamicDataType::getAllComponents(MemBuffer* buf) {
    std::vector<DataTypeComponent*> comps;
    int count = getCount(buf);
    if (header_ != nullptr) {
        comps.push_back(new DataTypeComponentImpl(header_, header_->getLength(), 0, 0, "header", ""));
    }
    if (baseStruct_ != nullptr && count > 0) {
        for (int i = 0; i < count; i++) {
            comps.push_back(new DataTypeComponentImpl(baseStruct_, baseStruct_->getLength(), i, 0,
                                                       "elem_" + std::to_string(i), ""));
        }
    }
    return comps;
}

} // namespace ghidra
