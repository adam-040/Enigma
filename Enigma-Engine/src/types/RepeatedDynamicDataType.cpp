/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RepeatedDynamicDataType.cpp
/// \brief Dynamic data type with header + terminator-separated repeated entries.
#include "ghidra/RepeatedDynamicDataType.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/DataTypeComponentImpl.h"

namespace ghidra {

RepeatedDynamicDataType::RepeatedDynamicDataType(const std::string& name,
                                                 const std::string& description,
                                                 DataType* header, DataType* baseStruct,
                                                 int64_t terminatorValue, int terminatorSize,
                                                 DataTypeManager* dtm)
    : DynamicDataType(name, dtm),
      description_(description), header_(header), baseStruct_(baseStruct),
      terminatorValue_(terminatorValue), terminatorSize_(terminatorSize) {}

std::vector<DataTypeComponent*> RepeatedDynamicDataType::getAllComponents(MemBuffer* buf) {
    std::vector<DataTypeComponent*> comps;
    if (buf == nullptr) return comps;
    int offset = 0;
    int ordinal = 0;
    if (header_ != nullptr) {
        auto* c = new DataTypeComponentImpl(header_, header_->getLength(), ordinal, offset,
                                            header_->getName(), "", this);
        comps.push_back(c);
        offset += header_->getLength();
        ordinal++;
    }
    if (baseStruct_ != nullptr) {
        int maxIter = 1024;
        while (moreComponents(buf) && --maxIter > 0) {
            int len = baseStruct_->getLength();
            auto* c = new DataTypeComponentImpl(baseStruct_, len, ordinal, offset,
                                                "elem_" + std::to_string(ordinal), "", this);
            comps.push_back(c);
            offset += len;
            ordinal++;
            break;
        }
    }
    return comps;
}

int RepeatedDynamicDataType::getLength(MemBuffer* /*buf*/, int /*maxLength*/) {
    return 0;
}

} // namespace ghidra
