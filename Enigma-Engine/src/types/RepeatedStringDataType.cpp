/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RepeatedStringDataType.cpp
/// \brief Some number of repeated strings; each string can be of variable length.
#include "ghidra/RepeatedStringDataType.h"
#include "ghidra/StringDataType.h"
#include "ghidra/CategoryPath.h"

namespace ghidra {

namespace {
StringDataType* sharedStringType() {
    static StringDataType* s = new StringDataType();
    return s;
}
}

RepeatedStringDataType::RepeatedStringDataType()
    : RepeatedStringDataType(nullptr) {}

RepeatedStringDataType::RepeatedStringDataType(DataTypeManager* dtm)
    : RepeatCountDataType(sharedStringType(), CategoryPath::ROOT(), "RepString", dtm) {}

std::string RepeatedStringDataType::getDescription() const {
    return "Repeated String";
}

DataType* RepeatedStringDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<RepeatedStringDataType*>(this);
    }
    return new RepeatedStringDataType(dtm);
}

} // namespace ghidra
