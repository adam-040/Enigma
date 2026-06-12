/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file BuiltInDataTypeClassExclusionFilter.cpp
/// \brief An exclusion filter for classes implementing BuiltInDataType.
#include "ghidra/BuiltInDataTypeClassExclusionFilter.h"
#include "ghidra/BadDataType.h"
#include "ghidra/MissingBuiltInDataType.h"

namespace ghidra {

const std::string BuiltInDataTypeClassExclusionFilter::BAD_DATA_TYPE = "ghidra.program.model.data.BadDataType";
const std::string BuiltInDataTypeClassExclusionFilter::MISSING_BUILTIN_DATA_TYPE = "ghidra.program.model.data.MissingBuiltInDataType";

BuiltInDataTypeClassExclusionFilter::BuiltInDataTypeClassExclusionFilter() {
    excluded_.push_back(BAD_DATA_TYPE);
    excluded_.push_back(MISSING_BUILTIN_DATA_TYPE);
}

bool BuiltInDataTypeClassExclusionFilter::isExcluded(const std::string& className) const {
    for (const auto& e : excluded_) {
        if (e == className) return true;
    }
    return false;
}

} // namespace ghidra
