/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file BuiltInDataTypeClassExclusionFilter.h
/// \brief An exclusion filter for classes implementing BuiltInDataType.
#pragma once

#include <string>
#include <vector>

namespace ghidra {

/**
 * An exclusion filter for classes that implement BuiltInDataType.
 * Excludes BadDataType and MissingBuiltInDataType.
 * Translated from: ghidra.program.model.data.BuiltInDataTypeClassExclusionFilter
 */
class BuiltInDataTypeClassExclusionFilter {
public:
    BuiltInDataTypeClassExclusionFilter();

    bool isExcluded(const std::string& className) const;

    static const std::string BAD_DATA_TYPE;
    static const std::string MISSING_BUILTIN_DATA_TYPE;

private:
    std::vector<std::string> excluded_;
};

} // namespace ghidra
