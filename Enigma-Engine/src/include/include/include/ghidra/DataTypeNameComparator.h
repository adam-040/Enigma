/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeNameComparator.h
/// \brief Case-insensitive name comparator with conflict-suffix ordering.
/// Translated from: ghidra.program.model.data.DataTypeNameComparator
#pragma once

#include <string>

namespace ghidra {

/// Compares two data-type name strings.
/// Case-insensitive on the base name, with conflict suffixes
/// (".conflict", ".conflict2", etc.) stripped and ordered numerically.
class DataTypeNameComparator {
public:
    static const DataTypeNameComparator INSTANCE;

    int compare(const std::string& a, const std::string& b) const;

    bool operator()(const std::string& a, const std::string& b) const {
        return compare(a, b) < 0;
    }
};

} // namespace ghidra
