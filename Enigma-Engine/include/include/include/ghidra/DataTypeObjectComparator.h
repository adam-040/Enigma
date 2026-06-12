/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeObjectComparator.h
/// \brief Heterogeneous comparator for DataType and String name lookups.
/// Translated from: ghidra.program.model.data.DataTypeObjectComparator
#pragma once

#include <string>

namespace ghidra {

class DataType;

/// Compares two values where each may be either a DataType* or a
/// std::string (used for lookups by name).
class DataTypeObjectComparator {
public:
    static const DataTypeObjectComparator INSTANCE;

    int compare(const DataType* a, const DataType* b) const;
    int compare(const std::string& a, const DataType* b) const;
    int compare(const DataType* a, const std::string& b) const;
    int compare(const std::string& a, const std::string& b) const;
};

} // namespace ghidra
