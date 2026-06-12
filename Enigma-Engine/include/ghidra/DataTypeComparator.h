/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeComparator.h
/// \brief Multi-level DataType comparator: name, DTM, category path.
/// Translated from: ghidra.program.model.data.DataTypeComparator
#pragma once

namespace ghidra {

class DataType;

/// Compares two DataType pointers by name (case-insensitive via
/// DataTypeNameComparator), then by DTM name, then by category path.
class DataTypeComparator {
public:
    static const DataTypeComparator INSTANCE;

    int compare(const DataType* a, const DataType* b) const;

    bool operator()(const DataType* a, const DataType* b) const {
        return compare(a, b) < 0;
    }
};

} // namespace ghidra
