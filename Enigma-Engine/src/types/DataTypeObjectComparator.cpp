/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeObjectComparator.cpp
#include "ghidra/DataTypeObjectComparator.h"
#include "ghidra/DataType.h"
#include "ghidra/DataTypeNameComparator.h"

namespace ghidra {

const DataTypeObjectComparator DataTypeObjectComparator::INSTANCE;

int DataTypeObjectComparator::compare(const DataType* a, const DataType* b) const {
    if (!a && !b) return 0;
    if (!a) return -1;
    if (!b) return 1;
    return DataTypeNameComparator::INSTANCE.compare(a->getName(), b->getName());
}

int DataTypeObjectComparator::compare(const std::string& a, const DataType* b) const {
    if (!b) return a.empty() ? 0 : 1;
    return DataTypeNameComparator::INSTANCE.compare(a, b->getName());
}

int DataTypeObjectComparator::compare(const DataType* a, const std::string& b) const {
    if (!a) return b.empty() ? 0 : -1;
    return DataTypeNameComparator::INSTANCE.compare(a->getName(), b);
}

int DataTypeObjectComparator::compare(const std::string& a, const std::string& b) const {
    return DataTypeNameComparator::INSTANCE.compare(a, b);
}

} // namespace ghidra
