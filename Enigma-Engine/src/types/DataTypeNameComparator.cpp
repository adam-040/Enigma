/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeNameComparator.cpp
#include "ghidra/DataTypeNameComparator.h"
#include "ghidra/DataTypeUtilities.h"
#include <cctype>

namespace ghidra {

const DataTypeNameComparator DataTypeNameComparator::INSTANCE;

int DataTypeNameComparator::compare(const std::string& a, const std::string& b) const {
    std::string n1 = getNameWithoutConflict(a);
    std::string n2 = getNameWithoutConflict(b);
    int len1 = static_cast<int>(n1.size());
    int len2 = static_cast<int>(n2.size());
    int overlap = len1 < len2 ? len1 : len2;
    int baseNameLen = overlap;
    int baseCaseCompare = 0;

    for (int i = 0; i < overlap; ++i) {
        char c1 = n1[i];
        char c2 = n2[i];
        char lc1 = static_cast<char>(std::tolower(static_cast<unsigned char>(c1)));
        char lc2 = static_cast<char>(std::tolower(static_cast<unsigned char>(c2)));
        if (lc1 == ' ') {
            if (lc2 == ' ') { baseNameLen = i; break; }
            return -1;
        }
        if (lc2 == ' ') return 1;
        if (lc1 != lc2) return lc1 - lc2;
        if (baseCaseCompare == 0) baseCaseCompare = c1 - c2;
    }

    if (len1 > baseNameLen && n1[baseNameLen] != ' ') return 1;
    if (len2 > baseNameLen && n2[baseNameLen] != ' ') return -1;
    if (baseCaseCompare != 0) return baseCaseCompare;

    int c1 = getConflictValue(a);
    int c2 = getConflictValue(b);
    if (c1 != c2) return c1 - c2;
    return n1.compare(n2);
}

} // namespace ghidra
