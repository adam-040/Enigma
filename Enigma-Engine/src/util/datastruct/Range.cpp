/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Range.cpp
/// \brief Inclusive integer range [min, max].
#include "ghidra/util/datastruct/Range.h"

namespace ghidra {

Range::Range(int min, int max) : min(min), max(max) {
    if (max < min) {
        throw std::invalid_argument("Range max (" + std::to_string(max) +
                                    ") cannot be less than min (" + std::to_string(min) + ").");
    }
}

int Range::compareTo(const Range& other) const {
    if (min == other.min) return 0;
    return (min > other.min) ? 1 : -1;
}

bool Range::equals(const Range& other) const {
    return other.min == min && other.max == max;
}

std::size_t Range::hashCode() const {
    return std::hash<std::string>{}(toString());
}

std::string Range::toString() const {
    return "(" + std::to_string(min) + "," + std::to_string(max) + ")";
}

bool Range::contains(int value) const {
    return value >= min && value <= max;
}

long long Range::size() const {
    return static_cast<long long>(max) - static_cast<long long>(min) + 1;
}

} // namespace ghidra
