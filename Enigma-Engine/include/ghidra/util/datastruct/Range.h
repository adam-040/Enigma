/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Range.h
/// \brief Inclusive integer range [min, max].
#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>

namespace ghidra {

/**
 * A simple inclusive integer range.
 * Translated from: ghidra.util.datastruct.Range
 */
class Range {
public:
    int min;
    int max;

    Range(int min, int max);

    int compareTo(const Range& other) const;
    bool equals(const Range& other) const;
    std::size_t hashCode() const;
    std::string toString() const;

    bool contains(int value) const;
    long long size() const;
};

} // namespace ghidra
