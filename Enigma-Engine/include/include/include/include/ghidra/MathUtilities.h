/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/// \file MathUtilities.h
/// \brief Utility functions for unsigned arithmetic and comparison
/// Translated from: ghidra.util.MathUtilities
#pragma once

#include <cstdint>
#include <stdexcept>
#include <algorithm>

namespace ghidra {

class MathUtilities {
private:
    MathUtilities() = default;

public:
    /// Perform unsigned division. Provides proper handling of all 64-bit unsigned values.
    static uint64_t unsignedDivide(uint64_t numerator, uint64_t denominator) {
        if (denominator == 0) {
            throw std::invalid_argument("divide by zero");
        }
        return numerator / denominator;
    }

    /// Perform unsigned modulo. Provides proper handling of all 64-bit unsigned values.
    static uint64_t unsignedModulo(uint64_t numerator, uint64_t denominator) {
        if (denominator == 0) {
            throw std::invalid_argument("modulo by zero");
        }
        return numerator % denominator;
    }

    /// Ensures that the given value is within the given range.
    static int clamp(int value, int min, int max) {
        if (value < min) return min;
        if (value > max) return max;
        return value;
    }

    /// Compute the minimum, treating the inputs as unsigned
    static uint64_t unsignedMin(uint64_t a, uint64_t b) {
        return (a < b) ? a : b;
    }

    /// Compute the minimum, treating the inputs as unsigned
    static uint32_t unsignedMin(uint32_t a, uint32_t b) {
        return (a < b) ? a : b;
    }

    /// Compute the minimum, treating the inputs as unsigned
    static uint32_t unsignedMin(uint32_t a, uint64_t b) {
        return (static_cast<uint64_t>(a) < b) ? a : static_cast<uint32_t>(b);
    }

    /// Compute the minimum, treating the inputs as unsigned
    static uint32_t unsignedMin(uint64_t a, uint32_t b) {
        return (a < static_cast<uint64_t>(b)) ? static_cast<uint32_t>(a) : b;
    }

    /// Compute the maximum, treating the inputs as unsigned
    static uint64_t unsignedMax(uint64_t a, uint64_t b) {
        return (a > b) ? a : b;
    }

    /// Compute the maximum, treating the inputs as unsigned
    static uint32_t unsignedMax(uint32_t a, uint32_t b) {
        return (a > b) ? a : b;
    }

    /// Compute the maximum, treating the inputs as unsigned
    static uint64_t unsignedMax(uint32_t a, uint64_t b) {
        return (static_cast<uint64_t>(a) > b) ? a : b;
    }

    /// Compute the maximum, treating the inputs as unsigned
    static uint64_t unsignedMax(uint64_t a, uint32_t b) {
        return (a > static_cast<uint64_t>(b)) ? a : b;
    }
};

} // namespace ghidra
