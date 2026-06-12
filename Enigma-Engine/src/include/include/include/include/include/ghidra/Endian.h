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
/// \file Endian.h
/// \brief Endianness representation
#pragma once

#include <string>
#include <algorithm>
#include <cctype>

namespace ghidra {

/**
 * Represents byte ordering (endianness).
 * Translated from: ghidra.program.model.lang.Endian (Java enum)
 * C++: enum class + helper class
 */
enum class Endian {
    BIG,
    LITTLE
};

namespace EndianUtil {

    /// Convert string to Endian value
    /// \param endianness string representation ("big", "little", "BE", "LE")
    /// \param result output endian value
    /// \return true if conversion successful, false otherwise
    inline bool toEndian(const std::string& endianness, Endian& result) {
        if (endianness.empty()) return false;

        // Create lowercase copy for comparison
        std::string lower = endianness;
        std::transform(lower.begin(), lower.end(), lower.begin(),
            [](unsigned char c) { return std::tolower(c); });

        if (lower == "big" || lower == "be") {
            result = Endian::BIG;
            return true;
        }
        if (lower == "little" || lower == "le") {
            result = Endian::LITTLE;
            return true;
        }
        return false;
    }

    /// Convert Endian to full string representation
    inline std::string toString(Endian e) {
        return (e == Endian::BIG) ? "big" : "little";
    }

    /// Convert Endian to short string representation
    inline std::string toShortString(Endian e) {
        return (e == Endian::BIG) ? "BE" : "LE";
    }

    /// Check if big endian
    inline bool isBigEndian(Endian e) {
        return e == Endian::BIG;
    }

    /// Get display name (capitalized)
    inline std::string getDisplayName(Endian e) {
        std::string name = toString(e);
        if (!name.empty()) {
            name[0] = std::toupper(name[0]);
        }
        return name;
    }

} // namespace EndianUtil

} // namespace ghidra
