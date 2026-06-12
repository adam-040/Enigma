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
/// \file NumericUtilities.h
/// \brief Utility methods for numeric operations (parsing, formatting, byte conversion)
/// Translated from: ghidra.util.NumericUtilities
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <stdexcept>

#include "SignednessFormatMode.h"

namespace ghidra {

/// \brief Static utility methods for numeric operations.
class NumericUtilities {
public:
    static constexpr uint64_t MAX_UNSIGNED_INT32_AS_LONG = 0xFFFFFFFFULL;

    NumericUtilities() = delete;

    /// \brief Parses the given string as a long value, auto-detecting hex (0x) prefix.
    static int64_t parseLong(const std::string& s);

    /// \brief Parses the given string as a long, returning defaultValue on failure.
    static int64_t parseLong(const std::string& s, int64_t defaultValue);

    /// \brief Parses the given hex string as a long (treats as hex regardless of prefix).
    static int64_t parseHexLong(const std::string& s);

    /// \brief Parses the given string as an int, auto-detecting hex (0x) prefix.
    static int32_t parseInt(const std::string& s);

    /// \brief Parses the given string as an int, returning defaultValue on failure.
    static int32_t parseInt(const std::string& s, int32_t defaultValue);

    /// \brief Decodes a big integer from hex (0x), binary (0b), octal (0), or decimal.
    static int64_t decodeBigInteger(const std::string& s);

    /// \brief Converts a long to hex string with 0x prefix.
    static std::string toHexString(int64_t value);

    /// \brief Converts a long to hex string with 0x prefix, masked to size bytes.
    static std::string toHexString(int64_t value, int32_t size);

    /// \brief Converts a long to signed hex string (with sign and 0x prefix).
    static std::string toSignedHexString(int64_t value);

    /// \brief Converts an unsigned long (stored in signed long) to unsigned long long.
    static uint64_t unsignedLongToUnsignedLong(int64_t value);

    /// \brief Convert a long, treated as unsigned, to a double.
    static double unsignedLongToDouble(int64_t val);

    /// \brief Get an unsigned aligned value >= specified value.
    static uint64_t getUnsignedAlignedValue(uint64_t unsignedValue, uint64_t alignment);

    /// \brief Format a number in a given radix with default signedness mode.
    static std::string formatNumber(int64_t number, int32_t radix);

    /// \brief Format a number in a given radix with specified signedness mode.
    static std::string formatNumber(int64_t number, int32_t radix, SignednessFormatMode mode);

    /// \brief Parse hex string into byte array.
    static std::vector<uint8_t> convertStringToBytes(const std::string& hexString);

    /// \brief Convert byte array to hex string.
    static std::string convertBytesToString(const std::vector<uint8_t>& bytes);

    /// \brief Convert byte array to hex string with delimiter between bytes.
    static std::string convertBytesToString(const std::vector<uint8_t>& bytes, const std::string& delimiter);

    /// \brief Determine if the provided number is an integer type (byte, short, int, long).
    template<typename T>
    static bool isIntegerType() {
        return std::is_integral_v<T> && !std::is_floating_point_v<T>;
    }

    /// \brief Determine if the provided number is a floating-point type.
    template<typename T>
    static bool isFloatingPointType() {
        return std::is_floating_point_v<T>;
    }

private:
    static int64_t parseHelper(const std::string& s, bool forceHex, uint64_t max);
    static std::string signedIntegerRadixToString(int64_t number, int32_t radix);
    static std::string unsignedIntegerRadixToString(int64_t number, int32_t radix);
    static std::string defaultIntegerRadixToString(int64_t number, int32_t radix);
};

} // namespace ghidra
