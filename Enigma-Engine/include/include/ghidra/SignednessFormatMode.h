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
/// \file SignednessFormatMode.h
/// \brief Defines how the sign of integer-type numbers is to be interpreted for rendering
/// Translated from: ghidra.util.SignednessFormatMode
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

/**
 * Defines how the sign of integer-type numbers is to be interpreted for rendering.
 */
enum class SignednessFormatMode {
    DEFAULT,    // Values in binary/octal/hex are unsigned; decimal is signed
    UNSIGNED,   // All values rendered unsigned
    SIGNED      // All values rendered signed
};

namespace SignednessFormatModeUtil {

    inline SignednessFormatMode parse(int value) {
        switch (value) {
            case 0: return SignednessFormatMode::DEFAULT;
            case 1: return SignednessFormatMode::UNSIGNED;
            case 2: return SignednessFormatMode::SIGNED;
            default: throw std::invalid_argument("invalid SignednessFormatMode value: " + std::to_string(value));
        }
    }

    inline int ordinal(SignednessFormatMode mode) {
        return static_cast<int>(mode);
    }

    inline std::string toString(SignednessFormatMode mode) {
        switch (mode) {
            case SignednessFormatMode::DEFAULT: return "DEFAULT";
            case SignednessFormatMode::UNSIGNED: return "UNSIGNED";
            case SignednessFormatMode::SIGNED: return "SIGNED";
            default: return "UNKNOWN";
        }
    }

} // namespace SignednessFormatModeUtil

} // namespace ghidra
