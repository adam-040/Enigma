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
/// \file UnsupportedFloatFormatException.h
/// \brief Exception for unsupported float format sizes
/// Translated from: ghidra.pcode.floatformat.UnsupportedFloatFormatException
#pragma once

#include "LowlevelError.h"
#include <string>

namespace ghidra {

class UnsupportedFloatFormatException : public LowlevelError {
public:
    explicit UnsupportedFloatFormatException(const std::string& message) : LowlevelError(message) {}

    explicit UnsupportedFloatFormatException(int formatSize)
        : LowlevelError("Unsupported float format size: " + std::to_string(formatSize)) {}
};

} // namespace ghidra
