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
/// \file InvalidDataTypeException.h
/// \brief Exception thrown if a data type is not valid for the operation being performed
/// Translated from: ghidra.program.model.data.InvalidDataTypeException
#pragma once

#include "UsrException.h"
#include <string>

namespace ghidra {

class InvalidDataTypeException : public UsrException {
public:
    InvalidDataTypeException() : UsrException("Invalid data type error.") {}

    explicit InvalidDataTypeException(const std::string& message) : UsrException(message) {}

    InvalidDataTypeException(const std::string& message, const std::exception& cause)
        : UsrException(message + " (caused by: " + std::string(cause.what()) + ")") {}
};

} // namespace ghidra
