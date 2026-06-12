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
/// \file ParameterConflictException.h
/// \brief Exception when stack offset conflicts with an existing function parameter
/// Translated from: ghidra.app.plugin.core.references.ParameterConflictException
#pragma once

#include <stdexcept>
#include <string>
#include <sstream>
#include <iomanip>

namespace ghidra {

class ParameterConflictException : public std::exception {
private:
    std::string message_;

public:
    ParameterConflictException(const std::string& paramName, int stackOffset)
        : message_("New parameter conflicts with '" + paramName + "' at stack offset " +
                   toSignedHexString(stackOffset)) {}

    const char* what() const noexcept override { return message_.c_str(); }

private:
    static std::string toSignedHexString(int value) {
        std::stringstream ss;
        ss << "0x" << std::hex << value;
        return ss.str();
    }
};

} // namespace ghidra
