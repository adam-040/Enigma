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
/// \file OverlappingFunctionException.h
/// \brief Exception thrown when a function overlaps with another namespace
/// Translated from: ghidra.program.database.function.OverlappingFunctionException
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class OverlappingFunctionException : public std::exception {
private:
    std::string message_;

public:
    explicit OverlappingFunctionException(const std::string& msg) : message_(msg) {}

    OverlappingFunctionException(const std::string& entryPoint, const std::string& start, const std::string& end)
        : message_("Unable to create function at " + entryPoint + " due to overlap with range [" +
                   start + "," + end + "]") {}

    OverlappingFunctionException(const std::string& entryPoint)
        : message_("Unable to create function at " + entryPoint + " due to overlap with another namespace") {}

    const char* what() const noexcept override { return message_.c_str(); }
};

} // namespace ghidra
