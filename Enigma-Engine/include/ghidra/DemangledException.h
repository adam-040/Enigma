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
/// \file DemangledException.h
/// \brief Exception handling demangling errors
/// Translated from: ghidra.app.util.demangler.DemangledException
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class DemangledException : public std::exception {
private:
    std::string message_;
    bool invalidMangledName = false;

public:
    explicit DemangledException(const std::string& message) : message_(message) {}

    DemangledException(const std::string& message, const std::exception& cause)
        : message_(message + " (caused by: " + std::string(cause.what()) + ")") {}

    explicit DemangledException(bool invalidMangledName)
        : message_(), invalidMangledName(invalidMangledName) {}

    const char* what() const noexcept override { return message_.c_str(); }

    bool isInvalidMangledName() const { return invalidMangledName; }
};

} // namespace ghidra
