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
/// \file MDException.h
/// \brief Exception handling demangling errors for MDMang
/// Translated from: mdemangler.MDException
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class MDException : public std::exception {
private:
    std::string message_;
    bool invalidMangledName = false;

public:
    explicit MDException(const std::string& message) : message_(message) {}

    explicit MDException(const std::exception& cause) : message_(cause.what()) {}

    explicit MDException(bool invalidMangledName)
        : message_(), invalidMangledName(invalidMangledName) {}

    const char* what() const noexcept override { return message_.c_str(); }

    bool isInvalidMangledName() const { return invalidMangledName; }
};

} // namespace ghidra
