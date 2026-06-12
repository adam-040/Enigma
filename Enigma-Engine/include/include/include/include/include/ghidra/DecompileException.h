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
/// \file DecompileException.h
/// \brief Exception from the decompiler process
/// Translated from: ghidra.app.decompiler.DecompileException
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class DecompileException : public std::exception {
private:
    std::string message_;

public:
    DecompileException(const std::string& type, const std::string& msg)
        : message_(type + ": " + msg) {}

    const char* what() const noexcept override { return message_.c_str(); }

    std::string toString() const { return "DecompileException: " + message_; }
};

} // namespace ghidra
