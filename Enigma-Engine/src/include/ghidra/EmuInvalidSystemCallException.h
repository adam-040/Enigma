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
/// \file EmuInvalidSystemCallException.h
/// \brief Exception when emulated program invokes a system call incorrectly
/// Translated from: ghidra.pcode.emu.sys.EmuInvalidSystemCallException
#pragma once

#include "EmuSystemException.h"
#include <string>

namespace ghidra {

class EmuInvalidSystemCallException : public EmuSystemException {
public:
    explicit EmuInvalidSystemCallException(long number)
        : EmuSystemException("Invalid system call number: " + std::to_string(number)) {}

    explicit EmuInvalidSystemCallException(const std::string& message)
        : EmuSystemException(message) {}

    EmuInvalidSystemCallException(const std::string& message, const std::exception& cause)
        : EmuSystemException(message, nullptr, cause) {}
};

} // namespace ghidra
