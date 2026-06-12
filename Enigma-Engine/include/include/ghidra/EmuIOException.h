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
/// \file EmuIOException.h
/// \brief Exception for I/O errors within the simulated system
/// Translated from: ghidra.pcode.emu.sys.EmuIOException
#pragma once

#include "EmuInvalidSystemCallException.h"
#include <string>

namespace ghidra {

class EmuIOException : public EmuInvalidSystemCallException {
public:
    EmuIOException(const std::string& message, const std::exception& cause)
        : EmuInvalidSystemCallException(message, cause) {}

    explicit EmuIOException(const std::string& message)
        : EmuInvalidSystemCallException(message) {}
};

} // namespace ghidra
