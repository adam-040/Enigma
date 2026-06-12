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
/// \file EmuUnixException.h
/// \brief Exception for errors within UNIX system call libraries
/// Translated from: ghidra.pcode.emu.unix.EmuUnixException
#pragma once

#include "EmuSystemException.h"
#include <optional>
#include <string>

namespace ghidra {

class EmuUnixException : public EmuSystemException {
private:
    std::optional<int> errno_;

public:
    explicit EmuUnixException(const std::string& message)
        : EmuSystemException(message), errno_() {}

    EmuUnixException(const std::string& message, int errno)
        : EmuSystemException(message), errno_(errno) {}

    EmuUnixException(const std::string& message, const std::exception& e)
        : EmuSystemException(message, nullptr, e), errno_() {}

    EmuUnixException(const std::string& message, int errno, const std::exception& e)
        : EmuSystemException(message, nullptr, e), errno_(errno) {}

    std::optional<int> getErrno() const { return errno_; }
};

} // namespace ghidra
