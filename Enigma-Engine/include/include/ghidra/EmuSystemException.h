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
/// \file EmuSystemException.h
/// \brief P-code execution exception related to system simulation
/// Translated from: ghidra.pcode.emu.sys.EmuSystemException
#pragma once

#include "PcodeExecutionException.h"
#include <string>

namespace ghidra {

class EmuSystemException : public PcodeExecutionException {
public:
    explicit EmuSystemException(const std::string& message) : PcodeExecutionException(message) {}

    EmuSystemException(const std::string& message, PcodeFrame* frame)
        : PcodeExecutionException(message, frame, std::runtime_error("")) {}

    EmuSystemException(const std::string& message, PcodeFrame* frame, const std::exception& cause)
        : PcodeExecutionException(message, frame, cause) {}
};

} // namespace ghidra
