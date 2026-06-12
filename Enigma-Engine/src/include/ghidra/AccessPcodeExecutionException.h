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
/// \file AccessPcodeExecutionException.h
/// \brief Exception for issues accessing executor state (memory or register values)
/// Translated from: ghidra.pcode.exec.AccessPcodeExecutionException
#pragma once

#include "PcodeExecutionException.h"
#include <stdexcept>
#include <string>

namespace ghidra {

class AccessPcodeExecutionException : public PcodeExecutionException {
public:
    AccessPcodeExecutionException(const std::string& message, PcodeFrame* frame, const std::exception& cause)
        : PcodeExecutionException(message, frame, cause) {}

    AccessPcodeExecutionException(const std::string& message, const std::exception& cause)
        : PcodeExecutionException(message, cause) {}

    explicit AccessPcodeExecutionException(const std::string& message)
        : PcodeExecutionException(message) {}
};

} // namespace ghidra
