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
/// \file InterruptPcodeExecutionException.h
/// \brief Exception thrown when execution hits a breakpoint
/// Translated from: ghidra.pcode.exec.InterruptPcodeExecutionException
#pragma once

#include "PcodeExecutionException.h"
#include <string>

namespace ghidra {

class InterruptPcodeExecutionException : public PcodeExecutionException {
public:
    InterruptPcodeExecutionException(PcodeFrame* frame, const std::exception& cause)
        : PcodeExecutionException("Execution hit breakpoint", frame, cause) {}
};

} // namespace ghidra
