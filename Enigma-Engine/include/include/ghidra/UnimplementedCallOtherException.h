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
/// \file UnimplementedCallOtherException.h
/// \brief Exception thrown for unimplemented CALLOTHER pcode operations
/// Translated from: ghidra.pcode.emulate.UnimplementedCallOtherException
#pragma once

#include "LowlevelError.h"
#include <string>

namespace ghidra {

class PcodeOpRaw;

class UnimplementedCallOtherException : public LowlevelError {
private:
    std::string opName;
    const PcodeOpRaw* op = nullptr;

public:
    UnimplementedCallOtherException(const PcodeOpRaw* op, const std::string& opName);

    const PcodeOpRaw* getCallOtherOp() const { return op; }
    const std::string& getCallOtherOpName() const { return opName; }
};

} // namespace ghidra
