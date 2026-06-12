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
/// \file InstructionDecodeException.h
/// \brief Exception thrown when instruction decoding fails
/// Translated from: ghidra.pcode.emulate.InstructionDecodeException
#pragma once

#include "LowlevelError.h"
#include "Address.h"
#include <string>

namespace ghidra {

class InstructionDecodeException : public LowlevelError {
private:
    Address pc;

public:
    InstructionDecodeException(const std::string& reason, const Address& pc)
        : LowlevelError("Instruction decode failed (" + reason + "), PC=" + pc.toString()),
          pc(pc) {}

    const Address& getProgramCounter() const { return pc; }
};

} // namespace ghidra
