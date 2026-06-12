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
/// \file UnimplementedInstructionException.h
/// \brief Exception thrown for unimplemented instructions
/// Translated from: ghidra.pcode.emulate.UnimplementedInstructionException
#pragma once

#include "LowlevelError.h"
#include "Address.h"

namespace ghidra {

class UnimplementedInstructionException : public LowlevelError {
private:
    Address addr;

public:
    explicit UnimplementedInstructionException(const Address& addr)
        : LowlevelError("Unimplemented instruction, PC=" + addr.toString()), addr(addr) {}

    const Address& getInstructionAddress() const { return addr; }
};

} // namespace ghidra
