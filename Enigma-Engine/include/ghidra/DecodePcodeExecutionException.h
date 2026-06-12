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
/// \file DecodePcodeExecutionException.h
/// \brief Exception for p-code decode errors during execution
/// Translated from: ghidra.pcode.exec.DecodePcodeExecutionException
#pragma once

#include "PcodeExecutionException.h"
#include "Address.h"
#include <string>

namespace ghidra {

class DecodePcodeExecutionException : public PcodeExecutionException {
private:
    Address pc;

public:
    DecodePcodeExecutionException(const std::string& message, const Address& pc)
        : PcodeExecutionException(formatMessage(message, pc)), pc(pc) {}

    const Address& getProgramCounter() const { return pc; }

private:
    static std::string formatMessage(const std::string& message, const Address& pc) {
        if (message.find("PC=") != std::string::npos) {
            return message;
        }
        return message + " (PC=" + pc.toString() + ")";
    }
};

} // namespace ghidra
