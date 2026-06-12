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
/// \file AssemblyGrammarException.h
/// \brief Exception to identify errors associated with grammar construction
/// Translated from: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammarException
#pragma once

#include "AssemblyException.h"
#include <string>

namespace ghidra {

class AssemblyGrammarException : public AssemblyException {
public:
    explicit AssemblyGrammarException(const std::string& msg) : AssemblyException(msg) {}

    AssemblyGrammarException(const std::string& msg, const std::exception& cause)
        : AssemblyException(msg + " (caused by: " + std::string(cause.what()) + ")") {}
};

} // namespace ghidra
