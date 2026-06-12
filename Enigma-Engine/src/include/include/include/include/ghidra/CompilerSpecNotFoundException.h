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
/// \file CompilerSpecNotFoundException.h
/// \brief Exception thrown when the named compiler spec cannot be found
/// Translated from: ghidra.program.model.lang.CompilerSpecNotFoundException
#pragma once

#include "LanguageID.h"
#include "CompilerSpecID.h"
#include <stdexcept>
#include <string>

namespace ghidra {

class CompilerSpecNotFoundException : public std::runtime_error {
public:
    CompilerSpecNotFoundException(const LanguageID& languageId, const CompilerSpecID& compilerSpecID)
        : std::runtime_error("Compiler Spec not found for '" + languageId.getIdAsString() + "/" +
                             compilerSpecID.getIdAsString() + "')") {}

    CompilerSpecNotFoundException(const LanguageID& languageId, const CompilerSpecID& compilerSpecID,
                                  const std::string& resourceFileName, const std::exception& e)
        : std::runtime_error("Exception reading " + languageId.getIdAsString() + "/" +
                             compilerSpecID.getIdAsString() + "(" + resourceFileName + "): " + e.what()) {}
};

} // namespace ghidra
