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
/// \file LanguageNotFoundException.h
/// \brief Exception thrown when the named language cannot be found
/// Translated from: ghidra.program.model.lang.LanguageNotFoundException
#pragma once

#include "LanguageID.h"
#include "CompilerSpecID.h"
#include <stdexcept>
#include <string>

namespace ghidra {

class LanguageNotFoundException : public std::runtime_error {
public:
    LanguageNotFoundException(const LanguageID& languageID, int majorVersion, int minorVersion)
        : std::runtime_error("Language version (V" + std::to_string(majorVersion) + "." +
                             std::to_string(minorVersion) + " or later) required for '" +
                             languageID.getIdAsString() + "'") {}

    explicit LanguageNotFoundException(const LanguageID& languageID)
        : std::runtime_error("Language not found for '" + languageID.getIdAsString() + "'") {}

    LanguageNotFoundException(const LanguageID& languageID, const std::exception& cause)
        : std::runtime_error("Language not found for '" + languageID.getIdAsString() +
                             "' (caused by: " + std::string(cause.what()) + ")") {}

    explicit LanguageNotFoundException(const std::string& message) : std::runtime_error(message) {}

    LanguageNotFoundException(const LanguageID& languageID, const CompilerSpecID& compilerSpecID)
        : std::runtime_error("Language/Compiler Spec not found for '" +
                             languageID.getIdAsString() + "/" + compilerSpecID.getIdAsString() + "'") {}

    LanguageNotFoundException(const LanguageID& languageID, const std::string& msg)
        : std::runtime_error("Language not found for '" + languageID.getIdAsString() + "' " + msg) {}
};

} // namespace ghidra
