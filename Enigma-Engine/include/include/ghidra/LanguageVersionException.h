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
/// \file LanguageVersionException.h
/// \brief Exception for language version mismatches
/// Translated from: ghidra.program.model.lang.LanguageVersionException
#pragma once

#include "VersionException.h"
#include <string>

namespace ghidra {

class Language;
class LanguageTranslator;

class LanguageVersionException : public VersionException {
private:
    const Language* oldLanguage = nullptr;
    const LanguageTranslator* languageTranslator = nullptr;

public:
    LanguageVersionException(const std::string& msg, bool upgradable)
        : VersionException(msg, upgradable ? OLDER_VERSION : UNKNOWN_VERSION, upgradable) {}

    LanguageVersionException(const Language* oldLanguage, const LanguageTranslator* languageTranslator)
        : VersionException(true), oldLanguage(oldLanguage), languageTranslator(languageTranslator) {}

    const Language* getOldLanguage() const { return oldLanguage; }
    const LanguageTranslator* getLanguageTranslator() const { return languageTranslator; }
};

} // namespace ghidra
