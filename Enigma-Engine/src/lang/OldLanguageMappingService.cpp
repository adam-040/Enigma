/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file OldLanguageMappingService.cpp
#include "ghidra/OldLanguageMappingService.h"
#include "ghidra/LanguageCompilerSpecPair.h"
#include "ghidra/LanguageID.h"
#include "ghidra/CompilerSpecID.h"

namespace ghidra {

static OldLanguageMappingService* g_instance = nullptr;

OldLanguageMappingService::OldLanguageMappingService() {
    if (g_instance == nullptr) g_instance = this;
}

LanguageCompilerSpecPair OldLanguageMappingService::lookupMagicString(const std::string& magicString,
                                                                       bool languageReplacementOK) {
    if (g_instance == nullptr) return LanguageCompilerSpecPair();
    return g_instance->doLookupMagicString(magicString, languageReplacementOK);
}

LanguageCompilerSpecPair OldLanguageMappingService::doLookupMagicString(const std::string&,
                                                                       bool) {
    return LanguageCompilerSpecPair();
}

LanguageCompilerSpecPair OldLanguageMappingService::validatePair(const LanguageCompilerSpecPair& pair) {
    if (!pair.isValid()) return pair;
    return pair;
}

LanguageCompilerSpecPair OldLanguageMappingService::processXmlLanguageString(const std::string& languageString) {
    if (languageString.empty()) return LanguageCompilerSpecPair();
    size_t pos = languageString.rfind(':');
    if (pos != std::string::npos && pos > 0) {
        LanguageCompilerSpecPair pair(
            LanguageID(languageString.substr(0, pos)),
            CompilerSpecID(languageString.substr(pos + 1)));
        return validatePair(pair);
    }
    return lookupMagicString(languageString, true);
}

} // namespace ghidra
