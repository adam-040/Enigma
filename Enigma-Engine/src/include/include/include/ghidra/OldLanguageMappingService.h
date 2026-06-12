/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file OldLanguageMappingService.h
/// \brief Service that maps deprecated old language "magic strings" to modern
///        LanguageID/CompilerSpecID pairs.
/// Translated from: ghidra.program.model.lang.OldLanguageMappingService
#pragma once

#include "ghidra/LanguageCompilerSpecPair.h"
#include <string>

namespace ghidra {

class OldLanguageMappingService {
public:
    OldLanguageMappingService();

    /// Look up the modern language/compiler pair for a deprecated "magic string".
    /// @param magicString the old name
    /// @param languageReplacementOK if true, the latest replacement language is returned
    /// @return the pair, or nullptr if not found
    static LanguageCompilerSpecPair lookupMagicString(const std::string& magicString,
                                                     bool languageReplacementOK);

    /// Parse an XML language string ("<langID>:<cspecID>" or an old magic string)
    /// and return the modern replacement pair (or nullptr if no mapping exists).
    static LanguageCompilerSpecPair processXmlLanguageString(const std::string& languageString);

protected:
    virtual LanguageCompilerSpecPair doLookupMagicString(const std::string& magicString,
                                                         bool languageReplacementOK);
    static LanguageCompilerSpecPair validatePair(const LanguageCompilerSpecPair& pair);
};

} // namespace ghidra
