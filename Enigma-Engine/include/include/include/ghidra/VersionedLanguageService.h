/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file VersionedLanguageService.h
/// \brief Service that provides Languages given a name, with version support
/// Translated from: ghidra.program.model.lang.VersionedLanguageService
#pragma once

#include "ghidra/LanguageService.h"

namespace ghidra {

class VersionedLanguageService : public LanguageService {
public:
    virtual Language* getLanguage(const LanguageID& languageID, int version) = 0;
    virtual LanguageDescription* getLanguageDescription(const LanguageID& languageID, int version) = 0;
};

} // namespace ghidra
