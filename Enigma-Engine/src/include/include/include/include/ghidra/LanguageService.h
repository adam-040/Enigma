/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file LanguageService.h
/// \brief Service that provides Languages given a name
/// Translated from: ghidra.program.model.lang.LanguageService
#pragma once

#include <vector>
#include "ghidra/Language.h"
#include "ghidra/LanguageID.h"
#include "ghidra/LanguageDescription.h"
#include "ghidra/Processor.h"

namespace ghidra {

class LanguageCompilerSpecPair;
class LanguageCompilerSpecQuery;
class ExternalLanguageCompilerSpecQuery;

class LanguageService {
public:
    virtual ~LanguageService() = default;
    virtual Language* getLanguage(const LanguageID& languageID) = 0;
    virtual Language* getDefaultLanguage(const Processor& processor) = 0;
    virtual LanguageDescription* getLanguageDescription(const LanguageID& languageID) = 0;
    virtual std::vector<LanguageDescription*> getLanguageDescriptions(bool includeDeprecated) = 0;
    virtual std::vector<LanguageCompilerSpecPair> getLanguageCompilerSpecPairs(const LanguageCompilerSpecQuery& query) = 0;
    virtual std::vector<LanguageCompilerSpecPair> getLanguageCompilerSpecPairs(const ExternalLanguageCompilerSpecQuery& query) = 0;
    virtual std::vector<LanguageDescription*> getLanguageDescriptions(const Processor& processor) = 0;
};

} // namespace ghidra
