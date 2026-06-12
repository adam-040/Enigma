/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <ghidra/ExtensionPoint.h>
#include <ghidra/LanguageID.h>
#include <ghidra/LanguageNotFoundException.h>
#include <vector>

namespace ghidra {

class Language;
class LanguageDescription;
class TaskMonitor;

class LanguageProvider : public ExtensionPoint {
public:
    Language* getLanguage(const LanguageID& languageId) {
        return getLanguage(languageId, nullptr);
    }

    virtual Language* getLanguage(const LanguageID& languageId, TaskMonitor* monitor) = 0;
    virtual std::vector<LanguageDescription*> getLanguageDescriptions() = 0;
    virtual bool hadLoadFailure() = 0;
    virtual bool isLanguageLoaded(const LanguageID& languageId) = 0;
};

} // namespace ghidra
