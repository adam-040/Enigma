/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SettingsDefinition.cpp
/// \brief Generic interface for defining display options on data and dataTypes
#include <ghidra/SettingsDefinition.h>

namespace ghidra {

std::vector<SettingsDefinition*> SettingsDefinition::concat(
    const std::vector<SettingsDefinition*>& base,
    const std::vector<SettingsDefinition*>& additional)
{
    if (additional.empty()) return base;
    if (base.empty()) return additional;

    std::vector<SettingsDefinition*> result = base;
    for (auto* def : additional) {
        bool found = false;
        for (auto* existing : base) {
            if (existing == def) { found = true; break; }
        }
        if (!found) result.push_back(def);
    }
    return result;
}

std::vector<SettingsDefinition*> SettingsDefinition::filterSettingsDefinitions(
    const std::vector<SettingsDefinition*>& definitions,
    const std::function<bool(const SettingsDefinition*)>& filter)
{
    std::vector<SettingsDefinition*> result;
    for (auto* def : definitions) {
        if (filter(def)) result.push_back(def);
    }
    return result;
}

} // namespace ghidra
