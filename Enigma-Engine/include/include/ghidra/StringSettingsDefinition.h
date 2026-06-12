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
/// \file StringSettingsDefinition.h
/// \brief Interface for a SettingsDefinition with string values
/// Translated from: ghidra.docking.settings.StringSettingsDefinition
#pragma once

#include <string>
#include <vector>
#include <unordered_set>
#include "ghidra/SettingsDefinition.h"

namespace ghidra {

class Settings;

/**
 * Interface for a SettingsDefinition with string values.
 */
class StringSettingsDefinition : public virtual SettingsDefinition {
public:
    virtual ~StringSettingsDefinition() = default;

    /// Gets the value for this SettingsDefinition given a Settings object
    virtual std::string getValue(const Settings* settings) const = 0;

    /// Sets the given value into the settings object
    virtual void setValue(Settings* settings, const std::string& value) = 0;

    std::string getValueString(const Settings* settings) const override {
        std::string str = getValue(settings);
        return str.empty() ? "" : str;
    }

    bool hasSameValue(const Settings* settings1, const Settings* settings2) const override {
        return getValue(settings1) == getValue(settings2);
    }

    /// Get suggested setting values
    virtual std::vector<std::string> getSuggestedValues(const Settings* settings) const {
        (void)settings;
        return {};
    }

    /// Determine if this settings definition supports suggested values
    virtual bool supportsSuggestedValues() const { return false; }

    /// Add preferred setting values to the specified set
    virtual bool addPreferredValues(const void* settingsOwner, std::unordered_set<std::string>& set) const {
        (void)settingsOwner;
        (void)set;
        return false;
    }
};

} // namespace ghidra
