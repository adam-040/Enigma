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
/// \file SettingsDefinition.h
/// \brief Generic interface for defining display options on data and dataTypes
/// Translated from: ghidra.docking.settings.SettingsDefinition
#pragma once

#include <string>
#include <vector>
#include <functional>

namespace ghidra {

class Settings;

/**
 * Generic interface for defining display options on data and dataTypes. Uses
 * Settings objects to store values which are interpreted by SettingsDefinition objects.
 */
class SettingsDefinition {
public:
    virtual ~SettingsDefinition() = default;

    /// Determine if a setting value has been stored
    virtual bool hasValue(const Settings* settings) const = 0;

    /// Get the setting value as a string. Returns default if not stored.
    virtual std::string getValueString(const Settings* settings) const = 0;

    /// Returns the display name of this SettingsDefinition
    virtual std::string getName() const = 0;

    /// Get the Settings key used when storing a key/value entry
    virtual std::string getStorageKey() const = 0;

    /// Returns a description of this settings definition
    virtual std::string getDescription() const = 0;

    /// Removes any values in the given settings object associated with this definition
    virtual void clear(Settings* settings) const = 0;

    /// Copies any setting value from srcSettings to destSettings
    virtual void copySetting(const Settings* srcSettings, Settings* destSettings) const = 0;

    /// Check two settings for equality corresponding to this definition
    virtual bool hasSameValue(const Settings* settings1, const Settings* settings2) const = 0;

    /// Concatenate two arrays of SettingsDefinition, discarding duplicates
    static std::vector<SettingsDefinition*> concat(
        const std::vector<SettingsDefinition*>& base,
        const std::vector<SettingsDefinition*>& additional);

    /// Filter settings definitions by predicate
    static std::vector<SettingsDefinition*> filterSettingsDefinitions(
        const std::vector<SettingsDefinition*>& definitions,
        const std::function<bool(const SettingsDefinition*)>& filter);
};

} // namespace ghidra
