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
/// \file EnumSettingsDefinition.h
/// \brief Interface for a SettingsDefinition with enumerated values
/// Translated from: ghidra.docking.settings.EnumSettingsDefinition
#pragma once

#include <string>
#include <vector>
#include "ghidra/SettingsDefinition.h"

namespace ghidra {

class Settings;

/**
 * Interface for a SettingsDefinition with enumerated values.
 */
class EnumSettingsDefinition : public virtual SettingsDefinition {
public:
    virtual ~EnumSettingsDefinition() = default;

    /// Returns the current value for this settings
    virtual int getChoice(const Settings* settings) const = 0;

    /// Sets the given value into the settings object
    virtual void setChoice(Settings* settings, int value) = 0;

    /// Returns the String for the given enum value
    virtual std::string getDisplayChoice(int value, const Settings* settings) const = 0;

    /// Gets the list of choices as strings
    virtual std::vector<std::string> getDisplayChoices(const Settings* settings) const = 0;

    bool hasSameValue(const Settings* settings1, const Settings* settings2) const override {
        return getChoice(settings1) == getChoice(settings2);
    }
};

} // namespace ghidra
