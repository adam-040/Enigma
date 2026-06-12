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
/// \file BooleanSettingsDefinition.h
/// \brief Interface for SettingsDefinitions that have boolean values
/// Translated from: ghidra.docking.settings.BooleanSettingsDefinition
#pragma once

#include "ghidra/SettingsDefinition.h"

namespace ghidra {

class Settings;

/**
 * The interface for SettingsDefinitions that have boolean values.
 * SettingsDefinition objects are used as keys into Settings objects that
 * contain the values using a name-value type storage mechanism.
 */
class BooleanSettingsDefinition : public SettingsDefinition {
public:
    ~BooleanSettingsDefinition() override = default;

    /// Gets the value for this SettingsDefinition given a Settings object
    virtual bool getValue(const Settings* settings) const = 0;

    /// Sets the given value into the given settings object using this settingsDefinition as the key
    virtual void setValue(Settings* settings, bool value) = 0;

    /// Check two settings for equality corresponding to this definition
    bool hasSameValue(const Settings* settings1, const Settings* settings2) const override {
        return getValue(settings1) == getValue(settings2);
    }
};

} // namespace ghidra
