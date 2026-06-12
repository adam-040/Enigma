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
/// \file NumberSettingsDefinition.h
/// \brief Interface for SettingsDefinitions that have numeric (long) values
/// Translated from: ghidra.docking.settings.NumberSettingsDefinition
#pragma once

#include <string>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include "ghidra/SettingsDefinition.h"

namespace ghidra {

class Settings;

/**
 * Interface for SettingsDefinitions that have numeric (long) values.
 */
class NumberSettingsDefinition : public virtual SettingsDefinition {
public:
    ~NumberSettingsDefinition() override = default;

    /// Gets the value for this SettingsDefinition given a Settings object
    virtual int64_t getValue(const Settings* settings) const = 0;

    /// Sets the given value into the given settings object
    virtual void setValue(Settings* settings, int64_t value) = 0;

    /// Get the maximum value permitted. The absolute value of the setting may not exceed this.
    virtual int64_t getMaxValue() const = 0;

    /// Determine if negative values are permitted.
    virtual bool allowNegativeValue() const = 0;

    /// Determine if hexadecimal entry/display is preferred due to the nature of the setting.
    virtual bool isHexModePreferred() const = 0;

    /// Get the setting value as a string (hex representation)
    std::string getValueString(const Settings* settings) const override;

    /// Check two settings for equality corresponding to this definition
    bool hasSameValue(const Settings* settings1, const Settings* settings2) const override;
};

} // namespace ghidra
