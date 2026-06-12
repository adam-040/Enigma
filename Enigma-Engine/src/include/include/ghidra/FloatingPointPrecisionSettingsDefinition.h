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
/// \file FloatingPointPrecisionSettingsDefinition.h
/// \brief Settings definition for floating-point display precision
/// Translated from: ghidra.docking.settings.FloatingPointPrecisionSettingsDefinition
#pragma once

#include <string>
#include <vector>
#include <array>
#include "ghidra/EnumSettingsDefinition.h"
#include "ghidra/Settings.h"

namespace ghidra {

/**
 * SettingsDefinition to define the number of digits of precision to show.
 * The value is rendered to thousandths, 3 digits of precision, by default.
 */
class FloatingPointPrecisionSettingsDefinition : public EnumSettingsDefinition {
public:
    static constexpr int MAX_PRECISION = 10;

    static const FloatingPointPrecisionSettingsDefinition* DEF();

    /// Get the precision (0-10 digits)
    int getPrecision(const Settings* settings) const {
        return getChoice(settings) - 1;
    }

    /// Set the precision (0-10 digits)
    void setPrecision(Settings* settings, int digits) {
        setChoice(settings, digits + 1);
    }

    int getChoice(const Settings* settings) const override;

    std::string getValueString(const Settings* settings) const override;

    void setChoice(Settings* settings, int valueIndex) override;

    std::vector<std::string> getDisplayChoices(const Settings* settings) const override;

    std::string getName() const override;

    std::string getStorageKey() const override;

    std::string getDescription() const override;

    int getChoice(const std::string& displayChoice, const Settings* settings) const;

    std::string getDisplayChoice(int value, const Settings* settings) const override;

    void clear(Settings* settings) const override;

    void copySetting(const Settings* settings, Settings* destSettings) const override;

    bool hasValue(const Settings* setting) const override;

    FloatingPointPrecisionSettingsDefinition() = default;
};

} // namespace ghidra
