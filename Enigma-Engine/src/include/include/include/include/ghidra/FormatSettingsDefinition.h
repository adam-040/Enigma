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
/// \file FormatSettingsDefinition.h
/// \brief Settings definition for numeric display format
/// Translated from: ghidra.docking.settings.FormatSettingsDefinition
#pragma once

#include <string>
#include <vector>
#include <array>
#include "ghidra/EnumSettingsDefinition.h"
#include "ghidra/Settings.h"

namespace ghidra {

/**
 * The settings definition for the numeric display format.
 */
class FormatSettingsDefinition : public EnumSettingsDefinition {
public:
    static constexpr int HEX = 0;
    static constexpr int DECIMAL = 1;
    static constexpr int BINARY = 2;
    static constexpr int OCTAL = 3;
    static constexpr int CHAR = 4;

    static const FormatSettingsDefinition* DEF_HEX();
    static const FormatSettingsDefinition* DEF_DECIMAL();
    static const FormatSettingsDefinition* DEF_BINARY();
    static const FormatSettingsDefinition* DEF_OCTAL();
    static const FormatSettingsDefinition* DEF_CHAR();
    static const FormatSettingsDefinition* DEF();

    /// Returns the format based on the specified settings
    int getFormat(const Settings* settings) const;

    /// Returns the numeric radix associated with the format
    int getRadix(const Settings* settings) const;

    /// Returns a descriptive string suffix for the format
    std::string getRepresentationPostfix(const Settings* settings) const;

    int getChoice(const Settings* settings) const override;

    std::string getValueString(const Settings* settings) const override;

    void setChoice(Settings* settings, int value) override;

    std::vector<std::string> getDisplayChoices(const Settings* settings) const override;

    std::string getName() const override;

    std::string getStorageKey() const override;

    std::string getDescription() const override;

    std::string getDisplayChoice(int value, const Settings* settings) const override;

    void clear(Settings* settings) const override;

    void copySetting(const Settings* settings, Settings* destSettings) const override;

    bool hasValue(const Settings* setting) const override;

    /// Sets the settings object to the enum value indicated by the choice string
    void setDisplayChoice(Settings* settings, const std::string& choice);

private:
    int defaultFormat_;

public:
    explicit FormatSettingsDefinition(int defaultFormat) : defaultFormat_(defaultFormat) {}
};

} // namespace ghidra
