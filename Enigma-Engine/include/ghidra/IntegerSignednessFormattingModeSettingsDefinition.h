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
/// \file IntegerSignednessFormattingModeSettingsDefinition.h
/// \brief Settings definition for the numeric display format for handling signed values
/// Translated from: ghidra.docking.settings.IntegerSignednessFormattingModeSettingsDefinition
#pragma once

#include <string>
#include <vector>
#include "ghidra/EnumSettingsDefinition.h"
#include "ghidra/SignednessFormatMode.h"
#include "ghidra/Settings.h"

namespace ghidra {

/**
 * The settings definition for the numeric display format for handling signed values.
 */
class IntegerSignednessFormattingModeSettingsDefinition : public EnumSettingsDefinition {
private:
    SignednessFormatMode defaultFormat_;

    IntegerSignednessFormattingModeSettingsDefinition(SignednessFormatMode defaultFormat)
        : defaultFormat_(defaultFormat) {}

public:
    static IntegerSignednessFormattingModeSettingsDefinition& def();
    static IntegerSignednessFormattingModeSettingsDefinition& def_signed();
    static IntegerSignednessFormattingModeSettingsDefinition& def_unsigned();

    /// Returns the format based on the specified settings
    SignednessFormatMode getFormatMode(const Settings* settings) const;

    /// Set, or clear if mode is DEFAULT, the new mode in the provided settings
    void setFormatMode(Settings* settings, SignednessFormatMode mode);

    int getChoice(const Settings* settings) const override;

    std::string getValueString(const Settings* settings) const override;

    void setChoice(Settings* settings, int value) override;

    std::vector<std::string> getDisplayChoices(const Settings* settings) const override;

    std::string getName() const override;

    std::string getStorageKey() const override;

    std::string getDescription() const override;

    std::string getDisplayChoice(int value, const Settings* s1) const override;

    void clear(Settings* settings) const override;

    void copySetting(const Settings* settings, Settings* destSettings) const override;

    bool hasValue(const Settings* setting) const override;

    std::string getDisplayChoice(const Settings* settings) const;

    void setDisplayChoice(Settings* settings, const std::string& choice);
};

} // namespace ghidra
