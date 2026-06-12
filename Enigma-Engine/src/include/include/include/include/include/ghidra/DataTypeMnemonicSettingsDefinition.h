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
/// \file DataTypeMnemonicSettingsDefinition.h
/// \brief Settings definition for data type mnemonic style
/// Translated from: ghidra.program.model.data.DataTypeMnemonicSettingsDefinition
#pragma once

#include <string>
#include <vector>
#include "ghidra/EnumSettingsDefinition.h"
#include "ghidra/Settings.h"

namespace ghidra {

/**
 * The settings definition for the data type mnemonic style.
 */
class DataTypeMnemonicSettingsDefinition : public EnumSettingsDefinition {
public:
    static constexpr int DEFAULT = 0;
    static constexpr int ASSEMBLY = 1;
    static constexpr int CSPEC = 2;

    static const DataTypeMnemonicSettingsDefinition* DEF();

    /// Returns the mnemonic style (DEFAULT, ASSEMBLY, CSPEC)
    int getMnemonicStyle(const Settings* settings) const;

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

    DataTypeMnemonicSettingsDefinition() = default;
};

} // namespace ghidra
