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
/// \file MutabilitySettingsDefinition.h
/// \brief Settings definition for data mutability
/// Translated from: ghidra.program.model.data.MutabilitySettingsDefinition
#pragma once

#include <string>
#include <vector>
#include "ghidra/EnumSettingsDefinition.h"
#include "ghidra/Settings.h"

namespace ghidra {

/**
 * The settings definition for the numeric display format
 */
class MutabilitySettingsDefinition : public EnumSettingsDefinition {
private:
    MutabilitySettingsDefinition() = default;

public:
    static const int NORMAL = 0;
    static const int VOLATILE = 1;
    static const int CONSTANT = 2;
    static const int WRITABLE = 3;

    static MutabilitySettingsDefinition& def();

    /// Returns the mutability mode based on the current settings
    int getMutabilityMode(const Settings* settings) const;

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
};

} // namespace ghidra
