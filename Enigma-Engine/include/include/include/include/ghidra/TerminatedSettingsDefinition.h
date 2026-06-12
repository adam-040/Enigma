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
/// \file TerminatedSettingsDefinition.h
/// \brief Settings definition for strings being terminated or unterminated
/// Translated from: ghidra.program.model.data.TerminatedSettingsDefinition
#pragma once

#include <string>
#include <vector>
#include "ghidra/EnumSettingsDefinition.h"
#include "ghidra/Settings.h"

namespace ghidra {

/**
 * Settings definition for strings being terminated or unterminated
 */
class TerminatedSettingsDefinition : public EnumSettingsDefinition {
private:
    static const int UNTERMINATED_VALUE = 0;
    static const int TERMINATED_VALUE = 1;

    TerminatedSettingsDefinition() = default;

public:
    static TerminatedSettingsDefinition& def();

    /// Gets the current termination setting from the given settings objects or returns
    /// the default if not in either settings object
    bool isTerminated(const Settings* settings) const;

    void setTerminated(Settings* settings, bool isTerminated);

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
