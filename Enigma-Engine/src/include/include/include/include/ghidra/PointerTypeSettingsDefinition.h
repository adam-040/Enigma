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
/// \file PointerTypeSettingsDefinition.h
/// \brief Settings definition for pointer type
/// Translated from: ghidra.program.model.data.PointerTypeSettingsDefinition
#pragma once

#include <string>
#include <vector>
#include "ghidra/EnumSettingsDefinition.h"
#include "ghidra/TypeDefSettingsDefinition.h"
#include "ghidra/PointerType.h"
#include "ghidra/Settings.h"

namespace ghidra {

/**
 * The settings definition for the numeric display format
 */
class PointerTypeSettingsDefinition : public EnumSettingsDefinition, public TypeDefSettingsDefinition {
private:
    PointerTypeSettingsDefinition() = default;

public:
    static PointerTypeSettingsDefinition& def();

    /// Returns the format based on the specified settings
    PointerType getType(const Settings* settings) const;

    void setType(Settings* settings, PointerType type);

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

    std::string getAttributeSpecification(const Settings* settings) const override;

    bool hasSameValue(const Settings* settings1, const Settings* settings2) const override {
        return getChoice(settings1) == getChoice(settings2);
    }
};

} // namespace ghidra
