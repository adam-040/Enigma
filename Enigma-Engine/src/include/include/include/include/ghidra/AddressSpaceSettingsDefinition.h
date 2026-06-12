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
/// \file AddressSpaceSettingsDefinition.h
/// \brief Settings definition for address space name
/// Translated from: ghidra.program.model.data.AddressSpaceSettingsDefinition
#pragma once

#include <string>
#include <vector>
#include <unordered_set>
#include "ghidra/StringSettingsDefinition.h"
#include "ghidra/TypeDefSettingsDefinition.h"
#include "ghidra/Settings.h"

namespace ghidra {

class AddressSpaceSettingsDefinition : public StringSettingsDefinition, public TypeDefSettingsDefinition {
private:
    AddressSpaceSettingsDefinition() = default;

public:
    static AddressSpaceSettingsDefinition& def();

    std::string getValue(const Settings* settings) const override;

    void setValue(Settings* settings, const std::string& value) override;

    bool hasValue(const Settings* settings) const override;

    std::string getName() const override;

    std::string getStorageKey() const override;

    std::string getDescription() const override;

    void clear(Settings* settings) const override;

    void copySetting(const Settings* srcSettings, Settings* destSettings) const override;

    std::string getAttributeSpecification(const Settings* settings) const override;

    bool supportsSuggestedValues() const override;

    bool hasSameValue(const Settings* settings1, const Settings* settings2) const override {
        return getValue(settings1) == getValue(settings2);
    }
};

} // namespace ghidra
