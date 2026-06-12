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
/// \file ComponentOffsetSettingsDefinition.h
/// \brief Settings definition for component offset applied to pointer references
/// Translated from: ghidra.program.model.data.ComponentOffsetSettingsDefinition
#pragma once

#include <string>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include "ghidra/NumberSettingsDefinition.h"
#include "ghidra/TypeDefSettingsDefinition.h"
#include "ghidra/Settings.h"

namespace ghidra {

class ComponentOffsetSettingsDefinition : public NumberSettingsDefinition, public TypeDefSettingsDefinition {
private:
    ComponentOffsetSettingsDefinition() = default;

public:
    static ComponentOffsetSettingsDefinition& def();

    int64_t getMaxValue() const override;

    bool allowNegativeValue() const override;

    bool isHexModePreferred() const override;

    int64_t getValue(const Settings* settings) const override;

    void setValue(Settings* settings, int64_t value) override;

    bool hasValue(const Settings* settings) const override;

    std::string getName() const override;

    std::string getStorageKey() const override;

    std::string getDescription() const override;

    void clear(Settings* settings) const override;

    void copySetting(const Settings* srcSettings, Settings* destSettings) const override;

    std::string getAttributeSpecification(const Settings* settings) const override;

    bool hasSameValue(const Settings* settings1, const Settings* settings2) const override {
        return getValue(settings1) == getValue(settings2);
    }
};

} // namespace ghidra
