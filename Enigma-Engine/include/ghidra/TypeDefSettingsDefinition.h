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
/// \file TypeDefSettingsDefinition.h
/// \brief Interface for TypeDef settings definitions
/// Translated from: ghidra.program.model.data.TypeDefSettingsDefinition
#pragma once

#include <vector>
#include <algorithm>
#include "ghidra/SettingsDefinition.h"

namespace ghidra {

class Settings;

/**
 * TypeDefSettingsDefinition specifies a SettingsDefinition whose use as a TypeDef
 * setting will be available for use within a non-Program DataType archive. Such
 * settings will be considered for DataType equivalence checks and preserved during
 * DataType cloning and resolve processing. As such, these settings are only currently
 * supported as a default-setting on a TypeDef and do not support component-specific
 * or data-instance use.
 *
 * NOTE: Full support for this type of setting has only been fully implemented for TypeDef
 * in support. There may be quite a few obstacles to overcome when introducing such
 * settings to a different datatype.
 */
class TypeDefSettingsDefinition : public virtual SettingsDefinition {
public:
    ~TypeDefSettingsDefinition() override = default;

    /// Get the TypeDef attribute specification for this setting and its current value
    virtual std::string getAttributeSpecification(const Settings* settings) const = 0;

    /// Create a new list of TypeDefSettingsDefinitions by concatenating a base list with
    /// additional list of setting defs. Any additional duplicates are discarded.
    static std::vector<TypeDefSettingsDefinition*> concat(
        const std::vector<TypeDefSettingsDefinition*>& base,
        const std::vector<TypeDefSettingsDefinition*>& additional);
};

inline std::vector<TypeDefSettingsDefinition*> TypeDefSettingsDefinition::concat(
    const std::vector<TypeDefSettingsDefinition*>& base,
    const std::vector<TypeDefSettingsDefinition*>& additional)
{
    if (additional.empty()) return base;
    if (base.empty()) return additional;

    std::vector<TypeDefSettingsDefinition*> result = base;
    for (auto* def : additional) {
        bool found = false;
        for (auto* existing : base) {
            if (existing == def) { found = true; break; }
        }
        if (!found) result.push_back(def);
    }
    return result;
}

} // namespace ghidra
