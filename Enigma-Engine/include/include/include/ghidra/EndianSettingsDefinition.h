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
/// \file EndianSettingsDefinition.h
/// \brief SettingsDefinition for endianness
/// Translated from: ghidra.program.model.data.EndianSettingsDefinition
#pragma once

#include <string>
#include "ghidra/EnumSettingsDefinition.h"
#include "ghidra/Endian.h"
#include "ghidra/MemBuffer.h"

namespace ghidra {

class Settings;

/**
 * SettingsDefinition for endianness
 */
class EndianSettingsDefinition : public EnumSettingsDefinition {
private:
    static inline const std::string ENDIAN_SETTING_NAME = "endian";

    EndianSettingsDefinition() = default;

public:
    static const int DEFAULT = 0;
    static const int LITTLE = 1;
    static const int BIG = 2;

    static inline EndianSettingsDefinition& def() {
        static EndianSettingsDefinition instance;
        return instance;
    }
    static inline EndianSettingsDefinition* ENDIAN = &def();

    /// Returns the endianness settings. First looks in settings, then defaultSettings
    /// and finally returns a default value if the first two have no value for this definition.
    bool isBigEndian(const Settings* settings, const MemBuffer* buf) const;

    Endian getEndianness(const Settings* settings, Endian defaultValue) const;

    void setBigEndian(Settings* settings, bool isBigEndian);

    int getChoice(const Settings* settings) const override;
    std::string getValueString(const Settings* settings) const override;
    void setChoice(Settings* settings, int value) override;
    std::vector<std::string> getDisplayChoices(const Settings* settings) const override;
    std::string getName() const override;
    std::string getStorageKey() const override;
    std::string getDescription() const override;
    std::string getDisplayChoice(int value, const Settings* settings) const override;
    void clear(Settings* settings) const override;
    void copySetting(const Settings* srcSettings, Settings* destSettings) const override;
    bool hasValue(const Settings* setting) const override;
};

} // namespace ghidra
