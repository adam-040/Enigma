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
/// \file RGB16EncodingSettingsDefinition.h
/// \brief Typedef settings definition which specifies a 16-bit RGB Color Encoding
/// Translated from: ghidra.program.model.data.RGB16EncodingSettingsDefinition
#pragma once

#include <string>
#include <vector>
#include <stdexcept>
#include "ghidra/EnumSettingsDefinition.h"
#include "ghidra/TypeDefSettingsDefinition.h"
#include "ghidra/Settings.h"

namespace ghidra {

/**
 * The typedef settings definition which specifies a 16-bit RGB Color Encoding
 */
class RGB16EncodingSettingsDefinition : public EnumSettingsDefinition, public TypeDefSettingsDefinition {
public:
    enum class RGB16Encoding {
        RGB_565,
        RGB_555,
        ARGB_1555
    };

    static const RGB16Encoding DEFAULT_ENCODING = RGB16Encoding::RGB_565;

private:
    RGB16EncodingSettingsDefinition() = default;

public:
    static RGB16EncodingSettingsDefinition& def();

    /// Returns the RGB encoding standard based on the specified settings
    RGB16Encoding getRGBEncoding(const Settings* settings) const;

    void setRGBEncoding(Settings* settings, RGB16Encoding encoding);

    int getChoice(const Settings* settings) const override;

    std::string getValueString(const Settings* settings) const override;

    void setChoice(Settings* settings, int choice) override;

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
