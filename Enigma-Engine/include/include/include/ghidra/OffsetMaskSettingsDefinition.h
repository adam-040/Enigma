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
/// \file OffsetMaskSettingsDefinition.h
/// \brief Setting definition for a pointer offset bit-mask
/// Translated from: ghidra.program.model.data.OffsetMaskSettingsDefinition
#pragma once

#include <string>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include "ghidra/NumberSettingsDefinition.h"
#include "ghidra/TypeDefSettingsDefinition.h"
#include "ghidra/Settings.h"

namespace ghidra {

/**
 * Setting definition for a pointer offset bit-mask to be applied prior to any
 * bit-shift (if specified) during the computation of an actual address offset.
 * Mask is defined as an unsigned long value where a value of zero (0) is ignored
 * and has no affect on pointer computation.
 */
class OffsetMaskSettingsDefinition : public NumberSettingsDefinition, public TypeDefSettingsDefinition {
public:
    static const int64_t DEFAULT = -1; // unsigned mask - all bits are ones

private:
    OffsetMaskSettingsDefinition() = default;

public:
    static OffsetMaskSettingsDefinition& def();

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
