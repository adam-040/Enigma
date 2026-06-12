/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file OffsetMaskSettingsDefinition.cpp
/// \brief Setting definition for a pointer offset bit-mask
#include <ghidra/OffsetMaskSettingsDefinition.h>
#include <ghidra/Settings.h>

namespace ghidra {

namespace {
    const char offsetMaskStorageKey[] = "offset_mask";
    const char offsetMaskDescription[] = "Identifies bit-mask to be applied to a stored pointer offset prior to any shift";
    const char offsetMaskDisplayName[] = "Offset Mask";
    const int64_t DEFAULT_MASK = -1;
}

OffsetMaskSettingsDefinition& OffsetMaskSettingsDefinition::def() {
    static OffsetMaskSettingsDefinition instance;
    return instance;
}

int64_t OffsetMaskSettingsDefinition::getValue(const Settings* settings) const {
    if (settings == nullptr) {
        return DEFAULT_MASK;
    }
    if (!settings->hasLong(offsetMaskStorageKey)) {
        return DEFAULT_MASK;
    }
    return settings->getLong(offsetMaskStorageKey);
}

void OffsetMaskSettingsDefinition::setValue(Settings* settings, int64_t value) {
    if (value == 0 || value == DEFAULT_MASK) {
        settings->clearSetting(offsetMaskStorageKey);
    } else {
        settings->setLong(offsetMaskStorageKey, value);
    }
}

bool OffsetMaskSettingsDefinition::hasValue(const Settings* settings) const {
    return getValue(settings) != DEFAULT_MASK;
}

void OffsetMaskSettingsDefinition::clear(Settings* settings) const {
    settings->clearSetting(offsetMaskStorageKey);
}

void OffsetMaskSettingsDefinition::copySetting(const Settings* srcSettings, Settings* destSettings) const {
    if (!srcSettings->hasLong(offsetMaskStorageKey)) {
        destSettings->clearSetting(offsetMaskStorageKey);
    } else {
        destSettings->setLong(offsetMaskStorageKey, srcSettings->getLong(offsetMaskStorageKey));
    }
}

std::string OffsetMaskSettingsDefinition::getAttributeSpecification(const Settings* settings) const {
    if (hasValue(settings)) {
        int64_t mask = getValue(settings);
        std::ostringstream oss;
        oss << "mask(0x" << std::hex << static_cast<uint64_t>(mask) << ")";
        return oss.str();
    }
    return "";
}

int64_t OffsetMaskSettingsDefinition::getMaxValue() const { return INT64_MAX; }
bool OffsetMaskSettingsDefinition::allowNegativeValue() const { return false; }
bool OffsetMaskSettingsDefinition::isHexModePreferred() const { return true; }
std::string OffsetMaskSettingsDefinition::getName() const { return offsetMaskDisplayName; }
std::string OffsetMaskSettingsDefinition::getStorageKey() const { return offsetMaskStorageKey; }
std::string OffsetMaskSettingsDefinition::getDescription() const { return offsetMaskDescription; }

} // namespace ghidra
