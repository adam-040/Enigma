/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file OffsetShiftSettingsDefinition.cpp
/// \brief Settings definition for bit-shift applied to pointer offset
#include <ghidra/OffsetShiftSettingsDefinition.h>
#include <ghidra/Settings.h>

namespace ghidra {

namespace {
    const char offsetShiftStorageKey[] = "offset_shift";
    const char offsetShiftDescription[] = "Identifies bit-shift to be applied to a stored pointer offset (+left/-right)";
    const char offsetShiftDisplayName[] = "Offset Shift";
    const int64_t DEFAULT_SHIFT = 0;
}

OffsetShiftSettingsDefinition& OffsetShiftSettingsDefinition::def() {
    static OffsetShiftSettingsDefinition instance;
    return instance;
}

int64_t OffsetShiftSettingsDefinition::getValue(const Settings* settings) const {
    if (settings == nullptr) {
        return DEFAULT_SHIFT;
    }
    if (!settings->hasLong(offsetShiftStorageKey)) {
        return DEFAULT_SHIFT;
    }
    return settings->getLong(offsetShiftStorageKey);
}

void OffsetShiftSettingsDefinition::setValue(Settings* settings, int64_t value) {
    if (value == DEFAULT_SHIFT) {
        settings->clearSetting(offsetShiftStorageKey);
    } else {
        settings->setLong(offsetShiftStorageKey, value);
    }
}

bool OffsetShiftSettingsDefinition::hasValue(const Settings* settings) const {
    return getValue(settings) != DEFAULT_SHIFT;
}

void OffsetShiftSettingsDefinition::clear(Settings* settings) const {
    settings->clearSetting(offsetShiftStorageKey);
}

void OffsetShiftSettingsDefinition::copySetting(const Settings* srcSettings, Settings* destSettings) const {
    if (!srcSettings->hasLong(offsetShiftStorageKey)) {
        destSettings->clearSetting(offsetShiftStorageKey);
    } else {
        destSettings->setLong(offsetShiftStorageKey, srcSettings->getLong(offsetShiftStorageKey));
    }
}

std::string OffsetShiftSettingsDefinition::getAttributeSpecification(const Settings* settings) const {
    if (hasValue(settings)) {
        int64_t shift = getValue(settings);
        std::ostringstream oss;
        oss << "shift(" << shift << ")";
        return oss.str();
    }
    return "";
}

int64_t OffsetShiftSettingsDefinition::getMaxValue() const { return 64; }
bool OffsetShiftSettingsDefinition::allowNegativeValue() const { return true; }
bool OffsetShiftSettingsDefinition::isHexModePreferred() const { return false; }
std::string OffsetShiftSettingsDefinition::getName() const { return offsetShiftDisplayName; }
std::string OffsetShiftSettingsDefinition::getStorageKey() const { return offsetShiftStorageKey; }
std::string OffsetShiftSettingsDefinition::getDescription() const { return offsetShiftDescription; }

} // namespace ghidra
