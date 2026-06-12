/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ComponentOffsetSettingsDefinition.cpp
/// \brief Settings definition for component offset applied to pointer references
#include <ghidra/ComponentOffsetSettingsDefinition.h>
#include <ghidra/Settings.h>

namespace ghidra {

namespace {
    const char componentOffsetStorageKey[] = "component_offset";
    const char componentOffsetDescription[] = "Identifies a component offset to be applied to a pointer reference";
    const char componentOffsetDisplayName[] = "Component Offset";
    const int64_t DEFAULT_OFFSET = 0;
}

ComponentOffsetSettingsDefinition& ComponentOffsetSettingsDefinition::def() {
    static ComponentOffsetSettingsDefinition instance;
    return instance;
}

int64_t ComponentOffsetSettingsDefinition::getValue(const Settings* settings) const {
    if (settings == nullptr) {
        return DEFAULT_OFFSET;
    }
    if (!settings->hasLong(componentOffsetStorageKey)) {
        return DEFAULT_OFFSET;
    }
    return settings->getLong(componentOffsetStorageKey);
}

void ComponentOffsetSettingsDefinition::setValue(Settings* settings, int64_t value) {
    if (value == DEFAULT_OFFSET) {
        settings->clearSetting(componentOffsetStorageKey);
    } else {
        settings->setLong(componentOffsetStorageKey, value);
    }
}

bool ComponentOffsetSettingsDefinition::hasValue(const Settings* settings) const {
    return getValue(settings) != DEFAULT_OFFSET;
}

void ComponentOffsetSettingsDefinition::clear(Settings* settings) const {
    settings->clearSetting(componentOffsetStorageKey);
}

void ComponentOffsetSettingsDefinition::copySetting(const Settings* srcSettings, Settings* destSettings) const {
    if (!srcSettings->hasLong(componentOffsetStorageKey)) {
        destSettings->clearSetting(componentOffsetStorageKey);
    } else {
        destSettings->setLong(componentOffsetStorageKey, srcSettings->getLong(componentOffsetStorageKey));
    }
}

std::string ComponentOffsetSettingsDefinition::getAttributeSpecification(const Settings* settings) const {
    if (hasValue(settings)) {
        int64_t offset = getValue(settings);
        std::string sign = "";
        if (offset < 0) {
            offset = -offset;
            sign = "-";
        }
        std::ostringstream oss;
        oss << "offset(" << sign << "0x" << std::hex << static_cast<uint64_t>(offset) << ")";
        return oss.str();
    }
    return "";
}

int64_t ComponentOffsetSettingsDefinition::getMaxValue() const { return INT64_MAX; }
bool ComponentOffsetSettingsDefinition::allowNegativeValue() const { return true; }
bool ComponentOffsetSettingsDefinition::isHexModePreferred() const { return false; }
std::string ComponentOffsetSettingsDefinition::getName() const { return componentOffsetDisplayName; }
std::string ComponentOffsetSettingsDefinition::getStorageKey() const { return componentOffsetStorageKey; }
std::string ComponentOffsetSettingsDefinition::getDescription() const { return componentOffsetDescription; }

} // namespace ghidra
