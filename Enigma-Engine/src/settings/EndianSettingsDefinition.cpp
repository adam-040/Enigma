/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file EndianSettingsDefinition.cpp
/// \brief SettingsDefinition for endianness
#include <ghidra/EndianSettingsDefinition.h>
#include <ghidra/Settings.h>

namespace ghidra {

bool EndianSettingsDefinition::isBigEndian(const Settings* settings, const MemBuffer* buf) const {
    int val = getChoice(settings);
    if (val == DEFAULT) {
        return buf->isBigEndian();
    }
    return val == BIG;
}

Endian EndianSettingsDefinition::getEndianness(const Settings* settings, Endian defaultValue) const {
    int val = getChoice(settings);
    switch (val) {
        default:
        case DEFAULT:
            return defaultValue;
        case BIG:
            return Endian::BIG;
        case LITTLE:
            return Endian::LITTLE;
    }
}

void EndianSettingsDefinition::setBigEndian(Settings* settings, bool isBigEndian) {
    setChoice(settings, isBigEndian ? BIG : LITTLE);
}

int EndianSettingsDefinition::getChoice(const Settings* settings) const {
    if (settings == nullptr) {
        return DEFAULT;
    }
    if (!settings->hasLong(ENDIAN_SETTING_NAME)) {
        return DEFAULT;
    }
    int val = static_cast<int>(settings->getLong(ENDIAN_SETTING_NAME));
    if (val < DEFAULT || val > BIG) {
        val = DEFAULT;
    }
    return val;
}

std::string EndianSettingsDefinition::getValueString(const Settings* settings) const {
    static const std::string choices[] = { "default", "little", "big" };
    return choices[getChoice(settings)];
}

void EndianSettingsDefinition::setChoice(Settings* settings, int value) {
    settings->setLong(ENDIAN_SETTING_NAME, value);
}

std::vector<std::string> EndianSettingsDefinition::getDisplayChoices(const Settings* settings) const {
    return { "default", "little", "big" };
}

std::string EndianSettingsDefinition::getName() const {
    return "Endian";
}

std::string EndianSettingsDefinition::getStorageKey() const {
    return ENDIAN_SETTING_NAME;
}

std::string EndianSettingsDefinition::getDescription() const {
    return "Selects the endianness of the data";
}

std::string EndianSettingsDefinition::getDisplayChoice(int value, const Settings* settings) const {
    static const std::string choices[] = { "default", "little", "big" };
    return choices[value];
}

void EndianSettingsDefinition::clear(Settings* settings) const {
    settings->clearSetting(ENDIAN_SETTING_NAME);
}

void EndianSettingsDefinition::copySetting(const Settings* srcSettings, Settings* destSettings) const {
    if (!srcSettings->hasLong(ENDIAN_SETTING_NAME)) {
        destSettings->clearSetting(ENDIAN_SETTING_NAME);
    } else {
        destSettings->setLong(ENDIAN_SETTING_NAME, srcSettings->getLong(ENDIAN_SETTING_NAME));
    }
}

bool EndianSettingsDefinition::hasValue(const Settings* setting) const {
    return setting->hasLong(ENDIAN_SETTING_NAME);
}

} // namespace ghidra
