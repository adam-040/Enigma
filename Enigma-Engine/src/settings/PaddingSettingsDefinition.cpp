/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PaddingSettingsDefinition.cpp
/// \brief Settings definition for setting the padded/unpadded setting
#include <ghidra/PaddingSettingsDefinition.h>
#include <ghidra/Settings.h>

namespace ghidra {

namespace {
    const std::string paddingChoices[] = { "unpadded", "padded" };
    const char paddingStorageKey[] = "padded";
}

PaddingSettingsDefinition& PaddingSettingsDefinition::def() {
    static PaddingSettingsDefinition instance;
    return instance;
}

bool PaddingSettingsDefinition::isPadded(const Settings* settings) const {
    if (settings == nullptr) {
        return false;
    }
    if (!settings->hasLong(paddingStorageKey)) {
        return false;
    }
    return settings->getLong(paddingStorageKey) != 0;
}

void PaddingSettingsDefinition::setPadded(Settings* settings, bool isPadded) {
    setChoice(settings, isPadded ? 1 : 0);
}

int PaddingSettingsDefinition::getChoice(const Settings* settings) const {
    if (isPadded(settings)) {
        return 1;
    }
    return 0;
}

std::string PaddingSettingsDefinition::getValueString(const Settings* settings) const {
    return paddingChoices[getChoice(settings)];
}

void PaddingSettingsDefinition::setChoice(Settings* settings, int value) {
    settings->setLong(paddingStorageKey, value);
}

std::vector<std::string> PaddingSettingsDefinition::getDisplayChoices(const Settings* settings) const {
    (void)settings;
    return std::vector<std::string>(paddingChoices, paddingChoices + 2);
}

std::string PaddingSettingsDefinition::getDisplayChoice(int value, const Settings* s1) const {
    (void)s1;
    return paddingChoices[value];
}

void PaddingSettingsDefinition::clear(Settings* settings) const {
    settings->clearSetting(paddingStorageKey);
}

void PaddingSettingsDefinition::copySetting(const Settings* settings, Settings* destSettings) const {
    if (!settings->hasLong(paddingStorageKey)) {
        destSettings->clearSetting(paddingStorageKey);
    } else {
        destSettings->setLong(paddingStorageKey, settings->getLong(paddingStorageKey));
    }
}

bool PaddingSettingsDefinition::hasValue(const Settings* setting) const {
    return setting->hasLong(paddingStorageKey);
}

std::string PaddingSettingsDefinition::getName() const { return "Padding"; }
std::string PaddingSettingsDefinition::getStorageKey() const { return paddingStorageKey; }
std::string PaddingSettingsDefinition::getDescription() const { return "Selects if the data is padded or not"; }

} // namespace ghidra
