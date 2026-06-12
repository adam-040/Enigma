/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file MutabilitySettingsDefinition.cpp
/// \brief Settings definition for data mutability
#include <ghidra/MutabilitySettingsDefinition.h>
#include <ghidra/Settings.h>

namespace ghidra {

namespace {
    const std::string mutabilityChoices[] = { "normal", "volatile", "constant", "writable" };
    const char mutabilityStorageKey[] = "mutability";
}

MutabilitySettingsDefinition& MutabilitySettingsDefinition::def() {
    static MutabilitySettingsDefinition instance;
    return instance;
}

int MutabilitySettingsDefinition::getMutabilityMode(const Settings* settings) const {
    if (settings == nullptr) {
        return NORMAL;
    }
    if (!settings->hasLong(mutabilityStorageKey)) {
        return NORMAL;
    }
    int mode = static_cast<int>(settings->getLong(mutabilityStorageKey));
    if (mode < 0 || mode > WRITABLE) {
        mode = NORMAL;
    }
    return mode;
}

std::string MutabilitySettingsDefinition::getValueString(const Settings* settings) const {
    return mutabilityChoices[getChoice(settings)];
}

void MutabilitySettingsDefinition::setChoice(Settings* settings, int value) {
    if (value < 0 || value > WRITABLE) {
        settings->clearSetting(mutabilityStorageKey);
    } else {
        settings->setLong(mutabilityStorageKey, value);
    }
}

std::vector<std::string> MutabilitySettingsDefinition::getDisplayChoices(const Settings* settings) const {
    (void)settings;
    return std::vector<std::string>(mutabilityChoices, mutabilityChoices + 4);
}

std::string MutabilitySettingsDefinition::getDisplayChoice(int value, const Settings* s1) const {
    (void)s1;
    return mutabilityChoices[value];
}

void MutabilitySettingsDefinition::clear(Settings* settings) const {
    settings->clearSetting(mutabilityStorageKey);
}

void MutabilitySettingsDefinition::copySetting(const Settings* settings, Settings* destSettings) const {
    if (!settings->hasLong(mutabilityStorageKey)) {
        destSettings->clearSetting(mutabilityStorageKey);
    } else {
        destSettings->setLong(mutabilityStorageKey, settings->getLong(mutabilityStorageKey));
    }
}

bool MutabilitySettingsDefinition::hasValue(const Settings* setting) const {
    return setting->hasLong(mutabilityStorageKey);
}

int MutabilitySettingsDefinition::getChoice(const Settings* settings) const { return getMutabilityMode(settings); }
std::string MutabilitySettingsDefinition::getName() const { return "Mutability"; }
std::string MutabilitySettingsDefinition::getStorageKey() const { return mutabilityStorageKey; }
std::string MutabilitySettingsDefinition::getDescription() const { return "Selects the data mutability"; }

} // namespace ghidra
