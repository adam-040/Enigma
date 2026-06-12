/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file TerminatedSettingsDefinition.cpp
/// \brief Settings definition for strings being terminated or unterminated
#include <ghidra/TerminatedSettingsDefinition.h>
#include <ghidra/Settings.h>

namespace ghidra {

namespace {
    const std::string terminatedChoices[] = { "unterminated", "terminated" };
    const char terminatedStorageKey[] = "terminated";
}

TerminatedSettingsDefinition& TerminatedSettingsDefinition::def() {
    static TerminatedSettingsDefinition instance;
    return instance;
}

bool TerminatedSettingsDefinition::isTerminated(const Settings* settings) const {
    if (settings == nullptr) {
        return false;
    }
    if (!settings->hasLong(terminatedStorageKey)) {
        return false;
    }
    return settings->getLong(terminatedStorageKey) == 1;
}

void TerminatedSettingsDefinition::setTerminated(Settings* settings, bool isTerminated) {
    setChoice(settings, isTerminated ? 1 : 0);
}

int TerminatedSettingsDefinition::getChoice(const Settings* settings) const {
    if (isTerminated(settings)) {
        return 1;
    }
    return 0;
}

std::string TerminatedSettingsDefinition::getValueString(const Settings* settings) const {
    return terminatedChoices[getChoice(settings)];
}

void TerminatedSettingsDefinition::setChoice(Settings* settings, int value) {
    settings->setLong(terminatedStorageKey, value);
}

std::vector<std::string> TerminatedSettingsDefinition::getDisplayChoices(const Settings* settings) const {
    (void)settings;
    return std::vector<std::string>(terminatedChoices, terminatedChoices + 2);
}

std::string TerminatedSettingsDefinition::getDisplayChoice(int value, const Settings* s1) const {
    (void)s1;
    return terminatedChoices[value];
}

void TerminatedSettingsDefinition::clear(Settings* settings) const {
    settings->clearSetting(terminatedStorageKey);
}

void TerminatedSettingsDefinition::copySetting(const Settings* settings, Settings* destSettings) const {
    if (!settings->hasLong(terminatedStorageKey)) {
        destSettings->clearSetting(terminatedStorageKey);
    } else {
        destSettings->setLong(terminatedStorageKey, settings->getLong(terminatedStorageKey));
    }
}

bool TerminatedSettingsDefinition::hasValue(const Settings* setting) const {
    return setting->hasLong(terminatedStorageKey);
}

std::string TerminatedSettingsDefinition::getName() const { return "Termination"; }
std::string TerminatedSettingsDefinition::getStorageKey() const { return terminatedStorageKey; }
std::string TerminatedSettingsDefinition::getDescription() const { return "Selects if the string is terminated or unterminated"; }

} // namespace ghidra
