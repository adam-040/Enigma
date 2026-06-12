/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file IntegerSignednessFormattingModeSettingsDefinition.cpp
/// \brief Settings definition for the numeric display format for handling signed values
#include <ghidra/IntegerSignednessFormattingModeSettingsDefinition.h>
#include <ghidra/Settings.h>

namespace ghidra {

namespace {
    const std::string signednessChoices[] = { "Default", "Unsigned", "Signed" };
    const char signednessStorageKey[] = "signedness-mode";
}

IntegerSignednessFormattingModeSettingsDefinition& IntegerSignednessFormattingModeSettingsDefinition::def() {
    static IntegerSignednessFormattingModeSettingsDefinition instance(SignednessFormatMode::DEFAULT);
    return instance;
}
IntegerSignednessFormattingModeSettingsDefinition& IntegerSignednessFormattingModeSettingsDefinition::def_signed() {
    static IntegerSignednessFormattingModeSettingsDefinition instance(SignednessFormatMode::SIGNED);
    return instance;
}
IntegerSignednessFormattingModeSettingsDefinition& IntegerSignednessFormattingModeSettingsDefinition::def_unsigned() {
    static IntegerSignednessFormattingModeSettingsDefinition instance(SignednessFormatMode::UNSIGNED);
    return instance;
}

SignednessFormatMode IntegerSignednessFormattingModeSettingsDefinition::getFormatMode(const Settings* settings) const {
    if (settings == nullptr) {
        return defaultFormat_;
    }
    if (!settings->hasLong(signednessStorageKey)) {
        return defaultFormat_;
    }
    int64_t value = settings->getLong(signednessStorageKey);
    if (value < 0 || value >= 3) {
        return defaultFormat_;
    }
    try {
        return SignednessFormatModeUtil::parse(static_cast<int>(value));
    } catch (const std::invalid_argument&) {
        return defaultFormat_;
    }
}

void IntegerSignednessFormattingModeSettingsDefinition::setFormatMode(Settings* settings, SignednessFormatMode mode) {
    settings->setLong(signednessStorageKey, SignednessFormatModeUtil::ordinal(mode));
}

int IntegerSignednessFormattingModeSettingsDefinition::getChoice(const Settings* settings) const {
    return SignednessFormatModeUtil::ordinal(getFormatMode(settings));
}

std::string IntegerSignednessFormattingModeSettingsDefinition::getValueString(const Settings* settings) const {
    return signednessChoices[getChoice(settings)];
}

void IntegerSignednessFormattingModeSettingsDefinition::setChoice(Settings* settings, int value) {
    try {
        SignednessFormatMode mode = SignednessFormatModeUtil::parse(value);
        settings->setLong(signednessStorageKey, SignednessFormatModeUtil::ordinal(mode));
    } catch (const std::invalid_argument&) {
        settings->clearSetting(signednessStorageKey);
    }
}

std::vector<std::string> IntegerSignednessFormattingModeSettingsDefinition::getDisplayChoices(const Settings* settings) const {
    (void)settings;
    return std::vector<std::string>(signednessChoices, signednessChoices + 3);
}

std::string IntegerSignednessFormattingModeSettingsDefinition::getDisplayChoice(int value, const Settings* s1) const {
    (void)s1;
    return signednessChoices[value];
}

void IntegerSignednessFormattingModeSettingsDefinition::clear(Settings* settings) const {
    settings->clearSetting(signednessStorageKey);
}

void IntegerSignednessFormattingModeSettingsDefinition::copySetting(const Settings* settings, Settings* destSettings) const {
    if (!settings->hasLong(signednessStorageKey)) {
        destSettings->clearSetting(signednessStorageKey);
    } else {
        destSettings->setLong(signednessStorageKey, settings->getLong(signednessStorageKey));
    }
}

bool IntegerSignednessFormattingModeSettingsDefinition::hasValue(const Settings* setting) const {
    return setting->hasLong(signednessStorageKey);
}

std::string IntegerSignednessFormattingModeSettingsDefinition::getDisplayChoice(const Settings* settings) const {
    return signednessChoices[getChoice(settings)];
}

void IntegerSignednessFormattingModeSettingsDefinition::setDisplayChoice(Settings* settings, const std::string& choice) {
    for (int i = 0; i < 3; i++) {
        if (signednessChoices[i] == choice) {
            setChoice(settings, i);
            break;
        }
    }
}

std::string IntegerSignednessFormattingModeSettingsDefinition::getName() const { return "Signedness Mode"; }
std::string IntegerSignednessFormattingModeSettingsDefinition::getStorageKey() const { return signednessStorageKey; }
std::string IntegerSignednessFormattingModeSettingsDefinition::getDescription() const { return "Selects the display mode for signed values"; }

} // namespace ghidra
