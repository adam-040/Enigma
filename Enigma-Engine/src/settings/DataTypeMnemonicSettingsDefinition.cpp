/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeMnemonicSettingsDefinition.cpp
/// \brief Settings definition for data type mnemonic style
#include <ghidra/DataTypeMnemonicSettingsDefinition.h>
#include <ghidra/Settings.h>

namespace ghidra {

namespace {
    const std::string mnemonicChoices[] = { "default", "assembly", "C" };
    const char mnemonicStorageKey[] = "mnemonic";
}

const DataTypeMnemonicSettingsDefinition* DataTypeMnemonicSettingsDefinition::DEF() {
    static DataTypeMnemonicSettingsDefinition inst; return &inst;
}

int DataTypeMnemonicSettingsDefinition::getMnemonicStyle(const Settings* settings) const {
    if (!settings) return ASSEMBLY;
    if (!settings->hasLong(mnemonicStorageKey)) return ASSEMBLY;
    int style = static_cast<int>(settings->getLong(mnemonicStorageKey));
    if (style < 0 || style > CSPEC) style = ASSEMBLY;
    return style;
}

void DataTypeMnemonicSettingsDefinition::setChoice(Settings* settings, int value) {
    if (value < 0 || value > CSPEC) {
        settings->clearSetting(mnemonicStorageKey);
    }
    else {
        settings->setLong(mnemonicStorageKey, value);
    }
}

std::vector<std::string> DataTypeMnemonicSettingsDefinition::getDisplayChoices(const Settings* settings) const {
    (void)settings;
    return std::vector<std::string>(mnemonicChoices, mnemonicChoices + 3);
}

std::string DataTypeMnemonicSettingsDefinition::getValueString(const Settings* settings) const {
    return mnemonicChoices[getChoice(settings)];
}

std::string DataTypeMnemonicSettingsDefinition::getDisplayChoice(int value, const Settings* settings) const {
    (void)settings;
    return mnemonicChoices[value];
}

void DataTypeMnemonicSettingsDefinition::clear(Settings* settings) const {
    settings->clearSetting(mnemonicStorageKey);
}

void DataTypeMnemonicSettingsDefinition::copySetting(const Settings* settings, Settings* destSettings) const {
    if (!settings->hasLong(mnemonicStorageKey)) {
        destSettings->clearSetting(mnemonicStorageKey);
    }
    else {
        destSettings->setLong(mnemonicStorageKey, settings->getLong(mnemonicStorageKey));
    }
}

bool DataTypeMnemonicSettingsDefinition::hasValue(const Settings* setting) const {
    return setting->hasLong(mnemonicStorageKey);
}

int DataTypeMnemonicSettingsDefinition::getChoice(const Settings* settings) const { return getMnemonicStyle(settings); }
std::string DataTypeMnemonicSettingsDefinition::getName() const { return "Mnemonic-style"; }
std::string DataTypeMnemonicSettingsDefinition::getStorageKey() const { return mnemonicStorageKey; }
std::string DataTypeMnemonicSettingsDefinition::getDescription() const { return "Selects the data-type mnemonic style"; }

} // namespace ghidra
