/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file FormatSettingsDefinition.cpp
/// \brief Settings definition for numeric display format
#include <ghidra/FormatSettingsDefinition.h>
#include <ghidra/Settings.h>

namespace ghidra {

namespace {
    const std::string formatChoices[] = { "hex", "decimal", "binary", "octal", "char" };
    const std::string formatValuePostfix[] = { "h", "", "b", "o", "" };
    const int formatRadix[] = { 16, 10, 2, 8, 0 };
    const char formatStorageKey[] = "format";
}

const FormatSettingsDefinition* FormatSettingsDefinition::DEF_HEX() {
    static FormatSettingsDefinition inst(HEX); return &inst;
}
const FormatSettingsDefinition* FormatSettingsDefinition::DEF_DECIMAL() {
    static FormatSettingsDefinition inst(DECIMAL); return &inst;
}
const FormatSettingsDefinition* FormatSettingsDefinition::DEF_BINARY() {
    static FormatSettingsDefinition inst(BINARY); return &inst;
}
const FormatSettingsDefinition* FormatSettingsDefinition::DEF_OCTAL() {
    static FormatSettingsDefinition inst(OCTAL); return &inst;
}
const FormatSettingsDefinition* FormatSettingsDefinition::DEF_CHAR() {
    static FormatSettingsDefinition inst(CHAR); return &inst;
}
const FormatSettingsDefinition* FormatSettingsDefinition::DEF() {
    return DEF_HEX();
}

int FormatSettingsDefinition::getFormat(const Settings* settings) const {
    if (!settings) return defaultFormat_;
    if (!settings->hasLong(formatStorageKey)) return defaultFormat_;
    int format = static_cast<int>(settings->getLong(formatStorageKey));
    if (format < 0 || format > CHAR) format = HEX;
    return format;
}

int FormatSettingsDefinition::getRadix(const Settings* settings) const {
    return formatRadix[getFormat(settings)];
}

std::string FormatSettingsDefinition::getRepresentationPostfix(const Settings* settings) const {
    return formatValuePostfix[getFormat(settings)];
}

void FormatSettingsDefinition::setChoice(Settings* settings, int value) {
    if (value < 0 || value > CHAR) {
        settings->clearSetting(formatStorageKey);
    }
    else {
        settings->setLong(formatStorageKey, value);
    }
}

std::vector<std::string> FormatSettingsDefinition::getDisplayChoices(const Settings* settings) const {
    (void)settings;
    return std::vector<std::string>(formatChoices, formatChoices + 5);
}

std::string FormatSettingsDefinition::getValueString(const Settings* settings) const {
    return formatChoices[getChoice(settings)];
}

std::string FormatSettingsDefinition::getDisplayChoice(int value, const Settings* settings) const {
    (void)settings;
    return formatChoices[value];
}

void FormatSettingsDefinition::clear(Settings* settings) const {
    settings->clearSetting(formatStorageKey);
}

void FormatSettingsDefinition::copySetting(const Settings* settings, Settings* destSettings) const {
    if (!settings->hasLong(formatStorageKey)) {
        destSettings->clearSetting(formatStorageKey);
    }
    else {
        destSettings->setLong(formatStorageKey, settings->getLong(formatStorageKey));
    }
}

bool FormatSettingsDefinition::hasValue(const Settings* setting) const {
    return setting->hasLong(formatStorageKey);
}

void FormatSettingsDefinition::setDisplayChoice(Settings* settings, const std::string& choice) {
    for (int i = 0; i < 5; i++) {
        if (formatChoices[i] == choice) {
            setChoice(settings, i);
            break;
        }
    }
}

std::string FormatSettingsDefinition::getName() const { return "Format"; }
std::string FormatSettingsDefinition::getStorageKey() const { return formatStorageKey; }
std::string FormatSettingsDefinition::getDescription() const { return "Selects the display format"; }
int FormatSettingsDefinition::getChoice(const Settings* settings) const { return getFormat(settings); }

} // namespace ghidra
