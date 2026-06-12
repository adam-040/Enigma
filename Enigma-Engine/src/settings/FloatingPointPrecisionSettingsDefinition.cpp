/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file FloatingPointPrecisionSettingsDefinition.cpp
/// \brief Settings definition for floating-point display precision
#include <ghidra/FloatingPointPrecisionSettingsDefinition.h>
#include <ghidra/Settings.h>

namespace ghidra {

namespace {
    const std::string fpPrecisionChoices[] = { "default", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10" };
    const char fpPrecisionStorageKey[] = "Precision digits";
}

const FloatingPointPrecisionSettingsDefinition* FloatingPointPrecisionSettingsDefinition::DEF() {
    static FloatingPointPrecisionSettingsDefinition inst; return &inst;
}

int FloatingPointPrecisionSettingsDefinition::getChoice(const Settings* settings) const {
    int value = 4; // DEFAULT_PRECISION(3) + 1
    if (settings && settings->hasLong(fpPrecisionStorageKey)) {
        value = static_cast<int>(settings->getLong(fpPrecisionStorageKey));
    }
    return value;
}

void FloatingPointPrecisionSettingsDefinition::setChoice(Settings* settings, int valueIndex) {
    if (valueIndex < 0) {
        settings->clearSetting(fpPrecisionStorageKey);
    }
    else {
        if (valueIndex == 0) valueIndex = 4; // DEFAULT_PRECISION + 1
        if (valueIndex > MAX_PRECISION + 1) valueIndex = MAX_PRECISION + 1;
        settings->setLong(fpPrecisionStorageKey, valueIndex);
    }
}

std::vector<std::string> FloatingPointPrecisionSettingsDefinition::getDisplayChoices(const Settings* settings) const {
    (void)settings;
    constexpr int N = sizeof(fpPrecisionChoices) / sizeof(fpPrecisionChoices[0]);
    return std::vector<std::string>(fpPrecisionChoices, fpPrecisionChoices + N);
}

std::string FloatingPointPrecisionSettingsDefinition::getValueString(const Settings* settings) const {
    return std::to_string(getPrecision(settings));
}

int FloatingPointPrecisionSettingsDefinition::getChoice(const std::string& displayChoice, const Settings* settings) const {
    (void)settings;
    constexpr int N = sizeof(fpPrecisionChoices) / sizeof(fpPrecisionChoices[0]);
    for (int i = 0; i < N; i++) {
        if (fpPrecisionChoices[i] == displayChoice) return i;
    }
    return -1;
}

std::string FloatingPointPrecisionSettingsDefinition::getDisplayChoice(int value, const Settings* settings) const {
    (void)settings;
    return fpPrecisionChoices[value];
}

void FloatingPointPrecisionSettingsDefinition::clear(Settings* settings) const {
    settings->clearSetting(fpPrecisionStorageKey);
}

void FloatingPointPrecisionSettingsDefinition::copySetting(const Settings* settings, Settings* destSettings) const {
    if (!settings->hasLong(fpPrecisionStorageKey)) {
        destSettings->clearSetting(fpPrecisionStorageKey);
    }
    else {
        destSettings->setLong(fpPrecisionStorageKey, settings->getLong(fpPrecisionStorageKey));
    }
}

bool FloatingPointPrecisionSettingsDefinition::hasValue(const Settings* setting) const {
    return setting->hasLong(fpPrecisionStorageKey);
}

std::string FloatingPointPrecisionSettingsDefinition::getName() const { return fpPrecisionStorageKey; }
std::string FloatingPointPrecisionSettingsDefinition::getStorageKey() const { return fpPrecisionStorageKey; }
std::string FloatingPointPrecisionSettingsDefinition::getDescription() const { return "Selects the number of digits of precision to display"; }

} // namespace ghidra
