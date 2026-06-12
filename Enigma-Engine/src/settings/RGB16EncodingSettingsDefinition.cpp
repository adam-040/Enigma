/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RGB16EncodingSettingsDefinition.cpp
/// \brief Typedef settings definition which specifies a 16-bit RGB Color Encoding
#include <ghidra/RGB16EncodingSettingsDefinition.h>
#include <ghidra/Settings.h>

namespace ghidra {

namespace {
    const std::string rgb16Choices[] = { "RGB_565", "RGB_555", "ARGB_1555" };
    const char rgb16StorageKey[] = "rgb16";
    const char rgb16Description[] = "Specifies a 16-bit RGB Color Encoding";
    const char rgb16DisplayName[] = "RGB16 Encoding";
}

RGB16EncodingSettingsDefinition& RGB16EncodingSettingsDefinition::def() {
    static RGB16EncodingSettingsDefinition instance;
    return instance;
}

RGB16EncodingSettingsDefinition::RGB16Encoding RGB16EncodingSettingsDefinition::getRGBEncoding(const Settings* settings) const {
    return static_cast<RGB16Encoding>(getChoice(settings));
}

void RGB16EncodingSettingsDefinition::setRGBEncoding(Settings* settings, RGB16Encoding encoding) {
    setChoice(settings, static_cast<int>(encoding));
}

int RGB16EncodingSettingsDefinition::getChoice(const Settings* settings) const {
    if (settings == nullptr) {
        return 0;
    }
    if (!settings->hasLong(rgb16StorageKey)) {
        return 0;
    }
    int choice = static_cast<int>(settings->getLong(rgb16StorageKey));
    if (choice < 0 || choice >= 3) {
        return 0;
    }
    return choice;
}

std::string RGB16EncodingSettingsDefinition::getValueString(const Settings* settings) const {
    return rgb16Choices[getChoice(settings)];
}

void RGB16EncodingSettingsDefinition::setChoice(Settings* settings, int choice) {
    if (choice > 0 && choice < 3) {
        settings->setLong(rgb16StorageKey, choice);
    } else {
        settings->clearSetting(rgb16StorageKey);
    }
}

std::vector<std::string> RGB16EncodingSettingsDefinition::getDisplayChoices(const Settings* settings) const {
    (void)settings;
    return std::vector<std::string>(rgb16Choices, rgb16Choices + 3);
}

std::string RGB16EncodingSettingsDefinition::getDisplayChoice(int value, const Settings* s1) const {
    (void)s1;
    return rgb16Choices[value];
}

void RGB16EncodingSettingsDefinition::clear(Settings* settings) const {
    settings->clearSetting(rgb16StorageKey);
}

void RGB16EncodingSettingsDefinition::copySetting(const Settings* settings, Settings* destSettings) const {
    if (!settings->hasLong(rgb16StorageKey)) {
        destSettings->clearSetting(rgb16StorageKey);
    } else {
        destSettings->setLong(rgb16StorageKey, settings->getLong(rgb16StorageKey));
    }
}

bool RGB16EncodingSettingsDefinition::hasValue(const Settings* setting) const {
    return setting->hasLong(rgb16StorageKey);
}

std::string RGB16EncodingSettingsDefinition::getDisplayChoice(const Settings* settings) const {
    return rgb16Choices[getChoice(settings)];
}

void RGB16EncodingSettingsDefinition::setDisplayChoice(Settings* settings, const std::string& choice) {
    for (int i = 0; i < 3; i++) {
        if (rgb16Choices[i] == choice) {
            setChoice(settings, i);
            break;
        }
    }
}

std::string RGB16EncodingSettingsDefinition::getAttributeSpecification(const Settings* settings) const {
    int choice = getChoice(settings);
    if (choice != 0) {
        return rgb16Choices[choice];
    }
    return "";
}

std::string RGB16EncodingSettingsDefinition::getName() const { return rgb16DisplayName; }
std::string RGB16EncodingSettingsDefinition::getStorageKey() const { return rgb16StorageKey; }
std::string RGB16EncodingSettingsDefinition::getDescription() const { return rgb16Description; }

} // namespace ghidra
