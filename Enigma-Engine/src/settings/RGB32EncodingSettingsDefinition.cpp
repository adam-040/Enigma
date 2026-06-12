/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RGB32EncodingSettingsDefinition.cpp
/// \brief Typedef settings definition which specifies a 32-bit RGB Color Encoding
#include <ghidra/RGB32EncodingSettingsDefinition.h>
#include <ghidra/Settings.h>

namespace ghidra {

namespace {
    const std::string rgb32Choices[] = { "ARGB_8888", "RGBA_8888", "BGRA_8888", "ABGR_8888" };
    const char rgb32StorageKey[] = "rgb32";
    const char rgb32Description[] = "Specifies a 32-bit RGB Color Encoding";
    const char rgb32DisplayName[] = "RGB32 Encoding";
}

RGB32EncodingSettingsDefinition& RGB32EncodingSettingsDefinition::def() {
    static RGB32EncodingSettingsDefinition instance;
    return instance;
}

RGB32EncodingSettingsDefinition::RGB32Encoding RGB32EncodingSettingsDefinition::getRGBEncoding(const Settings* settings) const {
    return static_cast<RGB32Encoding>(getChoice(settings));
}

void RGB32EncodingSettingsDefinition::setRGBEncoding(Settings* settings, RGB32Encoding encoding) {
    setChoice(settings, static_cast<int>(encoding));
}

int RGB32EncodingSettingsDefinition::getChoice(const Settings* settings) const {
    if (settings == nullptr) {
        return 0;
    }
    if (!settings->hasLong(rgb32StorageKey)) {
        return 0;
    }
    int choice = static_cast<int>(settings->getLong(rgb32StorageKey));
    if (choice < 0 || choice >= 4) {
        return 0;
    }
    return choice;
}

std::string RGB32EncodingSettingsDefinition::getValueString(const Settings* settings) const {
    return rgb32Choices[getChoice(settings)];
}

void RGB32EncodingSettingsDefinition::setChoice(Settings* settings, int choice) {
    if (choice > 0 && choice < 4) {
        settings->setLong(rgb32StorageKey, choice);
    } else {
        settings->clearSetting(rgb32StorageKey);
    }
}

std::vector<std::string> RGB32EncodingSettingsDefinition::getDisplayChoices(const Settings* settings) const {
    (void)settings;
    return std::vector<std::string>(rgb32Choices, rgb32Choices + 4);
}

std::string RGB32EncodingSettingsDefinition::getDisplayChoice(int value, const Settings* s1) const {
    (void)s1;
    return rgb32Choices[value];
}

void RGB32EncodingSettingsDefinition::clear(Settings* settings) const {
    settings->clearSetting(rgb32StorageKey);
}

void RGB32EncodingSettingsDefinition::copySetting(const Settings* settings, Settings* destSettings) const {
    if (!settings->hasLong(rgb32StorageKey)) {
        destSettings->clearSetting(rgb32StorageKey);
    } else {
        destSettings->setLong(rgb32StorageKey, settings->getLong(rgb32StorageKey));
    }
}

bool RGB32EncodingSettingsDefinition::hasValue(const Settings* setting) const {
    return setting->hasLong(rgb32StorageKey);
}

std::string RGB32EncodingSettingsDefinition::getDisplayChoice(const Settings* settings) const {
    return rgb32Choices[getChoice(settings)];
}

void RGB32EncodingSettingsDefinition::setDisplayChoice(Settings* settings, const std::string& choice) {
    for (int i = 0; i < 4; i++) {
        if (rgb32Choices[i] == choice) {
            setChoice(settings, i);
            break;
        }
    }
}

std::string RGB32EncodingSettingsDefinition::getAttributeSpecification(const Settings* settings) const {
    int choice = getChoice(settings);
    if (choice != 0) {
        return rgb32Choices[choice];
    }
    return "";
}

std::string RGB32EncodingSettingsDefinition::getName() const { return rgb32DisplayName; }
std::string RGB32EncodingSettingsDefinition::getStorageKey() const { return rgb32StorageKey; }
std::string RGB32EncodingSettingsDefinition::getDescription() const { return rgb32Description; }

} // namespace ghidra
