/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PointerTypeSettingsDefinition.cpp
/// \brief Settings definition for pointer type
#include <ghidra/PointerTypeSettingsDefinition.h>
#include <ghidra/Settings.h>

namespace ghidra {

namespace {
    const std::string ptrTypeChoices[] = { "default", "image-base-relative", "relative", "file-offset" };
    const char ptrTypeStorageKey[] = "ptr_type";
    const char ptrTypeDescription[] = "Specifies the pointer type which affects interpretation of offset";
    const char ptrTypeDisplayName[] = "Pointer Type";
}

PointerTypeSettingsDefinition& PointerTypeSettingsDefinition::def() {
    static PointerTypeSettingsDefinition instance;
    return instance;
}

PointerType PointerTypeSettingsDefinition::getType(const Settings* settings) const {
    if (settings == nullptr) {
        return PointerType::DEFAULT;
    }
    if (!settings->hasLong(ptrTypeStorageKey)) {
        return PointerType::DEFAULT;
    }
    int type = static_cast<int>(settings->getLong(ptrTypeStorageKey));
    try {
        return PointerType::valueOf(type);
    } catch (const std::out_of_range&) {
        return PointerType::DEFAULT;
    }
}

void PointerTypeSettingsDefinition::setType(Settings* settings, PointerType type) {
    if (settings == nullptr) {
        return;  // no settings container to store the choice in
    }
    if (type == PointerType::DEFAULT) {
        settings->clearSetting(ptrTypeStorageKey);
    } else {
        settings->setLong(ptrTypeStorageKey, type.value);
    }
}

int PointerTypeSettingsDefinition::getChoice(const Settings* settings) const {
    return getType(settings).value;
}

std::string PointerTypeSettingsDefinition::getValueString(const Settings* settings) const {
    return ptrTypeChoices[getChoice(settings)];
}

void PointerTypeSettingsDefinition::setChoice(Settings* settings, int value) {
    try {
        PointerType type = PointerType::valueOf(value);
        setType(settings, type);
    } catch (const std::out_of_range&) {
        settings->clearSetting(ptrTypeStorageKey);
    }
}

std::vector<std::string> PointerTypeSettingsDefinition::getDisplayChoices(const Settings* settings) const {
    (void)settings;
    return std::vector<std::string>(ptrTypeChoices, ptrTypeChoices + 4);
}

std::string PointerTypeSettingsDefinition::getDisplayChoice(int value, const Settings* s1) const {
    (void)s1;
    return ptrTypeChoices[value];
}

void PointerTypeSettingsDefinition::clear(Settings* settings) const {
    settings->clearSetting(ptrTypeStorageKey);
}

void PointerTypeSettingsDefinition::copySetting(const Settings* settings, Settings* destSettings) const {
    if (!settings->hasLong(ptrTypeStorageKey)) {
        destSettings->clearSetting(ptrTypeStorageKey);
    } else {
        destSettings->setLong(ptrTypeStorageKey, settings->getLong(ptrTypeStorageKey));
    }
}

bool PointerTypeSettingsDefinition::hasValue(const Settings* setting) const {
    return setting->hasLong(ptrTypeStorageKey);
}

std::string PointerTypeSettingsDefinition::getDisplayChoice(const Settings* settings) const {
    return ptrTypeChoices[getChoice(settings)];
}

void PointerTypeSettingsDefinition::setDisplayChoice(Settings* settings, const std::string& choice) {
    for (int i = 0; i < 4; i++) {
        if (ptrTypeChoices[i] == choice) {
            setChoice(settings, i);
            break;
        }
    }
}

std::string PointerTypeSettingsDefinition::getAttributeSpecification(const Settings* settings) const {
    int choice = getChoice(settings);
    if (choice != 0) {
        return ptrTypeChoices[choice];
    }
    return "";
}

std::string PointerTypeSettingsDefinition::getName() const { return ptrTypeDisplayName; }
std::string PointerTypeSettingsDefinition::getStorageKey() const { return ptrTypeStorageKey; }
std::string PointerTypeSettingsDefinition::getDescription() const { return ptrTypeDescription; }

} // namespace ghidra
